//! `testls` command-line interface.

mod target;

use std::io::IsTerminal as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Parser;
use clap::builder::TypedValueParser as _;
use testls_checks::{
    Finding, Severity, TrustStore, certificate_findings, cipher_findings, describe_certificate,
    protocol_findings, trust_findings,
};
use testls_probe::{
    ProtocolSupport, Transport, detect_protocols, enumerate_ciphers, fetch_certificates,
};
use testls_report::text::{self, CertificateSection, CipherSection};
use testls_report::{ColorChoice, Painter};
use testls_wire::ProtocolVersion;

use target::{Host, Target};

/// TLS/SSL scanner inspired by testssl.sh.
#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Target: host, host:port, [ipv6]:port, or https:// URL.
    target: Target,

    /// Server name to send in SNI (defaults to the target host name).
    #[arg(long)]
    sni: Option<String>,

    /// TCP connect timeout in seconds.
    #[arg(long, default_value_t = 5, value_name = "SECS")]
    connect_timeout: u64,

    /// Per-probe read timeout in seconds.
    #[arg(long, default_value_t = 10, value_name = "SECS")]
    read_timeout: u64,

    /// Exit with status 1 if any finding is at least this severe.
    #[arg(long, default_value_t = Severity::High, value_name = "SEVERITY",
          value_parser = clap::builder::PossibleValuesParser::new(Severity::ALL.map(Severity::as_str))
              .map(|s| s.parse::<Severity>().expect("listed value")))]
    fail_on: Severity,

    /// Trust only the root certificates in this PEM file instead of the
    /// bundled Mozilla roots.
    #[arg(long, value_name = "FILE")]
    ca_file: Option<PathBuf>,

    /// Colour the output: `auto` colours only on a terminal when `NO_COLOR`
    /// is unset.
    #[arg(long, default_value_t = ColorChoice::Auto, value_name = "WHEN",
          value_parser = clap::builder::PossibleValuesParser::new(ColorChoice::ALL.map(ColorChoice::as_str))
              .map(|s| s.parse::<ColorChoice>().expect("listed value")))]
    color: ColorChoice,
}

/// Resolves the target to the first socket address it maps to.
async fn resolve(target: &Target) -> std::io::Result<SocketAddr> {
    match &target.host {
        Host::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
        Host::Name(name) => tokio::net::lookup_host((name.as_str(), target.port))
            .await?
            .next()
            .ok_or_else(|| std::io::Error::other("no addresses found")),
    }
}

/// Reports whether stdout is a terminal that can render ANSI colour.
///
/// On Windows this also turns on virtual terminal processing for the
/// console; a console that refuses it counts as not colour-capable, so
/// `--color auto` falls back to plain text there.
fn colour_terminal() -> bool {
    std::io::stdout().is_terminal() && anstyle_query::windows::enable_ansi_colors().unwrap_or(true)
}

/// Runs the scan and maps the outcome to the exit code contract.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let paint = Painter::new(cli.color.enabled(
        cli.color != ColorChoice::Never && colour_terminal(),
        std::env::var("NO_COLOR").ok().as_deref(),
    ));
    let store = match &cli.ca_file {
        Some(path) => match std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|pem| TrustStore::from_pem(&pem))
        {
            Ok(store) => store,
            Err(e) => {
                eprintln!("error: cannot load {}: {e}", path.display());
                return ExitCode::from(2);
            }
        },
        None => TrustStore::webpki(),
    };
    let addr = match resolve(&cli.target).await {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: cannot resolve {}: {e}", cli.target);
            return ExitCode::from(2);
        }
    };
    let sni = cli.sni.as_deref().or(cli.target.default_sni());

    let mut transport = Transport::new(addr);
    transport.connect_timeout = Duration::from_secs(cli.connect_timeout);
    transport.read_timeout = Duration::from_secs(cli.read_timeout);

    print!("{}", text::header(&cli.target.to_string(), addr, sni));
    println!();
    let protocols = detect_protocols(&transport, sni).await;
    print!("{}", text::protocols(&protocols, paint));
    if protocols
        .iter()
        .all(|r| matches!(r.support, ProtocolSupport::Error(_)))
    {
        eprintln!("error: no protocol could be tested");
        return ExitCode::from(2);
    }
    let mut findings = protocol_findings(&protocols);

    for r in &protocols {
        if r.support != ProtocolSupport::Supported {
            continue;
        }
        let section = cipher_section(&transport, r.version, sni).await;
        println!();
        print!("{}", text::ciphers(&section, paint));
        findings.extend(section_findings(&section));
    }

    let host = sni.map_or_else(|| addr.ip().to_string(), str::to_owned);
    let (section, cert_findings) = certificate_section(&transport, sni, &host, &store).await;
    println!();
    print!("{}", text::certificate(&section, paint));
    findings.extend(cert_findings);

    findings.retain(|f| f.severity > Severity::Ok);
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    println!();
    print!("{}", text::findings(&findings, paint));

    if findings.iter().any(|f| f.severity >= cli.fail_on) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Enumerates the cipher suites of one protocol `version`.
async fn cipher_section(
    transport: &Transport,
    version: ProtocolVersion,
    sni: Option<&str>,
) -> CipherSection {
    CipherSection {
        version,
        outcome: enumerate_ciphers(transport, version, sni)
            .await
            .map_err(|e| e.to_string()),
    }
}

/// Findings for one cipher section; a failed enumeration is informational.
fn section_findings(section: &CipherSection) -> Vec<Finding> {
    match &section.outcome {
        Ok(c) => cipher_findings(c),
        Err(e) => vec![Finding::new(
            "cipher.error",
            Severity::Info,
            format!("{} ciphers could not be enumerated: {e}", section.version),
        )],
    }
}

/// Fetches and checks the certificate chain, returning its description and
/// findings.
///
/// The leaf is checked against `host`, the SNI name or the target IP.
async fn certificate_section(
    transport: &Transport,
    sni: Option<&str>,
    host: &str,
    store: &TrustStore,
) -> (Result<CertificateSection, String>, Vec<Finding>) {
    let chain = match fetch_certificates(transport, sni).await {
        Ok(chain) => chain,
        Err(e) => {
            let finding = Finding::new(
                "cert.error",
                Severity::Info,
                format!("certificate could not be retrieved: {e}"),
            );
            return (Err(e.to_string()), vec![finding]);
        }
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(i64::MAX);
    let mut findings = certificate_findings(&chain.certificates, Some(host), now);
    findings.extend(trust_findings(&chain.certificates, now, store));
    let section = CertificateSection {
        version: chain.version,
        certificates: chain
            .certificates
            .iter()
            .map(|der| describe_certificate(der))
            .collect(),
    };
    (Ok(section), findings)
}
