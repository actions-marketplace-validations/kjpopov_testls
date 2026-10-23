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
    Finding, Severity, TrustStore, certificate_findings, cipher_findings, cipher_name,
    cipher_severity, describe_certificate, protocol_findings, protocol_severity, trust_findings,
};
use testls_probe::{
    CipherOrder, ProtocolSupport, Transport, detect_protocols, enumerate_ciphers,
    fetch_certificates,
};
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

/// Runs the scan and maps the outcome to the exit code contract.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    let paint = Painter::new(cli.color.enabled(
        std::io::stdout().is_terminal(),
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

    println!("Target: {} ({addr})", cli.target);
    println!("SNI:    {}", sni.unwrap_or("(none)"));
    println!();
    println!("{}", paint.heading("Protocols"));
    let protocols = detect_protocols(&transport, sni).await;
    if protocols
        .iter()
        .all(|r| matches!(r.support, ProtocolSupport::Error(_)))
    {
        eprintln!("error: no protocol could be tested");
        return ExitCode::from(2);
    }
    let mut findings = protocol_findings(&protocols);
    for r in &protocols {
        let status = match &r.support {
            ProtocolSupport::Supported => paint.severity(protocol_severity(r.version).0, "offered"),
            ProtocolSupport::NotSupported => "not offered".to_owned(),
            ProtocolSupport::Error(e) => format!("error: {e}"),
        };
        println!("  {:<8} {status}", r.version.to_string());
    }

    for r in &protocols {
        if r.support != ProtocolSupport::Supported {
            continue;
        }
        println!();
        findings.extend(cipher_section(&transport, r.version, sni, paint).await);
    }

    println!();
    let host = sni.map_or_else(|| addr.ip().to_string(), str::to_owned);
    findings.extend(certificate_section(&transport, sni, &host, &store, paint).await);

    findings.retain(|f| f.severity > Severity::Ok);
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    println!();
    println!("{}", paint.heading("Findings"));
    if findings.is_empty() {
        println!("  {}", paint.severity(Severity::Ok, "none"));
    }
    for f in &findings {
        let label = format!("{:<8}", f.severity.as_str());
        println!("  {} {}", paint.severity(f.severity, &label), f.message);
    }

    if findings.iter().any(|f| f.severity >= cli.fail_on) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Enumerates and prints the cipher suites of one protocol `version`,
/// coloured by severity, returning their findings.
async fn cipher_section(
    transport: &Transport,
    version: ProtocolVersion,
    sni: Option<&str>,
    paint: Painter,
) -> Vec<Finding> {
    match enumerate_ciphers(transport, version, sni).await {
        Ok(c) => {
            let order = match c.order {
                CipherOrder::Server => "server order",
                CipherOrder::Client => "client order",
                CipherOrder::NotApplicable => "",
            };
            println!("{} {order}", paint.heading(&format!("Ciphers {version}")));
            for &id in &c.suites {
                let (severity, _, _) = cipher_severity(version, id);
                println!("  {}", paint.severity(severity, &cipher_label(version, id)));
            }
            cipher_findings(&c)
        }
        Err(e) => {
            println!(
                "{}: error: {e}",
                paint.heading(&format!("Ciphers {version}"))
            );
            vec![Finding::new(
                "cipher.error",
                Severity::Info,
                format!("{version} ciphers could not be enumerated: {e}"),
            )]
        }
    }
}

/// Fetches and prints the certificate chain, returning its findings.
///
/// The leaf is checked against `host`, the SNI name or the target IP;
/// headings are styled with `paint`.
async fn certificate_section(
    transport: &Transport,
    sni: Option<&str>,
    host: &str,
    store: &TrustStore,
    paint: Painter,
) -> Vec<Finding> {
    let chain = match fetch_certificates(transport, sni).await {
        Ok(chain) => chain,
        Err(e) => {
            println!("{}: error: {e}", paint.heading("Certificate"));
            return vec![Finding::new(
                "cert.error",
                Severity::Info,
                format!("certificate could not be retrieved: {e}"),
            )];
        }
    };
    println!(
        "{}",
        paint.heading(&format!("Certificate ({})", chain.version))
    );
    for (position, der) in chain.certificates.iter().enumerate() {
        match describe_certificate(der) {
            Ok(info) => {
                println!("  #{position} {}", info.subject);
                println!("     issuer  {}", info.issuer);
                println!("     valid   {} to {}", info.not_before, info.not_after);
                if !info.names.is_empty() {
                    println!("     names   {}", info.names.join(", "));
                }
                println!("     key     {}", info.key);
            }
            Err(e) => println!("  #{position} cannot be parsed: {e}"),
        }
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(i64::MAX);
    let mut findings = certificate_findings(&chain.certificates, Some(host), now);
    findings.extend(trust_findings(&chain.certificates, now, store));
    findings
}

/// Formats a cipher suite id and name for the cipher listing.
fn cipher_label(version: ProtocolVersion, id: u32) -> String {
    let name = cipher_name(version, id);
    if version == ProtocolVersion::SSL2 {
        format!("0x{id:06x}  {name}")
    } else {
        format!("0x{id:04x}  {name}")
    }
}
