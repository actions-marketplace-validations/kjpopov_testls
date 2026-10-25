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
    http_findings, key_exchange_findings, ocsp_findings, protocol_findings, trust_findings,
    verify_ocsp_response,
};
use testls_probe::{
    HttpResponse, ProtocolSupport, Transport, detect_protocols, enumerate_ciphers,
    fetch_certificates, fetch_http_headers, probe_key_exchange,
};
use testls_report::text::{self, CertificateSection, CipherSection, KeyExchangeSection};
use testls_report::{ColorChoice, Format, Painter, json};
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

    /// Trust the operating system's root certificates instead of the
    /// bundled Mozilla roots (`SSL_CERT_FILE` / `SSL_CERT_DIR` override the
    /// platform store).
    #[arg(long, conflicts_with = "ca_file")]
    system_roots: bool,

    /// Colour the output: `auto` colours only on a terminal when `NO_COLOR`
    /// is unset.
    #[arg(long, default_value_t = ColorChoice::Auto, value_name = "WHEN",
          value_parser = clap::builder::PossibleValuesParser::new(ColorChoice::ALL.map(ColorChoice::as_str))
              .map(|s| s.parse::<ColorChoice>().expect("listed value")))]
    color: ColorChoice,

    /// Output format: `text` prints sections as they finish, `json` prints
    /// one document at the end.
    #[arg(long, default_value_t = Format::Text, value_name = "FORMAT",
          value_parser = clap::builder::PossibleValuesParser::new(Format::ALL.map(Format::as_str))
              .map(|s| s.parse::<Format>().expect("listed value")))]
    format: Format,
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
    let store = match trust_store(&cli) {
        Ok(store) => store,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
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

    let started_at = unix_now();
    let target = cli.target.to_string();
    let is_text = cli.format == Format::Text;
    let show = |section: String| {
        if is_text {
            print!("{section}");
        }
    };

    show(text::header(&target, addr, sni));
    let protocols = detect_protocols(&transport, sni).await;
    show(format!("\n{}", text::protocols(&protocols, paint)));
    if protocols
        .iter()
        .all(|r| matches!(r.support, ProtocolSupport::Error(_)))
    {
        eprintln!("error: no protocol could be tested");
        return ExitCode::from(2);
    }
    let mut findings = protocol_findings(&protocols);

    let mut ciphers = Vec::new();
    let mut key_exchange = Vec::new();
    for r in &protocols {
        if r.support != ProtocolSupport::Supported {
            continue;
        }
        let section = cipher_section(&transport, r.version, sni).await;
        show(format!("\n{}", text::ciphers(&section, paint)));
        findings.extend(section_findings(&section));
        let kx = key_exchange_section(&transport, &section, sni).await;
        show(format!("\n{}", text::key_exchange(&kx, paint)));
        findings.extend(kx_findings(&kx));
        ciphers.push(section);
        key_exchange.push(kx);
    }

    let host = sni.map_or_else(|| addr.ip().to_string(), str::to_owned);
    let (certificate, cert_findings) = certificate_section(&transport, sni, &host, &store).await;
    show(format!("\n{}", text::certificate(&certificate, paint)));
    findings.extend(cert_findings);

    let (http, http_findings) = http_section(&transport, sni).await;
    show(format!("\n{}", text::http(&http, paint)));
    findings.extend(http_findings);

    findings.retain(|f| f.severity > Severity::Ok);
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    show(format!("\n{}", text::findings(&findings, paint)));

    if cli.format == Format::Json {
        print!(
            "{}",
            json::render(&json::Report {
                target: &target,
                addr,
                sni,
                started_at,
                protocols: &protocols,
                ciphers: &ciphers,
                key_exchange: &key_exchange,
                certificate: &certificate,
                http: &http,
                findings: &findings,
            })
        );
    }

    if findings.iter().any(|f| f.severity >= cli.fail_on) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

/// Loads the trust store selected on the command line: a `--ca-file`
/// bundle, the system roots, or the bundled Mozilla roots. Partial errors
/// while reading the system roots are printed as warnings.
fn trust_store(cli: &Cli) -> Result<TrustStore, String> {
    if let Some(path) = &cli.ca_file {
        std::fs::read(path)
            .map_err(|e| e.to_string())
            .and_then(|pem| TrustStore::from_pem(&pem))
            .map_err(|e| format!("cannot load {}: {e}", path.display()))
    } else if cli.system_roots {
        let (store, warnings) =
            TrustStore::system().map_err(|e| format!("cannot load system roots: {e}"))?;
        for warning in warnings {
            eprintln!("warning: system roots: {warning}");
        }
        Ok(store)
    } else {
        Ok(TrustStore::webpki())
    }
}

/// Current time as a Unix timestamp.
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_secs()).ok())
        .unwrap_or(i64::MAX)
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

/// Probes the supported groups and DH parameter size of one protocol
/// `version`, using the suites accepted in the cipher `section`.
///
/// When cipher enumeration failed the accepted suites are unknown, so the
/// key exchange section reports that instead of probing.
async fn key_exchange_section(
    transport: &Transport,
    section: &CipherSection,
    sni: Option<&str>,
) -> KeyExchangeSection {
    let outcome = match &section.outcome {
        Ok(c) => probe_key_exchange(transport, section.version, &c.suites, sni)
            .await
            .map_err(|e| e.to_string()),
        Err(_) => Err("cipher enumeration failed".to_owned()),
    };
    KeyExchangeSection {
        version: section.version,
        outcome,
    }
}

/// Findings for one key exchange section; a failed probe is informational.
fn kx_findings(section: &KeyExchangeSection) -> Vec<Finding> {
    match &section.outcome {
        Ok(k) => key_exchange_findings(k),
        Err(e) => vec![Finding::new(
            "group.error",
            Severity::Info,
            format!("{} key exchange could not be probed: {e}", section.version),
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
    let now = unix_now();
    let mut findings = certificate_findings(&chain.certificates, Some(host), now);
    findings.extend(trust_findings(&chain.certificates, now, store));
    let ocsp_response = chain.ocsp_response.as_deref();
    findings.extend(ocsp_findings(&chain.certificates, ocsp_response, now));
    let ocsp = ocsp_response.map(|der| verify_ocsp_response(der, &chain.certificates, now));
    let section = CertificateSection {
        version: chain.version,
        certificates: chain
            .certificates
            .iter()
            .map(|der| describe_certificate(der))
            .collect(),
        ocsp,
    };
    (Ok(section), findings)
}

/// Fetches the reply to `GET /` and checks HSTS and security headers.
///
/// A server that does not speak HTTP is common for non-web TLS services,
/// so a failed fetch is informational.
async fn http_section(
    transport: &Transport,
    sni: Option<&str>,
) -> (Result<HttpResponse, String>, Vec<Finding>) {
    match fetch_http_headers(transport, sni).await {
        Ok(response) => {
            let findings = http_findings(&response);
            (Ok(response), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "http.error",
                Severity::Info,
                format!("HTTP headers could not be retrieved: {e}"),
            );
            (Err(e.to_string()), vec![finding])
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the scan helpers.

    use super::*;

    /// A failed cipher enumeration is reported in the key exchange section
    /// without probing the server.
    #[tokio::test]
    async fn key_exchange_after_cipher_error() {
        // Nothing listens on port 9 of the discard address; no probe is sent.
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let ciphers = CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Err("timed out".to_owned()),
        };
        let kx = key_exchange_section(&transport, &ciphers, None).await;
        assert_eq!(kx.version, ProtocolVersion::TLS12);
        assert_eq!(
            kx.outcome.as_ref().unwrap_err(),
            "cipher enumeration failed"
        );
        assert_eq!(kx_findings(&kx)[0].id, "group.error");
    }

    /// A failed HTTP fetch becomes an informational finding.
    #[tokio::test]
    async fn http_error_is_info() {
        // Nothing listens on port 9 of the discard address.
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let (http, findings) = http_section(&transport, None).await;
        assert!(http.is_err());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "http.error");
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
