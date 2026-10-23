//! `testls` command-line interface.

mod target;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use clap::builder::TypedValueParser as _;
use testls_checks::{Finding, Severity, cipher_findings, cipher_name, protocol_findings};
use testls_probe::{CipherOrder, ProtocolSupport, Transport, detect_protocols, enumerate_ciphers};
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
}

async fn resolve(target: &Target) -> std::io::Result<SocketAddr> {
    match &target.host {
        Host::Ip(ip) => Ok(SocketAddr::new(*ip, target.port)),
        Host::Name(name) => tokio::net::lookup_host((name.as_str(), target.port))
            .await?
            .next()
            .ok_or_else(|| std::io::Error::other("no addresses found")),
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
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
    println!("Protocols");
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
            ProtocolSupport::Supported => "offered".to_owned(),
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
        match enumerate_ciphers(&transport, r.version, sni).await {
            Ok(c) => {
                let order = match c.order {
                    CipherOrder::Server => "server order",
                    CipherOrder::Client => "client order",
                    CipherOrder::NotApplicable => "",
                };
                println!("Ciphers {} {order}", r.version);
                for &id in &c.suites {
                    println!("  {}", cipher_label(r.version, id));
                }
                findings.extend(cipher_findings(&c));
            }
            Err(e) => {
                println!("Ciphers {}: error: {e}", r.version);
                findings.push(Finding::new(
                    "cipher.error",
                    Severity::Info,
                    format!("{} ciphers could not be enumerated: {e}", r.version),
                ));
            }
        }
    }

    findings.retain(|f| f.severity > Severity::Ok);
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    println!();
    println!("Findings");
    if findings.is_empty() {
        println!("  none");
    }
    for f in &findings {
        println!("  {:<8} {}", f.severity.as_str(), f.message);
    }

    if findings.iter().any(|f| f.severity >= cli.fail_on) {
        ExitCode::from(1)
    } else {
        ExitCode::SUCCESS
    }
}

fn cipher_label(version: ProtocolVersion, id: u32) -> String {
    let name = cipher_name(version, id);
    if version == ProtocolVersion::SSL2 {
        format!("0x{id:06x}  {name}")
    } else {
        format!("0x{id:04x}  {name}")
    }
}
