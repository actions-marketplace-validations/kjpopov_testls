//! `testls` command-line interface.

mod target;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
use testls_probe::{ProtocolSupport, Transport, detect_protocols};

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
    for r in detect_protocols(&transport, sni).await {
        let status = match &r.support {
            ProtocolSupport::Supported => "offered".to_owned(),
            ProtocolSupport::NotSupported => "not offered".to_owned(),
            ProtocolSupport::Error(e) => format!("error: {e}"),
        };
        println!("  {:<8} {status}", r.version.to_string());
    }
    ExitCode::SUCCESS
}
