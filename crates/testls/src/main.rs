//! `testls` command-line interface.

mod target;

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use clap::Parser;
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
                for id in c.suites {
                    println!("  {}", cipher_label(r.version, id));
                }
            }
            Err(e) => println!("Ciphers {}: error: {e}", r.version),
        }
    }
    ExitCode::SUCCESS
}

fn cipher_label(version: ProtocolVersion, id: u32) -> String {
    if version == ProtocolVersion::SSL2 {
        let name = match id {
            0x01_0080 => "SSL_CK_RC4_128_WITH_MD5",
            0x02_0080 => "SSL_CK_RC4_128_EXPORT40_WITH_MD5",
            0x03_0080 => "SSL_CK_RC2_128_CBC_WITH_MD5",
            0x04_0080 => "SSL_CK_RC2_128_CBC_EXPORT40_WITH_MD5",
            0x05_0080 => "SSL_CK_IDEA_128_CBC_WITH_MD5",
            0x06_0040 => "SSL_CK_DES_64_CBC_WITH_MD5",
            0x07_00c0 => "SSL_CK_DES_192_EDE3_CBC_WITH_MD5",
            _ => "unknown",
        };
        return format!("0x{id:06x}  {name}");
    }
    let name = u16::try_from(id)
        .ok()
        .and_then(testls_data::cipher_suite)
        .map_or("unknown", |c| c.name);
    format!("0x{id:04x}  {name}")
}
