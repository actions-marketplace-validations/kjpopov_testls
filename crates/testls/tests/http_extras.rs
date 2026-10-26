//! End-to-end scan of an in-process TLS server that sends banners,
//! `Alt-Svc` and cookies, checking the JSON report and finding ids.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::process::Command;
use std::sync::Arc;
use std::thread;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};

/// Test certificate for `localhost`, shared with the probe crate.
const CERT: &[u8] = include_bytes!("../../testls-probe/src/testdata/localhost.cert.der");
/// Private key for [`CERT`].
const KEY: &[u8] = include_bytes!("../../testls-probe/src/testdata/localhost.key.der");

/// HTTP reply with a versioned banner, `Alt-Svc` and two weak cookies.
const REPLY: &[u8] = b"HTTP/1.1 200 OK\r\n\
Server: nginx/1.25.3\r\n\
X-Powered-By: PHP/8.3\r\n\
Alt-Svc: h3=\":443\"; ma=60\r\n\
Set-Cookie: session=abc; HttpOnly\r\n\
Set-Cookie: theme=dark; Secure; SameSite=None\r\n\
Content-Length: 0\r\n\
Connection: close\r\n\r\n";

/// Starts a TLS server on a free port that answers every request with
/// [`REPLY`]; failed handshakes from the raw probes are ignored.
fn serve() -> SocketAddr {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(CERT.to_vec())],
            PrivateKeyDer::try_from(KEY.to_vec()).expect("key"),
        )
        .expect("certificate");
    let config = Arc::new(config);
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let config = Arc::clone(&config);
            thread::spawn(move || handle(config, stream));
        }
    });
    addr
}

/// Completes one TLS connection, reads the request head and sends [`REPLY`].
fn handle(config: Arc<ServerConfig>, stream: TcpStream) {
    let Ok(conn) = ServerConnection::new(config) else {
        return;
    };
    let mut tls = StreamOwned::new(conn, stream);
    let mut head = Vec::new();
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match tls.read(&mut buf) {
            Ok(0) | Err(_) => return,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    let _ = tls.write_all(REPLY);
    tls.conn.send_close_notify();
    let _ = tls.flush();
}

/// Banners, `Alt-Svc` and cookie attributes appear in the JSON report and
/// produce their findings.
#[test]
fn json_reports_http_extras() {
    let addr = serve();
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .args([
            "--sni",
            "localhost",
            "--format",
            "json",
            "--fail-on",
            "critical",
        ])
        .output()
        .expect("run testls");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    let http = &v["http"];
    assert_eq!(http["status"], 200, "{http}");
    assert_eq!(
        http["banners"]["server"],
        serde_json::json!(["nginx/1.25.3"])
    );
    assert_eq!(
        http["banners"]["x-powered-by"],
        serde_json::json!(["PHP/8.3"])
    );
    assert_eq!(
        http["alt_svc"],
        serde_json::json!([{"protocol": "h3", "authority": ":443", "max_age": 60}])
    );
    assert_eq!(
        http["cookies"],
        serde_json::json!([
            {"name": "session", "secure": false, "http_only": true, "same_site": null},
            {"name": "theme", "secure": true, "http_only": false, "same_site": "None"},
        ])
    );
    let ids: Vec<&str> = v["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .filter_map(|f| f["id"].as_str())
        .collect();
    for id in [
        "header.banner",
        "cookie.insecure",
        "cookie.no_httponly",
        "cookie.no_samesite",
    ] {
        assert!(ids.contains(&id), "missing {id} in {ids:?}");
    }
    assert!(!ids.contains(&"header.alt_svc_invalid"), "{ids:?}");
}

/// `--resolve` connects a host name that does not exist to the local
/// server and keeps the name as target and SNI.
#[test]
fn resolve_pins_address() {
    let addr = serve();
    let target = format!("pinned.invalid:{}", addr.port());
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(&target)
        .args(["--resolve", &format!("{target}:{}", addr.ip())])
        .args(["--format", "json", "--fail-on", "critical"])
        .output()
        .expect("run testls");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    let scanned = &v["target"];
    assert_eq!(scanned["input"], target);
    assert_eq!(scanned["address"], addr.to_string());
    assert_eq!(scanned["sni"], "pinned.invalid");
    assert_eq!(v["http"]["status"], 200, "{}", v["http"]);
}

/// Starts an HTTP `CONNECT` proxy on a free port that tunnels to any
/// address and records each request line it accepts.
fn proxy() -> (SocketAddr, Arc<std::sync::Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("address");
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    thread::spawn(move || {
        for client in listener.incoming().flatten() {
            let log = Arc::clone(&log);
            thread::spawn(move || tunnel(client, &log));
        }
    });
    (addr, seen)
}

/// Reads one `CONNECT` request from `client`, connects to its target and
/// relays bytes both ways until either side closes.
fn tunnel(mut client: TcpStream, log: &std::sync::Mutex<Vec<String>>) {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match client.read(&mut byte) {
            Ok(1) => head.push(byte[0]),
            _ => return,
        }
    }
    let head = String::from_utf8_lossy(&head);
    let line = head.lines().next().unwrap_or_default().to_owned();
    let Some(authority) = line
        .strip_prefix("CONNECT ")
        .and_then(|l| l.strip_suffix(" HTTP/1.1"))
    else {
        return;
    };
    let Ok(mut server) = TcpStream::connect(authority) else {
        let _ = client.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
        return;
    };
    log.lock().expect("log").push(line);
    let _ = client.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
    let (Ok(mut client_r), Ok(mut server_w)) = (client.try_clone(), server.try_clone()) else {
        return;
    };
    let up = thread::spawn(move || {
        let _ = std::io::copy(&mut client_r, &mut server_w);
        let _ = server_w.shutdown(std::net::Shutdown::Write);
    });
    let _ = std::io::copy(&mut server, &mut client);
    let _ = client.shutdown(std::net::Shutdown::Write);
    let _ = up.join();
}

/// `--proxy` tunnels every probe through the proxy to the scanned address;
/// an unresolvable proxy is a scan error.
#[test]
fn proxy_tunnels_scan() {
    let addr = serve();
    let (proxy, seen) = proxy();
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .args(["--sni", "localhost", "--proxy", &format!("http://{proxy}")])
        .args(["--format", "json", "--fail-on", "critical"])
        .output()
        .expect("run testls");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    assert_eq!(v["target"]["address"], addr.to_string());
    assert_eq!(v["http"]["status"], 200, "{}", v["http"]);
    let seen = seen.lock().expect("log");
    assert!(seen.len() > 1, "{seen:?}");
    let expected = format!("CONNECT {addr} HTTP/1.1");
    assert!(seen.iter().all(|l| *l == expected), "{seen:?}");

    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr.to_string())
        .args(["--proxy", "proxy.invalid:3128"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("cannot resolve proxy"), "{stderr}");
}

/// `--source-ip` scans from the given address and rejects targets that
/// have no address in its family as a scan error.
#[test]
fn source_ip() {
    let addr = serve();
    let run = |source: &str| {
        Command::new(env!("CARGO_BIN_EXE_testls"))
            .arg(addr.to_string())
            .args(["--source-ip", source])
            .args(["--format", "json", "--fail-on", "critical"])
            .output()
            .expect("run testls")
    };
    let out = run("127.0.0.1");
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("JSON output");
    assert_eq!(v["http"]["status"], 200, "{}", v["http"]);

    let out = run("::1");
    assert_eq!(out.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        format!("{stdout}{stderr}").contains("--source-ip ::1"),
        "{stdout}{stderr}"
    );
}
