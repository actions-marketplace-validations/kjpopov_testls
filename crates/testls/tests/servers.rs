//! End-to-end scans against the local servers in `tests/servers`.
//!
//! Ignored by default; start the servers first (see
//! `tests/servers/compose.yaml`), then run with `--ignored`.

use std::net::TcpStream;
use std::process::Command;
use std::thread::sleep;
use std::time::{Duration, Instant};

/// Exit code and captured stdout of one `testls` run.
struct Scan {
    code: i32,
    stdout: String,
}

impl Scan {
    /// Returns the first trimmed stdout line starting with `prefix`; panics if none.
    fn line(&self, prefix: &str) -> &str {
        self.stdout
            .lines()
            .map(str::trim)
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("no line starting with {prefix:?} in:\n{}", self.stdout))
    }

    /// Reports whether stdout contains `needle` anywhere.
    fn has(&self, needle: &str) -> bool {
        self.stdout.contains(needle)
    }
}

/// Blocks until `addr` accepts TCP connections; fails after 30 seconds.
fn wait_for(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(addr).is_err() {
        assert!(Instant::now() < deadline, "server {addr} did not come up");
        sleep(Duration::from_millis(200));
    }
}

/// Waits for the server at `addr`, then runs the `testls` binary against it.
fn scan(addr: &str, args: &[&str]) -> Scan {
    wait_for(addr);
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .arg(addr)
        .args(args)
        .output()
        .expect("run testls");
    Scan {
        code: out.status.code().expect("exit code"),
        stdout: String::from_utf8(out.stdout).expect("utf-8 output"),
    }
}

/// TLS 1.0–1.2 server with every cipher enabled: expects deprecated
/// protocols, client cipher order, an anonymous suite, and exit code 1.
#[test]
#[ignore = "needs tests/servers running"]
fn legacy_server() {
    let s = scan("127.0.0.1:14433", &[]);
    assert_eq!(s.line("SSLv3"), "SSLv3    not offered");
    assert_eq!(s.line("TLSv1.0 "), "TLSv1.0  offered");
    assert_eq!(s.line("TLSv1.1 "), "TLSv1.1  offered");
    assert_eq!(s.line("TLSv1.2 "), "TLSv1.2  offered");
    assert_eq!(s.line("TLSv1.3 "), "TLSv1.3  not offered");
    assert_eq!(s.line("Ciphers TLSv1.2"), "Ciphers TLSv1.2 client order");
    assert!(s.has("0x0034  TLS_DH_anon_WITH_AES_128_CBC_SHA"));
    assert!(s.has("critical TLSv1.2 TLS_DH_anon_WITH_AES_128_CBC_SHA: anonymous"));
    assert!(s.has("medium   TLSv1.0 offered: deprecated (RFC 8996)"));
    assert!(s.has("info     TLSv1.2: server follows the client's cipher order"));
    assert_eq!(
        s.code, 1,
        "critical findings must fail the default threshold"
    );
}

/// TLS 1.2+ server with strong suites in server order: expects no findings
/// even at `--fail-on info`, and exit code 0.
#[test]
#[ignore = "needs tests/servers running"]
fn modern_server() {
    let s = scan("127.0.0.1:14434", &["--fail-on", "info"]);
    assert_eq!(s.line("TLSv1.1 "), "TLSv1.1  not offered");
    assert_eq!(s.line("TLSv1.2 "), "TLSv1.2  offered");
    assert_eq!(s.line("TLSv1.3 "), "TLSv1.3  offered");
    assert_eq!(s.line("Ciphers TLSv1.2"), "Ciphers TLSv1.2 server order");
    assert_eq!(s.line("Ciphers TLSv1.3"), "Ciphers TLSv1.3 server order");
    assert!(s.has("0x1302  TLS_AES_256_GCM_SHA384"));
    assert!(s.has("0xcca8  TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256"));
    assert_eq!(s.line("Findings"), "Findings");
    assert!(s.stdout.trim_end().ends_with("none"), "{}", s.stdout);
    assert_eq!(s.code, 0);
}

/// A closed port must be reported as a scan error (exit code 2). Port 1 on
/// loopback is closed, so no server is needed.
#[test]
fn unreachable_is_scan_error() {
    let out = Command::new(env!("CARGO_BIN_EXE_testls"))
        .args(["127.0.0.1:1", "--connect-timeout", "2"])
        .output()
        .expect("run testls");
    assert_eq!(out.status.code(), Some(2));
}
