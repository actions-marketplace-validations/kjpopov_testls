//! `testls` command-line interface.

mod revocation;
mod target;

use std::fmt::Write as _;
use std::io::IsTerminal as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::builder::TypedValueParser as _;
use clap::{Parser, Subcommand};
use testls_checks::{
    Finding, RevocationCheck, Severity, TrustStore, Vulnerability, assess_vulnerabilities,
    baseline_findings, certificate_findings, cipher_findings, describe_certificate,
    details_findings, explain, explanations, http_extra_findings, http_findings,
    intolerance_findings, is_trusted, key_exchange_findings, ocsp_findings, post_quantum_readiness,
    protocol_findings, revocation_findings, revocation_urls, trust_findings, verify_ocsp_response,
    vulnerability_findings,
};
use testls_probe::{
    CipherResult, Fetcher, HandshakeDetails, HttpResponse, Intolerance, KeyExchangeResult,
    ProtocolResult, ProtocolSupport, Transport, detect_protocols, enumerate_ciphers,
    fetch_certificates, fetch_http_headers, probe_details, probe_features, probe_intolerance,
    probe_key_exchange,
};
use testls_report::text::{self, CertificateSection, CipherSection, KeyExchangeSection};
use testls_report::{ColorChoice, Format, Painter, json};
use testls_wire::ProtocolVersion;

use target::{Host, Target, TargetSpec};

/// TLS/SSL scanner inspired by testssl.sh.
#[derive(Debug, Parser)]
#[command(
    version,
    about,
    args_conflicts_with_subcommands = true,
    subcommand_negates_reqs = true
)]
struct Cli {
    /// Extra commands; without one, `testls` scans the target.
    #[command(subcommand)]
    command: Option<Command>,

    /// Targets: host, host:port, [ipv6]:port, https:// URL, or a CIDR range
    /// such as `192.0.2.0/28` or `[2001:db8::/120]:8443` (at most 16 host
    /// bits). Several targets are scanned one after another.
    #[arg(required_unless_present = "file", value_name = "TARGET")]
    targets: Vec<TargetSpec>,

    /// Read more targets from FILE, one per line in the same forms; blank
    /// lines and lines starting with `#` are skipped.
    #[arg(long, value_name = "FILE")]
    file: Option<PathBuf>,

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

    /// Also ask the certificate issuer's OCSP responder, falling back to its
    /// CRLs, whether the leaf certificate is revoked. This contacts servers
    /// other than the target.
    #[arg(long)]
    revocation: bool,

    /// Scan every A/AAAA address a host name resolves to, and warn when
    /// the addresses differ in protocols, cipher suites or certificate.
    #[arg(long)]
    all_addresses: bool,

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

/// Subcommands besides the default scan.
#[derive(Debug, Subcommand)]
enum Command {
    /// Describe a finding id, or list all ids when none is given.
    Explain {
        /// Finding id as shown in brackets in the findings list.
        id: Option<String>,
    },
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

/// Resolves the target to every distinct socket address it maps to, in
/// resolver order.
async fn addresses(target: &Target) -> std::io::Result<Vec<SocketAddr>> {
    let Host::Name(name) = &target.host else {
        return Ok(vec![resolve(target).await?]);
    };
    let mut addrs = Vec::new();
    for addr in tokio::net::lookup_host((name.as_str(), target.port)).await? {
        if !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    if addrs.is_empty() {
        return Err(std::io::Error::other("no addresses found"));
    }
    Ok(addrs)
}

/// Reports whether stdout is a terminal that can render ANSI colour.
///
/// On Windows this also turns on virtual terminal processing for the
/// console; a console that refuses it counts as not colour-capable, so
/// `--color auto` falls back to plain text there.
fn colour_terminal() -> bool {
    std::io::stdout().is_terminal() && anstyle_query::windows::enable_ansi_colors().unwrap_or(true)
}

/// Prints `testls explain` output: exit code 0, or 2 for an unknown id.
fn explain_command(id: Option<&str>) -> ExitCode {
    match explain_text(id) {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

/// Text for `testls explain`: one finding in detail, or a list of all ids.
fn explain_text(id: Option<&str>) -> Result<String, String> {
    let Some(id) = id else {
        let width = explanations().iter().map(|e| e.id.len()).max().unwrap_or(0);
        let mut out = String::new();
        for e in explanations() {
            let _ = writeln!(out, "{:<width$}  {}", e.id, e.title);
        }
        return Ok(out);
    };
    let e = explain(id).ok_or_else(|| {
        format!("unknown finding id `{id}`; run `testls explain` to list all ids")
    })?;
    Ok(format!(
        "{}: {}\n\n{}\n\nReference: {}\n",
        e.id, e.title, e.rationale, e.reference
    ))
}

/// Runs the selected command and maps the outcome to the exit code contract.
#[tokio::main(flavor = "current_thread")]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match &cli.command {
        Some(Command::Explain { id }) => explain_command(id.as_deref()),
        None => scan_all(&cli).await,
    }
}

/// Collects the targets from the command line and `--file`, in that order,
/// with CIDR ranges expanded.
fn targets(cli: &Cli) -> Result<Vec<Target>, String> {
    let mut targets: Vec<Target> = cli.targets.iter().flat_map(|s| s.0.clone()).collect();
    if let Some(path) = &cli.file {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        targets.extend(parse_target_list(&text).map_err(|e| format!("{}:{e}", path.display()))?);
    }
    if targets.is_empty() {
        return Err("no targets given".to_owned());
    }
    Ok(targets)
}

/// Parses a target list: one target per line, skipping blank lines and
/// `#` comments. Errors name the 1-based line number.
fn parse_target_list(text: &str) -> Result<Vec<Target>, String> {
    text.lines()
        .enumerate()
        .map(|(n, line)| (n + 1, line.trim()))
        .filter(|(_, line)| !line.is_empty() && !line.starts_with('#'))
        .map(|(n, line)| {
            line.parse::<TargetSpec>()
                .map(|s| s.0)
                .map_err(|e| format!("{n}: {e}"))
        })
        .collect::<Result<Vec<_>, _>>()
        .map(|lists| lists.concat())
}

/// Scans every target in turn. The exit code is 2 if any scan failed,
/// else 1 if any target has a finding at or above `--fail-on`, else 0.
/// JSON output is one document for a single target and an array of
/// documents otherwise.
async fn scan_all(cli: &Cli) -> ExitCode {
    let (targets, store) = match targets(cli).and_then(|t| Ok((t, trust_store(cli)?))) {
        Ok(ready) => ready,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };
    let mut code = 0;
    let mut scans = 0;
    let mut documents = Vec::new();
    for target in &targets {
        let resolved = if cli.all_addresses {
            addresses(target).await
        } else {
            resolve(target).await.map(|addr| vec![addr])
        };
        let addrs = match resolved {
            Ok(addrs) => addrs,
            Err(e) => {
                scans += 1;
                code = code.max(Outcome::failed(target, &format!("cannot resolve: {e}")).code);
                continue;
            }
        };
        let mut profiles = Vec::new();
        for addr in addrs {
            if scans > 0 && cli.format == Format::Text {
                println!();
            }
            scans += 1;
            let outcome = scan(cli, &store, target, addr).await;
            code = code.max(outcome.code);
            documents.extend(outcome.json);
            profiles.extend(outcome.profile.map(|p| (addr, p)));
        }
        for warning in divergence(&profiles) {
            eprintln!("warning: {target}: {warning}");
        }
    }
    if cli.format == Format::Json {
        print!("{}", json_output(scans, &documents));
    }
    ExitCode::from(code)
}

/// What must match across the addresses of one host: offered protocols,
/// accepted cipher suites per protocol, and the leaf certificate.
#[derive(Debug, PartialEq, Eq)]
struct Profile {
    /// Protocol versions the address offers.
    protocols: Vec<ProtocolVersion>,
    /// Accepted cipher suites per protocol, sorted; `None` if enumeration
    /// failed.
    suites: Vec<(ProtocolVersion, Option<Vec<u32>>)>,
    /// DER of the leaf certificate, if one was retrieved.
    leaf: Option<Vec<u8>>,
}

/// Describes how each address differs from the first scanned address.
fn divergence(profiles: &[(SocketAddr, Profile)]) -> Vec<String> {
    let Some(((first_addr, first), rest)) = profiles.split_first() else {
        return Vec::new();
    };
    rest.iter()
        .filter_map(|(addr, p)| {
            let aspects: Vec<&str> = [
                (p.protocols != first.protocols, "protocols"),
                (p.suites != first.suites, "cipher suites"),
                (p.leaf != first.leaf, "certificate"),
            ]
            .into_iter()
            .filter_map(|(differs, aspect)| differs.then_some(aspect))
            .collect();
            (!aspects.is_empty())
                .then(|| format!("{addr} differs from {first_addr} in {}", aspects.join(", ")))
        })
        .collect()
}

/// Combines the JSON documents of a run: the document itself for one
/// target (nothing if its scan failed), else an array of the documents.
fn json_output(targets: usize, documents: &[String]) -> String {
    if targets == 1 {
        documents.concat()
    } else {
        json::render_array(documents)
    }
}

/// Result of scanning one target.
#[derive(Debug)]
struct Outcome {
    /// Exit code for this target alone (0, 1 or 2).
    code: u8,
    /// Rendered JSON document, when `--format json` and the scan ran.
    json: Option<String>,
    /// Summary compared across a host's addresses, when the scan ran.
    profile: Option<Profile>,
}

impl Outcome {
    /// A scan that failed before producing a report.
    fn failed(target: &Target, error: &str) -> Self {
        eprintln!("error: {target}: {error}");
        Self {
            code: 2,
            json: None,
            profile: None,
        }
    }
}

/// Builds the painter from `--color`, the terminal, and `NO_COLOR`.
fn painter(cli: &Cli) -> Painter {
    Painter::new(cli.color.enabled(
        cli.color != ColorChoice::Never && colour_terminal(),
        std::env::var("NO_COLOR").ok().as_deref(),
    ))
}

/// Builds the transport to `addr` with the timeouts in `cli`.
fn transport(cli: &Cli, addr: SocketAddr) -> Transport {
    let mut transport = Transport::new(addr);
    transport.connect_timeout = Duration::from_secs(cli.connect_timeout);
    transport.read_timeout = Duration::from_secs(cli.read_timeout);
    transport
}

/// Scans `scan_target` at `addr` with the options in `cli`.
async fn scan(cli: &Cli, store: &TrustStore, scan_target: &Target, addr: SocketAddr) -> Outcome {
    let paint = painter(cli);
    let sni = cli.sni.as_deref().or(scan_target.default_sni());

    let transport = transport(cli, addr);

    let started_at = unix_now();
    let target = scan_target.to_string();
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
        return Outcome::failed(scan_target, "no protocol could be tested");
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
    let post_quantum = post_quantum_readiness(&measured(&key_exchange));
    show(format!("\n{}", text::post_quantum(&post_quantum, paint)));

    let host = sni.map_or_else(|| addr.ip().to_string(), str::to_owned);
    let (certificate, cert_findings, chain) =
        certificate_section(&transport, sni, &host, store).await;
    show(format!("\n{}", text::certificate(&certificate, paint)));
    findings.extend(cert_findings);

    let revocation = if cli.revocation {
        let (section, revocation_findings) = revocation_section(&transport, chain.as_deref()).await;
        show(format!("\n{}", text::revocation(&section, paint)));
        findings.extend(revocation_findings);
        Some(section)
    } else {
        None
    };

    let (http, http_findings) = http_section(&transport, sni).await;
    show(format!("\n{}", text::http(&http, paint)));
    findings.extend(http_findings);

    let vulns = vulnerability_section(&transport, &protocols, &ciphers, &key_exchange, sni).await;
    show(format!("\n{}", text::vulnerabilities(&vulns, paint)));
    findings.extend(vulnerability_findings(&vulns));

    let (intolerance, intolerance_findings) = intolerance_section(&transport, &ciphers, sni).await;
    show(format!("\n{}", text::intolerance(&intolerance, paint)));
    findings.extend(intolerance_findings);

    let (details, details_findings) = details_section(&transport, &ciphers, sni).await;
    show(format!("\n{}", text::details(&details, paint)));
    findings.extend(details_findings);

    findings.retain(|f| f.severity > Severity::Ok);
    findings.sort_by_key(|f| std::cmp::Reverse(f.severity));
    show(format!("\n{}", text::findings(&findings, paint)));

    let json = (cli.format == Format::Json).then(|| {
        json::render(&json::Report {
            target: &target,
            addr,
            sni,
            started_at,
            protocols: &protocols,
            ciphers: &ciphers,
            key_exchange: &key_exchange,
            post_quantum: &post_quantum,
            certificate: &certificate,
            http: &http,
            revocation: revocation.as_ref(),
            vulnerabilities: &vulns,
            intolerance: &intolerance,
            details: &details,
            findings: &findings,
        })
    });
    Outcome {
        code: u8::from(findings.iter().any(|f| f.severity >= cli.fail_on)),
        json,
        profile: Some(profile(&protocols, &ciphers, chain.as_deref())),
    }
}

/// Summarises one scan for comparison with the host's other addresses.
fn profile(
    protocols: &[ProtocolResult],
    ciphers: &[CipherSection],
    chain: Option<&[Vec<u8>]>,
) -> Profile {
    Profile {
        protocols: protocols
            .iter()
            .filter(|r| r.support == ProtocolSupport::Supported)
            .map(|r| r.version)
            .collect(),
        suites: ciphers
            .iter()
            .map(|s| {
                let suites = s.outcome.as_ref().ok().map(|c| {
                    let mut suites = c.suites.clone();
                    suites.sort_unstable();
                    suites
                });
                (s.version, suites)
            })
            .collect(),
        leaf: chain.and_then(<[_]>::first).cloned(),
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

/// Certificate section, its findings, and the DER chain when it was
/// retrieved.
type CertificateOutcome = (
    Result<CertificateSection, String>,
    Vec<Finding>,
    Option<Vec<Vec<u8>>>,
);

/// Fetches and checks the certificate chain, returning its description,
/// findings, and the chain itself.
///
/// The leaf is checked against `host`, the SNI name or the target IP.
async fn certificate_section(
    transport: &Transport,
    sni: Option<&str>,
    host: &str,
    store: &TrustStore,
) -> CertificateOutcome {
    let chain = match fetch_certificates(transport, sni).await {
        Ok(chain) => chain,
        Err(e) => {
            let finding = Finding::new(
                "cert.error",
                Severity::Info,
                format!("certificate could not be retrieved: {e}"),
            );
            return (Err(e.to_string()), vec![finding], None);
        }
    };
    let now = unix_now();
    let mut findings = certificate_findings(&chain.certificates, Some(host), now);
    if store.is_public() && is_trusted(&chain.certificates, now, store) {
        findings.extend(baseline_findings(&chain.certificates));
    }
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
    (Ok(section), findings, Some(chain.certificates))
}

/// Checks the leaf of `chain` against the issuer's OCSP responders and
/// CRLs. Without a chain or with unreadable URLs the check cannot run,
/// which is informational.
///
/// Requests use the connect and read timeouts of `transport`.
async fn revocation_section(
    transport: &Transport,
    chain: Option<&[Vec<u8>]>,
) -> (Result<Vec<RevocationCheck>, String>, Vec<Finding>) {
    let fetcher = Fetcher {
        connect_timeout: transport.connect_timeout,
        read_timeout: transport.read_timeout,
        max_body: 0,
    };
    let urls = chain
        .ok_or_else(|| "certificate chain could not be retrieved".to_owned())
        .and_then(|chain| {
            let leaf = chain.first().ok_or("empty certificate chain")?;
            revocation_urls(leaf).map(|urls| (chain, urls))
        });
    match urls {
        Ok((chain, urls)) => {
            let now = unix_now();
            let checks = revocation::check_revocation(fetcher, chain, &urls, now).await;
            let findings = revocation_findings(&checks, now);
            (Ok(checks), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "revocation.error",
                Severity::Info,
                format!("revocation status could not be checked: {e}"),
            );
            (Err(e), vec![finding])
        }
    }
}

/// Fetches the reply to `GET /` and checks HSTS, security headers, banners,
/// `Alt-Svc`, and cookies.
///
/// A server that does not speak HTTP is common for non-web TLS services,
/// so a failed fetch is informational.
async fn http_section(
    transport: &Transport,
    sni: Option<&str>,
) -> (Result<HttpResponse, String>, Vec<Finding>) {
    match fetch_http_headers(transport, sni).await {
        Ok(response) => {
            let mut findings = http_findings(&response);
            findings.extend(http_extra_findings(&response));
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

/// Probes compression, renegotiation and downgrade protection, then derives
/// the named vulnerabilities from everything the scan collected.
///
/// A failed feature probe leaves the affected verdicts as not tested.
async fn vulnerability_section(
    transport: &Transport,
    protocols: &[ProtocolResult],
    ciphers: &[CipherSection],
    key_exchange: &[KeyExchangeSection],
    sni: Option<&str>,
) -> Vec<Vulnerability> {
    let ciphers: Vec<CipherResult> = ciphers
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect();
    let key_exchange = measured(key_exchange);
    let features = probe_features(transport, &ciphers, sni).await.ok();
    assess_vulnerabilities(protocols, &ciphers, &key_exchange, features.as_ref())
}

/// Sends unusual but valid `ClientHello`s at the best offered version.
///
/// A probe error becomes an informational `intolerance.error` finding.
async fn intolerance_section(
    transport: &Transport,
    ciphers: &[CipherSection],
    sni: Option<&str>,
) -> (Result<Intolerance, String>, Vec<Finding>) {
    let ciphers: Vec<CipherResult> = ciphers
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect();
    match probe_intolerance(transport, &ciphers, sni).await {
        Ok(result) => {
            let findings = intolerance_findings(&result);
            (Ok(result), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "intolerance.error",
                Severity::Info,
                format!("ClientHello tolerance could not be tested: {e}"),
            );
            (Err(e.to_string()), vec![finding])
        }
    }
}

/// The key exchange results that were measured without error.
fn measured(sections: &[KeyExchangeSection]) -> Vec<KeyExchangeResult> {
    sections
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect()
}

/// Probes extended master secret, the downgrade sentinel, session tickets
/// and 0-RTT.
///
/// A probe error becomes an informational `handshake.error` finding.
async fn details_section(
    transport: &Transport,
    ciphers: &[CipherSection],
    sni: Option<&str>,
) -> (Result<HandshakeDetails, String>, Vec<Finding>) {
    let ciphers: Vec<CipherResult> = ciphers
        .iter()
        .filter_map(|s| s.outcome.as_ref().ok().cloned())
        .collect();
    match probe_details(transport, &ciphers, sni).await {
        Ok(result) => {
            let findings = details_findings(&result);
            (Ok(result), findings)
        }
        Err(e) => {
            let finding = Finding::new(
                "handshake.error",
                Severity::Info,
                format!("handshake details could not be probed: {e}"),
            );
            (Err(e.to_string()), vec![finding])
        }
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the scan helpers.

    use super::*;

    /// `explain` describes one id, lists all ids, and rejects unknown ones.
    #[test]
    fn explain_output() {
        let one = explain_text(Some("hsts.missing")).expect("known id");
        assert!(one.starts_with("hsts.missing: No HSTS header\n\n"), "{one}");
        assert!(one.ends_with("\n\nReference: RFC 6797\n"), "{one}");
        let all = explain_text(None).expect("list");
        assert_eq!(all.lines().count(), explanations().len());
        assert!(all.lines().any(|l| l.starts_with("hsts.missing ")));
        assert!(explain_text(Some("nope")).is_err());
    }

    /// A scan needs a target; `explain` does not, and the two do not mix.
    #[test]
    fn command_line_forms() {
        assert!(Cli::try_parse_from(["testls"]).is_err());
        assert!(Cli::try_parse_from(["testls", "example.com"]).is_ok());
        let cli = Cli::try_parse_from(["testls", "explain"]).expect("explain");
        assert!(matches!(cli.command, Some(Command::Explain { id: None })));
        let cli = Cli::try_parse_from(["testls", "explain", "hsts"]).expect("explain id");
        assert!(matches!(
            cli.command,
            Some(Command::Explain { id: Some(_) })
        ));
        let cli = Cli::try_parse_from(["testls", "a.example", "b.example:8443"]).expect("two");
        assert_eq!(cli.targets.len(), 2);
        let cli = Cli::try_parse_from(["testls", "192.0.2.0/30"]).expect("range");
        assert_eq!(targets(&cli).expect("targets").len(), 4);
        let cli = Cli::try_parse_from(["testls", "--file", "hosts.txt"]).expect("file only");
        assert_eq!(cli.targets, vec![]);
    }

    /// Target lists skip blanks and comments and name the bad line.
    #[test]
    fn target_lists() {
        let list = parse_target_list("# hosts\n\na.example\n  b.example:8443  \n").expect("list");
        let names: Vec<String> = list.iter().map(ToString::to_string).collect();
        assert_eq!(names, ["a.example:443", "b.example:8443"]);
        let list = parse_target_list("192.0.2.0/31:8443\n").expect("range");
        assert_eq!(list.len(), 2);
        assert!(
            parse_target_list("ok.example\n192.0.2.0/8\n")
                .unwrap_err()
                .starts_with("2: ")
        );
        let err = parse_target_list("a.example\nhttp://b.example\n").unwrap_err();
        assert!(err.starts_with("2: "), "{err}");
        assert_eq!(parse_target_list("# only\n").expect("empty"), vec![]);
    }

    /// A failed single target prints no JSON; failed targets in a run of
    /// several leave an array, empty if all failed.
    #[test]
    fn json_outputs() {
        let doc = "{}\n".to_string();
        assert_eq!(json_output(1, &[]), "");
        assert_eq!(json_output(1, std::slice::from_ref(&doc)), doc);
        assert_eq!(json_output(2, &[]), "[]\n");
        assert!(json_output(2, &[doc]).starts_with("[\n"));
    }

    /// Divergence names each address that differs from the first and how.
    #[test]
    fn divergence_report() {
        let profile = |protocols: Vec<ProtocolVersion>, leaf: &[u8]| Profile {
            protocols,
            suites: vec![(ProtocolVersion::TLS12, Some(vec![0xc02f]))],
            leaf: Some(leaf.to_vec()),
        };
        let a: SocketAddr = "192.0.2.1:443".parse().unwrap();
        let b: SocketAddr = "192.0.2.2:443".parse().unwrap();
        let c: SocketAddr = "[2001:db8::1]:443".parse().unwrap();
        assert_eq!(divergence(&[]), Vec::<String>::new());
        let same = [
            (a, profile(vec![ProtocolVersion::TLS12], b"x")),
            (b, profile(vec![ProtocolVersion::TLS12], b"x")),
        ];
        assert_eq!(divergence(&same), Vec::<String>::new());
        let mut odd = profile(vec![ProtocolVersion::TLS12, ProtocolVersion::TLS13], b"y");
        odd.suites[0].1 = None;
        let mixed = [
            (a, profile(vec![ProtocolVersion::TLS12], b"x")),
            (b, profile(vec![ProtocolVersion::TLS12], b"x")),
            (c, odd),
        ];
        assert_eq!(
            divergence(&mixed),
            [
                "[2001:db8::1]:443 differs from 192.0.2.1:443 in protocols, cipher suites, certificate"
            ]
        );
    }

    /// IP targets and `localhost` resolve without duplicates.
    #[tokio::test]
    async fn address_lists() {
        let ip: Target = "192.0.2.1:8443".parse().unwrap();
        assert_eq!(
            addresses(&ip).await.unwrap(),
            ["192.0.2.1:8443".parse::<SocketAddr>().unwrap()]
        );
        let local: Target = "localhost:443".parse().unwrap();
        let addrs = addresses(&local).await.unwrap();
        assert_ne!(addrs, Vec::new());
        assert!(addrs.iter().all(|a| a.ip().is_loopback()));
        let mut unique = addrs.clone();
        unique.dedup();
        assert_eq!(unique.len(), addrs.len());
    }

    /// `--file` errors and an empty list are scan errors before any connection.
    #[test]
    fn target_sources() {
        let cli = Cli::try_parse_from(["testls", "--file", "/nonexistent/hosts.txt"]).unwrap();
        assert!(targets(&cli).unwrap_err().starts_with("cannot read"));
        let dir = std::env::temp_dir().join(format!("testls-targets-{}", std::process::id()));
        std::fs::write(&dir, "# none\n").unwrap();
        let cli =
            Cli::try_parse_from(["testls", "a.example", "--file", dir.to_str().unwrap()]).unwrap();
        assert_eq!(targets(&cli).unwrap().len(), 1);
        let cli = Cli::try_parse_from(["testls", "--file", dir.to_str().unwrap()]).unwrap();
        assert_eq!(targets(&cli).unwrap_err(), "no targets given");
        std::fs::remove_file(&dir).unwrap();
    }

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

    /// Without a certificate chain the revocation check reports why.
    #[tokio::test]
    async fn revocation_without_chain() {
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let (section, findings) = revocation_section(&transport, None).await;
        assert_eq!(
            section.unwrap_err(),
            "certificate chain could not be retrieved"
        );
        assert_eq!(findings[0].id, "revocation.error");
        let (section, findings) = revocation_section(&transport, Some(&[])).await;
        assert_eq!(section.unwrap_err(), "empty certificate chain");
        assert_eq!(findings[0].severity, Severity::Info);
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

    /// A failed handshake feature probe leaves its verdicts untested.
    #[tokio::test]
    async fn vulnerabilities_without_features() {
        let transport = Transport::new(SocketAddr::from(([127, 0, 0, 1], 9)));
        let protocols = [ProtocolResult {
            version: ProtocolVersion::TLS12,
            support: ProtocolSupport::Supported,
        }];
        let ciphers = [CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::TLS12,
                suites: vec![0xc02f],
                order: testls_probe::CipherOrder::Server,
            }),
        }];
        let list = vulnerability_section(&transport, &protocols, &ciphers, &[], None).await;
        let crime = list.iter().find(|v| v.id == "crime").expect("crime");
        assert_eq!(crime.status, testls_checks::VulnStatus::NotTested);
        assert_eq!(vulnerability_findings(&list), vec![]);
    }

    /// A failed tolerance probe is reported as an info finding.
    #[tokio::test]
    async fn intolerance_error_is_info() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let ciphers = [CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::TLS12,
                suites: vec![0xc02f],
                order: testls_probe::CipherOrder::Server,
            }),
        }];
        let (section, findings) = intolerance_section(&Transport::new(addr), &ciphers, None).await;
        assert!(section.is_err());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "intolerance.error");
        assert_eq!(findings[0].severity, Severity::Info);
    }

    /// A failed handshake details probe is reported as an info finding.
    #[tokio::test]
    async fn details_error_is_info() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let ciphers = [CipherSection {
            version: ProtocolVersion::TLS12,
            outcome: Ok(CipherResult {
                version: ProtocolVersion::TLS12,
                suites: vec![0xc02f],
                order: testls_probe::CipherOrder::Server,
            }),
        }];
        let (section, findings) = details_section(&Transport::new(addr), &ciphers, None).await;
        assert!(section.is_err());
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "handshake.error");
        assert_eq!(findings[0].severity, Severity::Info);
    }
}
