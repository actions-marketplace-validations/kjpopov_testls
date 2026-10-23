//! Parsing of user-supplied scan targets.

use std::fmt;
use std::net::IpAddr;

/// Port used when the target does not specify one.
pub const DEFAULT_PORT: u16 = 443;

/// Host part of a target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Host {
    /// DNS name (lowercased, without trailing dot).
    Name(String),
    /// Literal IP address.
    Ip(IpAddr),
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Name(n) => f.write_str(n),
            Self::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
            Self::Ip(ip) => write!(f, "{ip}"),
        }
    }
}

/// A scan target: `host`, `host:port`, `[v6]:port`, or an `https://` URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    /// Host to connect to.
    pub host: Host,
    /// TCP port.
    pub port: u16,
}

impl Target {
    /// Server name to send in SNI: the DNS name, or none for IP literals.
    pub fn default_sni(&self) -> Option<&str> {
        match &self.host {
            Host::Name(n) => Some(n),
            Host::Ip(_) => None,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// Why a target string was rejected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseTargetError(String);

impl fmt::Display for ParseTargetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ParseTargetError {}

fn err(msg: impl Into<String>) -> ParseTargetError {
    ParseTargetError(msg.into())
}

impl std::str::FromStr for Target {
    type Err = ParseTargetError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let s = input.trim();
        let (s, scheme_port) = match s.split_once("://") {
            Some((scheme, rest)) => {
                let port = match scheme.to_ascii_lowercase().as_str() {
                    "https" => DEFAULT_PORT,
                    other => return Err(err(format!("unsupported URL scheme `{other}`"))),
                };
                (rest, Some(port))
            }
            None => (s, None),
        };
        // Drop path, query, fragment and userinfo.
        let authority = s.split(['/', '?', '#']).next().unwrap_or_default();
        let authority = authority.rsplit_once('@').map_or(authority, |(_, a)| a);
        if authority.is_empty() {
            return Err(err("empty host"));
        }

        let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
            let (ip, after) = rest
                .split_once(']')
                .ok_or_else(|| err("missing `]` in IPv6 address"))?;
            let ip: IpAddr = ip.parse().map_err(|_| err("invalid IPv6 address"))?;
            let port = match after {
                "" => None,
                p => Some(
                    p.strip_prefix(':')
                        .ok_or_else(|| err("unexpected text after `]`"))?,
                ),
            };
            (Host::Ip(ip), port)
        } else if let Ok(ip) = authority.parse::<IpAddr>() {
            // Bare IPv6 without brackets, or plain IPv4.
            (Host::Ip(ip), None)
        } else {
            let (host, port) = match authority.rsplit_once(':') {
                Some((h, p)) => (h, Some(p)),
                None => (authority, None),
            };
            let host = match host.parse::<IpAddr>() {
                Ok(ip @ IpAddr::V4(_)) => Host::Ip(ip),
                Ok(IpAddr::V6(_)) => return Err(err("IPv6 address with port must use [brackets]")),
                Err(_) => Host::Name(validate_name(host)?),
            };
            (host, port)
        };

        let port = match port {
            Some(p) => p
                .parse::<u16>()
                .ok()
                .filter(|&p| p != 0)
                .ok_or_else(|| err(format!("invalid port `{p}`")))?,
            None => scheme_port.unwrap_or(DEFAULT_PORT),
        };
        Ok(Self { host, port })
    }
}

fn validate_name(name: &str) -> Result<String, ParseTargetError> {
    let name = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    let label_ok = |l: &str| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    };
    if name.is_empty() || name.len() > 253 || !name.split('.').all(label_ok) {
        return Err(err(format!("invalid host name `{name}`")));
    }
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: &str) -> Target {
        s.parse().unwrap()
    }

    #[test]
    fn forms() {
        assert_eq!(t("Example.COM").to_string(), "example.com:443");
        assert_eq!(t("example.com:8443").port, 8443);
        assert_eq!(
            t("https://example.com/path?q=1").to_string(),
            "example.com:443"
        );
        assert_eq!(t("https://user@example.com:4443/").port, 4443);
        assert_eq!(t("192.0.2.1").to_string(), "192.0.2.1:443");
        assert_eq!(t("192.0.2.1:993").port, 993);
        assert_eq!(t("2001:db8::1").to_string(), "[2001:db8::1]:443");
        assert_eq!(t("[2001:db8::1]:8443").to_string(), "[2001:db8::1]:8443");
        assert_eq!(t("example.com.").host, Host::Name("example.com".into()));
    }

    #[test]
    fn sni() {
        assert_eq!(t("example.com").default_sni(), Some("example.com"));
        assert_eq!(t("192.0.2.1").default_sni(), None);
    }

    #[test]
    fn rejects() {
        for bad in [
            "",
            "http://example.com",
            "example.com:0",
            "example.com:99999",
            "exa mple.com",
            "-bad.com",
            "[2001:db8::1",
            "[::1]x",
        ] {
            assert!(bad.parse::<Target>().is_err(), "{bad} should be rejected");
        }
    }
}
