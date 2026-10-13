//! A strict `https` URL: the one parser both the daemon's host check and the
//! client use, so the host that was checked is the host that is connected to.
//!
//! Strict on purpose. Accepted: `https://HOST[:PORT]/path?query`, with a DNS
//! name or an IP literal in brackets for IPv6, plain ASCII, no userinfo, no
//! backslash, no whitespace or control character, no fragment. Anything else is
//! refused rather than interpreted, because two parsers that read an odd URL
//! differently are how a request ends up somewhere the person did not approve.

use std::fmt;

/// The default port of `https`.
pub const DEFAULT_PORT: u16 = 443;

/// A parsed URL. `path` starts with `/`; `query` has no `?`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    /// Lowercase, without brackets or a trailing dot.
    pub host: String,
    /// The port in the URL, or 443.
    pub port: u16,
    pub path: String,
    pub query: Option<String>,
}

/// Why a URL was refused. The text never carries the URL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UrlError {
    NotHttps,
    Invalid(&'static str),
}

impl fmt::Display for UrlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UrlError::NotHttps => f.write_str("only https:// URLs are allowed"),
            UrlError::Invalid(why) => write!(f, "not a usable URL: {why}"),
        }
    }
}

impl std::error::Error for UrlError {}

fn plain(c: char) -> bool {
    c.is_ascii()
        && !c.is_ascii_control()
        && c != ' '
        && c != '\\'
        && c != '"'
        && c != '<'
        && c != '>'
        && c != '`'
        && c != '{'
        && c != '}'
        && c != '|'
        && c != '^'
}

impl Url {
    pub fn parse(text: &str) -> Result<Url, UrlError> {
        let lower_scheme = text.get(..8).map(str::to_ascii_lowercase);
        let rest = match lower_scheme.as_deref() {
            Some("https://") => &text[8..],
            _ => {
                return Err(if text.to_ascii_lowercase().starts_with("http://") {
                    UrlError::NotHttps
                } else {
                    UrlError::Invalid("it must start with https://")
                });
            }
        };
        if !rest.chars().all(plain) {
            return Err(UrlError::Invalid(
                "only plain ASCII is allowed (percent-encode the rest, punycode a host)",
            ));
        }
        if rest.contains('#') {
            return Err(UrlError::Invalid("a fragment is not sent, remove it"));
        }
        let end = rest.find(['/', '?']).unwrap_or(rest.len());
        let (authority, tail) = rest.split_at(end);
        if authority.contains('@') {
            return Err(UrlError::Invalid("a user name or password in the URL"));
        }
        let (host_text, port) = split_authority(authority)?;
        let host = clean_host(host_text)?;
        let (path, query) = match tail.split_once('?') {
            Some((p, q)) => (p, Some(q.to_string())),
            None => (tail, None),
        };
        let path = if path.is_empty() { "/" } else { path };
        Ok(Url {
            host,
            port,
            path: path.to_string(),
            query,
        })
    }

    /// The URL as one string, as it is sent.
    pub fn to_url_string(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let mut s = format!("https://{host}");
        if self.port != DEFAULT_PORT {
            s.push_str(&format!(":{}", self.port));
        }
        s.push_str(&self.path);
        if let Some(q) = &self.query {
            s.push('?');
            s.push_str(q);
        }
        s
    }

    /// The target of a `Location` header, resolved against this URL. `http://`
    /// and other schemes are refused; a relative reference stays on this host.
    pub fn join(&self, location: &str) -> Result<Url, UrlError> {
        if location.contains("://") {
            return Url::parse(location);
        }
        if location.starts_with("//") {
            return Url::parse(&format!("https:{location}"));
        }
        if location.contains(':') && !location.starts_with(['/', '?']) {
            return Err(UrlError::Invalid("an unsupported redirect target"));
        }
        let mut next = self.clone();
        if !location.chars().all(plain) || location.contains('#') {
            return Err(UrlError::Invalid("an unusable redirect target"));
        }
        if let Some(q) = location.strip_prefix('?') {
            next.query = Some(q.to_string());
        } else {
            let (p, q) = match location.split_once('?') {
                Some((p, q)) => (p, Some(q.to_string())),
                None => (location, None),
            };
            next.path = if p.starts_with('/') {
                p.to_string()
            } else {
                let dir = &self.path[..self.path.rfind('/').map_or(0, |i| i + 1)];
                format!("{dir}{p}")
            };
            next.query = q;
        }
        Ok(next)
    }
}

fn split_authority(authority: &str) -> Result<(&str, u16), UrlError> {
    let (host, port_text) = if let Some(inner) = authority.strip_prefix('[') {
        let Some((h, after)) = inner.split_once(']') else {
            return Err(UrlError::Invalid("an unclosed [ in the host"));
        };
        (
            h,
            after
                .strip_prefix(':')
                .or(if after.is_empty() { Some("") } else { None }),
        )
    } else {
        match authority.split_once(':') {
            Some((h, p)) => (h, Some(p)),
            None => (authority, Some("")),
        }
    };
    let Some(port_text) = port_text else {
        return Err(UrlError::Invalid("text after the host"));
    };
    let port = if port_text.is_empty() {
        DEFAULT_PORT
    } else if port_text.len() <= 5 && port_text.bytes().all(|b| b.is_ascii_digit()) {
        match port_text.parse::<u16>() {
            Ok(p) if p != 0 => p,
            _ => return Err(UrlError::Invalid("the port")),
        }
    } else {
        return Err(UrlError::Invalid("the port"));
    };
    Ok((host, port))
}

fn clean_host(host: &str) -> Result<String, UrlError> {
    let host = host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
    if host.is_empty() || host.len() > 253 {
        return Err(UrlError::Invalid("the host"));
    }
    if host.contains(':') {
        // An IPv6 literal.
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            return Ok(host);
        }
        return Err(UrlError::Invalid("the host"));
    }
    let labels_ok = host.split('.').all(|l| {
        !l.is_empty()
            && l.len() <= 63
            && !l.starts_with('-')
            && !l.ends_with('-')
            && l.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    });
    if !labels_ok {
        return Err(UrlError::Invalid("the host"));
    }
    // Numbers in odd forms (`0x7f.1`, `2130706433`) are how a loopback address
    // hides: only a dotted quad of decimals counts as an IP address here, and
    // an all-numeric name is refused.
    let last = host.rsplit('.').next().unwrap_or("");
    if last.bytes().all(|b| b.is_ascii_digit()) && host.parse::<std::net::Ipv4Addr>().is_err() {
        return Err(UrlError::Invalid("the host"));
    }
    Ok(host)
}

/// Percent-encode `text` for a query key or value: everything but the
/// unreserved characters.
pub fn encode_component(text: &[u8]) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_plain_url_parses_and_round_trips() {
        let u = Url::parse("https://API.Example.com:8443/v1/x?a=b").unwrap();
        assert_eq!(u.host, "api.example.com");
        assert_eq!(u.port, 8443);
        assert_eq!(u.path, "/v1/x");
        assert_eq!(u.query.as_deref(), Some("a=b"));
        assert_eq!(u.to_url_string(), "https://api.example.com:8443/v1/x?a=b");
        let d = Url::parse("https://example.com").unwrap();
        assert_eq!((d.port, d.path.as_str()), (443, "/"));
        assert_eq!(
            Url::parse("https://example.com./").unwrap().host,
            "example.com"
        );
        assert_eq!(Url::parse("https://[::1]:9/").unwrap().host, "::1");
    }

    #[test]
    fn what_could_be_read_two_ways_is_refused() {
        for bad in [
            "http://example.com/",
            "ftp://example.com/",
            "example.com/",
            "https://user:pw@example.com/",
            "https://good.com\\@evil.com/",
            "https://example.com#frag",
            "https://example.com:99999/",
            "https://example.com:0/",
            "https://exa mple.com/",
            "https://example.com/a b",
            "https://example.com/\u{e9}",
            "https://2130706433/",
            "https://0x7f.1/",
            "https://a..b/",
            "https://-a.com/",
            "https://[::1/",
            "https://example.com:80a/",
            "https://example.com\n/",
        ] {
            assert!(Url::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(Url::parse("http://example.com/"), Err(UrlError::NotHttps));
    }

    #[test]
    fn a_redirect_target_is_resolved_against_the_url() {
        let u = Url::parse("https://example.com/a/b?x=1").unwrap();
        assert_eq!(
            u.join("/c").unwrap().to_url_string(),
            "https://example.com/c"
        );
        assert_eq!(
            u.join("d?y=2").unwrap().to_url_string(),
            "https://example.com/a/d?y=2"
        );
        assert_eq!(
            u.join("?z").unwrap().to_url_string(),
            "https://example.com/a/b?z"
        );
        assert_eq!(u.join("//other.com/q").unwrap().host, "other.com");
        assert_eq!(u.join("https://other.com:444/").unwrap().port, 444);
        assert_eq!(u.join("http://example.com/"), Err(UrlError::NotHttps));
        assert!(u.join("javascript:alert(1)").is_err());
    }

    #[test]
    fn a_component_is_percent_encoded() {
        assert_eq!(encode_component(b"a b&c=d/~-._"), "a%20b%26c%3Dd%2F~-._");
    }
}
