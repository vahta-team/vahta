//! Addresses a public name must not lead to. A host rule names a public service;
//! if the name resolves to the machine itself or to the local network, either
//! the DNS answer was changed on the way (rebinding) or the name never was
//! public. Either way the connection is refused unless the person wrote the
//! rule with the `private:` marker.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What kind of non-public address `ip` is, or `None` for a public one.
/// An IPv6 address that carries an IPv4 one (`::ffff:a.b.c.d`) is judged as that
/// IPv4 address.
pub fn private_kind(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => private_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => private_v4(v4),
            None => private_v6(v6),
        },
    }
}

fn private_v4(ip: Ipv4Addr) -> Option<&'static str> {
    let o = ip.octets();
    if ip.is_loopback() {
        Some("loopback")
    } else if o[0] == 0 {
        Some("unspecified")
    } else if o[0] == 10
        || (o[0] == 172 && (16..32).contains(&o[1]))
        || (o[0] == 192 && o[1] == 168)
    {
        Some("private")
    } else if o[0] == 100 && (64..128).contains(&o[1]) {
        Some("shared (100.64.0.0/10)")
    } else if o[0] == 169 && o[1] == 254 {
        Some("link-local")
    } else {
        None
    }
}

fn private_v6(ip: Ipv6Addr) -> Option<&'static str> {
    let first = ip.segments()[0];
    if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_unspecified() {
        Some("unspecified")
    } else if first & 0xfe00 == 0xfc00 {
        Some("private")
    } else if first & 0xffc0 == 0xfe80 {
        Some("link-local")
    } else {
        None
    }
}

/// The sentence for the person (stderr, journal) when `host` resolved to
/// `ip` and the rule did not allow that.
pub fn refusal_text(host: &str, ip: IpAddr, kind: &str) -> String {
    format!(
        "{host} resolved to {ip}, a {kind} address; refused (a rule can allow this with `private:{host}`)"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kind(text: &str) -> Option<&'static str> {
        private_kind(text.parse().unwrap())
    }

    #[test]
    fn the_local_ranges_are_told_from_public_addresses() {
        for (ip, want) in [
            ("127.0.0.1", "loopback"),
            ("127.9.9.9", "loopback"),
            ("0.0.0.0", "unspecified"),
            ("10.1.2.3", "private"),
            ("172.16.0.1", "private"),
            ("172.31.255.255", "private"),
            ("192.168.1.1", "private"),
            ("100.64.0.1", "shared (100.64.0.0/10)"),
            ("100.127.255.255", "shared (100.64.0.0/10)"),
            ("169.254.169.254", "link-local"),
            ("::1", "loopback"),
            ("::", "unspecified"),
            ("fc00::1", "private"),
            ("fd12:3456::1", "private"),
            ("fe80::1", "link-local"),
            ("febf::1", "link-local"),
            ("::ffff:127.0.0.1", "loopback"),
            ("::ffff:10.0.0.1", "private"),
        ] {
            assert_eq!(kind(ip), Some(want), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "172.15.0.1",
            "172.32.0.1",
            "100.63.255.255",
            "100.128.0.1",
            "169.253.0.1",
            "192.169.0.1",
            "93.184.216.34",
            "2606:4700::1111",
            "fe00::1",
            "::ffff:8.8.8.8",
        ] {
            assert_eq!(kind(ip), None, "{ip}");
        }
    }

    #[test]
    fn the_refusal_names_the_host_the_address_and_the_way_out() {
        let t = refusal_text("api.example.com", "10.0.0.5".parse().unwrap(), "private");
        assert!(t.contains("api.example.com") && t.contains("10.0.0.5"));
        assert!(t.contains("private:api.example.com"));
    }
}
