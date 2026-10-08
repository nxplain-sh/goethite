//! The root servers to start from: IANA's root hints (named.root, root
//! zone version 2026100701). A priming query (RFC 8109) replaces them with
//! what the root servers say about themselves.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Each root server: its name, IPv4 and IPv6 address.
pub(super) const ROOT_SERVERS: [(&str, Ipv4Addr, Ipv6Addr); 13] = [
    (
        "a.root-servers.net.",
        Ipv4Addr::new(198, 41, 0, 4),
        Ipv6Addr::new(0x2001, 0x503, 0xba3e, 0, 0, 0, 2, 0x30),
    ),
    (
        "b.root-servers.net.",
        Ipv4Addr::new(170, 247, 170, 2),
        Ipv6Addr::new(0x2801, 0x1b8, 0x10, 0, 0, 0, 0, 0xb),
    ),
    (
        "c.root-servers.net.",
        Ipv4Addr::new(192, 33, 4, 12),
        Ipv6Addr::new(0x2001, 0x500, 0x2, 0, 0, 0, 0, 0xc),
    ),
    (
        "d.root-servers.net.",
        Ipv4Addr::new(199, 7, 91, 13),
        Ipv6Addr::new(0x2001, 0x500, 0x2d, 0, 0, 0, 0, 0xd),
    ),
    (
        "e.root-servers.net.",
        Ipv4Addr::new(192, 203, 230, 10),
        Ipv6Addr::new(0x2001, 0x500, 0xa8, 0, 0, 0, 0, 0xe),
    ),
    (
        "f.root-servers.net.",
        Ipv4Addr::new(192, 5, 5, 241),
        Ipv6Addr::new(0x2001, 0x500, 0x2f, 0, 0, 0, 0, 0xf),
    ),
    (
        "g.root-servers.net.",
        Ipv4Addr::new(192, 112, 36, 4),
        Ipv6Addr::new(0x2001, 0x500, 0x12, 0, 0, 0, 0, 0xd0d),
    ),
    (
        "h.root-servers.net.",
        Ipv4Addr::new(198, 97, 190, 53),
        Ipv6Addr::new(0x2001, 0x500, 0x1, 0, 0, 0, 0, 0x53),
    ),
    (
        "i.root-servers.net.",
        Ipv4Addr::new(192, 36, 148, 17),
        Ipv6Addr::new(0x2001, 0x7fe, 0, 0, 0, 0, 0, 0x53),
    ),
    (
        "j.root-servers.net.",
        Ipv4Addr::new(192, 58, 128, 30),
        Ipv6Addr::new(0x2001, 0x503, 0xc27, 0, 0, 0, 2, 0x30),
    ),
    (
        "k.root-servers.net.",
        Ipv4Addr::new(193, 0, 14, 129),
        Ipv6Addr::new(0x2001, 0x7fd, 0, 0, 0, 0, 0, 1),
    ),
    (
        "l.root-servers.net.",
        Ipv4Addr::new(199, 7, 83, 42),
        Ipv6Addr::new(0x2001, 0x500, 0x9f, 0, 0, 0, 0, 0x42),
    ),
    (
        "m.root-servers.net.",
        Ipv4Addr::new(202, 12, 27, 33),
        Ipv6Addr::new(0x2001, 0xdc3, 0, 0, 0, 0, 0, 0x35),
    ),
];

#[cfg(test)]
mod tests {
    use goethite_proto::Name;

    use super::*;

    #[test]
    fn hints_are_valid() {
        for (name, v4, v6) in ROOT_SERVERS {
            let name: Name = name.parse().unwrap();
            assert!(name.is_within(&"root-servers.net.".parse().unwrap()));
            assert!(!v4.is_private() && !v4.is_loopback());
            assert!(!v6.is_loopback() && !v6.is_unspecified());
        }
    }
}
