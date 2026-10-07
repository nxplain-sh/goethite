//! IP networks in CIDR notation, for identifying clients.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

/// An IP network such as `192.168.1.0/24` or `2001:db8::/32`, or a single
/// address (`/32` or `/128`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

/// Why a network could not be parsed.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum CidrError {
    /// The address part is not an IP address.
    #[error("{0:?} is not an IP address")]
    Address(String),
    /// The prefix length is not a number in range.
    #[error("prefix length {0:?} is not a number from 0 to the address's bits")]
    Prefix(String),
    /// The address has bits set beyond the prefix.
    #[error("{given} has host bits set; the network is {network}")]
    HostBits {
        /// What was given.
        given: String,
        /// The network it is in.
        network: Cidr,
    },
}

impl Cidr {
    /// The network of `addr` with `prefix` leading bits, or `None` if the
    /// prefix is longer than the address.
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        (prefix <= max_prefix(addr)).then(|| Self {
            addr: mask(addr, prefix),
            prefix,
        })
    }

    /// The single address `addr`.
    pub fn host(addr: IpAddr) -> Self {
        Self {
            addr,
            prefix: max_prefix(addr),
        }
    }

    /// The network address.
    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    /// The prefix length.
    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    /// Whether `ip` is in the network. IPv4 addresses mapped into IPv6
    /// count as IPv4.
    pub fn contains(&self, ip: IpAddr) -> bool {
        let ip = canonical(ip);
        ip.is_ipv4() == self.addr.is_ipv4() && mask(ip, self.prefix) == self.addr
    }
}

/// IPv4 addresses mapped into IPv6 (as from a dual-stack socket) become
/// plain IPv4.
pub(crate) fn canonical(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map_or(ip, IpAddr::V4),
        IpAddr::V4(_) => ip,
    }
}

fn max_prefix(addr: IpAddr) -> u8 {
    if addr.is_ipv4() { 32 } else { 128 }
}

/// `addr` with all but its first `prefix` bits cleared.
pub(crate) fn mask(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::MAX
                .checked_shl(32_u32.saturating_sub(u32::from(prefix)))
                .unwrap_or(0);
            IpAddr::V4(Ipv4Addr::from(u32::from(v4) & bits))
        }
        IpAddr::V6(v6) => {
            let bits = u128::MAX
                .checked_shl(128_u32.saturating_sub(u32::from(prefix)))
                .unwrap_or(0);
            IpAddr::V6(Ipv6Addr::from(u128::from(v6) & bits))
        }
    }
}

impl FromStr for Cidr {
    type Err = CidrError;

    /// Parses `addr/prefix` or a bare address. The address must not have
    /// bits set beyond the prefix: `192.168.1.5/24` is an error rather than
    /// silently meaning `192.168.1.0/24`.
    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (addr_text, prefix_text) = match text.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (text, None),
        };
        let addr: IpAddr = addr_text
            .parse()
            .map_err(|_| CidrError::Address(addr_text.to_owned()))?;
        let Some(prefix_text) = prefix_text else {
            return Ok(Self::host(canonical(addr)));
        };
        let prefix = prefix_text
            .parse::<u8>()
            .ok()
            .filter(|prefix| *prefix <= max_prefix(addr) && prefix_text.len() <= 3)
            .filter(|_| prefix_text.bytes().all(|byte| byte.is_ascii_digit()))
            .filter(|_| prefix_text == "0" || !prefix_text.starts_with('0'))
            .ok_or_else(|| CidrError::Prefix(prefix_text.to_owned()))?;
        let network = mask(addr, prefix);
        if network != addr {
            return Err(CidrError::HostBits {
                given: text.to_owned(),
                network: Self {
                    addr: network,
                    prefix,
                },
            });
        }
        // An IPv4 network written in IPv6 form (`::ffff:10.0.0.0/104`) is
        // the IPv4 network, since client addresses are compared as IPv4.
        if let IpAddr::V6(v6) = addr
            && let Some(v4) = v6.to_ipv4_mapped()
            && let Some(v4_prefix) = prefix.checked_sub(96)
        {
            return Ok(Self {
                addr: IpAddr::V4(v4),
                prefix: v4_prefix,
            });
        }
        Ok(Self { addr, prefix })
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cidr(text: &str) -> Cidr {
        text.parse().unwrap()
    }

    #[test]
    fn parses_and_displays() {
        assert_eq!(cidr("192.168.1.0/24").to_string(), "192.168.1.0/24");
        assert_eq!(cidr("10.0.0.7").to_string(), "10.0.0.7/32");
        assert_eq!(cidr("2001:db8::/32").to_string(), "2001:db8::/32");
        assert_eq!(cidr("::1").to_string(), "::1/128");
        assert_eq!(cidr("0.0.0.0/0").to_string(), "0.0.0.0/0");
        assert_eq!(cidr("::/0").prefix(), 0);
        assert_eq!(cidr("::ffff:10.0.0.0/104").to_string(), "10.0.0.0/8");
        assert_eq!(cidr("::ffff:10.0.0.1").to_string(), "10.0.0.1/32");
    }

    #[test]
    fn rejects_bad_input() {
        for bad in [
            "",
            "/24",
            "192.168.1.0/",
            "192.168.1.0/33",
            "2001:db8::/129",
            "192.168.1.0/+8",
            "192.168.1.0/024",
            "192.168.1.0/2 4",
            "192.168.1.0/24/1",
            "host.example/24",
            "192.168.1.0 /24",
        ] {
            assert!(bad.parse::<Cidr>().is_err(), "{bad}");
        }
        let err = "192.168.1.5/24".parse::<Cidr>().unwrap_err();
        assert_eq!(
            err.to_string(),
            "192.168.1.5/24 has host bits set; the network is 192.168.1.0/24"
        );
    }

    #[test]
    fn fuzz_seeds_parse_as_named() {
        let seed = |name: &str| {
            let path = format!(
                "{}/../../fuzz/seeds/parse_cidr/{name}",
                env!("CARGO_MANIFEST_DIR")
            );
            std::fs::read_to_string(&path).unwrap()
        };
        for name in ["ipv4-network", "ipv4-host", "ipv6-network", "mapped"] {
            assert!(seed(name).parse::<Cidr>().is_ok(), "{name}");
        }
        assert!(matches!(
            seed("host-bits").parse::<Cidr>(),
            Err(CidrError::HostBits { .. })
        ));
    }

    #[test]
    fn contains() {
        let lan = cidr("192.168.1.0/24");
        assert!(lan.contains("192.168.1.200".parse().unwrap()));
        assert!(lan.contains("::ffff:192.168.1.200".parse().unwrap()));
        assert!(!lan.contains("192.168.2.1".parse().unwrap()));
        assert!(!lan.contains("::1".parse().unwrap()));
        let everything = cidr("0.0.0.0/0");
        assert!(everything.contains("8.8.8.8".parse().unwrap()));
        assert!(!everything.contains("2001:db8::1".parse().unwrap()));
        let v6 = cidr("2001:db8:1::/48");
        assert!(v6.contains("2001:db8:1:ffff::1".parse().unwrap()));
        assert!(!v6.contains("2001:db8:2::1".parse().unwrap()));
        assert_eq!(
            Cidr::new("10.1.2.3".parse().unwrap(), 8),
            Some(cidr("10.0.0.0/8"))
        );
        assert_eq!(Cidr::new("10.1.2.3".parse().unwrap(), 33), None);
    }
}
