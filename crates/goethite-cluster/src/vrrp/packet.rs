//! VRRP version 3 advertisements for IPv4 (RFC 5798, section 5).
//!
//! An advertisement is an IPv4 packet of protocol 112, sent to the group
//! 224.0.0.18 (or straight to the peer) with a TTL of 255:
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |Version| Type  | Virtual Rtr ID|   Priority    |Count IPvX Addr|
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |(rsvd) |     Max Adver Int     |          Checksum             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       IPv4 Address(es)                        |
//! ```
//!
//! [`parse`] reads a whole IPv4 packet as a raw socket receives it, header
//! included, and checks what RFC 5798 asks a receiver to check that does
//! not depend on configuration: the version, the type, the length and the
//! checksum. Its input comes from the network, so it never panics and
//! never allocates. [`encode`] writes the VRRP part only: the kernel adds
//! the IPv4 header.

use std::net::Ipv4Addr;

/// The IP protocol number of VRRP.
pub const PROTOCOL: u8 = 112;

/// The multicast group advertisements go to.
pub const GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 18);

/// The TTL advertisements are sent with, and must arrive with: a router
/// would have lowered it, so 255 proves the sender is on the same link.
pub const TTL: u8 = 255;

/// The longest advertisement interval, in centiseconds (12 bits).
pub const MAX_INTERVAL: u16 = 0x0fff;

/// The most addresses one advertisement can carry (the count is one byte).
pub const MAX_ADDRESSES: usize = 255;

/// The VRRP version spoken.
const VERSION: u8 = 3;

/// The only VRRP packet type.
const ADVERTISEMENT: u8 = 1;

/// The fixed part of an advertisement, before the addresses.
const HEADER_LEN: usize = 8;

/// The shortest IPv4 header.
const MIN_IP_HEADER_LEN: usize = 20;

/// Why a received packet is not a valid advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// Shorter than an IPv4 header, or than the length it states.
    #[error("the packet is truncated")]
    Truncated,
    /// Not IPv4, or an impossible header length.
    #[error("not a valid IPv4 packet")]
    NotIpv4,
    /// Another IP protocol.
    #[error("IP protocol {0}, not VRRP")]
    NotVrrp(u8),
    /// Another VRRP version, such as 2.
    #[error("VRRP version {0}; only version 3 is supported")]
    Version(u8),
    /// An unknown VRRP packet type.
    #[error("VRRP packet type {0}, not an advertisement")]
    Type(u8),
    /// The length does not match the address count.
    #[error("the length does not match {0} addresses")]
    Length(u8),
    /// The checksum is wrong.
    #[error("bad checksum")]
    Checksum,
}

/// An advertisement, as received.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Advert<'a> {
    /// The virtual router it is for.
    pub router_id: u8,
    /// The sender's priority: 0 when it stops being the master.
    pub priority: u8,
    /// How often the sender advertises, in centiseconds.
    pub interval: u16,
    /// The addresses, four bytes each.
    addresses: &'a [u8],
}

impl Advert<'_> {
    /// The virtual router's addresses.
    pub fn addresses(&self) -> impl ExactSizeIterator<Item = Ipv4Addr> + '_ {
        let (addresses, _) = self.addresses.as_chunks::<4>();
        addresses.iter().map(|&octets| Ipv4Addr::from(octets))
    }
}

/// An advertisement with the IPv4 header fields that matter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Received<'a> {
    /// Who sent it.
    pub source: Ipv4Addr,
    /// Where it was sent: the group, or this node.
    pub destination: Ipv4Addr,
    /// The TTL it arrived with.
    pub ttl: u8,
    /// The advertisement.
    pub advert: Advert<'a>,
}

/// Parses an IPv4 packet, header included, as a raw socket receives it.
///
/// # Errors
///
/// [`ParseError`] if it is not a valid VRRP version 3 advertisement.
pub fn parse(packet: &[u8]) -> Result<Received<'_>, ParseError> {
    let Some(header) = packet.first_chunk::<MIN_IP_HEADER_LEN>() else {
        return Err(ParseError::Truncated);
    };
    let [
        version_ihl,
        _,
        len_hi,
        len_lo,
        _,
        _,
        _,
        _,
        ttl,
        protocol,
        ..,
    ] = *header;
    if version_ihl >> 4 != 4 {
        return Err(ParseError::NotIpv4);
    }
    let header_len = usize::from(version_ihl & 0x0f).saturating_mul(4);
    let total_len = usize::from(u16::from_be_bytes([len_hi, len_lo]));
    if header_len < MIN_IP_HEADER_LEN || total_len < header_len {
        return Err(ParseError::NotIpv4);
    }
    if protocol != PROTOCOL {
        return Err(ParseError::NotVrrp(protocol));
    }
    let vrrp = packet
        .get(header_len..total_len)
        .ok_or(ParseError::Truncated)?;
    let source = address_at(header, 12);
    let destination = address_at(header, 16);
    let Some(
        &[
            version_type,
            router_id,
            priority,
            count,
            interval_hi,
            interval_lo,
            _,
            _,
        ],
    ) = vrrp.first_chunk::<HEADER_LEN>()
    else {
        return Err(ParseError::Truncated);
    };
    if version_type >> 4 != VERSION {
        return Err(ParseError::Version(version_type >> 4));
    }
    if version_type & 0x0f != ADVERTISEMENT {
        return Err(ParseError::Type(version_type & 0x0f));
    }
    let addresses = vrrp.get(HEADER_LEN..).unwrap_or_default();
    if addresses.len() != usize::from(count).saturating_mul(4) {
        return Err(ParseError::Length(count));
    }
    if checksum(source, destination, vrrp) != 0 {
        return Err(ParseError::Checksum);
    }
    Ok(Received {
        source,
        destination,
        ttl,
        advert: Advert {
            router_id,
            priority,
            // The top four bits are reserved and ignored on receipt.
            interval: u16::from_be_bytes([interval_hi, interval_lo]) & MAX_INTERVAL,
            addresses,
        },
    })
}

/// The address at `offset` in an IPv4 header.
fn address_at(header: &[u8; MIN_IP_HEADER_LEN], offset: usize) -> Ipv4Addr {
    header
        .get(offset..)
        .and_then(<[u8]>::first_chunk::<4>)
        .map_or(Ipv4Addr::UNSPECIFIED, |octets| Ipv4Addr::from(*octets))
}

/// An advertisement for `addresses` (at most [`MAX_ADDRESSES`]; more are
/// left out), sent from `source` to `destination`, which the checksum
/// covers. `interval` is in centiseconds, at most [`MAX_INTERVAL`].
pub fn encode(
    router_id: u8,
    priority: u8,
    interval: u16,
    addresses: &[Ipv4Addr],
    source: Ipv4Addr,
    destination: Ipv4Addr,
) -> Vec<u8> {
    let addresses = addresses.get(..MAX_ADDRESSES).unwrap_or(addresses);
    let count = u8::try_from(addresses.len()).unwrap_or(u8::MAX);
    let mut packet =
        Vec::with_capacity(HEADER_LEN.saturating_add(addresses.len().saturating_mul(4)));
    packet.extend_from_slice(&[(VERSION << 4) | ADVERTISEMENT, router_id, priority, count]);
    packet.extend_from_slice(&(interval & MAX_INTERVAL).to_be_bytes());
    packet.extend_from_slice(&[0, 0]);
    for address in addresses {
        packet.extend_from_slice(&address.octets());
    }
    let sum = checksum(source, destination, &packet);
    if let Some(field) = packet.get_mut(6..8) {
        field.copy_from_slice(&sum.to_be_bytes());
    }
    packet
}

/// The Internet checksum (RFC 1071) of `vrrp` with the IPv4 pseudo-header
/// in front (RFC 5798, section 5.2.8). Over a packet that holds its
/// checksum, the result is 0 when the checksum is right.
fn checksum(source: Ipv4Addr, destination: Ipv4Addr, vrrp: &[u8]) -> u16 {
    // A VRRP packet is far shorter than 64 KiB; anything longer has already
    // failed the length check, so the length always fits.
    let len = u16::try_from(vrrp.len()).unwrap_or(u16::MAX);
    let [s0, s1, s2, s3] = source.octets();
    let [d0, d1, d2, d3] = destination.octets();
    let [len_hi, len_lo] = len.to_be_bytes();
    let pseudo = [s0, s1, s2, s3, d0, d1, d2, d3, 0, PROTOCOL, len_hi, len_lo];
    let mut sum = add_words(add_words(0, &pseudo), vrrp);
    while sum > 0xffff {
        sum = (sum & 0xffff).wrapping_add(sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(u16::MAX)
}

/// Adds `data` to `sum` as big-endian 16-bit words, padding an odd last
/// byte with zero. Never wraps for data shorter than 128 KiB.
fn add_words(sum: u32, data: &[u8]) -> u32 {
    let (words, rest) = data.as_chunks::<2>();
    let mut sum = words.iter().fold(sum, |sum, &word| {
        sum.wrapping_add(u32::from(u16::from_be_bytes(word)))
    });
    if let &[last] = rest {
        sum = sum.wrapping_add(u32::from(last) << 8);
    }
    sum
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test arithmetic")]
mod tests {
    use super::*;
    use proptest::prelude::*;

    const SOURCE: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);

    /// `vrrp` in an IPv4 header from `source` to `destination`.
    fn ip(vrrp: &[u8], source: Ipv4Addr, destination: Ipv4Addr, ttl: u8) -> Vec<u8> {
        let total = u16::try_from(20 + vrrp.len()).unwrap();
        let mut packet = vec![0x45, 0xc0];
        packet.extend_from_slice(&total.to_be_bytes());
        packet.extend_from_slice(&[0, 0, 0, 0, ttl, PROTOCOL, 0, 0]);
        packet.extend_from_slice(&source.octets());
        packet.extend_from_slice(&destination.octets());
        packet.extend_from_slice(vrrp);
        packet
    }

    #[test]
    fn parses_what_it_encodes() {
        let floating = Ipv4Addr::new(192, 168, 1, 53);
        let vrrp = encode(53, 150, 100, &[floating], SOURCE, GROUP);
        let packet = ip(&vrrp, SOURCE, GROUP, TTL);
        let received = parse(&packet).unwrap();
        assert_eq!(received.source, SOURCE);
        assert_eq!(received.destination, GROUP);
        assert_eq!(received.ttl, TTL);
        assert_eq!(received.advert.router_id, 53);
        assert_eq!(received.advert.priority, 150);
        assert_eq!(received.advert.interval, 100);
        assert_eq!(received.advert.addresses().collect::<Vec<_>>(), [floating]);
    }

    /// The worked example of RFC 1071, section 3.
    #[test]
    fn sums_like_rfc_1071() {
        let sum = add_words(0, &[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]);
        assert_eq!(sum, 0x2_ddf0);
        // Folded: 0xddf2, and the checksum is its complement.
        assert_eq!((sum & 0xffff) + (sum >> 16), 0xddf2);
        assert_eq!(add_words(0, &[0xab]), 0xab00, "an odd byte is padded");
    }

    /// An advertisement whose checksum was computed apart from this code
    /// (with Python's `struct` module, and checked by hand): router 53,
    /// priority 150, 1 s, from 192.168.1.11 to the group.
    #[test]
    fn parses_an_independent_encoding() {
        let packet = [
            0x45, 0xc0, 0x00, 0x20, 0x00, 0x00, 0x00, 0x00, 0xff, 0x70, 0x00, 0x00, 0xc0, 0xa8,
            0x01, 0x0b, 0xe0, 0x00, 0x00, 0x12, 0x31, 0x35, 0x96, 0x01, 0x00, 0x64, 0xd4, 0x44,
            0xc0, 0xa8, 0x01, 0x35,
        ];
        let received = parse(&packet).unwrap();
        assert_eq!(received.source, Ipv4Addr::new(192, 168, 1, 11));
        assert_eq!(received.advert.router_id, 53);
        assert_eq!(received.advert.priority, 150);
        let floating = Ipv4Addr::new(192, 168, 1, 53);
        assert_eq!(received.advert.addresses().collect::<Vec<_>>(), [floating]);
        assert_eq!(
            encode(53, 150, 100, &[floating], received.source, GROUP),
            packet[20..]
        );
    }

    #[test]
    fn checks_what_the_rfc_asks() {
        let good = encode(1, 100, 100, &[Ipv4Addr::new(10, 0, 0, 1)], SOURCE, GROUP);
        let packet = ip(&good, SOURCE, GROUP, TTL);
        assert!(parse(&packet).is_ok());

        // Another source than the checksum was computed for.
        let spoofed = ip(&good, Ipv4Addr::new(192, 168, 1, 11), GROUP, TTL);
        assert_eq!(parse(&spoofed), Err(ParseError::Checksum));

        let mut flipped = packet.clone();
        flipped[22] ^= 1;
        assert_eq!(parse(&flipped), Err(ParseError::Checksum));

        let mut v2 = packet.clone();
        v2[20] = 0x21;
        assert_eq!(parse(&v2), Err(ParseError::Version(2)));

        let mut other_type = packet.clone();
        other_type[20] = 0x32;
        assert_eq!(parse(&other_type), Err(ParseError::Type(2)));

        let mut counted = packet.clone();
        counted[23] = 2;
        assert_eq!(parse(&counted), Err(ParseError::Length(2)));

        let mut udp = packet.clone();
        udp[9] = 17;
        assert_eq!(parse(&udp), Err(ParseError::NotVrrp(17)));

        let mut v6 = packet.clone();
        v6[0] = 0x65;
        assert_eq!(parse(&v6), Err(ParseError::NotIpv4));

        let mut short_header = packet.clone();
        short_header[0] = 0x44;
        assert_eq!(parse(&short_header), Err(ParseError::NotIpv4));

        assert_eq!(parse(&packet[..30]), Err(ParseError::Truncated));
        assert_eq!(parse(&packet[..19]), Err(ParseError::Truncated));
        assert_eq!(parse(&[]), Err(ParseError::Truncated));
    }

    #[test]
    fn skips_ip_options() {
        let vrrp = encode(7, 1, 1, &[], SOURCE, GROUP);
        let mut packet = ip(&vrrp, SOURCE, GROUP, TTL);
        // IHL 6: one word of options (a router alert, say).
        packet[0] = 0x46;
        packet.splice(20..20, [0x94, 0x04, 0x00, 0x00]);
        packet[3] = u8::try_from(packet.len()).unwrap();
        let received = parse(&packet).unwrap();
        assert_eq!(received.advert.router_id, 7);
        assert_eq!(received.advert.addresses().len(), 0);
    }

    #[test]
    fn ignores_the_reserved_bits_and_trailing_bytes() {
        let mut vrrp = encode(1, 100, 100, &[], SOURCE, GROUP);
        vrrp[4] |= 0xf0;
        let sum = {
            vrrp[6..8].copy_from_slice(&[0, 0]);
            checksum(SOURCE, GROUP, &vrrp)
        };
        vrrp[6..8].copy_from_slice(&sum.to_be_bytes());
        let mut packet = ip(&vrrp, SOURCE, GROUP, TTL);
        // Link-layer padding past the IPv4 total length.
        packet.extend_from_slice(&[0; 18]);
        assert_eq!(parse(&packet).unwrap().advert.interval, 100);
    }

    proptest! {
        /// Any bytes: never a panic.
        #[test]
        fn never_panics(packet in proptest::collection::vec(any::<u8>(), 0..1200)) {
            let _ = parse(&packet);
        }

        /// Any advertisement survives a round trip.
        #[test]
        fn round_trips(
            router_id in any::<u8>(),
            priority in any::<u8>(),
            interval in 0..=MAX_INTERVAL,
            addresses in proptest::collection::vec(any::<u32>(), 0..=MAX_ADDRESSES),
            source in any::<u32>(),
            destination in any::<u32>(),
            ttl in any::<u8>(),
        ) {
            let addresses: Vec<_> = addresses.into_iter().map(Ipv4Addr::from).collect();
            let (source, destination) = (Ipv4Addr::from(source), Ipv4Addr::from(destination));
            let vrrp = encode(router_id, priority, interval, &addresses, source, destination);
            let packet = ip(&vrrp, source, destination, ttl);
            let received = parse(&packet).unwrap();
            prop_assert_eq!(received.source, source);
            prop_assert_eq!(received.destination, destination);
            prop_assert_eq!(received.ttl, ttl);
            prop_assert_eq!(received.advert.router_id, router_id);
            prop_assert_eq!(received.advert.priority, priority);
            prop_assert_eq!(received.advert.interval, interval);
            prop_assert_eq!(received.advert.addresses().collect::<Vec<_>>(), addresses);
        }
    }
}
