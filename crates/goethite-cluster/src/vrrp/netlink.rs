//! Adding and removing the floating IP, and reading an interface's hardware
//! address, over rtnetlink (`man 7 rtnetlink`).
//!
//! The messages are built and read here by hand, without a netlink crate:
//! a 16-byte header in host byte order, a fixed structure, then attributes,
//! each padded to four bytes. Replies come from the kernel, and are still
//! read as carefully as packets from the network: [`parse_reply`] never
//! panics.

use std::net::Ipv4Addr;

/// `RTM_NEWLINK`: a link's description, in reply to [`RTM_GETLINK`].
const RTM_NEWLINK: u16 = 16;
/// `RTM_GETLINK`: describe a link.
const RTM_GETLINK: u16 = 18;
/// `RTM_NEWADDR`: add an address.
const RTM_NEWADDR: u16 = 20;
/// `RTM_DELADDR`: remove an address.
const RTM_DELADDR: u16 = 21;
/// `NLMSG_ERROR`: an error code, 0 for an acknowledgement.
const NLMSG_ERROR: u16 = 2;

const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;

/// `AF_INET`.
const AF_INET: u8 = 2;
/// `RT_SCOPE_UNIVERSE`.
const SCOPE_UNIVERSE: u8 = 0;
/// `IFA_ADDRESS`.
const IFA_ADDRESS: u16 = 1;
/// `IFA_LOCAL`.
const IFA_LOCAL: u16 = 2;
/// `IFLA_ADDRESS`: the link's hardware address.
const IFLA_ADDRESS: u16 = 1;
/// The flags in an attribute's type (`NLA_F_NESTED`,
/// `NLA_F_NET_BYTEORDER`).
const NLA_TYPE_MASK: u16 = 0x3fff;

/// `ARPHRD_ETHER`: an Ethernet link, which gratuitous ARP is for.
pub const ARPHRD_ETHER: u16 = 1;

/// A netlink message header.
const HEADER_LEN: usize = 16;
/// `struct ifinfomsg`.
const IFINFOMSG_LEN: usize = 16;
/// An attribute header.
const ATTRIBUTE_HEADER_LEN: usize = 4;

/// What to do with an address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Change {
    /// Add it.
    Add,
    /// Remove it.
    Remove,
}

/// A kernel reply that cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a malformed netlink reply")]
pub struct Malformed;

/// The kernel's reply to a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply {
    /// Done.
    Ack,
    /// Failed, with this `errno`.
    Error(i32),
    /// A link's description.
    Link(Link),
}

/// What `RTM_GETLINK` says about a link.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    /// Its hardware type (`ARPHRD_*`).
    pub kind: u16,
    /// Its six-byte hardware address, if it has one.
    pub hardware: Option<[u8; 6]>,
}

/// A request to add or remove `address`/32 on interface `index`.
pub fn address_request(change: Change, index: u32, address: Ipv4Addr, seq: u32) -> Vec<u8> {
    let (kind, flags) = match change {
        Change::Add => (
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        ),
        Change::Remove => (RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK),
    };
    // struct ifaddrmsg: family, prefix length, flags, scope, index.
    let mut body = vec![AF_INET, 32, 0, SCOPE_UNIVERSE];
    body.extend_from_slice(&index.to_ne_bytes());
    attribute(&mut body, IFA_LOCAL, &address.octets());
    attribute(&mut body, IFA_ADDRESS, &address.octets());
    message(kind, flags, seq, &body)
}

/// A request for the description of interface `index`.
pub fn link_request(index: u32, seq: u32) -> Vec<u8> {
    // struct ifinfomsg: family, padding, type, index, flags, change.
    let mut body = vec![0; 4];
    body.extend_from_slice(&index.to_ne_bytes());
    body.extend_from_slice(&[0; 8]);
    message(RTM_GETLINK, NLM_F_REQUEST, seq, &body)
}

fn message(kind: u16, flags: u16, seq: u32, body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(HEADER_LEN.saturating_add(body.len())).unwrap_or(u32::MAX);
    let mut message = Vec::with_capacity(HEADER_LEN.saturating_add(body.len()));
    message.extend_from_slice(&len.to_ne_bytes());
    message.extend_from_slice(&kind.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&seq.to_ne_bytes());
    // The port ID: 0 lets the kernel fill it in.
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(body);
    message
}

fn attribute(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    let len = ATTRIBUTE_HEADER_LEN.saturating_add(data.len());
    out.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_ne_bytes());
    out.extend_from_slice(&kind.to_ne_bytes());
    out.extend_from_slice(data);
    out.resize(out.len().saturating_add(padding(len)), 0);
}

/// The bytes that pad `len` to a multiple of four.
fn padding(len: usize) -> usize {
    len.wrapping_neg() & 3
}

/// The reply to request `seq` in a datagram from the kernel, if there is
/// one: a datagram can also hold replies to earlier requests, which are
/// skipped.
///
/// # Errors
///
/// [`Malformed`] if a message or attribute runs past its container.
pub fn parse_reply(datagram: &[u8], seq: u32) -> Result<Option<Reply>, Malformed> {
    let mut rest = datagram;
    while !rest.is_empty() {
        let Some(&[l0, l1, l2, l3, k0, k1, _, _, s0, s1, s2, s3, ..]) =
            rest.first_chunk::<HEADER_LEN>()
        else {
            return Err(Malformed);
        };
        let len = usize::try_from(u32::from_ne_bytes([l0, l1, l2, l3])).map_err(|_| Malformed)?;
        let message = rest.get(HEADER_LEN..len).ok_or(Malformed)?;
        if u32::from_ne_bytes([s0, s1, s2, s3]) == seq {
            match u16::from_ne_bytes([k0, k1]) {
                NLMSG_ERROR => {
                    let Some(&code) = message.first_chunk::<4>() else {
                        return Err(Malformed);
                    };
                    let code = i32::from_ne_bytes(code);
                    return Ok(Some(if code == 0 {
                        Reply::Ack
                    } else {
                        Reply::Error(code.saturating_neg())
                    }));
                }
                RTM_NEWLINK => return parse_link(message).map(|link| Some(Reply::Link(link))),
                _ => {}
            }
        }
        rest = rest
            .get(len.saturating_add(padding(len))..)
            .unwrap_or_default();
    }
    Ok(None)
}

/// A `struct ifinfomsg` and its attributes.
fn parse_link(body: &[u8]) -> Result<Link, Malformed> {
    let Some(&[_, _, t0, t1, ..]) = body.first_chunk::<IFINFOMSG_LEN>() else {
        return Err(Malformed);
    };
    let mut link = Link {
        kind: u16::from_ne_bytes([t0, t1]),
        hardware: None,
    };
    let mut rest = body.get(IFINFOMSG_LEN..).unwrap_or_default();
    while !rest.is_empty() {
        let Some(&[l0, l1, k0, k1]) = rest.first_chunk::<ATTRIBUTE_HEADER_LEN>() else {
            return Err(Malformed);
        };
        let len = usize::from(u16::from_ne_bytes([l0, l1]));
        let data = rest.get(ATTRIBUTE_HEADER_LEN..len).ok_or(Malformed)?;
        if u16::from_ne_bytes([k0, k1]) & NLA_TYPE_MASK == IFLA_ADDRESS {
            link.hardware = <[u8; 6]>::try_from(data).ok();
        }
        rest = rest
            .get(len.saturating_add(padding(len))..)
            .unwrap_or_default();
    }
    Ok(link)
}

#[cfg(target_os = "linux")]
pub use socket::Netlink;

#[cfg(target_os = "linux")]
mod socket {
    use std::io;
    use std::net::Ipv4Addr;
    use std::os::fd::OwnedFd;
    use std::time::Duration;

    use rustix::io::Errno;
    use rustix::net::netlink::SocketAddrNetlink;
    use rustix::net::sockopt::{Timeout, set_socket_timeout};
    use rustix::net::{
        AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType, bind, recvfrom, sendto,
        socket_with,
    };

    use super::{Change, Link, Reply, address_request, link_request, parse_reply};

    /// The longest a reply is waited for.
    const TIMEOUT: Duration = Duration::from_secs(2);

    /// The most datagrams read while looking for a reply.
    const MAX_READS: usize = 16;

    /// Room for a reply: a link's description with its statistics is a
    /// few kilobytes.
    const BUFFER_LEN: usize = 32 * 1024;

    /// A route netlink socket.
    #[derive(Debug)]
    pub struct Netlink {
        fd: OwnedFd,
        seq: u32,
    }

    impl Netlink {
        /// Opens one. Changing addresses needs `CAP_NET_ADMIN` when the
        /// requests are sent, not now.
        ///
        /// # Errors
        ///
        /// If the socket cannot be opened.
        pub fn open() -> io::Result<Self> {
            let fd = socket_with(
                AddressFamily::NETLINK,
                SocketType::RAW,
                SocketFlags::CLOEXEC,
                // Protocol 0 is NETLINK_ROUTE.
                None,
            )?;
            bind(&fd, &SocketAddrNetlink::new(0, 0))?;
            set_socket_timeout(&fd, Timeout::Recv, Some(TIMEOUT))?;
            Ok(Self { fd, seq: 0 })
        }

        /// Adds `address`/32 to interface `index`. Already there is fine.
        ///
        /// # Errors
        ///
        /// The kernel's error otherwise.
        pub fn add(&mut self, index: u32, address: Ipv4Addr) -> io::Result<()> {
            match self.request(|seq| address_request(Change::Add, index, address, seq))? {
                Reply::Ack => Ok(()),
                Reply::Error(code) if code == Errno::EXIST.raw_os_error() => Ok(()),
                other => Err(unexpected(other)),
            }
        }

        /// Removes `address` from interface `index`: whether it was there.
        ///
        /// # Errors
        ///
        /// The kernel's error, other than the address not being there.
        pub fn remove(&mut self, index: u32, address: Ipv4Addr) -> io::Result<bool> {
            match self.request(|seq| address_request(Change::Remove, index, address, seq))? {
                Reply::Ack => Ok(true),
                Reply::Error(code) if code == Errno::ADDRNOTAVAIL.raw_os_error() => Ok(false),
                other => Err(unexpected(other)),
            }
        }

        /// The description of interface `index`.
        ///
        /// # Errors
        ///
        /// The kernel's error, such as no such interface.
        pub fn link(&mut self, index: u32) -> io::Result<Link> {
            match self.request(|seq| link_request(index, seq))? {
                Reply::Link(link) => Ok(link),
                other => Err(unexpected(other)),
            }
        }

        fn request(&mut self, build: impl FnOnce(u32) -> Vec<u8>) -> io::Result<Reply> {
            self.seq = self.seq.wrapping_add(1);
            let seq = self.seq;
            let kernel = SocketAddrNetlink::new(0, 0);
            sendto(&self.fd, &build(seq), SendFlags::empty(), &kernel)?;
            let mut buffer = vec![0; BUFFER_LEN];
            for _ in 0..MAX_READS {
                let (len, full, from) = recvfrom(&self.fd, &mut buffer[..], RecvFlags::TRUNC)?;
                // Only the kernel (port 0) answers requests; other
                // processes could send to this socket too.
                let from_kernel = from
                    .and_then(|from| SocketAddrNetlink::try_from(from).ok())
                    .is_some_and(|from| from.pid() == 0);
                if !from_kernel {
                    continue;
                }
                if full > len {
                    return Err(io::Error::other("a netlink reply was too long"));
                }
                let datagram = buffer.get(..len).unwrap_or_default();
                if let Some(reply) = parse_reply(datagram, seq).map_err(io::Error::other)? {
                    return Ok(reply);
                }
            }
            Err(io::Error::other("no netlink reply"))
        }
    }

    fn unexpected(reply: Reply) -> io::Error {
        match reply {
            Reply::Error(code) => io::Error::from_raw_os_error(code),
            Reply::Ack | Reply::Link(_) => io::Error::other("an unexpected netlink reply"),
        }
    }
}

#[cfg(test)]
#[allow(clippy::arithmetic_side_effects, reason = "test arithmetic")]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn reply(kind: u16, seq: u32, body: &[u8]) -> Vec<u8> {
        let mut message = message(kind, 0, seq, body);
        message.resize(message.len() + padding(message.len()), 0);
        message
    }

    #[test]
    fn builds_address_requests() {
        let request = address_request(Change::Add, 2, Ipv4Addr::new(192, 168, 1, 53), 7);
        // Header, ifaddrmsg, two eight-byte attributes.
        assert_eq!(request.len(), 16 + 8 + 8 + 8);
        assert_eq!(u32::from_ne_bytes(request[..4].try_into().unwrap()), 40);
        assert_eq!(u16::from_ne_bytes([request[4], request[5]]), RTM_NEWADDR);
        assert_eq!(
            u16::from_ne_bytes([request[6], request[7]]),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        assert_eq!(u32::from_ne_bytes(request[8..12].try_into().unwrap()), 7);
        assert_eq!(&request[16..20], &[AF_INET, 32, 0, 0]);
        assert_eq!(u32::from_ne_bytes(request[20..24].try_into().unwrap()), 2);
        assert_eq!(u16::from_ne_bytes([request[26], request[27]]), IFA_LOCAL);
        assert_eq!(&request[28..32], &[192, 168, 1, 53]);
        assert_eq!(u16::from_ne_bytes([request[34], request[35]]), IFA_ADDRESS);

        let request = address_request(Change::Remove, 2, Ipv4Addr::new(192, 168, 1, 53), 8);
        assert_eq!(u16::from_ne_bytes([request[4], request[5]]), RTM_DELADDR);

        let request = link_request(3, 9);
        assert_eq!(request.len(), 32);
        assert_eq!(u16::from_ne_bytes([request[4], request[5]]), RTM_GETLINK);
        assert_eq!(u32::from_ne_bytes(request[20..24].try_into().unwrap()), 3);
    }

    #[test]
    fn reads_acknowledgements_and_errors() {
        let ack = reply(NLMSG_ERROR, 5, &[0; 20]);
        assert_eq!(parse_reply(&ack, 5), Ok(Some(Reply::Ack)));
        let mut error = (-17_i32).to_ne_bytes().to_vec();
        error.extend_from_slice(&[0; 16]);
        assert_eq!(
            parse_reply(&reply(NLMSG_ERROR, 5, &error), 5),
            Ok(Some(Reply::Error(17)))
        );
        // A reply to another request is skipped.
        assert_eq!(parse_reply(&ack, 4), Ok(None));
        let both = [reply(NLMSG_ERROR, 4, &error), ack].concat();
        assert_eq!(parse_reply(&both, 5), Ok(Some(Reply::Ack)));
    }

    #[test]
    fn reads_links() {
        let mut body = vec![0, 0];
        body.extend_from_slice(&ARPHRD_ETHER.to_ne_bytes());
        body.extend_from_slice(&[0; 12]);
        // IFLA_IFNAME "eth0", padded, then IFLA_ADDRESS.
        attribute(&mut body, 3, b"eth0\0");
        attribute(&mut body, IFLA_ADDRESS, &[2, 0, 0, 0, 0, 1]);
        let link = parse_reply(&reply(RTM_NEWLINK, 1, &body), 1)
            .unwrap()
            .unwrap();
        assert_eq!(
            link,
            Reply::Link(Link {
                kind: ARPHRD_ETHER,
                hardware: Some([2, 0, 0, 0, 0, 1]),
            })
        );

        // A link without a six-byte address, such as a tunnel.
        let mut body = vec![0, 0, 0xff, 0xff];
        body.extend_from_slice(&[0; 12]);
        attribute(&mut body, IFLA_ADDRESS, &[0; 4]);
        let Some(Reply::Link(link)) = parse_reply(&reply(RTM_NEWLINK, 1, &body), 1).unwrap() else {
            panic!("not a link");
        };
        assert_eq!(link.hardware, None);
    }

    #[test]
    fn refuses_what_runs_past_its_end() {
        let ack = reply(NLMSG_ERROR, 5, &[0; 20]);
        assert_eq!(parse_reply(&ack[..10], 5), Err(Malformed));
        let mut long = ack.clone();
        long[0] = 200;
        assert_eq!(parse_reply(&long, 5), Err(Malformed));
        let mut short = ack;
        short[..4].copy_from_slice(&3_u32.to_ne_bytes());
        assert_eq!(parse_reply(&short, 5), Err(Malformed));
        assert_eq!(
            parse_reply(&reply(NLMSG_ERROR, 5, &[0; 2]), 5),
            Err(Malformed)
        );
        let mut body = vec![0; 16];
        body.extend_from_slice(&[40, 0, 1, 0, 1, 2]);
        assert_eq!(
            parse_reply(&reply(RTM_NEWLINK, 1, &body), 1),
            Err(Malformed)
        );
        assert_eq!(parse_reply(&[], 1), Ok(None));
    }

    proptest! {
        /// Any bytes: never a panic.
        #[test]
        fn never_panics(
            datagram in proptest::collection::vec(any::<u8>(), 0..512),
            seq in 0..4_u32,
        ) {
            let _ = parse_reply(&datagram, seq);
        }
    }
}
