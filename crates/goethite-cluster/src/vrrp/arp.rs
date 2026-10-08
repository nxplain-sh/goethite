//! Gratuitous ARP: telling the network which hardware address the floating
//! IP is at, so switches and hosts stop sending its traffic to the node
//! that held it before.
//!
//! The announcement is an ARP request for the address, from the address
//! (RFC 5227, section 3), broadcast on the interface. It goes out through
//! an `AF_PACKET` socket, whose destination is a link-layer address
//! (`struct sockaddr_ll`). rustix has no type for one, and passing it to
//! the kernel takes the one `unsafe` implementation in this crate.

use std::net::Ipv4Addr;

/// An ARP packet for Ethernet and IPv4.
pub const ARP_LEN: usize = 28;

/// The announcement that `address` is at `hardware`.
pub fn announcement(hardware: [u8; 6], address: Ipv4Addr) -> [u8; ARP_LEN] {
    let [h0, h1, h2, h3, h4, h5] = hardware;
    let [a0, a1, a2, a3] = address.octets();
    [
        // Ethernet, IPv4, address lengths 6 and 4, a request.
        0, 1, 8, 0, 6, 4, 0, 1, //
        // Sender: this hardware address, the floating IP.
        h0, h1, h2, h3, h4, h5, a0, a1, a2, a3, //
        // Target: unknown hardware, the floating IP again.
        0, 0, 0, 0, 0, 0, a0, a1, a2, a3,
    ]
}

#[cfg(target_os = "linux")]
pub use socket::ArpSocket;

#[cfg(target_os = "linux")]
mod socket {
    use std::io;
    use std::net::Ipv4Addr;
    use std::os::fd::OwnedFd;

    use rustix::net::addr::{SocketAddrArg, SocketAddrLen, SocketAddrOpaque};
    use rustix::net::{AddressFamily, SendFlags, SocketFlags, SocketType, sendto, socket_with};

    use super::announcement;

    /// `AF_PACKET`.
    const AF_PACKET: u16 = 17;
    /// `ETH_P_ARP`.
    const ETH_P_ARP: u16 = 0x0806;
    /// `ARPHRD_ETHER`.
    const ARPHRD_ETHER: u16 = 1;

    /// A packet socket for announcements on one interface.
    #[derive(Debug)]
    pub struct ArpSocket {
        fd: OwnedFd,
        destination: LinkAddress,
    }

    impl ArpSocket {
        /// Opens one for interface `index`. Needs `CAP_NET_RAW`.
        ///
        /// # Errors
        ///
        /// If the socket cannot be opened.
        pub fn open(index: u32) -> io::Result<Self> {
            // Protocol 0: the socket receives nothing, it only sends.
            let fd = socket_with(
                AddressFamily::PACKET,
                SocketType::DGRAM,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )?;
            let index = i32::try_from(index).map_err(io::Error::other)?;
            Ok(Self {
                fd,
                destination: LinkAddress::broadcast(index),
            })
        }

        /// Announces that `address` is at `hardware`, this interface's
        /// address. The kernel adds the Ethernet header.
        ///
        /// # Errors
        ///
        /// If it cannot be sent.
        pub fn announce(&self, hardware: [u8; 6], address: Ipv4Addr) -> io::Result<()> {
            let packet = announcement(hardware, address);
            sendto(&self.fd, &packet, SendFlags::empty(), &self.destination)?;
            Ok(())
        }
    }

    /// `struct sockaddr_ll` (`man 7 packet`), field for field.
    #[derive(Clone, Copy, Debug)]
    #[repr(C)]
    struct LinkAddress {
        family: u16,
        /// The Ethernet protocol, in network byte order.
        protocol: u16,
        index: i32,
        hardware_type: u16,
        packet_type: u8,
        address_len: u8,
        address: [u8; 8],
    }

    /// Its size, which the kernel checks.
    const LINK_ADDRESS_LEN: SocketAddrLen = 20;
    const _: () = assert!(size_of::<LinkAddress>() == LINK_ADDRESS_LEN as usize);

    impl LinkAddress {
        /// The Ethernet broadcast address on interface `index`, for ARP.
        fn broadcast(index: i32) -> Self {
            Self {
                family: AF_PACKET,
                protocol: ETH_P_ARP.to_be(),
                index,
                hardware_type: ARPHRD_ETHER,
                packet_type: 0,
                address_len: 6,
                address: [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0],
            }
        }
    }

    // SAFETY: `with_sockaddr` passes `f` a pointer to `self`, which is
    // borrowed for the whole call, so the pointer stays valid and readable
    // while `f` runs. `LinkAddress` is `#[repr(C)]` with the fields of
    // `struct sockaddr_ll` in its order and of its types, every field
    // initialized and no padding between them, so its
    // `LINK_ADDRESS_LEN` bytes (checked against its size above) are a
    // valid `sockaddr_ll` for the system calls that read one.
    #[allow(
        unsafe_code,
        reason = "rustix has no link-layer address type; see the SAFETY comment"
    )]
    unsafe impl SocketAddrArg for LinkAddress {
        unsafe fn with_sockaddr<R>(
            &self,
            f: impl FnOnce(*const SocketAddrOpaque, SocketAddrLen) -> R,
        ) -> R {
            f(std::ptr::from_ref(self).cast(), LINK_ADDRESS_LEN)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn announces_the_address() {
        let packet = announcement([2, 0, 0, 0, 0, 7], Ipv4Addr::new(192, 168, 1, 53));
        assert_eq!(&packet[..8], &[0, 1, 8, 0, 6, 4, 0, 1]);
        assert_eq!(&packet[8..14], &[2, 0, 0, 0, 0, 7]);
        assert_eq!(&packet[14..18], &[192, 168, 1, 53]);
        assert_eq!(&packet[18..24], &[0; 6]);
        assert_eq!(&packet[24..], &[192, 168, 1, 53]);
    }
}
