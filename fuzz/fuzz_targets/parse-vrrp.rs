//! Fuzz target: reading VRRP advertisements from the network, IPv4 header
//! included, as `goethite vrrp` receives them on a raw socket.
//!
//! Invariants checked on every input:
//! - parsing and checking against a configuration never panic;
//! - a parsed advertisement, encoded again from what was read, parses
//!   back to the same fields.

#![no_main]

use std::net::Ipv4Addr;

use goethite_cluster::vrrp::packet::{self, PROTOCOL};
use goethite_cluster::vrrp::{VrrpConfig, check};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(received) = packet::parse(data) else {
        return;
    };
    let config = VrrpConfig {
        interface: "eth0".into(),
        address: Ipv4Addr::new(192, 168, 1, 53),
        router_id: received.advert.router_id,
        priority: 100,
        interval: 100,
        preempt: true,
        peer: received.source,
        unicast: false,
    };
    let _ = check(&config, Ipv4Addr::new(192, 168, 1, 10), &received);

    let advert = received.advert;
    let addresses: Vec<Ipv4Addr> = advert.addresses().collect();
    let vrrp = packet::encode(
        advert.router_id,
        advert.priority,
        advert.interval,
        &addresses,
        received.source,
        received.destination,
    );
    let total = u16::try_from(20 + vrrp.len()).expect("an advertisement is short");
    let mut again = vec![0x45, 0];
    again.extend_from_slice(&total.to_be_bytes());
    again.extend_from_slice(&[0, 0, 0, 0, received.ttl, PROTOCOL, 0, 0]);
    again.extend_from_slice(&received.source.octets());
    again.extend_from_slice(&received.destination.octets());
    again.extend_from_slice(&vrrp);
    let reparsed = packet::parse(&again).expect("an encoded advertisement parses");
    assert_eq!(reparsed.source, received.source);
    assert_eq!(reparsed.destination, received.destination);
    assert_eq!(reparsed.ttl, received.ttl);
    assert_eq!(reparsed.advert.router_id, advert.router_id);
    assert_eq!(reparsed.advert.priority, advert.priority);
    assert_eq!(reparsed.advert.interval, advert.interval);
    assert!(reparsed.advert.addresses().eq(addresses));
});
