//! Fuzz target: reading rtnetlink replies, as `goethite vrrp` does after
//! adding or removing the floating IP and when reading the interface's
//! hardware address.
//!
//! Invariants checked on every input:
//! - parsing never panics, whichever request the reply is matched to;
//! - parsing is deterministic.

#![no_main]

use goethite_cluster::vrrp::netlink::parse_reply;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Sequence numbers start at 1; the first message's own is likely too.
    let own = data
        .get(8..12)
        .and_then(|seq| <[u8; 4]>::try_from(seq).ok())
        .map_or(1, u32::from_ne_bytes);
    for seq in [0, 1, own] {
        let first = parse_reply(data, seq);
        assert_eq!(first, parse_reply(data, seq));
    }
});
