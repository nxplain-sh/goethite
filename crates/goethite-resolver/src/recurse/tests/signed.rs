//! DNSSEC validation against a signed simulated internet:
//!
//! - the root at 10.0.0.1 (NSEC), delegating `com` and `net` with DS;
//! - `com` at 10.0.1.1 (NSEC3), delegating `example.com` with DS and
//!   `insecure.com` without;
//! - `net` at 10.0.2.1 (NSEC), delegating `provider.net` without DS;
//! - `example.com` at 10.0.3.1 (NSEC): addresses, a CNAME into
//!   `insecure.com`, a wildcard and an empty non-terminal;
//! - `insecure.com` and `provider.net` at 10.0.4.1 and 10.0.5.1, unsigned.

use std::time::{SystemTime, UNIX_EPOCH};

use goethite_proto::dnssec::signing::{self, Key};

use super::*;
use crate::recurse::RecursorStats;

/// How the zone proves what does not exist.
#[derive(Clone, Copy)]
enum Chain {
    Nsec,
    Nsec3,
}

/// A name from its labels, so `*` may be one.
fn labels(text: &str) -> Name {
    Name::from_labels(text.split('.').filter(|l| !l.is_empty()).map(str::as_bytes)).unwrap()
}

fn now() -> u32 {
    u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    )
    .unwrap()
}

/// Signatures valid from an hour ago for a month.
fn current() -> (u32, u32) {
    (now() - 3_600, now() + 30 * 86_400)
}

/// `records` of the zone at `origin`, signed with `key` for `window`: an
/// SOA and the DNSKEY added, the denial chain built, and every RRset the
/// zone is authoritative for signed (not delegations' NS, nor glue).
fn signed(
    origin: &str,
    key: &Key,
    records: Vec<Record>,
    chain: Chain,
    window: (u32, u32),
) -> Vec<Record> {
    let origin = name(origin);
    let mut records = records;
    records.push(Record::soa(origin.clone(), 3600, name("ns.invalid."), 300));
    records.push(key.dnskey(3600));
    let cuts: Vec<Name> = records
        .iter()
        .filter(|r| r.record_type() == RecordType::NS && r.name() != &origin)
        .map(|r| r.name().clone())
        .collect();
    let below_cut = |r: &Record| {
        cuts.iter().any(|cut| {
            // The parent's DS and NSEC at the cut are its own.
            r.name().is_within(cut)
                && !(r.name() == cut
                    && matches!(r.record_type(), RecordType::DS | RecordType::NSEC))
        })
    };
    let mut owners: Vec<Name> = Vec::new();
    for record in &records {
        if (!below_cut(record) || cuts.contains(record.name())) && !owners.contains(record.name()) {
            owners.push(record.name().clone());
        }
    }
    let types_at = |owner: &Name| -> Vec<RecordType> {
        let mut types: Vec<RecordType> = records
            .iter()
            .filter(|r| r.name() == owner)
            .map(Record::record_type)
            .collect();
        types.sort_by_key(|t| t.0);
        types.dedup();
        types
    };
    match chain {
        Chain::Nsec => {
            owners.sort_by(Name::canonical_cmp);
            let mut nsecs = Vec::new();
            for (i, owner) in owners.iter().enumerate() {
                let next = &owners[(i + 1) % owners.len()];
                let mut types = types_at(owner);
                types.extend([RecordType::NSEC, RecordType::RRSIG]);
                nsecs.push(signing::nsec(owner, 300, next, &types));
            }
            records.extend(nsecs);
        }
        Chain::Nsec3 => {
            // Empty non-terminals have hashes too.
            let mut names = owners.clone();
            for owner in &owners {
                let mut at = owner.parent();
                while let Some(parent) = at {
                    if parent.label_count() <= origin.label_count() {
                        break;
                    }
                    if !names.contains(&parent) {
                        names.push(parent.clone());
                    }
                    at = parent.parent();
                }
            }
            let mut hashed: Vec<(Vec<u8>, Name)> = names
                .into_iter()
                .map(|n| (goethite_proto::dnssec::nsec3_hash(&n, &[], 0).unwrap(), n))
                .collect();
            hashed.sort_by(|a, b| a.0.cmp(&b.0));
            let mut nsec3s = Vec::new();
            for (i, (_, owner)) in hashed.iter().enumerate() {
                let next = &hashed[(i + 1) % hashed.len()].0;
                let mut types = types_at(owner);
                // Signed data there: not an empty non-terminal, nor an
                // unsigned delegation.
                let unsigned_cut = cuts.contains(owner) && !types.contains(&RecordType::DS);
                if !types.is_empty() && !unsigned_cut {
                    types.push(RecordType::RRSIG);
                }
                nsec3s.push(signing::nsec3(&origin, owner, 300, next, false, &types));
            }
            records.extend(nsec3s);
        }
    }
    let mut sigs = Vec::new();
    for rrset in crate::recurse::dnssec::rrsets(&records) {
        if !below_cut(&rrset[0]) {
            sigs.push(key.sign(&rrset, window.0, window.1));
        }
    }
    records.extend(sigs);
    records
}

struct World {
    fake: Fake,
    root: Key,
}

/// The signed internet, with `example.com` signed for `window`.
fn world_with(window: (u32, u32)) -> World {
    let root = Key::generate(&Name::root());
    let com = Key::generate(&name("com."));
    let net = Key::generate(&name("net."));
    let example = Key::generate(&name("example.com."));
    let mut fake = Fake::default();
    fake.serve(
        "10.0.0.1",
        ".",
        signed(
            ".",
            &root,
            vec![
                Record::ns(Name::root(), 518_400, name("a.root.test.")),
                Record::ns(name("com."), 172_800, name("ns.com.")),
                Record::a(name("ns.com."), 172_800, Ipv4Addr::new(10, 0, 1, 1)),
                com.ds(86_400),
                Record::ns(name("net."), 172_800, name("ns.net.")),
                Record::a(name("ns.net."), 172_800, Ipv4Addr::new(10, 0, 2, 1)),
                net.ds(86_400),
                Record::a(name("a.root.test."), 518_400, Ipv4Addr::new(10, 0, 0, 1)),
            ],
            Chain::Nsec,
            current(),
        ),
    )
    .serve(
        "10.0.1.1",
        "com.",
        signed(
            "com.",
            &com,
            vec![
                Record::ns(name("example.com."), 172_800, name("ns1.example.com.")),
                Record::a(
                    name("ns1.example.com."),
                    172_800,
                    Ipv4Addr::new(10, 0, 3, 1),
                ),
                example.ds(86_400),
                Record::ns(name("insecure.com."), 172_800, name("ns.insecure.com.")),
                Record::a(
                    name("ns.insecure.com."),
                    172_800,
                    Ipv4Addr::new(10, 0, 4, 1),
                ),
            ],
            Chain::Nsec3,
            current(),
        ),
    )
    .serve(
        "10.0.2.1",
        "net.",
        signed(
            "net.",
            &net,
            vec![
                Record::ns(name("provider.net."), 172_800, name("ns.provider.net.")),
                Record::a(
                    name("ns.provider.net."),
                    172_800,
                    Ipv4Addr::new(10, 0, 5, 1),
                ),
            ],
            Chain::Nsec,
            current(),
        ),
    )
    .serve(
        "10.0.3.1",
        "example.com.",
        signed(
            "example.com.",
            &example,
            vec![
                Record::a(name("www.example.com."), 300, Ipv4Addr::new(192, 0, 2, 1)),
                Record::cname(name("out.example.com."), 300, name("www.insecure.com.")),
                Record::a(
                    labels("*.wild.example.com."),
                    300,
                    Ipv4Addr::new(192, 0, 2, 7),
                ),
                Record::a(name("a.b.c.example.com."), 300, Ipv4Addr::new(192, 0, 2, 9)),
            ],
            Chain::Nsec,
            window,
        ),
    )
    .serve(
        "10.0.4.1",
        "insecure.com.",
        vec![Record::a(
            name("www.insecure.com."),
            300,
            Ipv4Addr::new(192, 0, 2, 4),
        )],
    )
    .serve(
        "10.0.5.1",
        "provider.net.",
        vec![Record::a(
            name("ns.provider.net."),
            300,
            Ipv4Addr::new(10, 0, 5, 1),
        )],
    );
    World { fake, root }
}

fn world() -> World {
    world_with(current())
}

fn validating(world: World) -> (Recursor, Arc<Fake>) {
    let anchors = vec![world.root.ds(172_800)];
    recursor(
        world.fake,
        RecursorConfig {
            dnssec: true,
            anchors: Some(anchors),
            ..config()
        },
    )
}

fn with_do(mut query: Query) -> Query {
    query.edns = Some(Edns {
        dnssec_ok: true,
        ..Edns::ours()
    });
    query
}

fn security(stats: RecursorStats) -> (u64, u64, u64) {
    (stats.secure, stats.insecure, stats.bogus)
}

#[tokio::test]
async fn signed_answers_are_secure() {
    let (recursor, _) = validating(world());
    let (response, _) = recursor
        .resolve(&query("www.example.com.", RecordType::A))
        .await;
    assert_eq!(response.rcode, ResponseCode::NO_ERROR);
    assert!(response.authentic_data);
    assert_eq!(addresses(&response), [ip("192.0.2.1")]);
    assert!(
        response
            .answers
            .iter()
            .all(|r| r.record_type() == RecordType::A),
        "no signatures for a client without DO"
    );
    // With DO, the signature comes along.
    let (signed, _) = recursor
        .resolve(&with_do(query("www.example.com.", RecordType::A)))
        .await;
    assert!(signed.authentic_data);
    assert!(
        signed
            .answers
            .iter()
            .any(|r| r.record_type() == RecordType::RRSIG)
    );
    // A wildcard, proven not to hide a real name; an empty non-terminal on
    // the way to a name.
    for qname in ["anything.wild.example.com.", "a.b.c.example.com."] {
        let (response, _) = recursor.resolve(&query(qname, RecordType::A)).await;
        assert!(response.authentic_data, "{qname}");
        assert_eq!(addresses(&response).len(), 1, "{qname}");
    }
    assert_eq!(security(recursor.stats()), (4, 0, 0));
}

#[tokio::test]
async fn denial_is_proven() {
    let (recursor, _) = validating(world());
    for (qname, qtype, rcode) in [
        // NSEC in example.com.
        ("nope.example.com.", RecordType::A, ResponseCode::NX_DOMAIN),
        ("www.example.com.", RecordType::AAAA, ResponseCode::NO_ERROR),
        // An empty non-terminal.
        ("c.example.com.", RecordType::A, ResponseCode::NO_ERROR),
        // A wildcard without the type.
        (
            "x.wild.example.com.",
            RecordType::TXT,
            ResponseCode::NO_ERROR,
        ),
        // NSEC3 in com.
        ("nope.com.", RecordType::A, ResponseCode::NX_DOMAIN),
        // The parent's proof of no DS for an unsigned delegation.
        ("insecure.com.", RecordType::DS, ResponseCode::NO_ERROR),
    ] {
        let (response, _) = recursor.resolve(&with_do(query(qname, qtype))).await;
        assert_eq!(response.rcode, rcode, "{qname} {qtype}");
        assert!(response.authentic_data, "{qname} {qtype}");
        assert!(
            response
                .authority
                .iter()
                .any(|r| matches!(r.record_type(), RecordType::NSEC | RecordType::NSEC3)),
            "{qname} {qtype}: the proof, for a client with DO"
        );
    }
}

#[tokio::test]
async fn unsigned_zones_are_insecure() {
    let (recursor, _) = validating(world());
    // Into an unsigned zone through a signed CNAME: answered, without AD.
    let (response, _) = recursor
        .resolve(&query("out.example.com.", RecordType::A))
        .await;
    assert_eq!(response.rcode, ResponseCode::NO_ERROR);
    assert!(!response.authentic_data);
    assert_eq!(addresses(&response), [ip("192.0.2.4")]);
    // Under net, NSEC proves provider.net unsigned.
    let (response, _) = recursor
        .resolve(&query("ns.provider.net.", RecordType::A))
        .await;
    assert_eq!(addresses(&response), [ip("10.0.5.1")]);
    assert!(!response.authentic_data);
    assert_eq!(security(recursor.stats()), (0, 2, 0));
}

#[tokio::test]
async fn bogus_answers_are_refused() {
    // Changed data (the negative answer is untouched), missing signatures
    // and stale signatures.
    let quirks = [
        (
            Quirks {
                tampers: true,
                ..Quirks::default()
            },
            ResponseCode::NX_DOMAIN,
        ),
        (
            Quirks {
                strips: true,
                ..Quirks::default()
            },
            ResponseCode::SERV_FAIL,
        ),
    ];
    for (quirk, negative) in quirks {
        let mut world = world();
        world.fake.quirks("10.0.3.1", quirk);
        let (recursor, _) = validating(world);
        let (response, server) = recursor
            .resolve(&query("www.example.com.", RecordType::A))
            .await;
        assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
        assert_eq!((response.answers.len(), server), (0, None));
        let (nx, _) = recursor
            .resolve(&query("nope.example.com.", RecordType::A))
            .await;
        assert_eq!(nx.rcode, negative);
        assert!(recursor.stats().bogus >= 1);
    }
    let expired = (now() - 30 * 86_400, now() - 86_400);
    let (recursor, _) = validating(world_with(expired));
    let (response, _) = recursor
        .resolve(&query("www.example.com.", RecordType::A))
        .await;
    assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
    // Asked to skip validation (CD): the answer, without AD.
    let mut world = world();
    world.fake.quirks(
        "10.0.3.1",
        Quirks {
            tampers: true,
            ..Quirks::default()
        },
    );
    let (recursor, _) = validating(world);
    let mut unchecked = query("www.example.com.", RecordType::A);
    unchecked.checking_disabled = true;
    let (response, _) = recursor.resolve(&unchecked).await;
    assert_eq!(addresses(&response), [ip("6.6.6.6")]);
    assert!(!response.authentic_data);
}

/// A server that signs `www.example.com` with its own key, claiming that
/// name as the signer: an unsigned zone of its own, it hopes. The parent's
/// signed NSEC there shows no delegation, so it is no zone: bogus, not
/// insecure.
#[tokio::test]
async fn a_forged_signer_does_not_downgrade() {
    let mut world = world();
    let www = name("www.example.com.");
    let attacker = Key::generate(&www);
    let server = world.fake.servers.get_mut(&ip("10.0.3.1")).unwrap();
    let zone = &mut server.zones[0];
    zone.records.retain(|r| {
        !(r.name() == &www
            && r.rrsig()
                .is_some_and(|sig| sig.type_covered == RecordType::A))
    });
    let forged = vec![Record::a(www.clone(), 300, Ipv4Addr::new(6, 6, 6, 6))];
    let sig = attacker.sign(&forged, current().0, current().1);
    zone.records
        .retain(|r| !(r.name() == &www && r.record_type() == RecordType::A));
    zone.records.extend(forged);
    zone.records.push(sig);
    zone.records.push(attacker.dnskey(300));
    let (recursor, _) = validating(world);
    let (response, _) = recursor
        .resolve(&query("www.example.com.", RecordType::A))
        .await;
    assert_eq!(response.rcode, ResponseCode::SERV_FAIL);
    assert_eq!(security(recursor.stats()), (0, 0, 1));
}

#[tokio::test]
async fn the_wrong_trust_anchor_fails_everything() {
    let mut world = world();
    world.root = Key::generate(&Name::root());
    let (recursor, _) = validating(world);
    for qname in ["www.example.com.", "www.insecure.com."] {
        let (response, _) = recursor.resolve(&query(qname, RecordType::A)).await;
        assert_eq!(response.rcode, ResponseCode::SERV_FAIL, "{qname}");
    }
}

#[tokio::test]
async fn the_chain_of_trust_is_kept() {
    let (recursor, fake) = validating(world());
    recursor
        .resolve(&query("www.example.com.", RecordType::A))
        .await;
    let before = fake.asked().len();
    let (response, _) = recursor
        .resolve(&query("nope.example.com.", RecordType::A))
        .await;
    assert!(response.authentic_data);
    assert_eq!(
        fake.asked()[before..]
            .iter()
            .filter(|(_, _, qtype, _)| matches!(qtype, &RecordType::DS | &RecordType::DNSKEY))
            .count(),
        0,
        "the keys and DS records are known by now"
    );
}
