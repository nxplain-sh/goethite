//! Cache and pipeline micro-benchmarks.
//!
//! Run with `cargo bench -p goethite-resolver`. See `bench/README.md` for
//! how results are recorded.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    missing_docs,
    reason = "benchmark harness, not product code"
)]

use std::fmt::Write as _;
use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::pin;
use std::sync::Arc;
use std::task::{Context, Poll, Waker};

use criterion::{Criterion, criterion_group, criterion_main};
use goethite_filter::{FilterBuilder, Source, Sources};
use goethite_proto::{
    Edns, Query, Question, Record, RecordClass, RecordType, Response, ResponseCode,
};
use goethite_resolver::{
    BlockResponse, Cache, CacheConfig, ClientPolicy, Forwarder, ForwarderConfig, GroupPolicy,
    Policy, PolicyParts, PolicyState, Resolver, UpstreamConfig,
};

const ENTRIES: usize = 10_000;

fn query(name: &str) -> Query {
    Query {
        id: 7,
        recursion_desired: true,
        checking_disabled: false,
        authentic_data: false,
        question: Question {
            name: name.parse().unwrap(),
            qtype: RecordType::A,
            qclass: RecordClass::IN,
        },
        edns: Some(Edns {
            udp_payload_size: 1232,
            dnssec_ok: false,
            padding: false,
        }),
    }
}

fn answer(query: &Query) -> Response {
    let mut response = Response::for_query(query, ResponseCode::NO_ERROR);
    response.answers = vec![
        Record::a(
            query.question.name.clone(),
            3_600,
            Ipv4Addr::new(192, 0, 2, 1),
        ),
        Record::a(
            query.question.name.clone(),
            3_600,
            Ipv4Addr::new(192, 0, 2, 2),
        ),
    ];
    response
}

/// A cache filled with `ENTRIES` names, `host{i}.example.`.
fn filled() -> Cache {
    let cache = Cache::new(CacheConfig::default());
    for i in 0..ENTRIES {
        let q = query(&format!("host{i}.example."));
        cache.insert(&q, &answer(&q));
    }
    cache
}

fn cache(c: &mut Criterion) {
    let cache = filled();
    let hit = query("host4242.example.");
    let miss = query("absent.example.");
    let fresh = query("fresh.example.");
    let fresh_answer = answer(&fresh);

    c.bench_function("cache/get hit (10k entries)", |b| {
        b.iter(|| black_box(cache.get(black_box(&hit))));
    });
    c.bench_function("cache/get miss (10k entries)", |b| {
        b.iter(|| black_box(cache.get(black_box(&miss))));
    });
    c.bench_function("cache/insert (10k entries)", |b| {
        b.iter(|| cache.insert(black_box(&fresh), black_box(&fresh_answer)));
    });
}

/// A policy like a busy home network's: 100,000 rules in two lists, a
/// default group and a group using both lists, and 100 known clients.
fn policy() -> Policy {
    let mut builder = FilterBuilder::new();
    for list in 0..2 {
        let mut text = String::new();
        for i in 0..50_000 {
            writeln!(text, "||ad{i}.list{list}.example^").unwrap();
        }
        builder.add_list(Source::new(list).unwrap(), &text);
    }
    let both: Sources = (0..2).map(|i| Source::new(i).unwrap()).collect();
    let clients = (0..100_u8)
        .map(|i| ClientPolicy {
            id: format!("client{i}").into(),
            addresses: vec![IpAddr::from(Ipv4Addr::new(192, 168, 1, i)).into_cidr()],
            ids: Vec::new(),
            group: usize::from(i % 2),
        })
        .collect();
    Policy::new(PolicyParts {
        filter: Arc::new(builder.build().unwrap()),
        source_ids: vec!["a".into(), "b".into()],
        groups: vec![
            GroupPolicy::new("default", Sources::NONE.with(Source::new(0).unwrap())),
            GroupPolicy::new("strict", both),
        ],
        clients,
        block_response: BlockResponse::NullIp,
        blocked_ttl: 10,
        protection: true,
        services: Arc::new(goethite_resolver::ServiceFilter::empty()),
        access: goethite_resolver::Access::default(),
    })
    .unwrap()
}

trait IntoCidr {
    fn into_cidr(self) -> goethite_resolver::Cidr;
}

impl IntoCidr for IpAddr {
    fn into_cidr(self) -> goethite_resolver::Cidr {
        goethite_resolver::Cidr::host(self)
    }
}

/// `Resolver::resolve` for a cached name: the full pipeline in front of the
/// network, which completes without waiting, so it is polled directly.
fn pipeline(c: &mut Criterion) {
    let unused = UpstreamConfig::udp("127.0.0.1:9".parse().unwrap());
    let bare = Resolver::new(Vec::new())
        .with_cache(filled())
        .with_forwarder(Forwarder::new(ForwarderConfig::new(vec![unused.clone()])).unwrap());
    let policed = Resolver::new(Vec::new())
        .with_policy(Arc::new(PolicyState::new(policy())))
        .with_cache(filled())
        .with_forwarder(Forwarder::new(ForwarderConfig::new(vec![unused])).unwrap());
    let hit = query("host4242.example.");
    let client = IpAddr::from(Ipv4Addr::new(192, 168, 1, 41));
    let mut cx = Context::from_waker(Waker::noop());

    for (label, resolver) in [
        ("resolve/cached answer", &bare),
        (
            "resolve/cached answer, 100k rules, groups, 100 clients",
            &policed,
        ),
    ] {
        c.bench_function(label, |b| {
            b.iter(|| {
                let mut future = pin!(resolver.resolve(black_box(&hit), client));
                match future.as_mut().poll(&mut cx) {
                    Poll::Ready(resolution) => black_box(resolution),
                    Poll::Pending => panic!("a cached answer should not wait"),
                }
            });
        });
    }
}

criterion_group!(benches, cache, pipeline);
criterion_main!(benches);
