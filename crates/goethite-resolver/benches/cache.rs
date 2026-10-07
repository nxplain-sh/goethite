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

use std::hint::black_box;
use std::net::Ipv4Addr;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use criterion::{Criterion, criterion_group, criterion_main};
use goethite_proto::{
    Edns, Query, Question, Record, RecordClass, RecordType, Response, ResponseCode,
};
use goethite_resolver::{Cache, CacheConfig, Forwarder, ForwarderConfig, Resolver, UpstreamConfig};

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

/// `Resolver::resolve` for a cached name: the full pipeline in front of the
/// network, which completes without waiting, so it is polled directly.
fn pipeline(c: &mut Criterion) {
    let unused = UpstreamConfig::udp("127.0.0.1:9".parse().unwrap());
    let forwarder = Forwarder::new(ForwarderConfig::new(vec![unused])).unwrap();
    let resolver = Resolver::new(Vec::new())
        .with_cache(filled())
        .with_forwarder(forwarder);
    let hit = query("host4242.example.");
    let mut cx = Context::from_waker(Waker::noop());

    c.bench_function("resolve/cached answer", |b| {
        b.iter(|| {
            let mut future = pin!(resolver.resolve(black_box(&hit)));
            match future.as_mut().poll(&mut cx) {
                Poll::Ready(response) => black_box(response),
                Poll::Pending => panic!("a cached answer should not wait"),
            }
        });
    });
}

criterion_group!(benches, cache, pipeline);
criterion_main!(benches);
