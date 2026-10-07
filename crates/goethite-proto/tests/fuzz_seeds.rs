//! The committed fuzz seeds decode the way their names say, so they keep
//! steering the fuzzer towards the code paths they were written for.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use goethite_proto::{
    DecodeError, DnsCodec, HickoryCodec, Query, RecordClass, RecordType, ResponseCode,
};

fn seed(name: &str) -> Vec<u8> {
    seed_in("decode_query", name)
}

fn seed_in(target: &str, name: &str) -> Vec<u8> {
    let path = format!(
        "{}/../../fuzz/seeds/{target}/{name}.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|err| panic!("{path}: {err}"))
}

fn decode(name: &str) -> Query {
    HickoryCodec.decode_query(&seed(name)).unwrap()
}

fn rejection(name: &str) -> ResponseCode {
    let err = HickoryCodec.decode_query(&seed(name)).unwrap_err();
    err.response().unwrap().rcode
}

#[test]
fn queries() {
    let query = decode("goethite-test-a-edns");
    assert_eq!(query.question.name.to_string(), "goethite.test.");
    assert_eq!(query.question.qtype, RecordType::A);
    assert_eq!(query.edns.unwrap().udp_payload_size, 1232);

    let query = decode("example-com-aaaa");
    assert_eq!(query.question.qtype, RecordType::AAAA);
    assert!(query.edns.is_none());

    let query = decode("mixed-case-do-cookie");
    assert_eq!(query.question.name.to_string(), "GoEtHiTe.TeSt.");
    assert!(query.edns.unwrap().dnssec_ok);

    assert!(decode("root-ns").question.name.is_root());
    assert_eq!(
        decode("chaos-version-bind").question.qclass,
        RecordClass::CH
    );
}

#[test]
fn response_seeds() {
    let decode = |seed: &str| HickoryCodec.decode_response(&seed_in("decode_response", seed));
    let a = decode("a-answer-edns").unwrap();
    assert_eq!(a.answers[0].ip(), Some([192, 0, 2, 1].into()));
    assert!(a.edns.is_some());
    let chain = decode("cname-chain-compressed").unwrap();
    assert_eq!(
        chain.answers[0].cname_target().unwrap().to_string(),
        "cdn.example.com."
    );
    assert_eq!(chain.answers[1].name().to_string(), "cdn.example.com.");
    let nx = decode("nxdomain-soa").unwrap();
    assert_eq!(nx.rcode, ResponseCode::NX_DOMAIN);
    assert_eq!(nx.authority[0].soa_minimum(), Some(300));
    assert!(decode("truncated").unwrap().truncated);
    let mixed = decode("aaaa-mixed-case").unwrap();
    assert_eq!(mixed.answers[0].name().to_string(), "ExAmPlE.CoM.");
}

#[test]
fn name_seeds() {
    let dir = format!("{}/../../fuzz/seeds/parse_name", env!("CARGO_MANIFEST_DIR"));
    let parse = |seed: &str| {
        let text = std::fs::read_to_string(format!("{dir}/{seed}")).unwrap();
        text.parse::<goethite_proto::Name>()
    };
    assert_eq!(
        parse("goethite-test").unwrap().to_string(),
        "goethite.test."
    );
    assert!(parse("root").unwrap().is_root());
    assert_eq!(
        parse("mixed-case-relative").unwrap().to_string(),
        "Mixed-Case_Label.Example."
    );
    assert_eq!(parse("underscore").unwrap().label_count(), 3);
    assert!(parse("empty-label").is_err());
}

#[test]
fn rejected_queries() {
    assert_eq!(rejection("notify"), ResponseCode::NOT_IMP);
    assert_eq!(rejection("no-question"), ResponseCode::FORM_ERR);
    assert!(matches!(
        HickoryCodec.decode_query(&seed("edns-version-1")),
        Err(DecodeError::BadVersion { version: 1, .. })
    ));
}
