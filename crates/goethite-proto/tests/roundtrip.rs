//! Property tests: encoding and decoding agree with each other.

mod strategies;

use std::net::Ipv4Addr;

use goethite_proto::{DnsCodec, HickoryCodec, Record, RecordData, Response, ResponseCode};
use hickory_proto::op::Message;
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1024))]

    #[test]
    fn query_roundtrips(query in strategies::query()) {
        let mut wire = Vec::new();
        HickoryCodec.encode_query(&query, &mut wire).unwrap();
        let decoded = HickoryCodec.decode_query(&wire).unwrap();

        prop_assert_eq!(&decoded, &query);
        // `Name` equality ignores case; the wire format must not.
        prop_assert_eq!(
            decoded.question.name.to_string(),
            query.question.name.to_string()
        );
    }

    #[test]
    fn host_names_display_and_parse_back(name in strategies::host_name()) {
        let shown = name.to_string();
        let parsed: goethite_proto::Name = shown.parse().unwrap();
        prop_assert_eq!(&parsed, &name);
        prop_assert_eq!(parsed.to_string(), shown);
    }

    #[test]
    fn wire_names_display_as_printable_ascii(name in strategies::name()) {
        prop_assert!(name.to_string().bytes().all(|b| b.is_ascii_graphic()));
    }

    #[test]
    fn responses_respect_the_size_limit(
        query in strategies::query(),
        answers in 0..200_u8,
        max_len in 512..=4096_usize,
    ) {
        let mut response = Response::for_query(&query, ResponseCode::NO_ERROR);
        response.answers = (0..answers)
            .map(|i| Record {
                name: query.question.name.clone(),
                ttl: 60,
                data: RecordData::A(Ipv4Addr::new(192, 0, 2, i)),
            })
            .collect();

        let mut wire = Vec::new();
        HickoryCodec.encode_response(&response, max_len, &mut wire).unwrap();
        prop_assert!(wire.len() <= max_len);

        let decoded = Message::from_vec(&wire).unwrap();
        prop_assert_eq!(decoded.metadata.id, query.id);
        prop_assert_eq!(decoded.queries.len(), 1);
        prop_assert_eq!(decoded.edns.is_some(), query.edns.is_some());
        if decoded.metadata.truncation {
            prop_assert!(decoded.answers.is_empty());
        } else {
            prop_assert_eq!(decoded.answers.len(), usize::from(answers));
        }
    }
}
