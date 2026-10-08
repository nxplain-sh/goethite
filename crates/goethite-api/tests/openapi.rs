//! The committed `openapi.json` must match the code. The site's API
//! reference, the web UI's typed client and the breaking-change check in CI
//! all read the committed file.
//!
//! After changing the API, regenerate it:
//!
//! ```sh
//! GOETHITE_UPDATE_OPENAPI=1 cargo test -p goethite-api --test openapi
//! ```

#![allow(clippy::unwrap_used, clippy::panic, reason = "test")]

#[test]
fn the_committed_openapi_document_is_up_to_date() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.json");
    let generated = goethite_api::openapi_json();
    if std::env::var_os("GOETHITE_UPDATE_OPENAPI").is_some() {
        std::fs::write(path, &generated).unwrap();
        return;
    }
    let committed = std::fs::read_to_string(path).unwrap_or_default();
    assert!(
        committed == generated,
        "crates/goethite-api/openapi.json is out of date; regenerate it with \
         GOETHITE_UPDATE_OPENAPI=1 cargo test -p goethite-api --test openapi"
    );
}

#[test]
fn every_operation_is_documented() {
    let spec: serde_json::Value = serde_json::from_str(&goethite_api::openapi_json()).unwrap();
    let paths = spec["paths"].as_object().unwrap();
    assert!(paths.len() >= 15, "{} paths", paths.len());
    for (path, operations) in paths {
        for (method, operation) in operations.as_object().unwrap() {
            assert!(
                operation["responses"]
                    .as_object()
                    .is_some_and(|r| !r.is_empty()),
                "{method} {path} has no responses"
            );
            if path != "/api/v1/health" {
                assert!(
                    operation["security"].is_array(),
                    "{method} {path} does not say it needs the token"
                );
            }
        }
    }
    assert!(spec["components"]["securitySchemes"]["token"].is_object());
}

/// Every `$ref` points at a schema the document defines: utoipa emits a
/// reference for a type it was not told to include, which breaks clients.
#[test]
fn every_reference_resolves() {
    fn walk(value: &serde_json::Value, refs: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, value) in map {
                    if key == "$ref" {
                        refs.push(value.as_str().unwrap().to_owned());
                    } else {
                        walk(value, refs);
                    }
                }
            }
            serde_json::Value::Array(items) => items.iter().for_each(|item| walk(item, refs)),
            _ => {}
        }
    }
    let spec: serde_json::Value = serde_json::from_str(&goethite_api::openapi_json()).unwrap();
    let mut refs = Vec::new();
    walk(&spec, &mut refs);
    assert!(refs.len() > 10, "{} references", refs.len());
    for reference in refs {
        let name = reference
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("unexpected reference {reference}"));
        assert!(
            spec["components"]["schemas"].get(name).is_some(),
            "{reference} is not defined"
        );
    }
}
