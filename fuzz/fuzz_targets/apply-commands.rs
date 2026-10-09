//! Fuzz target: applying entries of the cluster's log, untrusted JSON from
//! another member, to a store. The input is a list of commands (seeds of
//! a whole configuration, and changes), applied in order to a new store in
//! memory, as a follower applies them.
//!
//! Invariants checked on every input:
//! - nothing panics, whatever the commands hold;
//! - an applied change leaves a configuration that validates, at the
//!   version it reports, with the cluster's note of the entry kept;
//! - a refused change leaves the configuration as it was.

#![no_main]

use goethite_store::{Applied, Command, Store};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(commands) = serde_json::from_slice::<Vec<Command>>(data) else {
        return;
    };
    let Ok(store) = Store::open_in_memory() else {
        return;
    };
    for (index, command) in commands.into_iter().enumerate() {
        let note = index.to_string();
        let is_change = matches!(command, Command::Change(_));
        let before = (store.config(), store.version());
        match store.apply(Some(command), &note) {
            Ok(Applied::Done { version }) => {
                assert_eq!(store.version(), version);
                assert_eq!(store.applied().as_deref(), Some(note.as_str()));
                if is_change {
                    assert!(store.config().validate().is_ok(), "an applied change is valid");
                }
            }
            Ok(Applied::Refused { .. }) => {
                assert_eq!((store.config(), store.version()), before);
                assert_eq!(store.applied().as_deref(), Some(note.as_str()));
            }
            Ok(Applied::Nothing) => unreachable!("every entry here has a command"),
            // Another schema, or a kind this version does not know: the
            // node stops following, and its configuration stays.
            Err(_) => assert_eq!((store.config(), store.version()), before),
        }
    }
});
