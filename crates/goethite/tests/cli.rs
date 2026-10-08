//! Tests of the `goethite` binary as a user runs it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test helpers; the no-panic rules cover non-test code"
)]

use std::path::PathBuf;
use std::process::{Command, Output};

const BIN: &str = env!("CARGO_BIN_EXE_goethite");

/// Writes `contents` to a config file unique to `test`.
fn config_file(test: &str, contents: &str) -> PathBuf {
    let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{test}.toml"));
    std::fs::write(&path, contents).unwrap();
    path
}

fn goethite(args: &[&str]) -> Output {
    Command::new(BIN)
        .args(args)
        .env("RUST_LOG", "info")
        .output()
        .unwrap()
}

#[test]
fn prints_its_version() {
    let output = goethite(&["--version"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert_eq!(stdout, format!("goethite {}\n", env!("CARGO_PKG_VERSION")));
}

#[test]
fn token_prints_a_token_and_its_hash() {
    let output = goethite(&["token"]);
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let token = stdout
        .split_whitespace()
        .find(|word| word.starts_with("gth_"))
        .expect("a token");
    let hash = stdout
        .lines()
        .find_map(|line| line.trim().strip_prefix("token_sha256 = "))
        .expect("a hash line")
        .trim_matches('"');
    assert!(
        hash.parse::<goethite_api::TokenHash>()
            .unwrap()
            .matches(token)
    );
    assert_ne!(
        goethite(&["token"]).stdout,
        stdout.as_bytes(),
        "a new token each time"
    );
}

#[test]
fn openapi_prints_the_committed_document() {
    let output = goethite(&["openapi"]);
    assert!(output.status.success());
    let committed = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../goethite-api/openapi.json"
    ))
    .unwrap();
    assert_eq!(String::from_utf8(output.stdout).unwrap(), committed);
}

#[test]
fn tui_rejects_a_bad_api_address() {
    let output = goethite(&["tui", "--api", "ftp://nowhere"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("not an http:// or https:// URL"));
}

#[test]
fn run_requires_a_config() {
    let output = goethite(&["run"]);
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("--config"));
}

#[test]
fn missing_config_file_is_an_error() {
    let output = goethite(&["run", "--config", "/nonexistent/goethite.toml"]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("cannot open config file"), "{stderr}");
}

#[test]
fn unknown_config_keys_are_an_error() {
    let path = config_file(
        "unknown_keys",
        "[server]\nlisen = \"127.0.0.1:0\"\n\n[[upstream]]\naddress = \"127.0.0.1\"\n",
    );
    let output = goethite(&["run", "--config", path.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown field"), "{stderr}");
}

#[test]
fn missing_upstreams_are_an_error() {
    let path = config_file("no_upstreams", "[server]\nlisten = \"127.0.0.1:0\"\n");
    let output = goethite(&["run", "--config", path.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("no upstream resolvers configured"),
        "{stderr}"
    );
    assert!(stderr.contains("[[upstream]]"), "{stderr}");
}

#[test]
fn check_config_accepts_the_example() {
    let example = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/goethite.example.toml"
    );
    let output = goethite(&["check-config", "--config", example]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("configuration is valid"), "{stderr}");
}

#[test]
fn check_config_rejects_problems() {
    let upstream = "[[upstream]]\naddress = \"127.0.0.1\"\n";
    for (test, extra, expected) in [
        ("check_no_upstreams", "", "no upstream resolvers configured"),
        (
            "check_bad_tls_name",
            "[[upstream]]\naddress = \"127.0.0.1\"\nprotocol = \"tls\"\ntls_name = \"not a name\"\n",
            "invalid TLS server name",
        ),
        (
            "check_bad_rule",
            "[filter]\nrules = [\"||ads.example^$important\"]\n",
            "not supported yet",
        ),
        (
            "check_missing_list",
            "[[filter.list]]\npath = \"/nonexistent/goethite/list.txt\"\n",
            "cannot open filter list",
        ),
    ] {
        let contents = if test == "check_no_upstreams" || test == "check_bad_tls_name" {
            extra.to_owned()
        } else {
            format!("{upstream}{extra}")
        };
        let path = config_file(test, &contents);
        let output = goethite(&["check-config", "--config", path.to_str().unwrap()]);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success(), "{test}: {stderr}");
        assert!(stderr.contains(expected), "{test}: {stderr}");
    }
}

#[cfg(unix)]
mod serving {
    use std::io::{BufRead, BufReader};
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::str::FromStr;
    use std::sync::mpsc;
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType, rdata::A};

    use super::{BIN, config_file};

    const WAIT: Duration = Duration::from_secs(10);

    /// A running server whose log lines arrive on `lines`.
    struct Running {
        child: Child,
        lines: mpsc::Receiver<String>,
        log: Vec<String>,
    }

    impl Running {
        fn start(test: &str, upstream: SocketAddr) -> Self {
            Self::start_with(test, upstream, "")
        }

        fn start_with(test: &str, upstream: SocketAddr, extra: &str) -> Self {
            Self::start_config(
                test,
                &format!(
                    "[server]\nlisten = \"127.0.0.1:0\"\n\n[[upstream]]\naddress = \"{upstream}\"\n{extra}"
                ),
            )
        }

        /// Starts goethite with `config`, plus a fresh store of its own
        /// unless the config names one.
        fn start_config(test: &str, config: &str) -> Self {
            // No two servers on the API's default port at once.
            let config = if config.contains("[api]") {
                config.to_owned()
            } else {
                format!("{config}\n[api]\nlisten = \"127.0.0.1:0\"\n")
            };
            let config = if config.contains("[store]") {
                config.clone()
            } else {
                let store = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!("{test}.redb"));
                let _ = std::fs::remove_file(&store);
                format!(
                    "{config}\n[store]\npath = {:?}\n",
                    store.display().to_string()
                )
            };
            let path = config_file(test, &config);
            let mut child = Command::new(BIN)
                .args(["run", "--config", path.to_str().unwrap()])
                .env("RUST_LOG", "info")
                .stderr(Stdio::piped())
                .spawn()
                .unwrap();
            let stderr = child.stderr.take().unwrap();
            let (tx, lines) = mpsc::channel();
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines() {
                    let Ok(line) = line else { break };
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });
            Self {
                child,
                lines,
                log: Vec::new(),
            }
        }

        /// Waits for a log line containing `needle` and returns it.
        fn wait_for_log(&mut self, needle: &str) -> String {
            loop {
                match self.lines.recv_timeout(WAIT) {
                    Ok(line) => {
                        self.log.push(line.clone());
                        if line.contains(needle) {
                            return line;
                        }
                    }
                    Err(err) => panic!("no log line with {needle:?} ({err}); log: {:#?}", self.log),
                }
            }
        }

        fn signal(&self, name: &str) {
            // The shell's built-in `kill`: minimal systems may lack /bin/kill.
            let status = Command::new("sh")
                .args(["-c", &format!("kill -{name} {}", self.child.id())])
                .status()
                .unwrap();
            assert!(status.success());
        }

        fn wait_for_exit(&mut self) -> std::process::ExitStatus {
            for _ in 0..500 {
                if let Some(status) = self.child.try_wait().unwrap() {
                    return status;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            panic!("server did not exit; log: {:#?}", self.log);
        }
    }

    impl Drop for Running {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Extracts `key=<addr>` from a log line.
    fn field(line: &str, key: &str) -> SocketAddr {
        let prefix = format!("{key}=");
        line.split_whitespace()
            .find_map(|part| part.strip_prefix(&prefix))
            .expect("field present")
            .parse()
            .unwrap()
    }

    /// The DNS server's "listening" line. The API logs "API listening" too,
    /// in no fixed order, so "listening" alone may match the wrong one.
    const DNS_LISTENING: &str = "listening udp=";

    fn ask(server: SocketAddr, name: &str) -> Message {
        let mut query = Message::new(0x5353, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        ask_raw(server, &query.to_vec().unwrap())
    }

    fn ask_raw(server: SocketAddr, wire: &[u8]) -> Message {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(WAIT)).unwrap();
        socket.send_to(wire, server).unwrap();
        let mut buf = [0; 512];
        let len = socket.recv(&mut buf).unwrap();
        Message::from_vec(&buf[..len]).unwrap()
    }

    /// A query for `goethite.test. A` whose OPT record carries an EDNS option
    /// that claims 5 bytes but has 2. hickory-proto alone would log a warning
    /// quoting the bytes and answer it; goethite rejects it first.
    fn query_with_malformed_edns_option() -> Vec<u8> {
        let mut wire = vec![0x01, 0x01, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1];
        wire.extend_from_slice(b"\x08goethite\x04test\x00\x00\x01\x00\x01");
        wire.extend_from_slice(&[0, 0, 41, 0x04, 0xd0, 0, 0, 0, 0, 0, 6]);
        wire.extend_from_slice(&[0, 10, 0, 5, 1, 2]);
        wire
    }

    /// A fake upstream that answers every query with `192.0.2.53`.
    fn upstream() -> SocketAddr {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        let addr = socket.local_addr().unwrap();
        std::thread::spawn(move || {
            let mut buf = [0; 4096];
            while let Ok((len, peer)) = socket.recv_from(&mut buf) {
                let query = Message::from_vec(&buf[..len]).unwrap();
                let mut reply =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                reply.add_queries(query.queries.clone());
                let name = query.queries[0].name().clone();
                let data = RData::A(A(Ipv4Addr::new(192, 0, 2, 53)));
                reply.add_answer(hickory_proto::rr::Record::from_rdata(name, 300, data));
                socket.send_to(&reply.to_vec().unwrap(), peer).unwrap();
            }
        });
        addr
    }

    fn serves_then_stops_on(signal: &str) {
        let mut server = Running::start(&format!("serves_then_stops_on_{signal}"), upstream());
        let line = server.wait_for_log(DNS_LISTENING);
        let udp = field(&line, "udp");

        let answer = ask(udp, "goethite.test.");
        assert_eq!(answer.metadata.id, 0x5353);
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(
            answer.answers[0].data,
            RData::A(A(Ipv4Addr::new(127, 0, 0, 53)))
        );
        let forwarded = ask(udp, "example.com.");
        assert_eq!(forwarded.metadata.response_code, ResponseCode::NoError);
        assert!(forwarded.metadata.recursion_available);
        assert_eq!(
            forwarded.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 53)))
        );
        let odd = ask_raw(udp, &query_with_malformed_edns_option());
        assert_eq!(odd.metadata.id, 0x0101);
        assert_eq!(odd.metadata.response_code, ResponseCode::FormErr);

        server.signal(signal);
        server.wait_for_log(&format!("received SIG{signal}"));
        server.wait_for_log("stopped");
        assert!(server.wait_for_exit().success());
        assert!(
            !server.log.iter().any(|line| line.contains("hickory_proto")),
            "hickory-proto logged at the default level: {:#?}",
            server.log
        );
    }

    #[test]
    fn blocks_listed_names_and_reloads_lists_on_sighup() {
        let list = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("blocklist.txt");
        std::fs::write(&list, "0.0.0.0 ads.example\n").unwrap();
        let extra = format!(
            "\n[filter]\nrules = [\"||tracker.example^\"]\n\n[[filter.list]]\npath = {:?}\n",
            list.display().to_string()
        );
        let mut server = Running::start_with("blocks_and_reloads", upstream(), &extra);
        let udp = field(&server.wait_for_log(DNS_LISTENING), "udp");
        let null = RData::A(A(Ipv4Addr::UNSPECIFIED));
        let forwarded = RData::A(A(Ipv4Addr::new(192, 0, 2, 53)));

        assert_eq!(ask(udp, "ads.example.").answers[0].data, null);
        assert_eq!(ask(udp, "x.tracker.example.").answers[0].data, null);
        assert_eq!(ask(udp, "popup.example.").answers[0].data, forwarded);

        std::fs::write(&list, "0.0.0.0 popup.example\n").unwrap();
        server.signal("HUP");
        server.wait_for_log("received SIGHUP");
        server.wait_for_log("filter ready");
        assert_eq!(ask(udp, "popup.example.").answers[0].data, null);
        assert_eq!(ask(udp, "ads.example.").answers[0].data, forwarded);
        assert_eq!(
            ask(udp, "x.tracker.example.").answers[0].data,
            null,
            "config rules stay"
        );

        server.signal("TERM");
        assert!(server.wait_for_exit().success());
    }

    /// The value of `key` in `/proc/<pid>/status`.
    #[cfg(target_os = "linux")]
    fn proc_status(pid: u32, key: &str) -> String {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).unwrap();
        status
            .lines()
            .find_map(|line| line.strip_prefix(&format!("{key}:")))
            .unwrap_or_else(|| panic!("no {key} in {status}"))
            .trim()
            .to_owned()
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn gives_up_capabilities_and_sets_no_new_privs() {
        let mut server = Running::start("privileges", upstream());
        let udp = field(&server.wait_for_log(DNS_LISTENING), "udp");
        let pid = server.child.id();
        assert_eq!(proc_status(pid, "NoNewPrivs"), "1");
        assert_eq!(proc_status(pid, "CapEff"), "0000000000000000");
        assert_eq!(proc_status(pid, "CapPrm"), "0000000000000000");
        assert_eq!(proc_status(pid, "CapAmb"), "0000000000000000");
        assert_eq!(ask(udp, "goethite.test.").answers.len(), 1);
    }

    /// Switching users needs root: this is skipped unless the tests run as
    /// root, which CI does separately with `GOETHITE_ROOT_TESTS=1` set.
    #[cfg(target_os = "linux")]
    #[test]
    fn switches_to_the_configured_user_when_root() {
        if proc_status(std::process::id(), "Uid")
            .split_whitespace()
            .next()
            != Some("0")
        {
            assert!(
                std::env::var_os("GOETHITE_ROOT_TESTS").is_none(),
                "GOETHITE_ROOT_TESTS is set, but the tests do not run as root"
            );
            return;
        }
        // The store must be writable by nobody.
        let state =
            std::env::temp_dir().join(format!("goethite-switch-user-{}", std::process::id()));
        std::fs::create_dir_all(&state).unwrap();
        let status = Command::new("chown")
            .args(["nobody", state.to_str().unwrap()])
            .status()
            .unwrap();
        assert!(status.success());
        let config = format!(
            "[server]\nlisten = \"127.0.0.1:0\"\nuser = \"nobody\"\n\n[[upstream]]\naddress = \"{}\"\n\n[store]\npath = {:?}\n",
            upstream(),
            state.join("goethite.redb").display().to_string()
        );
        let mut server = Running::start_config("switch_user", &config);
        let line = server.wait_for_log("dropped privileges");
        assert!(line.contains("user=nobody"), "{line}");
        let udp = field(&server.wait_for_log(DNS_LISTENING), "udp");
        let pid = server.child.id();
        let uid = proc_status(pid, "Uid");
        assert!(uid.split_whitespace().all(|id| id == "65534"), "{uid}");
        let gid = proc_status(pid, "Gid");
        assert!(gid.split_whitespace().all(|id| id != "0"), "{gid}");
        assert_eq!(proc_status(pid, "Groups"), "");
        assert_eq!(proc_status(pid, "CapEff"), "0000000000000000");
        assert_eq!(proc_status(pid, "CapPrm"), "0000000000000000");
        assert_eq!(ask(udp, "goethite.test.").answers.len(), 1);
    }

    #[test]
    fn import_needs_the_server_stopped() {
        let store = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("import.redb");
        let _ = std::fs::remove_file(&store);
        let config = format!(
            "[server]\nlisten = \"127.0.0.1:0\"\n\n[[upstream]]\naddress = \"{}\"\n\n\
             [filter]\nrules = [\"||ads.example^\"]\n\n[store]\npath = {:?}\n",
            upstream(),
            store.display().to_string()
        );
        let path = config_file("import", &config);
        let import = || {
            Command::new(BIN)
                .args(["import", "--config", path.to_str().unwrap()])
                .env("RUST_LOG", "info")
                .output()
                .unwrap()
        };
        let first = import();
        let log = String::from_utf8_lossy(&first.stderr);
        assert!(first.status.success(), "{log}");
        assert!(log.contains("rules_added=1"), "{log}");

        let mut server = Running::start_config("import", &config);
        server.wait_for_log(DNS_LISTENING);
        let refused = import();
        let log = String::from_utf8_lossy(&refused.stderr);
        assert!(!refused.status.success());
        assert!(log.contains("in use by another goethite process"), "{log}");
        server.signal("TERM");
        assert!(server.wait_for_exit().success());

        let again = import();
        let log = String::from_utf8_lossy(&again.stderr);
        assert!(again.status.success(), "{log}");
        assert!(log.contains("rules_added=0"), "{log}");
    }

    #[test]
    fn serves_then_stops_on_sigterm() {
        serves_then_stops_on("TERM");
    }

    #[test]
    fn serves_then_stops_on_sigint() {
        serves_then_stops_on("INT");
    }
}
