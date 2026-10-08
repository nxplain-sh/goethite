//! Tests of the `goethite` binary as a user runs it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
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
    assert!(stderr.contains("[recursion]"), "{stderr}");
}

/// Recursion instead of upstreams: one or the other.
#[test]
fn recursion_or_upstreams() {
    let recursive = config_file(
        "recursive",
        "[server]\nlisten = \"127.0.0.1:0\"\n\n[recursion]\nenabled = true\nipv6 = false\n",
    );
    let output = goethite(&["check-config", "--config", recursive.to_str().unwrap()]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let both = config_file(
        "recursive_and_upstreams",
        "[[upstream]]\naddress = \"9.9.9.9\"\n\n[recursion]\nenabled = true\n",
    );
    let output = goethite(&["check-config", "--config", both.to_str().unwrap()]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("choose one"), "{stderr}");
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
        (
            "check_missing_services_file",
            "[filter]\nservices_file = \"/nonexistent/goethite/services.json\"\n",
            "/nonexistent/goethite/services.json does not exist",
        ),
        (
            "check_bad_services_file",
            &format!(
                "[filter]\nservices_file = {:?}\n",
                config_file("not_a_catalog", "<html>").display().to_string()
            ),
            "unexpected data in the services catalog",
        ),
        (
            "check_missing_dns_certificate",
            "[server.tls]\ncert = \"/nonexistent/dns.crt\"\nkey = \"/nonexistent/dns.key\"\n\
             dot = \"127.0.0.1:853\"\n",
            "cannot read the DNS certificate",
        ),
        (
            "check_bad_dns_certificate",
            &format!(
                "[server.tls]\ncert = {path:?}\nkey = {path:?}\ndot = \"127.0.0.1:853\"\n",
                path = config_file("not_a_certificate", "not PEM")
                    .display()
                    .to_string()
            ),
            "holds no certificate",
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
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::{Ipv4Addr, SocketAddr, TcpStream, UdpSocket};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::str::FromStr;
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RData, RecordType, rdata::A};
    use rustls::pki_types::{CertificateDer, ServerName};

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
        /// unless the config names one, and without the default list and
        /// the services catalog, which it would try to download.
        fn start_config(test: &str, config: &str) -> Self {
            // Nor the services catalog, unless the test brings its own.
            let offline = if config.contains("services") {
                "default_lists = false\n"
            } else {
                "default_lists = false\nservices = false\n"
            };
            let config = if config.contains("[filter]\n") {
                config.replacen("[filter]\n", &format!("[filter]\n{offline}"), 1)
            } else {
                format!("{config}\n[filter]\n{offline}")
            };
            Self::start_exact(test, &config)
        }

        /// Starts goethite with `config` as it is, plus a store and the API
        /// on an ephemeral port unless the config names them.
        fn start_exact(test: &str, config: &str) -> Self {
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

        /// The first log line containing `needle`, logged already or to
        /// come: for lines whose order is not fixed.
        fn find_log(&mut self, needle: &str) -> String {
            if let Some(line) = self.log.iter().find(|line| line.contains(needle)) {
                return line.clone();
            }
            self.wait_for_log(needle)
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

    /// Nothing reads goethite's log any more (its supervisor died, a pipe
    /// closed): it goes on answering, and still stops on SIGTERM.
    #[test]
    fn keeps_working_when_nothing_reads_its_log() {
        let mut server = Running::start("no_log_reader", upstream());
        let udp = field(&server.wait_for_log(DNS_LISTENING), "udp");
        // The reading thread stops at the next line, closing the pipe; the
        // reload logs more lines after that, which cannot be written.
        server.lines = mpsc::channel().1;
        server.signal("HUP");
        std::thread::sleep(Duration::from_millis(500));
        let answer = ask(udp, "goethite.test.");
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        server.signal("TERM");
        assert!(server.wait_for_exit().success());
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

    #[test]
    fn a_broken_store_fails_open_or_closed() {
        let store = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("broken-store.redb");
        let garbage = b"this is not a redb database, and it must survive".repeat(100);
        std::fs::write(&store, &garbage).unwrap();
        let config = format!(
            "[server]\nlisten = \"127.0.0.1:0\"\n\n[[upstream]]\naddress = \"{}\"\n\n\
             [filter]\nrules = [\"||ads.example^\"]\n\n[store]\npath = {:?}\n",
            upstream(),
            store.display().to_string()
        );

        // Open (the default): it answers, filtering by the config file.
        let mut server = Running::start_config("broken_store_open", &config);
        server.wait_for_log("temporary store in memory");
        let udp = field(&server.wait_for_log(DNS_LISTENING), "udp");
        assert_eq!(
            ask(udp, "ads.example.").answers[0].data,
            RData::A(A(Ipv4Addr::UNSPECIFIED))
        );
        assert_eq!(
            ask(udp, "popup.example.").answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 53)))
        );
        server.signal("TERM");
        assert!(server.wait_for_exit().success());
        assert_eq!(
            std::fs::read(&store).unwrap(),
            garbage,
            "the file is left alone"
        );

        // Closed: it refuses to start.
        let closed = config.replace("[filter]\n", "[filter]\non_failure = \"closed\"\n");
        let path = config_file(
            "broken_store_closed",
            &format!("{closed}\n[api]\nlisten = \"127.0.0.1:0\"\n"),
        );
        let output = super::goethite(&["run", "--config", path.to_str().unwrap()]);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("cannot open the store"), "{stderr}");
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

    /// A certificate for `dns.example` and `*.dns.example`, written to
    /// `cert` and `key`; its DER.
    fn write_certificate(cert: &std::path::Path, key: &std::path::Path) -> Vec<u8> {
        let rcgen::CertifiedKey {
            cert: made,
            signing_key,
        } = rcgen::generate_simple_self_signed(vec!["dns.example".into(), "*.dns.example".into()])
            .unwrap();
        std::fs::write(cert, made.pem()).unwrap();
        std::fs::write(key, signing_key.serialize_pem()).unwrap();
        made.der().to_vec()
    }

    /// A TLS client that trusts any certificate: the test checks which one
    /// it got itself.
    #[derive(Debug)]
    struct TrustAll(Arc<rustls::crypto::CryptoProvider>);

    impl rustls::client::danger::ServerCertVerifier for TrustAll {
        fn verify_server_cert(
            &self,
            _: &CertificateDer<'_>,
            _: &[CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls12_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            rustls::crypto::verify_tls13_signature(
                message,
                cert,
                dss,
                &self.0.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            self.0.signature_verification_algorithms.supported_schemes()
        }
    }

    type Tls = rustls::StreamOwned<rustls::ClientConnection, TcpStream>;

    /// A TLS connection to `addr` for `server_name`, handshake done.
    fn tls(addr: SocketAddr, server_name: &str, alpn: &[u8]) -> Tls {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(TrustAll(provider)))
            .with_no_client_auth();
        config.alpn_protocols = vec![alpn.to_vec()];
        let name = ServerName::try_from(server_name.to_owned()).unwrap();
        let connection = rustls::ClientConnection::new(Arc::new(config), name).unwrap();
        let socket = TcpStream::connect(addr).unwrap();
        socket.set_read_timeout(Some(WAIT)).unwrap();
        let mut stream = rustls::StreamOwned::new(connection, socket);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock).unwrap();
        }
        stream
    }

    fn query(name: &str) -> Vec<u8> {
        let mut query = Message::new(0, MessageType::Query, OpCode::Query);
        query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        query.to_vec().unwrap()
    }

    fn dot_ask(stream: &mut Tls, name: &str) -> Message {
        let wire = query(name);
        let mut frame = u16::try_from(wire.len()).unwrap().to_be_bytes().to_vec();
        frame.extend_from_slice(&wire);
        stream.write_all(&frame).unwrap();
        stream.flush().unwrap();
        let mut len = [0; 2];
        stream.read_exact(&mut len).unwrap();
        let mut buf = vec![0; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut buf).unwrap();
        Message::from_vec(&buf).unwrap()
    }

    /// An HTTP/1.1 request for `host` on `stream`; the status, the headers
    /// (lowercase names) and the body.
    fn request(
        stream: &mut impl ReadWrite,
        host: &str,
        head: &str,
        body: &[u8],
    ) -> (u16, Vec<(String, String)>, Vec<u8>) {
        let mut sent = format!(
            "{head}\r\nHost: {host}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        )
        .into_bytes();
        sent.extend_from_slice(body);
        stream.write_all(&sent).unwrap();
        stream.flush().unwrap();
        let mut received = Vec::new();
        let mut chunk = [0; 4096];
        let (head_len, length) = loop {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0, "the connection ended early");
            received.extend_from_slice(&chunk[..read]);
            if let Some(end) = received.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&received[..end]).to_lowercase();
                let length = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .map_or(0, |len| len.trim().parse::<usize>().unwrap());
                break (end + 4, length);
            }
        };
        while received.len() < head_len + length {
            let read = stream.read(&mut chunk).unwrap();
            assert!(read > 0, "the connection ended early");
            received.extend_from_slice(&chunk[..read]);
        }
        let head = String::from_utf8_lossy(&received[..head_len]).into_owned();
        let mut lines = head.lines();
        let status = lines
            .next()
            .unwrap()
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse()
            .unwrap();
        let headers = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.to_lowercase(), value.trim().to_owned()))
            .collect();
        (
            status,
            headers,
            received[head_len..head_len + length].to_vec(),
        )
    }

    /// Asks `name` over DNS over QUIC, as `server_name`, on a stream of its
    /// own, trusting any certificate.
    fn doq_ask(addr: SocketAddr, server_name: &str, name: &str) -> Message {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let provider = Arc::new(rustls::crypto::ring::default_provider());
            let mut config = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(TrustAll(provider)))
                .with_no_client_auth();
            config.alpn_protocols = vec![b"doq".to_vec()];
            let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(config).unwrap();
            let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
            let connection = endpoint.connect(addr, server_name).unwrap().await.unwrap();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            let wire = query(name);
            let mut frame = u16::try_from(wire.len()).unwrap().to_be_bytes().to_vec();
            frame.extend_from_slice(&wire);
            send.write_all(&frame).await.unwrap();
            send.finish().unwrap();
            let stream = recv.read_to_end(65_537).await.unwrap();
            connection.close(0_u32.into(), b"");
            endpoint.wait_idle().await;
            Message::from_vec(&stream[2..]).unwrap()
        })
    }

    trait ReadWrite: Read + Write {}
    impl<T: Read + Write> ReadWrite for T {}

    /// A JSON request to the API.
    fn api(addr: SocketAddr, head: &str, body: &str) -> (u16, serde_json::Value) {
        let mut stream = TcpStream::connect(addr).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let (status, _, body) = request(
            &mut stream,
            "localhost",
            &format!("{head}\r\nContent-Type: application/json"),
            body.as_bytes(),
        );
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    /// An Oblivious DoH target: keys at the well-known path, encrypted
    /// queries and answers at `/dns-query`, logged as `odoh`.
    #[test]
    fn serves_oblivious_doh() {
        use goethite_server::odoh::client::{parse_configs, seal_query};

        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let (cert, key) = (dir.join("odoh.crt"), dir.join("odoh.key"));
        write_certificate(&cert, &key);
        let config = format!(
            "[server]\nlisten = \"127.0.0.1:0\"\n\n[server.tls]\ncert = {:?}\nkey = {:?}\n\
             doh = \"127.0.0.1:0\"\nodoh = true\n\n[[upstream]]\naddress = \"{}\"\n",
            cert.display().to_string(),
            key.display().to_string(),
            upstream()
        );
        let mut server = Running::start_config("oblivious_doh", &config);
        let doh = field(&server.find_log("DNS over HTTPS listening"), "address");
        let api_addr = field(&server.find_log("API listening"), "address");
        server.find_log("Oblivious DoH target");

        let mut stream = tls(doh, "dns.example", b"http/1.1");
        let (status, _, configs) = request(
            &mut stream,
            "dns.example",
            "GET /.well-known/odohconfigs HTTP/1.1",
            b"",
        );
        assert_eq!(status, 200);
        let target = parse_configs(&configs).unwrap();
        let (wire, pending) = seal_query(&target, &query("example.com."), 32).unwrap();
        let mut stream = tls(doh, "dns.example", b"http/1.1");
        let (status, headers, body) = request(
            &mut stream,
            "dns.example",
            "POST /dns-query HTTP/1.1\r\nContent-Type: application/oblivious-dns-message",
            &wire,
        );
        assert_eq!(status, 200);
        assert!(headers.contains(&(
            "content-type".into(),
            "application/oblivious-dns-message".into()
        )));
        let answer = Message::from_vec(&pending.open(&body).unwrap()).unwrap();
        assert_eq!(
            answer.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 53)))
        );

        let (_, status) = api(api_addr, "GET /api/v1/status HTTP/1.1", "");
        assert_eq!(status["encrypted"]["odoh"], true);
        let mut logged = serde_json::Value::Null;
        for _ in 0..100 {
            let (_, page) = api(api_addr, "GET /api/v1/querylog HTTP/1.1", "");
            if let Some(entry) = page["entries"].as_array().and_then(|e| e.first()) {
                logged = entry.clone();
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(logged["protocol"], "odoh", "{logged}");
        assert_eq!(logged["name"], "example.com.");
        server.signal("TERM");
        assert!(server.wait_for_exit().success());
    }

    #[test]
    fn serves_dns_over_tls_and_https_with_client_ids() {
        let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
        let (cert, key) = (dir.join("dns-tls.crt"), dir.join("dns-tls.key"));
        let first = write_certificate(&cert, &key);
        let config = format!(
            "[server]\nlisten = \"127.0.0.1:0\"\n\n[server.tls]\ncert = {:?}\nkey = {:?}\n\
             server_name = \"dns.example\"\ndot = \"127.0.0.1:0\"\ndoh = \"127.0.0.1:0\"\n\
             doq = \"127.0.0.1:0\"\n\n\
             [[upstream]]\naddress = \"{}\"\n",
            cert.display().to_string(),
            key.display().to_string(),
            upstream()
        );
        let mut server = Running::start_config("dns_over_tls_and_https", &config);
        let dot = field(&server.find_log("DNS over TLS listening"), "address");
        let doh = field(&server.find_log("DNS over HTTPS listening"), "address");
        let doq = field(&server.find_log("DNS over QUIC listening"), "address");
        let api_addr = field(&server.find_log("API listening"), "address");

        let (status, kid) = api(
            api_addr,
            "POST /api/v1/clients HTTP/1.1",
            r#"{"name": "Kid", "addresses": [], "ids": ["kid"]}"#,
        );
        assert_eq!(status, 201, "{kid}");
        let kid = kid["id"].as_str().unwrap().to_owned();

        // DNS over TLS, named by the server name.
        let mut stream = tls(dot, "kid.dns.example", b"dot");
        assert_eq!(stream.conn.alpn_protocol(), Some(&b"dot"[..]));
        let peer_cert = |stream: &Tls| stream.conn.peer_certificates().unwrap()[0].to_vec();
        assert_eq!(peer_cert(&stream), first);
        let answer = dot_ask(&mut stream, "goethite.test.");
        assert_eq!(answer.answers.len(), 1);
        let forwarded = dot_ask(&mut stream, "example.com.");
        assert_eq!(
            forwarded.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 53)))
        );

        // DNS over HTTPS, named by the path.
        let mut stream = tls(doh, "dns.example", b"http/1.1");
        let (status, headers, body) = request(
            &mut stream,
            "dns.example",
            "POST /dns-query/kid HTTP/1.1\r\nContent-Type: application/dns-message",
            &query("goethite.test."),
        );
        assert_eq!(status, 200);
        assert!(headers.contains(&("cache-control".into(), "max-age=60".into())));
        assert_eq!(Message::from_vec(&body).unwrap().answers.len(), 1);
        let mut stream = tls(doh, "dns.example", b"http/1.1");
        let (status, _, _) = request(&mut stream, "dns.example", "GET /nothing HTTP/1.1", b"");
        assert_eq!(status, 404);

        // DNS over QUIC, named by the server name.
        let answer = doq_ask(doq, "kid.dns.example", "goethite.test.");
        assert_eq!(answer.answers.len(), 1);

        // All reach the query log, as the client with the ID.
        let mut seen = Vec::new();
        for _ in 0..100 {
            let (_, page) = api(api_addr, "GET /api/v1/querylog HTTP/1.1", "");
            seen = page["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|entry| {
                    (
                        entry["protocol"].as_str().unwrap().to_owned(),
                        entry["client_id"].as_str().map(str::to_owned),
                    )
                })
                .collect();
            if seen.len() >= 4 {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let by_kid = |protocol: &str| {
            seen.iter()
                .filter(|(p, id)| p == protocol && id.as_deref() == Some(kid.as_str()))
                .count()
        };
        assert_eq!(
            (by_kid("dot"), by_kid("doh"), by_kid("doq")),
            (2, 1, 1),
            "{seen:?}"
        );

        // A renewed certificate is served after SIGHUP, to new connections.
        let renewed = write_certificate(&cert, &key);
        server.signal("HUP");
        server.wait_for_log("serving the renewed DNS certificate");
        assert_eq!(peer_cert(&tls(dot, "dns.example", b"dot")), renewed);

        // A broken one is not.
        std::fs::write(&key, "not a key").unwrap();
        server.signal("HUP");
        server.wait_for_log("still serving the DNS certificate in use");
        let mut stream = tls(dot, "dns.example", b"dot");
        assert_eq!(peer_cert(&stream), renewed);
        assert_eq!(dot_ask(&mut stream, "goethite.test.").answers.len(), 1);

        server.signal("TERM");
        assert!(server.wait_for_exit().success());
    }

    /// A new node with no lists in its config file filters with the
    /// default list, in the default group; once only.
    #[test]
    fn a_new_node_starts_with_the_default_list() {
        let store = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("default_list.redb");
        let _ = std::fs::remove_file(&store);
        let config = format!(
            "[server]\nlisten = \"127.0.0.1:0\"\n\n[[upstream]]\naddress = \"{}\"\n\n\
             [store]\npath = {:?}\n",
            upstream(),
            store.display().to_string()
        );
        for start in 0..2 {
            let mut server = Running::start_exact("default_list", &config);
            if start == 0 {
                server.find_log("filtering with goethite's default list");
            }
            let api_addr = field(&server.find_log("API listening"), "address");
            let (_, lists) = api(api_addr, "GET /api/v1/lists HTTP/1.1", "");
            let lists = lists.as_array().unwrap();
            assert_eq!(lists.len(), 1, "start {start}: {lists:?}");
            assert_eq!(lists[0]["spec"]["name"], "HaGeZi Multi Normal");
            assert_eq!(
                lists[0]["spec"]["url"],
                "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/multi.txt"
            );
            assert_eq!(lists[0]["spec"]["managed_by"], "api");
            let (_, group) = api(api_addr, "GET /api/v1/groups/default HTTP/1.1", "");
            assert_eq!(group["spec"]["lists"][0]["list"], lists[0]["id"]);
            server.signal("TERM");
            assert!(server.wait_for_exit().success());
        }
        let _ = std::fs::remove_file(&store);
    }

    /// A group blocks a service from the catalog: every name the service
    /// uses, logged as the service's.
    #[test]
    fn groups_block_services() {
        let catalog = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("services.json");
        std::fs::write(
            &catalog,
            r#"{"groups": [{"id": "social_network"}], "blocked_services": [
                {"id": "tiktok", "name": "TikTok", "group": "social_network", "icon_svg": "<svg/>",
                 "rules": ["||tiktok.com^", "||tiktokv.com^"]},
                {"id": "youtube", "name": "YouTube", "group": "video",
                 "rules": ["||youtube.com^"]}
            ]}"#,
        )
        .unwrap();
        let mut server = Running::start_with(
            "groups_block_services",
            upstream(),
            &format!(
                "\n[filter]\nservices_file = {:?}\n",
                catalog.display().to_string()
            ),
        );
        let udp = field(&server.find_log(DNS_LISTENING), "udp");
        let api_addr = field(&server.find_log("API listening"), "address");
        server.find_log("services catalog ready");
        let (status, services) = api(api_addr, "GET /api/v1/services HTTP/1.1", "");
        assert_eq!(status, 200, "{services}");
        assert_eq!(services["source"], catalog.display().to_string());
        assert_eq!(services["license"], "GPL-3.0");
        let names: Vec<&str> = services["services"]
            .as_array()
            .unwrap()
            .iter()
            .map(|service| service["name"].as_str().unwrap())
            .collect();
        assert_eq!(names, ["TikTok", "YouTube"]);

        let (status, body) = api(
            api_addr,
            "PUT /api/v1/groups/default HTTP/1.1",
            r#"{"name": "Default", "blocked_services": [{"service": "tiktok"}]}"#,
        );
        assert_eq!(status, 200, "{body}");
        let blocked = ask(udp, "api16-normal.tiktokv.com.");
        assert_eq!(
            blocked.answers[0].data,
            RData::A(A(Ipv4Addr::UNSPECIFIED)),
            "blocked"
        );
        let allowed = ask(udp, "www.youtube.com.");
        assert_eq!(
            allowed.answers[0].data,
            RData::A(A(Ipv4Addr::new(192, 0, 2, 53)))
        );

        let mut entry = serde_json::Value::Null;
        for _ in 0..100 {
            let (_, page) = api(
                api_addr,
                "GET /api/v1/querylog?outcome=blocked HTTP/1.1",
                "",
            );
            if let Some(found) = page["entries"].as_array().and_then(|e| e.first()) {
                entry = found.clone();
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        assert_eq!(entry["list"], "service:tiktok", "{entry}");
        assert_eq!(entry["rule"], "||tiktokv.com^");
        server.signal("TERM");
        assert!(server.wait_for_exit().success());
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
