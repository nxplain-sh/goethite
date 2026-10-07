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
    let path = config_file("unknown_keys", "[server]\nlisen = \"127.0.0.1:0\"\n");
    let output = goethite(&["run", "--config", path.to_str().unwrap()]);
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("unknown field"), "{stderr}");
}

#[cfg(unix)]
mod serving {
    use std::io::{BufRead, BufReader};
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
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
        fn start(test: &str) -> Self {
            let path = config_file(test, "[server]\nlisten = \"127.0.0.1:0\"\n");
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
            let status = Command::new("kill")
                .args([&format!("-{name}"), &self.child.id().to_string()])
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

    fn serves_then_stops_on(signal: &str) {
        let mut server = Running::start(&format!("serves_then_stops_on_{signal}"));
        let line = server.wait_for_log("listening");
        let udp = field(&line, "udp");

        let answer = ask(udp, "goethite.test.");
        assert_eq!(answer.metadata.id, 0x5353);
        assert_eq!(answer.metadata.response_code, ResponseCode::NoError);
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(
            answer.answers[0].data,
            RData::A(A(Ipv4Addr::new(127, 0, 0, 53)))
        );
        assert_eq!(
            ask(udp, "example.com.").metadata.response_code,
            ResponseCode::Refused
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
    fn serves_then_stops_on_sigterm() {
        serves_then_stops_on("TERM");
    }

    #[test]
    fn serves_then_stops_on_sigint() {
        serves_then_stops_on("INT");
    }
}
