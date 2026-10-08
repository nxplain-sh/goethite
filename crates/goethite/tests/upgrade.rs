//! Upgrading in place: on `SIGUSR2` goethite starts its binary again, hands
//! the new process its sockets and its store, and exits once the new one
//! answers, while queries go on being answered throughout.

#![cfg(target_os = "linux")]
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code; the no-panic rules cover non-test code"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_goethite");
const WAIT: Duration = Duration::from_secs(30);

struct Running {
    child: Child,
    lines: mpsc::Receiver<String>,
    log: Vec<String>,
}

impl Running {
    fn start(config: &Path) -> Self {
        let mut child = Command::new(BIN)
            .args(["run", "--config", config.to_str().unwrap()])
            .env("RUST_LOG", "info")
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let stderr = child.stderr.take().unwrap();
        let (tx, lines) = mpsc::channel();
        // The new process inherits this pipe, so its lines arrive here too.
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

    fn wait_for_log(&mut self, needle: &str) -> String {
        let [line] = self.wait_for_logs([needle]);
        line
    }

    /// A line with each of `needles`, in whatever order they come: tasks
    /// that start together log in any order.
    fn wait_for_logs<const N: usize>(&mut self, needles: [&str; N]) -> [String; N] {
        let mut found: [Option<String>; N] = std::array::from_fn(|_| None);
        while found.iter().any(Option::is_none) {
            let line = self.lines.recv_timeout(WAIT).unwrap_or_else(|_| {
                panic!("no log line with each of {needles:?}; log: {:#?}", self.log)
            });
            self.log.push(line.clone());
            for (needle, slot) in needles.iter().zip(&mut found) {
                if slot.is_none() && line.contains(needle) {
                    *slot = Some(line.clone());
                }
            }
        }
        found.map(Option::unwrap)
    }

    /// The DNS and API addresses, once both listen.
    fn addresses(&mut self) -> (SocketAddr, SocketAddr) {
        let [dns, api] = self.wait_for_logs(["listening udp=", "API listening"]);
        (
            field(&dns, "udp").parse().unwrap(),
            field(&api, "address").parse().unwrap(),
        )
    }
}

/// A failed test must not leave goethite running: it would also hold the
/// test's output open, and `cargo test` would wait for it.
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Kills the process the upgrade started, if the test fails before it is
/// stopped.
struct Stray(u32);

impl Drop for Stray {
    fn drop(&mut self) {
        if process_exists(self.0) {
            signal("KILL", self.0);
        }
    }
}

/// Sends signal `name` to process `pid`.
fn signal(name: &str, pid: u32) {
    let status = Command::new("sh")
        .args(["-c", &format!("kill -{name} {pid}")])
        .status()
        .unwrap();
    assert!(status.success());
}

fn field(line: &str, key: &str) -> String {
    let prefix = format!("{key}=");
    line.split_whitespace()
        .find_map(|part| part.strip_prefix(&prefix))
        .unwrap()
        .trim_matches('"')
        .to_owned()
}

fn http(api: SocketAddr, method: &str, path: &str, body: Option<&str>) -> (u16, Value) {
    let mut stream = TcpStream::connect(api).unwrap();
    stream.set_read_timeout(Some(WAIT)).unwrap();
    let body = body.unwrap_or("");
    write!(
        stream,
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    )
    .unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    let status = answer
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .unwrap();
    let json = answer
        .split_once("\r\n\r\n")
        .map_or(Value::Null, |(_, body)| {
            serde_json::from_str(body).unwrap_or(Value::Null)
        });
    (status, json)
}

/// Queries `goethite.test.` (answered by goethite itself) without pause,
/// counting answers and losses, until stopped.
struct Load {
    stop: Arc<AtomicBool>,
    answered: Arc<AtomicU64>,
    lost: Arc<AtomicU64>,
    thread: std::thread::JoinHandle<()>,
}

impl Load {
    fn start(server: SocketAddr) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let answered = Arc::new(AtomicU64::new(0));
        let lost = Arc::new(AtomicU64::new(0));
        let (s, a, l) = (Arc::clone(&stop), Arc::clone(&answered), Arc::clone(&lost));
        let thread = std::thread::spawn(move || {
            let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let mut id = 0_u16;
            while !s.load(Ordering::Relaxed) {
                id = id.wrapping_add(1);
                let mut query = Message::new(id, MessageType::Query, OpCode::Query);
                query.add_query(Query::query(
                    Name::from_str("goethite.test.").unwrap(),
                    RecordType::A,
                ));
                socket.send_to(&query.to_vec().unwrap(), server).unwrap();
                let mut buf = [0; 512];
                // Skip late answers to earlier queries.
                loop {
                    let Ok(len) = socket.recv(&mut buf) else {
                        l.fetch_add(1, Ordering::Relaxed);
                        break;
                    };
                    if Message::from_vec(&buf[..len]).unwrap().metadata.id == id {
                        a.fetch_add(1, Ordering::Relaxed);
                        break;
                    }
                }
            }
        });
        Self {
            stop,
            answered,
            lost,
            thread,
        }
    }

    fn finish(self) -> (u64, u64) {
        self.stop.store(true, Ordering::Relaxed);
        self.thread.join().unwrap();
        (
            self.answered.load(Ordering::Relaxed),
            self.lost.load(Ordering::Relaxed),
        )
    }
}

fn setup(name: &str) -> (PathBuf, PathBuf) {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("goethite.toml");
    std::fs::write(
        &config,
        "[server]\nlisten = \"127.0.0.1:0\"\n\n[[upstream]]\naddress = \"192.0.2.1\"\n\n\
         [api]\nlisten = \"127.0.0.1:0\"\n",
    )
    .unwrap();
    (dir, config)
}

fn process_exists(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

#[test]
fn an_upgrade_loses_no_query() {
    let (_dir, config) = setup("upgrade");
    let mut old = Running::start(&config);
    let (udp, api) = old.addresses();
    let (status, rule) = http(
        api,
        "POST",
        "/api/v1/rules",
        Some(r#"{"rule":"||ads.example^"}"#),
    );
    assert_eq!(status, 201, "{rule}");

    let load = Load::start(udp);
    std::thread::sleep(Duration::from_millis(300));
    signal("USR2", old.child.id());
    let started = old.wait_for_log("started the new goethite");
    let new_pid: u32 = field(&started, "pid").parse().unwrap();
    let _stray = Stray(new_pid);
    old.wait_for_log("answering in place of the previous goethite");
    let exited = Instant::now();
    let status = loop {
        if let Some(status) = old.child.try_wait().unwrap() {
            break status;
        }
        assert!(exited.elapsed() < WAIT, "the old goethite did not exit");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "the old goethite exited with {status}");
    std::thread::sleep(Duration::from_millis(500));
    let (answered, lost) = load.finish();
    assert!(answered > 50, "{answered} answered");
    assert_eq!(lost, 0, "{lost} queries lost of {}", answered + lost);

    // The new process answers on the same sockets, with the same store.
    assert!(process_exists(new_pid));
    let (status, rules) = http(api, "GET", "/api/v1/rules", None);
    assert_eq!(status, 200);
    assert_eq!(rules[0]["id"], rule["id"]);
    signal("TERM", new_pid);
    let stopping = Instant::now();
    while process_exists(new_pid) {
        assert!(stopping.elapsed() < WAIT, "the new goethite did not stop");
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// DNS over TLS and HTTPS listeners are handed over like the others: the new
/// process listens on the very ports the old one had (with port 0 in the
/// config, binding afresh would pick others).
#[test]
fn encrypted_listeners_are_handed_over() {
    let (dir, config) = setup("upgrade_tls");
    let rcgen::CertifiedKey { cert, signing_key } =
        rcgen::generate_simple_self_signed(vec!["dns.example".into()]).unwrap();
    std::fs::write(dir.join("dns.crt"), cert.pem()).unwrap();
    std::fs::write(dir.join("dns.key"), signing_key.serialize_pem()).unwrap();
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replace(
            "[[upstream]]",
            "[server.tls]\ncert = \"dns.crt\"\nkey = \"dns.key\"\n\
             dot = \"127.0.0.1:0\"\ndoh = \"127.0.0.1:0\"\n\n[[upstream]]",
        ),
    )
    .unwrap();
    let mut old = Running::start(&config);
    let [dot, doh, _, _] = old.wait_for_logs([
        "DNS over TLS listening",
        "DNS over HTTPS listening",
        "listening udp=",
        "API listening",
    ]);
    let (dot, doh) = (field(&dot, "address"), field(&doh, "address"));

    signal("USR2", old.child.id());
    let started = old.wait_for_log("started the new goethite");
    let new_pid: u32 = field(&started, "pid").parse().unwrap();
    let _stray = Stray(new_pid);
    // The new process logs these, and the old one says it handed over, in
    // no fixed order.
    let [_, tls_after, https_after, _] = old.wait_for_logs([
        "took over the previous goethite's sockets",
        "DNS over TLS listening",
        "DNS over HTTPS listening",
        "answering in place of the previous goethite",
    ]);
    assert_eq!(field(&tls_after, "address"), dot);
    assert_eq!(field(&https_after, "address"), doh);
    for addr in [&dot, &doh] {
        TcpStream::connect(addr.parse::<SocketAddr>().unwrap()).unwrap();
    }
    signal("TERM", new_pid);
    let stopping = Instant::now();
    while process_exists(new_pid) {
        assert!(stopping.elapsed() < WAIT, "the new goethite did not stop");
        std::thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn a_failed_upgrade_changes_nothing() {
    let (_dir, config) = setup("upgrade_fails");
    let mut old = Running::start(&config);
    let (udp, api) = old.addresses();
    // A second listen address: the new process cannot have a socket for it.
    let text = std::fs::read_to_string(&config).unwrap();
    std::fs::write(
        &config,
        text.replace(
            "listen = \"127.0.0.1:0\"\n\n[[upstream]]",
            "listen = [\"127.0.0.1:0\", \"127.0.0.2:0\"]\n\n[[upstream]]",
        ),
    )
    .unwrap();
    let load = Load::start(udp);
    signal("USR2", old.child.id());
    old.wait_for_log("the upgrade failed, carrying on");
    std::thread::sleep(Duration::from_millis(300));
    let (answered, lost) = load.finish();
    assert!(answered > 10);
    assert_eq!(lost, 0);
    assert!(old.child.try_wait().unwrap().is_none(), "still running");
    assert_eq!(http(api, "GET", "/api/v1/status", None).0, 200);
    signal("TERM", old.child.id());
    assert!(old.child.wait().unwrap().success());
}
