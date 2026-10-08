//! Two real goethite processes as a cluster: certificates from the command
//! line, a replica following the primary, changes forwarded through the
//! replica, read-only while the primary is gone, and promotion.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the no-panic rules cover non-test code"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_goethite");

/// How long to wait for something to happen.
const WAIT: Duration = Duration::from_secs(20);

fn dir(name: &str) -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn goethite(args: &[&str]) {
    let output = Command::new(BIN).args(args).output().unwrap();
    assert!(
        output.status.success(),
        "goethite {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// A port nothing listens on right now.
fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Node {
    child: Child,
    lines: mpsc::Receiver<String>,
    api: SocketAddr,
}

impl Node {
    fn start(dir: &Path, name: &str, role: &str, port: u16, peer: &str, peer_port: u16) -> Self {
        let certs = dir.join("certs");
        let config = format!(
            r#"[server]
listen = "127.0.0.1:0"

[[upstream]]
address = "192.0.2.1"

[filter]
# Offline: no default list to download.
default_lists = false

[api]
listen = "127.0.0.1:0"

[store]
path = "{store}"

[cluster]
node = "{name}"
role = "{role}"
listen = "127.0.0.1:{port}"
ca = "{certs}/ca.crt"
cert = "{certs}/{name}.crt"
key = "{certs}/{name}.key"

[cluster.peer]
node = "{peer}"
address = "127.0.0.1:{peer_port}"
"#,
            store = dir.join(format!("{name}.redb")).display(),
            certs = certs.display(),
        );
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(&path, config).unwrap();
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
        let mut node = Self {
            child,
            lines,
            api: "0.0.0.0:0".parse().unwrap(),
        };
        let line = node.wait_for_log("API listening");
        node.api = line
            .split_whitespace()
            .find_map(|part| part.strip_prefix("address="))
            .unwrap()
            .parse()
            .unwrap();
        node
    }

    fn wait_for_log(&self, needle: &str) -> String {
        loop {
            let line = self
                .lines
                .recv_timeout(WAIT)
                .unwrap_or_else(|_| panic!("no log line with {needle:?}"));
            if line.contains(needle) {
                return line;
            }
        }
    }

    /// One HTTP/1.1 request to the node's API: the status and the JSON body.
    fn http(&self, method: &str, path: &str, body: Option<&str>) -> (u16, Value) {
        let mut stream = TcpStream::connect(self.api).unwrap();
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

    /// Polls the cluster status until `done` holds.
    fn wait_for_cluster(&self, what: &str, done: impl Fn(&Value) -> bool) -> Value {
        let started = Instant::now();
        loop {
            let (status, cluster) = self.http("GET", "/api/v1/cluster", None);
            if status == 200 && done(&cluster) {
                return cluster;
            }
            assert!(started.elapsed() < WAIT, "{what}: {cluster}");
            std::thread::sleep(Duration::from_millis(200));
        }
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_two_node_cluster() {
    let dir = dir("cluster");
    let certs = dir.join("certs");
    std::fs::create_dir_all(&certs).unwrap();
    let certs = certs.to_str().unwrap();
    goethite(&["cluster", "init", "--dir", certs]);
    goethite(&["cluster", "cert", "dns1", "--dir", certs]);
    goethite(&["cluster", "cert", "dns2", "--dir", certs]);
    let (p1, p2) = (free_port(), free_port());
    let primary = Node::start(&dir, "dns1", "primary", p1, "dns2", p2);
    let replica = Node::start(&dir, "dns2", "replica", p2, "dns1", p1);
    replica.wait_for_log("copied the primary's configuration");
    let cluster = replica.wait_for_cluster("the replica sees the primary", |c| {
        c["peer"]["reachable"] == true && c["peer"]["role"] == "primary"
    });
    assert_eq!(
        (cluster["role"].as_str(), cluster["writable"].as_bool()),
        (Some("replica"), Some(true))
    );
    assert_eq!(cluster["problems"], Value::Array(Vec::new()));

    // A change through the replica lands on the primary, as its caller.
    let (status, created) = replica.http(
        "POST",
        "/api/v1/rules",
        Some(r#"{"rule":"||ads.example^"}"#),
    );
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap();
    assert_eq!(
        primary.http("GET", &format!("/api/v1/rules/{id}"), None).0,
        200
    );
    assert_eq!(
        replica.http("GET", &format!("/api/v1/rules/{id}"), None).0,
        200,
        "read your write"
    );
    let (_, audit) = primary.http("GET", "/api/v1/audit?limit=1", None);
    assert_eq!(audit[0]["actor"]["node"], "dns2");

    // Without the primary the replica answers, but its configuration is
    // read-only until it is promoted.
    drop(primary);
    replica.wait_for_cluster("the replica notices", |c| c["peer"]["reachable"] == false);
    let (status, refused) = replica.http(
        "POST",
        "/api/v1/rules",
        Some(r#"{"rule":"||more.example^"}"#),
    );
    assert_eq!(status, 503, "{refused}");
    let (status, promoted) = replica.http("POST", "/api/v1/cluster/promote", None);
    assert_eq!(status, 200, "{promoted}");
    assert_eq!(promoted["role"], "primary");
    let (status, _) = replica.http(
        "POST",
        "/api/v1/rules",
        Some(r#"{"rule":"||more.example^"}"#),
    );
    assert_eq!(status, 201);
}
