//! Real goethite processes as a cluster: certificates from the command
//! line, goethite 0.4's two-node tables starting a Raft cluster, changes
//! forwarded to the leader, read-only without one, taking over and joining
//! again; and two nodes with a witness electing a new leader by themselves.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the no-panic rules cover non-test code"
)]

use std::fmt::Write as _;
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

/// The certificates of a cluster of `nodes`, in `dir`/certs.
fn certificates(dir: &Path, nodes: &[&str]) -> PathBuf {
    let certs = dir.join("certs");
    std::fs::create_dir_all(&certs).unwrap();
    let path = certs.to_str().unwrap();
    goethite(&["cluster", "init", "--dir", path]);
    for node in nodes {
        goethite(&["cluster", "cert", node, "--dir", path]);
    }
    certs
}

/// A `[cluster]` table for `name` on `port`, with `extra` (such as
/// `bootstrap = true`) and the other members.
fn cluster_table(
    certs: &Path,
    name: &str,
    port: u16,
    extra: &str,
    members: &[(&str, u16)],
) -> String {
    let mut table = format!(
        "[cluster]\nnode = \"{name}\"\nlisten = \"127.0.0.1:{port}\"\nca = \"{certs}/ca.crt\"\n\
         cert = \"{certs}/{name}.crt\"\nkey = \"{certs}/{name}.key\"\n{extra}\n",
        certs = certs.display()
    );
    for (member, port) in members {
        writeln!(
            table,
            "[[cluster.member]]\nnode = \"{member}\"\naddress = \"127.0.0.1:{port}\"\n"
        )
        .unwrap();
    }
    table
}

struct Node {
    child: Child,
    lines: mpsc::Receiver<String>,
    api: SocketAddr,
}

impl Node {
    /// Starts goethite `name` with `cluster` as its `[cluster]` table, on
    /// the store `dir`/`name`.redb.
    fn start(dir: &Path, name: &str, cluster: &str) -> Self {
        let config = format!(
            r#"[server]
listen = "127.0.0.1:0"

[[upstream]]
address = "192.0.2.1"

[filter]
# Offline: no default list or services catalog to download.
default_lists = false
services = false

[api]
listen = "127.0.0.1:0"

[store]
path = "{store}"

{cluster}"#,
            store = dir.join(format!("{name}.redb")).display(),
        );
        let mut node = Self::spawn(dir, name, "run", &config);
        let line = node.wait_for_log("API listening");
        node.api = line
            .split_whitespace()
            .find_map(|part| part.strip_prefix("address="))
            .unwrap()
            .parse()
            .unwrap();
        node
    }

    /// Starts `goethite witness` `name` with `cluster` as its `[cluster]`
    /// table: no DNS, no API.
    fn witness(dir: &Path, name: &str, cluster: &str) -> Self {
        let config = format!(
            "[store]\npath = \"{}\"\n\n{cluster}",
            dir.join(format!("{name}.redb")).display()
        );
        let node = Self::spawn(dir, name, "witness", &config);
        node.wait_for_log("starting goethite witness");
        node
    }

    fn spawn(dir: &Path, name: &str, command: &str, config: &str) -> Self {
        let path = dir.join(format!("{name}.toml"));
        std::fs::write(&path, config).unwrap();
        let mut child = Command::new(BIN)
            .args([command, "--config", path.to_str().unwrap()])
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
            api: "0.0.0.0:0".parse().unwrap(),
        }
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

/// The members of `cluster` that vote.
fn voters(cluster: &Value) -> Vec<String> {
    cluster["members"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|member| member["membership"] == "voter")
        .map(|member| member["node"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn goethite_0_4_s_two_nodes_take_over_and_join_again() {
    let dir = dir("cluster-two");
    let certs = certificates(&dir, &["dns1", "dns2"]);
    let (p1, p2) = (free_port(), free_port());
    // goethite 0.4's tables: a role, and one peer.
    let legacy = |name: &str, role: &str, port: u16, peer: &str, peer_port: u16| {
        let table = cluster_table(&certs, name, port, &format!("role = \"{role}\""), &[]);
        format!("{table}[cluster.peer]\nnode = \"{peer}\"\naddress = \"127.0.0.1:{peer_port}\"\n")
    };
    let dns1_table = legacy("dns1", "primary", p1, "dns2", p2);
    let dns1 = Node::start(&dir, "dns1", &dns1_table);
    let dns2 = Node::start(&dir, "dns2", &legacy("dns2", "replica", p2, "dns1", p1));
    dns1.wait_for_log("started the cluster");
    // Two nodes: dns1 votes alone, dns2 learns, as a replica did.
    let cluster = dns2.wait_for_cluster("dns2 follows dns1", |c| {
        c["leader"] == "dns1" && c["state"] == "learner" && c["writable"] == true
    });
    assert_eq!(cluster["role"], "replica");
    assert_eq!(cluster["peer"]["node"], "dns1");
    assert_eq!(cluster["peer"]["role"], "primary");
    assert_eq!(voters(&cluster), ["dns1"]);
    assert_eq!(cluster["problems"], Value::Array(Vec::new()), "{cluster}");

    // A change through dns2 is made by the leader, as its caller.
    let (status, created) = dns2.http(
        "POST",
        "/api/v1/rules",
        Some(r#"{"rule":"||ads.example^"}"#),
    );
    assert_eq!(status, 201, "{created}");
    let id = created["id"].as_str().unwrap();
    assert_eq!(
        dns1.http("GET", &format!("/api/v1/rules/{id}"), None).0,
        200
    );
    assert_eq!(
        dns2.http("GET", &format!("/api/v1/rules/{id}"), None).0,
        200,
        "read your write"
    );
    let (_, audit) = dns1.http("GET", "/api/v1/audit?limit=1", None);
    assert_eq!(audit[0]["actor"]["node"], "dns2");
    // Every member keeps the same audit entry, from the log.
    let (_, audit) = dns2.http("GET", "/api/v1/audit?limit=1", None);
    assert_eq!(audit[0]["actor"]["node"], "dns2");
    assert_eq!(audit[0]["resource"].as_str(), Some(id));

    // Without the leader dns2 answers, but its configuration is read-only
    // until it takes the cluster over.
    drop(dns1);
    dns2.wait_for_cluster("dns2 notices", |c| c["peer"]["reachable"] == false);
    let (status, refused) = dns2.http(
        "POST",
        "/api/v1/rules",
        Some(r#"{"rule":"||more.example^"}"#),
    );
    assert_eq!(status, 503, "{refused}");
    let (status, promoted) = dns2.http("POST", "/api/v1/cluster/promote", None);
    assert_eq!(status, 200, "{promoted}");
    assert_eq!(
        (promoted["role"].as_str(), promoted["state"].as_str()),
        (Some("primary"), Some("leader"))
    );
    let (status, _) = dns2.http(
        "POST",
        "/api/v1/rules",
        Some(r#"{"rule":"||more.example^"}"#),
    );
    assert_eq!(status, 201);

    // dns1 comes back in its old cluster: both say so, and dns1 joins
    // dns2's once demoted, taking its configuration.
    let dns1 = Node::start(&dir, "dns1", &dns1_table);
    let cluster = dns1.wait_for_cluster("dns1 sees the other cluster", |c| {
        c["problems"]
            .as_array()
            .unwrap()
            .iter()
            .any(|problem| problem.as_str().unwrap().contains("in another cluster"))
    });
    assert_ne!(cluster["cluster"], promoted["cluster"]);
    let (status, demoted) = dns1.http("POST", "/api/v1/cluster/demote", None);
    assert_eq!(status, 200, "{demoted}");
    dns1.wait_for_cluster("dns1 joined dns2's cluster", |c| {
        c["cluster"] == promoted["cluster"] && c["leader"] == "dns2"
    });
    let started = Instant::now();
    loop {
        let (_, rules) = dns1.http("GET", "/api/v1/rules", None);
        if rules.as_array().is_some_and(|rules| rules.len() == 2) {
            break;
        }
        assert!(started.elapsed() < WAIT, "dns1 has dns2's rules: {rules}");
        std::thread::sleep(Duration::from_millis(200));
    }
}

#[test]
fn two_nodes_and_a_witness_elect_a_new_leader() {
    let dir = dir("cluster-witness");
    let certs = certificates(&dir, &["dns1", "dns2", "witness"]);
    let (p1, p2, pw) = (free_port(), free_port(), free_port());
    let dns1 = Node::start(
        &dir,
        "dns1",
        &cluster_table(
            &certs,
            "dns1",
            p1,
            "bootstrap = true",
            &[("dns2", p2), ("witness", pw)],
        ),
    );
    let dns2 = Node::start(
        &dir,
        "dns2",
        &cluster_table(&certs, "dns2", p2, "", &[("dns1", p1), ("witness", pw)]),
    );
    let witness = Node::witness(
        &dir,
        "witness",
        &cluster_table(&certs, "witness", pw, "", &[("dns1", p1), ("dns2", p2)]),
    );
    // Once both have caught up, all three vote.
    let cluster = dns1.wait_for_cluster("three voters", |c| voters(c).len() == 3);
    assert_eq!(cluster["state"], "leader");
    let witness_status = cluster["members"]
        .as_array()
        .unwrap()
        .iter()
        .find(|member| member["node"] == "witness")
        .unwrap()
        .clone();
    assert_eq!(witness_status["witness"], true, "{witness_status}");
    witness.wait_for_log("the cluster's leader leader=dns1");

    let (status, created) = dns2.http(
        "POST",
        "/api/v1/rules",
        Some(r#"{"rule":"||ads.example^"}"#),
    );
    assert_eq!(status, 201, "{created}");
    // The cluster's statistics leave the witness out.
    let (_, report) = dns2.http("GET", "/api/v1/stats?scope=cluster", None);
    assert_eq!(
        report["nodes"],
        serde_json::json!(["dns2", "dns1"]),
        "{report}"
    );

    // The leader goes: dns2 leads with the witness's vote, and changes go on.
    drop(dns1);
    dns2.wait_for_cluster("dns2 leads", |c| c["state"] == "leader");
    witness.wait_for_log("the cluster's leader leader=dns2");
    let (status, created) = dns2.http(
        "POST",
        "/api/v1/rules",
        Some(r#"{"rule":"||tracker.example^"}"#),
    );
    assert_eq!(status, 201, "{created}");
}
