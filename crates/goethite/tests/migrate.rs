//! `goethite migrate` against a fake Pi-hole and a fake AdGuard Home that
//! answer like the real ones, into a real goethite: the plan, applying it,
//! applying it again (nothing changes), and a migrated local record
//! answering over DNS.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the no-panic rules cover non-test code"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::str::FromStr;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, RecordType};
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

/// A goethite with its API and DNS on ephemeral loopback ports.
struct Node {
    child: Child,
    api: SocketAddr,
    dns: SocketAddr,
}

impl Node {
    fn start(dir: &Path) -> Self {
        let config = format!(
            r#"[server]
listen = "127.0.0.1:0"

[[upstream]]
address = "192.0.2.1"

[filter]
default_lists = false
services = false

[api]
listen = "127.0.0.1:0"

[store]
path = "{}"
"#,
            dir.join("goethite.redb").display()
        );
        let path = dir.join("goethite.toml");
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
        let (mut api, mut dns) = (None, None);
        while api.is_none() || dns.is_none() {
            let line = lines.recv_timeout(WAIT).expect("goethite did not start");
            let field = |name: &str| {
                line.split_whitespace()
                    .find_map(|part| part.strip_prefix(name))
                    .map(|value| value.parse::<SocketAddr>().unwrap())
            };
            if line.contains("API listening") {
                api = field("address=");
            }
            if line.contains("listening udp=") {
                dns = field("udp=");
            }
        }
        Self {
            child,
            api: api.unwrap(),
            dns: dns.unwrap(),
        }
    }

    fn get(&self, path: &str) -> Value {
        let mut stream = TcpStream::connect(self.api).unwrap();
        stream.set_read_timeout(Some(WAIT)).unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        let (_, body) = answer.split_once("\r\n\r\n").unwrap();
        serde_json::from_str(body).unwrap()
    }

    fn resolve(&self, name: &str) -> Vec<RData> {
        let mut query = Message::new(7, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_str(name).unwrap(), RecordType::A));
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_read_timeout(Some(WAIT)).unwrap();
        socket.send_to(&query.to_vec().unwrap(), self.dns).unwrap();
        let mut buf = [0_u8; 1500];
        let len = socket.recv(&mut buf).unwrap();
        let answer = Message::from_vec(&buf[..len]).unwrap();
        answer
            .answers
            .into_iter()
            .map(|record| record.data)
            .collect()
    }

    fn migrate(&self, args: &[&str]) -> String {
        let api = format!("http://{}", self.api);
        let output = Command::new(BIN)
            .arg("migrate")
            .args(args)
            .args(["--api", &api])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&output.stdout).into_owned();
        assert!(
            output.status.success(),
            "goethite migrate {args:?}: {}{text}",
            String::from_utf8_lossy(&output.stderr)
        );
        text
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// A fake HTTP server: `answer` maps a request (method, path, headers) to a
/// status and a JSON body. Every request is recorded.
struct Fake {
    url: String,
    seen: Arc<Mutex<Vec<String>>>,
}

type Answer = fn(&str, &str, &[(String, String)]) -> (u16, String);

impl Fake {
    fn start(answer: Answer) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { break };
                serve(stream, answer, &log);
            }
        });
        Self { url, seen }
    }
}

fn serve(mut stream: TcpStream, answer: Answer, log: &Mutex<Vec<String>>) {
    stream.set_read_timeout(Some(WAIT)).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    let mut parts = first.split_whitespace();
    let (method, path) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    let mut headers = Vec::new();
    let mut length = 0;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let line = line.trim_end();
        if line.is_empty() {
            break;
        }
        let (name, value) = line.split_once(':').unwrap();
        let (name, value) = (name.to_ascii_lowercase(), value.trim().to_owned());
        if name == "content-length" {
            length = value.parse().unwrap();
        }
        headers.push((name, value));
    }
    let mut body = vec![0_u8; length];
    reader.read_exact(&mut body).unwrap();
    log.lock().unwrap().push(format!("{method} {path}"));
    let (status, json) = answer(method, path, &headers);
    write!(
        stream,
        "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n{json}",
        json.len()
    )
    .unwrap();
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header == name)
        .map(|(_, value)| value.as_str())
}

/// Pi-hole v6: a session from `/api/auth`, then the configuration.
fn pihole(method: &str, path: &str, headers: &[(String, String)]) -> (u16, String) {
    if path == "/api/auth" {
        return match method {
            "POST" => (
                200,
                r#"{"session":{"valid":true,"totp":false,"sid":"vFA+EP4MQ5JJvJg+3Q2Jn","csrf":"x","validity":1800,"message":"password correct"},"took":0.003}"#.into(),
            ),
            _ => (204, String::new()),
        };
    }
    if header(headers, "x-ftl-sid") != Some("vFA+EP4MQ5JJvJg+3Q2Jn") {
        return (
            401,
            r#"{"error":{"key":"unauthorized","message":"Unauthorized","hint":null},"took":0.001}"#
                .into(),
        );
    }
    let body = match path {
        "/api/lists" => {
            r#"{"lists":[{"address":"https://lists.example/ads.txt","comment":null,"groups":[0],"enabled":true,"id":1,"type":"block","status":2},
                         {"address":"http://lists.example/plain.txt","comment":null,"groups":[0],"enabled":true,"id":2,"type":"block","status":2}],"took":0.01}"#
        }
        "/api/domains" => {
            r#"{"domains":[{"domain":"tracker.example","unicode":"tracker.example","type":"deny","kind":"exact","comment":null,"groups":[0],"enabled":true,"id":1}],"took":0.01}"#
        }
        "/api/groups" => {
            r#"{"groups":[{"name":"Default","comment":"The default group","enabled":true,"id":0},{"name":"kids","comment":null,"enabled":true,"id":5}],"took":0.01}"#
        }
        "/api/clients" => {
            r#"{"clients":[{"client":"192.168.1.23","name":"tablet.lan","comment":null,"groups":[5],"id":1}],"took":0.01}"#
        }
        "/api/config/dns" => {
            r#"{"config":{"dns":{"upstreams":["9.9.9.9"],"blockTTL":2,"hosts":["192.168.1.10 nas.lan"],"cnameRecords":["files.lan,nas.lan"],"blocking":{"active":true,"mode":"NULL","edns":"TEXT"}}},"took":0.01}"#
        }
        _ => {
            return (
                404,
                r#"{"error":{"key":"not_found","message":"Not found"}}"#.into(),
            );
        }
    };
    (200, body.into())
}

/// AdGuard Home: Basic auth (`admin:secret`), plain-text errors.
fn adguard(_method: &str, path: &str, headers: &[(String, String)]) -> (u16, String) {
    if header(headers, "authorization") != Some("Basic YWRtaW46c2VjcmV0") {
        return (401, String::new());
    }
    let body = match path {
        "/control/filtering/status" => {
            r#"{"filters":[{"url":"https://lists.example/agh.txt","name":"AdGuard list","id":1,"enabled":true}],"whitelist_filters":null,"user_rules":["||ads.example^"],"interval":24,"enabled":true}"#
        }
        "/control/clients" => {
            r#"{"clients":[{"name":"kid","ids":["192.168.1.40","kid-phone"],"use_global_settings":false,"filtering_enabled":true,"safe_search":{"enabled":true},"use_global_blocked_services":false,"blocked_services":["tiktok"],"upstreams":null}],"auto_clients":null}"#
        }
        "/control/rewrite/list" => {
            r#"[{"domain":"*.home.example","answer":"192.168.1.50","enabled":true}]"#
        }
        "/control/blocked_services/get" => {
            r#"{"ids":["youtube"],"schedule":{"time_zone":"Local"}}"#
        }
        "/control/safesearch/status" => r#"{"enabled":false}"#,
        "/control/dns_info" => {
            r#"{"blocking_mode":"refused","blocked_response_ttl":30,"upstream_dns":["https://dns.example/dns-query"]}"#
        }
        "/control/access/list" => {
            r#"{"allowed_clients":null,"disallowed_clients":["192.168.1.66"],"blocked_hosts":null}"#
        }
        "/control/status" => r#"{"version":"v0.107.79","running":true}"#,
        // Older than v0.107.68: no rewrite settings.
        _ => return (404, "404 page not found".into()),
    };
    (200, body.into())
}

#[test]
fn a_pi_hole_moves_over() {
    let dir = dir("migrate-pihole");
    let node = Node::start(&dir);
    let source = Fake::start(pihole);
    let password = dir.join("password");
    std::fs::write(&password, "secret\n").unwrap();
    let args = [
        "pihole",
        "--from",
        &source.url,
        "--password-file",
        password.to_str().unwrap(),
    ];

    let plan = node.migrate(&args);
    assert!(plan.contains("1 filter lists"), "{plan}");
    assert!(plan.contains("Nothing was changed"), "{plan}");
    assert!(plan.contains("http://lists.example/plain.txt"), "{plan}");
    assert_eq!(node.get("/api/v1/lists").as_array().unwrap().len(), 0);

    let applied = node.migrate(&[&args[..], &["--apply"]].concat());
    assert!(applied.contains("0 failed"), "{applied}");
    let lists = node.get("/api/v1/lists");
    assert_eq!(lists[0]["spec"]["url"], "https://lists.example/ads.txt");
    let default = node.get("/api/v1/groups/default");
    assert_eq!(default["spec"]["lists"][0]["list"], lists[0]["id"]);
    let clients = node.get("/api/v1/clients");
    assert_eq!(clients[0]["spec"]["name"], "tablet.lan");
    let groups = node.get("/api/v1/groups");
    let kids = groups
        .as_array()
        .unwrap()
        .iter()
        .find(|group| group["spec"]["name"] == "kids")
        .unwrap();
    assert_eq!(clients[0]["spec"]["group"], kids["id"]);
    assert_eq!(
        node.get("/api/v1/rules")[0]["spec"]["rule"],
        "|tracker.example^"
    );
    assert_eq!(node.get("/api/v1/records").as_array().unwrap().len(), 2);
    assert_eq!(node.get("/api/v1/settings")["spec"]["blocked_ttl"], 2);

    // Answered over DNS, through the CNAME.
    let answers = node.resolve("files.lan.");
    assert!(
        answers
            .iter()
            .any(|data| matches!(data, RData::A(a) if a.0.octets() == [192, 168, 1, 10])),
        "{answers:?}"
    );

    let again = node.migrate(&[&args[..], &["--apply"]].concat());
    assert!(again.contains("Applied: 0 changes made"), "{again}");
    let seen = source.seen.lock().unwrap();
    assert_eq!(
        seen.iter()
            .filter(|request| *request == "DELETE /api/auth")
            .count(),
        3,
        "every run logs out"
    );
}

#[test]
fn an_adguard_home_moves_over() {
    let dir = dir("migrate-adguard");
    let node = Node::start(&dir);
    let source = Fake::start(adguard);
    let password = dir.join("password");
    std::fs::write(&password, "secret").unwrap();
    let applied = node.migrate(&[
        "adguard-home",
        "--from",
        &source.url,
        "--password-file",
        password.to_str().unwrap(),
        "--apply",
    ]);
    assert!(applied.contains("0 failed"), "{applied}");
    let default = node.get("/api/v1/groups/default");
    assert_eq!(default["spec"]["blocked_services"][0]["service"], "youtube");
    let clients = node.get("/api/v1/clients");
    assert_eq!(clients[0]["spec"]["ids"][0], "kid-phone");
    let records = node.get("/api/v1/records");
    assert_eq!(records[0]["spec"]["name"], "*.home.example");
    let settings = node.get("/api/v1/settings");
    assert_eq!(settings["spec"]["block_response"], "refused");
    assert_eq!(settings["spec"]["blocked_ttl"], 30);
    assert_eq!(settings["spec"]["access"]["blocked"][0], "192.168.1.66");

    let answers = node.resolve("tv.home.example.");
    assert!(
        answers
            .iter()
            .any(|data| matches!(data, RData::A(a) if a.0.octets() == [192, 168, 1, 50])),
        "{answers:?}"
    );

    let wrong = dir.join("wrong");
    std::fs::write(&wrong, "nope").unwrap();
    let output = Command::new(BIN)
        .args(["migrate", "adguard-home", "--from", &source.url])
        .args(["--password-file", wrong.to_str().unwrap()])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("password"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
