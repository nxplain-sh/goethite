//! The cluster channel over real mutual TLS: certificates, the members'
//! identity checks, and Raft clusters agreeing on configuration changes,
//! losing their leader, being taken over and joined again.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the no-panic rules cover non-test code"
)]

use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use goethite_api::{ApiListeners, Serving, serve_router};
use goethite_cluster::certs::{self, Pem};
use goethite_cluster::raft::node::RaftNode;
use goethite_cluster::raft::raft_id;
use goethite_cluster::server::{self, Shared};
use goethite_cluster::wire::RaftState;
use goethite_cluster::{ClientError, Identity, NodeId, PeerClient, Peers};
use goethite_store::{Actor, ManagedBy, Rule, RuleSpec, Store, StoreError};
use jiff::Timestamp;
use tokio::sync::oneshot;

fn node(name: &str) -> NodeId {
    NodeId::new(name).unwrap()
}

fn identity(ca: &Pem, name: &str) -> Identity {
    let cert = certs::issue(&ca.key, &node(name)).unwrap();
    Identity::from_pem(
        node(name),
        ca.cert.as_bytes(),
        cert.cert.as_bytes(),
        cert.key.as_bytes(),
    )
    .unwrap()
}

fn temp_path() -> PathBuf {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    let path = std::env::temp_dir().join(format!(
        "goethite-cluster-{}-{}.redb",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_file(&path);
    path
}

/// A store at a new path, holding `rules`: a node's configuration from
/// before it was in a cluster.
fn prepared(rules: &[&str]) -> PathBuf {
    let path = temp_path();
    let store = Store::open(&path).unwrap();
    for text in rules {
        store.create::<Rule>(rule(text), &Actor::cli()).unwrap();
    }
    path
}

fn rule(text: &str) -> RuleSpec {
    RuleSpec {
        rule: text.into(),
        enabled: true,
        comment: String::new(),
        managed_by: ManagedBy::Api,
    }
}

/// A member: its store, its Raft and its cluster listener, serving until
/// stopped.
struct Node {
    name: NodeId,
    addr: SocketAddr,
    store: Arc<Store>,
    raft: Arc<RaftNode>,
    stop: Option<oneshot::Sender<()>>,
    path: PathBuf,
}

impl Node {
    /// Starts `name` on the store at `path`, accepting `peers`; on the same
    /// address as before when `addr` is given.
    async fn start(
        ca: &Pem,
        name: &str,
        witness: bool,
        peers: &[&str],
        path: PathBuf,
        addr: Option<SocketAddr>,
    ) -> Self {
        let identity = identity(ca, name);
        let store = Arc::new(Store::open(&path).unwrap());
        let bind = addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
        let listeners = ApiListeners::bind(&[bind]).unwrap();
        let addr = listeners.local_addrs().unwrap()[0];
        let raft = RaftNode::start(
            node(name),
            addr,
            witness,
            Arc::clone(&store),
            identity.client_config().unwrap(),
        )
        .await
        .unwrap();
        let shared = Arc::new(Shared {
            node: node(name),
            witness,
            raft: Arc::clone(raft.shared()),
            store: Arc::clone(&store),
            log: None,
            started_at: Timestamp::now(),
        });
        let peers = Peers::new(peers.iter().map(|peer| node(peer)));
        let serving = Serving {
            name: "cluster",
            router: server::router(shared),
            tls: Some(identity.server_config(peers).unwrap()),
            max_connections: 16,
        };
        let (stop, stopped) = oneshot::channel::<()>();
        tokio::spawn(serve_router(listeners, serving, async {
            let _ = stopped.await;
        }));
        Self {
            name: node(name),
            addr,
            store,
            raft,
            stop: Some(stop),
            path,
        }
    }

    /// Stops it, keeping its store's file.
    async fn stop(mut self) -> (PathBuf, SocketAddr) {
        self.raft.shutdown().await;
        drop(self.stop.take());
        // Let the listener and the store go.
        tokio::time::sleep(Duration::from_millis(200)).await;
        let path = std::mem::take(&mut self.path);
        let addr = self.addr;
        drop(self);
        (path, addr)
    }

    fn id(&self) -> u64 {
        raft_id(&self.name)
    }

    fn state(&self) -> RaftState {
        goethite_cluster::raft::state_of(self.raft.metrics().as_ref()).0
    }

    /// Adds a rule through this node's store, as the API would.
    async fn add_rule(&self, text: &str) -> Result<Rule, StoreError> {
        let store = Arc::clone(&self.store);
        let spec = rule(text);
        tokio::task::spawn_blocking(move || store.create::<Rule>(spec, &Actor::cli()))
            .await
            .unwrap()
    }

    fn rules(&self) -> Vec<String> {
        self.store
            .config()
            .rules
            .iter()
            .map(|rule| rule.spec.rule.clone())
            .collect()
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if !self.path.as_os_str().is_empty() {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Waits up to 15 seconds for `check`.
async fn eventually(what: &str, mut check: impl FnMut() -> bool) {
    let started = Instant::now();
    while !check() {
        assert!(
            started.elapsed() < Duration::from_secs(15),
            "timed out waiting until {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Adds `learners` to the cluster `leader` leads, then makes `voters` its
/// voters once they have caught up.
async fn grow(leader: &Node, learners: &[&Node], voters: &[&Node]) {
    for learner in learners {
        leader
            .raft
            .add_learner(&learner.name, learner.addr)
            .await
            .unwrap();
    }
    for learner in learners {
        eventually("the learner caught up", || {
            learner.store.version() == leader.store.version()
        })
        .await;
    }
    if !voters.is_empty() {
        let ids: BTreeSet<u64> = voters.iter().map(|node| node.id()).collect();
        leader.raft.set_voters(ids).await.unwrap();
    }
}

#[test]
fn identities_are_checked_when_loaded() {
    let ca = certs::new_ca().unwrap();
    let dns1 = certs::issue(&ca.key, &node("dns1")).unwrap();
    let load = |ca: &Pem, cert: &Pem, name: &str| {
        Identity::from_pem(
            node(name),
            ca.cert.as_bytes(),
            cert.cert.as_bytes(),
            cert.key.as_bytes(),
        )
    };
    assert_eq!(load(&ca, &dns1, "dns1").unwrap().node().as_str(), "dns1");
    // Another node's name, another cluster's CA, another key.
    assert!(load(&ca, &dns1, "dns2").is_err());
    let other_ca = certs::new_ca().unwrap();
    assert!(load(&other_ca, &dns1, "dns1").is_err());
    let dns1_again = certs::issue(&ca.key, &node("dns1")).unwrap();
    let mixed = Pem {
        cert: dns1.cert.clone(),
        key: dns1_again.key,
    };
    assert!(load(&ca, &mixed, "dns1").is_err());
    // Garbage.
    let junk = Pem {
        cert: "not a certificate".into(),
        key: "not a key".into(),
    };
    assert!(load(&ca, &junk, "dns1").is_err());
    assert!(format!("{dns1:?}").contains('…'), "keys are never printed");
}

#[tokio::test(flavor = "multi_thread")]
async fn only_known_members_get_in() {
    let ca = certs::new_ca().unwrap();
    let dns1 = Node::start(&ca, "dns1", false, &["dns2"], temp_path(), None).await;
    let dns3 = identity(&ca, "dns3");

    // dns3 has a valid cluster certificate, but dns1 knows only dns2.
    let intruder = PeerClient::new(node("dns1"), dns1.addr, dns3.client_config().unwrap()).unwrap();
    assert!(matches!(
        intruder.node().await,
        Err(ClientError::Connect { .. })
    ));

    // A client expecting dns2 at dns1's address refuses dns1's certificate.
    let fooled = PeerClient::new(node("dns2"), dns1.addr, dns3.client_config().unwrap()).unwrap();
    assert!(matches!(
        fooled.node().await,
        Err(ClientError::Connect { .. })
    ));

    // A certificate from another cluster's CA is refused too.
    let other_ca = certs::new_ca().unwrap();
    let stranger = identity(&other_ca, "dns2");
    let outsider =
        PeerClient::new(node("dns1"), dns1.addr, stranger.client_config().unwrap()).unwrap();
    assert!(matches!(
        outsider.node().await,
        Err(ClientError::Connect { .. })
    ));

    // dns2 gets in, and learns about dns1.
    let dns2 = identity(&ca, "dns2");
    let member = PeerClient::new(node("dns1"), dns1.addr, dns2.client_config().unwrap()).unwrap();
    let info = member.node().await.unwrap();
    assert_eq!(info.node.as_str(), "dns1");
    assert_eq!((info.cluster, info.state), (None, RaftState::Learner));
    assert!(!info.witness);
}

#[tokio::test(flavor = "multi_thread")]
async fn a_cluster_agrees_and_survives_losing_its_leader() {
    let ca = certs::new_ca().unwrap();
    let everyone = ["dns1", "dns2", "witness"];
    let dns1 = Node::start(
        &ca,
        "dns1",
        false,
        &everyone,
        prepared(&["||before.example^"]),
        None,
    )
    .await;
    let dns2 = Node::start(
        &ca,
        "dns2",
        false,
        &everyone,
        prepared(&["||mine.example^"]),
        None,
    )
    .await;
    let witness = Node::start(&ca, "witness", true, &everyone, temp_path(), None).await;

    // Before it is in a cluster, a node's configuration cannot change.
    assert!(matches!(
        dns1.add_rule("||early.example^").await,
        Err(StoreError::Unavailable(_))
    ));
    // dns1's configuration becomes the cluster's; dns2's own is replaced.
    dns1.raft.bootstrap().await.unwrap();
    assert_eq!(dns1.state(), RaftState::Leader);
    grow(&dns1, &[&dns2, &witness], &[&dns1, &dns2, &witness]).await;
    assert_eq!(dns2.rules(), ["||before.example^"]);
    assert_eq!(dns2.raft.cluster(), dns1.raft.cluster());

    // Changes on the leader reach every member, the witness included.
    dns1.add_rule("||ads.example^").await.unwrap();
    eventually("every member has the change", || {
        dns2.rules().len() == 2 && witness.rules().len() == 2
    })
    .await;
    assert_eq!(*dns2.store.config(), *dns1.store.config());
    assert_eq!(dns2.store.version(), dns1.store.version());
    // A follower cannot make changes itself: they go to the leader.
    assert!(matches!(
        dns2.add_rule("||follower.example^").await,
        Err(StoreError::Unavailable(_))
    ));

    // The leader goes; dns2 leads with the witness's vote. The witness
    // itself never stands.
    let leader_term = dns1.raft.metrics().unwrap().current_term;
    let _ = dns1.stop().await;
    eventually("dns2 leads", || dns2.state() == RaftState::Leader).await;
    assert_ne!(witness.state(), RaftState::Leader);
    assert!(dns2.raft.metrics().unwrap().current_term > leader_term);
    dns2.add_rule("||tracker.example^").await.unwrap();
    eventually("the witness has the change", || witness.rules().len() == 3).await;

    // Without a majority, changes are refused rather than lost.
    let _ = witness.stop().await;
    let started = Instant::now();
    let refused = dns2.add_rule("||lonely.example^").await;
    assert!(
        matches!(refused, Err(StoreError::Unavailable(_))),
        "{refused:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(15));
}

#[tokio::test(flavor = "multi_thread")]
async fn a_node_takes_the_cluster_over_and_the_other_joins_it() {
    let ca = certs::new_ca().unwrap();
    let both = ["dns1", "dns2"];
    let dns1 = Node::start(&ca, "dns1", false, &both, temp_path(), None).await;
    let dns2 = Node::start(&ca, "dns2", false, &both, temp_path(), None).await;
    dns1.raft.bootstrap().await.unwrap();
    // Two nodes: dns1 votes alone, dns2 learns.
    grow(&dns1, &[&dns2], &[]).await;
    dns1.add_rule("||ads.example^").await.unwrap();
    eventually("dns2 has the change", || dns2.rules().len() == 1).await;
    let old_cluster = dns1.raft.cluster().unwrap();

    // dns1 goes. dns2 cannot elect itself: it takes the cluster over.
    let (path, addr) = dns1.stop().await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(dns2.state(), RaftState::Learner);
    dns2.raft.take_over().await.unwrap();
    assert_eq!(dns2.state(), RaftState::Leader);
    assert_ne!(dns2.raft.cluster(), Some(old_cluster));
    assert_eq!(dns2.rules(), ["||ads.example^"], "its configuration stays");
    dns2.add_rule("||tracker.example^").await.unwrap();

    // dns1 comes back, still in the old cluster: it cannot rejoin by
    // itself, and its configuration does not change.
    let dns1 = Node::start(&ca, "dns1", false, &both, path, Some(addr)).await;
    assert_eq!(dns1.raft.cluster(), Some(old_cluster));
    assert!(dns2.raft.add_learner(&dns1.name, dns1.addr).await.is_ok());
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(dns1.rules(), ["||ads.example^"]);
    assert_eq!(dns1.raft.cluster(), Some(old_cluster));

    // Once it leaves its old cluster, the leader's entries reach it.
    dns1.raft.leave().await.unwrap();
    eventually("dns1 joined dns2's cluster", || {
        dns1.raft.cluster() == dns2.raft.cluster() && dns1.rules().len() == 2
    })
    .await;
    assert_eq!(*dns1.store.config(), *dns2.store.config());

    // The leader removes members.
    dns2.raft.remove(dns1.id()).await.unwrap();
    eventually("dns1 is gone", || {
        !dns2
            .raft
            .metrics()
            .unwrap()
            .membership_config
            .nodes()
            .any(|(id, _)| *id == dns1.id())
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_late_member_catches_up_from_a_snapshot() {
    let ca = certs::new_ca().unwrap();
    let both = ["dns1", "dns2"];
    let dns1 = Node::start(&ca, "dns1", false, &both, temp_path(), None).await;
    dns1.raft.bootstrap().await.unwrap();
    // Enough changes that dns1 takes a snapshot and drops the start of its
    // log (every 500 entries, keeping 100).
    let store = Arc::clone(&dns1.store);
    tokio::task::spawn_blocking(move || {
        for n in 0..620 {
            store
                .create::<Rule>(rule(&format!("||n{n}.example^")), &Actor::cli())
                .unwrap();
        }
    })
    .await
    .unwrap();
    eventually("dns1 purged its log", || {
        dns1.raft
            .metrics()
            .is_some_and(|metrics| metrics.purged.is_some() && metrics.snapshot.is_some())
    })
    .await;

    // dns2 joins: the log it needs is gone, so it gets the snapshot.
    let dns2 = Node::start(&ca, "dns2", false, &both, temp_path(), None).await;
    grow(&dns1, &[&dns2], &[]).await;
    assert_eq!(dns2.rules().len(), 620);
    assert_eq!(*dns2.store.config(), *dns1.store.config());
    let audit = dns2.store.audit(None, 1).unwrap();
    assert_eq!(audit[0].action, goethite_store::AuditAction::Replicate);
    // And it follows from there.
    dns1.add_rule("||after.example^").await.unwrap();
    eventually("dns2 has the change", || dns2.rules().len() == 621).await;
}
