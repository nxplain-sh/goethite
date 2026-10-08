//! The cluster channel over real mutual TLS: certificates, the node's
//! identity checks, and a replica following the primary's configuration.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code; the no-panic rules cover non-test code"
)]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use goethite_api::{ApiListeners, Serving, serve_router};
use goethite_cluster::certs::{self, Pem};
use goethite_cluster::server::{self, Shared};
use goethite_cluster::{ClientError, Identity, NodeId, PeerClient, Role};
use goethite_store::{Actor, ManagedBy, QueryLogConfig, Rule, RuleSpec, Store};
use jiff::Timestamp;
use tokio::sync::{oneshot, watch};

fn node(name: &str) -> NodeId {
    NodeId::new(name).unwrap()
}

fn identity(ca: &Pem, cert: &Pem, name: &str) -> Identity {
    Identity::from_pem(
        node(name),
        ca.cert.as_bytes(),
        cert.cert.as_bytes(),
        cert.key.as_bytes(),
    )
    .unwrap()
}

struct TempStore(Arc<Store>, PathBuf);

impl TempStore {
    fn new() -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "goethite-cluster-{}-{}.redb",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_file(&path);
        Self(Arc::new(Store::open(&path).unwrap()), path)
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.1);
    }
}

fn rule(text: &str) -> RuleSpec {
    RuleSpec {
        rule: text.into(),
        enabled: true,
        comment: String::new(),
        managed_by: ManagedBy::Api,
    }
}

/// A node's cluster listener, serving until dropped.
struct Listener {
    addr: SocketAddr,
    role: watch::Sender<Role>,
    _stop: oneshot::Sender<()>,
}

fn listen(identity: &Identity, peer: &str, store: &Arc<Store>, role: Role) -> Listener {
    let (role_tx, role_rx) = watch::channel(role);
    let shared = Arc::new(Shared {
        node: identity.node().clone(),
        role: role_rx,
        store: Arc::clone(store),
        log: store
            .start_query_log(QueryLogConfig::default(), Vec::new())
            .unwrap(),
        started_at: Timestamp::now(),
    });
    let listeners = ApiListeners::bind(&["127.0.0.1:0".parse().unwrap()]).unwrap();
    let addr = listeners.local_addrs().unwrap()[0];
    let serving = Serving {
        name: "cluster",
        router: server::router(shared),
        tls: Some(identity.server_config(&node(peer)).unwrap()),
        max_connections: 8,
    };
    let (stop, stopped) = oneshot::channel::<()>();
    tokio::spawn(serve_router(listeners, serving, async {
        let _ = stopped.await;
    }));
    Listener {
        addr,
        role: role_tx,
        _stop: stop,
    }
}

#[test]
fn identities_are_checked_when_loaded() {
    let ca = certs::new_ca().unwrap();
    let dns1 = certs::issue(&ca.key, &node("dns1")).unwrap();
    assert_eq!(identity(&ca, &dns1, "dns1").node().as_str(), "dns1");
    let load = |ca: &Pem, cert: &Pem, name: &str| {
        Identity::from_pem(
            node(name),
            ca.cert.as_bytes(),
            cert.cert.as_bytes(),
            cert.key.as_bytes(),
        )
    };
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

#[tokio::test]
async fn a_replica_follows_the_primary() {
    let ca = certs::new_ca().unwrap();
    let dns1 = identity(&ca, &certs::issue(&ca.key, &node("dns1")).unwrap(), "dns1");
    let dns2 = identity(&ca, &certs::issue(&ca.key, &node("dns2")).unwrap(), "dns2");
    let primary = TempStore::new();
    let replica = TempStore::new();
    primary
        .0
        .create::<Rule>(rule("||ads.example^"), &Actor::cli())
        .unwrap();
    let listener = listen(&dns1, "dns2", &primary.0, Role::Primary);
    let client =
        PeerClient::new(node("dns1"), listener.addr, dns2.client_config().unwrap()).unwrap();

    let info = client.node().await.unwrap();
    assert_eq!((info.node.as_str(), info.role), ("dns1", Role::Primary));
    assert_eq!(info.config, primary.0.version());
    let stats = client.stats(24).await.unwrap();
    assert_eq!(stats.totals.queries, 0);

    // A different epoch: the whole configuration, at once.
    let export = client
        .config(replica.0.version(), 0)
        .await
        .unwrap()
        .unwrap();
    replica
        .0
        .replace(export, &Actor::replication("dns1"))
        .unwrap()
        .unwrap();
    assert_eq!(*replica.0.config(), *primary.0.config());

    // Up to date: nothing after the wait.
    let started = Instant::now();
    assert!(
        client
            .config(replica.0.version(), 1)
            .await
            .unwrap()
            .is_none()
    );
    assert!(started.elapsed() >= Duration::from_millis(900));

    // A change while the replica waits arrives without waiting it out.
    let store = Arc::clone(&primary.0);
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(200)).await;
        store
            .create::<Rule>(rule("||tracker.example^"), &Actor::cli())
            .unwrap();
    });
    let started = Instant::now();
    let export = client
        .config(replica.0.version(), 30)
        .await
        .unwrap()
        .unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    replica
        .0
        .replace(export, &Actor::replication("dns1"))
        .unwrap()
        .unwrap();
    assert_eq!(replica.0.config().rules.len(), 2);

    // A node that is not the primary does not hand out its configuration.
    listener.role.send_replace(Role::Replica);
    let refused = client.config(replica.0.version(), 0).await.unwrap_err();
    assert!(
        matches!(refused, ClientError::Peer { status: 409, ref code, .. } if code == "not_primary")
    );
}

#[tokio::test]
async fn only_the_configured_peer_gets_in() {
    let ca = certs::new_ca().unwrap();
    let dns1 = identity(&ca, &certs::issue(&ca.key, &node("dns1")).unwrap(), "dns1");
    let dns3 = identity(&ca, &certs::issue(&ca.key, &node("dns3")).unwrap(), "dns3");
    let store = TempStore::new();
    let listener = listen(&dns1, "dns2", &store.0, Role::Primary);

    // dns3 has a valid cluster certificate, but dns1 expects dns2.
    let intruder =
        PeerClient::new(node("dns1"), listener.addr, dns3.client_config().unwrap()).unwrap();
    assert!(matches!(
        intruder.node().await,
        Err(ClientError::Connect { .. })
    ));

    // A client expecting dns2 at dns1's address refuses dns1's certificate.
    let fooled =
        PeerClient::new(node("dns2"), listener.addr, dns3.client_config().unwrap()).unwrap();
    assert!(matches!(
        fooled.node().await,
        Err(ClientError::Connect { .. })
    ));

    // A certificate from another cluster's CA is refused too.
    let other_ca = certs::new_ca().unwrap();
    let stranger = identity(
        &other_ca,
        &certs::issue(&other_ca.key, &node("dns2")).unwrap(),
        "dns2",
    );
    let outsider = PeerClient::new(
        node("dns1"),
        listener.addr,
        stranger.client_config().unwrap(),
    )
    .unwrap();
    assert!(matches!(
        outsider.node().await,
        Err(ClientError::Connect { .. })
    ));
}
