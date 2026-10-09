//! Raft's log and state machine, kept in the store's database.
//!
//! Log entries are JSON, by index ([`Store::log_append`]). The state machine
//! is the store's configuration: each entry is applied with
//! [`Store::apply`], together with a note of the entry and the membership
//! it leaves, in one transaction, so the configuration and what it includes
//! never disagree. A snapshot is the whole configuration, taken when asked
//! for: the configuration is small, and it is always on disk already.
//!
//! The store's calls block on disk I/O, so they run on blocking threads.

#![allow(
    clippy::result_large_err,
    reason = "openraft's StorageError is large, and its traits return it"
)]
#![allow(
    clippy::unused_async_trait_impl,
    reason = "openraft's traits are async; some answers are at hand"
)]

use std::fmt::Debug;
use std::io::Cursor;
use std::ops::RangeBounds;
use std::sync::Arc;

use goethite_store::{Applied, ConfigExport, Store, StoreError};
use openraft::storage::{LogFlushed, LogState, RaftLogStorage, RaftStateMachine, Snapshot};
use openraft::{
    AnyError, Entry, EntryPayload, ErrorSubject, ErrorVerb, LogId, RaftLogReader,
    RaftSnapshotBuilder, SnapshotMeta, StorageError, StorageIOError, Vote,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::{Member, Membership, RaftId, TypeConfig};
use crate::node::NodeId;

type StorageResult<T> = Result<T, StorageError<RaftId>>;

/// The store keys of this node's vote, of the last entry known committed,
/// and of the last entry purged from the log.
const VOTE: &str = "vote";
const COMMITTED: &str = "committed";
const PURGED: &str = "purged";

/// What the configuration includes: the last entry applied to it, and the
/// membership as of then. Kept with every entry applied.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct AppliedNote {
    last: Option<LogId<RaftId>>,
    membership: Membership,
}

/// A snapshot: the configuration, and the node it was taken on.
#[derive(Serialize, Deserialize)]
struct SnapshotData {
    node: String,
    export: ConfigExport,
}

/// The log, in the store.
#[derive(Clone)]
pub struct LogStore {
    store: Arc<Store>,
}

impl Debug for LogStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogStore").finish_non_exhaustive()
    }
}

impl LogStore {
    /// The log in `store`.
    pub fn new(store: Arc<Store>) -> Self {
        Self { store }
    }

    async fn value<T: DeserializeOwned + Send + 'static>(
        &self,
        key: &'static str,
        subject: ErrorSubject<RaftId>,
    ) -> StorageResult<Option<T>> {
        let text = blocking(&self.store, move |store| store.cluster_value(key))
            .await
            .map_err(|err| io_error(subject.clone(), ErrorVerb::Read, &err))?;
        text.map(|text| serde_json::from_str(&text))
            .transpose()
            .map_err(|err| io_error(subject, ErrorVerb::Read, &err))
    }

    async fn set_value<T: Serialize>(
        &self,
        key: &'static str,
        value: &T,
        subject: ErrorSubject<RaftId>,
    ) -> StorageResult<()> {
        let text = serde_json::to_string(value)
            .map_err(|err| io_error(subject.clone(), ErrorVerb::Write, &err))?;
        blocking(&self.store, move |store| {
            store.set_cluster_value(key, Some(&text))
        })
        .await
        .map_err(|err| io_error(subject, ErrorVerb::Write, &err))
    }
}

impl RaftLogReader<TypeConfig> for LogStore {
    async fn try_get_log_entries<RB: RangeBounds<u64> + Clone + Debug + Send>(
        &mut self,
        range: RB,
    ) -> StorageResult<Vec<Entry<TypeConfig>>> {
        let bounds = (range.start_bound().cloned(), range.end_bound().cloned());
        let rows = blocking(&self.store, move |store| store.log_entries(bounds))
            .await
            .map_err(|err| io_error(ErrorSubject::Logs, ErrorVerb::Read, &err))?;
        rows.iter()
            .map(|(_, bytes)| {
                serde_json::from_slice(bytes)
                    .map_err(|err| io_error(ErrorSubject::Logs, ErrorVerb::Read, &err))
            })
            .collect()
    }
}

impl RaftLogStorage<TypeConfig> for LogStore {
    type LogReader = Self;

    async fn get_log_state(&mut self) -> StorageResult<LogState<TypeConfig>> {
        let purged: Option<LogId<RaftId>> = self.value(PURGED, ErrorSubject::Logs).await?;
        let last = blocking(&self.store, Store::log_last)
            .await
            .map_err(|err| io_error(ErrorSubject::Logs, ErrorVerb::Read, &err))?;
        let last_log_id = match last {
            Some((_, bytes)) => {
                let entry: Entry<TypeConfig> = serde_json::from_slice(&bytes)
                    .map_err(|err| io_error(ErrorSubject::Logs, ErrorVerb::Read, &err))?;
                Some(entry.log_id)
            }
            None => purged,
        };
        Ok(LogState {
            last_purged_log_id: purged,
            last_log_id,
        })
    }

    async fn get_log_reader(&mut self) -> Self::LogReader {
        self.clone()
    }

    async fn save_vote(&mut self, vote: &Vote<RaftId>) -> StorageResult<()> {
        self.set_value(VOTE, vote, ErrorSubject::Vote).await
    }

    async fn read_vote(&mut self) -> StorageResult<Option<Vote<RaftId>>> {
        self.value(VOTE, ErrorSubject::Vote).await
    }

    async fn save_committed(&mut self, committed: Option<LogId<RaftId>>) -> StorageResult<()> {
        self.set_value(COMMITTED, &committed, ErrorSubject::Store)
            .await
    }

    async fn read_committed(&mut self) -> StorageResult<Option<LogId<RaftId>>> {
        Ok(self
            .value::<Option<LogId<RaftId>>>(COMMITTED, ErrorSubject::Store)
            .await?
            .flatten())
    }

    async fn append<I>(&mut self, entries: I, callback: LogFlushed<TypeConfig>) -> StorageResult<()>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let rows = entries
            .into_iter()
            .map(|entry| serde_json::to_vec(&entry).map(|bytes| (entry.log_id.index, bytes)))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|err| io_error(ErrorSubject::Logs, ErrorVerb::Write, &err))?;
        match blocking(&self.store, move |store| store.log_append(&rows)).await {
            Ok(()) => {
                callback.log_io_completed(Ok(()));
                Ok(())
            }
            Err(err) => {
                callback.log_io_completed(Err(std::io::Error::other(err.to_string())));
                Err(io_error(ErrorSubject::Logs, ErrorVerb::Write, &err))
            }
        }
    }

    async fn truncate(&mut self, log_id: LogId<RaftId>) -> StorageResult<()> {
        blocking(&self.store, move |store| store.log_truncate(log_id.index))
            .await
            .map_err(|err| io_error(ErrorSubject::Logs, ErrorVerb::Delete, &err))
    }

    async fn purge(&mut self, log_id: LogId<RaftId>) -> StorageResult<()> {
        let text = serde_json::to_string(&log_id)
            .map_err(|err| io_error(ErrorSubject::Logs, ErrorVerb::Delete, &err))?;
        blocking(&self.store, move |store| {
            store.log_purge(log_id.index, PURGED, &text)
        })
        .await
        .map_err(|err| io_error(ErrorSubject::Logs, ErrorVerb::Delete, &err))
    }
}

/// The configuration, as Raft's state machine.
pub struct StateMachine {
    store: Arc<Store>,
    node: String,
    membership: Membership,
}

impl Debug for StateMachine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateMachine")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

impl StateMachine {
    /// The configuration in `store`, on `node`.
    ///
    /// # Errors
    ///
    /// [`StoreError::Incompatible`] if the store's note of what it applied
    /// cannot be read.
    pub fn new(store: Arc<Store>, node: &NodeId) -> Result<Self, StoreError> {
        let membership = note(&store)?.membership;
        Ok(Self {
            store,
            node: node.to_string(),
            membership,
        })
    }
}

/// The store's note of what its configuration includes.
fn note(store: &Store) -> Result<AppliedNote, StoreError> {
    store
        .applied()
        .map(|text| serde_json::from_str(&text))
        .transpose()
        .map(Option::unwrap_or_default)
        .map_err(|err| StoreError::Incompatible(format!("the applied note: {err}")))
}

impl RaftStateMachine<TypeConfig> for StateMachine {
    type SnapshotBuilder = SnapshotBuilder;

    async fn applied_state(&mut self) -> StorageResult<(Option<LogId<RaftId>>, Membership)> {
        let note = note(&self.store)
            .map_err(|err| io_error(ErrorSubject::StateMachine, ErrorVerb::Read, &err))?;
        Ok((note.last, note.membership))
    }

    async fn apply<I>(&mut self, entries: I) -> StorageResult<Vec<Applied>>
    where
        I: IntoIterator<Item = Entry<TypeConfig>> + Send,
        I::IntoIter: Send,
    {
        let mut results = Vec::new();
        for entry in entries {
            let log_id = entry.log_id;
            let command = match entry.payload {
                EntryPayload::Blank => None,
                EntryPayload::Normal(command) => Some(command),
                EntryPayload::Membership(membership) => {
                    self.membership = Membership::new(Some(log_id), membership);
                    None
                }
            };
            let note = serde_json::to_string(&AppliedNote {
                last: Some(log_id),
                membership: self.membership.clone(),
            })
            .map_err(|err| StorageIOError::apply(log_id, AnyError::new(&err)))?;
            let applied = blocking(&self.store, move |store| store.apply(command, &note))
                .await
                .map_err(|err| StorageIOError::apply(log_id, AnyError::new(&err)))?;
            results.push(applied);
        }
        Ok(results)
    }

    async fn get_snapshot_builder(&mut self) -> Self::SnapshotBuilder {
        SnapshotBuilder {
            store: Arc::clone(&self.store),
            node: self.node.clone(),
        }
    }

    async fn begin_receiving_snapshot(&mut self) -> StorageResult<Box<Cursor<Vec<u8>>>> {
        Ok(Box::new(Cursor::new(Vec::new())))
    }

    async fn install_snapshot(
        &mut self,
        meta: &SnapshotMeta<RaftId, Member>,
        snapshot: Box<Cursor<Vec<u8>>>,
    ) -> StorageResult<()> {
        let subject = ErrorSubject::Snapshot(Some(meta.signature()));
        let note = serde_json::to_string(&AppliedNote {
            last: meta.last_log_id,
            membership: meta.last_membership.clone(),
        })
        .map_err(|err| io_error(subject.clone(), ErrorVerb::Write, &err))?;
        let bytes = snapshot.into_inner();
        blocking(&self.store, move |store| {
            let data: SnapshotData = serde_json::from_slice(&bytes).map_err(|err| {
                StoreError::Incompatible(format!("a snapshot that cannot be read: {err}"))
            })?;
            store.install_snapshot(data.export, &data.node, &note)
        })
        .await
        .map_err(|err| io_error(subject, ErrorVerb::Write, &err))?;
        self.membership = meta.last_membership.clone();
        Ok(())
    }

    async fn get_current_snapshot(&mut self) -> StorageResult<Option<Snapshot<TypeConfig>>> {
        let snapshot = take_snapshot(&self.store, &self.node).await?;
        Ok(snapshot.meta.last_log_id.is_some().then_some(snapshot))
    }
}

/// Takes snapshots of the configuration.
pub struct SnapshotBuilder {
    store: Arc<Store>,
    node: String,
}

impl Debug for SnapshotBuilder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SnapshotBuilder")
            .field("node", &self.node)
            .finish_non_exhaustive()
    }
}

impl RaftSnapshotBuilder<TypeConfig> for SnapshotBuilder {
    async fn build_snapshot(&mut self) -> StorageResult<Snapshot<TypeConfig>> {
        take_snapshot(&self.store, &self.node).await
    }
}

/// The configuration now, with what it includes, as a snapshot.
async fn take_snapshot(store: &Arc<Store>, node: &str) -> StorageResult<Snapshot<TypeConfig>> {
    let taken_on = node.to_owned();
    let (included, bytes, node) = blocking(store, move |store| {
        let (export, applied) = store.snapshot();
        let included: AppliedNote = applied
            .map(|text| serde_json::from_str(&text))
            .transpose()
            .map_err(|err| StoreError::Incompatible(format!("the applied note: {err}")))?
            .unwrap_or_default();
        let bytes = serde_json::to_vec(&SnapshotData {
            node: taken_on.clone(),
            export,
        })
        .map_err(StoreError::Encode)?;
        Ok((included, bytes, taken_on))
    })
    .await
    .map_err(|err| io_error(ErrorSubject::Snapshot(None), ErrorVerb::Read, &err))?;
    // The state as of one entry, taken on one node, is always the same
    // bytes: so is its ID.
    let snapshot_id = match included.last {
        Some(last) => format!("{node}-{last}"),
        None => format!("{node}-empty"),
    };
    Ok(Snapshot {
        meta: SnapshotMeta {
            last_log_id: included.last,
            last_membership: included.membership,
            snapshot_id,
        },
        snapshot: Box::new(Cursor::new(bytes)),
    })
}

/// Runs `call` with the store on a blocking thread.
async fn blocking<T: Send + 'static>(
    store: &Arc<Store>,
    call: impl FnOnce(&Store) -> Result<T, StoreError> + Send + 'static,
) -> Result<T, StoreError> {
    let store = Arc::clone(store);
    tokio::task::spawn_blocking(move || call(&store))
        .await
        .map_err(|err| StoreError::Unavailable(format!("a store task failed: {err}")))?
}

fn io_error(
    subject: ErrorSubject<RaftId>,
    verb: ErrorVerb,
    err: &(impl std::error::Error + 'static),
) -> StorageError<RaftId> {
    StorageIOError::new(subject, verb, AnyError::new(err)).into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use openraft::testing::{StoreBuilder, Suite};

    struct Builder;

    impl StoreBuilder<TypeConfig, LogStore, StateMachine, ()> for Builder {
        async fn build(&self) -> StorageResult<((), LogStore, StateMachine)> {
            let store = Arc::new(
                Store::open_in_memory()
                    .map_err(|err| io_error(ErrorSubject::Store, ErrorVerb::Write, &err))?,
            );
            let node = NodeId::new("dns1")
                .map_err(|err| io_error(ErrorSubject::Store, ErrorVerb::Write, &err))?;
            let machine = StateMachine::new(Arc::clone(&store), &node)
                .map_err(|err| io_error(ErrorSubject::Store, ErrorVerb::Read, &err))?;
            Ok(((), LogStore::new(store), machine))
        }
    }

    /// openraft's own checks of a log and a state machine.
    #[test]
    fn the_storage_passes_openraft_s_suite() {
        Suite::test_all(Builder).unwrap();
    }
}
