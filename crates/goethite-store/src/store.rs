//! The store: configuration resources and the audit log in one redb
//! database file.
//!
//! The whole configuration is small, so it is also kept in memory as an
//! immutable [`ConfigSnapshot`]: reads never touch the disk. A change copies
//! the snapshot, applies itself, validates the result as a whole, then writes
//! the changed rows and an audit entry in one transaction before the new
//! snapshot replaces the old one. Writes are serialized; they block on disk
//! I/O, so async callers run them on a blocking thread.
//!
//! In a cluster, a change is not written at once: it becomes a [`Change`]
//! that goes through the cluster's log ([`Replicator`]), and every member
//! applies it in the log's order ([`Store::apply`]). The log itself lives in
//! the same database (`log`).
//!
//! Every change that writes resources also bumps the [`ConfigVersion`], in
//! the same transaction, and announces it on a watch channel, so the node
//! can put it into effect and a caller can wait to read its own write.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use jiff::Timestamp;
use redb::{
    Database, DatabaseError, ReadableDatabase, ReadableTable, ReadableTableMetadata,
    TableDefinition,
};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;
use tracing::{info, warn};
use utoipa::ToSchema;

use crate::model::{
    Client, ConfigSnapshot, DEFAULT_GROUP, Group, GroupList, List, ListSpec, ManagedBy, Record,
    Resource, Rule, RuleSpec, Schedule, Settings, SettingsSpec, User, ValidationError,
    default_group_resource,
};

mod log;

/// The most audit entries kept; older ones are dropped.
pub const MAX_AUDIT_ENTRIES: u64 = 100_000;

/// The store's schema version, kept in the `meta` table. A cluster member
/// takes a whole configuration (a seed or a snapshot) only with the same
/// one. Version 2 added local DNS records; version 3 users. Opening an
/// older store creates the missing tables, which is the whole migration.
const SCHEMA_VERSION: &str = "3";

const SETTINGS: TableDefinition<'static, &'static str, &'static [u8]> =
    TableDefinition::new("settings");
const META: TableDefinition<'static, &'static str, &'static str> = TableDefinition::new("meta");
/// The `meta` key of the configuration's epoch.
const EPOCH_KEY: &str = "config_epoch";
/// The `meta` key of the configuration's version.
const VERSION_KEY: &str = "config_version";
/// The `meta` key of what the cluster's log applied to the configuration,
/// opaque to the store ([`Store::apply`]).
const APPLIED_KEY: &str = "cluster_applied";
const AUDIT: TableDefinition<'static, u64, &'static [u8]> = TableDefinition::new("audit");

/// A kind of stored resource.
pub trait Kind: Clone + Serialize + DeserializeOwned + Send + Sync + 'static {
    /// What a client writes.
    type Spec: Clone + PartialEq + Serialize;
    /// The kind's name, such as `client`.
    const NAME: &'static str;
    /// The prefix of generated IDs, such as `cl`.
    const PREFIX: &'static str;
    /// The name of the table holding the kind.
    const TABLE_NAME: &'static str;

    /// The table holding the kind.
    fn table() -> TableDefinition<'static, &'static str, &'static [u8]> {
        TableDefinition::new(Self::TABLE_NAME)
    }

    /// A resource from its parts.
    fn new(
        id: String,
        revision: u64,
        created_at: Timestamp,
        updated_at: Timestamp,
        spec: Self::Spec,
    ) -> Self;
    /// Its ID.
    fn id(&self) -> &str;
    /// Its revision.
    fn revision(&self) -> u64;
    /// When it was created.
    fn created_at(&self) -> Timestamp;
    /// Its spec.
    fn spec(&self) -> &Self::Spec;
    /// All resources of this kind in `config`.
    fn all(config: &ConfigSnapshot) -> &Vec<Self>;
    /// All resources of this kind in `config`, to change them.
    fn all_mut(config: &mut ConfigSnapshot) -> &mut Vec<Self>;
    /// The resource, tagged with its kind.
    fn into_resource(self) -> Resource;
}

/// Implements the OpenAPI schema of an enum whose values grow over time: a
/// string with `x-extensible-enum` rather than `enum`, so clients must
/// handle values they do not know yet, and adding one is not a breaking
/// change. The exhaustive match keeps the published list complete.
macro_rules! extensible_enum {
    ($ty:ident, $description:literal, [$($variant:ident),+ $(,)?]) => {
        impl utoipa::PartialSchema for $ty {
            fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
                // Fails to compile if a variant is missing below.
                fn listed(value: $ty) {
                    match value {
                        $($ty::$variant)|+ => {}
                    }
                }
                let _ = listed;
                let values: Vec<serde_json::Value> = [$($ty::$variant),+]
                    .iter()
                    .filter_map(|value| serde_json::to_value(value).ok())
                    .collect();
                utoipa::openapi::ObjectBuilder::new()
                    .schema_type(utoipa::openapi::schema::Type::String)
                    .description(Some($description))
                    .extensions(Some(utoipa::openapi::extensions::Extensions::from_iter([(
                        "x-extensible-enum",
                        serde_json::Value::Array(values),
                    )])))
                    .into()
            }
        }

        impl utoipa::ToSchema for $ty {}
    };
}

/// Who made a change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorKind {
    /// An API client with the admin token.
    Token,
    /// A signed-in user, named in the actor's `name`.
    User,
    /// An API client on loopback while no admin token is configured.
    Unauthenticated,
    /// The `goethite` command line, such as `goethite import`.
    Cli,
    /// goethite itself, such as seeding the store on the first start.
    System,
    /// The cluster: this node took a whole configuration from another
    /// member, which is named.
    Replication,
}

/// Who made a change, and from where.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Actor {
    /// What kind of actor.
    pub kind: ActorKind,
    /// The user's sign-in name, when a user made the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// The client's IP address, for API requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// The cluster node the change came from or through, when it was not
    /// made on this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
}

impl Actor {
    /// goethite itself.
    pub fn system() -> Self {
        Self {
            kind: ActorKind::System,
            name: None,
            address: None,
            node: None,
        }
    }

    /// The command line.
    pub fn cli() -> Self {
        Self {
            kind: ActorKind::Cli,
            name: None,
            address: None,
            node: None,
        }
    }

    /// The signed-in user `name`, from `address`.
    pub fn user(name: impl Into<String>, address: Option<String>) -> Self {
        Self {
            kind: ActorKind::User,
            name: Some(name.into()),
            address,
            node: None,
        }
    }

    /// The cluster node `node`, whose configuration was copied.
    pub fn replication(node: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Replication,
            name: None,
            address: None,
            node: Some(node.into()),
        }
    }
}

extensible_enum!(
    ActorKind,
    "Who made a change: `token` (an API client with the admin token), `user` (a signed-in user, \
     named in the actor's `name`), `unauthenticated` (an API client on loopback while no admin \
     token is configured), `cli` (the goethite command line), `system` (goethite itself) or \
     `replication` (a whole configuration taken from another cluster member). More may be added: \
     show unknown values as they are.",
    [Token, User, Unauthenticated, Cli, System, Replication]
);

/// What an audit entry records.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction {
    /// A resource was created.
    Create,
    /// A resource or the settings were changed.
    Update,
    /// A resource was deleted.
    Delete,
    /// The `[filter]` table of the config file was imported.
    Import,
    /// Filtering was paused.
    Pause,
    /// Filtering was resumed.
    Resume,
    /// A list download was started.
    Refresh,
    /// This node took the cluster's whole configuration from another
    /// member.
    Replicate,
    /// This node took the cluster over.
    Promote,
    /// This node left its cluster to join another.
    Demote,
}

extensible_enum!(
    AuditAction,
    "What an audit entry records: `create`, `update` or `delete` (a resource or the settings), \
     `import` (the config file's `[filter]` table), `pause` or `resume` (filtering), `refresh` \
     (a list download), `replicate` (the cluster's whole configuration, taken from another \
     member), `promote` (this node took the cluster over) or `demote` (this node left its \
     cluster to join another). More may be added: show unknown values as they are.",
    [
        Create, Update, Delete, Import, Pause, Resume, Refresh, Replicate, Promote, Demote
    ]
);

/// One entry of the audit log.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct AuditEntry {
    /// Increasing number.
    pub id: u64,
    /// When.
    pub time: Timestamp,
    /// Who.
    pub actor: Actor,
    /// What.
    pub action: AuditAction,
    /// The kind of resource, if one changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// The resource's ID, if one changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// The resource before the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub before: Option<serde_json::Value>,
    /// The resource after the change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schema(value_type = Option<Object>)]
    pub after: Option<serde_json::Value>,
    /// More about the change, for people.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The resource does not exist.
    #[error("there is no {kind} {id:?}")]
    NotFound {
        /// The kind.
        kind: &'static str,
        /// The ID.
        id: String,
    },
    /// The change would make the configuration invalid.
    #[error("invalid configuration: {0}")]
    Invalid(ValidationError),
    /// The change conflicts with other resources, such as deleting a list a
    /// group still uses.
    #[error("conflict: {0}")]
    Conflict(String),
    /// The resource changed since the client read it.
    #[error("{kind} {id:?} is at revision {actual}, not {expected}")]
    Revision {
        /// The kind.
        kind: &'static str,
        /// The ID.
        id: String,
        /// The revision the client expected.
        expected: u64,
        /// The current revision.
        actual: u64,
    },
    /// Another goethite process has the database open.
    #[error("the store {0} is in use by another goethite process; stop it first")]
    Locked(PathBuf),
    /// The database failed.
    #[error("store database: {0}")]
    Database(#[from] redb::Error),
    /// A stored row could not be read back.
    #[error("cannot read stored {what}: {source}")]
    Corrupt {
        /// Which row.
        what: String,
        /// The decoding error.
        #[source]
        source: serde_json::Error,
    },
    /// A value could not be encoded.
    #[error("cannot encode: {0}")]
    Encode(#[source] serde_json::Error),
    /// The cluster cannot take configuration changes now, such as while it
    /// has no leader.
    #[error("{0}")]
    Unavailable(String),
    /// A change from the cluster's log that this goethite version cannot
    /// apply.
    #[error(
        "this node cannot apply the cluster's change ({0}): run the same goethite version on every node"
    )]
    Incompatible(String),
    /// A replicated configuration comes from a store with another schema.
    #[error(
        "the configuration comes from store schema {found}, this node has {expected}: run the same goethite version on every node"
    )]
    Schema {
        /// This node's schema.
        expected: String,
        /// The sender's schema.
        found: String,
    },
}

impl From<ValidationError> for StoreError {
    fn from(err: ValidationError) -> Self {
        if err.conflict {
            Self::Conflict(err.to_string())
        } else {
            Self::Invalid(err)
        }
    }
}

macro_rules! db_error {
    ($($ty:ty),*) => {
        $(impl From<$ty> for StoreError {
            fn from(err: $ty) -> Self {
                Self::Database(err.into())
            }
        })*
    };
}
db_error!(
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

/// One row a configuration change writes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Row {
    /// Creates or replaces a resource.
    Put { resource: Resource },
    /// Deletes a resource of `kind` (such as `list`).
    Delete { kind: String, id: String },
    /// Replaces the settings.
    Settings { settings: Settings },
}

/// An audit entry still without its number, time and actor.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct Pending {
    action: AuditAction,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    resource: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    before: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    after: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

/// What a transaction writes.
#[derive(Default)]
struct Batch {
    rows: Vec<Row>,
    audit: Vec<Pending>,
}

impl Batch {
    fn put<K: Kind>(&mut self, resource: &K) {
        self.rows.push(Row::Put {
            resource: resource.clone().into_resource(),
        });
    }

    fn delete<K: Kind>(&mut self, id: &str) {
        self.rows.push(Row::Delete {
            kind: K::NAME.to_owned(),
            id: id.to_owned(),
        });
    }

    fn settings(&mut self, settings: &Settings) {
        self.rows.push(Row::Settings {
            settings: settings.clone(),
        });
    }

    fn record<K: Kind>(&mut self, action: AuditAction, before: Option<&K>, after: Option<&K>) {
        let id = after.or(before).map(|r| r.id().to_owned());
        let shown = |resource: &K| {
            let mut value = serde_json::to_value(resource).ok()?;
            if K::NAME == User::NAME {
                redact_user(&mut value);
            }
            Some(value)
        };
        self.audit.push(Pending {
            action,
            kind: Some(K::NAME.to_owned()),
            resource: id,
            before: before.and_then(shown),
            after: after.and_then(shown),
            detail: None,
        });
    }
}

/// A configuration change, prepared on one node and applied in the same
/// order on every node of a cluster: the rows it writes and its audit
/// entries, with when and by whom. It applies only to the configuration
/// version it was prepared against, so every node either applies it or
/// refuses it, the same way.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    base: ConfigVersion,
    time: Timestamp,
    actor: Actor,
    rows: Vec<Row>,
    audit: Vec<Pending>,
}

/// One node's whole configuration, made the cluster's: when a cluster
/// starts on that node, or the node takes the cluster over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Seed {
    node: String,
    time: Timestamp,
    export: ConfigExport,
}

/// An entry of the cluster's log, as the store applies it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Command {
    /// A configuration change.
    Change(Change),
    /// A whole configuration.
    Seed(Seed),
}

/// What applying a [`Command`] did.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum Applied {
    /// Nothing: a log entry without a command, such as a membership change.
    #[default]
    Nothing,
    /// The configuration is at `version` now.
    Done {
        /// The new version.
        version: ConfigVersion,
    },
    /// The change was refused, on every node alike: the configuration
    /// changed after it was prepared.
    Refused {
        /// Why, for people.
        reason: String,
    },
}

/// Puts configuration changes through a cluster's log instead of writing
/// them at once: the store hands each change to it and the cluster applies
/// it on every node, through [`Store::apply`].
pub trait Replicator: Send + Sync {
    /// Proposes `command` and returns once this node applied it. Called on
    /// a blocking thread, with the store's writer lock held.
    ///
    /// # Errors
    ///
    /// [`StoreError::Unavailable`] if the cluster cannot take changes now.
    fn replicate(&self, command: Command) -> Result<Applied, StoreError>;
}

/// What an import changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ImportSummary {
    /// Lists added.
    pub lists_added: usize,
    /// Lists changed.
    pub lists_updated: usize,
    /// Lists removed, along with the groups' references to them.
    pub lists_removed: usize,
    /// Rules added.
    pub rules_added: usize,
    /// Rules removed.
    pub rules_removed: usize,
    /// Whether the settings changed.
    pub settings_changed: bool,
}

/// The `[filter]` table of a config file, to import.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Import {
    /// The settings.
    pub settings: SettingsSpec,
    /// The lists; imported lists are added to the default group.
    pub lists: Vec<ListSpec>,
    /// The rules.
    pub rules: Vec<RuleSpec>,
}

/// Which configuration a store holds.
///
/// `epoch` names a line of history: it is chosen at random when a store is
/// created, and again when a node's whole configuration becomes a
/// cluster's ([`Store::seed`]). `version` counts the changes along it.
/// Every member of a cluster goes through the same versions, so a member
/// that forwarded a change waits until it holds the version the leader
/// reported.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
pub struct ConfigVersion {
    /// The line of history: a random number below 2^53, so it is exact in
    /// JSON.
    pub epoch: u64,
    /// Changes so far along it.
    pub version: u64,
}

impl ConfigVersion {
    /// The next version in the same epoch.
    fn next(self) -> Self {
        Self {
            epoch: self.epoch,
            version: self.version.saturating_add(1),
        }
    }

    /// Whether a configuration at `self` should replace one at `current`.
    pub fn replaces(self, current: Self) -> bool {
        self.epoch != current.epoch || self.version > current.version
    }
}

/// A random epoch below 2^53.
fn new_epoch() -> u64 {
    rand::random::<u64>() >> 11
}

/// The whole configuration with its version: a cluster's seed, or a
/// snapshot.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigExport {
    /// The store schema it was taken from; a store with another schema
    /// refuses it.
    pub schema: String,
    /// Its version.
    pub version: ConfigVersion,
    /// The configuration.
    pub config: ConfigSnapshot,
}

/// What applying a replicated configuration changed.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct ReplaceSummary {
    /// Resources added.
    pub added: usize,
    /// Resources changed.
    pub changed: usize,
    /// Resources removed.
    pub removed: usize,
    /// Whether the settings changed.
    pub settings_changed: bool,
    /// Whether lists changed: they may need downloading.
    pub lists_changed: bool,
    /// Whether lists or custom rules changed: the filter must be rebuilt.
    pub filter_changed: bool,
}

/// The configuration in memory, with its version.
#[derive(Clone)]
struct Current {
    config: Arc<ConfigSnapshot>,
    version: ConfigVersion,
    /// What the cluster's log applied to it, if this node is in a cluster.
    applied: Option<Arc<str>>,
}

/// The configuration and audit log, persisted.
pub struct Store {
    path: PathBuf,
    db: Database,
    current: RwLock<Current>,
    changes: watch::Sender<ConfigVersion>,
    /// Serializes changes made on this node, from preparing one to
    /// applying it. Applying a change from the cluster's log never takes
    /// it: the leader holds it while its own change goes through the log.
    writer: Mutex<()>,
    replicator: RwLock<Option<Arc<dyn Replicator>>>,
}

// The path only: printing the configuration would take its lock and dump
// every list, rule and client.
impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens the database at `path`, creating it if needed.
    ///
    /// # Errors
    ///
    /// [`StoreError::Locked`] if another process has it open, or a database
    /// or decoding error.
    pub fn open(path: &Path) -> Result<Self, StoreError> {
        create_private(path)?;
        let db = Database::create(path).map_err(|err| match err {
            DatabaseError::DatabaseAlreadyOpen => StoreError::Locked(path.to_path_buf()),
            other => StoreError::Database(other.into()),
        })?;
        Self::init(path.to_path_buf(), db)
    }

    /// A store that lives in memory, for when the database file cannot be
    /// used: everything works, and everything is lost when goethite stops.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn open_in_memory() -> Result<Self, StoreError> {
        let db = redb::Builder::new()
            .create_with_backend(redb::backends::InMemoryBackend::new())
            .map_err(|err| StoreError::Database(err.into()))?;
        Self::init(PathBuf::from("(in memory)"), db)
    }

    /// Creates the tables the database lacks (all of them for a new one),
    /// records the schema version and loads the configuration.
    fn init(path: PathBuf, db: Database) -> Result<Self, StoreError> {
        let now = Timestamp::now();
        let tx = db.begin_write()?;
        let version;
        let applied;
        {
            let mut meta = tx.open_table(META)?;
            meta.insert("schema", SCHEMA_VERSION)?;
            let stored_epoch = meta
                .get(EPOCH_KEY)?
                .and_then(|value| value.value().parse::<u64>().ok());
            let epoch = if let Some(epoch) = stored_epoch {
                epoch
            } else {
                let epoch = new_epoch();
                meta.insert(EPOCH_KEY, epoch.to_string().as_str())?;
                epoch
            };
            let counted = meta
                .get(VERSION_KEY)?
                .and_then(|value| value.value().parse::<u64>().ok())
                .unwrap_or(0);
            version = ConfigVersion {
                epoch,
                version: counted,
            };
            applied = meta.get(APPLIED_KEY)?.map(|value| Arc::from(value.value()));
            let mut settings = tx.open_table(SETTINGS)?;
            if settings.get("settings")?.is_none() {
                let initial = ConfigSnapshot::empty(now).settings;
                let bytes = serde_json::to_vec(&initial).map_err(StoreError::Encode)?;
                settings.insert("settings", bytes.as_slice())?;
            }
            let mut groups = tx.open_table(Group::table())?;
            if groups.get(DEFAULT_GROUP)?.is_none() {
                let bytes =
                    serde_json::to_vec(&default_group_resource(now)).map_err(StoreError::Encode)?;
                groups.insert(DEFAULT_GROUP, bytes.as_slice())?;
            }
            for table in [
                List::table(),
                Rule::table(),
                Client::table(),
                Schedule::table(),
                Record::table(),
                User::table(),
            ] {
                tx.open_table(table)?;
            }
            tx.open_table(AUDIT)?;
            tx.open_table(log::LOG)?;
        }
        tx.commit()?;
        let config = load(&db)?;
        if let Err(err) = config.validate() {
            warn!(%err, "the stored configuration has a problem; fix it through the API");
        }
        let (changes, _) = watch::channel(version);
        Ok(Self {
            path,
            db,
            current: RwLock::new(Current {
                config: Arc::new(config),
                version,
                applied,
            }),
            changes,
            writer: Mutex::new(()),
            replicator: RwLock::new(None),
        })
    }

    /// Where the database lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The database, for the query log and statistics tables.
    pub(crate) fn database(&self) -> &Database {
        &self.db
    }

    /// The current configuration.
    pub fn config(&self) -> Arc<ConfigSnapshot> {
        self.current().config
    }

    /// The current configuration's version.
    pub fn version(&self) -> ConfigVersion {
        self.current().version
    }

    /// The current configuration and its version, as one.
    pub fn export(&self) -> ConfigExport {
        let current = self.current();
        ConfigExport {
            schema: SCHEMA_VERSION.to_owned(),
            version: current.version,
            config: (*current.config).clone(),
        }
    }

    /// A receiver that sees every new configuration version.
    pub fn subscribe(&self) -> watch::Receiver<ConfigVersion> {
        self.changes.subscribe()
    }

    fn current(&self) -> Current {
        self.current
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// The resource of kind `K` with `id`.
    pub fn get<K: Kind>(&self, id: &str) -> Option<K> {
        K::all(&self.config())
            .iter()
            .find(|r| r.id() == id)
            .cloned()
    }

    /// The user with the sign-in name `name` (ignoring case), if there is
    /// one.
    pub fn user_by_name(&self, name: &str) -> Option<User> {
        self.config()
            .users
            .iter()
            .find(|user| user.spec.name.eq_ignore_ascii_case(name))
            .cloned()
    }

    /// Whether any user exists.
    pub fn users_exist(&self) -> bool {
        !self.config().users.is_empty()
    }

    /// Creates a resource.
    ///
    /// # Errors
    ///
    /// [`StoreError::Invalid`] or [`StoreError::Conflict`] if the result
    /// would be invalid, or a database error.
    pub fn create<K: Kind>(&self, spec: K::Spec, actor: &Actor) -> Result<K, StoreError> {
        let mut created = None;
        self.transact(actor, |config, now, batch| {
            let resource = K::new(new_id(K::PREFIX), 1, now, now, spec);
            batch.put(&resource);
            batch.record(AuditAction::Create, None, Some(&resource));
            K::all_mut(config).push(resource.clone());
            created = Some(resource);
            Ok(())
        })?;
        created.ok_or_else(|| StoreError::Conflict("nothing was created".into()))
    }

    /// Replaces a resource's spec. With `expected`, fails unless the
    /// resource is at that revision.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`], [`StoreError::Revision`], an invalid result
    /// or a database error.
    pub fn update<K: Kind>(
        &self,
        id: &str,
        spec: K::Spec,
        expected: Option<u64>,
        actor: &Actor,
    ) -> Result<K, StoreError> {
        let mut updated = None;
        self.transact(actor, |config, now, batch| {
            let all = K::all_mut(config);
            let slot = all
                .iter_mut()
                .find(|r| r.id() == id)
                .ok_or_else(|| not_found::<K>(id))?;
            check_revision::<K>(slot, expected)?;
            if *slot.spec() == spec {
                updated = Some(slot.clone());
                return Ok(());
            }
            let before = slot.clone();
            let after = K::new(
                before.id().to_owned(),
                before.revision().saturating_add(1),
                before.created_at(),
                now,
                spec,
            );
            batch.put(&after);
            batch.record(AuditAction::Update, Some(&before), Some(&after));
            *slot = after.clone();
            updated = Some(after);
            Ok(())
        })?;
        updated.ok_or_else(|| not_found::<K>(id))
    }

    /// Deletes a resource. With `expected`, fails unless it is at that
    /// revision. The default group cannot be deleted.
    ///
    /// # Errors
    ///
    /// [`StoreError::NotFound`], [`StoreError::Revision`],
    /// [`StoreError::Conflict`] if something still refers to it, or a
    /// database error.
    pub fn delete<K: Kind>(
        &self,
        id: &str,
        expected: Option<u64>,
        actor: &Actor,
    ) -> Result<(), StoreError> {
        if K::NAME == "group" && id == DEFAULT_GROUP {
            return Err(StoreError::Conflict(
                "the default group cannot be deleted".into(),
            ));
        }
        self.transact(actor, |config, _, batch| {
            let all = K::all_mut(config);
            let index = all
                .iter()
                .position(|r| r.id() == id)
                .ok_or_else(|| not_found::<K>(id))?;
            let before = all.remove(index);
            check_revision::<K>(&before, expected)?;
            batch.delete::<K>(id);
            batch.record(AuditAction::Delete, Some(&before), None);
            Ok(())
        })
        .map(drop)
    }

    /// Replaces the settings.
    ///
    /// # Errors
    ///
    /// [`StoreError::Revision`], invalid settings or a database error.
    pub fn update_settings(
        &self,
        spec: SettingsSpec,
        expected: Option<u64>,
        actor: &Actor,
    ) -> Result<Settings, StoreError> {
        let config = self.transact(actor, |config, now, batch| {
            let before = config.settings.clone();
            if let Some(expected) = expected
                && expected != before.revision
            {
                return Err(StoreError::Revision {
                    kind: "settings",
                    id: "settings".into(),
                    expected,
                    actual: before.revision,
                });
            }
            if before.spec == spec {
                return Ok(());
            }
            let after = Settings {
                revision: before.revision.saturating_add(1),
                updated_at: now,
                spec,
            };
            batch.settings(&after);
            batch.audit.push(Pending {
                action: AuditAction::Update,
                kind: Some("settings".into()),
                resource: None,
                before: serde_json::to_value(&before).ok(),
                after: serde_json::to_value(&after).ok(),
                detail: None,
            });
            config.settings = after;
            Ok(())
        })?;
        Ok(config.settings.clone())
    }

    /// Makes the lists and rules managed by the config file, and the
    /// settings, match `import`. Lists and rules from the API stay, and so
    /// do the access lists, which the config file does not hold. New lists
    /// are added to the default group; removed ones are removed from every
    /// group.
    ///
    /// # Errors
    ///
    /// An invalid result or a database error.
    pub fn import(&self, import: Import, actor: &Actor) -> Result<ImportSummary, StoreError> {
        let mut summary = ImportSummary::default();
        self.transact(actor, |config, now, batch| {
            import_lists(config, now, batch, import.lists, &mut summary);
            import_rules(config, now, batch, import.rules, &mut summary);
            let spec = SettingsSpec {
                access: config.settings.spec.access.clone(),
                ..import.settings
            };
            if config.settings.spec != spec {
                let before = config.settings.clone();
                config.settings = Settings {
                    revision: before.revision.saturating_add(1),
                    updated_at: now,
                    spec,
                };
                batch.settings(&config.settings);
                summary.settings_changed = true;
            }
            let settings = if summary.settings_changed {
                "; settings changed"
            } else {
                ""
            };
            batch.audit.push(Pending {
                action: AuditAction::Import,
                kind: None,
                resource: None,
                before: None,
                after: None,
                detail: Some(format!(
                    "{} lists added, {} updated, {} removed; {} rules added, {} removed{settings}",
                    summary.lists_added,
                    summary.lists_updated,
                    summary.lists_removed,
                    summary.rules_added,
                    summary.rules_removed,
                )),
            });
            Ok(())
        })?;
        Ok(summary)
    }

    /// A command that makes this node's configuration, `node`'s, the
    /// cluster's, in a new epoch: for the node a cluster starts on, or one
    /// that takes a cluster over.
    pub fn seed(&self, node: &str) -> Command {
        let current = self.current();
        let mut epoch = new_epoch();
        while epoch == current.version.epoch {
            epoch = new_epoch();
        }
        Command::Seed(Seed {
            node: node.to_owned(),
            time: Timestamp::now(),
            export: ConfigExport {
                schema: SCHEMA_VERSION.to_owned(),
                version: ConfigVersion {
                    epoch,
                    version: current.version.version.saturating_add(1),
                },
                config: (*current.config).clone(),
            },
        })
    }

    /// Applies an entry of the cluster's log: its `command`, if it has
    /// one, and `applied`, the cluster's own note of the entry, kept in the
    /// same transaction ([`Store::snapshot`]). Every node applies the same
    /// entries in the same order, and so comes to the same configuration;
    /// a change that no longer fits is refused on every node alike.
    ///
    /// # Errors
    ///
    /// A database error, or [`StoreError::Schema`] or
    /// [`StoreError::Incompatible`] for a command this goethite version
    /// cannot apply: this node cannot follow the cluster then.
    pub fn apply(&self, command: Option<Command>, applied: &str) -> Result<Applied, StoreError> {
        match command {
            None => {
                self.commit_applied(applied)?;
                Ok(Applied::Nothing)
            }
            Some(Command::Change(change)) => self.apply_change(change, Some(applied)),
            Some(Command::Seed(seed)) => {
                let version = seed.export.version;
                let actor = Actor::replication(seed.node.as_str());
                let summary = self.install(seed.export, &actor, seed.time, applied)?;
                info!(
                    node = %seed.node,
                    added = summary.added,
                    changed = summary.changed,
                    removed = summary.removed,
                    "the configuration of {} is the cluster's", seed.node
                );
                Ok(Applied::Done { version })
            }
        }
    }

    /// Makes a snapshot of the cluster's configuration, taken on `node`,
    /// this store's configuration, with `applied`, the cluster's note of
    /// what it includes. Resources keep their IDs, revisions and times.
    ///
    /// # Errors
    ///
    /// [`StoreError::Schema`] for a configuration from another store schema,
    /// or a database error.
    pub fn install_snapshot(
        &self,
        export: ConfigExport,
        node: &str,
        applied: &str,
    ) -> Result<ReplaceSummary, StoreError> {
        self.install(export, &Actor::replication(node), Timestamp::now(), applied)
    }

    /// The configuration and the cluster's note of what it includes, as
    /// one: for a snapshot of the cluster's state.
    pub fn snapshot(&self) -> (ConfigExport, Option<String>) {
        let current = self.current();
        (
            ConfigExport {
                schema: SCHEMA_VERSION.to_owned(),
                version: current.version,
                config: (*current.config).clone(),
            },
            current.applied.map(|applied| applied.to_string()),
        )
    }

    /// The cluster's note of the last entry applied to the configuration,
    /// if this node is in a cluster.
    pub fn applied(&self) -> Option<String> {
        self.current().applied.map(|applied| applied.to_string())
    }

    /// Hands configuration changes made on this node to `replicator`
    /// instead of writing them at once: this node is in a cluster.
    pub fn set_replicator(&self, replicator: Arc<dyn Replicator>) {
        *self
            .replicator
            .write()
            .unwrap_or_else(PoisonError::into_inner) = Some(replicator);
    }

    /// Writes changes at once again: the cluster stopped. The replicator
    /// usually refers back to the store, so this also breaks that cycle.
    pub fn clear_replicator(&self) {
        *self
            .replicator
            .write()
            .unwrap_or_else(PoisonError::into_inner) = None;
    }

    fn replicator(&self) -> Option<Arc<dyn Replicator>> {
        self.replicator
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Makes `export` this store's configuration, from `actor`, whatever
    /// it holds now: only the differences are written.
    fn install(
        &self,
        export: ConfigExport,
        actor: &Actor,
        time: Timestamp,
        applied: &str,
    ) -> Result<ReplaceSummary, StoreError> {
        if export.schema != SCHEMA_VERSION {
            return Err(StoreError::Schema {
                expected: SCHEMA_VERSION.to_owned(),
                found: export.schema,
            });
        }
        if let Err(err) = export.config.validate() {
            // Taken anyway: every node must hold the same configuration.
            warn!(%err, "the cluster's configuration has a problem; fix it through the API");
        }
        let current = self.current();
        let old = &current.config;
        let new = &export.config;
        let mut batch = Batch::default();
        let mut summary = ReplaceSummary::default();
        replace_kind::<List>(old, new, &mut batch, &mut summary);
        summary.lists_changed = !batch.rows.is_empty();
        replace_kind::<Rule>(old, new, &mut batch, &mut summary);
        summary.filter_changed = !batch.rows.is_empty();
        replace_kind::<Group>(old, new, &mut batch, &mut summary);
        replace_kind::<Client>(old, new, &mut batch, &mut summary);
        replace_kind::<Schedule>(old, new, &mut batch, &mut summary);
        replace_kind::<Record>(old, new, &mut batch, &mut summary);
        replace_kind::<User>(old, new, &mut batch, &mut summary);
        if old.settings != new.settings {
            batch.settings(&new.settings);
            summary.settings_changed = true;
        }
        let settings = if summary.settings_changed {
            "; settings changed"
        } else {
            ""
        };
        batch.audit.push(Pending {
            action: AuditAction::Replicate,
            kind: None,
            resource: None,
            before: serde_json::to_value(current.version).ok(),
            after: serde_json::to_value(export.version).ok(),
            detail: Some(format!(
                "{} added, {} changed, {} removed{settings}",
                summary.added, summary.changed, summary.removed
            )),
        });
        self.commit(Commit {
            next: export.config,
            rows: batch.rows,
            audit: batch.audit,
            actor,
            time,
            version: export.version,
            applied: Some(applied),
        })?;
        Ok(summary)
    }

    /// Applies `change` to the configuration it was prepared against. On
    /// this node alone (`applied` is `None`), the caller holds the writer
    /// lock and validated the change. From the cluster's log, a change
    /// that no longer fits is refused, and `applied` kept either way.
    fn apply_change(&self, change: Change, applied: Option<&str>) -> Result<Applied, StoreError> {
        let current = self.current();
        let refuse = |reason: String| -> Result<Applied, StoreError> {
            if let Some(applied) = applied {
                self.commit_applied(applied)?;
            }
            Ok(Applied::Refused { reason })
        };
        if change.base != current.version {
            return refuse(
                "the configuration changed while this change was being made; make it again".into(),
            );
        }
        let mut next = (*current.config).clone();
        for row in &change.rows {
            apply_row(&mut next, row)?;
        }
        if applied.is_some()
            && let Err(err) = next.validate()
        {
            return refuse(err.to_string());
        }
        let version = current.version.next();
        self.commit(Commit {
            next,
            rows: change.rows,
            audit: change.audit,
            actor: &change.actor,
            time: change.time,
            version,
            applied,
        })?;
        Ok(Applied::Done { version })
    }

    /// Records an action that is not a configuration change, such as
    /// pausing filtering.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn record(
        &self,
        actor: &Actor,
        action: AuditAction,
        detail: Option<String>,
    ) -> Result<(), StoreError> {
        self.transact(actor, |_, _, batch| {
            batch.audit.push(Pending {
                action,
                kind: None,
                resource: None,
                before: None,
                after: None,
                detail,
            });
            Ok(())
        })
        .map(drop)
    }

    /// Up to `limit` audit entries before entry `before` (or the newest),
    /// newest first.
    ///
    /// # Errors
    ///
    /// A database or decoding error.
    pub fn audit(&self, before: Option<u64>, limit: usize) -> Result<Vec<AuditEntry>, StoreError> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(AUDIT)?;
        let range = table.range(..before.unwrap_or(u64::MAX))?;
        let mut entries = Vec::new();
        for row in range.rev().take(limit) {
            let (key, value) = row?;
            let entry =
                serde_json::from_slice(value.value()).map_err(|source| StoreError::Corrupt {
                    what: format!("audit entry {}", key.value()),
                    source,
                })?;
            entries.push(entry);
        }
        Ok(entries)
    }

    /// A value from the `meta` table.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn meta(&self, key: &str) -> Result<Option<String>, StoreError> {
        let tx = self.db.begin_read()?;
        let table = tx.open_table(META)?;
        Ok(table.get(key)?.map(|value| value.value().to_owned()))
    }

    /// Sets a value in the `meta` table.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn set_meta(&self, key: &str, value: &str) -> Result<(), StoreError> {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let tx = self.db.begin_write()?;
        tx.open_table(META)?.insert(key, value)?;
        tx.commit()?;
        Ok(())
    }

    /// Applies `change` to a copy of the configuration and validates it.
    /// The rows and audit entries it fills in are then written in one
    /// transaction, or, in a cluster, go through the cluster's log first.
    /// Audit entries alone are this node's: they are written at once.
    fn transact(
        &self,
        actor: &Actor,
        change: impl FnOnce(&mut ConfigSnapshot, Timestamp, &mut Batch) -> Result<(), StoreError>,
    ) -> Result<Arc<ConfigSnapshot>, StoreError> {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.current();
        let mut scratch = (*current.config).clone();
        let now = Timestamp::now();
        let mut batch = Batch::default();
        change(&mut scratch, now, &mut batch)?;
        if batch.rows.is_empty() {
            if !batch.audit.is_empty() {
                self.commit_audit(batch.audit, actor, now)?;
            }
            return Ok(current.config);
        }
        scratch.validate()?;
        let change = Change {
            base: current.version,
            time: now,
            actor: actor.clone(),
            rows: batch.rows,
            audit: batch.audit,
        };
        let applied = match self.replicator() {
            Some(replicator) => replicator.replicate(Command::Change(change))?,
            None => self.apply_change(change, None)?,
        };
        match applied {
            Applied::Done { .. } => Ok(self.config()),
            Applied::Refused { reason } => Err(StoreError::Conflict(reason)),
            Applied::Nothing => Err(StoreError::Unavailable(
                "the cluster did not apply the change".into(),
            )),
        }
    }

    /// Writes a change's rows, audit entries and version in one
    /// transaction, with the cluster's note of the log entry it came from,
    /// then makes its configuration the current one.
    fn commit(&self, commit: Commit<'_>) -> Result<Arc<ConfigSnapshot>, StoreError> {
        let tx = self.db.begin_write()?;
        {
            let mut meta = tx.open_table(META)?;
            meta.insert(EPOCH_KEY, commit.version.epoch.to_string().as_str())?;
            meta.insert(VERSION_KEY, commit.version.version.to_string().as_str())?;
            if let Some(applied) = commit.applied {
                meta.insert(APPLIED_KEY, applied)?;
            }
        }
        for row in &commit.rows {
            write_row(&tx, row)?;
        }
        write_audit(&tx, commit.audit, commit.actor, commit.time)?;
        tx.commit()?;
        let next = Arc::new(commit.next);
        {
            let mut current = self.current.write().unwrap_or_else(PoisonError::into_inner);
            let applied = commit
                .applied
                .map(Arc::from)
                .or_else(|| current.applied.clone());
            *current = Current {
                config: Arc::clone(&next),
                version: commit.version,
                applied,
            };
        }
        self.changes.send_replace(commit.version);
        Ok(next)
    }

    /// Keeps the cluster's note of a log entry that changed nothing.
    fn commit_applied(&self, applied: &str) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        tx.open_table(META)?.insert(APPLIED_KEY, applied)?;
        tx.commit()?;
        self.current
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .applied = Some(Arc::from(applied));
        Ok(())
    }

    /// Writes audit entries that change no configuration.
    fn commit_audit(
        &self,
        audit: Vec<Pending>,
        actor: &Actor,
        time: Timestamp,
    ) -> Result<(), StoreError> {
        let tx = self.db.begin_write()?;
        write_audit(&tx, audit, actor, time)?;
        tx.commit()?;
        Ok(())
    }
}

/// A change, ready to write.
struct Commit<'a> {
    next: ConfigSnapshot,
    rows: Vec<Row>,
    audit: Vec<Pending>,
    actor: &'a Actor,
    time: Timestamp,
    version: ConfigVersion,
    applied: Option<&'a str>,
}

/// Applies `row` to `config` in memory.
fn apply_row(config: &mut ConfigSnapshot, row: &Row) -> Result<(), StoreError> {
    fn upsert<K: Kind>(config: &mut ConfigSnapshot, resource: &K) {
        let all = K::all_mut(config);
        match all.iter_mut().find(|r| r.id() == resource.id()) {
            Some(slot) => *slot = resource.clone(),
            None => all.push(resource.clone()),
        }
    }
    fn remove<K: Kind>(config: &mut ConfigSnapshot, id: &str) {
        K::all_mut(config).retain(|r| r.id() != id);
    }
    match row {
        Row::Put { resource } => match resource {
            Resource::List(r) => upsert(config, r),
            Resource::Rule(r) => upsert(config, r),
            Resource::Group(r) => upsert(config, r),
            Resource::Client(r) => upsert(config, r),
            Resource::Record(r) => upsert(config, r),
            Resource::Schedule(r) => upsert(config, r),
            Resource::User(r) => upsert(config, r),
        },
        Row::Delete { kind, id } => match kind.as_str() {
            List::NAME => remove::<List>(config, id),
            Rule::NAME => remove::<Rule>(config, id),
            Group::NAME => remove::<Group>(config, id),
            Client::NAME => remove::<Client>(config, id),
            Record::NAME => remove::<Record>(config, id),
            Schedule::NAME => remove::<Schedule>(config, id),
            User::NAME => remove::<User>(config, id),
            other => return Err(unknown_kind(other)),
        },
        Row::Settings { settings } => config.settings = settings.clone(),
    }
    Ok(())
}

/// Writes `row` to its table.
fn write_row(tx: &redb::WriteTransaction, row: &Row) -> Result<(), StoreError> {
    fn put<K: Kind>(tx: &redb::WriteTransaction, resource: &K) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(resource).map_err(StoreError::Encode)?;
        tx.open_table(K::table())?
            .insert(resource.id(), bytes.as_slice())?;
        Ok(())
    }
    fn remove<K: Kind>(tx: &redb::WriteTransaction, id: &str) -> Result<(), StoreError> {
        tx.open_table(K::table())?.remove(id)?;
        Ok(())
    }
    match row {
        Row::Put { resource } => match resource {
            Resource::List(r) => put(tx, r),
            Resource::Rule(r) => put(tx, r),
            Resource::Group(r) => put(tx, r),
            Resource::Client(r) => put(tx, r),
            Resource::Record(r) => put(tx, r),
            Resource::Schedule(r) => put(tx, r),
            Resource::User(r) => put(tx, r),
        },
        Row::Delete { kind, id } => match kind.as_str() {
            List::NAME => remove::<List>(tx, id),
            Rule::NAME => remove::<Rule>(tx, id),
            Group::NAME => remove::<Group>(tx, id),
            Client::NAME => remove::<Client>(tx, id),
            Record::NAME => remove::<Record>(tx, id),
            Schedule::NAME => remove::<Schedule>(tx, id),
            User::NAME => remove::<User>(tx, id),
            other => Err(unknown_kind(other)),
        },
        Row::Settings { settings } => {
            let bytes = serde_json::to_vec(settings).map_err(StoreError::Encode)?;
            tx.open_table(SETTINGS)?
                .insert("settings", bytes.as_slice())?;
            Ok(())
        }
    }
}

fn unknown_kind(kind: &str) -> StoreError {
    StoreError::Incompatible(format!("a change to an unknown kind of resource, {kind:?}"))
}

/// Leaves the secrets out of a user's audit entry: password hash, TOTP
/// secret, recovery hashes and the pending reset's hash.
fn redact_user(value: &mut serde_json::Value) {
    let Some(spec) = value
        .get_mut("spec")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    for secret in ["password_hash", "recovery", "reset"] {
        spec.remove(secret);
    }
    if let Some(totp) = spec.get_mut("totp")
        && let Some(totp) = totp.as_object_mut()
    {
        totp.remove("secret");
    }
}

/// Writes `audit` as numbered entries, dropping the oldest beyond
/// [`MAX_AUDIT_ENTRIES`].
fn write_audit(
    tx: &redb::WriteTransaction,
    audit: Vec<Pending>,
    actor: &Actor,
    time: Timestamp,
) -> Result<(), StoreError> {
    let mut table = tx.open_table(AUDIT)?;
    let mut next_id = table
        .last()?
        .map_or(1, |(key, _)| key.value().saturating_add(1));
    for pending in audit {
        let entry = AuditEntry {
            id: next_id,
            time,
            actor: actor.clone(),
            action: pending.action,
            kind: pending.kind,
            resource: pending.resource,
            before: pending.before,
            after: pending.after,
            detail: pending.detail,
        };
        let bytes = serde_json::to_vec(&entry).map_err(StoreError::Encode)?;
        table.insert(next_id, bytes.as_slice())?;
        next_id = next_id.saturating_add(1);
    }
    let newest = next_id.saturating_sub(1);
    if table.len()? > MAX_AUDIT_ENTRIES {
        let keep_from = newest.saturating_sub(MAX_AUDIT_ENTRIES).saturating_add(1);
        table.retain_in(..keep_from, |_, _| false)?;
    }
    Ok(())
}

/// Writes the resources of kind `K` in which `new` differs from `old`.
fn replace_kind<K: Kind + PartialEq>(
    old: &ConfigSnapshot,
    new: &ConfigSnapshot,
    batch: &mut Batch,
    summary: &mut ReplaceSummary,
) {
    let before: HashMap<&str, &K> = K::all(old).iter().map(|r| (r.id(), r)).collect();
    let after: HashSet<&str> = K::all(new).iter().map(Kind::id).collect();
    for resource in K::all(new) {
        match before.get(resource.id()) {
            None => {
                batch.put(resource);
                summary.added = summary.added.saturating_add(1);
            }
            Some(existing) if *existing != resource => {
                batch.put(resource);
                summary.changed = summary.changed.saturating_add(1);
            }
            Some(_) => {}
        }
    }
    for id in before.keys().filter(|id| !after.contains(*id)) {
        batch.delete::<K>(id);
        summary.removed = summary.removed.saturating_add(1);
    }
}

/// Makes the config-file lists match `lists`, by a stable ID derived from
/// each list's source.
fn import_lists(
    config: &mut ConfigSnapshot,
    now: Timestamp,
    batch: &mut Batch,
    lists: Vec<ListSpec>,
    summary: &mut ImportSummary,
) {
    let mut wanted = Vec::new();
    for mut spec in lists {
        spec.managed_by = ManagedBy::ConfigFile;
        let source = spec
            .url
            .clone()
            .or_else(|| spec.path.clone())
            .unwrap_or_default();
        wanted.push((stable_id("li_cfg", &source), spec));
    }
    let wanted_ids: HashSet<String> = wanted.iter().map(|(id, _)| id.clone()).collect();
    let removed: Vec<List> = config
        .lists
        .iter()
        .filter(|l| l.spec.managed_by == ManagedBy::ConfigFile && !wanted_ids.contains(&l.id))
        .cloned()
        .collect();
    for list in &removed {
        batch.delete::<List>(&list.id);
        batch.record(AuditAction::Delete, Some(list), None);
        summary.lists_removed = summary.lists_removed.saturating_add(1);
    }
    config
        .lists
        .retain(|l| !removed.iter().any(|r| r.id == l.id));
    for group in &mut config.groups {
        let before = group.clone();
        group
            .spec
            .lists
            .retain(|entry| !removed.iter().any(|r| r.id == entry.list));
        if *group != before {
            group.revision = group.revision.saturating_add(1);
            group.updated_at = now;
            batch.put(group);
            batch.record(AuditAction::Update, Some(&before), Some(group));
        }
    }
    for (id, spec) in wanted {
        if let Some(existing) = config.lists.iter_mut().find(|l| l.id == id) {
            if existing.spec != spec {
                let before = existing.clone();
                existing.spec = spec;
                existing.revision = existing.revision.saturating_add(1);
                existing.updated_at = now;
                batch.put(existing);
                batch.record(AuditAction::Update, Some(&before), Some(existing));
                summary.lists_updated = summary.lists_updated.saturating_add(1);
            }
            continue;
        }
        let list = List::new(id.clone(), 1, now, now, spec);
        batch.put(&list);
        batch.record(AuditAction::Create, None, Some(&list));
        config.lists.push(list);
        summary.lists_added = summary.lists_added.saturating_add(1);
        if let Some(default) = config.groups.iter_mut().find(|g| g.id == DEFAULT_GROUP) {
            let before = default.clone();
            default.spec.lists.push(GroupList {
                list: id,
                schedule: None,
            });
            default.revision = default.revision.saturating_add(1);
            default.updated_at = now;
            batch.put(default);
            batch.record(AuditAction::Update, Some(&before), Some(default));
        }
    }
}

/// Makes the config-file rules match `rules`, by a stable ID derived from
/// each rule's text.
fn import_rules(
    config: &mut ConfigSnapshot,
    now: Timestamp,
    batch: &mut Batch,
    rules: Vec<RuleSpec>,
    summary: &mut ImportSummary,
) {
    let mut wanted = Vec::new();
    let mut seen = HashSet::new();
    for mut spec in rules {
        spec.managed_by = ManagedBy::ConfigFile;
        let id = stable_id("ru_cfg", &spec.rule);
        if seen.insert(id.clone()) {
            wanted.push((id, spec));
        }
    }
    let removed: Vec<Rule> = config
        .rules
        .iter()
        .filter(|r| r.spec.managed_by == ManagedBy::ConfigFile && !seen.contains(&r.id))
        .cloned()
        .collect();
    for rule in &removed {
        batch.delete::<Rule>(&rule.id);
        batch.record(AuditAction::Delete, Some(rule), None);
        summary.rules_removed = summary.rules_removed.saturating_add(1);
    }
    config
        .rules
        .retain(|r| !removed.iter().any(|x| x.id == r.id));
    for (id, spec) in wanted {
        if config.rules.iter().any(|r| r.id == id) {
            continue;
        }
        let rule = Rule::new(id, 1, now, now, spec);
        batch.put(&rule);
        batch.record(AuditAction::Create, None, Some(&rule));
        config.rules.push(rule);
        summary.rules_added = summary.rules_added.saturating_add(1);
    }
}

/// Creates the database file readable and writable by its owner only, if it
/// does not exist yet: it holds the audit log and, later, client addresses.
fn create_private(path: &Path) -> Result<(), StoreError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
    match options.open(path) {
        Ok(_) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        Err(err) => Err(StoreError::Database(err.into())),
    }
}

fn not_found<K: Kind>(id: &str) -> StoreError {
    StoreError::NotFound {
        kind: K::NAME,
        id: id.to_owned(),
    }
}

fn check_revision<K: Kind>(resource: &K, expected: Option<u64>) -> Result<(), StoreError> {
    match expected {
        Some(expected) if expected != resource.revision() => Err(StoreError::Revision {
            kind: K::NAME,
            id: resource.id().to_owned(),
            expected,
            actual: resource.revision(),
        }),
        _ => Ok(()),
    }
}

/// A random ID such as `cl_3f9c0a41d2e87b65`.
fn new_id(prefix: &str) -> String {
    format!("{prefix}_{:016x}", rand::random::<u64>())
}

/// An ID derived from `source`, so importing the same thing twice gives the
/// same ID: FNV-1a, which unlike the standard hasher is stable.
fn stable_id(prefix: &str, source: &str) -> String {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in source.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{prefix}_{hash:016x}")
}

/// Reads every row of every configuration table.
fn load(db: &Database) -> Result<ConfigSnapshot, StoreError> {
    let tx = db.begin_read()?;
    let settings_table = tx.open_table(SETTINGS)?;
    let settings: Settings = match settings_table.get("settings")? {
        Some(value) => decode("settings", value.value())?,
        None => ConfigSnapshot::empty(Timestamp::now()).settings,
    };
    let mut config = ConfigSnapshot {
        settings,
        lists: Vec::new(),
        rules: Vec::new(),
        groups: Vec::new(),
        clients: Vec::new(),
        schedules: Vec::new(),
        records: Vec::new(),
        users: Vec::new(),
    };
    load_kind::<List>(&tx, &mut config)?;
    load_kind::<Rule>(&tx, &mut config)?;
    load_kind::<Group>(&tx, &mut config)?;
    load_kind::<Client>(&tx, &mut config)?;
    load_kind::<Schedule>(&tx, &mut config)?;
    load_kind::<Record>(&tx, &mut config)?;
    load_kind::<User>(&tx, &mut config)?;
    // The default group first.
    config.groups.sort_by_key(|group| group.id != DEFAULT_GROUP);
    Ok(config)
}

fn load_kind<K: Kind>(
    tx: &redb::ReadTransaction,
    config: &mut ConfigSnapshot,
) -> Result<(), StoreError> {
    let table = tx.open_table(K::table())?;
    let all = K::all_mut(config);
    for row in table.iter()? {
        let (key, value) = row?;
        all.push(decode(
            &format!("{} {}", K::NAME, key.value()),
            value.value(),
        )?);
    }
    all.sort_by(|a, b| (a.created_at(), a.id()).cmp(&(b.created_at(), b.id())));
    Ok(())
}

fn decode<T: DeserializeOwned>(what: &str, bytes: &[u8]) -> Result<T, StoreError> {
    serde_json::from_slice(bytes).map_err(|source| StoreError::Corrupt {
        what: what.to_owned(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        AccessSpec, ClientSpec, GroupSpec, RecordKind, RecordSpec, Role, ScheduleSpec, TotpSpec,
        UserSpec, Weekday, Window,
    };

    struct TempStore {
        store: Option<Store>,
        path: PathBuf,
    }

    impl TempStore {
        fn new(name: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "goethite-store-{name}-{}-{:x}.redb",
                std::process::id(),
                rand::random::<u32>()
            ));
            Self {
                store: Some(Store::open(&path).unwrap()),
                path,
            }
        }

        fn reopen(&mut self) {
            self.store = None;
            self.store = Some(Store::open(&self.path).unwrap());
        }
    }

    impl std::ops::Deref for TempStore {
        type Target = Store;
        fn deref(&self) -> &Store {
            self.store.as_ref().unwrap()
        }
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            self.store = None;
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn api() -> Actor {
        Actor {
            kind: ActorKind::Token,
            name: None,
            address: Some("192.0.2.1".into()),
            node: None,
        }
    }

    fn list(name: &str, url: &str) -> ListSpec {
        ListSpec {
            name: name.into(),
            url: Some(url.into()),
            path: None,
            enabled: true,
            comment: String::new(),
            managed_by: ManagedBy::Api,
        }
    }

    #[test]
    fn opens_with_defaults_and_persists_changes() {
        let mut store = TempStore::new("persist");
        let config = store.config();
        assert_eq!(config.groups.len(), 1);
        assert_eq!(config.groups[0].id, DEFAULT_GROUP);
        assert!(config.settings.spec.protection);

        let ads = store
            .create::<List>(list("Ads", "https://lists.example/ads.txt"), &api())
            .unwrap();
        assert!(ads.id.starts_with("li_"));
        assert_eq!(ads.revision, 1);
        let kids = store
            .create::<Group>(
                GroupSpec {
                    name: "Kids".into(),
                    filtering: true,
                    safe_search: true,
                    lists: vec![GroupList {
                        list: ads.id.clone(),
                        schedule: None,
                    }],
                    blocked_services: Vec::new(),
                    comment: String::new(),
                    managed_by: ManagedBy::ConfigFile,
                },
                &api(),
            )
            .unwrap();
        let tablet = store
            .create::<Client>(
                ClientSpec {
                    name: "Tablet".into(),
                    addresses: vec!["192.168.1.23".into()],
                    ids: Vec::new(),
                    group: kids.id.clone(),
                    comment: String::new(),
                    managed_by: ManagedBy::Api,
                },
                &api(),
            )
            .unwrap();

        store.reopen();
        let config = store.config();
        assert_eq!(config.lists, vec![ads.clone()]);
        assert_eq!(config.groups.len(), 2);
        assert_eq!(
            config.groups[0].id, DEFAULT_GROUP,
            "the default group comes first"
        );
        assert_eq!(config.clients, vec![tablet.clone()]);
        assert_eq!(
            store.get::<Group>(&kids.id).unwrap().spec.managed_by,
            ManagedBy::ConfigFile
        );

        // Audit entries, newest first.
        let audit = store.audit(None, 10).unwrap();
        assert_eq!(audit.len(), 3);
        assert_eq!(audit[0].action, AuditAction::Create);
        assert_eq!(audit[0].kind.as_deref(), Some("client"));
        assert_eq!(audit[0].actor, api());
        assert!(audit[0].after.is_some());
        assert_eq!(store.audit(Some(audit[0].id), 10).unwrap().len(), 2);
    }

    #[test]
    fn updates_check_revisions_and_references() {
        let store = TempStore::new("update");
        let ads = store
            .create::<List>(list("Ads", "https://lists.example/ads.txt"), &api())
            .unwrap();
        let mut renamed = ads.spec.clone();
        renamed.name = "Advertising".into();
        let updated = store
            .update::<List>(&ads.id, renamed.clone(), Some(1), &api())
            .unwrap();
        assert_eq!(updated.revision, 2);
        assert_eq!(updated.created_at, ads.created_at);
        assert!(matches!(
            store.update::<List>(&ads.id, renamed.clone(), Some(1), &api()),
            Err(StoreError::Revision { actual: 2, .. })
        ));
        // An unchanged spec is not a new revision.
        let same = store
            .update::<List>(&ads.id, renamed, None, &api())
            .unwrap();
        assert_eq!(same.revision, 2);
        assert!(matches!(
            store.update::<List>("li_missing", ads.spec.clone(), None, &api()),
            Err(StoreError::NotFound { kind: "list", .. })
        ));

        let mut default = store.get::<Group>(DEFAULT_GROUP).unwrap().spec;
        default.lists.push(GroupList {
            list: ads.id.clone(),
            schedule: None,
        });
        store
            .update::<Group>(DEFAULT_GROUP, default, None, &api())
            .unwrap();
        assert!(matches!(
            store.delete::<List>(&ads.id, None, &api()),
            Err(StoreError::Conflict(_))
        ));
        assert!(matches!(
            store.delete::<Group>(DEFAULT_GROUP, None, &api()),
            Err(StoreError::Conflict(_))
        ));
        // A bad value is refused and changes nothing.
        let mut bad = ads.spec.clone();
        bad.url = Some("ftp://lists.example/ads.txt".into());
        assert!(matches!(
            store.update::<List>(&ads.id, bad, None, &api()),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(store.get::<List>(&ads.id).unwrap().revision, 2);
    }

    #[test]
    fn schedules_and_settings() {
        let store = TempStore::new("settings");
        let school = store
            .create::<Schedule>(
                ScheduleSpec {
                    name: "School".into(),
                    time_zone: "Europe/Berlin".into(),
                    windows: vec![Window {
                        days: vec![Weekday::Mon, Weekday::Fri],
                        start: "08:00".into(),
                        end: "13:00".into(),
                    }],
                    comment: String::new(),
                    managed_by: ManagedBy::Api,
                },
                &api(),
            )
            .unwrap();
        assert!(school.id.starts_with("sc_"));
        let mut spec = store.config().settings.spec.clone();
        spec.protection = false;
        let settings = store
            .update_settings(spec.clone(), Some(1), &api())
            .unwrap();
        assert_eq!(settings.revision, 2);
        assert!(matches!(
            store.update_settings(spec, Some(1), &api()),
            Err(StoreError::Revision { .. })
        ));
        store
            .record(&api(), AuditAction::Pause, Some("for 600 s".into()))
            .unwrap();
        let audit = store.audit(None, 1).unwrap();
        assert_eq!(audit[0].action, AuditAction::Pause);
        assert_eq!(audit[0].detail.as_deref(), Some("for 600 s"));
    }

    #[test]
    fn access_lists_are_checked() {
        let store = TempStore::new("access");
        let with = |allowed: &[&str], blocked: &[&str]| {
            let mut spec = store.config().settings.spec.clone();
            spec.access = AccessSpec {
                allowed: allowed.iter().map(|entry| (*entry).to_owned()).collect(),
                blocked: blocked.iter().map(|entry| (*entry).to_owned()).collect(),
            };
            store.update_settings(spec, None, &api())
        };
        with(
            &["192.168.1.0/24", "2001:db8::/48", "anna-phone"],
            &["192.168.1.66", "guest"],
        )
        .unwrap();
        for (allowed, blocked, field) in [
            (&["192.168.1.5/24"][..], &[][..], "allowed[0]"),
            (&["Anna Phone"][..], &[][..], "allowed[0]"),
            (&[][..], &["guest", "10.0.0.1", "guest"][..], "blocked[2]"),
            (&[][..], &["10.0.0.1", "10.0.0.1/32"][..], "blocked[1]"),
        ] {
            let Err(StoreError::Invalid(error)) = with(allowed, blocked) else {
                panic!("{allowed:?} {blocked:?} were accepted");
            };
            assert_eq!(error.field, format!("settings.access.{field}"));
        }
        let too_many: Vec<String> = (0..=goethite_resolver::MAX_ACCESS_ENTRIES)
            .map(|index| format!("client-{index}"))
            .collect();
        let mut spec = store.config().settings.spec.clone();
        spec.access.blocked = too_many;
        assert!(store.update_settings(spec, None, &api()).is_err());
    }

    #[test]
    fn imports_are_idempotent_and_keep_api_resources() {
        let store = TempStore::new("import");
        let mine = store
            .create::<List>(list("Mine", "https://lists.example/mine.txt"), &api())
            .unwrap();
        let rule = |text: &str| RuleSpec {
            rule: text.into(),
            enabled: true,
            comment: String::new(),
            managed_by: ManagedBy::Api,
        };
        let import = Import {
            settings: SettingsSpec::default(),
            lists: vec![
                list("A", "https://lists.example/a.txt"),
                list("B", "https://lists.example/b.txt"),
            ],
            rules: vec![rule("||ads.example^"), rule("||ads.example^")],
        };
        let first = store.import(import.clone(), &Actor::system()).unwrap();
        assert_eq!((first.lists_added, first.rules_added), (2, 1));
        let again = store.import(import.clone(), &Actor::system()).unwrap();
        assert_eq!(
            again,
            ImportSummary::default(),
            "nothing changes the second time"
        );
        let config = store.config();
        assert_eq!(config.lists.len(), 3);
        assert_eq!(
            config.groups[0].spec.lists.len(),
            2,
            "imported lists join the default group"
        );
        assert!(config.lists.iter().any(|l| l.id == mine.id));

        // Dropping list B from the config removes it from the store and the
        // default group; the API's list stays.
        let mut smaller = import;
        smaller.lists.truncate(1);
        smaller.rules.clear();
        let second = store.import(smaller, &Actor::cli()).unwrap();
        assert_eq!((second.lists_removed, second.rules_removed), (1, 1));
        let config = store.config();
        assert_eq!(config.lists.len(), 2);
        assert_eq!(config.groups[0].spec.lists.len(), 1);
        assert_eq!(config.rules.len(), 0);
        let audit = store.audit(None, 1).unwrap();
        assert_eq!(audit[0].action, AuditAction::Import);
        assert_eq!(audit[0].actor, Actor::cli());
    }

    #[test]
    fn imports_keep_the_access_lists() {
        let store = TempStore::new("import-access");
        let mut spec = store.config().settings.spec.clone();
        spec.access.blocked = vec!["guest".into()];
        store.update_settings(spec, None, &api()).unwrap();
        let import = Import {
            settings: SettingsSpec {
                blocked_ttl: 60,
                ..SettingsSpec::default()
            },
            lists: Vec::new(),
            rules: Vec::new(),
        };
        let summary = store.import(import, &Actor::system()).unwrap();
        assert!(summary.settings_changed);
        let settings = store.config().settings.spec.clone();
        assert_eq!(settings.blocked_ttl, 60);
        assert_eq!(settings.access.blocked, vec!["guest".to_owned()]);
    }

    #[cfg(unix)]
    #[test]
    fn the_file_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let store = TempStore::new("private");
        let mode = std::fs::metadata(&store.path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn a_second_process_is_refused() {
        let store = TempStore::new("locked");
        let err = Store::open(&store.path).err().unwrap();
        assert!(matches!(err, StoreError::Locked(_)), "{err}");
    }

    fn rule(text: &str) -> RuleSpec {
        RuleSpec {
            rule: text.into(),
            enabled: true,
            comment: String::new(),
            managed_by: ManagedBy::Api,
        }
    }

    #[test]
    fn versions_count_changes_and_survive_restarts() {
        let mut store = TempStore::new("versions");
        let start = store.version();
        assert_eq!(start.version, 0);
        assert!(start.epoch < 1 << 53, "exact in JSON");
        let mut changes = store.subscribe();
        store
            .create::<Rule>(rule("||ads.example^"), &api())
            .unwrap();
        assert_eq!(store.version().version, 1);
        assert!(changes.has_changed().unwrap());
        assert_eq!(changes.borrow_and_update().version, 1);
        // Audit-only records and changes to nothing keep the version.
        store.record(&api(), AuditAction::Pause, None).unwrap();
        let settings = store.config().settings.spec.clone();
        store.update_settings(settings, None, &api()).unwrap();
        assert_eq!(store.version().version, 1);
        assert!(!changes.has_changed().unwrap());
        store.reopen();
        assert_eq!(
            store.version(),
            ConfigVersion {
                epoch: start.epoch,
                version: 1
            }
        );
        // Exports carry the version and the configuration as one.
        let export = store.export();
        assert_eq!(export.version, store.version());
        assert_eq!(export.config, *store.config());
    }

    /// A cluster's log in miniature: applies each command on the store it
    /// serves, as the cluster would, and keeps it for the other nodes.
    struct Recorder {
        store: std::sync::Weak<Store>,
        log: Mutex<Vec<Command>>,
    }

    impl Recorder {
        fn attach(store: &Arc<Store>) -> Arc<Self> {
            let recorder = Arc::new(Self {
                store: Arc::downgrade(store),
                log: Mutex::new(Vec::new()),
            });
            store.set_replicator(Arc::clone(&recorder) as Arc<dyn Replicator>);
            recorder
        }

        fn take(&self) -> Vec<Command> {
            std::mem::take(&mut *self.log.lock().unwrap())
        }
    }

    impl Replicator for Recorder {
        fn replicate(&self, command: Command) -> Result<Applied, StoreError> {
            let store = self.store.upgrade().unwrap();
            self.log.lock().unwrap().push(command.clone());
            store.apply(Some(command), "leader")
        }
    }

    #[test]
    fn every_node_applies_the_log_alike() {
        let leader = Arc::new(Store::open_in_memory().unwrap());
        let follower = Store::open_in_memory().unwrap();
        // The follower's own configuration gives way to the seed.
        follower
            .create::<Rule>(rule("||local.example^"), &api())
            .unwrap();
        leader
            .create::<Rule>(rule("||before.example^"), &api())
            .unwrap();
        let seed = leader.seed("dns1");
        for store in [&*leader, &follower] {
            assert!(matches!(
                store.apply(Some(seed.clone()), "1").unwrap(),
                Applied::Done { .. }
            ));
        }
        assert_eq!(*follower.config(), *leader.config());
        assert_eq!(follower.version(), leader.version());
        let audit = follower.audit(None, 1).unwrap();
        assert_eq!(audit[0].action, AuditAction::Replicate);
        assert_eq!(audit[0].actor, Actor::replication("dns1"));

        // Changes made on the leader go through the log.
        let recorder = Recorder::attach(&leader);
        let ads = leader
            .create::<List>(list("Ads", "https://lists.example/ads.txt"), &api())
            .unwrap();
        let mut group = leader.config().groups[0].clone();
        group.spec.lists.push(GroupList {
            list: ads.id.clone(),
            schedule: None,
        });
        leader
            .update::<Group>(DEFAULT_GROUP, group.spec, None, &api())
            .unwrap();
        let before = leader.config().rules[0].id.clone();
        leader.delete::<Rule>(&before, None, &api()).unwrap();
        let mut settings = leader.config().settings.spec.clone();
        settings.protection = false;
        leader.update_settings(settings, None, &api()).unwrap();
        // Audit entries alone stay on the node.
        leader.record(&api(), AuditAction::Pause, None).unwrap();
        let log = recorder.take();
        assert_eq!(log.len(), 4);
        for command in log.clone() {
            assert!(matches!(
                follower.apply(Some(command), "n").unwrap(),
                Applied::Done { .. }
            ));
        }
        assert_eq!(*follower.config(), *leader.config());
        assert_eq!(follower.version(), leader.version());
        assert_eq!(follower.applied().as_deref(), Some("n"));
        // The follower's audit log names who made each change.
        let audit = follower.audit(None, 1).unwrap();
        assert_eq!(audit[0].actor, api());
        assert_eq!(audit[0].kind.as_deref(), Some("settings"));

        // A change prepared against an older configuration is refused, the
        // same way everywhere, and the log goes on.
        let version = follower.version();
        let stale = log[0].clone();
        assert!(matches!(
            follower.apply(Some(stale), "m").unwrap(),
            Applied::Refused { .. }
        ));
        assert_eq!(follower.version(), version);
        assert_eq!(follower.applied().as_deref(), Some("m"));
        assert!(matches!(
            follower.apply(None, "o").unwrap(),
            Applied::Nothing
        ));
        assert_eq!(follower.applied().as_deref(), Some("o"));

        // A configuration from another schema cannot be followed.
        let Command::Seed(mut other) = leader.seed("dns1") else {
            panic!("a seed is a seed")
        };
        other.export.schema = "999".into();
        assert!(matches!(
            follower.apply(Some(Command::Seed(other)), "p"),
            Err(StoreError::Schema { .. })
        ));
        // Nor can a change to a kind this version does not know.
        let Command::Change(mut change) = log[1].clone() else {
            panic!("the second entry is a change")
        };
        change.base = follower.version();
        change.rows = vec![Row::Delete {
            kind: "widget".into(),
            id: "wi_1".into(),
        }];
        assert!(matches!(
            follower.apply(Some(Command::Change(change)), "q"),
            Err(StoreError::Incompatible(_))
        ));

        // A refused change is the caller's conflict on the leader.
        leader.clear_replicator();
        assert_eq!(leader.version(), follower.version());
    }

    #[test]
    fn snapshots_copy_the_configuration_and_the_applied_note() {
        let leader = Store::open_in_memory().unwrap();
        let joiner = Store::open_in_memory().unwrap();
        joiner
            .create::<Rule>(rule("||local.example^"), &api())
            .unwrap();
        leader
            .create::<List>(list("Ads", "https://lists.example/ads.txt"), &api())
            .unwrap();
        leader.apply(None, "7").unwrap();
        let (export, applied) = leader.snapshot();
        assert_eq!(applied.as_deref(), Some("7"));
        let summary = joiner
            .install_snapshot(export, "dns1", applied.as_deref().unwrap())
            .unwrap();
        assert_eq!((summary.added, summary.removed), (1, 1));
        assert!(summary.lists_changed && summary.filter_changed);
        assert_eq!(*joiner.config(), *leader.config());
        assert_eq!(joiner.version(), leader.version());
        assert_eq!(joiner.applied().as_deref(), Some("7"));
        let audit = joiner.audit(None, 1).unwrap();
        assert_eq!(audit[0].action, AuditAction::Replicate);
        assert_eq!(audit[0].actor, Actor::replication("dns1"));
    }

    #[test]
    fn a_refused_change_is_a_conflict_for_its_caller() {
        struct Refuser;
        impl Replicator for Refuser {
            fn replicate(&self, _: Command) -> Result<Applied, StoreError> {
                Ok(Applied::Refused {
                    reason: "changed meanwhile".into(),
                })
            }
        }
        struct Down;
        impl Replicator for Down {
            fn replicate(&self, _: Command) -> Result<Applied, StoreError> {
                Err(StoreError::Unavailable("no leader".into()))
            }
        }
        let store = Store::open_in_memory().unwrap();
        store.set_replicator(Arc::new(Refuser));
        assert!(matches!(
            store.create::<Rule>(rule("||ads.example^"), &api()),
            Err(StoreError::Conflict(reason)) if reason == "changed meanwhile"
        ));
        store.set_replicator(Arc::new(Down));
        assert!(matches!(
            store.create::<Rule>(rule("||ads.example^"), &api()),
            Err(StoreError::Unavailable(_))
        ));
        // Invalid changes never reach the log.
        assert!(matches!(
            store.create::<Rule>(rule(""), &api()),
            Err(StoreError::Invalid(_))
        ));
        assert_eq!(store.config().rules.len(), 0);
        // Audit entries alone are written at once.
        store.record(&api(), AuditAction::Pause, None).unwrap();
        assert_eq!(store.audit(None, 10).unwrap().len(), 1);
    }

    #[test]
    fn a_store_in_memory_works_like_a_file() {
        let store = Store::open_in_memory().unwrap();
        assert_eq!(store.config().groups[0].id, DEFAULT_GROUP);
        store
            .create::<Rule>(rule("||ads.example^"), &api())
            .unwrap();
        assert_eq!(store.config().rules.len(), 1);
        assert_eq!(store.version().version, 1);
        assert_eq!(store.audit(None, 10).unwrap().len(), 1);
    }

    #[test]
    fn records_are_stored_and_checked() {
        let store = TempStore::new("records");
        let record = |name: &str, kind, value: &str| RecordSpec {
            name: name.into(),
            kind,
            value: value.into(),
            ttl: 300,
            enabled: true,
            comment: String::new(),
            managed_by: ManagedBy::Api,
        };
        let nas = store
            .create::<Record>(record("nas.lan", RecordKind::A, "192.168.1.10"), &api())
            .unwrap();
        assert!(nas.id.starts_with("rc_"));
        store
            .create::<Record>(record("nas.lan", RecordKind::Aaaa, "fd00::10"), &api())
            .unwrap();
        store
            .create::<Record>(
                record("*.home.example", RecordKind::Cname, "nas.lan"),
                &api(),
            )
            .unwrap();
        for (spec, problem) in [
            (
                record("NAS.lan", RecordKind::A, "192.168.1.10"),
                "another record is the same",
            ),
            (
                record("nas.lan", RecordKind::Cname, "other.lan"),
                "has a CNAME, so it can have no other record",
            ),
            (record("x.lan", RecordKind::A, "fd00::1"), "IPv4"),
            (record("x.*.lan", RecordKind::A, "10.0.0.1"), "first label"),
            (
                record("x.goethite.test", RecordKind::A, "10.0.0.1"),
                "goethite answers itself",
            ),
            (
                record("x.lan", RecordKind::Cname, "*.lan"),
                "without wildcards",
            ),
        ] {
            let error = store.create::<Record>(spec.clone(), &api()).unwrap_err();
            assert!(error.to_string().contains(problem), "{spec:?}: {error}");
        }
        let config = store.config();
        assert_eq!(config.records.len(), 3);
        let local = config.records[2].spec.local().unwrap();
        assert!(local.wildcard);
        assert_eq!(local.name, "home.example".parse().unwrap());
    }

    #[test]
    fn a_schema_1_store_gains_the_records_table() {
        let mut store = TempStore::new("schema-1");
        store.set_meta("schema", "1").unwrap();
        let tx = store.db.begin_write().unwrap();
        tx.delete_table(Record::table()).unwrap();
        tx.commit().unwrap();
        store.reopen();
        assert_eq!(store.meta("schema").unwrap().as_deref(), Some("3"));
        assert_eq!(store.config().records.len(), 0);
        assert_eq!(store.config().users.len(), 0);
    }

    #[test]
    fn users_persist_and_their_secrets_stay_out_of_the_audit() {
        let mut store = TempStore::new("users");
        let hash = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g".to_owned();
        let spec = UserSpec {
            name: "admin".into(),
            role: Role::Admin,
            disabled: false,
            password_hash: hash.clone(),
            totp: Some(TotpSpec {
                secret: "A".repeat(32),
                enabled: true,
            }),
            recovery: vec!["b".repeat(64)],
            reset: None,
        };
        let created = store.create::<User>(spec, &api()).unwrap();
        assert!(created.id.starts_with("us_"), "{}", created.id);

        let entry = store
            .audit(None, 10)
            .unwrap()
            .into_iter()
            .find(|entry| entry.kind.as_deref() == Some("user"))
            .expect("a user audit entry");
        let after = entry.after.unwrap();
        assert_eq!(after["spec"]["name"], "admin");
        assert!(after["spec"].get("password_hash").is_none(), "{after}");
        assert!(after["spec"]["totp"].get("secret").is_none(), "{after}");
        assert!(after["spec"].get("recovery").is_none(), "{after}");

        store.reopen();
        let held = store.get::<User>(&created.id).unwrap();
        assert_eq!(held.spec.password_hash, hash);
        assert_eq!(held.spec.recovery, vec!["b".repeat(64)]);
    }

    #[test]
    fn user_rules_are_enforced() {
        let store = TempStore::new("user-rules");
        let user = |name: &str, role: Role, disabled: bool| UserSpec {
            name: name.into(),
            role,
            disabled,
            password_hash: "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHQ$aGFzaGhhc2g".into(),
            totp: None,
            recovery: Vec::new(),
            reset: None,
        };
        let admin = store
            .create::<User>(user("Admin", Role::Admin, false), &api())
            .unwrap();
        // No second user with the same name, whatever the case.
        let clash = store.create::<User>(user("admin", Role::Viewer, false), &api());
        assert!(matches!(clash, Err(StoreError::Invalid(_))), "{clash:?}");
        // A viewer is fine next to an admin.
        let viewer = store
            .create::<User>(user("kid", Role::Viewer, false), &api())
            .unwrap();
        // The last enabled admin can be neither disabled, demoted nor
        // deleted while only viewers remain.
        let disabled =
            store.update::<User>(&admin.id, user("Admin", Role::Admin, true), None, &api());
        assert!(
            matches!(disabled, Err(StoreError::Conflict(_))),
            "{disabled:?}"
        );
        let demoted =
            store.update::<User>(&admin.id, user("Admin", Role::Viewer, false), None, &api());
        assert!(
            matches!(demoted, Err(StoreError::Conflict(_))),
            "{demoted:?}"
        );
        let deleted = store.delete::<User>(&admin.id, None, &api());
        assert!(
            matches!(deleted, Err(StoreError::Conflict(_))),
            "{deleted:?}"
        );
        // A second admin unlocks it.
        store
            .create::<User>(user("second", Role::Admin, false), &api())
            .unwrap();
        store.delete::<User>(&admin.id, None, &api()).unwrap();
        let off = store
            .update::<User>(&viewer.id, user("kid", Role::Viewer, true), None, &api())
            .unwrap();
        assert!(off.spec.disabled);
        // Anything that is not an Argon2id hash is refused.
        let mut bad = user("eve", Role::Viewer, false);
        bad.password_hash = "plain".into();
        assert!(matches!(
            store.create::<User>(bad, &api()),
            Err(StoreError::Invalid(_))
        ));
    }

    #[test]
    fn meta_values() {
        let store = TempStore::new("meta");
        assert_eq!(store.meta("seed").unwrap(), None);
        store.set_meta("seed", "abc").unwrap();
        assert_eq!(store.meta("seed").unwrap().as_deref(), Some("abc"));
        assert_eq!(
            store.meta("schema").unwrap().as_deref(),
            Some(SCHEMA_VERSION)
        );
    }
}
