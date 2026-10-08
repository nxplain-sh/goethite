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
//! Every change that writes resources also bumps the [`ConfigVersion`], in
//! the same transaction, and announces it on a watch channel, so a cluster
//! replica can follow the configuration ([`Store::export`],
//! [`Store::replace`]).

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
use tracing::warn;
use utoipa::ToSchema;

use crate::model::{
    Client, ConfigSnapshot, DEFAULT_GROUP, Group, GroupList, List, ListSpec, ManagedBy, Rule,
    RuleSpec, Schedule, Settings, SettingsSpec, ValidationError, default_group_resource,
};

/// The most audit entries kept; older ones are dropped.
pub const MAX_AUDIT_ENTRIES: u64 = 100_000;

/// The store's schema version, kept in the `meta` table.
const SCHEMA_VERSION: &str = "1";

const SETTINGS: TableDefinition<'static, &'static str, &'static [u8]> =
    TableDefinition::new("settings");
const META: TableDefinition<'static, &'static str, &'static str> = TableDefinition::new("meta");
/// The `meta` key of the configuration's epoch.
const EPOCH_KEY: &str = "config_epoch";
/// The `meta` key of the configuration's version.
const VERSION_KEY: &str = "config_version";
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
    /// An API client on loopback while no admin token is configured.
    Unauthenticated,
    /// The `goethite` command line, such as `goethite import`.
    Cli,
    /// goethite itself, such as seeding the store on the first start.
    System,
    /// The cluster's primary, whose configuration this replica copied.
    Replication,
}

/// Who made a change, and from where.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Actor {
    /// What kind of actor.
    pub kind: ActorKind,
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
            address: None,
            node: None,
        }
    }

    /// The command line.
    pub fn cli() -> Self {
        Self {
            kind: ActorKind::Cli,
            address: None,
            node: None,
        }
    }

    /// The cluster node `node`, whose configuration was copied.
    pub fn replication(node: impl Into<String>) -> Self {
        Self {
            kind: ActorKind::Replication,
            address: None,
            node: Some(node.into()),
        }
    }
}

extensible_enum!(
    ActorKind,
    "Who made a change: `token` (an API client with the admin token), `unauthenticated` (an API \
     client on loopback while no admin token is configured), `cli` (the goethite command line), \
     `system` (goethite itself) or `replication` (copied from the cluster's primary). More may \
     be added: show unknown values as they are.",
    [Token, Unauthenticated, Cli, System, Replication]
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
    /// The configuration was copied from the cluster's primary.
    Replicate,
    /// This node became the cluster's primary.
    Promote,
    /// This node became a replica of the cluster's primary.
    Demote,
}

extensible_enum!(
    AuditAction,
    "What an audit entry records: `create`, `update` or `delete` (a resource or the settings), \
     `import` (the config file's `[filter]` table), `pause` or `resume` (filtering), `refresh` \
     (a list download), `replicate` (a copy of the cluster primary's configuration), `promote` \
     or `demote` (this node became the cluster's primary or a replica). More may be added: show \
     unknown values as they are.",
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

/// One row to write.
enum Write {
    Put(&'static str, String, Vec<u8>),
    Delete(&'static str, String),
    Settings(Vec<u8>),
}

/// An audit entry still without its number.
struct Pending {
    action: AuditAction,
    kind: Option<String>,
    resource: Option<String>,
    before: Option<serde_json::Value>,
    after: Option<serde_json::Value>,
    detail: Option<String>,
}

/// What a transaction writes.
#[derive(Default)]
struct Batch {
    writes: Vec<Write>,
    audit: Vec<Pending>,
}

impl Batch {
    fn put<K: Kind>(&mut self, resource: &K) -> Result<(), StoreError> {
        let bytes = serde_json::to_vec(resource).map_err(StoreError::Encode)?;
        self.writes
            .push(Write::Put(K::TABLE_NAME, resource.id().to_owned(), bytes));
        Ok(())
    }

    fn delete<K: Kind>(&mut self, id: &str) {
        self.writes
            .push(Write::Delete(K::TABLE_NAME, id.to_owned()));
    }

    fn record<K: Kind>(&mut self, action: AuditAction, before: Option<&K>, after: Option<&K>) {
        let id = after.or(before).map(|r| r.id().to_owned());
        self.audit.push(Pending {
            action,
            kind: Some(K::NAME.to_owned()),
            resource: id,
            before: before.and_then(|r| serde_json::to_value(r).ok()),
            after: after.and_then(|r| serde_json::to_value(r).ok()),
            detail: None,
        });
    }
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
/// created and again when a node becomes the cluster's primary. `version`
/// counts the changes along it. A replica takes a configuration whose epoch
/// differs from its own, or whose version is newer.
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

/// The whole configuration with its version, as a replica receives it.
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
}

/// The configuration and audit log, persisted.
pub struct Store {
    path: PathBuf,
    db: Database,
    current: RwLock<Current>,
    changes: watch::Sender<ConfigVersion>,
    writer: Mutex<()>,
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

    /// Creates the tables a new database needs and loads the
    /// configuration.
    fn init(path: PathBuf, db: Database) -> Result<Self, StoreError> {
        let now = Timestamp::now();
        let tx = db.begin_write()?;
        let version;
        {
            let mut meta = tx.open_table(META)?;
            if meta.get("schema")?.is_none() {
                meta.insert("schema", SCHEMA_VERSION)?;
            }
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
            ] {
                tx.open_table(table)?;
            }
            tx.open_table(AUDIT)?;
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
            }),
            changes,
            writer: Mutex::new(()),
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
            batch.put(&resource)?;
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
            batch.put(&after)?;
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
            batch.writes.push(Write::Settings(
                serde_json::to_vec(&after).map_err(StoreError::Encode)?,
            ));
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
    /// settings, match `import`. Lists and rules from the API or Terraform
    /// stay. New lists are added to the default group; removed ones are
    /// removed from every group.
    ///
    /// # Errors
    ///
    /// An invalid result or a database error.
    pub fn import(&self, import: Import, actor: &Actor) -> Result<ImportSummary, StoreError> {
        let mut summary = ImportSummary::default();
        self.transact(actor, |config, now, batch| {
            import_lists(config, now, batch, import.lists, &mut summary)?;
            import_rules(config, now, batch, import.rules, &mut summary)?;
            if config.settings.spec != import.settings {
                let before = config.settings.clone();
                config.settings = Settings {
                    revision: before.revision.saturating_add(1),
                    updated_at: now,
                    spec: import.settings,
                };
                batch.writes.push(Write::Settings(
                    serde_json::to_vec(&config.settings).map_err(StoreError::Encode)?,
                ));
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

    /// Makes this store's configuration a copy of `incoming`, from the
    /// cluster's primary `actor`, if it is newer (see
    /// [`ConfigVersion::replaces`]). Resources keep the primary's IDs,
    /// revisions and times. Returns what changed, or `None` if `incoming`
    /// is not newer.
    ///
    /// # Errors
    ///
    /// [`StoreError::Schema`] for a configuration from another store schema,
    /// an invalid configuration, or a database error.
    pub fn replace(
        &self,
        incoming: ConfigExport,
        actor: &Actor,
    ) -> Result<Option<ReplaceSummary>, StoreError> {
        if incoming.schema != SCHEMA_VERSION {
            return Err(StoreError::Schema {
                expected: SCHEMA_VERSION.to_owned(),
                found: incoming.schema,
            });
        }
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.current();
        if !incoming.version.replaces(current.version) {
            return Ok(None);
        }
        incoming.config.validate()?;
        let old = &current.config;
        let new = &incoming.config;
        let mut batch = Batch::default();
        let mut summary = ReplaceSummary::default();
        replace_kind::<List>(old, new, &mut batch, &mut summary)?;
        summary.lists_changed = !batch.writes.is_empty();
        replace_kind::<Rule>(old, new, &mut batch, &mut summary)?;
        summary.filter_changed = !batch.writes.is_empty();
        replace_kind::<Group>(old, new, &mut batch, &mut summary)?;
        replace_kind::<Client>(old, new, &mut batch, &mut summary)?;
        replace_kind::<Schedule>(old, new, &mut batch, &mut summary)?;
        if old.settings != new.settings {
            batch.writes.push(Write::Settings(
                serde_json::to_vec(&new.settings).map_err(StoreError::Encode)?,
            ));
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
            after: serde_json::to_value(incoming.version).ok(),
            detail: Some(format!(
                "{} added, {} changed, {} removed{settings}",
                summary.added, summary.changed, summary.removed
            )),
        });
        self.commit(
            incoming.config,
            batch,
            actor,
            Timestamp::now(),
            incoming.version,
        )?;
        Ok(Some(summary))
    }

    /// Starts a new epoch: this node's configuration becomes the cluster's,
    /// and a replica that copied another primary takes it whole. For a node
    /// that becomes the primary.
    ///
    /// # Errors
    ///
    /// A database error.
    pub fn start_epoch(&self, actor: &Actor) -> Result<ConfigVersion, StoreError> {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.current();
        let mut epoch = new_epoch();
        while epoch == current.version.epoch {
            epoch = new_epoch();
        }
        let next = ConfigVersion {
            epoch,
            version: current.version.version.saturating_add(1),
        };
        let mut batch = Batch::default();
        batch.audit.push(Pending {
            action: AuditAction::Promote,
            kind: None,
            resource: None,
            before: serde_json::to_value(current.version).ok(),
            after: serde_json::to_value(next).ok(),
            detail: Some("this node is now the cluster's primary".into()),
        });
        self.commit(
            (*current.config).clone(),
            batch,
            actor,
            Timestamp::now(),
            next,
        )?;
        Ok(next)
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

    /// Applies `change` to a copy of the configuration, validates it, and
    /// writes the batch it fills in, with audit entries, in one transaction.
    fn transact(
        &self,
        actor: &Actor,
        change: impl FnOnce(&mut ConfigSnapshot, Timestamp, &mut Batch) -> Result<(), StoreError>,
    ) -> Result<Arc<ConfigSnapshot>, StoreError> {
        let _writer = self.writer.lock().unwrap_or_else(PoisonError::into_inner);
        let current = self.current();
        let mut next = (*current.config).clone();
        let now = Timestamp::now();
        let mut batch = Batch::default();
        change(&mut next, now, &mut batch)?;
        if batch.writes.is_empty() && batch.audit.is_empty() {
            return Ok(current.config);
        }
        next.validate()?;
        let version = if batch.writes.is_empty() {
            current.version
        } else {
            current.version.next()
        };
        self.commit(next, batch, actor, now, version)
    }

    /// Writes `batch` and its audit entries in one transaction, with
    /// `version` if it changed, then makes `next` the configuration. The
    /// caller holds the writer lock.
    fn commit(
        &self,
        next: ConfigSnapshot,
        batch: Batch,
        actor: &Actor,
        now: Timestamp,
        version: ConfigVersion,
    ) -> Result<Arc<ConfigSnapshot>, StoreError> {
        let previous = self.version();
        let tx = self.db.begin_write()?;
        if version != previous {
            let mut meta = tx.open_table(META)?;
            meta.insert(EPOCH_KEY, version.epoch.to_string().as_str())?;
            meta.insert(VERSION_KEY, version.version.to_string().as_str())?;
        }
        for write in batch.writes {
            match write {
                Write::Put(table, id, bytes) => {
                    tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?
                        .insert(id.as_str(), bytes.as_slice())?;
                }
                Write::Delete(table, id) => {
                    tx.open_table(TableDefinition::<&str, &[u8]>::new(table))?
                        .remove(id.as_str())?;
                }
                Write::Settings(bytes) => {
                    tx.open_table(SETTINGS)?
                        .insert("settings", bytes.as_slice())?;
                }
            }
        }
        {
            let mut audit = tx.open_table(AUDIT)?;
            let mut next_id = audit
                .last()?
                .map_or(1, |(key, _)| key.value().saturating_add(1));
            for pending in batch.audit {
                let entry = AuditEntry {
                    id: next_id,
                    time: now,
                    actor: actor.clone(),
                    action: pending.action,
                    kind: pending.kind,
                    resource: pending.resource,
                    before: pending.before,
                    after: pending.after,
                    detail: pending.detail,
                };
                let bytes = serde_json::to_vec(&entry).map_err(StoreError::Encode)?;
                audit.insert(next_id, bytes.as_slice())?;
                next_id = next_id.saturating_add(1);
            }
            let newest = next_id.saturating_sub(1);
            if audit.len()? > MAX_AUDIT_ENTRIES {
                let keep_from = newest.saturating_sub(MAX_AUDIT_ENTRIES).saturating_add(1);
                audit.retain_in(..keep_from, |_, _| false)?;
            }
        }
        tx.commit()?;
        let next = Arc::new(next);
        *self.current.write().unwrap_or_else(PoisonError::into_inner) = Current {
            config: Arc::clone(&next),
            version,
        };
        if version != previous {
            self.changes.send_replace(version);
        }
        Ok(next)
    }
}

/// Writes the resources of kind `K` in which `new` differs from `old`.
fn replace_kind<K: Kind + PartialEq>(
    old: &ConfigSnapshot,
    new: &ConfigSnapshot,
    batch: &mut Batch,
    summary: &mut ReplaceSummary,
) -> Result<(), StoreError> {
    let before: HashMap<&str, &K> = K::all(old).iter().map(|r| (r.id(), r)).collect();
    let after: HashSet<&str> = K::all(new).iter().map(Kind::id).collect();
    for resource in K::all(new) {
        match before.get(resource.id()) {
            None => {
                batch.put(resource)?;
                summary.added = summary.added.saturating_add(1);
            }
            Some(existing) if *existing != resource => {
                batch.put(resource)?;
                summary.changed = summary.changed.saturating_add(1);
            }
            Some(_) => {}
        }
    }
    for id in before.keys().filter(|id| !after.contains(*id)) {
        batch.delete::<K>(id);
        summary.removed = summary.removed.saturating_add(1);
    }
    Ok(())
}

/// Makes the config-file lists match `lists`, by a stable ID derived from
/// each list's source.
fn import_lists(
    config: &mut ConfigSnapshot,
    now: Timestamp,
    batch: &mut Batch,
    lists: Vec<ListSpec>,
    summary: &mut ImportSummary,
) -> Result<(), StoreError> {
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
            batch.put(group)?;
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
                batch.put(existing)?;
                batch.record(AuditAction::Update, Some(&before), Some(existing));
                summary.lists_updated = summary.lists_updated.saturating_add(1);
            }
            continue;
        }
        let list = List::new(id.clone(), 1, now, now, spec);
        batch.put(&list)?;
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
            batch.put(default)?;
            batch.record(AuditAction::Update, Some(&before), Some(default));
        }
    }
    Ok(())
}

/// Makes the config-file rules match `rules`, by a stable ID derived from
/// each rule's text.
fn import_rules(
    config: &mut ConfigSnapshot,
    now: Timestamp,
    batch: &mut Batch,
    rules: Vec<RuleSpec>,
    summary: &mut ImportSummary,
) -> Result<(), StoreError> {
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
        batch.put(&rule)?;
        batch.record(AuditAction::Create, None, Some(&rule));
        config.rules.push(rule);
        summary.rules_added = summary.rules_added.saturating_add(1);
    }
    Ok(())
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
    };
    load_kind::<List>(&tx, &mut config)?;
    load_kind::<Rule>(&tx, &mut config)?;
    load_kind::<Group>(&tx, &mut config)?;
    load_kind::<Client>(&tx, &mut config)?;
    load_kind::<Schedule>(&tx, &mut config)?;
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
    use crate::model::{ClientSpec, GroupSpec, ScheduleSpec, Weekday, Window};

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
                    comment: String::new(),
                    managed_by: ManagedBy::Terraform,
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
            ManagedBy::Terraform
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

    #[test]
    fn replicas_copy_the_primary() {
        let primary = TempStore::new("primary");
        let replica = TempStore::new("replica");
        let from = Actor::replication("dns1");
        // The replica's own changes are replaced: its epoch differs.
        replica
            .create::<Rule>(rule("||local.example^"), &api())
            .unwrap();
        let ads = primary
            .create::<List>(list("Ads", "https://lists.example/ads.txt"), &api())
            .unwrap();
        let mut group = primary.config().groups[0].clone();
        group.spec.lists.push(GroupList {
            list: ads.id.clone(),
            schedule: None,
        });
        primary
            .update::<Group>(DEFAULT_GROUP, group.spec, None, &api())
            .unwrap();
        primary
            .create::<Rule>(rule("||tracker.example^"), &api())
            .unwrap();

        let summary = replica.replace(primary.export(), &from).unwrap().unwrap();
        assert_eq!(summary.added, 2, "the list and the primary's rule");
        assert_eq!(summary.changed, 1, "the default group");
        assert_eq!(summary.removed, 1, "the replica's own rule");
        assert!(summary.lists_changed && summary.filter_changed);
        assert_eq!(*replica.config(), *primary.config(), "an exact copy");
        assert_eq!(replica.version(), primary.version());

        // The same version again changes nothing.
        assert_eq!(replica.replace(primary.export(), &from).unwrap(), None);

        // Deletions and settings follow.
        let tracker = primary.config().rules[0].id.clone();
        primary.delete::<Rule>(&tracker, None, &api()).unwrap();
        let mut settings = primary.config().settings.spec.clone();
        settings.protection = false;
        primary.update_settings(settings, None, &api()).unwrap();
        let summary = replica.replace(primary.export(), &from).unwrap().unwrap();
        assert_eq!((summary.removed, summary.settings_changed), (1, true));
        assert!(!summary.lists_changed && summary.filter_changed);
        assert_eq!(*replica.config(), *primary.config());

        // An older version of the same history is refused.
        let mut stale = primary.export();
        stale.version.version = 1;
        assert_eq!(replica.replace(stale, &from).unwrap(), None);

        // So is another schema.
        let mut other = primary.export();
        other.schema = "999".into();
        other.version.version += 10;
        assert!(matches!(
            replica.replace(other, &from),
            Err(StoreError::Schema { .. })
        ));

        // The copy is audit-logged as replication from the primary.
        let audit = replica.audit(None, 1).unwrap();
        assert_eq!(audit[0].action, AuditAction::Replicate);
        assert_eq!(audit[0].actor.kind, ActorKind::Replication);
        assert_eq!(audit[0].actor.node.as_deref(), Some("dns1"));
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
