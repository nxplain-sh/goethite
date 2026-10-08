//! Embedded storage for goethite.
//!
//! One redb database file holds the configuration resources (lists, rules,
//! groups, clients, schedules, settings) and the audit log of every change,
//! and later the query log and statistics. The store is the source of truth
//! for filtering configuration: the TOML config file only seeds it.

pub mod model;
mod store;

pub use model::{
    BlockResponseKind, Client, ClientSpec, ConfigSnapshot, DEFAULT_GROUP, Group, GroupList,
    GroupSpec, List, ListSpec, ManagedBy, Rule, RuleSpec, Schedule, ScheduleSpec, Settings,
    SettingsSpec, ValidationError, Weekday, Window,
};
pub use store::{
    Actor, ActorKind, AuditAction, AuditEntry, Import, ImportSummary, Kind, MAX_AUDIT_ENTRIES,
    Store, StoreError,
};
