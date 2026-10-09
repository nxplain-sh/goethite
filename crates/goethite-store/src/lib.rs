//! Embedded storage for goethite.
//!
//! One redb database file holds the configuration resources (lists, rules,
//! groups, clients, schedules, local DNS records, settings), the audit log of
//! every change, the
//! query log and hourly statistics. The store is the source of truth for
//! filtering configuration: the TOML config file only seeds it.

#![forbid(unsafe_code)]

pub mod model;
pub mod querylog;
pub mod stats;
mod store;

pub use model::{
    AccessSpec, BlockResponseKind, BlockedService, Client, ClientSpec, ConfigSnapshot,
    DEFAULT_GROUP, Group, GroupList, GroupSpec, List, ListSpec, ManagedBy, Record, RecordKind,
    RecordSpec, Rule, RuleSpec, Schedule, ScheduleSpec, Settings, SettingsSpec, ValidationError,
    Weekday, Window,
};
pub use querylog::{
    LogEvent, LogUpstream, NameBuf, Protocol, QueryEntry, QueryLog, QueryLogConfig, QueryOutcome,
    QueryPage, RuleHit, Search, StoredQuery,
};
pub use stats::{Counters, HourPoint, StatsReport, TopEntry};
pub use store::{
    Actor, ActorKind, AuditAction, AuditEntry, ConfigExport, ConfigVersion, Import, ImportSummary,
    Kind, MAX_AUDIT_ENTRIES, ReplaceSummary, Store, StoreError,
};
