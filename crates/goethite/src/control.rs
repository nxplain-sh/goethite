//! Keeping the data plane in step with the store: compiling the filter and
//! the policy, downloading lists, and tracking which schedules are active.
//!
//! Compiling the filter is the expensive part (about a second per million
//! rules), so it only happens when lists or rules change. Changes to groups,
//! clients, schedules and settings recompile the policy around the current
//! filter, which takes microseconds. Either way the result is swapped in
//! atomically, and if compiling fails the current policy stays.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use goethite_filter::Sources;
use goethite_resolver::{
    Access, BlockResponse, Cidr, ClientPolicy, GroupPolicy, LocalRecords, Policy, PolicyError,
    PolicyParts, PolicyState, ScheduledServices, ScheduledSources, ServiceFilter, ServiceMask,
};
use goethite_store::{AccessSpec, BlockResponseKind, ConfigSnapshot, Store};
use jiff::Timestamp;
use tokio::sync::{Notify, watch};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::download::Downloader;
use crate::filters::{self, CUSTOM_RULES, Compiled, Downloaded, ListStatus};
use crate::lists::ListStore;
use crate::services::{self, Catalog, ServicesFrom};

/// The control plane's handle on the data plane.
pub(crate) struct Control {
    store: Arc<Store>,
    state: Arc<PolicyState>,
    lists: ListStore,
    compiled: Mutex<Arc<Compiled>>,
    downloads: Mutex<HashMap<String, ListStatus>>,
    rebuilding: tokio::sync::Mutex<()>,
    refresh: Notify,
    /// Why the last filter or policy build failed, while it did.
    build_error: Mutex<Option<String>>,
    /// Where the services catalog comes from; no blocked services without.
    services_from: Option<ServicesFrom>,
    catalog: Mutex<Arc<Catalog>>,
    /// Why the catalog could not be downloaded or read, while it could not.
    services_error: Mutex<Option<String>>,
}

impl Control {
    /// A control plane for `store`, steering `state`, keeping downloaded
    /// lists in `lists`, with the services catalog from `services_from`.
    pub(crate) fn new(
        store: Arc<Store>,
        state: Arc<PolicyState>,
        lists: ListStore,
        services_from: Option<ServicesFrom>,
    ) -> Arc<Self> {
        Arc::new(Self {
            store,
            state,
            lists,
            compiled: Mutex::new(Arc::new(Compiled::empty())),
            downloads: Mutex::new(HashMap::new()),
            rebuilding: tokio::sync::Mutex::new(()),
            refresh: Notify::new(),
            build_error: Mutex::new(None),
            services_from,
            catalog: Mutex::new(Arc::new(Catalog::empty())),
            services_error: Mutex::new(None),
        })
    }

    /// The store.
    pub(crate) fn store(&self) -> &Arc<Store> {
        &self.store
    }

    /// The policy state the resolver uses.
    pub(crate) fn state(&self) -> &Arc<PolicyState> {
        &self.state
    }

    /// The current filter.
    pub(crate) fn compiled(&self) -> Arc<Compiled> {
        Arc::clone(&self.compiled.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// Why the last filter or policy build failed, if it did and nothing
    /// has been built since.
    pub(crate) fn build_error(&self) -> Option<String> {
        self.build_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn set_build_error(&self, error: Option<String>) {
        *self
            .build_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = error;
    }

    /// The services catalog in use.
    pub(crate) fn catalog(&self) -> Arc<Catalog> {
        Arc::clone(&self.catalog.lock().unwrap_or_else(PoisonError::into_inner))
    }

    /// The services groups can block, for the API; `None` when this node
    /// does not use the catalog.
    pub(crate) fn services(&self) -> Option<goethite_api::services::Services> {
        let from = self.services_from.as_ref()?;
        let catalog = self.catalog();
        Some(goethite_api::services::Services {
            source: match from {
                ServicesFrom::Url(url) => url.clone(),
                ServicesFrom::File(path) => path.display().to_string(),
            },
            license: goethite_api::services::LICENSE.into(),
            downloaded_at: catalog.saved_at,
            error: self
                .services_error
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            services: catalog.services.clone(),
        })
    }

    fn set_services_error(&self, error: Option<String>) {
        *self
            .services_error
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = error;
    }

    /// The file the catalog is read from.
    fn catalog_file(&self) -> Option<std::path::PathBuf> {
        match self.services_from.as_ref()? {
            ServicesFrom::Url(url) => Some(self.lists.path_for(url)),
            ServicesFrom::File(path) => Some(path.clone()),
        }
    }

    /// Reads the services catalog again, off the async runtime. If it
    /// cannot be read, the current one stays.
    async fn reload_services(&self) {
        let Some(path) = self.catalog_file() else {
            return;
        };
        let known = self.catalog().saved_at;
        let file = matches!(self.services_from, Some(ServicesFrom::File(_)));
        match tokio::task::spawn_blocking(move || services::read(&path, known)).await {
            Ok(Ok(services::Read::Changed(catalog))) => {
                info!(services = catalog.services.len(), "services catalog ready");
                *self.catalog.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(catalog);
                if file {
                    self.set_services_error(None);
                }
            }
            Ok(Ok(services::Read::Unchanged)) => {
                if file {
                    self.set_services_error(None);
                }
            }
            Ok(Ok(services::Read::Missing)) if file => {
                error!(path = %self.catalog_file().unwrap_or_default().display(), "the services file does not exist");
                self.set_services_error(Some("the services file does not exist".into()));
            }
            Ok(Ok(services::Read::Missing)) => debug!("services catalog not downloaded yet"),
            Ok(Err(err)) => {
                error!("{err:#}; keeping the current services catalog");
                self.set_services_error(Some(format!("{err:#}")));
            }
            Err(err) => error!(%err, "reading the services catalog failed"),
        }
    }

    /// Downloads the services catalog if it comes from a URL. Returns
    /// whether it changed.
    async fn download_services(&self, downloader: &Downloader) -> bool {
        let Some(ServicesFrom::Url(url)) = &self.services_from else {
            return false;
        };
        match filters::download_checked(url, &self.lists, downloader, services::validate).await {
            Downloaded::Changed => {
                self.set_services_error(None);
                true
            }
            Downloaded::Unchanged => {
                self.set_services_error(None);
                false
            }
            Downloaded::Failed(why) => {
                self.set_services_error(Some(why));
                false
            }
        }
    }

    /// Recompiles the filter from the store's lists and rules off the async
    /// runtime, then the policy. The services catalog is read again too. If
    /// compiling fails, the current filter stays. Returns whether the new
    /// filter is in use.
    #[tracing::instrument(level = "debug", name = "filter.build", skip_all)]
    pub(crate) async fn rebuild_filter(&self) -> bool {
        let _rebuilding = self.rebuilding.lock().await;
        self.reload_services().await;
        let config = self.store.config();
        let lists = self.lists.clone();
        match tokio::task::spawn_blocking(move || filters::compile(&config, &lists)).await {
            Ok(Ok(compiled)) => {
                *self.compiled.lock().unwrap_or_else(PoisonError::into_inner) = Arc::new(compiled);
            }
            Ok(Err(err)) => {
                error!("{err:#}; keeping the current filter");
                self.set_build_error(Some(format!("cannot build the filter: {err:#}")));
                return false;
            }
            Err(err) => {
                error!(%err, "compiling the filter failed; keeping the current filter");
                self.set_build_error(Some(format!("building the filter failed: {err}")));
                return false;
            }
        }
        if !self.rebuild_policy() {
            return false;
        }
        // Only now does the new filter answer queries.
        let filter = &self.compiled().filter;
        info!(
            rules = filter.rule_count(),
            memory_kib = filter.memory_bytes() / 1024,
            "filter ready"
        );
        true
    }

    /// Recompiles the policy around the current filter, after groups,
    /// clients, schedules, local records or settings changed.
    pub(crate) fn rebuild_policy(&self) -> bool {
        let config = self.store.config();
        match build_policy(&config, &self.compiled(), &self.catalog().filter) {
            Ok(policy) => {
                self.state.replace(policy);
                self.update_schedules();
                self.set_build_error(None);
                true
            }
            Err(err) => {
                error!(%err, "cannot apply the configuration; keeping the current policy");
                self.set_build_error(Some(format!("cannot apply the configuration: {err}")));
                false
            }
        }
    }

    /// Sets which schedules are active right now.
    pub(crate) fn update_schedules(&self) {
        self.state
            .set_active_schedules(active_schedules(&self.store.config(), Timestamp::now()));
    }

    /// How each list is doing, by list ID.
    pub(crate) fn list_statuses(&self) -> HashMap<String, ListStatus> {
        let compiled = self.compiled();
        let downloads = self
            .downloads
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        self.store
            .config()
            .lists
            .iter()
            .map(|list| {
                let mut status = compiled.lists.get(&list.id).cloned().unwrap_or_default();
                if let Some(download) = downloads.get(&list.id) {
                    status.last_attempt = download.last_attempt;
                    status.last_success = download.last_success;
                    status.download_error.clone_from(&download.download_error);
                }
                (list.id.clone(), status)
            })
            .collect()
    }

    /// Downloads the lists now instead of at the next scheduled time.
    pub(crate) fn refresh_lists(&self) {
        self.refresh.notify_one();
    }

    /// Starts downloading lists (now, then every `list_update_hours`) and
    /// tracking schedules (every minute), in `tasks`, until `stopped`
    /// turns true.
    pub(crate) fn spawn(
        self: &Arc<Self>,
        downloader: Downloader,
        tasks: &mut JoinSet<()>,
        stopped: &watch::Receiver<bool>,
    ) {
        let control = Arc::clone(self);
        let stop = stopped.clone();
        tasks.spawn(async move {
            loop {
                let lists_changed = tokio::select! {
                    changed = control.download_all(&downloader) => changed,
                    () = crate::until(stop.clone()) => return,
                };
                let services_changed = tokio::select! {
                    changed = control.download_services(&downloader) => changed,
                    () = crate::until(stop.clone()) => return,
                };
                if lists_changed {
                    control.rebuild_filter().await;
                } else if services_changed {
                    let _rebuilding = control.rebuilding.lock().await;
                    control.reload_services().await;
                    control.rebuild_policy();
                }
                let hours = control.store.config().settings.spec.list_update_hours;
                let interval = Duration::from_secs(u64::from(hours).saturating_mul(3600));
                // Up to 10% later, so installations do not all hit list
                // servers at once.
                let jitter = interval.mul_f64(rand::random::<f64>() * 0.1);
                tokio::select! {
                    () = tokio::time::sleep(interval.saturating_add(jitter)) => {}
                    () = control.refresh.notified() => {}
                    () = crate::until(stop.clone()) => return,
                }
            }
        });
        let control = Arc::clone(self);
        let stop = stopped.clone();
        tasks.spawn(async move {
            loop {
                tokio::select! {
                    () = tokio::time::sleep(until_next_minute()) => control.update_schedules(),
                    () = crate::until(stop.clone()) => return,
                }
            }
        });
    }

    /// Downloads every enabled URL list. Returns whether one changed.
    #[tracing::instrument(level = "debug", name = "lists.refresh", skip_all)]
    async fn download_all(&self, downloader: &Downloader) -> bool {
        let config = self.store.config();
        let mut changed = false;
        for list in config.lists.iter().filter(|list| list.spec.enabled) {
            let Some(url) = &list.spec.url else {
                continue;
            };
            let started = Timestamp::now();
            let outcome = filters::download(url, &self.lists, downloader).await;
            let mut downloads = self
                .downloads
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            let status = downloads.entry(list.id.clone()).or_default();
            status.last_attempt = Some(started);
            match outcome {
                Downloaded::Changed => {
                    changed = true;
                    status.last_success = Some(started);
                    status.download_error = None;
                }
                Downloaded::Unchanged => {
                    status.last_success = Some(started);
                    status.download_error = None;
                }
                Downloaded::Failed(why) => status.download_error = Some(why),
            }
        }
        changed
    }
}

/// How long until one second past the next full minute.
fn until_next_minute() -> Duration {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs() % 60);
    Duration::from_secs(61_u64.saturating_sub(seconds))
}

/// Bit `i` for every schedule `i` active at `now`.
fn active_schedules(config: &ConfigSnapshot, now: Timestamp) -> u64 {
    config
        .schedules
        .iter()
        .enumerate()
        .filter(|(_, schedule)| schedule.spec.is_active(now))
        .fold(0, |mask, (index, _)| {
            mask | u32::try_from(index)
                .ok()
                .and_then(|index| 1_u64.checked_shl(index))
                .unwrap_or(0)
        })
}

/// The index of schedule `id`, as the policy counts schedules.
fn schedule_index(config: &ConfigSnapshot, id: &str) -> Option<u8> {
    config
        .schedules
        .iter()
        .position(|schedule| schedule.id == id)
        .and_then(|index| u8::try_from(index).ok())
}

/// The services `group` blocks, always and per schedule. Services the
/// catalog does not have are left out.
fn group_services(
    config: &ConfigSnapshot,
    group: &goethite_store::Group,
    catalog: &ServiceFilter,
) -> (ServiceMask, Vec<ScheduledServices>) {
    let mut always = ServiceMask::NONE;
    let mut scheduled: Vec<ScheduledServices> = Vec::new();
    for entry in &group.spec.blocked_services {
        let Some(service) = catalog.index(&entry.service) else {
            continue;
        };
        let Some(schedule_id) = &entry.schedule else {
            always = always.with(service);
            continue;
        };
        let Some(index) = schedule_index(config, schedule_id) else {
            continue;
        };
        match scheduled.iter_mut().find(|s| s.schedule == index) {
            Some(existing) => existing.services = existing.services.with(service),
            None => scheduled.push(ScheduledServices {
                schedule: index,
                services: ServiceMask::NONE.with(service),
            }),
        }
    }
    (always, scheduled)
}

/// The policy for `config` around the filter in `compiled` and the services
/// in `catalog`. Lists that are not compiled in (disabled ones) are left out
/// of every group.
pub(crate) fn build_policy(
    config: &ConfigSnapshot,
    compiled: &Compiled,
    catalog: &Arc<ServiceFilter>,
) -> Result<Policy, PolicyError> {
    let custom = compiled
        .source(CUSTOM_RULES)
        .map_or(Sources::NONE, |source| Sources::NONE.with(source));
    let groups = config
        .groups
        .iter()
        .map(|group| {
            let mut always = custom;
            let mut scheduled: Vec<ScheduledSources> = Vec::new();
            for entry in &group.spec.lists {
                let Some(source) = compiled.source(&entry.list) else {
                    continue;
                };
                let Some(schedule_id) = &entry.schedule else {
                    always = always.with(source);
                    continue;
                };
                let Some(index) = schedule_index(config, schedule_id) else {
                    continue;
                };
                match scheduled.iter_mut().find(|s| s.schedule == index) {
                    Some(existing) => existing.sources = existing.sources.with(source),
                    None => scheduled.push(ScheduledSources {
                        schedule: index,
                        sources: Sources::NONE.with(source),
                    }),
                }
            }
            let (services, scheduled_services) = group_services(config, group, catalog);
            GroupPolicy {
                id: group.id.as_str().into(),
                filtering: group.spec.filtering,
                safe_search: group.spec.safe_search,
                sources: always,
                scheduled,
                services,
                scheduled_services,
            }
        })
        .collect();
    let clients = config
        .clients
        .iter()
        .map(|client| {
            let addresses = client
                .spec
                .addresses
                .iter()
                .filter_map(|address| match address.parse::<Cidr>() {
                    Ok(network) => Some(network),
                    Err(err) => {
                        warn!(client = %client.id, %err, "ignoring an invalid address");
                        None
                    }
                })
                .collect();
            let group = config
                .groups
                .iter()
                .position(|group| group.id == client.spec.group)
                .unwrap_or(0);
            ClientPolicy {
                id: client.id.as_str().into(),
                addresses,
                ids: client
                    .spec
                    .ids
                    .iter()
                    .map(|id| id.as_str().into())
                    .collect(),
                group,
            }
        })
        .collect();
    let settings = &config.settings.spec;
    Policy::new(PolicyParts {
        filter: Arc::clone(&compiled.filter),
        source_ids: compiled.source_ids.clone(),
        groups,
        clients,
        block_response: match settings.block_response {
            BlockResponseKind::NullIp => BlockResponse::NullIp,
            BlockResponseKind::Nxdomain => BlockResponse::NxDomain,
            BlockResponseKind::Refused => BlockResponse::Refused,
        },
        blocked_ttl: settings.blocked_ttl,
        protection: settings.protection,
        services: Arc::clone(catalog),
        access: Access::new(
            &AccessSpec::list(&settings.access.allowed),
            &AccessSpec::list(&settings.access.blocked),
        ),
        records: local_records(config),
    })
}

/// The enabled local records, compiled.
fn local_records(config: &ConfigSnapshot) -> LocalRecords {
    LocalRecords::new(
        config
            .records
            .iter()
            .filter(|record| record.spec.enabled)
            .filter_map(|record| {
                let local = record.spec.local();
                if local.is_none() {
                    warn!(record = %record.id, "skipping a local record that is not valid");
                }
                local
            }),
    )
}

#[cfg(test)]
mod tests {
    use std::net::IpAddr;

    use goethite_filter::{FilterBuilder, Source};
    use goethite_store::{
        BlockedService, Client, ClientSpec, Group, GroupList, GroupSpec, ManagedBy, Record,
        RecordKind, RecordSpec, Schedule, ScheduleSpec, Weekday, Window,
    };

    use super::*;

    fn compiled() -> Compiled {
        let mut builder = FilterBuilder::new();
        builder.add_list(Source::new(0).unwrap(), "||custom.example^\n");
        builder.add_list(Source::new(1).unwrap(), "||ads.example^\n");
        builder.add_list(Source::new(2).unwrap(), "||social.example^\n");
        Compiled {
            filter: Arc::new(builder.build().unwrap()),
            source_ids: vec!["custom".into(), "li_ads".into(), "li_social".into()],
            lists: HashMap::new(),
        }
    }

    fn config(now: Timestamp) -> ConfigSnapshot {
        let mut config = ConfigSnapshot::empty(now);
        config.groups[0].spec.lists.push(GroupList {
            list: "li_ads".into(),
            schedule: None,
        });
        config.schedules.push(Schedule {
            id: "sc_school".into(),
            revision: 1,
            created_at: now,
            updated_at: now,
            spec: ScheduleSpec {
                name: "School".into(),
                time_zone: "UTC".into(),
                windows: vec![Window {
                    days: vec![Weekday::Wed],
                    start: "08:00".into(),
                    end: "13:00".into(),
                }],
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        });
        config.groups.push(Group {
            id: "gr_kids".into(),
            revision: 1,
            created_at: now,
            updated_at: now,
            spec: GroupSpec {
                name: "Kids".into(),
                filtering: true,
                safe_search: true,
                lists: vec![
                    GroupList {
                        list: "li_ads".into(),
                        schedule: None,
                    },
                    GroupList {
                        list: "li_social".into(),
                        schedule: Some("sc_school".into()),
                    },
                    GroupList {
                        list: "li_disabled".into(),
                        schedule: None,
                    },
                ],
                blocked_services: Vec::new(),
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        });
        config.clients.push(Client {
            id: "cl_tablet".into(),
            revision: 1,
            created_at: now,
            updated_at: now,
            spec: ClientSpec {
                name: "Tablet".into(),
                addresses: vec!["192.168.1.23".into()],
                ids: vec!["tablet".into()],
                group: "gr_kids".into(),
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        });
        config
    }

    #[test]
    fn policies_follow_the_config() {
        let wednesday_morning: Timestamp = "2026-10-07T09:00:00Z".parse().unwrap();
        let config = config(wednesday_morning);
        let compiled = compiled();
        let policy = build_policy(&config, &compiled, &Arc::new(ServiceFilter::empty())).unwrap();
        let blocked = |ip: &str, name: &str, active: u64| {
            let (_, group) = policy.identify(ip.parse::<IpAddr>().unwrap(), None);
            policy
                .filter()
                .check(&name.parse().unwrap(), group.sources_now(active))
                .is_blocked()
        };
        // Custom rules and the default group's list apply to unknown clients.
        assert!(blocked("10.0.0.9", "custom.example", 0));
        assert!(blocked("10.0.0.9", "ads.example", 0));
        assert!(!blocked("10.0.0.9", "social.example", u64::MAX));
        // The kids' social media list only while school is on.
        assert!(blocked("192.168.1.23", "custom.example", 0));
        assert!(!blocked("192.168.1.23", "social.example", 0));
        let active = active_schedules(&config, wednesday_morning);
        assert_eq!(active, 1);
        assert!(blocked("192.168.1.23", "social.example", active));
        let evening = "2026-10-07T18:00:00Z".parse().unwrap();
        assert_eq!(active_schedules(&config, evening), 0);
        let (client, group) = policy.identify("192.168.1.23".parse().unwrap(), None);
        assert_eq!(client.unwrap().id.as_ref(), "cl_tablet");
        assert!(group.safe_search);
        // The tablet's client ID finds it on any network.
        let (client, _) = policy.identify("203.0.113.5".parse().unwrap(), Some("tablet"));
        assert_eq!(client.unwrap().id.as_ref(), "cl_tablet");
    }

    #[test]
    fn enabled_local_records_reach_the_policy() {
        let now: Timestamp = "2026-10-07T09:00:00Z".parse().unwrap();
        let mut config = config(now);
        for (id, name, enabled) in [("rc_nas", "nas.lan", true), ("rc_old", "old.lan", false)] {
            config.records.push(Record {
                id: id.into(),
                revision: 1,
                created_at: now,
                updated_at: now,
                spec: RecordSpec {
                    name: name.into(),
                    kind: RecordKind::A,
                    value: "192.168.1.10".into(),
                    ttl: 300,
                    enabled,
                    comment: String::new(),
                    managed_by: ManagedBy::Api,
                },
            });
        }
        let policy = build_policy(&config, &compiled(), &Arc::new(ServiceFilter::empty())).unwrap();
        assert_eq!(policy.records().len(), 1);
    }

    #[test]
    fn groups_block_services_in_the_catalog() {
        let now: Timestamp = "2026-10-07T09:00:00Z".parse().unwrap();
        let mut config = config(now);
        let blocked = |service: &str, schedule: Option<&str>| BlockedService {
            service: service.into(),
            schedule: schedule.map(Into::into),
        };
        config.groups[1].spec.blocked_services = vec![
            blocked("tiktok", None),
            blocked("youtube", Some("sc_school")),
            blocked("not_in_the_catalog", None),
        ];
        let rules = |line: &str| {
            let mut rules = Vec::new();
            goethite_filter::parse_line(line, |rule| rules.push(rule));
            rules
        };
        let catalog = Arc::new(
            ServiceFilter::build(&[
                goethite_resolver::ServiceRules {
                    id: "youtube".into(),
                    rules: rules("||youtube.com^"),
                },
                goethite_resolver::ServiceRules {
                    id: "tiktok".into(),
                    rules: rules("||tiktok.com^"),
                },
            ])
            .unwrap(),
        );
        let policy = build_policy(&config, &compiled(), &catalog).unwrap();
        let (_, kids) = policy.identify("192.168.1.23".parse().unwrap(), None);
        let (youtube, tiktok) = (
            catalog.index("youtube").unwrap(),
            catalog.index("tiktok").unwrap(),
        );
        assert_eq!(kids.services, ServiceMask::NONE.with(tiktok));
        assert_eq!(
            kids.services_now(1),
            ServiceMask::NONE.with(tiktok).with(youtube),
            "YouTube while school is on"
        );
        let (_, default) = policy.identify("10.0.0.9".parse().unwrap(), None);
        assert!(default.services_now(u64::MAX).is_empty());
        let name = "www.tiktok.com".parse().unwrap();
        let (service, _) = policy.services().check(&name, &kids.services).unwrap();
        assert_eq!(
            policy.services().source_id(service).map(|s| &**s),
            Some("service:tiktok")
        );
    }

    #[test]
    fn the_next_minute_is_never_far() {
        let wait = until_next_minute();
        assert!(wait >= Duration::from_secs(1) && wait <= Duration::from_secs(61));
    }
}
