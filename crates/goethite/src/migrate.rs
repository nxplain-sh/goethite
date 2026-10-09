//! `goethite migrate`: brings a Pi-hole's or an AdGuard Home's
//! configuration over, reading it through their HTTP APIs and writing it
//! through goethite's. Without `--apply` it only shows the plan.
//!
//! Applying adds what goethite does not have yet and keeps what it has: a
//! list with the same URL, a group or client with the same name, the same
//! rule or record. Running it twice changes nothing the second time. Every
//! change goes through the API, so it is checked, audit-logged and, in a
//! cluster, replicated.

use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::{Context as _, Result, bail};
use goethite_migrate::{Plan, adguard, base64, pihole};
use goethite_store::{
    BlockedService, Client as StoredClient, ClientSpec, DEFAULT_GROUP, Group, GroupList, GroupSpec,
    List, ManagedBy, Record, RecordKind, Rule, Settings,
};
use goethite_tui::{Client, ClientError};
use hyper::Method;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

/// Which server the configuration comes from.
#[derive(Clone, Copy, Debug)]
pub(crate) enum From {
    /// Pi-hole v6.
    Pihole,
    /// AdGuard Home.
    AdguardHome,
}

/// How to reach the old server.
#[derive(Debug)]
pub(crate) struct Source {
    /// Which kind it is.
    pub(crate) from: From,
    /// Its web address, such as `http://pi.hole`.
    pub(crate) url: String,
    /// AdGuard Home's user name.
    pub(crate) user: Option<String>,
    /// Its password.
    pub(crate) password: Option<String>,
    /// A PEM CA certificate for its HTTPS.
    pub(crate) ca: Option<Vec<u8>>,
}

/// Reads the old server's configuration and returns the report; with
/// `target`, applies the plan to goethite through its API first.
pub(crate) async fn migrate(source: Source, target: Option<Client>) -> Result<String> {
    let plan = match source.from {
        From::Pihole => fetch_pihole(&source).await?.plan(),
        From::AdguardHome => fetch_adguard(&source).await?.plan(),
    };
    let mut report = plan.report();
    match target {
        Some(api) => {
            let applied = apply(&plan, &api).await?;
            let _ = write!(report, "\n{applied}");
        }
        None => report
            .push_str("\nNothing was changed. Run again with --apply to make these changes.\n"),
    }
    Ok(report)
}

async fn fetch_pihole(source: &Source) -> Result<pihole::Export> {
    let client = Client::new(&source.url, None, source.ca.as_deref())?;
    // No password set: everything is open, and logging in gives no session.
    let mut session = false;
    let client = match &source.password {
        Some(password) => {
            let reply: Value = client
                .send(
                    Method::POST,
                    "/api/auth",
                    Some(&json!({ "password": password })),
                    None,
                )
                .await
                .context(
                    "Pi-hole refused to log in: check the password (an app password works too)",
                )?;
            match reply.pointer("/session/sid").and_then(Value::as_str) {
                Some(sid) => {
                    session = true;
                    client.with_header("X-FTL-SID", sid)?
                }
                None => client,
            }
        }
        None => client,
    };
    let export = async {
        Ok::<_, ClientError>(pihole::Export {
            lists: client.get("/api/lists").await?,
            domains: client.get("/api/domains").await?,
            groups: client.get("/api/groups").await?,
            clients: client.get("/api/clients").await?,
            config: client.get("/api/config/dns").await?,
        })
    }
    .await;
    // Pi-hole keeps few sessions: give this one back.
    if session {
        let _ = client
            .send_empty::<()>(Method::DELETE, "/api/auth", None)
            .await;
    }
    export
        .context("cannot read Pi-hole's configuration (is it Pi-hole v6, and the password right?)")
}

async fn fetch_adguard(source: &Source) -> Result<adguard::Export> {
    let mut client = Client::new(&source.url, None, source.ca.as_deref())?;
    if let Some(password) = &source.password {
        let user = source.user.as_deref().unwrap_or("admin");
        let credentials = base64(format!("{user}:{password}").as_bytes());
        client = client.with_header("authorization", &format!("Basic {credentials}"))?;
    }
    // First a request every version answers, so a wrong address or
    // password says so before anything else does.
    if let Err(err) = client.get::<Value>("/control/status").await {
        let hint = match err {
            ClientError::Api {
                status: 401 | 403, ..
            } => {
                "AdGuard Home refused the user name or password (check --user and --password-file)"
            }
            _ => "cannot reach AdGuard Home (check --from)",
        };
        return Err(err).context(hint);
    }
    let blocked_services = match client.get::<Value>("/control/blocked_services/get").await {
        Ok(value) => serde_json::from_value(value)
            .context("unexpected blocked services from AdGuard Home")?,
        // Before v0.107.37: a bare list of IDs.
        Err(ClientError::Api { status: 404, .. }) => {
            let ids: Vec<String> = optional(&client, "/control/blocked_services/list")
                .await?
                .unwrap_or_default();
            adguard::BlockedServices {
                ids: Some(ids),
                schedule: None,
            }
        }
        Err(err) => return Err(err).context("cannot read AdGuard Home's blocked services"),
    };
    Ok(adguard::Export {
        filtering: read(&client, "/control/filtering/status").await?,
        clients: read(&client, "/control/clients").await?,
        rewrites: read(&client, "/control/rewrite/list").await?,
        rewrite_settings: optional(&client, "/control/rewrite/settings").await?,
        blocked_services,
        safe_search: optional(&client, "/control/safesearch/status")
            .await?
            .unwrap_or_default(),
        dns: read(&client, "/control/dns_info").await?,
        access: read(&client, "/control/access/list").await?,
    })
}

/// `GET path` from AdGuard Home.
async fn read<T: DeserializeOwned>(client: &Client, path: &str) -> Result<T> {
    client.get(path).await.with_context(|| {
        format!("cannot read {path} from AdGuard Home (are the address, user and password right?)")
    })
}

/// `GET path`, or `None` where an older server does not have it.
async fn optional<T: DeserializeOwned>(client: &Client, path: &str) -> Result<Option<T>> {
    match client.get(path).await {
        Ok(value) => Ok(Some(value)),
        Err(ClientError::Api { status: 404, .. }) => Ok(None),
        Err(err) => Err(err).with_context(|| format!("cannot read {path}")),
    }
}

/// What applying did.
#[derive(Debug, Default)]
struct Applied {
    added: Vec<String>,
    kept: usize,
    failed: Vec<String>,
}

impl std::fmt::Display for Applied {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Applied: {} changes made, {} already in goethite, {} failed.",
            self.added.len(),
            self.kept,
            self.failed.len()
        )?;
        for failure in &self.failed {
            writeln!(f, "  failed: {failure}")?;
        }
        Ok(())
    }
}

impl Applied {
    fn outcome<T>(&mut self, what: String, result: Result<T, ClientError>) -> Option<T> {
        match result {
            Ok(value) => {
                self.added.push(what);
                Some(value)
            }
            Err(err) => {
                self.failed.push(format!("{what}: {err}"));
                None
            }
        }
    }
}

/// Makes the plan's changes through goethite's API.
async fn apply(plan: &Plan, api: &Client) -> Result<Applied> {
    let mut applied = Applied::default();
    let lists: Vec<List> = api
        .get("/api/v1/lists")
        .await
        .context("cannot reach goethite's API (check --api and --token-file)")?;
    let mut list_ids: HashMap<String, String> = lists
        .iter()
        .filter_map(|list| Some((list.spec.url.clone()?, list.id.clone())))
        .collect();
    for spec in &plan.lists {
        let Some(url) = &spec.url else { continue };
        if list_ids.contains_key(url) {
            applied.kept = applied.kept.saturating_add(1);
            continue;
        }
        let created: Option<List> = applied.outcome(
            format!("list {}", spec.name),
            api.send(Method::POST, "/api/v1/lists", Some(spec), None)
                .await,
        );
        if let Some(list) = created {
            list_ids.insert(url.clone(), list.id);
        }
    }
    let ids = |urls: &[String]| -> Vec<String> {
        urls.iter()
            .filter_map(|url| list_ids.get(url).cloned())
            .collect()
    };
    apply_default_group(plan, api, &ids(&plan.default_lists), &mut applied).await?;
    let group_ids = apply_groups(plan, api, &ids, &mut applied).await?;
    apply_clients(plan, api, &group_ids, &mut applied).await?;
    apply_rules_and_records(plan, api, &mut applied).await?;
    apply_settings(plan, api, &mut applied).await?;
    Ok(applied)
}

async fn apply_default_group(
    plan: &Plan,
    api: &Client,
    lists: &[String],
    applied: &mut Applied,
) -> Result<()> {
    let group: Group = api.get(&format!("/api/v1/groups/{DEFAULT_GROUP}")).await?;
    let mut spec = group.spec.clone();
    for list in lists {
        if !spec.lists.iter().any(|used| &used.list == list) {
            spec.lists.push(GroupList {
                list: list.clone(),
                schedule: None,
            });
        }
    }
    if let Some(safe_search) = plan.default_safe_search {
        spec.safe_search = safe_search;
    }
    for service in &plan.default_blocked_services {
        if !spec
            .blocked_services
            .iter()
            .any(|blocked| &blocked.service == service)
        {
            spec.blocked_services.push(BlockedService {
                service: service.clone(),
                schedule: None,
            });
        }
    }
    if spec != group.spec {
        let path = format!("/api/v1/groups/{DEFAULT_GROUP}");
        applied.outcome::<Group>(
            "the default group's lists and settings".into(),
            api.send(Method::PUT, &path, Some(&spec), Some(group.revision))
                .await,
        );
    }
    Ok(())
}

async fn apply_groups(
    plan: &Plan,
    api: &Client,
    list_ids: &impl Fn(&[String]) -> Vec<String>,
    applied: &mut Applied,
) -> Result<HashMap<String, String>> {
    let groups: Vec<Group> = api.get("/api/v1/groups").await?;
    let mut ids: HashMap<String, String> = groups
        .into_iter()
        .map(|group| (group.spec.name, group.id))
        .collect();
    for planned in &plan.groups {
        if ids.contains_key(&planned.name) {
            applied.kept = applied.kept.saturating_add(1);
            continue;
        }
        let spec = GroupSpec {
            name: planned.name.clone(),
            filtering: planned.filtering,
            safe_search: planned.safe_search,
            lists: list_ids(&planned.lists)
                .into_iter()
                .map(|list| GroupList {
                    list,
                    schedule: None,
                })
                .collect(),
            blocked_services: planned
                .blocked_services
                .iter()
                .map(|service| BlockedService {
                    service: service.clone(),
                    schedule: None,
                })
                .collect(),
            comment: planned.comment.clone(),
            managed_by: ManagedBy::Api,
        };
        let created: Option<Group> = applied.outcome(
            format!("group {}", planned.name),
            api.send(Method::POST, "/api/v1/groups", Some(&spec), None)
                .await,
        );
        if let Some(group) = created {
            ids.insert(planned.name.clone(), group.id);
        }
    }
    Ok(ids)
}

async fn apply_clients(
    plan: &Plan,
    api: &Client,
    group_ids: &HashMap<String, String>,
    applied: &mut Applied,
) -> Result<()> {
    let clients: Vec<StoredClient> = api.get("/api/v1/clients").await?;
    for planned in &plan.clients {
        if clients
            .iter()
            .any(|client| client.spec.name == planned.name)
        {
            applied.kept = applied.kept.saturating_add(1);
            continue;
        }
        let group = planned
            .group
            .as_ref()
            .and_then(|name| group_ids.get(name))
            .cloned()
            .unwrap_or_else(|| DEFAULT_GROUP.to_owned());
        let spec = ClientSpec {
            name: planned.name.clone(),
            addresses: planned.addresses.clone(),
            ids: planned.ids.clone(),
            group,
            comment: planned.comment.clone(),
            managed_by: ManagedBy::Api,
        };
        applied.outcome::<StoredClient>(
            format!("client {}", planned.name),
            api.send(Method::POST, "/api/v1/clients", Some(&spec), None)
                .await,
        );
    }
    Ok(())
}

async fn apply_rules_and_records(plan: &Plan, api: &Client, applied: &mut Applied) -> Result<()> {
    let rules: Vec<Rule> = api.get("/api/v1/rules").await?;
    for spec in &plan.rules {
        if rules.iter().any(|rule| rule.spec.rule == spec.rule) {
            applied.kept = applied.kept.saturating_add(1);
            continue;
        }
        applied.outcome::<Rule>(
            format!("rule {}", spec.rule),
            api.send(Method::POST, "/api/v1/rules", Some(spec), None)
                .await,
        );
    }
    let records: Vec<Record> = api.get("/api/v1/records").await?;
    let same = |record: &Record, kind: RecordKind, name: &str, value: &str| {
        record.spec.kind == kind
            && record.spec.name.eq_ignore_ascii_case(name)
            && record.spec.value.eq_ignore_ascii_case(value)
    };
    for spec in &plan.records {
        if records
            .iter()
            .any(|record| same(record, spec.kind, &spec.name, &spec.value))
        {
            applied.kept = applied.kept.saturating_add(1);
            continue;
        }
        applied.outcome::<Record>(
            format!("record {} {}", spec.name, spec.value),
            api.send(Method::POST, "/api/v1/records", Some(spec), None)
                .await,
        );
    }
    Ok(())
}

async fn apply_settings(plan: &Plan, api: &Client, applied: &mut Applied) -> Result<()> {
    let settings: Settings = api.get("/api/v1/settings").await?;
    let mut spec = settings.spec.clone();
    if let Some(kind) = plan.block_response {
        spec.block_response = kind;
    }
    if let Some(ttl) = plan.blocked_ttl {
        spec.blocked_ttl = ttl;
    }
    if let Some(hours) = plan.list_update_hours {
        spec.list_update_hours = hours;
    }
    for (planned, current) in [
        (&plan.access.allowed, &mut spec.access.allowed),
        (&plan.access.blocked, &mut spec.access.blocked),
    ] {
        for entry in planned {
            if !current.contains(entry) {
                current.push(entry.clone());
            }
        }
    }
    if spec != settings.spec {
        applied.outcome::<Settings>(
            "settings".into(),
            api.send(
                Method::PUT,
                "/api/v1/settings",
                Some(&spec),
                Some(settings.revision),
            )
            .await,
        );
    }
    Ok(())
}

/// Reads a password file: its first line, without the line ending.
pub(crate) fn read_password(path: &std::path::Path) -> Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read the password file {}", path.display()))?;
    let password = text.lines().next().unwrap_or_default().to_owned();
    if password.is_empty() {
        bail!("the password file {} is empty", path.display());
    }
    Ok(password)
}
