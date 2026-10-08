//! Drawing the screens.
//!
//! Neobrutalist like the web UI: thick borders, no rounding, the ochre
//! accent for focus, rust for blocked and teal for good. Outcomes always
//! carry a text label, so nothing depends on color alone.

use goethite_api::leak::{LeakLookup, LeakTest};
use goethite_api::{ClusterRole, ClusterStatus};
use goethite_store::{ManagedBy, Protocol, QueryOutcome};
use jiff::Timestamp;
use jiff::tz::TimeZone;
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Cell, Paragraph, Row, Table, TableState, Tabs, Wrap};

use crate::app::{App, Tab};

/// The accent, for focus and highlights.
const OCHRE: Color = Color::Rgb(0xE8, 0xA3, 0x3D);
/// Blocked.
const RUST: Color = Color::Rgb(0xE0, 0x6A, 0x4B);
/// Fine.
const TEAL: Color = Color::Rgb(0x5C, 0xC2, 0xB0);
/// Cached answers.
const SAND: Color = Color::Rgb(0xF6, 0xDF, 0xA8);

fn block(title: &str) -> Block<'_> {
    Block::bordered()
        .border_type(BorderType::Thick)
        .title(Line::from(format!(" {title} ")).bold())
}

/// Draws the whole screen.
pub fn render(frame: &mut Frame<'_>, app: &App) {
    let [header, tabs, main, footer] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(3),
        Constraint::Min(5),
        Constraint::Length(2),
    ])
    .areas(frame.area());
    render_header(frame, header, app);
    let titles = Tab::ALL
        .iter()
        .enumerate()
        .map(|(i, tab)| format!("{} {}", i.saturating_add(1), tab.title()));
    let selected = Tab::ALL.iter().position(|tab| *tab == app.tab).unwrap_or(0);
    frame.render_widget(
        Tabs::new(titles)
            .select(selected)
            .highlight_style(Style::new().fg(Color::Black).bg(OCHRE).bold())
            .block(Block::bordered().border_type(BorderType::Thick)),
        tabs,
    );
    match app.tab {
        Tab::Dashboard => render_dashboard(frame, main, app),
        Tab::QueryLog => render_log(frame, main, app),
        Tab::Lists => render_lists(frame, main, app),
        Tab::Clients => render_clients(frame, main, app),
        Tab::Groups => render_groups(frame, main, app),
        Tab::LeakTests => render_leak_tests(frame, main, app),
    }
    render_footer(frame, footer, app);
}

fn render_header(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let mut spans = vec![
        Span::from(" goethite ").fg(Color::Black).bg(OCHRE).bold(),
        Span::from(format!(" {} ", app.address)),
    ];
    if let Some(status) = &app.data.status {
        spans.push(Span::from(format!("v{} ", status.version)).dim());
        let (label, color) = match (status.protection, status.paused_until) {
            (false, _) => ("FILTERING OFF".to_owned(), RUST),
            (true, Some(until)) => (format!("PAUSED until {}", clock(until)), OCHRE),
            (true, None) => ("FILTERING ON".to_owned(), TEAL),
        };
        spans.push(
            Span::from(format!(" {label} "))
                .fg(Color::Black)
                .bg(color)
                .bold(),
        );
        if let Some(cluster) = &status.cluster {
            spans.extend(cluster_spans(cluster));
        }
        if !status.problems.is_empty() {
            spans.push(Span::from(" "));
            spans.push(
                Span::from(format!(" {} NODE PROBLEM(S) ", status.problems.len()))
                    .fg(Color::Black)
                    .bg(RUST)
                    .bold(),
            );
        }
    }
    if let Some(updated) = app.updated {
        spans.push(Span::from(format!("  updated {}", clock(updated))).dim());
    }
    frame.render_widget(Line::from(spans), area);
}

/// The node's role and its peer, in words; problems in rust.
fn cluster_spans(cluster: &ClusterStatus) -> Vec<Span<'static>> {
    let role = match cluster.role {
        ClusterRole::Primary => "PRIMARY",
        ClusterRole::Replica => "REPLICA",
    };
    let mut spans = vec![
        Span::from(format!("  {} ", cluster.node)),
        Span::from(format!(" {role} "))
            .fg(Color::Black)
            .bg(SAND)
            .bold(),
    ];
    let (peer, color) = if cluster.peer.reachable {
        (format!(" peer {} UP ", cluster.peer.node), TEAL)
    } else {
        (format!(" peer {} DOWN ", cluster.peer.node), RUST)
    };
    spans.push(Span::from(" "));
    spans.push(Span::from(peer).fg(Color::Black).bg(color).bold());
    if !cluster.problems.is_empty() {
        spans.push(
            Span::from(format!(" {} PROBLEM(S) ", cluster.problems.len()))
                .fg(Color::Black)
                .bg(RUST)
                .bold(),
        );
    }
    spans
}

/// The totals' title: whose counts they are.
fn totals_title(app: &App) -> String {
    let Some(stats) = &app.data.stats else {
        return "Last 24 hours".to_owned();
    };
    if stats.nodes.len() < 2 && stats.unreachable.is_empty() {
        return "Last 24 hours".to_owned();
    }
    let missing = if stats.unreachable.is_empty() {
        String::new()
    } else {
        format!(" ({} missing)", stats.unreachable.join(", "))
    };
    format!("Last 24 hours, {}{missing}", stats.nodes.join(" + "))
}

fn render_footer(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let keys = match (app.tab, &app.input) {
        (_, Some(input)) => format!("filter: {input}_   enter apply · esc cancel"),
        (Tab::QueryLog, None) => {
            "/ filter · b blocked only · ↑↓ scroll · p pause 10 min · P resume · R refresh · q quit"
                .to_owned()
        }
        (Tab::Lists, None) => {
            "space turn on/off · r download now · ↑↓ select · p pause · P resume · q quit"
                .to_owned()
        }
        (Tab::LeakTests, None) => {
            "t test this machine's DNS · ↑↓ select · R refresh · tab/1-6 screens · q quit"
                .to_owned()
        }
        _ => "tab/1-6 screens · ↑↓ select · p pause 10 min · P resume · R refresh · q quit"
            .to_owned(),
    };
    let message = app.message.as_ref().map_or_else(
        || Line::from(""),
        |(text, error)| {
            if *error {
                Line::from(vec![
                    Span::from(" ERROR ").fg(Color::Black).bg(RUST).bold(),
                    Span::from(format!(" {text}")),
                ])
            } else {
                Line::from(format!(" {text}")).fg(TEAL)
            }
        },
    );
    frame.render_widget(Paragraph::new(vec![message, Line::from(keys).dim()]), area);
}

/// Local time of day.
fn clock(time: Timestamp) -> String {
    time.to_zoned(TimeZone::system())
        .strftime("%H:%M:%S")
        .to_string()
}

fn percent(part: u64, whole: u64) -> String {
    if whole == 0 {
        return "–".to_owned();
    }
    let tenths = part.saturating_mul(1000).checked_div(whole).unwrap_or(0);
    format!("{}.{}%", tenths / 10, tenths % 10)
}

/// The totals of the last 24 hours, one line each.
fn totals(app: &App) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if let Some(stats) = &app.data.stats {
        let t = &stats.totals;
        let average = t.elapsed_us.checked_div(t.queries).map_or_else(
            || "–".to_owned(),
            |micros| format!("{}.{} ms", micros / 1000, (micros % 1000) / 100),
        );
        for (label, value, color) in [
            ("Queries", t.queries.to_string(), None),
            (
                "Blocked",
                format!("{} ({})", t.blocked, percent(t.blocked, t.queries)),
                Some(RUST),
            ),
            (
                "Cached",
                format!("{} ({})", t.cached, percent(t.cached, t.queries)),
                Some(SAND),
            ),
            ("Forwarded", t.forwarded.to_string(), Some(TEAL)),
            ("Safe search", t.safe_search.to_string(), None),
            (
                "Failed",
                t.failed.to_string(),
                (t.failed > 0).then_some(RUST),
            ),
            ("Average", average, None),
        ] {
            let value = Span::from(value).bold();
            let value = match color {
                Some(color) => value.fg(color),
                None => value,
            };
            lines.push(Line::from(vec![Span::from(format!("{label:<12}")), value]));
        }
    } else {
        lines.push(Line::from("waiting for the API…").dim());
    }
    if let Some(status) = &app.data.status {
        lines.push(Line::from(format!(
            "{:<12}{} rules",
            "Filter", status.filter.rules
        )));
    }
    lines
}

/// What the Recursion panel says.
fn recursion_lines(recursion: &goethite_api::RecursionStatus) -> Vec<Line<'static>> {
    vec![
        Line::from("From the root servers down"),
        Line::from(format!(
            "{} queries sent, {} over TCP",
            recursion.sent, recursion.tcp
        )),
        Line::from(format!(
            "{} timed out, {} unresolved",
            recursion.timeouts, recursion.failures
        )),
        Line::from(format!(
            "{} zones and {} servers known",
            recursion.zones, recursion.servers
        )),
        Line::from(if recursion.dnssec {
            format!(
                "DNSSEC: {} secure, {} insecure, {} bogus",
                recursion.secure, recursion.insecure, recursion.bogus
            )
        } else {
            "DNSSEC validation off".to_owned()
        }),
    ]
}

fn render_dashboard(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area);
    let [totals_area, upstreams_area] =
        Layout::vertical([Constraint::Length(11), Constraint::Min(4)]).areas(left);
    frame.render_widget(
        Paragraph::new(totals(app)).block(block(&totals_title(app))),
        totals_area,
    );

    if let Some(recursion) = app
        .data
        .status
        .as_ref()
        .and_then(|status| status.recursion.as_ref())
    {
        frame.render_widget(
            Paragraph::new(recursion_lines(recursion)).block(block("Recursion")),
            upstreams_area,
        );
    } else {
        let rows = app
            .data
            .status
            .iter()
            .flat_map(|status| &status.upstreams)
            .map(|upstream| {
                let state = if upstream.healthy {
                    Cell::from("UP").fg(TEAL).bold()
                } else {
                    Cell::from("DOWN").fg(RUST).bold()
                };
                Row::new(vec![
                    Cell::from(upstream.address.clone()),
                    Cell::from(upstream.protocol.clone()),
                    state,
                ])
            });
        frame.render_widget(
            Table::new(
                rows,
                [
                    Constraint::Fill(1),
                    Constraint::Length(6),
                    Constraint::Length(5),
                ],
            )
            .block(block("Upstreams")),
            upstreams_area,
        );
    }

    let [names, blocked, clients] = Layout::vertical([
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
        Constraint::Ratio(1, 3),
    ])
    .areas(right);
    let top = |list: Option<&Vec<goethite_store::TopEntry>>| -> Vec<Row<'static>> {
        list.into_iter()
            .flatten()
            .map(|entry| {
                Row::new(vec![
                    Cell::from(entry.count.to_string()).bold(),
                    Cell::from(entry.key.clone()),
                ])
            })
            .collect()
    };
    let widths = [Constraint::Length(8), Constraint::Fill(1)];
    let stats = app.data.stats.as_ref();
    frame.render_widget(
        Table::new(top(stats.map(|s| &s.top_names)), widths).block(block("Top names")),
        names,
    );
    frame.render_widget(
        Table::new(top(stats.map(|s| &s.top_blocked)), widths)
            .block(block("Top blocked"))
            .style(Style::new().fg(RUST)),
        blocked,
    );
    frame.render_widget(
        Table::new(top(stats.map(|s| &s.top_clients)), widths).block(block("Top clients")),
        clients,
    );
}

fn outcome(outcome: QueryOutcome) -> Cell<'static> {
    let (label, color) = match outcome {
        QueryOutcome::Blocked => ("BLOCKED", RUST),
        QueryOutcome::Cached => ("CACHED", SAND),
        QueryOutcome::Forwarded => ("FORWARDED", TEAL),
        QueryOutcome::SafeSearch => ("SAFE SEARCH", OCHRE),
        QueryOutcome::Local => ("LOCAL", TEAL),
        QueryOutcome::Rejected => ("REJECTED", OCHRE),
        QueryOutcome::Failed => ("FAILED", RUST),
    };
    Cell::from(label).fg(color).bold()
}

fn table_state(app: &App) -> TableState {
    TableState::default().with_selected(Some(app.selected))
}

fn highlight() -> Style {
    Style::new()
        .bg(OCHRE)
        .fg(Color::Black)
        .add_modifier(Modifier::BOLD)
}

fn render_log(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let rows = app.data.log.iter().map(|entry| {
        let detail = match (&entry.rule, &entry.upstream) {
            (Some(rule), _) => entry
                .cname
                .as_ref()
                .map_or_else(|| rule.clone(), |cname| format!("{rule} via {cname}")),
            (None, Some(upstream)) => upstream.clone(),
            (None, None) => String::new(),
        };
        Row::new(vec![
            Cell::from(clock(entry.time)),
            Cell::from(
                entry
                    .client_id
                    .clone()
                    .unwrap_or_else(|| entry.client.clone()),
            ),
            Cell::from(entry.qtype.clone()),
            Cell::from(entry.name.clone()),
            outcome(entry.outcome),
            Cell::from(detail).dim(),
        ])
    });
    let mut limits = Vec::new();
    if !app.filter.is_empty() {
        limits.push(format!("name contains {:?}", app.filter));
    }
    if app.only_blocked {
        limits.push("blocked only".to_owned());
    }
    let title = if limits.is_empty() {
        "Query log".to_owned()
    } else {
        format!("Query log ({})", limits.join(", "))
    };
    let table = Table::new(
        rows,
        [
            Constraint::Length(8),
            Constraint::Length(22),
            Constraint::Length(6),
            Constraint::Fill(2),
            Constraint::Length(11),
            Constraint::Fill(1),
        ],
    )
    .header(
        Row::new([
            "TIME",
            "CLIENT",
            "TYPE",
            "NAME",
            "OUTCOME",
            "RULE / UPSTREAM",
        ])
        .bold(),
    )
    .row_highlight_style(highlight())
    .block(block(&title));
    frame.render_stateful_widget(table, area, &mut table_state(app));
}

fn managed(by: ManagedBy) -> Cell<'static> {
    match by {
        ManagedBy::Terraform => Cell::from("terraform (read-only)").fg(OCHRE),
        ManagedBy::ConfigFile => Cell::from("config file"),
        ManagedBy::Api => Cell::from("api"),
    }
}

fn on_off(on: bool) -> Cell<'static> {
    if on {
        Cell::from("ON").fg(TEAL).bold()
    } else {
        Cell::from("OFF").fg(RUST).bold()
    }
}

fn render_lists(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let statuses = app.data.status.as_ref().map(|status| &status.lists);
    let rows = app.data.lists.iter().map(|list| {
        let status = statuses.and_then(|all| all.iter().find(|s| s.id == list.id));
        let rules = status
            .and_then(|s| s.rules)
            .map_or_else(|| "–".to_owned(), |rules| rules.to_string());
        let problem = status
            .and_then(|s| s.download_error.clone().or_else(|| s.error.clone()))
            .unwrap_or_default();
        let downloaded = status
            .and_then(|s| s.last_success)
            .map_or_else(String::new, clock);
        Row::new(vec![
            on_off(list.spec.enabled),
            Cell::from(list.spec.name.clone()),
            Cell::from(rules),
            Cell::from(downloaded),
            managed(list.spec.managed_by),
            Cell::from(problem).fg(RUST),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(4),
            Constraint::Fill(2),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Length(21),
            Constraint::Fill(1),
        ],
    )
    .header(Row::new(["", "NAME", "RULES", "UPDATED", "MANAGED BY", "PROBLEM"]).bold())
    .row_highlight_style(highlight())
    .block(block("Filter lists"));
    frame.render_stateful_widget(table, area, &mut table_state(app));
}

fn group_name(app: &App, id: &str) -> String {
    app.data
        .groups
        .iter()
        .find(|group| group.id == id)
        .map_or_else(|| id.to_owned(), |group| group.spec.name.clone())
}

fn render_clients(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let rows = app.data.clients.iter().map(|client| {
        Row::new(vec![
            Cell::from(client.spec.name.clone()),
            Cell::from(client.spec.addresses.join(", ")),
            Cell::from(client.spec.ids.join(", ")),
            Cell::from(group_name(app, &client.spec.group)),
            managed(client.spec.managed_by),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Fill(2),
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Length(21),
        ],
    )
    .header(Row::new(["NAME", "ADDRESSES", "CLIENT IDS", "GROUP", "MANAGED BY"]).bold())
    .row_highlight_style(highlight())
    .block(block("Clients"));
    frame.render_stateful_widget(table, area, &mut table_state(app));
    if app.data.clients.is_empty() {
        let inner = Rect {
            y: area.y.saturating_add(2),
            height: area.height.saturating_sub(3),
            x: area.x.saturating_add(2),
            width: area.width.saturating_sub(4),
        };
        frame.render_widget(
            Paragraph::new(
                "No clients yet: everyone is in the default group. Add clients through the API \
                 (POST /api/v1/clients).",
            )
            .wrap(Wrap { trim: true })
            .dim(),
            inner,
        );
    }
}

fn client_name(app: &App, id: &str) -> String {
    app.data
        .clients
        .iter()
        .find(|client| client.id == id)
        .map_or_else(|| id.to_owned(), |client| client.spec.name.clone())
}

/// A test's verdict, in words: color only repeats it.
fn leak_verdict(test: &LeakTest) -> Cell<'static> {
    let total = test.names.len();
    match usize::try_from(test.reached).unwrap_or(usize::MAX) {
        0 => Cell::from("LEAK").fg(RUST).bold(),
        n if n >= total => Cell::from("NO LEAK").fg(TEAL).bold(),
        _ => Cell::from("PARTIAL LEAK").fg(RUST).bold(),
    }
}

/// The distinct values of `pick` over a test's lookups, in order.
fn distinct(test: &LeakTest, pick: impl Fn(&LeakLookup) -> Option<String>) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for value in test.lookups.iter().filter_map(pick) {
        if !seen.contains(&value) {
            seen.push(value);
        }
    }
    seen
}

fn protocol(protocol: Protocol) -> &'static str {
    match protocol {
        Protocol::Udp => "UDP",
        Protocol::Tcp => "TCP",
        Protocol::Dot => "DoT",
        Protocol::Doh => "DoH",
        Protocol::Doq => "DoQ",
        Protocol::Odoh => "ODoH",
    }
}

/// What the Leak tests screen says about the selected test.
fn leak_detail(app: &App, test: Option<&LeakTest>) -> Vec<Line<'static>> {
    match test {
        None => vec![
            Line::from(
                "No tests yet. Press t to test this machine's DNS, or open the web UI's Leak test \
                 page on a device to test its browser.",
            ),
            Line::from(
                "A test has the device look up names only goethite answers: those that never \
                 arrive went to another resolver.",
            )
            .dim(),
        ],
        Some(test) if test.lookups.is_empty() => vec![Line::from(
            "None of the names reached goethite: the device asks another resolver (secure DNS \
             in the browser, a VPN, or DNS servers set on the device).",
        )],
        Some(test) => {
            let clients = distinct(test, |l| l.client.as_deref().map(|id| client_name(app, id)));
            let groups = distinct(test, |l| l.group.as_deref().map(|id| group_name(app, id)));
            let filtering = distinct(test, |l| Some(l.filtering.to_string()));
            let mut lines = vec![Line::from(format!(
                "As {}, in {}; filtering {}",
                if clients.is_empty() {
                    "no known client".to_owned()
                } else {
                    clients.join(", ")
                },
                if groups.is_empty() {
                    "no group".to_owned()
                } else {
                    format!("the group {}", groups.join(", "))
                },
                match filtering.as_slice() {
                    [only] if only == "true" => "on",
                    [only] if only == "false" => "off",
                    _ => "on for some",
                }
            ))];
            let elsewhere: Vec<String> = distinct(test, |l| Some(l.address.clone()))
                .into_iter()
                .filter(|address| Some(address) != test.requested_by.as_ref())
                .collect();
            if !elsewhere.is_empty() && test.requested_by.is_some() {
                lines.push(
                    Line::from(format!(
                        "Lookups came from {}, not the test's own address: if that is a router \
                         forwarding them, goethite sees its devices as one client.",
                        elsewhere.join(", ")
                    ))
                    .fg(OCHRE),
                );
            }
            lines.extend(test.lookups.iter().rev().take(5).map(|lookup| {
                Line::from(format!(
                    "{}  name {} of {}  {:<5} {:<4} from {}",
                    clock(lookup.time),
                    lookup.probe,
                    test.names.len(),
                    lookup.qtype,
                    protocol(lookup.protocol),
                    lookup.address
                ))
                .dim()
            }));
            lines
        }
    }
}

fn render_leak_tests(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let [list_area, detail_area] =
        Layout::vertical([Constraint::Fill(1), Constraint::Length(9)]).areas(area);
    let rows = app.data.leak_tests.iter().map(|test| {
        Row::new(vec![
            Cell::from(clock(test.created_at)),
            Cell::from(test.requested_by.clone().unwrap_or_default()),
            leak_verdict(test),
            Cell::from(format!("{} of {}", test.reached, test.names.len())),
            Cell::from(distinct(test, |l| Some(protocol(l.protocol).to_owned())).join(", ")),
            Cell::from(distinct(test, |l| Some(l.address.clone())).join(", ")),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Length(10),
            Constraint::Fill(1),
            Constraint::Length(13),
            Constraint::Length(8),
            Constraint::Length(12),
            Constraint::Fill(2),
        ],
    )
    .header(
        Row::new([
            "STARTED",
            "FROM",
            "VERDICT",
            "REACHED",
            "OVER",
            "LOOKUPS FROM",
        ])
        .bold(),
    )
    .row_highlight_style(highlight())
    .block(block("Leak tests (last hour)"));
    frame.render_stateful_widget(table, list_area, &mut table_state(app));
    let detail = leak_detail(app, app.data.leak_tests.get(app.selected));
    frame.render_widget(
        Paragraph::new(detail)
            .wrap(Wrap { trim: true })
            .block(block("Selected test")),
        detail_area,
    );
}

fn render_groups(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let rows = app.data.groups.iter().map(|group| {
        let clients = app
            .data
            .clients
            .iter()
            .filter(|client| client.spec.group == group.id)
            .count();
        let scheduled = group
            .spec
            .lists
            .iter()
            .filter(|entry| entry.schedule.is_some())
            .count();
        Row::new(vec![
            Cell::from(group.spec.name.clone()),
            on_off(group.spec.filtering),
            on_off(group.spec.safe_search),
            Cell::from(format!(
                "{}{}",
                group.spec.lists.len(),
                if scheduled > 0 {
                    format!(" ({scheduled} scheduled)")
                } else {
                    String::new()
                }
            )),
            Cell::from(
                group
                    .spec
                    .blocked_services
                    .iter()
                    .map(|entry| entry.service.as_str())
                    .collect::<std::collections::HashSet<_>>()
                    .len()
                    .to_string(),
            ),
            Cell::from(clients.to_string()),
            managed(group.spec.managed_by),
        ])
    });
    let table = Table::new(
        rows,
        [
            Constraint::Fill(1),
            Constraint::Length(10),
            Constraint::Length(12),
            Constraint::Length(16),
            Constraint::Length(9),
            Constraint::Length(8),
            Constraint::Length(21),
        ],
    )
    .header(
        Row::new([
            "NAME",
            "FILTERING",
            "SAFE SEARCH",
            "LISTS",
            "SERVICES",
            "CLIENTS",
            "MANAGED BY",
        ])
        .bold(),
    )
    .row_highlight_style(highlight())
    .block(block("Groups"));
    frame.render_stateful_widget(table, area, &mut table_state(app));
}

#[cfg(test)]
mod tests {
    use goethite_api::{FilterStatus, QueryLogStatus, Status, UpstreamStatus};
    use goethite_store::{
        Client, ClientSpec, Counters, Group, GroupSpec, List, ListSpec, Protocol, QueryEntry,
        StatsReport, TopEntry,
    };
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::app::Update;

    fn status() -> Status {
        Status {
            version: "0.2.0".into(),
            started_at: Timestamp::UNIX_EPOCH,
            protection: true,
            paused_until: None,
            filter: FilterStatus {
                rules: 72_526,
                memory_bytes: 740_000,
            },
            lists: Vec::new(),
            upstreams: vec![
                UpstreamStatus {
                    address: "9.9.9.9:853".into(),
                    protocol: "tls".into(),
                    healthy: true,
                    consecutive_failures: 0,
                },
                UpstreamStatus {
                    address: "149.112.112.112:853".into(),
                    protocol: "tls".into(),
                    healthy: false,
                    consecutive_failures: 3,
                },
            ],
            recursion: None,
            cache: None,
            query_log: QueryLogStatus {
                enabled: true,
                entries: 3,
                dropped: 0,
            },
            cluster: None,
            encrypted: None,
            api_docs: false,
            problems: Vec::new(),
        }
    }

    fn screen(app: &App) -> String {
        let mut terminal = Terminal::new(TestBackend::new(140, 36)).unwrap();
        terminal.draw(|frame| render(frame, app)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..buffer.area.height {
            for x in 0..buffer.area.width {
                text.push_str(buffer[(x, y)].symbol());
            }
            text.push('\n');
        }
        text
    }

    fn app() -> App {
        let mut app = App::new("127.0.0.1:8053");
        app.apply(Update::Status(Box::new(status())));
        app
    }

    #[test]
    fn dashboard() {
        let mut app = app();
        assert!(screen(&app).contains("waiting for the API"));
        app.apply(Update::Stats(Box::new(StatsReport {
            from: Timestamp::UNIX_EPOCH,
            to: Timestamp::UNIX_EPOCH,
            totals: Counters {
                queries: 1000,
                blocked: 250,
                cached: 400,
                forwarded: 350,
                elapsed_us: 2_500_000,
                ..Counters::default()
            },
            hours: Vec::new(),
            top_names: vec![TopEntry {
                key: "www.example.com.".into(),
                count: 99,
            }],
            top_blocked: vec![TopEntry {
                key: "ads.example.".into(),
                count: 42,
            }],
            top_clients: Vec::new(),
            nodes: Vec::new(),
            unreachable: Vec::new(),
        })));
        let text = screen(&app);
        for expected in [
            "goethite",
            "FILTERING ON",
            "1 Dashboard",
            "250 (25.0%)",
            "2.5 ms",
            "72526 rules",
            "9.9.9.9:853",
            "DOWN",
            "ads.example.",
            "www.example.com.",
            "q quit",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in\n{text}");
        }
    }

    #[test]
    fn query_log_labels_outcomes() {
        let mut app = app();
        app.tab = Tab::QueryLog;
        app.filter = "ads".into();
        let entry = |name: &str, outcome: QueryOutcome, rule: Option<&str>| QueryEntry {
            id: 1,
            time: Timestamp::UNIX_EPOCH,
            client: "192.0.2.7".into(),
            client_id: None,
            group: None,
            protocol: Protocol::Udp,
            name: name.into(),
            qtype: "A".into(),
            rcode: "NOERROR".into(),
            outcome,
            upstream: None,
            rule: rule.map(Into::into),
            list: None,
            cname: None,
            elapsed_us: 10,
        };
        app.apply(Update::Log(vec![
            entry(
                "x.ads.example.",
                QueryOutcome::Blocked,
                Some("||ads.example^"),
            ),
            entry("ok.example.", QueryOutcome::Cached, None),
        ]));
        let text = screen(&app);
        for expected in [
            "Query log (name contains \"ads\")",
            "BLOCKED",
            "CACHED",
            "||ads.example^",
            "192.0.2.7",
            "/ filter",
        ] {
            assert!(text.contains(expected), "missing {expected:?} in\n{text}");
        }
    }

    #[test]
    fn lists_clients_and_groups() {
        let mut app = app();
        let now = Timestamp::UNIX_EPOCH;
        app.apply(Update::Lists(vec![List {
            id: "li_1".into(),
            revision: 1,
            created_at: now,
            updated_at: now,
            spec: ListSpec {
                name: "StevenBlack".into(),
                url: Some("https://lists.example/hosts".into()),
                path: None,
                enabled: false,
                comment: String::new(),
                managed_by: ManagedBy::Terraform,
            },
        }]));
        app.apply(Update::Groups(vec![Group {
            id: "gr_kids".into(),
            revision: 1,
            created_at: now,
            updated_at: now,
            spec: GroupSpec {
                name: "Kids".into(),
                filtering: true,
                safe_search: true,
                lists: Vec::new(),
                blocked_services: Vec::new(),
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        }]));
        app.tab = Tab::Lists;
        let lists = screen(&app);
        assert!(
            lists.contains("StevenBlack") && lists.contains("OFF"),
            "{lists}"
        );
        assert!(lists.contains("terraform (read-only)"), "{lists}");
        app.tab = Tab::Clients;
        assert!(screen(&app).contains("No clients yet"));
        app.apply(Update::Clients(vec![Client {
            id: "cl_1".into(),
            revision: 1,
            created_at: now,
            updated_at: now,
            spec: ClientSpec {
                name: "Tablet".into(),
                addresses: vec!["192.168.1.23".into(), "fd00::23".into()],
                ids: vec!["tablet".into()],
                group: "gr_kids".into(),
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        }]));
        let clients = screen(&app);
        assert!(
            clients.contains("192.168.1.23, fd00::23")
                && clients.contains("tablet")
                && clients.contains("Kids"),
            "{clients}"
        );
        app.tab = Tab::Groups;
        let groups = screen(&app);
        assert!(
            groups.contains("Kids") && groups.contains("ON") && groups.contains("SERVICES"),
            "{groups}"
        );
    }

    #[test]
    fn recursion_replaces_the_upstreams() {
        let mut app = app();
        let mut status = status();
        status.upstreams.clear();
        status.recursion = Some(goethite_api::RecursionStatus {
            qname_minimisation: true,
            ipv6: false,
            dnssec: true,
            sent: 1234,
            tcp: 5,
            timeouts: 7,
            failures: 1,
            secure: 900,
            insecure: 300,
            bogus: 1,
            zones: 300,
            servers: 80,
        });
        app.data.status = Some(status);
        let dashboard = screen(&app);
        assert!(dashboard.contains("Recursion"), "{dashboard}");
        assert!(
            dashboard.contains("1234 queries sent, 5 over TCP"),
            "{dashboard}"
        );
        assert!(
            dashboard.contains("DNSSEC: 900 secure, 300 insecure, 1 bogus"),
            "{dashboard}"
        );
        assert!(!dashboard.contains("Upstreams"), "{dashboard}");
    }

    #[test]
    fn the_cluster_shows_in_words() {
        let mut app = app();
        let mut status = status();
        status.cluster = Some(ClusterStatus {
            node: "dns2".into(),
            role: ClusterRole::Replica,
            config: goethite_store::ConfigVersion::default(),
            writable: false,
            peer: goethite_api::PeerStatus {
                node: "dns1".into(),
                address: "192.0.2.11:8054".into(),
                reachable: false,
                checked_at: None,
                role: None,
                version: None,
                config: None,
                error: Some("connection refused".into()),
            },
            sync: None,
            problems: vec!["cannot copy the primary's configuration".into()],
        });
        app.apply(Update::Status(Box::new(status)));
        let text = screen(&app);
        assert!(text.contains("dns2") && text.contains("REPLICA"), "{text}");
        assert!(text.contains("peer dns1 DOWN"), "{text}");
        assert!(text.contains("1 PROBLEM(S)"), "{text}");
    }

    #[test]
    fn errors_and_pauses_show_in_words() {
        let mut app = app();
        app.apply(Update::Message("cannot reach the API".into(), true));
        let mut paused = status();
        paused.paused_until = Some(Timestamp::UNIX_EPOCH);
        app.apply(Update::Status(Box::new(paused)));
        let text = screen(&app);
        assert!(text.contains("ERROR") && text.contains("cannot reach the API"));
        assert!(text.contains("PAUSED until"));
    }

    fn leak_test(reached: u32, from: &str, lookups: &[(u8, &str)]) -> LeakTest {
        LeakTest {
            id: "ab".into(),
            names: (1..=8)
                .map(|n| format!("ab-{n}.leak.goethite.test."))
                .collect(),
            created_at: Timestamp::UNIX_EPOCH,
            expires_at: Timestamp::UNIX_EPOCH,
            requested_by: Some(from.into()),
            reached,
            lookups: lookups
                .iter()
                .map(|&(probe, address)| LeakLookup {
                    probe,
                    time: Timestamp::UNIX_EPOCH,
                    address: address.into(),
                    protocol: Protocol::Doh,
                    qtype: "AAAA".into(),
                    client: None,
                    group: Some("default".into()),
                    filtering: true,
                })
                .collect(),
        }
    }

    #[test]
    fn leak_tests_say_their_verdict_in_words() {
        let mut app = app();
        app.tab = Tab::LeakTests;
        assert!(screen(&app).contains("Press t to test this machine's DNS"));
        app.apply(Update::LeakTests(vec![
            leak_test(2, "192.0.2.10", &[(1, "192.0.2.1"), (2, "192.0.2.1")]),
            leak_test(0, "192.0.2.11", &[]),
        ]));
        let shown = screen(&app);
        for text in [
            "PARTIAL LEAK",
            "2 of 8",
            "DoH",
            "LEAK ",
            "0 of 8",
            "in the group default; filtering on",
            "Lookups came from 192.0.2.1, not the test's own address",
            "t test this machine's DNS",
        ] {
            assert!(shown.contains(text), "{text:?} in\n{shown}");
        }
        app.selected = 1;
        assert!(screen(&app).contains("None of the names reached goethite"));
    }
}
