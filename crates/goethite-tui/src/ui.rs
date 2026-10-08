//! Drawing the screens.
//!
//! Neobrutalist like the web UI: thick borders, no rounding, the ochre
//! accent for focus, rust for blocked and teal for good. Outcomes always
//! carry a text label, so nothing depends on color alone.

use goethite_store::{ManagedBy, QueryOutcome};
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
    }
    if let Some(updated) = app.updated {
        spans.push(Span::from(format!("  updated {}", clock(updated))).dim());
    }
    frame.render_widget(Line::from(spans), area);
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
        _ => "tab/1-5 screens · ↑↓ select · p pause 10 min · P resume · R refresh · q quit"
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

fn render_dashboard(frame: &mut Frame<'_>, area: Rect, app: &App) {
    let [left, right] =
        Layout::horizontal([Constraint::Percentage(40), Constraint::Percentage(60)]).areas(area);
    let [totals_area, upstreams_area] =
        Layout::vertical([Constraint::Length(11), Constraint::Min(4)]).areas(left);
    frame.render_widget(
        Paragraph::new(totals(app)).block(block("Last 24 hours")),
        totals_area,
    );

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
            Constraint::Length(21),
        ],
    )
    .header(Row::new(["NAME", "ADDRESSES", "GROUP", "MANAGED BY"]).bold())
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
            cache: None,
            query_log: QueryLogStatus {
                enabled: true,
                entries: 3,
                dropped: 0,
            },
            cluster: None,
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
                group: "gr_kids".into(),
                comment: String::new(),
                managed_by: ManagedBy::Api,
            },
        }]));
        let clients = screen(&app);
        assert!(
            clients.contains("192.168.1.23, fd00::23") && clients.contains("Kids"),
            "{clients}"
        );
        app.tab = Tab::Groups;
        let groups = screen(&app);
        assert!(groups.contains("Kids") && groups.contains("ON"), "{groups}");
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
}
