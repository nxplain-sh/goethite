//! The TUI's state and how keys change it.

use goethite_api::Status;
use goethite_api::leak::LeakTest;
use goethite_store::{Client, Group, List, ManagedBy, QueryEntry, QueryOutcome, StatsReport};
use jiff::Timestamp;
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

/// The screens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tab {
    /// Totals, top lists, upstreams.
    Dashboard,
    /// The live query log.
    QueryLog,
    /// Filter lists.
    Lists,
    /// Clients.
    Clients,
    /// Groups.
    Groups,
    /// DNS leak tests: from any device, or this machine's.
    LeakTests,
}

impl Tab {
    /// In display order.
    pub const ALL: [Self; 6] = [
        Self::Dashboard,
        Self::QueryLog,
        Self::Lists,
        Self::Clients,
        Self::Groups,
        Self::LeakTests,
    ];

    /// The tab's title.
    pub fn title(self) -> &'static str {
        match self {
            Self::Dashboard => "Dashboard",
            Self::QueryLog => "Query log",
            Self::Lists => "Lists",
            Self::Clients => "Clients",
            Self::Groups => "Groups",
            Self::LeakTests => "Leak tests",
        }
    }

    fn index(self) -> usize {
        Self::ALL.iter().position(|tab| *tab == self).unwrap_or(0)
    }

    fn step(self, forward: bool) -> Self {
        let len = Self::ALL.len();
        let next = if forward {
            self.index().saturating_add(1).checked_rem(len).unwrap_or(0)
        } else {
            self.index().checked_sub(1).unwrap_or(len.saturating_sub(1))
        };
        Self::ALL.get(next).copied().unwrap_or(Self::Dashboard)
    }
}

/// What the API last told us.
#[derive(Clone, Debug, Default)]
pub struct Data {
    /// The node's status.
    pub status: Option<Status>,
    /// Statistics for the last 24 hours.
    pub stats: Option<StatsReport>,
    /// The newest query log entries matching the filter.
    pub log: Vec<QueryEntry>,
    /// The filter lists.
    pub lists: Vec<List>,
    /// The clients.
    pub clients: Vec<Client>,
    /// The groups.
    pub groups: Vec<Group>,
    /// The node's DNS leak tests, newest first.
    pub leak_tests: Vec<LeakTest>,
}

/// Fresh data from the API, or an error.
#[derive(Debug)]
pub enum Update {
    /// The node's status.
    Status(Box<Status>),
    /// Statistics.
    Stats(Box<StatsReport>),
    /// Query log entries.
    Log(Vec<QueryEntry>),
    /// Filter lists.
    Lists(Vec<List>),
    /// Clients.
    Clients(Vec<Client>),
    /// Groups.
    Groups(Vec<Group>),
    /// DNS leak tests.
    LeakTests(Vec<LeakTest>),
    /// Something to tell the user; `true` for an error.
    Message(String, bool),
}

/// What a key asks the API for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Nothing.
    None,
    /// Leave.
    Quit,
    /// Fetch everything for the current tab now.
    Refresh,
    /// Turn a list on or off.
    ToggleList(Box<List>),
    /// Download the lists now.
    RefreshLists,
    /// Pause filtering for this many seconds.
    Pause(u32),
    /// Resume filtering.
    Resume,
    /// Run a DNS leak test from this machine.
    RunLeakTest,
}

/// The TUI's state.
#[derive(Debug)]
pub struct App {
    /// The current screen.
    pub tab: Tab,
    /// What the API last told us.
    pub data: Data,
    /// The selected row on table screens.
    pub selected: usize,
    /// The query log's name filter.
    pub filter: String,
    /// Whether the query log shows blocked queries only.
    pub only_blocked: bool,
    /// The filter being typed, while typing.
    pub input: Option<String>,
    /// The last message, and whether it is an error.
    pub message: Option<(String, bool)>,
    /// Where the API is.
    pub address: String,
    /// When data last arrived.
    pub updated: Option<Timestamp>,
}

impl App {
    /// A fresh state for the API at `address`.
    pub fn new(address: impl Into<String>) -> Self {
        Self {
            tab: Tab::Dashboard,
            data: Data::default(),
            selected: 0,
            filter: String::new(),
            only_blocked: false,
            input: None,
            message: None,
            address: address.into(),
            updated: None,
        }
    }

    /// The outcome the query log is limited to.
    pub fn outcome(&self) -> Option<QueryOutcome> {
        self.only_blocked.then_some(QueryOutcome::Blocked)
    }

    /// Rows on the current screen, for moving the selection.
    fn rows(&self) -> usize {
        match self.tab {
            Tab::Dashboard => 0,
            Tab::QueryLog => self.data.log.len(),
            Tab::Lists => self.data.lists.len(),
            Tab::Clients => self.data.clients.len(),
            Tab::Groups => self.data.groups.len(),
            Tab::LeakTests => self.data.leak_tests.len(),
        }
    }

    /// Takes in fresh data.
    pub fn apply(&mut self, update: Update) {
        match update {
            Update::Status(status) => self.data.status = Some(*status),
            Update::Stats(stats) => self.data.stats = Some(*stats),
            Update::Log(log) => self.data.log = log,
            Update::Lists(lists) => self.data.lists = lists,
            Update::Clients(clients) => self.data.clients = clients,
            Update::Groups(groups) => self.data.groups = groups,
            Update::LeakTests(tests) => self.data.leak_tests = tests,
            Update::Message(text, error) => {
                self.message = Some((text, error));
                return;
            }
        }
        self.updated = Some(Timestamp::now());
        self.selected = self.selected.min(self.rows().saturating_sub(1));
    }

    /// Handles a key; returns what to ask the API for.
    pub fn on_key(&mut self, key: KeyEvent) -> Action {
        if key.kind != KeyEventKind::Press {
            return Action::None;
        }
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            return Action::Quit;
        }
        if let Some(input) = &mut self.input {
            match key.code {
                KeyCode::Enter => {
                    self.filter = std::mem::take(input);
                    self.input = None;
                    return Action::Refresh;
                }
                KeyCode::Esc => self.input = None,
                KeyCode::Backspace => {
                    input.pop();
                }
                KeyCode::Char(c) if input.len() < 255 && !c.is_control() => input.push(c),
                _ => {}
            }
            return Action::None;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => Action::Quit,
            KeyCode::Tab | KeyCode::Right => self.switch(self.tab.step(true)),
            KeyCode::BackTab | KeyCode::Left => self.switch(self.tab.step(false)),
            KeyCode::Char(digit @ '1'..='6') => {
                let index = usize::from(u8::try_from(digit).unwrap_or(b'1').saturating_sub(b'1'));
                Tab::ALL
                    .get(index)
                    .copied()
                    .map_or(Action::None, |tab| self.switch(tab))
            }
            KeyCode::Down | KeyCode::Char('j') => {
                self.selected = self
                    .selected
                    .saturating_add(1)
                    .min(self.rows().saturating_sub(1));
                Action::None
            }
            KeyCode::Up | KeyCode::Char('k') => {
                self.selected = self.selected.saturating_sub(1);
                Action::None
            }
            KeyCode::Char('R') | KeyCode::F(5) => Action::Refresh,
            KeyCode::Char('p') => Action::Pause(600),
            KeyCode::Char('P') => Action::Resume,
            KeyCode::Char('/') if self.tab == Tab::QueryLog => {
                self.input = Some(self.filter.clone());
                Action::None
            }
            KeyCode::Char('b') if self.tab == Tab::QueryLog => {
                self.only_blocked = !self.only_blocked;
                Action::Refresh
            }
            KeyCode::Char('r') if self.tab == Tab::Lists => Action::RefreshLists,
            KeyCode::Char(' ' | 'e') if self.tab == Tab::Lists => self.toggle_selected_list(),
            KeyCode::Char('t') if self.tab == Tab::LeakTests => Action::RunLeakTest,
            _ => Action::None,
        }
    }

    fn switch(&mut self, tab: Tab) -> Action {
        if tab == self.tab {
            return Action::None;
        }
        self.tab = tab;
        self.selected = 0;
        Action::Refresh
    }

    fn toggle_selected_list(&mut self) -> Action {
        let Some(list) = self.data.lists.get(self.selected) else {
            return Action::None;
        };
        if list.spec.managed_by == ManagedBy::Terraform {
            self.message = Some((
                format!(
                    "{} is managed by Terraform; change it there",
                    list.spec.name
                ),
                true,
            ));
            return Action::None;
        }
        Action::ToggleList(Box::new(list.clone()))
    }
}

#[cfg(test)]
mod tests {
    use goethite_store::ListSpec;
    use ratatui::crossterm::event::KeyEventState;

    use super::*;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        }
    }

    fn list(name: &str, managed_by: ManagedBy) -> List {
        List {
            id: format!("li_{name}"),
            revision: 3,
            created_at: Timestamp::UNIX_EPOCH,
            updated_at: Timestamp::UNIX_EPOCH,
            spec: ListSpec {
                name: name.into(),
                url: Some("https://lists.example/x".into()),
                path: None,
                enabled: true,
                comment: String::new(),
                managed_by,
            },
        }
    }

    #[test]
    fn tabs_and_selection() {
        let mut app = App::new("127.0.0.1:8053");
        assert_eq!(app.on_key(key(KeyCode::Tab)), Action::Refresh);
        assert_eq!(app.tab, Tab::QueryLog);
        assert_eq!(app.on_key(key(KeyCode::BackTab)), Action::Refresh);
        assert_eq!(app.on_key(key(KeyCode::BackTab)), Action::Refresh);
        assert_eq!(app.tab, Tab::LeakTests, "wraps around");
        assert_eq!(app.on_key(key(KeyCode::Char('t'))), Action::RunLeakTest);
        assert_eq!(app.on_key(key(KeyCode::Char('5'))), Action::Refresh);
        assert_eq!(app.tab, Tab::Groups);
        assert_eq!(app.on_key(key(KeyCode::Char('t'))), Action::None);
        assert_eq!(app.on_key(key(KeyCode::Char('3'))), Action::Refresh);
        assert_eq!(app.tab, Tab::Lists);
        assert_eq!(app.on_key(key(KeyCode::Char('3'))), Action::None);
        app.apply(Update::Lists(vec![
            list("a", ManagedBy::Api),
            list("b", ManagedBy::Terraform),
        ]));
        app.on_key(key(KeyCode::Down));
        app.on_key(key(KeyCode::Down));
        assert_eq!(app.selected, 1, "stops at the last row");
        assert_eq!(app.on_key(key(KeyCode::Char(' '))), Action::None);
        assert!(app.message.as_ref().unwrap().0.contains("Terraform"));
        app.on_key(key(KeyCode::Up));
        assert!(matches!(
            app.on_key(key(KeyCode::Char(' '))),
            Action::ToggleList(list) if list.spec.name == "a"
        ));
        // Fewer rows after a refresh keep the selection in range.
        app.selected = 1;
        app.apply(Update::Lists(vec![list("a", ManagedBy::Api)]));
        assert_eq!(app.selected, 0);
        assert_eq!(app.on_key(key(KeyCode::Char('q'))), Action::Quit);
    }

    #[test]
    fn filtering_the_query_log() {
        let mut app = App::new("x");
        app.on_key(key(KeyCode::Char('2')));
        assert_eq!(app.on_key(key(KeyCode::Char('/'))), Action::None);
        for c in "adsq".chars() {
            app.on_key(key(KeyCode::Char(c)));
        }
        app.on_key(key(KeyCode::Backspace));
        assert_eq!(app.input.as_deref(), Some("ads"));
        assert_eq!(
            app.on_key(key(KeyCode::Char('q'))),
            Action::None,
            "typing, not quitting"
        );
        app.on_key(key(KeyCode::Backspace));
        assert_eq!(app.on_key(key(KeyCode::Enter)), Action::Refresh);
        assert_eq!(app.filter, "ads");
        assert_eq!(app.input, None);
        assert_eq!(app.on_key(key(KeyCode::Char('b'))), Action::Refresh);
        assert_eq!(app.outcome(), Some(QueryOutcome::Blocked));
        assert_eq!(app.on_key(key(KeyCode::Char('p'))), Action::Pause(600));
        assert_eq!(app.on_key(key(KeyCode::Char('P'))), Action::Resume);
        let mut ctrl_c = key(KeyCode::Char('c'));
        ctrl_c.modifiers = KeyModifiers::CONTROL;
        assert_eq!(app.on_key(ctrl_c), Action::Quit);
    }
}
