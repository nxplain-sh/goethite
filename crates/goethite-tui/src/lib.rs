//! The goethite terminal UI (`goethite tui`).
//!
//! A ratatui client that talks to a goethite node only through the REST API,
//! so it has exactly the permissions of the token it is given. It shows a
//! dashboard, the live query log, filter lists, clients and groups; it can
//! turn lists on and off, download them now, and pause or resume filtering.
//! Resources managed by Terraform are read-only here.

mod app;
mod client;
mod ui;

use std::fmt::Write as _;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use goethite_api::Status;
use goethite_store::{Client as ClientResource, Group, List, QueryPage, StatsReport};
use hyper::Method;
use ratatui::crossterm::event::{self, Event};
use serde_json::json;
use tokio::sync::mpsc;

pub use app::{Action, App, Data, Tab, Update};
pub use client::{Client, ClientError};
pub use ui::render;

/// How often the screen's data is fetched again.
const REFRESH: Duration = Duration::from_secs(2);

/// Query log entries shown.
const LOG_ROWS: usize = 200;

/// Why the TUI stopped.
#[derive(Debug, thiserror::Error)]
pub enum TuiError {
    /// The API client could not be set up.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// The terminal failed.
    #[error("terminal: {0}")]
    Terminal(#[from] std::io::Error),
}

/// Where the API is and how to authenticate.
#[derive(Clone, Debug, Default)]
pub struct Options {
    /// The API's address, such as `http://127.0.0.1:8053`.
    pub url: String,
    /// The admin token, if the node has one.
    pub token: Option<String>,
    /// A PEM CA certificate for a node with its own HTTPS certificate.
    pub ca: Option<Vec<u8>>,
}

/// Restores the terminal however the TUI ends.
struct Restore;

impl Drop for Restore {
    fn drop(&mut self) {
        ratatui::restore();
    }
}

/// Runs the TUI until the user quits.
///
/// # Errors
///
/// A [`TuiError`] if the API address is unusable or the terminal fails. API
/// errors while running are shown on screen, not returned.
pub async fn run(options: Options) -> Result<(), TuiError> {
    let client = Client::new(&options.url, options.token, options.ca.as_deref())?;
    let mut terminal = ratatui::try_init()?;
    let _restore = Restore;
    let (keys_tx, mut keys) = mpsc::channel(64);
    // Reading keys blocks, so it gets its own thread.
    std::thread::spawn(move || {
        loop {
            match event::poll(Duration::from_millis(200)) {
                Ok(true) => match event::read() {
                    Ok(Event::Key(key)) => {
                        if keys_tx.blocking_send(key).is_err() {
                            return;
                        }
                    }
                    Ok(_) => {}
                    Err(_) => return,
                },
                Ok(false) => {
                    if keys_tx.is_closed() {
                        return;
                    }
                }
                Err(_) => return,
            }
        }
    });
    let (updates_tx, mut updates) = mpsc::channel(64);
    let busy = Arc::new(AtomicBool::new(false));
    let mut app = App::new(client.address());
    refresh(&client, &app, &updates_tx, &busy);
    let mut tick = tokio::time::interval(REFRESH);
    loop {
        terminal.draw(|frame| render(frame, &app))?;
        tokio::select! {
            Some(key) = keys.recv() => match app.on_key(key) {
                Action::Quit => break,
                Action::None => {}
                Action::Refresh => refresh(&client, &app, &updates_tx, &busy),
                action => perform(&client, action, &updates_tx),
            },
            Some(update) = updates.recv() => app.apply(update),
            _ = tick.tick() => refresh(&client, &app, &updates_tx, &busy),
        }
    }
    Ok(())
}

/// Fetches what the current screen shows, in the background. Skipped while
/// a fetch is still running.
fn refresh(client: &Client, app: &App, updates: &mpsc::Sender<Update>, busy: &Arc<AtomicBool>) {
    if busy.swap(true, Ordering::AcqRel) {
        return;
    }
    let client = client.clone();
    let updates = updates.clone();
    let busy = Arc::clone(busy);
    let tab = app.tab;
    let mut log_path = format!("/api/v1/querylog?limit={LOG_ROWS}");
    if !app.filter.is_empty() {
        log_path.push_str("&name=");
        log_path.push_str(&encode(&app.filter));
    }
    if let Some(outcome) = app.outcome() {
        log_path.push_str("&outcome=");
        log_path.push_str(outcome.as_str());
    }
    tokio::spawn(async move {
        let result = fetch(&client, tab, &log_path, &updates).await;
        if let Err(err) = result {
            let _ = updates.send(Update::Message(err.to_string(), true)).await;
        }
        busy.store(false, Ordering::Release);
    });
}

async fn fetch(
    client: &Client,
    tab: Tab,
    log_path: &str,
    updates: &mpsc::Sender<Update>,
) -> Result<(), ClientError> {
    let status: Status = client.get("/api/v1/status").await?;
    let _ = updates.send(Update::Status(Box::new(status))).await;
    match tab {
        Tab::Dashboard => {
            let report: StatsReport = client.get("/api/v1/stats?hours=24").await?;
            let _ = updates.send(Update::Stats(Box::new(report))).await;
        }
        Tab::QueryLog => {
            let page: QueryPage = client.get(log_path).await?;
            let _ = updates.send(Update::Log(page.entries)).await;
        }
        Tab::Lists => {
            let lists: Vec<List> = client.get("/api/v1/lists").await?;
            let _ = updates.send(Update::Lists(lists)).await;
        }
        Tab::Clients | Tab::Groups => {
            let groups: Vec<Group> = client.get("/api/v1/groups").await?;
            let _ = updates.send(Update::Groups(groups)).await;
            let clients: Vec<ClientResource> = client.get("/api/v1/clients").await?;
            let _ = updates.send(Update::Clients(clients)).await;
        }
    }
    Ok(())
}

/// Carries out an action in the background and reports how it went.
fn perform(client: &Client, action: Action, updates: &mpsc::Sender<Update>) {
    let client = client.clone();
    let updates = updates.clone();
    tokio::spawn(async move {
        let done = match action {
            Action::ToggleList(list) => {
                let mut spec = list.spec.clone();
                spec.enabled = !spec.enabled;
                let state = if spec.enabled { "on" } else { "off" };
                let path = format!("/api/v1/lists/{}", list.id);
                client
                    .send::<_, List>(Method::PUT, &path, Some(&spec), Some(list.revision))
                    .await
                    .map(|_| format!("{} turned {state}", list.spec.name))
            }
            Action::RefreshLists => client
                .send_empty::<()>(Method::POST, "/api/v1/lists/refresh", None)
                .await
                .map(|()| "downloading the lists".to_owned()),
            Action::Pause(seconds) => client
                .send::<_, serde_json::Value>(
                    Method::PUT,
                    "/api/v1/pause",
                    Some(&json!({ "seconds": seconds })),
                    None,
                )
                .await
                .map(|_| format!("filtering paused for {} minutes", seconds / 60)),
            Action::Resume => client
                .send::<(), serde_json::Value>(Method::DELETE, "/api/v1/pause", None, None)
                .await
                .map(|_| "filtering resumed".to_owned()),
            Action::None | Action::Quit | Action::Refresh => return,
        };
        let message = match done {
            Ok(text) => Update::Message(text, false),
            Err(err) => Update::Message(err.to_string(), true),
        };
        let _ = updates.send(message).await;
    });
}

/// Percent-encodes `text` for a query string.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_strings_are_encoded() {
        assert_eq!(encode("ads.example"), "ads.example");
        assert_eq!(encode("a b&c=d/é"), "a%20b%26c%3Dd%2F%C3%A9");
    }
}
