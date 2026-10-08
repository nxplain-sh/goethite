//! The VRRP state machine (RFC 5798, section 6.4).
//!
//! It does no I/O: time, advertisements and health checks go in, and
//! [`Action`]s come out for the caller to carry out, so every transition
//! can be tested with made-up time.
//!
//! goethite adds a state to the RFC's two running ones. A node whose DNS
//! server fails its health checks is in [`State::Fault`]: it neither
//! advertises nor holds the address, so its peer takes over. A node starts
//! there, and becomes a backup once its first health check passes.

use std::fmt;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

/// What the state machine knows about this node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Settings {
    /// This node's priority, 1 to 254: of two healthy nodes, the higher
    /// holds the address.
    pub priority: u8,
    /// How often to advertise as master, in centiseconds, 1 to 4095.
    pub interval: u16,
    /// Whether to take the address from a master of lower priority.
    pub preempt: bool,
    /// This node's address, which breaks ties between equal priorities.
    pub address: Ipv4Addr,
}

/// Where a node stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// Unhealthy, or not yet known to be healthy: no address, no
    /// advertisements.
    Fault,
    /// Healthy, and listening to the master: takes over when it falls
    /// silent.
    Backup,
    /// Holds the address and advertises.
    Master,
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Fault => "fault",
            Self::Backup => "backup",
            Self::Master => "master",
        })
    }
}

/// Something for the caller to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Send an advertisement with this priority: 0 to hand over at once.
    Advertise(u8),
    /// Add the address to the interface and announce it.
    Take,
    /// Remove the address from the interface.
    Release,
}

/// An advertisement from the peer, checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Heard {
    /// The peer's priority.
    pub priority: u8,
    /// The peer's interval, in centiseconds.
    pub interval: u16,
    /// The peer's address.
    pub source: Ipv4Addr,
}

/// One node's VRRP state machine.
#[derive(Debug)]
pub struct Machine {
    settings: Settings,
    state: State,
    /// The master's interval, as last heard (`Master_Adver_Interval`).
    master_interval: u16,
    /// When the advertisement timer (as master) or the master-down timer
    /// (as backup) fires.
    deadline: Option<Instant>,
}

impl Machine {
    /// A machine in [`State::Fault`], waiting for a health check.
    pub fn new(settings: Settings) -> Self {
        Self {
            settings,
            state: State::Fault,
            master_interval: settings.interval,
            deadline: None,
        }
    }

    /// The current state.
    pub fn state(&self) -> State {
        self.state
    }

    /// When to call [`Machine::tick`] next, if at all.
    pub fn deadline(&self) -> Option<Instant> {
        self.deadline
    }

    /// The result of a health check.
    pub fn health(&mut self, healthy: bool, now: Instant) -> Vec<Action> {
        match (self.state, healthy) {
            (State::Fault, true) => {
                self.become_backup(self.settings.interval, now);
                Vec::new()
            }
            (State::Backup, false) => {
                self.become_fault();
                Vec::new()
            }
            (State::Master, false) => {
                self.become_fault();
                vec![Action::Advertise(0), Action::Release]
            }
            _ => Vec::new(),
        }
    }

    /// Time passed: fires the timer once its deadline is reached.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        if self.deadline.is_none_or(|deadline| deadline > now) {
            return Vec::new();
        }
        match self.state {
            State::Fault => Vec::new(),
            // The master fell silent.
            State::Backup => {
                self.state = State::Master;
                self.deadline = now.checked_add(self.interval());
                vec![Action::Advertise(self.settings.priority), Action::Take]
            }
            State::Master => {
                self.deadline = now.checked_add(self.interval());
                vec![Action::Advertise(self.settings.priority)]
            }
        }
    }

    /// An advertisement from the peer arrived.
    pub fn heard(&mut self, heard: Heard, now: Instant) -> Vec<Action> {
        match self.state {
            State::Fault => Vec::new(),
            State::Backup => {
                if heard.priority == 0 {
                    // The master is stepping down: take over soon.
                    self.deadline = now.checked_add(self.skew());
                } else if !self.settings.preempt || heard.priority >= self.settings.priority {
                    self.become_backup(heard.interval, now);
                }
                // Otherwise the master has a lower priority: let the timer
                // run out, and take over.
                Vec::new()
            }
            State::Master => {
                if heard.priority == 0 {
                    // The peer stepped down: show at once who is master.
                    self.deadline = now.checked_add(self.interval());
                    vec![Action::Advertise(self.settings.priority)]
                } else if (heard.priority, heard.source)
                    > (self.settings.priority, self.settings.address)
                {
                    // Addresses compare as unsigned integers in network
                    // byte order, as the RFC asks.
                    self.become_backup(heard.interval, now);
                    vec![Action::Release]
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// Stopping: a master hands over at once.
    pub fn shutdown(&mut self) -> Vec<Action> {
        let was = self.state;
        self.become_fault();
        if was == State::Master {
            vec![Action::Advertise(0), Action::Release]
        } else {
            Vec::new()
        }
    }

    fn become_backup(&mut self, master_interval: u16, now: Instant) {
        self.state = State::Backup;
        self.master_interval = master_interval.max(1);
        self.deadline = now.checked_add(self.master_down());
    }

    fn become_fault(&mut self) {
        self.state = State::Fault;
        self.deadline = None;
    }

    fn interval(&self) -> Duration {
        centiseconds(u32::from(self.settings.interval.max(1)))
    }

    /// `Skew_Time`: a lower priority waits a little longer, so the higher
    /// one wins when the master goes silent.
    fn skew(&self) -> Duration {
        let wait = 256_u32.saturating_sub(u32::from(self.settings.priority));
        centiseconds(wait.saturating_mul(u32::from(self.master_interval)) / 256)
    }

    /// `Master_Down_Interval`: three missed advertisements and the skew.
    fn master_down(&self) -> Duration {
        centiseconds(3_u32.saturating_mul(u32::from(self.master_interval)))
            .saturating_add(self.skew())
    }
}

fn centiseconds(count: u32) -> Duration {
    Duration::from_millis(u64::from(count).saturating_mul(10))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 10);
    const NOTHING: [Action; 0] = [];
    const PEER: Ipv4Addr = Ipv4Addr::new(192, 168, 1, 11);

    fn settings(priority: u8) -> Settings {
        Settings {
            priority,
            interval: 100,
            preempt: true,
            address: ME,
        }
    }

    fn peer(priority: u8) -> Heard {
        Heard {
            priority,
            interval: 100,
            source: PEER,
        }
    }

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    /// A healthy machine left alone becomes master once the master-down
    /// interval (3 s plus the skew) passes.
    fn master(priority: u8, start: Instant) -> Machine {
        let mut machine = Machine::new(settings(priority));
        assert_eq!(machine.health(true, start), NOTHING);
        let deadline = machine.deadline().unwrap();
        assert_eq!(
            machine.tick(deadline),
            [Action::Advertise(priority), Action::Take]
        );
        assert_eq!(machine.state(), State::Master);
        machine
    }

    #[test]
    fn starts_in_fault_and_waits_for_health() {
        let now = Instant::now();
        let mut machine = Machine::new(settings(100));
        assert_eq!(machine.state(), State::Fault);
        assert_eq!(machine.deadline(), None);
        assert_eq!(machine.tick(now + ms(10_000)), NOTHING);
        assert_eq!(machine.heard(peer(50), now), NOTHING);
        assert_eq!(machine.state(), State::Fault);

        machine.health(true, now);
        assert_eq!(machine.state(), State::Backup);
        // 3 × 1 s, plus a skew of (256 - 100) × 1 s / 256 = 0.6 s.
        assert_eq!(machine.deadline(), Some(now + ms(3_600)));
    }

    #[test]
    fn takes_over_when_the_master_goes_silent() {
        let start = Instant::now();
        let mut machine = Machine::new(settings(100));
        machine.health(true, start);
        assert_eq!(machine.tick(start + ms(3_599)), NOTHING, "too early");
        assert_eq!(machine.state(), State::Backup);
        machine = master(100, start);
        // Then advertises every interval.
        let next = machine.deadline().unwrap();
        assert_eq!(machine.tick(next), [Action::Advertise(100)]);
        assert_eq!(machine.deadline(), Some(next + ms(1_000)));
    }

    #[test]
    fn a_backup_hearing_the_master_waits_longer() {
        let start = Instant::now();
        let mut machine = Machine::new(settings(100));
        machine.health(true, start);
        let later = start + ms(3_000);
        assert_eq!(machine.heard(peer(150), later), NOTHING);
        assert_eq!(machine.deadline(), Some(later + ms(3_600)));
        // The master's interval is learned.
        let slow = Heard {
            interval: 200,
            ..peer(150)
        };
        machine.heard(slow, later);
        // 3 × 2 s, plus (256 - 100) × 2 s / 256 = 1.21875 s, in whole
        // centiseconds.
        assert_eq!(machine.deadline(), Some(later + ms(7_210)));
    }

    #[test]
    fn a_master_stepping_down_hands_over_after_the_skew() {
        let start = Instant::now();
        let mut machine = Machine::new(settings(100));
        machine.health(true, start);
        assert_eq!(machine.heard(peer(0), start), NOTHING);
        assert_eq!(machine.deadline(), Some(start + ms(600)));
    }

    #[test]
    fn preemption() {
        let start = Instant::now();
        // A backup of higher priority ignores a lower master and takes over.
        let mut machine = Machine::new(settings(200));
        machine.health(true, start);
        let first = machine.deadline().unwrap();
        machine.heard(peer(100), start + ms(500));
        assert_eq!(machine.deadline(), Some(first), "the timer keeps running");

        // Without preemption it stays a backup.
        let mut machine = Machine::new(Settings {
            preempt: false,
            ..settings(200)
        });
        machine.health(true, start);
        machine.heard(peer(100), start + ms(500));
        assert!(machine.deadline().unwrap() > first);
        assert_eq!(machine.state(), State::Backup);
    }

    #[test]
    fn a_master_yields_to_a_higher_priority() {
        let start = Instant::now();
        let mut machine = master(100, start);
        let now = start + ms(5_000);
        assert_eq!(machine.heard(peer(50), now), NOTHING, "lower: ignored");
        assert_eq!(machine.state(), State::Master);
        assert_eq!(machine.heard(peer(150), now), [Action::Release]);
        assert_eq!(machine.state(), State::Backup);
        // (256 - 100) × 1 s / 256 = 0.609375 s, in whole centiseconds.
        assert_eq!(machine.deadline(), Some(now + ms(3_600)));
    }

    #[test]
    fn equal_priorities_go_to_the_higher_address() {
        let start = Instant::now();
        let mut machine = master(100, start);
        let lower = Heard {
            source: Ipv4Addr::new(192, 168, 1, 9),
            ..peer(100)
        };
        assert_eq!(machine.heard(lower, start), NOTHING);
        assert_eq!(machine.state(), State::Master);
        // 192.168.1.11 is higher than 192.168.1.10.
        assert_eq!(machine.heard(peer(100), start), [Action::Release]);
        assert_eq!(machine.state(), State::Backup);
    }

    #[test]
    fn a_master_answers_a_peer_stepping_down() {
        let start = Instant::now();
        let mut machine = master(100, start);
        let now = start + ms(4_000);
        assert_eq!(machine.heard(peer(0), now), [Action::Advertise(100)]);
        assert_eq!(machine.deadline(), Some(now + ms(1_000)));
    }

    #[test]
    fn failing_health_checks_hand_over() {
        let start = Instant::now();
        let mut machine = master(100, start);
        assert_eq!(
            machine.health(false, start),
            [Action::Advertise(0), Action::Release]
        );
        assert_eq!(machine.state(), State::Fault);
        assert_eq!(machine.deadline(), None);
        assert_eq!(machine.health(false, start), NOTHING);

        // A backup just stops listening.
        let mut machine = Machine::new(settings(100));
        machine.health(true, start);
        assert_eq!(machine.health(false, start), NOTHING);
        assert_eq!(machine.state(), State::Fault);

        // Healthy again: a backup first, never straight to master.
        assert_eq!(machine.health(true, start), NOTHING);
        assert_eq!(machine.state(), State::Backup);
    }

    #[test]
    fn shutting_down_hands_over() {
        let start = Instant::now();
        let mut machine = master(100, start);
        assert_eq!(machine.shutdown(), [Action::Advertise(0), Action::Release]);
        assert_eq!(machine.state(), State::Fault);
        let mut machine = Machine::new(settings(100));
        machine.health(true, start);
        assert_eq!(machine.shutdown(), NOTHING);
    }

    #[test]
    fn odd_values_do_not_panic() {
        let start = Instant::now();
        for priority in [0, 1, 254, 255] {
            for interval in [0, 1, 4095, u16::MAX] {
                let mut machine = Machine::new(Settings {
                    interval,
                    ..settings(priority)
                });
                machine.health(true, start);
                machine.heard(
                    Heard {
                        interval,
                        ..peer(priority)
                    },
                    start,
                );
                machine.tick(start + ms(1_000_000));
                machine.tick(start + ms(2_000_000));
                machine.shutdown();
            }
        }
    }
}
