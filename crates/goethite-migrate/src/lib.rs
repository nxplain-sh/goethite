//! Moving to goethite from Pi-hole or AdGuard Home.
//!
//! [`pihole`] and [`adguard`] describe what those resolvers' HTTP APIs
//! return and turn it into a [`Plan`]: the lists, groups, clients, rules,
//! local records and settings goethite would get, and everything it leaves
//! out, with the reason. Nothing here touches the network; `goethite
//! migrate` fetches the source's configuration, prints the plan, and applies
//! it through goethite's API when asked to.
//!
//! The source's answers are untrusted input: every planned resource is
//! checked the way goethite's store would check it, so a plan never holds
//! something goethite refuses.

#![forbid(unsafe_code)]

pub mod adguard;
pub mod pihole;
mod plan;

pub use plan::{Plan, PlannedClient, PlannedGroup, Skipped, base64};
