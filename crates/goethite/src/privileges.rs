//! Giving up privileges once the listen sockets are bound.
//!
//! goethite needs privileges only to bind port 53. Started as root with
//! `server.user` set, it switches to that user and group with no
//! supplementary groups. Started by systemd as an unprivileged user with
//! `CAP_NET_BIND_SERVICE`, it gives the capability up. Either way it then sets
//! `no_new_privs` and checks that the privileges are really gone.
//!
//! On Linux the system calls that change user IDs and capabilities only
//! affect the calling thread, so this must run before the async runtime
//! starts its threads; it refuses to run in a process with more than one.
//! Other platforms are for development only: there, `server.user` is an
//! error and nothing else is done.

use std::fs::File;
use std::io::Read;

use anyhow::{Context, Result, bail};

/// Where users are looked up.
const PASSWD: &str = "/etc/passwd";

/// Larger password files are refused.
const MAX_PASSWD_LEN: u64 = 16 * 1024 * 1024;

/// A user to run as.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Account {
    /// The user name.
    pub name: String,
    /// Its user ID.
    pub uid: u32,
    /// Its primary group ID.
    pub gid: u32,
}

/// Looks `name` up in `/etc/passwd`. Users known only to other name services
/// (LDAP, systemd-homed) are not found: goethite does not use the C
/// library's name service switch.
pub(crate) fn lookup(name: &str) -> Result<Account> {
    let mut text = String::new();
    File::open(PASSWD)
        .and_then(|file| file.take(MAX_PASSWD_LEN).read_to_string(&mut text))
        .with_context(|| format!("cannot read {PASSWD}"))?;
    let account = find_account(&text, name)
        .with_context(|| format!("server.user: no user {name:?} in {PASSWD}"))?;
    if account.uid == 0 {
        bail!("server.user: {name:?} is root; use an unprivileged user");
    }
    Ok(account)
}

/// Finds `name` in the text of a password file: lines of
/// `name:password:uid:gid:...`.
fn find_account(passwd: &str, name: &str) -> Option<Account> {
    passwd.lines().find_map(|line| {
        let mut fields = line.split(':');
        if fields.next()? != name {
            return None;
        }
        let _password = fields.next()?;
        let uid = fields.next()?.parse().ok()?;
        let gid = fields.next()?.parse().ok()?;
        Some(Account {
            name: name.to_owned(),
            uid,
            gid,
        })
    })
}

/// Switches to `account` if running as root, gives up every capability, and
/// sets `no_new_privs`. Call it after binding the sockets and before
/// starting any thread.
#[cfg(target_os = "linux")]
pub(crate) fn drop_privileges(account: Option<&Account>) -> Result<()> {
    use rustix::process::{Gid, Uid, getegid, geteuid, getgid, getuid};
    use rustix::thread::{
        CapabilitySet, CapabilitySets, capabilities, set_capabilities, set_no_new_privs,
        set_thread_groups, set_thread_res_gid, set_thread_res_uid,
    };
    use tracing::{info, warn};

    let threads = std::fs::read_dir("/proc/self/task")
        .context("cannot count the process's threads in /proc/self/task")?
        .count();
    if threads != 1 {
        bail!("cannot drop privileges: the process already runs {threads} threads");
    }

    if let Some(account) = account {
        let uid = Uid::from_raw(account.uid);
        let gid = Gid::from_raw(account.gid);
        if geteuid().is_root() {
            set_thread_groups(&[]).context("cannot clear the supplementary groups")?;
            set_thread_res_gid(gid, gid, gid)
                .with_context(|| format!("cannot switch to group {}", account.gid))?;
            set_thread_res_uid(uid, uid, uid)
                .with_context(|| format!("cannot switch to user {:?}", account.name))?;
        } else if geteuid() != uid {
            bail!(
                "server.user is {:?}, but goethite runs as user {} and is not root",
                account.name,
                geteuid().as_raw()
            );
        }
    } else if geteuid().is_root() {
        warn!("running as root: set server.user to drop root privileges after binding");
    }

    // Nothing needs a capability once the sockets are bound. Emptying the
    // permitted set empties the ambient set too.
    let none = CapabilitySets {
        effective: CapabilitySet::empty(),
        permitted: CapabilitySet::empty(),
        inheritable: CapabilitySet::empty(),
    };
    set_capabilities(None, none).context("cannot give up capabilities")?;
    set_no_new_privs(true).context("cannot set no_new_privs")?;

    // Check rather than trust.
    let left = capabilities(None).context("cannot read capabilities")?;
    if !left.effective.is_empty() || !left.permitted.is_empty() {
        bail!("capabilities remain after dropping them: {left:?}");
    }
    if let Some(account) = account {
        let (uid, gid) = (Uid::from_raw(account.uid), Gid::from_raw(account.gid));
        if getuid() != uid || geteuid() != uid || getgid() != gid || getegid() != gid {
            bail!("the user or group did not change to {:?}", account.name);
        }
        if set_thread_res_uid(Uid::ROOT, Uid::ROOT, Uid::ROOT).is_ok() {
            bail!("root privileges could be regained after dropping them");
        }
        info!(
            user = %account.name,
            uid = account.uid,
            gid = account.gid,
            "dropped privileges"
        );
    } else {
        info!("dropped capabilities");
    }
    Ok(())
}

/// Keeps only `CAP_NET_ADMIN`, for `goethite vrrp` once its sockets are
/// open, and sets `no_new_privs`. Call it before starting any thread.
#[cfg(target_os = "linux")]
pub(crate) fn keep_net_admin() -> Result<()> {
    use rustix::process::geteuid;
    use rustix::thread::{
        CapabilitySet, CapabilitySets, capabilities, set_capabilities, set_no_new_privs,
    };
    use tracing::{info, warn};

    let threads = std::fs::read_dir("/proc/self/task")
        .context("cannot count the process's threads in /proc/self/task")?
        .count();
    if threads != 1 {
        bail!("cannot drop privileges: the process already runs {threads} threads");
    }
    let keep = CapabilitySet::NET_ADMIN;
    let held = capabilities(None).context("cannot read capabilities")?;
    if !held.permitted.contains(keep) {
        bail!("goethite vrrp needs CAP_NET_ADMIN to add and remove the floating IP");
    }
    // The ambient set follows: it cannot hold what is not inheritable.
    let only = CapabilitySets {
        effective: keep,
        permitted: keep,
        inheritable: CapabilitySet::empty(),
    };
    set_capabilities(None, only).context("cannot give up capabilities")?;
    set_no_new_privs(true).context("cannot set no_new_privs")?;
    let left = capabilities(None).context("cannot read capabilities")?;
    if left.effective != keep || left.permitted != keep {
        bail!("capabilities other than CAP_NET_ADMIN remain: {left:?}");
    }
    if geteuid().is_root() {
        warn!("running as root: the systemd unit runs goethite vrrp as an unprivileged user");
    }
    info!("kept only CAP_NET_ADMIN");
    Ok(())
}

/// Other platforms are for development only: `server.user` is refused.
#[cfg(not(target_os = "linux"))]
pub(crate) fn drop_privileges(account: Option<&Account>) -> Result<()> {
    if account.is_some() {
        bail!("server.user is only supported on Linux");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PASSWD_TEXT: &str = "\
root:x:0:0:root:/root:/bin/bash
# a comment
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
broken:x:not-a-number:5::/:/bin/false
goethite:x:999:998:goethite DNS:/var/lib/goethite:/usr/sbin/nologin
short:x
+nis
";

    #[test]
    fn finds_accounts() {
        assert_eq!(
            find_account(PASSWD_TEXT, "goethite"),
            Some(Account {
                name: "goethite".into(),
                uid: 999,
                gid: 998
            })
        );
        assert_eq!(find_account(PASSWD_TEXT, "root").map(|a| a.uid), Some(0));
        for missing in ["broken", "short", "nobody", "", "goethite:x", "+nis"] {
            assert_eq!(find_account(PASSWD_TEXT, missing), None, "{missing}");
        }
    }

    proptest::proptest! {
        /// Any text: no panic, and a well-formed line for the name is found
        /// among arbitrary other lines.
        #[test]
        fn finds_its_line_among_any_others(
            before in "[^\n]{0,200}",
            after in "(?s).{0,200}",
            name in "[a-z_][a-z0-9_-]{0,31}",
            uid in proptest::prelude::any::<u32>(),
            gid in proptest::prelude::any::<u32>(),
        ) {
            let _ = find_account(&format!("{before}\n{after}"), &name);
            let line = format!("{name}:x:{uid}:{gid}:Some User:/home:/bin/false");
            let text = format!("{before}\n{line}\n{after}");
            let found = find_account(&text, &name).unwrap();
            // An earlier line for the same name wins, as with getpwnam.
            if !before.starts_with(&format!("{name}:")) {
                proptest::prop_assert_eq!(found, Account { name: name.clone(), uid, gid });
            }
        }
    }

    #[test]
    fn never_panics_on_odd_files() {
        for text in [
            "",
            ":",
            "::::",
            "\n\n",
            "a:b:c:d",
            "a:b:4294967296:1",
            "é:x:1:1",
        ] {
            let _ = find_account(text, "a");
            let _ = find_account(text, "é");
        }
    }
}
