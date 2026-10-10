//! Confining goethite once it runs: Landlock limits the files it can open,
//! and a seccomp filter takes away system calls it never makes (ADR 0032).
//!
//! It is applied after privileges are dropped and before any thread starts:
//! Landlock restricts the calling thread and what it starts afterwards, not
//! the threads that already exist. Both are inherited across `execve`, so
//! the goethite an upgrade starts runs inside this one's sandbox before it
//! adds its own. That shapes the rules:
//!
//! - they name directories rather than files, since an upgrade, a renewed
//!   certificate or an edited config replaces files, and a rule holds on to
//!   the file it was made for;
//! - the system call filter lists what is taken away rather than what is
//!   allowed, so a newer goethite can still start inside an older one's.
//!
//! Linux only; elsewhere [`apply`] does nothing. A kernel without Landlock,
//! or without some of its rights, gets what it supports, and the log says
//! what that is.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use anyhow::Result;

use crate::config::Config;

/// System directories: programs, libraries and time zones.
const SYSTEM: [&str; 5] = ["/usr", "/lib", "/lib64", "/bin", "/sbin"];

/// What a process may do once confined.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Policy {
    /// What the process is, for the log.
    pub name: &'static str,
    /// Directories and files it may read and start programs from.
    pub run_from: BTreeSet<PathBuf>,
    /// Directories and files it may read.
    pub read: BTreeSet<PathBuf>,
    /// Directories it may read and change.
    pub write: BTreeSet<PathBuf>,
    /// Directories holding Unix sockets it may connect to.
    pub connect_unix: BTreeSet<PathBuf>,
    /// Whether it may start programs: an upgrade starts the new goethite.
    pub exec: bool,
    /// Whether it may open netlink and packet sockets, besides IPv4, IPv6
    /// and Unix ones.
    pub link_sockets: bool,
}

impl Policy {
    /// `goethite run`: the DNS server, the control plane and upgrades.
    ///
    /// It reads the system directories (and starts the new goethite from
    /// them, or from `binary`'s directory), the config file's directory,
    /// the directories of the certificates, keys and the services file it
    /// names, the local lists directory, `/proc` (an upgraded goethite
    /// counts its threads there) and, with `server.user`, the password file.
    /// It changes only the store's directory, the downloaded lists and the
    /// runtime directory, where upgrades meet.
    pub(crate) fn run(config: &Config, config_path: &Path, binary: &Path, runtime: &Path) -> Self {
        let mut policy = Self {
            name: "goethite run",
            exec: true,
            ..Self::default()
        };
        policy.run_from.extend(SYSTEM.iter().map(PathBuf::from));
        policy.run_from.extend(directories_of(binary));
        policy.read.extend(
            ["/etc/ld.so.cache", "/etc/localtime", "/proc"]
                .iter()
                .map(PathBuf::from),
        );
        if let Some(dir) = std::env::var_os("TZDIR") {
            policy.read.insert(PathBuf::from(dir));
        }
        if config.server.user.is_some() {
            policy.read.insert(PathBuf::from("/etc/passwd"));
        }
        policy.read.extend(directories_of(config_path));
        for file in files_read(config) {
            policy.read.extend(directories_of(&file));
        }
        policy.read.insert(config.local_lists_dir());
        policy.write.extend(directories_of(&config.store_path()));
        policy.write.insert(config.lists_dir());
        policy.write.insert(runtime.to_path_buf());
        policy.connect_unix.extend(notify_socket_dir());
        policy
    }

    /// `goethite witness`: it changes only its store's directory.
    pub(crate) fn witness(config: &Config) -> Self {
        let mut policy = Self {
            name: "goethite witness",
            ..Self::default()
        };
        policy.write.extend(directories_of(&config.store_path()));
        policy.connect_unix.extend(notify_socket_dir());
        policy
    }

    /// `goethite vrrp`: no files at all, once its sockets are open.
    #[cfg_attr(
        all(not(target_os = "linux"), not(test)),
        expect(dead_code, reason = "goethite vrrp runs on Linux only")
    )]
    pub(crate) fn vrrp() -> Self {
        let mut policy = Self {
            name: "goethite vrrp",
            link_sockets: true,
            ..Self::default()
        };
        policy.connect_unix.extend(notify_socket_dir());
        policy
    }
}

/// The files the config file names that goethite reads again after it
/// starts: certificates and keys (reloaded on `SIGHUP`, or read by an
/// upgraded goethite), the telemetry headers and CA (read by an upgraded
/// goethite) and the services catalog.
fn files_read(config: &Config) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Some(tls) = &config.server.tls {
        files.extend([tls.cert.clone(), tls.key.clone()]);
    }
    files.extend(config.api.tls_cert.iter().cloned());
    files.extend(config.api.tls_key.iter().cloned());
    if let Some(cluster) = &config.cluster {
        files.extend([
            cluster.ca.clone(),
            cluster.cert.clone(),
            cluster.key.clone(),
        ]);
    }
    files.extend(config.filter.services_file.iter().cloned());
    files.extend(config.telemetry.headers_file.iter().cloned());
    files.extend(config.telemetry.ca_file.iter().cloned());
    files
}

/// The directory holding `file`, as named and with symbolic links
/// resolved: a renewed certificate is often a new file behind a link.
fn directories_of(file: &Path) -> Vec<PathBuf> {
    let mut dirs: Vec<PathBuf> = file.parent().map(Path::to_path_buf).into_iter().collect();
    if let Some(resolved) = std::fs::canonicalize(file)
        .ok()
        .and_then(|path| path.parent().map(Path::to_path_buf))
        && !dirs.contains(&resolved)
    {
        dirs.push(resolved);
    }
    dirs
}

/// The directory of systemd's notification socket, unless it is abstract
/// (`@…`), which no file rule covers.
fn notify_socket_dir() -> Option<PathBuf> {
    let socket = PathBuf::from(std::env::var_os("NOTIFY_SOCKET")?);
    socket
        .is_absolute()
        .then(|| socket.parent().map(Path::to_path_buf))
        .flatten()
}

/// Confines this process by `policy`, as far as the kernel allows, and
/// logs how far that is. Call it before starting any thread.
///
/// # Errors
///
/// If the kernel refuses a sandbox it supports: `[security] sandbox =
/// false` turns it off.
#[cfg(target_os = "linux")]
pub(crate) fn apply(policy: &Policy) -> Result<()> {
    linux::apply(policy).map(drop)
}

/// Other platforms are for development only: nothing is confined.
#[cfg(not(target_os = "linux"))]
#[allow(clippy::unnecessary_wraps, reason = "the same signature as on Linux")]
pub(crate) fn apply(policy: &Policy) -> Result<()> {
    tracing::debug!(process = policy.name, "no sandbox on this platform");
    Ok(())
}

#[cfg(target_os = "linux")]
mod linux {
    use std::collections::BTreeMap;

    use anyhow::{Context, Result};
    use landlock::{
        ABI, Access, AccessFs, AccessNet, CompatLevel, Compatible, LandlockStatus, Ruleset,
        RulesetAttr, RulesetCreatedAttr, RulesetStatus, path_beneath_rules,
    };
    use seccompiler::{
        BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
        SeccompRule, TargetArch,
    };
    #[cfg(target_arch = "x86_64")]
    use seccompiler::sock_filter;
    use tracing::{debug, info, warn};

    use super::Policy;

    /// The newest Landlock this goethite knows; older kernels get what they
    /// support of it.
    const ABI_WANTED: ABI = ABI::V9;

    /// `EPERM`: what a denied system call returns, as if it were refused
    /// for want of a privilege.
    const EPERM: u32 = 1;

    /// The seccomp return values of the raw BPF program below: allow, and
    /// `EPERM` with the errno in its low 16 bits.
    #[cfg(target_arch = "x86_64")]
    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    #[cfg(target_arch = "x86_64")]
    const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0001;

    /// Denies the x32 system calls on x86-64.
    ///
    /// x32 shares the x86-64 audit architecture, so seccompiler's
    /// architecture check passes them, and each call number is the x86-64
    /// number with `0x40000000` set, which none of the rules names: without
    /// this, a denied call is reachable as its x32 number. Stacked with the
    /// named-call filter, it returns `EPERM` for every number at or above
    /// that bit, and lets everything else (including an i386 call, which
    /// the named-call filter declines on its own architecture check) pass.
    #[cfg(target_arch = "x86_64")]
    const X32_DENIED: [sock_filter; 6] = [
        // The audit architecture.
        sock_filter {
            code: 0x20, // BPF_LD | BPF_W | BPF_ABS
            jt: 0,
            jf: 0,
            k: 4,
        },
        // Not x86-64: to the allow, three instructions on.
        sock_filter {
            code: 0x15, // BPF_JMP | BPF_JEQ | BPF_K
            jt: 0,
            jf: 3,
            k: 0xc000_003e, // AUDIT_ARCH_X86_64
        },
        // The system call number.
        sock_filter {
            code: 0x20,
            jt: 0,
            jf: 0,
            k: 0,
        },
        // At or above the x32 bit: the deny below; under it: the allow.
        sock_filter {
            code: 0x35, // BPF_JMP | BPF_JGE | BPF_K
            jt: 0,
            jf: 1,
            k: 0x4000_0000,
        },
        sock_filter {
            code: 0x06, // BPF_RET | BPF_K
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO_EPERM,
        },
        sock_filter {
            code: 0x06,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ALLOW,
        },
    ];

    /// Socket families (the same numbers on every architecture).
    const AF_UNIX: u64 = 1;
    const AF_INET: u64 = 2;
    const AF_INET6: u64 = 10;
    const AF_NETLINK: u64 = 16;
    const AF_PACKET: u64 = 17;

    /// A system call goethite never makes, with its numbers on x86-64 and
    /// on 64-bit Arm (`None` where it does not exist).
    struct Denied {
        name: &'static str,
        x86_64: Option<i64>,
        aarch64: Option<i64>,
    }

    const fn both(name: &'static str, x86_64: i64, aarch64: i64) -> Denied {
        Denied {
            name,
            x86_64: Some(x86_64),
            aarch64: Some(aarch64),
        }
    }

    const fn x86_only(name: &'static str, x86_64: i64) -> Denied {
        Denied {
            name,
            x86_64: Some(x86_64),
            aarch64: None,
        }
    }

    /// Taken from every goethite: mounting, modules, rebooting, swapping,
    /// debugging other processes, BPF, `io_uring`, namespaces, keyrings, the
    /// clock and the host's names, file handles, and old x86 I/O. Most need
    /// privileges goethite has given up anyway; the rest (`ptrace`,
    /// `userfaultfd`, `io_uring_*`, `bpf`, `unshare`, `perf_event_open`)
    /// are common ways from a bug to the kernel.
    const DENIED: &[Denied] = &[
        both("mount", 165, 40),
        both("umount2", 166, 39),
        both("pivot_root", 155, 41),
        both("chroot", 161, 51),
        both("fsopen", 430, 430),
        both("fsconfig", 431, 431),
        both("fsmount", 432, 432),
        both("fspick", 433, 433),
        both("move_mount", 429, 429),
        both("open_tree", 428, 428),
        both("mount_setattr", 442, 442),
        both("swapon", 167, 224),
        both("swapoff", 168, 225),
        both("reboot", 169, 142),
        both("kexec_load", 246, 104),
        both("kexec_file_load", 320, 294),
        both("init_module", 175, 105),
        both("finit_module", 313, 273),
        both("delete_module", 176, 106),
        both("ptrace", 101, 117),
        both("process_vm_readv", 310, 270),
        both("process_vm_writev", 311, 271),
        both("perf_event_open", 298, 241),
        both("bpf", 321, 280),
        both("userfaultfd", 323, 282),
        both("keyctl", 250, 219),
        both("add_key", 248, 217),
        both("request_key", 249, 218),
        both("acct", 163, 89),
        both("quotactl", 179, 60),
        both("settimeofday", 164, 170),
        both("clock_settime", 227, 112),
        both("clock_adjtime", 305, 266),
        both("adjtimex", 159, 171),
        both("syslog", 103, 116),
        both("vhangup", 153, 58),
        both("sethostname", 170, 161),
        both("setdomainname", 171, 162),
        both("open_by_handle_at", 304, 265),
        both("name_to_handle_at", 303, 264),
        both("unshare", 272, 97),
        both("setns", 308, 268),
        both("io_uring_setup", 425, 425),
        both("io_uring_enter", 426, 426),
        both("io_uring_register", 427, 427),
        both("pidfd_getfd", 438, 438),
        both("lookup_dcookie", 212, 18),
        x86_only("iopl", 172),
        x86_only("ioperm", 173),
        x86_only("modify_ldt", 154),
        x86_only("uselib", 134),
    ];

    /// Starting programs, taken from processes that never do.
    const EXEC: &[Denied] = &[
        Denied {
            name: "execve",
            x86_64: Some(59),
            aarch64: Some(221),
        },
        Denied {
            name: "execveat",
            x86_64: Some(322),
            aarch64: Some(281),
        },
    ];

    /// `socket`.
    const SOCKET: Denied = Denied {
        name: "socket",
        x86_64: Some(41),
        aarch64: Some(198),
    };

    /// Confines this process. Returns the kernel's Landlock ABI and
    /// whether all of it is enforced, or `None` without Landlock.
    pub(super) fn apply(policy: &Policy) -> Result<Option<(i32, bool)>> {
        // Both Landlock and seccomp need it; dropping privileges set it
        // already, except for the witness.
        rustix::thread::set_no_new_privs(true).context("cannot set no_new_privs")?;
        let landlock = restrict_files(policy).context(
            "cannot restrict file access with Landlock (set [security] sandbox = false to run \
             without the sandbox)",
        )?;
        let denied = restrict_calls(policy).context(
            "cannot install the seccomp filter (set [security] sandbox = false to run without \
             the sandbox)",
        )?;
        // Not available: an older kernel, or a sandbox around goethite (a
        // systemd unit's or a container's system call filter) that refuses
        // the calls. That sandbox then confines goethite itself.
        let elsewhere = "an older kernel, or a sandbox around goethite that refuses it";
        match (landlock, denied) {
            (Some((abi, true)), Some(denied)) => info!(
                process = policy.name,
                landlock_abi = abi,
                system_calls_denied = denied,
                "sandboxed: Landlock limits files, seccomp system calls"
            ),
            (Some((abi, false)), Some(denied)) => info!(
                process = policy.name,
                landlock_abi = abi,
                system_calls_denied = denied,
                "sandboxed: Landlock limits files (as far as this kernel supports), seccomp \
                 system calls"
            ),
            (None, Some(denied)) => warn!(
                process = policy.name,
                system_calls_denied = denied,
                "Landlock is not available ({elsewhere}), so file access is not limited; \
                 seccomp limits system calls"
            ),
            (Some((abi, _)), None) => warn!(
                process = policy.name,
                landlock_abi = abi,
                "the seccomp filter is not available ({elsewhere}); Landlock limits files"
            ),
            (None, None) => warn!(
                process = policy.name,
                "neither Landlock nor the seccomp filter is available ({elsewhere}): goethite \
                 runs without its own sandbox"
            ),
        }
        Ok(landlock)
    }

    /// Restricts file access, and binding TCP ports, with Landlock.
    /// Returns the kernel's Landlock ABI and whether everything asked for
    /// is enforced, or `None` without Landlock.
    fn restrict_files(policy: &Policy) -> Result<Option<(i32, bool)>> {
        let read = AccessFs::ReadFile | AccessFs::ReadDir;
        let status = Ruleset::default()
            .set_compatibility(CompatLevel::BestEffort)
            .handle_access(AccessFs::from_all(ABI_WANTED))?
            // No new TCP listeners: they are all open before this.
            .handle_access(AccessNet::BindTcp)?
            .create()?
            .add_rules(path_beneath_rules(
                &policy.run_from,
                AccessFs::from_read(ABI_WANTED),
            ))?
            .add_rules(path_beneath_rules(&policy.read, read))?
            .add_rules(path_beneath_rules(
                &policy.write,
                AccessFs::from_all(ABI_WANTED),
            ))?
            .add_rules(path_beneath_rules(
                &policy.connect_unix,
                AccessFs::ResolveUnix,
            ))?
            .restrict_self()?;
        let abi = match status.landlock {
            LandlockStatus::Available { effective_abi, .. } => effective_abi as i32,
            _ => 0,
        };
        Ok(match status.ruleset {
            RulesetStatus::NotEnforced => None,
            RulesetStatus::PartiallyEnforced => Some((abi, false)),
            RulesetStatus::FullyEnforced => Some((abi, true)),
        })
    }

    /// Installs the seccomp filter. Returns how many system calls it
    /// denies, or `None` if the kernel refuses filters here.
    fn restrict_calls(policy: &Policy) -> Result<Option<usize>> {
        let arch = TargetArch::try_from(std::env::consts::ARCH)
            .context("no seccomp filter for this architecture")?;
        let number = |call: &Denied| match arch {
            TargetArch::x86_64 => call.x86_64,
            TargetArch::aarch64 => call.aarch64,
            TargetArch::riscv64 => None,
        };
        let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
        let mut names = Vec::new();
        let exec: &[Denied] = if policy.exec { &[] } else { EXEC };
        for call in DENIED.iter().chain(exec) {
            if let Some(number) = number(call) {
                rules.insert(number, Vec::new());
                names.push(call.name);
            }
        }
        let denied = rules.len();
        debug!(process = policy.name, calls = %names.join(" "), "seccomp denies");
        // Sockets of any other family are refused: one rule, true when the
        // family is none of those allowed.
        let mut families = vec![AF_UNIX, AF_INET, AF_INET6];
        if policy.link_sockets {
            families.extend([AF_NETLINK, AF_PACKET]);
        }
        let others = families
            .into_iter()
            .map(|family| {
                SeccompCondition::new(0, SeccompCmpArgLen::Dword, SeccompCmpOp::Ne, family)
            })
            .collect::<Result<Vec<_>, _>>()?;
        if let Some(number) = number(&SOCKET) {
            rules.insert(number, vec![SeccompRule::new(others)?]);
        }
        let filter = SeccompFilter::new(
            rules,
            SeccompAction::Allow,
            SeccompAction::Errno(EPERM),
            arch,
        )?;
        let program = BpfProgram::try_from(filter)?;
        // x32 calls pass the architecture check of the named-call filter and
        // match none of its rules: a raw filter stacked with it denies them.
        #[cfg(target_arch = "x86_64")]
        match seccompiler::apply_filter(&X32_DENIED) {
            Ok(()) => {}
            Err(err) if refused(&err) => {
                // An outer sandbox refuses the filter, as below; goethite is
                // confined by whatever refused it.
            }
            Err(err) => return Err(err.into()),
        }
        match seccompiler::apply_filter(&program) {
            Ok(()) => Ok(Some(denied)),
            // Refused rather than broken: an outer filter (EPERM, EACCES)
            // or a kernel without seccomp (ENOSYS). An invalid filter
            // (EINVAL) would be goethite's own bug, and stays an error.
            Err(err) if refused(&err) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    /// Whether seccomp refused a filter: an outer filter (EPERM, EACCES) or
    /// a kernel without seccomp (ENOSYS), rather than a bug of ours.
    fn refused(err: &seccompiler::Error) -> bool {
        matches!(
            err,
            seccompiler::Error::Seccomp(source)
                if matches!(source.raw_os_error(), Some(1 | 13 | 38))
        )
    }

    #[cfg(test)]
    mod tests {
        use std::path::PathBuf;

        use super::*;

        /// The variable that tells the test binary it runs as the child of
        /// [`a_confined_process_keeps_to_its_files_and_starts_nothing`],
        /// confined to the directory it names.
        const CHILD: &str = "GOETHITE_SANDBOX_TEST_DIR";

        /// A sandbox cannot be undone, so the test confines a child: the
        /// test binary itself, running this one test.
        #[test]
        fn a_confined_process_keeps_to_its_files_and_starts_nothing() {
            match std::env::var_os(CHILD) {
                Some(dir) => confined_child(&PathBuf::from(dir)),
                None => run_child("a_confined_process_keeps_to_its_files_and_starts_nothing"),
            }
        }

        /// A sandbox around goethite that refuses Landlock and seccomp, as
        /// an older systemd's filter does, leaves goethite running.
        #[test]
        fn an_outer_sandbox_refusing_the_calls_is_not_fatal() {
            match std::env::var_os(CHILD) {
                Some(dir) => refused_child(&PathBuf::from(dir)),
                None => run_child("an_outer_sandbox_refusing_the_calls_is_not_fatal"),
            }
        }

        /// An x32 system call (an x86-64 number with `0x40000000` set) is
        /// sent to the raw filter and denied, whatever the named-call
        /// filter says.
        #[test]
        #[cfg(target_arch = "x86_64")]
        fn x32_calls_are_denied() {
            match std::env::var_os(CHILD) {
                Some(_) => x32_child(),
                None => run_child("x32_calls_are_denied"),
            }
        }

        /// Applies the x32 filter and makes one x32 call: `EPERM`, or
        /// `ENOSYS` on a kernel built without x32.
        #[cfg(target_arch = "x86_64")]
        #[allow(unsafe_code, reason = "issuing the x32 call the filter denies")]
        fn x32_child() {
            seccompiler::apply_filter(&X32_DENIED).unwrap();
            // SAFETY: the x32 `getpid` call takes no arguments and writes
            // only the return register.
            let pid = unsafe {
                let pid: i64;
                std::arch::asm!(
                    "syscall",
                    in("rax") 0x4000_0027_u64, // x32 getpid
                    lateout("rax") pid,
                    out("rcx") _,
                    out("r11") _,
                );
                pid
            };
            assert!(pid < 0, "x32 getpid returned {pid}");
            let errno = -pid;
            assert!(errno == 1 || errno == 38, "x32 getpid failed with {errno}");
        }

        /// Runs the test `name` again in a child process, as the child.
        fn run_child(name: &str) {
            let dir = std::env::temp_dir().join(format!(
                "goethite-sandbox-child-{}-{name}",
                std::process::id()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    &format!("sandbox::linux::tests::{name}"),
                    "--nocapture",
                ])
                .env(CHILD, &dir)
                .output()
                .unwrap();
            std::fs::remove_dir_all(&dir).unwrap();
            assert!(
                output.status.success(),
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }

        fn refused_child(dir: &std::path::Path) {
            // The outer sandbox: `seccomp` and the Landlock calls refused.
            let arch = TargetArch::try_from(std::env::consts::ARCH).unwrap();
            let seccomp = match arch {
                TargetArch::x86_64 => 317,
                _ => 277,
            };
            let rules = [seccomp, 444, 445, 446]
                .into_iter()
                .map(|number| (number, Vec::new()))
                .collect();
            let outer = SeccompFilter::new(
                rules,
                SeccompAction::Allow,
                SeccompAction::Errno(EPERM),
                arch,
            )
            .unwrap();
            seccompiler::apply_filter(&BpfProgram::try_from(outer).unwrap()).unwrap();
            let policy = Policy {
                name: "test",
                write: [dir.to_path_buf()].into(),
                ..Policy::default()
            };
            assert_eq!(
                apply(&policy).unwrap(),
                None,
                "no Landlock behind the filter"
            );
            // Nothing of goethite's own sandbox applies.
            assert!(std::fs::read("/etc/hostname").is_ok());
            assert!(std::process::Command::new("/bin/true").status().is_ok());
        }

        fn confined_child(dir: &std::path::Path) {
            let policy = Policy {
                name: "test",
                write: [dir.to_path_buf()].into(),
                ..Policy::default()
            };
            let landlock = apply(&policy).unwrap();
            // Its own directory works.
            std::fs::write(dir.join("ok.txt"), "ok").unwrap();
            assert_eq!(std::fs::read_to_string(dir.join("ok.txt")).unwrap(), "ok");
            // Nothing else, with Landlock (a kernel without it has none).
            if landlock.is_some() {
                let err = std::fs::read("/etc/hostname").unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
                let err =
                    std::fs::write(std::env::temp_dir().join("goethite-escape"), "x").unwrap_err();
                assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
                // No new TCP listeners, with Landlock's network rules.
                if landlock.is_some_and(|(abi, _)| abi >= 4) {
                    assert!(std::net::TcpListener::bind("127.0.0.1:0").is_err());
                }
            }
            // No programs.
            let err = std::process::Command::new("/bin/true")
                .status()
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(1), "EPERM: {err}");
            // No sockets of other families (40 is AF_VSOCK).
            let err = socket2::Socket::new(socket2::Domain::from(40), socket2::Type::STREAM, None)
                .unwrap_err();
            assert_eq!(err.raw_os_error(), Some(1), "EPERM: {err}");
            // IPv4 sockets are fine.
            assert!(std::net::UdpSocket::bind("127.0.0.1:0").is_ok());
        }

        #[test]
        fn every_denied_call_has_a_name_and_numbers_are_distinct() {
            for arch in [TargetArch::x86_64, TargetArch::aarch64] {
                let mut seen = std::collections::HashSet::new();
                for call in DENIED.iter().chain(EXEC).chain([&SOCKET]) {
                    let number = match arch {
                        TargetArch::x86_64 => call.x86_64,
                        _ => call.aarch64,
                    };
                    if let Some(number) = number {
                        assert!(seen.insert(number), "{} repeats {number}", call.name);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policies_name_what_each_process_needs() {
        let mut config =
            Config::parse("[store]\npath = \"/var/lib/goethite/goethite.redb\"\n").unwrap();
        config.dir = PathBuf::from("/etc/goethite");
        let run = Policy::run(
            &config,
            Path::new("/etc/goethite/goethite.toml"),
            Path::new("/usr/bin/goethite"),
            Path::new("/run/goethite"),
        );
        assert!(run.exec);
        assert!(run.run_from.contains(Path::new("/usr")));
        assert!(run.run_from.contains(Path::new("/usr/bin")));
        assert!(run.read.contains(Path::new("/etc/goethite")));
        assert!(run.read.contains(Path::new("/etc/goethite/lists")));
        assert!(
            !run.read.contains(Path::new("/etc/passwd")),
            "no server.user"
        );
        assert!(run.write.contains(Path::new("/var/lib/goethite")));
        assert!(run.write.contains(Path::new("/run/goethite")));
        assert!(!run.link_sockets);

        let witness = Policy::witness(&config);
        assert!(!witness.exec);
        assert!(witness.read.is_empty() && witness.run_from.is_empty());
        assert_eq!(
            witness.write.iter().collect::<Vec<_>>(),
            [Path::new("/var/lib/goethite")]
        );

        let vrrp = Policy::vrrp();
        assert!(!vrrp.exec && vrrp.link_sockets);
        assert!(vrrp.read.is_empty() && vrrp.write.is_empty() && vrrp.run_from.is_empty());
    }

    #[test]
    fn certificate_directories_are_readable_through_links() {
        let dir = std::env::temp_dir().join(format!("goethite-sandbox-{}", std::process::id()));
        let archive = dir.join("archive");
        let live = dir.join("live");
        std::fs::create_dir_all(&archive).unwrap();
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(archive.join("cert1.pem"), "x").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(archive.join("cert1.pem"), live.join("cert.pem")).unwrap();
        let dirs = directories_of(&live.join("cert.pem"));
        assert_eq!(dirs[0], live);
        #[cfg(unix)]
        assert_eq!(dirs[1], std::fs::canonicalize(&archive).unwrap());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
