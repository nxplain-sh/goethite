//! Upgrading without dropping a query: the running goethite starts the new
//! binary and hands it its listening sockets.
//!
//! On `SIGUSR2` the running process, the parent:
//!
//! 1. listens on a private Unix socket and starts the binary from the path
//!    it was itself started from, with that socket's path in
//!    `GOETHITE_HANDOFF`;
//! 2. checks that the process connecting is that child (`SO_PEERCRED`) and
//!    sends it every listening socket (`SCM_RIGHTS`) and the keys it read;
//! 3. once the child has them, stops its own control plane, closing the
//!    store, and says so;
//! 4. the child opens the store, starts up and starts answering, and says
//!    so;
//! 5. the parent stops answering, finishes the queries in flight and exits.
//!
//! Until step 5 the parent answers every query, so none is lost; both read
//! the same sockets for a moment. If the child fails before step 3 the
//! parent carries on; after it, it starts its control plane again.
//!
//! Messages are JSON, one per `SOCK_SEQPACKET` packet, so each arrives
//! whole with its descriptors. Every step is bounded in time. Linux only:
//! other platforms are for development.

#[cfg(not(target_os = "linux"))]
use std::path::Path;

#[cfg(not(target_os = "linux"))]
use anyhow::Result;

#[cfg(not(target_os = "linux"))]
use crate::secrets::Secrets;
#[cfg(not(target_os = "linux"))]
use crate::sockets::Sockets;

/// The environment variable that tells a new goethite where to connect.
pub(crate) const ENV: &str = "GOETHITE_HANDOFF";

#[cfg(target_os = "linux")]
pub(crate) use linux::{Child, Parent};

#[cfg(target_os = "linux")]
mod linux {
    use std::io::{IoSlice, IoSliceMut};
    use std::mem::MaybeUninit;
    use std::os::fd::{BorrowedFd, OwnedFd};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::time::{Duration, Instant};

    use anyhow::{Context, Result, bail};
    use rustix::net::sockopt::{Timeout, set_socket_timeout, socket_peercred};
    use rustix::net::{
        AddressFamily, RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags,
        SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix, SocketFlags,
        SocketType, accept_with, bind, connect, listen, recvmsg, sendmsg, socket_with,
    };
    use serde::{Deserialize, Serialize};
    use tracing::info;

    use super::ENV;
    use crate::secrets::Secrets;
    use crate::sockets::Sockets;

    /// Descriptors per message, well below the kernel's limit of 253.
    const FDS_PER_MESSAGE: usize = 200;

    /// What parent and child tell each other.
    #[derive(Debug, Serialize, Deserialize)]
    #[serde(tag = "type", rename_all = "snake_case")]
    enum Message {
        /// The child, connected.
        Hello {
            /// Its goethite version.
            version: String,
        },
        /// Sockets, attached, in the order of `names`; `more` if another
        /// message follows. The first carries the keys.
        Sockets {
            names: Vec<String>,
            secrets: Option<Secrets>,
            more: bool,
        },
        /// The child has the sockets and is ready for the store.
        Adopted,
        /// The parent closed the store.
        StoreReleased,
        /// The child answers queries.
        Serving,
        /// The child gave up.
        Failed { reason: String },
    }

    /// How long the new process may take to connect.
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(15);

    /// How long one step may take: starting up includes building the
    /// filter, which takes a few seconds for millions of rules.
    const STEP_TIMEOUT: Duration = Duration::from_secs(120);

    /// The largest message: names and keys.
    const MAX_MESSAGE: usize = 1024 * 1024;

    fn send(socket: &OwnedFd, message: &Message, fds: &[BorrowedFd<'_>]) -> Result<()> {
        let bytes = serde_json::to_vec(message)?;
        let mut space = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(fds.len()))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(fds)) {
            bail!("too many sockets for one message");
        }
        sendmsg(
            socket,
            &[IoSlice::new(&bytes)],
            &mut control,
            SendFlags::empty(),
        )
        .context("cannot send to the other goethite")?;
        Ok(())
    }

    fn receive(socket: &OwnedFd) -> Result<(Message, Vec<OwnedFd>)> {
        let mut buffer = vec![0_u8; MAX_MESSAGE];
        let mut space =
            vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(FDS_PER_MESSAGE))];
        let mut control = RecvAncillaryBuffer::new(&mut space);
        let received = recvmsg(
            socket,
            &mut [IoSliceMut::new(&mut buffer)],
            &mut control,
            RecvFlags::CMSG_CLOEXEC,
        )
        .context("no word from the other goethite")?;
        if received.flags.contains(ReturnFlags::TRUNC)
            || received.flags.contains(ReturnFlags::CTRUNC)
        {
            bail!("a message from the other goethite was cut short");
        }
        if received.bytes == 0 {
            bail!("the other goethite went away");
        }
        let mut fds = Vec::new();
        for message in control.drain() {
            if let RecvAncillaryMessage::ScmRights(received) = message {
                fds.extend(received);
            }
        }
        let message = buffer
            .get(..received.bytes)
            .context("a message longer than its buffer")?;
        Ok((serde_json::from_slice(message)?, fds))
    }

    fn timeouts(socket: &OwnedFd) -> Result<()> {
        set_socket_timeout(socket, Timeout::Recv, Some(STEP_TIMEOUT))?;
        set_socket_timeout(socket, Timeout::Send, Some(STEP_TIMEOUT))?;
        Ok(())
    }

    /// The running goethite's side.
    pub(crate) struct Parent {
        socket: OwnedFd,
        child: std::process::Child,
    }

    impl Parent {
        /// Starts `binary` (`goethite run --config <config>`), listening
        /// for it on a socket in `dir`, and waits for it to connect.
        ///
        /// # Errors
        ///
        /// If it cannot start, does not connect in time, or another
        /// process connects.
        pub(crate) fn spawn(binary: &Path, config: &Path, dir: &Path) -> Result<Self> {
            let path = dir.join(format!("handoff-{}.sock", std::process::id()));
            let _ = std::fs::remove_file(&path);
            let listener = socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC | SocketFlags::NONBLOCK,
                None,
            )?;
            bind(&listener, &SocketAddrUnix::new(path.as_path())?)
                .with_context(|| format!("cannot listen on {}", path.display()))?;
            let cleanup = Cleanup(path.clone());
            {
                use std::os::unix::fs::PermissionsExt as _;
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            }
            listen(&listener, 1)?;
            let mut child = Command::new(binary)
                .args(["run", "--config"])
                .arg(config)
                .env(ENV, &path)
                .env_remove("LISTEN_PID")
                .env_remove("LISTEN_FDS")
                .env_remove("LISTEN_FDNAMES")
                .spawn()
                .with_context(|| format!("cannot start {}", binary.display()))?;
            info!(pid = child.id(), binary = %binary.display(), "started the new goethite");
            let started = Instant::now();
            let socket = loop {
                match accept_with(&listener, SocketFlags::CLOEXEC) {
                    Ok(socket) => break socket,
                    Err(err) if err == rustix::io::Errno::AGAIN => {
                        if let Some(status) = child.try_wait()? {
                            bail!("the new goethite exited before connecting: {status}");
                        }
                        if started.elapsed() > CONNECT_TIMEOUT {
                            let _ = child.kill();
                            let _ = child.wait();
                            bail!("the new goethite did not connect in time");
                        }
                        std::thread::sleep(Duration::from_millis(20));
                    }
                    Err(err) => return Err(err).context("cannot accept the new goethite"),
                }
            };
            // Accepted sockets do not inherit the listener's non-blocking flag.
            drop(cleanup);
            timeouts(&socket)?;
            let peer = socket_peercred(&socket)?;
            let pid = u32::try_from(peer.pid.as_raw_nonzero().get()).unwrap_or_default();
            if pid != child.id() {
                let _ = child.kill();
                let _ = child.wait();
                bail!("process {pid} connected instead of the new goethite");
            }
            let mut parent = Self { socket, child };
            match receive(&parent.socket)? {
                (Message::Hello { version }, _) => {
                    info!(version, "the new goethite connected");
                }
                (other, _) => {
                    parent.abandon();
                    bail!("unexpected first message from the new goethite: {other:?}");
                }
            }
            Ok(parent)
        }

        /// Sends every socket and the keys.
        ///
        /// # Errors
        ///
        /// If sending fails.
        pub(crate) fn send_sockets(&self, sockets: &Sockets, secrets: &Secrets) -> Result<()> {
            let all: Vec<(&str, BorrowedFd<'_>)> = sockets.named().collect();
            let chunks: Vec<_> = all.chunks(FDS_PER_MESSAGE).collect();
            let last = chunks.len().saturating_sub(1);
            for (index, chunk) in chunks.iter().enumerate() {
                let message = Message::Sockets {
                    names: chunk.iter().map(|(name, _)| (*name).to_owned()).collect(),
                    secrets: (index == 0).then(|| secrets.clone()),
                    more: index < last,
                };
                let fds: Vec<BorrowedFd<'_>> = chunk.iter().map(|(_, fd)| *fd).collect();
                send(&self.socket, &message, &fds)?;
            }
            Ok(())
        }

        /// Waits for the child to have the sockets.
        ///
        /// # Errors
        ///
        /// If it failed or went away.
        pub(crate) fn wait_adopted(&mut self) -> Result<()> {
            self.expect("taking the sockets", |message| {
                matches!(message, Message::Adopted)
            })
        }

        /// Tells the child the store is closed.
        ///
        /// # Errors
        ///
        /// If it went away.
        pub(crate) fn store_released(&self) -> Result<()> {
            send(&self.socket, &Message::StoreReleased, &[])
        }

        /// Waits for the child to answer queries.
        ///
        /// # Errors
        ///
        /// If it failed or went away.
        pub(crate) fn wait_serving(&mut self) -> Result<()> {
            self.expect("starting up", |message| matches!(message, Message::Serving))
        }

        fn expect(&mut self, step: &str, wanted: impl Fn(&Message) -> bool) -> Result<()> {
            match receive(&self.socket) {
                Ok((message, _)) if wanted(&message) => Ok(()),
                Ok((Message::Failed { reason }, _)) => {
                    bail!("the new goethite failed {step}: {reason}")
                }
                Ok((other, _)) => bail!("unexpected message from the new goethite: {other:?}"),
                Err(err) => Err(err.context(format!("the new goethite failed {step}"))),
            }
        }

        /// Gives up: stops the child.
        pub(crate) fn abandon(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }

    /// Removes the listening socket's file.
    struct Cleanup(PathBuf);

    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// The new goethite's side.
    pub(crate) struct Child {
        socket: OwnedFd,
    }

    impl Child {
        /// The goethite that started this one to take over, if one did.
        ///
        /// # Errors
        ///
        /// If `GOETHITE_HANDOFF` is set but its socket cannot be reached.
        pub(crate) fn from_env() -> Result<Option<Self>> {
            let Some(path) = std::env::var_os(ENV) else {
                return Ok(None);
            };
            let socket = socket_with(
                AddressFamily::UNIX,
                SocketType::SEQPACKET,
                SocketFlags::CLOEXEC,
                None,
            )?;
            connect(&socket, &SocketAddrUnix::new(Path::new(&path))?)
                .context("cannot reach the goethite this one takes over from")?;
            timeouts(&socket)?;
            let child = Self { socket };
            send(
                &child.socket,
                &Message::Hello {
                    version: env!("CARGO_PKG_VERSION").to_owned(),
                },
                &[],
            )?;
            Ok(Some(child))
        }

        /// Receives the sockets, by name, and the keys.
        ///
        /// # Errors
        ///
        /// If the parent sends something else or goes away.
        pub(crate) fn receive(&self) -> Result<(Vec<(String, OwnedFd)>, Secrets)> {
            let mut sockets = Vec::new();
            let mut keys = None;
            loop {
                match receive(&self.socket)? {
                    (
                        Message::Sockets {
                            names,
                            secrets,
                            more,
                        },
                        fds,
                    ) => {
                        if names.len() != fds.len() {
                            bail!("{} sockets for {} names", fds.len(), names.len());
                        }
                        sockets.extend(names.into_iter().zip(fds));
                        if secrets.is_some() {
                            keys = secrets;
                        }
                        if !more {
                            return Ok((sockets, keys.unwrap_or_default()));
                        }
                    }
                    (other, _) => bail!("unexpected message from the previous goethite: {other:?}"),
                }
            }
        }

        /// Tells the parent this process has the sockets, and waits for it
        /// to close the store.
        ///
        /// # Errors
        ///
        /// If the parent goes away.
        pub(crate) fn adopted(&self) -> Result<()> {
            send(&self.socket, &Message::Adopted, &[])?;
            match receive(&self.socket)? {
                (Message::StoreReleased, _) => Ok(()),
                (other, _) => bail!("unexpected message from the previous goethite: {other:?}"),
            }
        }

        /// Tells the parent this process answers queries.
        ///
        /// # Errors
        ///
        /// If the parent went away.
        pub(crate) fn serving(&self) -> Result<()> {
            send(&self.socket, &Message::Serving, &[])
        }

        /// Tells the parent this process gave up.
        pub(crate) fn failed(&self, reason: &str) {
            let _ = send(
                &self.socket,
                &Message::Failed {
                    reason: reason.to_owned(),
                },
                &[],
            );
        }
    }
}

/// Upgrading by handing over sockets needs Linux.
#[cfg(not(target_os = "linux"))]
pub(crate) struct Parent;

#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::unused_self,
    clippy::unnecessary_wraps,
    clippy::needless_pass_by_ref_mut,
    reason = "the same API as on Linux"
)]
impl Parent {
    /// Always fails: other platforms are for development.
    ///
    /// # Errors
    ///
    /// Always.
    pub(crate) fn spawn(_binary: &Path, _config: &Path, _dir: &Path) -> Result<Self> {
        anyhow::bail!("upgrading by handing over sockets needs Linux")
    }

    /// Never reached.
    pub(crate) fn send_sockets(&self, _sockets: &Sockets, _secrets: &Secrets) -> Result<()> {
        Ok(())
    }

    /// Never reached.
    pub(crate) fn wait_adopted(&mut self) -> Result<()> {
        Ok(())
    }

    /// Never reached.
    pub(crate) fn store_released(&self) -> Result<()> {
        Ok(())
    }

    /// Never reached.
    pub(crate) fn wait_serving(&mut self) -> Result<()> {
        Ok(())
    }

    /// Never reached.
    pub(crate) fn abandon(&mut self) {}
}

/// Taking over needs Linux.
#[cfg(not(target_os = "linux"))]
pub(crate) struct Child;

#[cfg(not(target_os = "linux"))]
#[expect(
    clippy::unused_self,
    clippy::unnecessary_wraps,
    reason = "the same API as on Linux"
)]
impl Child {
    /// Fails if a parent asked for a takeover; otherwise `None`.
    ///
    /// # Errors
    ///
    /// If `GOETHITE_HANDOFF` is set.
    pub(crate) fn from_env() -> Result<Option<Self>> {
        if std::env::var_os(ENV).is_some() {
            anyhow::bail!("taking over from another goethite needs Linux");
        }
        Ok(None)
    }

    /// Never reached.
    pub(crate) fn receive(&self) -> Result<(Vec<(String, std::os::fd::OwnedFd)>, Secrets)> {
        Ok((Vec::new(), Secrets::default()))
    }

    /// Never reached.
    pub(crate) fn adopted(&self) -> Result<()> {
        Ok(())
    }

    /// Never reached.
    pub(crate) fn serving(&self) -> Result<()> {
        Ok(())
    }

    /// Never reached.
    pub(crate) fn failed(&self, _reason: &str) {}
}
