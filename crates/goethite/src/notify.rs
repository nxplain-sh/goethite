//! Telling systemd how goethite is doing (`Type=notify`), and keeping its
//! listening sockets in systemd's file-descriptor store so a restart after
//! a crash gets them back.
//!
//! The protocol is one datagram per message to the socket in
//! `NOTIFY_SOCKET`, with file descriptors attached as `SCM_RIGHTS`. Without
//! `NOTIFY_SOCKET` (goethite was not started by systemd) nothing is sent.
//! Failures are logged at debug level and otherwise ignored: notifications
//! are a courtesy to the service manager, never a reason to stop.

use std::os::fd::BorrowedFd;

use tracing::debug;

/// Sends `state` (such as `READY=1`) with `fds` attached.
fn notify(state: &str, fds: &[BorrowedFd<'_>]) {
    if let Err(err) = imp::send(state, fds) {
        debug!(%err, state, "cannot notify systemd");
    }
}

/// Startup is done: goethite answers queries.
pub(crate) fn ready() {
    notify("READY=1", &[]);
}

/// goethite is shutting down.
pub(crate) fn stopping() {
    notify("STOPPING=1", &[]);
}

/// This process, which took over from the previous one, is now the
/// service's main process, and ready.
pub(crate) fn took_over() {
    notify(&format!("MAINPID={}\nREADY=1", std::process::id()), &[]);
}

/// Removes the sockets named `name` from systemd's store.
pub(crate) fn forget(name: &str) {
    notify(&format!("FDSTOREREMOVE=1\nFDNAME={name}"), &[]);
}

/// Keeps `fd` in systemd's store under `name`. Storing the same socket
/// again is harmless: systemd keeps one copy.
pub(crate) fn store(name: &str, fd: BorrowedFd<'_>) {
    notify(&format!("FDSTORE=1\nFDNAME={name}"), &[fd]);
}

#[cfg(target_os = "linux")]
mod imp {
    use std::io::{self, IoSlice};
    use std::mem::MaybeUninit;
    use std::os::fd::BorrowedFd;

    use rustix::net::{
        AddressFamily, SendAncillaryBuffer, SendAncillaryMessage, SendFlags, SocketAddrUnix,
        SocketFlags, SocketType, sendmsg_addr, socket_with,
    };

    pub(super) fn send(state: &str, fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        let Some(path) = std::env::var_os("NOTIFY_SOCKET") else {
            return Ok(());
        };
        let address = match path.as_encoded_bytes().strip_prefix(b"@") {
            Some(name) => SocketAddrUnix::new_abstract_name(name)?,
            None => SocketAddrUnix::new(path.as_os_str())?,
        };
        let socket = socket_with(
            AddressFamily::UNIX,
            SocketType::DGRAM,
            SocketFlags::CLOEXEC,
            None,
        )?;
        let mut space = vec![MaybeUninit::uninit(); rustix::cmsg_space!(ScmRights(fds.len()))];
        let mut control = SendAncillaryBuffer::new(&mut space);
        if !fds.is_empty() && !control.push(SendAncillaryMessage::ScmRights(fds)) {
            return Err(io::Error::other(
                "too many file descriptors for one message",
            ));
        }
        sendmsg_addr(
            &socket,
            &address,
            &[IoSlice::new(state.as_bytes())],
            &mut control,
            SendFlags::empty(),
        )?;
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use std::io;
    use std::os::fd::BorrowedFd;

    /// systemd is Linux only.
    #[expect(clippy::unnecessary_wraps, reason = "the same signature as on Linux")]
    pub(super) fn send(_state: &str, _fds: &[BorrowedFd<'_>]) -> io::Result<()> {
        Ok(())
    }
}
