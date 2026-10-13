//! Listening sockets across reloads (#89), as nginx's ngx_init_cycle hands
//! the old cycle's sockets to the new one: `main` opens them, not the
//! workers, and keeps them for as long as some configuration listens there.
//!
//! Each TCP address gets one `SO_REUSEPORT` socket per worker slot, so
//! worker *i* of every generation accepts from the same accept queue: when
//! a reload starts new workers and the old ones stop accepting, a
//! connection waiting in a queue is taken by the new worker, not reset. A
//! `listen unix:` path has one socket all workers share.
//!
//! A worker gets its own sockets by number: they are in its copy of
//! `main`'s fd table (`unshare(CLONE_FILES)` copies it at spawn). It
//! accepts on a duplicate and closes the originals and every other
//! worker's sockets in its copy, so a socket `main` lets go of is closed
//! once the workers that accepted on it have stopped.

use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};

use super::{
    PreparedHttp, claim_addresses, errno_text, listen_socket, set_deferred, set_listen_options,
};

/// The listening sockets `main` holds.
#[derive(Default)]
pub struct ListenerSet {
    tcp: Vec<TcpGroup>,
    unix: Vec<(PathBuf, OwnedFd)>,
}

/// One TCP address's sockets, one per worker slot.
struct TcpGroup {
    addr: SocketAddr,
    /// `IPV6_V6ONLY` is set before bind, so it is part of the key.
    ipv6only: bool,
    slots: Vec<OwnedFd>,
}

/// What a worker accepts on: (listen index, descriptor in `main`'s fd
/// table), and the other listening descriptors its copy of the table
/// holds, to close.
pub struct WorkerListeners {
    pub own: Vec<(usize, RawFd)>,
    pub foreign: Vec<RawFd>,
}

impl ListenerSet {
    /// Open what `http` listens on for `workers` workers and hand out each
    /// worker's sockets. Sockets already open for an address are kept
    /// (their `listen` options set again, as nginx does for a socket it
    /// inherits); new addresses are checked as at startup
    /// (`claim_addresses`) and bound. On failure, the sockets this call
    /// opened are closed again and the error is nginx's `[emerg]` text.
    pub fn open(
        &mut self,
        http: &PreparedHttp,
        workers: usize,
    ) -> Result<Vec<WorkerListeners>, String> {
        let tcp_before = self.tcp.len();
        let slots_before: Vec<usize> = self.tcp.iter().map(|g| g.slots.len()).collect();
        let unix_before = self.unix.len();
        let result = self.open_inner(http, workers);
        if result.is_err() {
            self.unix.truncate(unix_before);
            self.tcp.truncate(tcp_before);
            for (group, &n) in self.tcp.iter_mut().zip(&slots_before) {
                group.slots.truncate(n);
            }
            return result.map(|_| Vec::new());
        }
        let mut out: Vec<WorkerListeners> = (0..workers)
            .map(|_| WorkerListeners {
                own: Vec::new(),
                foreign: Vec::new(),
            })
            .collect();
        for (worker, listeners) in out.iter_mut().enumerate() {
            for (listen_index, listen) in http.listens.iter().enumerate() {
                let fd = match listen.unix {
                    Some(path) => self.unix_fd(path),
                    None => self
                        .group(listen.addr, listen.socket.ipv6only)
                        .map(|g| g.slots[worker].as_raw_fd()),
                };
                // `open_inner` made sure there is one.
                if let Some(fd) = fd {
                    listeners.own.push((listen_index, fd));
                }
            }
            listeners.foreign = self
                .all_fds()
                .filter(|fd| !listeners.own.iter().any(|(_, own)| own == fd))
                .collect();
        }
        Ok(out)
    }

    fn open_inner(&mut self, http: &PreparedHttp, workers: usize) -> Result<(), String> {
        // Addresses nobody listens on yet are checked first, so a busy
        // port is reported as at startup, with its retries.
        let new: Vec<_> = http
            .listens
            .iter()
            .filter(|l| l.unix.is_none() && self.group(l.addr, l.socket.ipv6only).is_none())
            .collect();
        claim_addresses(&new)?;
        for listen in &http.listens {
            if let Some(path) = listen.unix {
                if self.unix_fd(path).is_none() {
                    let fd = bind_unix(path, listen.socket.backlog)?;
                    self.unix.push((path.to_path_buf(), fd));
                }
                continue;
            }
            let index = match self
                .tcp
                .iter()
                .position(|g| g.addr == listen.addr && g.ipv6only == listen.socket.ipv6only)
            {
                Some(i) => {
                    // Kept: nginx sets the options of an inherited socket
                    // again (ngx_configure_listening_sockets).
                    for fd in &self.tcp[i].slots {
                        reconfigure(http, listen, fd);
                    }
                    i
                }
                None => {
                    self.tcp.push(TcpGroup {
                        addr: listen.addr,
                        ipv6only: listen.socket.ipv6only,
                        slots: Vec::new(),
                    });
                    self.tcp.len() - 1
                }
            };
            while self.tcp[index].slots.len() < workers {
                let socket = listen_socket(http, listen).map_err(|e| {
                    format!("bind() to {} failed ({})", listen.addr, errno_text(&e))
                })?;
                self.tcp[index].slots.push(socket.into());
            }
        }
        Ok(())
    }

    /// Close every socket `http` with `workers` workers doesn't use: the
    /// addresses a reload removed, the slots of workers there are no more
    /// of, or what a failed reload opened. A unix socket's file goes too.
    pub fn retain(&mut self, http: &PreparedHttp, workers: usize) {
        self.tcp.retain_mut(|group| {
            let used = http.listens.iter().any(|l| {
                l.unix.is_none() && l.addr == group.addr && l.socket.ipv6only == group.ipv6only
            });
            group.slots.truncate(if used { workers } else { 0 });
            used
        });
        self.unix.retain(|(path, _)| {
            let used = http.listens.iter().any(|l| l.unix == Some(path.as_path()));
            if !used {
                let _ = std::fs::remove_file(path);
            }
            used
        });
    }

    /// Remove the `listen unix:` socket files on exit, as
    /// ngx_close_listening_sockets does.
    pub fn remove_unix_files(&self) {
        for (path, _) in &self.unix {
            let _ = std::fs::remove_file(path);
        }
    }

    fn group(&self, addr: SocketAddr, ipv6only: bool) -> Option<&TcpGroup> {
        self.tcp
            .iter()
            .find(|g| g.addr == addr && g.ipv6only == ipv6only)
    }

    fn unix_fd(&self, path: &Path) -> Option<RawFd> {
        self.unix
            .iter()
            .find(|(p, _)| p == path)
            .map(|(_, fd)| fd.as_raw_fd())
    }

    fn all_fds(&self) -> impl Iterator<Item = RawFd> + '_ {
        self.tcp
            .iter()
            .flat_map(|g| g.slots.iter().map(AsRawFd::as_raw_fd))
            .chain(self.unix.iter().map(|(_, fd)| fd.as_raw_fd()))
    }
}

/// The `listen` options of a kept socket, set again: the buffers and
/// keep-alive, and the backlog through a second `listen()`, which Linux
/// allows on a listening socket.
fn reconfigure(http: &PreparedHttp, listen: &super::PreparedListen, fd: &OwnedFd) {
    let socket = socket2::SockRef::from(fd);
    set_listen_options(http, listen, &socket);
    let _ = socket.listen(listen.socket.backlog);
    set_deferred(http, listen, &socket, true);
}

/// Bind a `listen unix:` socket (#263), as ngx_open_listening_sockets: a
/// socket file left behind fails with EADDRINUSE, and the socket is made
/// writable for everyone (0666).
fn bind_unix(path: &Path, backlog: i32) -> Result<OwnedFd, String> {
    use std::os::unix::fs::PermissionsExt;
    let failed = |e: std::io::Error| {
        format!(
            "bind() to unix:{} failed ({})",
            path.display(),
            errno_text(&e)
        )
    };
    let socket =
        socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None).map_err(failed)?;
    socket
        .bind(&socket2::SockAddr::unix(path).map_err(failed)?)
        .map_err(failed)?;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
    socket.listen(backlog).map_err(|e| {
        format!(
            "listen() to unix:{} failed ({})",
            path.display(),
            errno_text(&e)
        )
    })?;
    socket.set_nonblocking(true).map_err(failed)?;
    Ok(socket.into())
}

/// In a worker, right after its fd table became its own: a duplicate of
/// each of its sockets to accept on, with the originals and every other
/// worker's sockets closed in its table. Returns (listen index, duplicate).
/// `unshared` false (the table is still `main`'s): nothing is closed.
pub(crate) fn adopt(
    listeners: WorkerListeners,
    unshared: bool,
) -> std::io::Result<Vec<(usize, OwnedFd)>> {
    let mut adopted = Vec::with_capacity(listeners.own.len());
    for &(listen_index, fd) in &listeners.own {
        // SAFETY: fcntl on a descriptor `main` opened and keeps open.
        let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
        if dup < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: a fresh descriptor nothing else owns.
        adopted.push((listen_index, unsafe { OwnedFd::from_raw_fd(dup) }));
    }
    if unshared {
        let mut closed: Vec<RawFd> = Vec::new();
        for fd in listeners
            .foreign
            .iter()
            .chain(listeners.own.iter().map(|(_, fd)| fd))
        {
            // The same socket can serve two listens (a unix path): close
            // its number once.
            if closed.contains(fd) {
                continue;
            }
            closed.push(*fd);
            // SAFETY: this worker's private copy of `main`'s descriptor;
            // `main`'s own stays open.
            unsafe { libc::close(*fd) };
        }
    }
    Ok(adopted)
}

/// The descriptors a worker holds before it opens any of its own, but its
/// listeners: what `shut_down_sockets` leaves alone (stdio, which may be a
/// socket to a journal, root directories, the root helper's socket).
pub(crate) fn inherited_fds(except: &[RawFd]) -> Vec<RawFd> {
    let mut fds: Vec<RawFd> = open_fds()
        .into_iter()
        .filter(|fd| !except.contains(fd))
        .collect();
    fds.sort_unstable();
    fds
}

fn open_fds() -> Vec<RawFd> {
    // The calling thread's own table, which `unshare` made private.
    let Ok(dir) = std::fs::read_dir("/proc/thread-self/fd") else {
        return Vec::new();
    };
    dir.filter_map(|e| e.ok()?.file_name().to_str()?.parse().ok())
        .collect()
}

/// `worker_shutdown_timeout` passed after a reload: shut down every
/// connected socket this worker opened (clients and upstreams), as nginx's
/// ngx_shutdown_timer_handler closes an old worker's connections. Each
/// connection then ends as on a closed peer: its reads see EOF, its writes
/// fail, and its future finishes and frees what it holds. Listening sockets
/// and descriptors in `inherited` are left alone.
pub(crate) fn shut_down_sockets(inherited: &[RawFd]) {
    for fd in open_fds() {
        if inherited.binary_search(&fd).is_ok() || !is_connection(fd) {
            continue;
        }
        // SAFETY: shutdown(2) on a socket in this worker's own table.
        unsafe { libc::shutdown(fd, libc::SHUT_RDWR) };
    }
}

/// A socket that isn't listening.
fn is_connection(fd: RawFd) -> bool {
    // SAFETY: fstat into a zeroed struct.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut st) } != 0 || st.st_mode & libc::S_IFMT != libc::S_IFSOCK {
        return false;
    }
    let mut listening: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: an int option read into an int.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ACCEPTCONN,
            (&mut listening as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    rc == 0 && listening == 0
}
