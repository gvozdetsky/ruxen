// Port helpers for tests that run in parallel inside one test binary.
//
// "Bind :0, read the port, drop the listener" leaves the port free for any
// other test thread to grab — a parallel test's ruxen or backend can then
// answer on the address this test expected to be dead.

use std::io;
use std::path::Path;
use std::process::Child;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Held from picking a port (bind :0, then drop) until the server under
/// test listens on it, and while a test binds its own listeners or
/// `DeadPort`s. Without it, a parallel test in the same binary can bind
/// the port in between, and a readiness check that waits for "something
/// accepts" passes against the wrong server. Not reentrant: take it once.
pub fn setup_lock() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Wait until ruxen has written `pid_file` (start it with
/// `-g "pid <path>;"` if its configuration has none). ruxen writes it once
/// every worker is bound, so unlike "the port accepts" it can't be another
/// process that took the port (the lock only covers this test binary),
/// and ruxen's own bind retries ride out a port held for a moment.
pub fn wait_for_pid_file(child: &mut Child, pid_file: &Path, timeout: Duration) {
    let deadline = Instant::now() + timeout;
    while !pid_file.exists() {
        assert!(
            child.try_wait().unwrap().is_none(),
            "ruxen exited at startup"
        );
        assert!(Instant::now() < deadline, "ruxen did not start");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// `N` distinct free ports, for a test that needs several at once: all `N`
/// listeners are held until every port is read. Bound and dropped one at
/// a time, the kernel can hand out the same port twice (about 1 run in
/// 1300 for five ports); two backends then share one address, and a
/// round-robin over three servers sees two (m113 on CI, 2026-10-20).
/// Take `setup_lock` first, as for a single port.
pub fn free_ports<const N: usize>() -> [u16; N] {
    let probes: Vec<std::net::TcpListener> = (0..N)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    std::array::from_fn(|i| probes[i].local_addr().unwrap().port())
}

/// A `DeadPort`, made under `setup_lock`.
pub fn dead_port() -> DeadPort {
    let _setup = setup_lock();
    DeadPort::new()
}

/// A loopback TCP port that refuses connections for as long as this value
/// is alive. The socket is bound but never `listen()`s, so `connect()` gets
/// ECONNREFUSED while the kernel keeps the port reserved.
pub struct DeadPort {
    fd: libc::c_int,
    port: u16,
}

impl DeadPort {
    pub fn new() -> Self {
        // SAFETY: plain socket/bind/getsockname on a fresh fd with
        // correctly sized sockaddr_in buffers.
        unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0);
            assert!(fd >= 0, "socket: {}", io::Error::last_os_error());
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            addr.sin_addr.s_addr = u32::from_ne_bytes([127, 0, 0, 1]);
            let len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            let rc = libc::bind(fd, &addr as *const _ as *const libc::sockaddr, len);
            assert!(rc == 0, "bind: {}", io::Error::last_os_error());
            let mut bound: libc::sockaddr_in = std::mem::zeroed();
            let mut blen = len;
            let rc = libc::getsockname(fd, &mut bound as *mut _ as *mut libc::sockaddr, &mut blen);
            assert!(rc == 0, "getsockname: {}", io::Error::last_os_error());
            DeadPort {
                fd,
                port: u16::from_be(bound.sin_port),
            }
        }
    }

    pub fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for DeadPort {
    fn drop(&mut self) {
        // SAFETY: fd is owned by this value and closed exactly once.
        unsafe {
            libc::close(self.fd);
        }
    }
}
