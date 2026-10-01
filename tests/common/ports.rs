// Port helpers for tests that run in parallel inside one test binary.
//
// "Bind :0, read the port, drop the listener" leaves the port free for any
// other test thread to grab — a parallel test's ruxen or backend can then
// answer on the address this test expected to be dead.

use std::io;

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
