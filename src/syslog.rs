//! Sending log lines to syslog, as nginx's `ngx_syslog.c`: one RFC 3164
//! datagram per line (`<PRI>Mmm dd hh:mm:ss host tag: line`), over UDP or
//! a unix datagram socket, sent without blocking. A line that can't be
//! sent at once is dropped, as nginx drops it.

use std::io;
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::os::unix::net::UnixDatagram;

use crate::worker::{PreparedErrorLogSyslogServer, PreparedSyslogPeer};

/// The first address `host:port` resolves to.
pub(crate) fn resolve(addr: &str) -> io::Result<SocketAddr> {
    addr.to_socket_addrs()?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "host not found"))
}

/// A worker's socket for one syslog peer.
pub(crate) enum SyslogSocket {
    /// Connected, so a send is one syscall.
    Udp(UdpSocket),
    /// Unbound; sent to the path each time, so the listener may come and
    /// go (nginx doesn't require it at startup either).
    Unix(UnixDatagram, &'static std::path::Path),
}

impl SyslogSocket {
    pub(crate) fn open(peer: &PreparedSyslogPeer) -> io::Result<Self> {
        match peer.server {
            PreparedErrorLogSyslogServer::Udp(addr) => {
                let target = resolve(addr)?;
                let local: SocketAddr = if target.is_ipv4() {
                    ([0, 0, 0, 0], 0).into()
                } else {
                    ([0u16; 8], 0).into()
                };
                let sock = UdpSocket::bind(local)?;
                sock.connect(target)?;
                sock.set_nonblocking(true)?;
                Ok(SyslogSocket::Udp(sock))
            }
            PreparedErrorLogSyslogServer::Unix(path) => {
                let sock = UnixDatagram::unbound()?;
                sock.set_nonblocking(true)?;
                Ok(SyslogSocket::Unix(sock, path))
            }
        }
    }

    /// Send one message. A full socket buffer, or a peer that isn't
    /// listening (ECONNREFUSED from an earlier datagram), drops it.
    pub(crate) fn send(&self, msg: &[u8]) -> io::Result<()> {
        let res = match self {
            SyslogSocket::Udp(sock) => sock.send(msg).map(drop),
            SyslogSocket::Unix(sock, path) => sock.send_to(msg, path).map(drop),
        };
        match res {
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::ConnectionRefused
                        | io::ErrorKind::NotFound
                ) =>
            {
                Ok(())
            }
            other => other,
        }
    }
}

/// `<PRI>Mmm dd hh:mm:ss host tag: ` (nginx's ngx_syslog_add_header; the
/// time is UTC, like every time ruxen writes).
pub(crate) fn write_header(out: &mut Vec<u8>, peer: &PreparedSyslogPeer, secs: u64) {
    out.push(b'<');
    crate::worker::write_u64_decimal(out, u64::from(peer.pri));
    out.push(b'>');
    crate::worker::write_time_syslog(out, secs);
    out.push(b' ');
    if !peer.nohostname {
        out.extend_from_slice(crate::worker::hostname());
        out.push(b' ');
    }
    out.extend_from_slice(peer.tag);
    out.extend_from_slice(b": ");
}
