//! systemd's notification protocol (#502), without a library: one datagram
//! per message on the `AF_UNIX` socket `$NOTIFY_SOCKET` names (a leading
//! `@` is the abstract namespace). Without it, nothing is sent: ruxen run
//! by hand, or by a unit that isn't `Type=notify`.

use std::os::unix::net::{SocketAddr, UnixDatagram};
use std::sync::OnceLock;
use std::time::Duration;

fn socket() -> Option<&'static (UnixDatagram, SocketAddr)> {
    static SOCKET: OnceLock<Option<(UnixDatagram, SocketAddr)>> = OnceLock::new();
    SOCKET
        .get_or_init(|| {
            let path = std::env::var_os("NOTIFY_SOCKET")?;
            let path = path.to_str()?;
            let addr = match path.strip_prefix('@') {
                Some(name) => {
                    use std::os::linux::net::SocketAddrExt;
                    SocketAddr::from_abstract_name(name.as_bytes()).ok()?
                }
                None => SocketAddr::from_pathname(path).ok()?,
            };
            Some((UnixDatagram::unbound().ok()?, addr))
        })
        .as_ref()
}

/// Send `message` (`READY=1`, `RELOADING=1`, …); errors are ignored, as
/// sd_notify(3) callers usually do: systemd may be gone, or not listening.
pub fn notify(message: &str) {
    if let Some((sock, addr)) = socket() {
        let _ = sock.send_to_addr(message.as_bytes(), addr);
    }
}

/// `RELOADING=1` with `MONOTONIC_USEC`, which `Type=notify-reload` needs.
pub fn reloading() {
    if socket().is_none() {
        return;
    }
    // SAFETY: clock_gettime fills the timespec we pass.
    let usec = unsafe {
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        ts.tv_sec as u64 * 1_000_000 + ts.tv_nsec as u64 / 1_000
    };
    notify(&format!("RELOADING=1\nMONOTONIC_USEC={usec}"));
}

/// systemd's watchdog interval (`WatchdogSec=`), if it watches this process:
/// `$WATCHDOG_USEC`, and `$WATCHDOG_PID` naming ours when set.
pub fn watchdog_interval() -> Option<Duration> {
    socket()?;
    if let Some(pid) = std::env::var_os("WATCHDOG_PID")
        && pid.to_str().and_then(|p| p.parse::<u32>().ok()) != Some(std::process::id())
    {
        return None;
    }
    let usec: u64 = std::env::var("WATCHDOG_USEC").ok()?.parse().ok()?;
    (usec > 0).then(|| Duration::from_micros(usec))
}
