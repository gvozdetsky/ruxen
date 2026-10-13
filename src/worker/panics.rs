//! What a panic does (#130). A panic while a connection is served ends
//! that connection only: its future is wrapped in `Contained`, which
//! catches the unwind, and the worker carries on with its other
//! connections. The panic hook writes the message and where it happened to
//! the error log at `alert`, not only to stderr. A panic anywhere else ends
//! the worker thread; `main` then stops the other workers gracefully,
//! removes the pid file and exits with status 1, for systemd's `Restart=`
//! to take over. Respawning the worker in place, as nginx's master does,
//! would mean binding its listeners again after the switch to `user`,
//! which can't bind ports below 1024.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use crate::config::ErrorLogLevel;

use super::{PreparedHttp, write_worker_log};

/// Set to make ruxen panic on purpose, for the tests of what then happens:
/// `trace` panics while serving a TRACE request (a path nothing else
/// takes, since TRACE is always refused), `worker` panics each worker once
/// it is ready to accept. Read once.
pub const TEST_PANIC_ENV: &str = "RUXEN_TEST_PANIC";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestPanic {
    Off,
    Trace,
    Worker,
}

pub(crate) fn test_panic() -> TestPanic {
    static MODE: std::sync::OnceLock<TestPanic> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| match std::env::var(TEST_PANIC_ENV).as_deref() {
        Ok("trace") => TestPanic::Trace,
        Ok("worker") => TestPanic::Worker,
        _ => TestPanic::Off,
    })
}

/// Send panic messages to the error log. With `RUST_BACKTRACE` set, Rust's
/// own report (with the backtrace) follows on stderr.
pub fn install_panic_hook(http: &'static PreparedHttp) {
    let previous = std::panic::take_hook();
    let backtrace = std::env::var_os("RUST_BACKTRACE").is_some();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let payload = info.payload();
        let message = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("Box<dyn Any>");
        let location = info
            .location()
            .map(|l| format!(" at {}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_default();
        // A worker logs where its generation's configuration says (#89).
        let logs = super::worker_http().map_or(http.error_logs, |h| h.error_logs);
        write_worker_log(
            logs,
            ErrorLogLevel::Alert,
            &format!(
                "{} panicked{location}: {message}",
                thread.name().unwrap_or("thread")
            ),
        );
        if backtrace {
            previous(info);
        }
    }));
}

/// A connection's future. A panic in it ends the connection (the future is
/// dropped, which closes the socket and runs the guards that un-count it)
/// instead of unwinding the worker thread.
pub(crate) struct Contained<F> {
    fut: F,
    http: &'static PreparedHttp,
    connection_id: u64,
    client: SocketAddr,
}

impl<F> Contained<F> {
    pub(crate) fn new(
        fut: F,
        http: &'static PreparedHttp,
        connection_id: u64,
        client: SocketAddr,
    ) -> Self {
        Contained {
            fut,
            http,
            connection_id,
            client,
        }
    }
}

impl<F: Future<Output = ()>> Future for Contained<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // SAFETY: `fut` is structurally pinned: never moved out of `self`,
        // and the other fields are plain data.
        let this = unsafe { self.get_unchecked_mut() };
        let fut = unsafe { Pin::new_unchecked(&mut this.fut) };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fut.poll(cx))) {
            Ok(poll) => poll,
            Err(_) => {
                contained_panic(this.http, this.connection_id, this.client);
                Poll::Ready(())
            }
        }
    }
}

#[cold]
#[inline(never)]
fn contained_panic(http: &PreparedHttp, connection_id: u64, client: SocketAddr) {
    write_worker_log(
        http.error_logs,
        ErrorLogLevel::Alert,
        &format!(
            "*{connection_id} connection closed after the panic above, client: {}",
            client.ip()
        ),
    );
}
