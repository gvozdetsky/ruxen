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
/// it is ready to accept, `task` panics in the flush timer of a buffered
/// `access_log` (a task outside any connection, #496). Read once.
pub const TEST_PANIC_ENV: &str = "RUXEN_TEST_PANIC";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TestPanic {
    Off,
    Trace,
    Worker,
    Task,
}

pub(crate) fn test_panic() -> TestPanic {
    static MODE: std::sync::OnceLock<TestPanic> = std::sync::OnceLock::new();
    *MODE.get_or_init(|| match std::env::var(TEST_PANIC_ENV).as_deref() {
        Ok("trace") => TestPanic::Trace,
        Ok("worker") => TestPanic::Worker,
        Ok("task") => TestPanic::Task,
        _ => TestPanic::Off,
    })
}

/// The configuration whose error log takes panics outside a worker's own
/// (the main thread, the reload thread, cache managers). Held while a
/// panic is logged, so `set_panic_hook_config` waits for a writer still
/// using the configuration it replaces, which a reload then frees (#343).
static HOOK_HTTP: std::sync::Mutex<Option<&'static PreparedHttp>> = std::sync::Mutex::new(None);

/// The configuration the panic hook logs with when the panicking thread
/// has none of its own: the running generation's.
pub fn set_panic_hook_config(http: &'static PreparedHttp) {
    *HOOK_HTTP.lock().unwrap_or_else(|e| e.into_inner()) = Some(http);
}

/// Send panic messages to the error log. With `RUST_BACKTRACE` set, Rust's
/// own report (with the backtrace) follows on stderr.
pub fn install_panic_hook(http: &'static PreparedHttp) {
    set_panic_hook_config(http);
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
        // A worker logs where its generation's configuration says (#89);
        // other threads where the running one does.
        let current = HOOK_HTTP.lock().unwrap_or_else(|e| e.into_inner());
        let Some(logs) = super::worker_http().or(*current).map(|h| h.error_logs) else {
            return;
        };
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

/// Run a task the worker keeps outside any connection (#496): the
/// background update of `proxy_cache_background_update`, the flush timer
/// of a buffered `access_log`, the ticker of the client-close watch. A
/// panic in it ends that task only: it is logged, `on_panic` puts back
/// what the task held (such as the flag that says it runs, so the next
/// use starts it again), and the worker carries on. monoio doesn't catch
/// a panic in a spawned task: it would end the worker thread, and with it
/// the server.
pub(crate) fn spawn_contained<F: Future<Output = ()> + 'static>(
    what: &'static str,
    on_panic: fn(),
    fut: F,
) {
    monoio::spawn(ContainedTask {
        fut,
        what,
        on_panic,
    });
}

struct ContainedTask<F> {
    fut: F,
    what: &'static str,
    on_panic: fn(),
}

impl<F: Future<Output = ()>> Future for ContainedTask<F> {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        // SAFETY: as in `Contained::poll`: `fut` is structurally pinned.
        let this = unsafe { self.get_unchecked_mut() };
        let fut = unsafe { Pin::new_unchecked(&mut this.fut) };
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fut.poll(cx))) {
            Ok(poll) => poll,
            Err(_) => {
                task_panic(this.what);
                (this.on_panic)();
                Poll::Ready(())
            }
        }
    }
}

#[cold]
#[inline(never)]
fn task_panic(what: &str) {
    let logs = super::worker_http().map_or(&[][..], |h| h.error_logs);
    write_worker_log(
        logs,
        ErrorLogLevel::Alert,
        &format!("{what} stopped after the panic above"),
    );
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
