//! Connection and request counters for `stub_status` and the
//! `$connections_*` variables (#96), as nginx's ngx_http_stub_status_module
//! reports them. Kept only when the configuration reads them
//! (`PreparedHttp::stats`), so other configurations pay nothing.
//!
//! Each worker owns one cache-line slot and is its only writer, so an
//! update is a plain load and store (no locked instruction, no shared line);
//! a reader sums the slots and may see a worker's counts a moment old.
//! nginx's shared atomics in shm are contended across workers instead.

use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering::Relaxed};

#[repr(align(64))]
#[derive(Default)]
struct WorkerStats {
    accepted: AtomicU64,
    handled: AtomicU64,
    requests: AtomicU64,
    active: AtomicI64,
    reading: AtomicI64,
    writing: AtomicI64,
    waiting: AtomicI64,
}

/// Every worker's slot, for the readers. Slots live as long as the process.
static ALL: Mutex<Vec<&'static WorkerStats>> = Mutex::new(Vec::new());

thread_local! {
    static MINE: &'static WorkerStats = {
        let slot: &'static WorkerStats = Box::leak(Box::default());
        ALL.lock().unwrap_or_else(|e| e.into_inner()).push(slot);
        slot
    };
}

/// Owner-only update: a load and a store, both relaxed.
fn add_u(counter: &AtomicU64) {
    counter.store(counter.load(Relaxed) + 1, Relaxed);
}

fn add_i(counter: &AtomicI64, delta: i64) {
    counter.store(counter.load(Relaxed) + delta, Relaxed);
}

/// A connection was accepted; `handled` when it was also taken on (not
/// refused at `worker_connections`).
pub(crate) fn accepted(handled: bool) {
    MINE.with(|s| {
        add_u(&s.accepted);
        if handled {
            add_u(&s.handled);
        }
    });
}

/// Totals over all workers, as `stub_status` prints them.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Totals {
    pub active: u64,
    pub accepted: u64,
    pub handled: u64,
    pub requests: u64,
    pub reading: u64,
    pub writing: u64,
    pub waiting: u64,
}

pub(crate) fn totals() -> Totals {
    let all = ALL.lock().unwrap_or_else(|e| e.into_inner());
    let mut sums = [0i64; 4];
    let mut t = Totals::default();
    for s in all.iter() {
        t.accepted += s.accepted.load(Relaxed);
        t.handled += s.handled.load(Relaxed);
        t.requests += s.requests.load(Relaxed);
        sums[0] += s.active.load(Relaxed);
        sums[1] += s.reading.load(Relaxed);
        sums[2] += s.writing.load(Relaxed);
        sums[3] += s.waiting.load(Relaxed);
    }
    // A worker's slot can be read mid-update: never below zero.
    [t.active, t.reading, t.writing, t.waiting] = sums.map(|v| v.max(0) as u64);
    t
}

/// What a connection is doing, for the gauges.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Phase {
    /// Idle: before its first request, or between keep-alive requests.
    Waiting,
    /// Its request head is coming in.
    Reading,
    /// A request is being processed and answered.
    Writing,
}

/// One connection's place in the counters: `active` while it lives, and
/// one of the three gauges. Inert when the configuration doesn't read the
/// counters. Dropping it takes the connection out, however it ends.
pub(crate) struct ConnStats {
    phase: Option<Phase>,
}

impl ConnStats {
    pub(crate) fn new(on: bool) -> Self {
        if !on {
            return ConnStats { phase: None };
        }
        MINE.with(|s| {
            add_i(&s.active, 1);
            add_i(&s.waiting, 1);
        });
        ConnStats {
            phase: Some(Phase::Waiting),
        }
    }

    /// Move to `phase` (a no-op when inert or already there).
    #[inline]
    pub(crate) fn set(&mut self, phase: Phase) {
        if let Some(current) = self.phase
            && current != phase
        {
            self.move_to(current, phase);
        }
    }

    #[cold]
    #[inline(never)]
    fn move_to(&mut self, from: Phase, to: Phase) {
        MINE.with(|s| {
            add_i(gauge(s, from), -1);
            add_i(gauge(s, to), 1);
        });
        self.phase = Some(to);
    }

    /// A request head was parsed: count it, and the connection is writing.
    #[inline]
    pub(crate) fn request(&mut self) {
        if self.phase.is_some() {
            MINE.with(|s| add_u(&s.requests));
            self.set(Phase::Writing);
        }
    }
}

fn gauge(s: &WorkerStats, phase: Phase) -> &AtomicI64 {
    match phase {
        Phase::Waiting => &s.waiting,
        Phase::Reading => &s.reading,
        Phase::Writing => &s.writing,
    }
}

impl Drop for ConnStats {
    fn drop(&mut self) {
        if let Some(phase) = self.phase {
            MINE.with(|s| {
                add_i(gauge(s, phase), -1);
                add_i(&s.active, -1);
            });
        }
    }
}

/// `stub_status`'s body (ngx_http_stub_status_handler), trailing spaces
/// included.
pub(crate) fn status_text() -> String {
    let t = totals();
    format!(
        "Active connections: {} \nserver accepts handled requests\n {} {} {} \n\
         Reading: {} Writing: {} Waiting: {} \n",
        t.active, t.accepted, t.handled, t.requests, t.reading, t.writing, t.waiting
    )
}
