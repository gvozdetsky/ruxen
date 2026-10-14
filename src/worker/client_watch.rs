//! When a proxied exchange starts watching its client for a close (#136).
//!
//! nginx peeks at the client whenever it becomes readable while the
//! upstream is awaited (ngx_http_upstream_check_broken_connection). Here
//! the watch is a read on the client, armed only once the upstream has
//! kept the exchange waiting for a tick or two, so a fast exchange pays
//! neither for the read nor for a timer of its own: one ticker per worker
//! counts the ticks and wakes the exchanges that became due.

use std::cell::RefCell;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use super::connection::ConnIo;

/// The client of a proxied exchange, watched for a close. A trait object,
/// so `settle_proxy_response` isn't generic over the transport: one copy
/// of it for every kind of connection.
pub(crate) trait WatchClient {
    fn closed(&self) -> Pin<Box<dyn Future<Output = ()> + '_>>;
}

impl<S: ConnIo> WatchClient for S {
    fn closed(&self) -> Pin<Box<dyn Future<Output = ()> + '_>> {
        Box::pin(self.peer_closed())
    }
}

/// The proxy's future, raced against its client's close: `None` when the
/// client went away first. Hand-written rather than a `select`, to keep
/// the connection's future small: the exchange's whole state here is a
/// few words, and the ticket is taken only once the proxy waits.
pub(crate) struct Watched<'a, F> {
    proxy: Pin<&'a mut F>,
    client: Option<&'a dyn WatchClient>,
    ticket: Option<Ticket>,
    watch: Option<Pin<Box<dyn Future<Output = ()> + 'a>>>,
}

impl<'a, F: Future> Watched<'a, F> {
    pub(crate) fn new(proxy: Pin<&'a mut F>, client: Option<&'a dyn WatchClient>) -> Self {
        Watched {
            proxy,
            client,
            ticket: None,
            watch: None,
        }
    }
}

impl<F: Future> Future for Watched<'_, F> {
    type Output = Option<F::Output>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        if let Poll::Ready(out) = this.proxy.as_mut().poll(cx) {
            return Poll::Ready(Some(out));
        }
        let Some(client) = this.client else {
            return Poll::Pending;
        };
        if this.watch.is_none() {
            if !this.ticket.get_or_insert_with(Ticket::new).due(cx) {
                return Poll::Pending;
            }
            this.watch = Some(client.closed());
        }
        match this.watch.as_mut().map(|w| w.as_mut().poll(cx)) {
            Some(Poll::Ready(())) => Poll::Ready(None),
            _ => Poll::Pending,
        }
    }
}

/// The ticker's period: an exchange is watched after one to two of them.
const TICK: Duration = Duration::from_millis(100);

struct Waiting {
    /// `Registry::epoch` when it started waiting.
    since: u32,
    waker: Option<Waker>,
}

/// The worker's waiting exchanges. One thread-local, initialized at
/// compile time: a ticket costs three accesses to it (taken, checked once
/// the proxy waits, dropped).
struct Registry {
    /// Ticks since the worker started.
    epoch: u32,
    slots: Vec<Option<Waiting>>,
    free: Vec<usize>,
    live: usize,
    ticking: bool,
}

thread_local! {
    static REGISTRY: RefCell<Registry> = const {
        RefCell::new(Registry {
            epoch: 0,
            slots: Vec::new(),
            free: Vec::new(),
            live: 0,
            ticking: false,
        })
    };
}

/// One exchange waiting on its upstream. Dropping it ends the wait.
pub(crate) struct Ticket {
    slot: usize,
}

impl Ticket {
    pub(crate) fn new() -> Self {
        REGISTRY.with(|r| {
            let mut r = r.borrow_mut();
            let waiting = Some(Waiting {
                since: r.epoch,
                waker: None,
            });
            let slot = match r.free.pop() {
                Some(slot) => {
                    r.slots[slot] = waiting;
                    slot
                }
                None => {
                    r.slots.push(waiting);
                    r.slots.len() - 1
                }
            };
            r.live += 1;
            if !r.ticking {
                r.ticking = true;
                monoio::spawn(tick());
            }
            Ticket { slot }
        })
    }

    /// The exchange has waited long enough: watch the client. Otherwise
    /// the ticker wakes `cx` once it has.
    pub(crate) fn due(&self, cx: &Context<'_>) -> bool {
        REGISTRY.with(|r| {
            let mut r = r.borrow_mut();
            let now = r.epoch;
            let Some(waiting) = r.slots[self.slot].as_mut() else {
                return true;
            };
            if is_due(waiting.since, now) {
                return true;
            }
            match &waiting.waker {
                Some(w) if w.will_wake(cx.waker()) => {}
                _ => waiting.waker = Some(cx.waker().clone()),
            }
            false
        })
    }
}

impl Drop for Ticket {
    fn drop(&mut self) {
        REGISTRY.with(|r| {
            let mut r = r.borrow_mut();
            r.slots[self.slot] = None;
            r.free.push(self.slot);
            r.live -= 1;
        });
    }
}

/// Two ticks apart: at least one whole period has passed.
fn is_due(since: u32, now: u32) -> bool {
    now.wrapping_sub(since) >= 2
}

/// Counts the ticks while any exchange waits, waking those that became
/// due; ends when none is left (the next `Ticket` starts it again).
async fn tick() {
    loop {
        monoio::time::sleep(TICK).await;
        let wake: Vec<Waker> = REGISTRY.with(|r| {
            let mut r = r.borrow_mut();
            r.epoch = r.epoch.wrapping_add(1);
            let now = r.epoch;
            if r.live == 0 {
                r.ticking = false;
                return Vec::new();
            }
            r.slots
                .iter_mut()
                .flatten()
                .filter(|w| is_due(w.since, now))
                .filter_map(|w| w.waker.take())
                .collect()
        });
        if !REGISTRY.with(|r| r.borrow().ticking) {
            return;
        }
        // Outside the borrow: a woken task may run `due` or drop its ticket.
        for waker in wake {
            waker.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn due_after_a_whole_tick() {
        assert!(!is_due(5, 5));
        assert!(!is_due(5, 6));
        assert!(is_due(5, 7));
        assert!(is_due(u32::MAX, 1));
    }
}
