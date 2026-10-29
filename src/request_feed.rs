//! A request body sent upstream as it arrives, with `proxy_request_buffering
//! off` (#134, nginx's `request_body_no_buffering`). The worker reads it
//! from the client (`put`, one piece at a time) while the proxy writes it
//! to the upstream (`next`), in the same task: whichever waits yields.

use std::cell::RefCell;
use std::rc::Rc;
use std::task::{Poll, Waker};

/// Why the client's body didn't all come: the request ends with this
/// status, as nginx's ngx_http_read_unbuffered_request_body returns it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FeedError {
    /// `client_body_timeout`: 408.
    TimedOut,
    /// Over `client_max_body_size` (a chunked body): 413.
    TooLarge,
    /// The client closed, or sent a malformed chunked body: 400.
    Invalid,
}

impl FeedError {
    pub(crate) fn status(self) -> u16 {
        match self {
            FeedError::TimedOut => 408,
            FeedError::TooLarge => 413,
            FeedError::Invalid => 400,
        }
    }
}

#[derive(Default)]
struct State {
    /// A piece read and not yet taken by the proxy.
    slot: Option<Vec<u8>>,
    /// Set once the body ended, or failed.
    end: Option<Result<(), FeedError>>,
    /// The proxy took a piece: the body can't be sent again, so there is
    /// no next upstream (ngx_http_upstream_next, `request_body_sent`).
    started: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

/// Shared by the worker's reader and the proxy plan(s) of one request.
#[derive(Clone)]
pub(crate) struct BodyFeed {
    state: Rc<RefCell<State>>,
    /// The client's body is chunked: it goes upstream re-chunked.
    chunked: bool,
}

impl std::fmt::Debug for BodyFeed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyFeed")
            .field("chunked", &self.chunked)
            .field("started", &self.started())
            .finish()
    }
}

impl BodyFeed {
    pub(crate) fn new(chunked: bool) -> Self {
        BodyFeed {
            state: Rc::default(),
            chunked,
        }
    }

    pub(crate) fn chunked(&self) -> bool {
        self.chunked
    }

    pub(crate) fn started(&self) -> bool {
        self.state.borrow().started
    }

    /// The next piece of the body, `None` at its end.
    pub(crate) async fn next(&self) -> Result<Option<Vec<u8>>, FeedError> {
        std::future::poll_fn(|cx| {
            let mut s = self.state.borrow_mut();
            if let Some(piece) = s.slot.take() {
                s.started = true;
                if let Some(w) = s.writer.take() {
                    w.wake();
                }
                return Poll::Ready(Ok(Some(piece)));
            }
            match s.end {
                Some(Ok(())) => Poll::Ready(Ok(None)),
                Some(Err(e)) => Poll::Ready(Err(e)),
                None => {
                    s.reader = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// A piece already there, without waiting.
    pub(crate) fn try_take(&self) -> Option<Vec<u8>> {
        let mut s = self.state.borrow_mut();
        let piece = s.slot.take()?;
        s.started = true;
        if let Some(w) = s.writer.take() {
            w.wake();
        }
        Some(piece)
    }

    /// The body ended and all of it was taken.
    pub(crate) fn ended(&self) -> bool {
        let s = self.state.borrow();
        s.slot.is_none() && s.end == Some(Ok(()))
    }

    /// Hand a piece to the proxy. Pieces it hasn't taken yet are joined,
    /// up to `JOIN_MAX`, as nginx sends what it read at once in one chunk.
    pub(crate) async fn put(&self, piece: Vec<u8>) {
        const JOIN_MAX: usize = 64 * 1024;
        let mut piece = Some(piece);
        std::future::poll_fn(|cx| {
            let mut s = self.state.borrow_mut();
            if let Some(slot) = s.slot.as_mut() {
                let len = piece.as_ref().map_or(0, Vec::len);
                if slot.len() + len > JOIN_MAX {
                    s.writer = Some(cx.waker().clone());
                    return Poll::Pending;
                }
                slot.extend_from_slice(piece.as_deref().unwrap_or_default());
                return Poll::Ready(());
            }
            s.slot = piece.take();
            if let Some(w) = s.reader.take() {
                w.wake();
            }
            Poll::Ready(())
        })
        .await
    }

    /// The body ended (`Ok`) or can't go on.
    pub(crate) fn finish(&self, end: Result<(), FeedError>) {
        let mut s = self.state.borrow_mut();
        s.end = Some(end);
        if let Some(w) = s.reader.take() {
            w.wake();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pieces_go_in_order_then_the_end() {
        let feed = BodyFeed::new(false);
        let reader = feed.clone();
        let got = monoio::RuntimeBuilder::<monoio::LegacyDriver>::new()
            .enable_timer()
            .build()
            .unwrap()
            .block_on(async move {
                let pump = async {
                    feed.put(b"ab".to_vec()).await;
                    feed.put(b"cd".to_vec()).await;
                    monoio::time::sleep(std::time::Duration::from_millis(1)).await;
                    feed.put(b"ef".to_vec()).await;
                    feed.finish(Ok(()));
                };
                let read = async {
                    let mut out = Vec::new();
                    while let Some(piece) = reader.next().await.unwrap() {
                        out.push(piece);
                    }
                    (out, reader.started())
                };
                let (_, got) = monoio::join!(pump, read);
                got
            });
        // Joined while the proxy didn't take them.
        assert_eq!(got, (vec![b"abcd".to_vec(), b"ef".to_vec()], true));
    }

    #[test]
    fn an_error_reaches_the_proxy() {
        let feed = BodyFeed::new(true);
        feed.finish(Err(FeedError::TimedOut));
        let got = monoio::RuntimeBuilder::<monoio::LegacyDriver>::new()
            .build()
            .unwrap()
            .block_on(async move { feed.next().await });
        assert_eq!(got, Err(FeedError::TimedOut));
        assert_eq!(FeedError::TimedOut.status(), 408);
    }
}
