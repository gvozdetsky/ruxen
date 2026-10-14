//! The `h2` crate drives its connection through tokio's poll-style
//! `AsyncRead` / `AsyncWrite`; ruxen's streams are monoio's rent-style
//! (`AsyncReadRent` / `AsyncWriteRent`, the buffer moves into the
//! operation). `PollIo` runs one read and one write operation at a time on
//! the stream it owns, each a boxed future polled from `poll_read` /
//! `poll_write`, with buffers of its own.
//!
//! A read and a write can be in flight at once. That is what a TLS stream
//! in tunnel mode (`TlsStream::begin_tunnel`) allows, and what a plain TCP
//! socket does anyway: each operation touches the stream only between
//! awaits.

use std::cell::UnsafeCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, ready};

use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use tokio::io::ReadBuf;

/// Read size: one maximum-size TLS record, or a few HTTP/2 frames.
const READ_BUF: usize = 16 * 1024;

/// How much `poll_write` takes while a write is in flight, for the next
/// one: `h2` keeps encoding frames instead of waiting (#348).
const PENDING_MAX: usize = 256 * 1024;

type Op<T> = Pin<Box<dyn Future<Output = T>>>;

pub(crate) struct PollIo<S: 'static> {
    // The operations borrow `*stream`; declared first, so they are dropped
    // before it.
    reading: Option<Op<(io::Result<usize>, Vec<u8>)>>,
    writing: Option<Op<(io::Result<usize>, Vec<u8>)>>,
    shutting_down: Option<Op<io::Result<()>>>,
    /// Bytes read and not yet handed out: `rbuf[rpos..]`.
    rbuf: Vec<u8>,
    rpos: usize,
    /// The write buffer between writes.
    wbuf: Vec<u8>,
    /// Bytes taken while a write was in flight, written next.
    pending: Vec<u8>,
    /// A failed write, reported by the next `poll_write` or `poll_flush`.
    write_error: Option<io::Error>,
    /// When the write in flight started; `None` while none is.
    writing_since: std::rc::Rc<std::cell::Cell<Option<std::time::Instant>>>,
    /// Shared with `serve`, which closes the connection once the `h2`
    /// connection (and with it this) is dropped.
    stream: Rc<UnsafeCell<S>>,
}

impl<S: AsyncReadRent + AsyncWriteRent + 'static> PollIo<S> {
    pub(crate) fn new(stream: S) -> Self {
        PollIo {
            reading: None,
            writing: None,
            shutting_down: None,
            rbuf: Vec::new(),
            rpos: 0,
            wbuf: Vec::new(),
            pending: Vec::new(),
            write_error: None,
            writing_since: Default::default(),
            stream: Rc::new(UnsafeCell::new(stream)),
        }
    }

    /// The stream, for after `self` is dropped: no operation borrows it
    /// any more then.
    pub(crate) fn stream_handle(&self) -> Rc<UnsafeCell<S>> {
        self.stream.clone()
    }

    /// When the write in flight started, kept up to date for whoever
    /// holds the handle (`serve`, once the `h2` connection owns `self`).
    pub(crate) fn writing_since(&self) -> std::rc::Rc<std::cell::Cell<Option<std::time::Instant>>> {
        self.writing_since.clone()
    }

    /// The stream, for an operation that may run alongside the other
    /// direction's.
    ///
    /// SAFETY: the caller keeps the reference inside an operation stored in
    /// `self`, which is dropped before `stream` (field order), and at most
    /// one read and one write operation exist at a time.
    unsafe fn stream(&self) -> &'static mut S {
        unsafe { &mut *self.stream.get() }
    }

    /// Start writing `buf` and poll it once: on io_uring, the submission
    /// is what gets it going.
    fn start_write(&mut self, buf: Vec<u8>, cx: &mut Context<'_>) {
        // SAFETY: see `stream`.
        let stream = unsafe { self.stream() };
        self.writing = Some(Box::pin(async move { stream.write_all(buf).await }));
        self.writing_since.set(Some(std::time::Instant::now()));
        let _ = self.poll_in_flight(cx);
    }

    /// Poll the write in flight; when it is done, start the pending bytes.
    /// `Ready` once nothing is in flight.
    fn poll_in_flight(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            let Some(op) = self.writing.as_mut() else {
                return Poll::Ready(());
            };
            let (res, buf) = ready!(op.as_mut().poll(cx));
            self.writing = None;
            self.writing_since.set(None);
            self.wbuf = buf;
            if let Err(e) = res {
                self.write_error = Some(e);
                self.pending.clear();
                return Poll::Ready(());
            }
            if self.pending.is_empty() {
                return Poll::Ready(());
            }
            let mut next = std::mem::take(&mut self.wbuf);
            next.clear();
            std::mem::swap(&mut next, &mut self.pending);
            // SAFETY: see `stream`.
            let stream = unsafe { self.stream() };
            self.writing = Some(Box::pin(async move { stream.write_all(next).await }));
            self.writing_since.set(Some(std::time::Instant::now()));
        }
    }

    /// Wait until everything taken is written.
    fn poll_written(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_in_flight(cx));
        match self.write_error.take() {
            Some(e) => Poll::Ready(Err(e)),
            None => Poll::Ready(Ok(())),
        }
    }
}

impl<S: AsyncReadRent + AsyncWriteRent + 'static> tokio::io::AsyncRead for PollIo<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.rpos == this.rbuf.len() {
            if this.reading.is_none() {
                let mut buf = std::mem::take(&mut this.rbuf);
                this.rpos = 0;
                buf.clear();
                buf.reserve(READ_BUF);
                // SAFETY: see `stream`.
                let stream = unsafe { this.stream() };
                this.reading = Some(Box::pin(async move { stream.read(buf).await }));
            }
            let op = this.reading.as_mut().expect("set above");
            let (res, buf) = ready!(op.as_mut().poll(cx));
            this.reading = None;
            this.rbuf = buf;
            this.rpos = 0;
            if let Err(e) = res {
                this.rbuf.clear();
                return Poll::Ready(Err(e));
            }
            // `Ok(0)`, EOF: nothing is filled in.
        }
        let n = (this.rbuf.len() - this.rpos).min(out.remaining());
        out.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
        this.rpos += n;
        Poll::Ready(Ok(()))
    }
}

impl<S: AsyncReadRent + AsyncWriteRent + 'static> tokio::io::AsyncWrite for PollIo<S> {
    /// Takes the bytes at once and writes them in the background; the next
    /// call waits for that write first, so one write is in flight at most.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_vectored(cx, &[io::IoSlice::new(data)])
    }

    /// `h2` sends a DATA payload over 256 bytes as its own slice after the
    /// frame head. Taking all slices at once makes that one socket write
    /// instead of one per slice, each waiting for the last (#348).
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let len: usize = data.iter().map(|s| s.len()).sum();
        if this.poll_in_flight(cx).is_pending() {
            // Taken for the next write while this one runs, up to a bound.
            if this.pending.len() + len > PENDING_MAX {
                return Poll::Pending;
            }
            for slice in data {
                this.pending.extend_from_slice(slice);
            }
            return Poll::Ready(Ok(len));
        }
        if let Some(e) = this.write_error.take() {
            return Poll::Ready(Err(e));
        }
        let mut buf = std::mem::take(&mut this.wbuf);
        buf.clear();
        for slice in data {
            buf.extend_from_slice(slice);
        }
        this.start_write(buf, cx);
        Poll::Ready(Ok(len))
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.get_mut().poll_written(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_written(cx))?;
        if this.shutting_down.is_none() {
            // SAFETY: see `stream`; no write is in flight any more.
            let stream = unsafe { this.stream() };
            this.shutting_down = Some(Box::pin(async move { stream.shutdown().await }));
        }
        let res = ready!(
            this.shutting_down
                .as_mut()
                .expect("set above")
                .as_mut()
                .poll(cx)
        );
        Poll::Ready(res)
    }
}
