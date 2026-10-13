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

    /// Wait for the write in flight, if any.
    fn poll_written(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(op) = self.writing.as_mut() {
            let (res, buf) = ready!(op.as_mut().poll(cx));
            self.writing = None;
            self.writing_since.set(None);
            self.wbuf = buf;
            if let Err(e) = res {
                self.write_error = Some(e);
            }
        }
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
        let this = self.get_mut();
        ready!(this.poll_written(cx))?;
        let mut buf = std::mem::take(&mut this.wbuf);
        buf.clear();
        buf.extend_from_slice(data);
        // SAFETY: see `stream`.
        let stream = unsafe { this.stream() };
        this.writing = Some(Box::pin(async move { stream.write_all(buf).await }));
        this.writing_since.set(Some(std::time::Instant::now()));
        // Start it now: on io_uring, the submission is what gets it going.
        if let Poll::Ready(Err(e)) = this.poll_written(cx) {
            // Taken already: reported as this write's error.
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(data.len()))
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
