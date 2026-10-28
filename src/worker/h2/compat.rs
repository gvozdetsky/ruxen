//! The `h2` crate drives its connection through tokio's poll-style
//! `AsyncRead` / `AsyncWrite`; ruxen's streams are monoio's rent-style
//! (`AsyncReadRent` / `AsyncWriteRent`, the buffer moves into the
//! operation). `PollIo` runs one read and one write operation at a time on
//! the stream it owns, each a boxed future polled from `poll_read` /
//! `poll_write`, with buffers of its own.
//!
//! A read and a write can be in flight at once, each on its half of the
//! stream (`crate::duplex`, #501).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, ready};

use monoio::io::{AsyncReadRent, AsyncWriteRent, AsyncWriteRentExt};
use tokio::io::ReadBuf;

use crate::duplex::{Duplex, OwnedReadHalf, OwnedWriteHalf, Reclaim};

/// Read size: one maximum-size TLS record, or a few HTTP/2 frames.
const READ_BUF: usize = 16 * 1024;

/// How much `poll_write` takes while a write is in flight, for the next
/// one: `h2` keeps encoding frames instead of waiting (#348).
const PENDING_MAX: usize = 256 * 1024;

type Op<T> = Pin<Box<dyn Future<Output = T>>>;

/// The size of each request's header block as the client sent it: the
/// HEADERS payload without padding and priority, plus its CONTINUATIONs.
/// nginx's `$request_length` on HTTP/2 starts from it
/// (ngx_http_v2_state_headers, ngx_http_v2_handle_continuation); the `h2`
/// crate decodes the block without saying how long it was (#409), so
/// `PollIo` reads the frame heads as the bytes go by.
#[derive(Default)]
pub(crate) struct HeaderBlocks {
    /// Per stream id, until its stream takes it.
    sizes: std::cell::RefCell<Vec<(u32, u64)>>,
}

impl HeaderBlocks {
    /// Streams the crate refused or reset never take theirs: keep the
    /// latest few.
    const KEEP: usize = 256;

    fn add(&self, sid: u32, n: u64) {
        let mut sizes = self.sizes.borrow_mut();
        if let Some(entry) = sizes.iter_mut().rev().find(|(id, _)| *id == sid) {
            entry.1 += n;
            return;
        }
        if sizes.len() == Self::KEEP {
            sizes.remove(0);
        }
        sizes.push((sid, n));
    }

    /// Stream `sid`'s header block size, once.
    pub(crate) fn take(&self, sid: u32) -> u64 {
        let mut sizes = self.sizes.borrow_mut();
        match sizes.iter().position(|(id, _)| *id == sid) {
            Some(i) => sizes.remove(i).1,
            None => 0,
        }
    }
}

/// Walks the client's frames as they are read, from frame head to frame
/// head, for `HeaderBlocks`.
struct FrameScan {
    /// Bytes of the preface, then of the current frame's payload, still to
    /// pass over.
    skip: usize,
    /// A frame head split across reads.
    head: [u8; 9],
    head_len: usize,
    /// A padded HEADERS frame waiting for its first payload byte, the pad
    /// length: its stream, and the payload length less the priority.
    padded: Option<(u32, u64)>,
    blocks: Rc<HeaderBlocks>,
}

impl FrameScan {
    fn scan(&mut self, mut data: &[u8]) {
        while !data.is_empty() {
            if self.skip > 0 {
                if let Some((sid, len)) = self.padded.take() {
                    let pad = u64::from(data[0]) + 1;
                    self.blocks.add(sid, len.saturating_sub(pad));
                }
                let n = self.skip.min(data.len());
                self.skip -= n;
                data = &data[n..];
                continue;
            }
            let n = (9 - self.head_len).min(data.len());
            self.head[self.head_len..self.head_len + n].copy_from_slice(&data[..n]);
            self.head_len += n;
            data = &data[n..];
            if self.head_len < 9 {
                break;
            }
            self.head_len = 0;
            let h = &self.head;
            let len = u32::from_be_bytes([0, h[0], h[1], h[2]]) as usize;
            let sid = u32::from_be_bytes([h[5], h[6], h[7], h[8]]) & 0x7fff_ffff;
            self.skip = len;
            match h[3] {
                // HEADERS: less the priority fields and the padding.
                0x1 => {
                    let rest = (len as u64).saturating_sub(if h[4] & 0x20 != 0 { 5 } else { 0 });
                    if h[4] & 0x8 != 0 && len > 0 {
                        self.padded = Some((sid, rest));
                    } else {
                        self.blocks.add(sid, rest);
                    }
                }
                // CONTINUATION.
                0x9 => self.blocks.add(sid, len as u64),
                _ => {}
            }
        }
    }
}

/// For the `h2_frames` fuzz target (#477): the header-block sizes
/// `FrameScan` finds in `data` (the client preface first), read in pieces
/// cut at `cuts`, per stream id in the order they were first seen.
#[cfg(feature = "fuzzing")]
pub(crate) fn scan_header_blocks(data: &[u8], cuts: &[usize]) -> Vec<(u32, u64)> {
    let blocks: Rc<HeaderBlocks> = Rc::default();
    let mut scan = FrameScan {
        skip: super::PREFACE.len(),
        head: [0; 9],
        head_len: 0,
        padded: None,
        blocks: blocks.clone(),
    };
    let mut at = 0;
    for &cut in cuts {
        let cut = cut.clamp(at, data.len());
        scan.scan(&data[at..cut]);
        at = cut;
    }
    scan.scan(&data[at..]);
    drop(scan);
    Rc::try_unwrap(blocks)
        .map(|b| b.sizes.into_inner())
        .unwrap_or_default()
}

/// An operation's result, and the half it ran on.
type ReadDone<S> = (io::Result<usize>, Vec<u8>, OwnedReadHalf<S>);
type WriteDone<S> = (io::Result<usize>, Vec<u8>, OwnedWriteHalf<S>);

pub(crate) struct PollIo<S: Duplex> {
    /// A half is in its operation while one runs, else here.
    read_half: Option<OwnedReadHalf<S>>,
    write_half: Option<OwnedWriteHalf<S>>,
    reading: Option<Op<ReadDone<S>>>,
    writing: Option<Op<WriteDone<S>>>,
    /// Keeps the write half: nothing is written after.
    shutting_down: Option<Op<io::Result<()>>>,
    /// Bytes read and not yet handed out: `rbuf[rpos..]`.
    rbuf: Vec<u8>,
    scan: FrameScan,
    rpos: usize,
    /// The write buffer between writes.
    wbuf: Vec<u8>,
    /// Bytes taken while a write was in flight, written next.
    pending: Vec<u8>,
    /// A failed write, reported by the next `poll_write` or `poll_flush`.
    write_error: Option<io::Error>,
    /// When the write in flight started; `None` while none is.
    writing_since: std::rc::Rc<std::cell::Cell<Option<std::time::Instant>>>,
}

impl<S: Duplex> PollIo<S> {
    /// Also the stream back for `serve`, which closes the connection once
    /// the `h2` connection (and with it this) is dropped.
    pub(crate) fn new(stream: S) -> (Self, Reclaim<S>) {
        let (read_half, write_half, reclaim) = crate::duplex::into_split(stream);
        let io = PollIo {
            read_half: Some(read_half),
            write_half: Some(write_half),
            reading: None,
            writing: None,
            shutting_down: None,
            rbuf: Vec::new(),
            rpos: 0,
            scan: FrameScan {
                // The client preface comes first (RFC 9113, 3.4).
                skip: super::PREFACE.len(),
                head: [0; 9],
                head_len: 0,
                padded: None,
                blocks: Rc::default(),
            },
            wbuf: Vec::new(),
            pending: Vec::new(),
            write_error: None,
            writing_since: Default::default(),
        };
        (io, reclaim)
    }

    /// The header block sizes the frames read so far gave.
    pub(crate) fn header_blocks(&self) -> Rc<HeaderBlocks> {
        self.scan.blocks.clone()
    }

    /// When the write in flight started, kept up to date for whoever
    /// holds the handle (`serve`, once the `h2` connection owns `self`).
    pub(crate) fn writing_since(&self) -> std::rc::Rc<std::cell::Cell<Option<std::time::Instant>>> {
        self.writing_since.clone()
    }

    /// Write `buf` on the write half, which is free: `poll_in_flight` is
    /// `Ready`.
    fn write_op(&mut self, buf: Vec<u8>) -> io::Result<()> {
        let Some(mut half) = self.write_half.take() else {
            return Err(io::ErrorKind::NotConnected.into());
        };
        self.writing = Some(Box::pin(async move {
            let (res, buf) = half.write_all(buf).await;
            (res, buf, half)
        }));
        self.writing_since.set(Some(std::time::Instant::now()));
        Ok(())
    }

    /// Start writing `buf` and poll it once: on io_uring, the submission
    /// is what gets it going.
    fn start_write(&mut self, buf: Vec<u8>, cx: &mut Context<'_>) -> io::Result<()> {
        self.write_op(buf)?;
        let _ = self.poll_in_flight(cx);
        Ok(())
    }

    /// Poll the write in flight; when it is done, start the pending bytes.
    /// `Ready` once nothing is in flight.
    fn poll_in_flight(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            let Some(op) = self.writing.as_mut() else {
                return Poll::Ready(());
            };
            let (res, buf, half) = ready!(op.as_mut().poll(cx));
            self.writing = None;
            self.write_half = Some(half);
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
            if let Err(e) = self.write_op(next) {
                self.write_error = Some(e);
                return Poll::Ready(());
            }
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

impl<S: Duplex> tokio::io::AsyncRead for PollIo<S> {
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
                let Some(mut half) = this.read_half.take() else {
                    return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
                };
                this.reading = Some(Box::pin(async move {
                    let (res, buf) = half.read(buf).await;
                    (res, buf, half)
                }));
            }
            let op = this.reading.as_mut().expect("set above");
            let (res, buf, half) = ready!(op.as_mut().poll(cx));
            this.reading = None;
            this.read_half = Some(half);
            this.rbuf = buf;
            this.rpos = 0;
            if let Err(e) = res {
                this.rbuf.clear();
                return Poll::Ready(Err(e));
            }
            this.scan.scan(&this.rbuf);
            // `Ok(0)`, EOF: nothing is filled in.
        }
        let n = (this.rbuf.len() - this.rpos).min(out.remaining());
        out.put_slice(&this.rbuf[this.rpos..this.rpos + n]);
        this.rpos += n;
        Poll::Ready(Ok(()))
    }
}

impl<S: Duplex> tokio::io::AsyncWrite for PollIo<S> {
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
        this.start_write(buf, cx)?;
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
            let Some(mut half) = this.write_half.take() else {
                return Poll::Ready(Err(io::ErrorKind::NotConnected.into()));
            };
            this.shutting_down = Some(Box::pin(async move { half.shutdown().await }));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, flags: u8, sid: u32, payload: &[u8]) -> Vec<u8> {
        let len = payload.len() as u32;
        let mut f = len.to_be_bytes()[1..].to_vec();
        f.extend_from_slice(&[kind, flags]);
        f.extend_from_slice(&sid.to_be_bytes());
        f.extend_from_slice(payload);
        f
    }

    /// A client's first bytes: stream 1 has a header block of 18 bytes,
    /// 3 of 10, 5 of 11.
    fn wire() -> Vec<u8> {
        let mut wire = super::super::PREFACE.to_vec();
        wire.extend(frame(0x4, 0, 0, &[0; 6])); // SETTINGS
        wire.extend(frame(0x1, 0x4, 1, &[0; 18])); // HEADERS, END_HEADERS
        // Padded (pad length 3) and with priority: 1 + 5 + 10 + 3.
        let mut padded = vec![3];
        padded.extend_from_slice(&[0; 5 + 10 + 3]);
        wire.extend(frame(0x1, 0x8 | 0x20 | 0x4, 3, &padded));
        wire.extend(frame(0x1, 0, 5, &[0; 7])); // HEADERS without END_HEADERS
        wire.extend(frame(0x0, 0x1, 1, &[0; 40])); // DATA: not counted
        wire.extend(frame(0x9, 0x4, 5, &[0; 4])); // CONTINUATION
        wire
    }

    /// Header block sizes as nginx counts them (#409), whatever the reads'
    /// boundaries: HEADERS less padding and priority, plus CONTINUATIONs.
    #[test]
    fn header_blocks_follow_the_frames() {
        let wire = wire();
        for step in [1, 2, 7, 9, 10, wire.len()] {
            let blocks = Rc::new(HeaderBlocks::default());
            let mut scan = FrameScan {
                skip: super::super::PREFACE.len(),
                head: [0; 9],
                head_len: 0,
                padded: None,
                blocks: blocks.clone(),
            };
            for piece in wire.chunks(step) {
                scan.scan(piece);
            }
            assert_eq!(blocks.take(1), 18, "step {step}");
            assert_eq!(blocks.take(3), 10, "step {step}");
            assert_eq!(blocks.take(5), 11, "step {step}");
            assert_eq!(blocks.take(5), 0, "taken once");
        }
    }

    /// A read and a write in flight at once, as `h2` drives `PollIo`, over
    /// an in-memory stream: runs under Miri (#501, see `crate::duplex`).
    #[test]
    fn poll_io_reads_while_writing() {
        use crate::duplex::testing::MemStream;
        use std::task::Waker;
        use tokio::io::{AsyncRead, AsyncWrite};

        let wire = wire();
        let (mut io, stream) = PollIo::new(MemStream::new(&wire, 10));
        let blocks = io.header_blocks();
        let mut cx = Context::from_waker(Waker::noop());
        let (mut got, mut sent) = (Vec::new(), Vec::new());
        let mut out = [0u8; 64];
        for turn in 0u8.. {
            let mut rb = ReadBuf::new(&mut out);
            if let Poll::Ready(res) = Pin::new(&mut io).poll_read(&mut cx, &mut rb) {
                res.unwrap();
                if rb.filled().is_empty() {
                    break;
                }
                got.extend_from_slice(rb.filled());
            }
            // Taken at once, also while the last write is in flight.
            let data = [turn; 5];
            if let Poll::Ready(res) = Pin::new(&mut io).poll_write(&mut cx, &data) {
                assert_eq!(res.unwrap(), 5);
                sent.extend_from_slice(&data);
            }
        }
        while Pin::new(&mut io).poll_shutdown(&mut cx).is_pending() {}
        assert_eq!(got, wire);
        drop(io);
        let s = stream.take().expect("PollIo dropped");
        assert_eq!(s.output, sent);
        assert!(s.shut);
        assert_eq!(blocks.take(1), 18);
        assert_eq!(blocks.take(3), 10);
        assert_eq!(blocks.take(5), 11);
    }
}
