//! A proxied response whose body is relayed to the client as it arrives
//! (#88), instead of being read whole first. `proxy::attempt` hands one
//! over when the body didn't come in with the header and nothing needs it
//! whole (no `add_trailer`); the worker writes the head and calls
//! [`relay`]. gzip compresses it on the way (`ProxyStream::gzip`), the
//! range filter cuts one range from it (`ProxyStream::window`), and a
//! cacheable one goes into the cache file as well (`ProxyStream::cache`,
//! #463). As in nginx
//! (`ngx_http_upstream_process_non_buffered_*`), once the head is out an
//! upstream error can't become a 502 or a retry: the client connection is
//! closed.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::task::Poll;
use std::time::Duration;
use std::time::Instant;

use monoio::time::timeout;

use crate::proxy::{AttemptFailure, Stage, UpstreamError};
use crate::upstream::{self, LeasedPeer};

/// The body still to come from the upstream, and how it ends.
pub struct ProxyStream {
    /// The client's header block, through the empty line.
    pub head: Vec<u8>,
    pub(crate) framing: StreamFraming,
    /// Body bytes read together with the header (wire bytes for chunked).
    pub(crate) pending: Vec<u8>,
    pub(crate) upstream: crate::upstream_io::UpstreamIo,
    pub(crate) read_buf: Vec<u8>,
    pub(crate) read_timeout: Duration,
    /// `proxy_limit_rate`, from `pacer_start` with `paced` bytes counted.
    pub(crate) limit_rate: u64,
    pub(crate) pacer_start: Instant,
    pub(crate) paced: u64,
    /// When the try started, for `$upstream_response_time`.
    pub(crate) started: Instant,
    /// Where the connection goes back to once the body is read exactly;
    /// `None`: it closes.
    pub(crate) pool: Option<StreamPool>,
    /// The worker_connections slot the upstream connection holds.
    pub(crate) slot: crate::worker::UpstreamSlot,
    /// `upstream: "…"` for the error log.
    pub(crate) upstream_url: String,
    /// The peer stays leased until the body is in, so `least_conn` counts
    /// it, as nginx frees the peer when the request ends. Only held.
    #[allow(dead_code)]
    pub lease: Option<LeasedPeer>,
    /// gzip compresses the body on its way (`gzip::filter`): the client
    /// gets no length.
    pub(crate) gzip: Option<crate::worker::gzip::GzipStream>,
    /// `proxy_cache`: the body is written to this file as it goes, and
    /// stored once complete (nginx's `p->cacheable`).
    pub(crate) cache: Option<Box<crate::proxy_cache::CacheFill<'static>>>,
    /// The range filter's one range: the client gets these body bytes
    /// only.
    pub(crate) window: Option<Window>,
    /// `add_trailer` or `proxy_pass_trailers`: the body goes chunked, and
    /// the worker writes the last chunk with the trailers
    /// (`RelayEnd::trailers_due`).
    pub(crate) trailers: bool,
    /// `proxy_pass_trailers`: the upstream's trailers, less the hidden
    /// ones, go to the client (`RelayEnd::upstream_trailers`).
    pub(crate) pass_trailers: Option<&'static crate::worker::ProxyResponseRules>,
    /// `proxy_buffering` (#764); `None`: off, or `X-Accel-Buffering: no`.
    pub(crate) buffering: Option<Buffering>,
}

/// The part of the body still to skip, then to send.
#[derive(Clone, Copy)]
pub(crate) struct Window {
    skip: u64,
    left: u64,
}

impl Window {
    /// Body bytes `[start, end)`.
    pub(crate) fn new(start: u64, end: u64) -> Self {
        Window {
            skip: start,
            left: end - start,
        }
    }

    /// The part of the next `body` bytes inside the window.
    fn cut<'a>(&mut self, body: &'a [u8]) -> &'a [u8] {
        let skip = (self.skip.min(body.len() as u64)) as usize;
        self.skip -= skip as u64;
        let rest = &body[skip..];
        let take = (self.left.min(rest.len() as u64)) as usize;
        self.left -= take as u64;
        &rest[..take]
    }
}

/// The client has the whole window.
fn window_sent(window: Option<&Window>) -> bool {
    window.is_some_and(|w| w.left == 0)
}

pub(crate) enum StreamFraming {
    /// `Content-Length`: this many body bytes are still due. The client
    /// gets the upstream's `Content-Length`.
    Length(u64),
    Chunked(ChunkedDecoder),
    /// Close-delimited: the body ends at the upstream's EOF.
    Close,
}

pub(crate) struct StreamPool {
    pub upstream: upstream::UpstreamRef,
    pub peer_idx: usize,
    /// `PreparedProxy::pool_tag`.
    pub tag: usize,
    pub opened_at: Instant,
    pub requests_served: u32,
}

impl ProxyStream {
    /// The client learns the length from the head (`Content-Length`);
    /// otherwise the worker chunks the body (HTTP/1.1) or closes after it.
    pub fn length_known(&self) -> bool {
        matches!(self.framing, StreamFraming::Length(_)) && self.gzip.is_none() && !self.trailers
    }
}

/// How the relay ended.
pub struct RelayEnd {
    /// Bytes written to the client after the head (chunk framing
    /// included), for `$bytes_sent` / `$body_bytes_sent`.
    pub body_sent: u64,
    /// Bytes read from the upstream during the relay.
    pub upstream_read: u64,
    /// Body bytes, from the upstream's point of view, read during the
    /// relay (for `$upstream_response_length`).
    pub upstream_body: u64,
    pub response_ms: u64,
    /// The upstream failed before the body was complete, or sent more
    /// than the body (a warning, the body complete).
    pub failure: Option<AttemptFailure>,
    /// The body reached the client whole.
    pub complete: bool,
    /// The last chunk is still to be written, with the trailers.
    pub trailers_due: bool,
    /// `proxy_pass_trailers`: the upstream's trailer lines to send.
    pub upstream_trailers: Vec<u8>,
}

/// Read buffer of a relay: one read takes whatever the upstream socket
/// holds, up to this, and goes out in one write (nginx reads until EAGAIN
/// before it writes).
const RELAY_BUF: usize = 64 * 1024;
const RELAY_POOL_LIMIT: usize = 32;

/// How long in all a relay waits on a client while memory is full before
/// the rest goes to the temp file. One that keeps up takes it from memory:
/// spilled at once, proxy_1m ran at 62% (ABBA on #834).
const SPILL_AFTER: Duration = Duration::from_millis(100);

thread_local! {
    // Relay buffers have a pool of their own: back in the proxy's pool, one
    // would become the next header read's buffer, which then takes a whole
    // 64 KiB response in, copies it into `accum` and sends it buffered.
    // nginx reads the header into `proxy_buffer_size` (a page).
    static RELAY_POOL: std::cell::RefCell<Vec<Vec<u8>>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

fn take_relay_buf() -> Vec<u8> {
    RELAY_POOL
        .with(|p| p.borrow_mut().pop())
        .unwrap_or_else(|| Vec::with_capacity(RELAY_BUF))
}

/// Return a relay's read buffer to its pool, or a header-sized one to the
/// proxy's.
fn return_read_buf(mut v: Vec<u8>) {
    if v.capacity() != RELAY_BUF {
        crate::proxy::return_proxy_buf(v);
        return;
    }
    v.clear();
    RELAY_POOL.with(|p| {
        let mut pool = p.borrow_mut();
        if pool.len() < RELAY_POOL_LIMIT {
            pool.push(v);
        }
    });
}

/// How a buffered relay keeps what the client hasn't taken yet (#764).
#[derive(Clone, Copy)]
pub(crate) struct Buffering {
    /// Bytes kept in memory: `proxy_buffers`, at least two reads.
    mem: usize,
    /// `proxy_max_temp_file_size`; `0`: no temp file.
    max_temp_file_size: u64,
    /// `proxy_temp_path`; `None`: the http level's request-body directory.
    temp: Option<&'static crate::worker::BodyTempDir>,
}

impl Buffering {
    pub(crate) fn of(rules: &crate::worker::ProxyResponseRules) -> Self {
        Buffering {
            mem: usize::try_from(rules.buffering.buffers)
                .unwrap_or(usize::MAX)
                .max(2 * RELAY_BUF),
            max_temp_file_size: rules.buffering.max_temp_file_size,
            temp: rules.temp,
        }
    }
}

/// Write `head`, then relay the body: the bytes that came with the
/// header, then each upstream read, re-chunked when `chunked_out`. Each
/// client write is held to `send_timeout` (and `limit_rate` through
/// `pacer`), each upstream read to `proxy_read_timeout`. Buffered
/// (`ProxyStream::buffering`), the upstream is read on while the client
/// is slow, into memory and then a temp file, and released once the body
/// is in, as nginx's event pipe does; unbuffered, the next read waits for
/// the last write. Returns `head` as written, for the access log.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn relay<S: crate::worker::ConnIo>(
    mut s: Box<ProxyStream>,
    client: &mut S,
    mut head: Vec<u8>,
    chunked_out: bool,
    mut pacer: Option<crate::worker::Pacer>,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
    default_temp: &crate::worker::BodyTempDir,
) -> (RelayEnd, Vec<u8>) {
    let mut end = RelayEnd {
        body_sent: 0,
        upstream_read: 0,
        upstream_body: 0,
        response_ms: 0,
        failure: None,
        complete: false,
        trailers_due: false,
        upstream_trailers: Vec::new(),
    };
    // The last chunk, unless the worker writes it with the trailers.
    let last_chunk: &'static [u8] = if chunked_out && !s.trailers {
        b"0\r\n\r\n"
    } else {
        b""
    };
    let mut deflater = s.gzip.map(crate::worker::gzip::Deflater::new);

    // The head goes out with whatever body came with it.
    let head_len = head.len();
    let pending = std::mem::take(&mut s.pending);
    let mut extra = false;
    let done = {
        let mut decoded = Vec::new();
        let mut plain = Vec::new();
        let mut compressed = Vec::new();
        match consume_out(
            &mut s.framing,
            &pending,
            chunked_out,
            &mut decoded,
            deflater.as_mut().map(|d| (d, &mut plain, &mut compressed)),
            s.cache.as_deref_mut(),
            s.window.as_mut(),
            &mut head,
        ) {
            Ok((done, _, more)) => {
                extra = more;
                if done {
                    head.extend_from_slice(last_chunk);
                }
                done
            }
            Err(()) => {
                end.failure = Some(failure(&s, UpstreamError::InvalidChunked));
                return finish(s, end, extra, head);
            }
        }
    };
    // `pending` was cut to the body's size: not a read buffer, dropped.
    drop(pending);
    let len = head.len();
    let (ok, returned) =
        write_out(client, head, len, &mut pacer, timer.as_mut(), send_timeout).await;
    head = returned;
    let body_len = head.len().saturating_sub(head_len);
    head.truncate(head_len);
    if !ok {
        return finish(s, end, extra, head);
    }
    end.body_sent += body_len as u64;
    if done || window_sent(s.window.as_ref()) {
        end.complete = true;
        return finish(s, end, extra, head);
    }

    if s.read_buf.capacity() < RELAY_BUF {
        crate::proxy::return_proxy_buf(std::mem::replace(&mut s.read_buf, take_relay_buf()));
    }
    let trailers = s.trailers;
    let direct = !chunked_out
        && deflater.is_none()
        && s.window.is_none()
        && matches!(s.framing, StreamFraming::Length(_));
    let mut rd = BodyReader {
        decoded: Vec::new(),
        plain: Vec::new(),
        compressed: Vec::new(),
        deflater,
        chunked_out,
        last_chunk,
        direct,
        end: ReadEnd {
            done: false,
            extra: false,
            failure: None,
        },
        read: 0,
        body: 0,
    };
    // `proxy_pass_trailers`: the upstream's, taken when it is released.
    let mut passed = Vec::new();
    // The rest often comes in one read: it goes out without the pipe
    // (~2% on a 64 KiB response).
    let step = rd.read(&mut s, Vec::new).await;
    if let Some((data, false)) = step {
        Box::pin(pipelined(
            s,
            rd,
            data,
            client,
            &mut pacer,
            timer.as_mut(),
            send_timeout,
            default_temp,
            &mut end,
            &mut passed,
        ))
        .await;
    } else {
        end.upstream_read = rd.read;
        end.upstream_body = rd.body;
        let mut read_end = rd.end;
        let mut ok = true;
        if let Some((data, _)) = step
            && !data.is_empty()
        {
            let len = data.len();
            let (written, returned) =
                write_out(client, data, len, &mut pacer, timer.as_mut(), send_timeout).await;
            if s.read_buf.capacity() == 0 {
                s.read_buf = returned;
            }
            ok = written;
            if ok {
                end.body_sent += len as u64;
            }
        }
        // Released after the write, as before #764: the other way round
        // the next request's read mostly finds nothing yet and parks.
        end.response_ms = release(
            s,
            read_end.done,
            read_end.extra,
            &mut read_end.failure,
            &mut passed,
        );
        end.failure = read_end.failure;
        end.complete = ok && read_end.done;
    }
    end.trailers_due = trailers && end.complete;
    if end.trailers_due {
        end.upstream_trailers = passed;
    }
    (end, head)
}

/// The relay past its first read: that read's `first` bytes are queued,
/// and the upstream is read on while the client writes.
#[allow(clippy::too_many_arguments)]
async fn pipelined<S: crate::worker::ConnIo>(
    s: Box<ProxyStream>,
    rd: BodyReader,
    first: Vec<u8>,
    client: &mut S,
    pacer: &mut Option<crate::worker::Pacer>,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
    default_temp: &crate::worker::BodyTempDir,
    end: &mut RelayEnd,
    passed: &mut Vec<u8>,
) {
    let started = s.started;
    let has_cache = s.cache.is_some();
    let pipe = Pipe::new(s.buffering, default_temp);
    pipe.upstream_read.set(rd.read);
    pipe.upstream_body.set(rd.body);
    pipe.push(first);
    // The reader's end once the upstream is released, and its time.
    let mut released: Option<(ReadEnd, u64)> = None;
    let mut writer_ok = true;
    {
        let mut reader = std::pin::pin!(read_side(s, rd, &pipe));
        let mut writer = std::pin::pin!(write_side(
            client,
            &pipe,
            pacer,
            timer.as_mut(),
            send_timeout
        ));
        let mut reading = true;
        let mut writing = true;
        // Both sides in this task: each waits on the pipe without a waker,
        // so both are polled again while either changes it.
        std::future::poll_fn(|cx| {
            loop {
                let generation = pipe.generation.get();
                if reading && let Poll::Ready((s, mut read_end)) = reader.as_mut().poll(cx) {
                    reading = false;
                    pipe.reader_done.set(true);
                    pipe.bump();
                    // The body is in: the upstream goes now, not once the
                    // client has it all.
                    let ms = release(
                        s,
                        read_end.done,
                        read_end.extra,
                        &mut read_end.failure,
                        passed,
                    );
                    released = Some((read_end, ms));
                }
                if writing && let Poll::Ready(ok) = writer.as_mut().poll(cx) {
                    writing = false;
                    writer_ok = ok;
                    if !ok {
                        pipe.stop.set(true);
                        pipe.bump();
                    }
                }
                // The client is gone: without a cache file the upstream
                // read is dropped, closing the connection; with one, the
                // reader stops at its read's end and the cache reads on
                // (`fill_detached`).
                if !writing && (!reading || !has_cache) {
                    return Poll::Ready(());
                }
                if generation == pipe.generation.get() {
                    return Poll::Pending;
                }
            }
        })
        .await;
    }
    end.body_sent += pipe.sent.get();
    end.upstream_read = pipe.upstream_read.get();
    end.upstream_body = pipe.upstream_body.get();
    match released {
        Some((read_end, ms)) => {
            end.response_ms = ms;
            end.failure = read_end.failure;
            end.complete = writer_ok && read_end.done;
        }
        None => end.response_ms = started.elapsed().as_millis() as u64,
    }
    pipe.return_bufs();
}

/// What the upstream side of a relay left.
struct ReadEnd {
    /// The client has all it gets once the pipe is drained: the body, or
    /// the range's window.
    done: bool,
    /// Bytes followed the body.
    extra: bool,
    failure: Option<AttemptFailure>,
}

/// Client bytes not written yet, in order.
enum Seg {
    Mem(Vec<u8>),
    /// This many bytes of the temp file, from its read position.
    File(u64),
}

/// Between the upstream reads and the client writes of a relay. Both run
/// in one task, so plain cells.
struct Pipe<'t> {
    segs: RefCell<VecDeque<Seg>>,
    /// `Seg::Mem` bytes.
    mem: Cell<usize>,
    /// Buffers back from the client writes.
    free: RefCell<Vec<Vec<u8>>>,
    spill: RefCell<Spill>,
    buffering: Option<Buffering>,
    default_temp: &'t crate::worker::BodyTempDir,
    /// A client write is under way.
    writing: Cell<bool>,
    reader_done: Cell<bool>,
    /// The client is gone: the reader stops.
    stop: Cell<bool>,
    /// The client stalled (`SPILL_AFTER`): past memory, reads go to the
    /// temp file.
    spilling: Cell<bool>,
    /// Bumped on each change the other side may wait for.
    generation: Cell<u32>,
    sent: Cell<u64>,
    upstream_read: Cell<u64>,
    upstream_body: Cell<u64>,
}

/// The temp file, made on first use; written at `write`, read at `read`.
/// Drained, both go back to 0.
#[derive(Default)]
struct Spill {
    file: Option<std::fs::File>,
    write: u64,
    read: u64,
    /// It couldn't be made or written: memory only from then on.
    off: bool,
}

impl<'t> Pipe<'t> {
    fn new(buffering: Option<Buffering>, default_temp: &'t crate::worker::BodyTempDir) -> Self {
        Pipe {
            segs: RefCell::default(),
            mem: Cell::new(0),
            free: RefCell::default(),
            spill: RefCell::default(),
            buffering,
            default_temp,
            writing: Cell::new(false),
            reader_done: Cell::new(false),
            stop: Cell::new(false),
            spilling: Cell::new(false),
            generation: Cell::new(0),
            sent: Cell::new(0),
            upstream_read: Cell::new(0),
            upstream_body: Cell::new(0),
        }
    }

    fn bump(&self) {
        self.generation.set(self.generation.get().wrapping_add(1));
    }

    /// Whether the reader may read on now. Unbuffered, only once the
    /// client has the last read.
    fn room(&self) -> bool {
        let Some(b) = self.buffering else {
            return self.segs.borrow().is_empty() && !self.writing.get();
        };
        self.mem.get() < b.mem || (self.spilling.get() && self.file_room(b))
    }

    /// Memory is full, and the temp file could take more.
    fn file_room_only(&self) -> bool {
        self.buffering
            .is_some_and(|b| self.mem.get() >= b.mem && self.file_room(b))
    }

    fn file_room(&self, b: Buffering) -> bool {
        let spill = self.spill.borrow();
        !spill.off && spill.write < b.max_temp_file_size
    }

    /// Queue `data` for the client: in memory, or past `proxy_buffers` in
    /// the temp file.
    fn push(&self, data: Vec<u8>) {
        if data.is_empty() || self.stop.get() {
            self.recycle(data);
            return;
        }
        if let Some(b) = self.buffering
            && self.mem.get() >= b.mem
            && self.spill_out(&data, b)
        {
            let mut segs = self.segs.borrow_mut();
            match segs.back_mut() {
                Some(Seg::File(n)) => *n += data.len() as u64,
                _ => segs.push_back(Seg::File(data.len() as u64)),
            }
            drop(segs);
            self.recycle(data);
        } else {
            self.mem.set(self.mem.get() + data.len());
            self.segs.borrow_mut().push_back(Seg::Mem(data));
        }
        self.bump();
    }

    #[cold]
    #[inline(never)]
    fn spill_out(&self, data: &[u8], b: Buffering) -> bool {
        use std::os::unix::fs::FileExt;
        let mut spill = self.spill.borrow_mut();
        if spill.off || spill.write >= b.max_temp_file_size {
            return false;
        }
        if spill.file.is_none() {
            spill.file = crate::worker::new_temp_file(b.temp.unwrap_or(self.default_temp));
        }
        let at = spill.write;
        match spill.file.as_ref().map(|f| f.write_all_at(data, at)) {
            Some(Ok(())) => {
                spill.write += data.len() as u64;
                true
            }
            _ => {
                spill.off = true;
                false
            }
        }
    }

    /// The next bytes for the client; `Err` when the temp file fails.
    fn next(&self) -> Option<Result<Vec<u8>, ()>> {
        let mut segs = self.segs.borrow_mut();
        let out = match segs.front_mut()? {
            Seg::Mem(_) => {
                let Some(Seg::Mem(data)) = segs.pop_front() else {
                    unreachable!()
                };
                self.mem.set(self.mem.get() - data.len());
                Ok(data)
            }
            Seg::File(left) => {
                let n = (*left).min(RELAY_BUF as u64);
                *left -= n;
                if *left == 0 {
                    segs.pop_front();
                }
                self.unspill(n as usize)
            }
        };
        drop(segs);
        self.bump();
        Some(out)
    }

    #[cold]
    #[inline(never)]
    fn unspill(&self, n: usize) -> Result<Vec<u8>, ()> {
        use std::os::unix::fs::FileExt;
        let mut buf = self.read_buf();
        buf.clear();
        buf.resize(n, 0);
        let mut spill = self.spill.borrow_mut();
        let at = spill.read;
        let file = spill.file.as_ref().ok_or(())?;
        file.read_exact_at(&mut buf, at).map_err(drop)?;
        spill.read += n as u64;
        if spill.read == spill.write {
            spill.read = 0;
            spill.write = 0;
        }
        Ok(buf)
    }

    /// A read buffer.
    fn read_buf(&self) -> Vec<u8> {
        let mut free = self.free.borrow_mut();
        match free.iter().rposition(|b| b.capacity() == RELAY_BUF) {
            Some(i) => free.swap_remove(i),
            None => take_relay_buf(),
        }
    }

    /// A buffer for framed bytes.
    fn out_buf(&self) -> Vec<u8> {
        let mut free = self.free.borrow_mut();
        match free.iter().rposition(|b| b.capacity() != RELAY_BUF) {
            Some(i) => free.swap_remove(i),
            None => free.pop().unwrap_or_default(),
        }
    }

    fn recycle(&self, mut buf: Vec<u8>) {
        if buf.capacity() != 0 {
            buf.clear();
            self.free.borrow_mut().push(buf);
        }
    }

    /// The relay's read buffers go back to their pool.
    fn return_bufs(&self) {
        let left: Vec<Seg> = self.segs.borrow_mut().drain(..).collect();
        for seg in left {
            if let Seg::Mem(buf) = seg {
                self.recycle(buf);
            }
        }
        for buf in self.free.borrow_mut().drain(..) {
            if buf.capacity() == RELAY_BUF {
                return_read_buf(buf);
            }
        }
    }
}

/// The upstream side of a relay: decode, compress, cut and cache the body
/// as it is read.
struct BodyReader {
    /// The decoded body of a chunked upstream, and gzip's input and output.
    decoded: Vec<u8>,
    plain: Vec<u8>,
    compressed: Vec<u8>,
    deflater: Option<crate::worker::gzip::Deflater>,
    chunked_out: bool,
    last_chunk: &'static [u8],
    /// A length-framed body to a client that takes it as it is goes out
    /// in the read buffers themselves.
    direct: bool,
    end: ReadEnd,
    /// `$upstream_bytes_received` and `$upstream_response_length` so far.
    read: u64,
    body: u64,
}

impl BodyReader {
    /// One upstream read into `s.read_buf`: the client's bytes from it
    /// (that buffer, or one from `out_buf`), and whether it has all it
    /// gets. `None`: the relay ends (`end.failure`).
    async fn read(
        &mut self,
        s: &mut ProxyStream,
        out_buf: impl FnOnce() -> Vec<u8>,
    ) -> Option<(Vec<u8>, bool)> {
        let mut buf = std::mem::take(&mut s.read_buf);
        buf.clear();
        if s.limit_rate != 0 {
            buf = paced_read_buf(buf, s.limit_rate, s.paced, s.pacer_start);
        }
        let (res, returned) = match timeout(s.read_timeout, s.upstream.read_now(buf)).await {
            Ok(pair) => pair,
            Err(_) => {
                self.end.failure = Some(failure(s, UpstreamError::TimedOut(Stage::ReadingBody)));
                return None;
            }
        };
        s.read_buf = returned;
        let n = match res {
            Ok(0) => {
                if !matches!(s.framing, StreamFraming::Close) {
                    self.end.failure = Some(failure(
                        s,
                        UpstreamError::PrematurelyClosed(Stage::ReadingBody),
                    ));
                    return None;
                }
                // The upstream closed: the body is complete, and nothing
                // goes back to the pool.
                s.pool = None;
                let mut framed = out_buf();
                // The rest of the compressed body.
                if let Some(d) = self.deflater.as_mut() {
                    self.compressed.clear();
                    d.push(&[], &mut self.compressed, true);
                    push_body(&mut framed, &self.compressed, self.chunked_out);
                }
                framed.extend_from_slice(self.last_chunk);
                self.end.done = true;
                return Some((framed, true));
            }
            Ok(n) => n,
            Err(e) => {
                self.end.failure =
                    Some(failure(s, UpstreamError::RecvFailed(e, Stage::ReadingBody)));
                return None;
            }
        };
        self.read += n as u64;
        s.paced += n as u64;
        // proxy_limit_rate: what was read goes out once it is due, the
        // last read too (#700), as the whole-body path waits after each
        // read.
        crate::proxy::pace_body_read(s.limit_rate, s.paced, s.pacer_start).await;
        if self.direct
            && let StreamFraming::Length(left) = &mut s.framing
        {
            let take = n.min(*left as usize);
            self.end.extra |= n > take;
            *left -= take as u64;
            let done = *left == 0;
            self.body += take as u64;
            if let Some(fill) = s.cache.as_deref_mut() {
                fill.write(&s.read_buf[..take]);
            }
            let mut buf = std::mem::take(&mut s.read_buf);
            buf.truncate(take);
            self.end.done = done;
            return Some((buf, done));
        }
        let mut framed = out_buf();
        match consume_out(
            &mut s.framing,
            &s.read_buf[..n],
            self.chunked_out,
            &mut self.decoded,
            self.deflater
                .as_mut()
                .map(|d| (d, &mut self.plain, &mut self.compressed)),
            s.cache.as_deref_mut(),
            s.window.as_mut(),
            &mut framed,
        ) {
            Ok((done, used, more)) => {
                self.end.extra |= more;
                self.body += used as u64;
                if done {
                    framed.extend_from_slice(self.last_chunk);
                }
                let done = done || window_sent(s.window.as_ref());
                self.end.done = done;
                Some((framed, done))
            }
            Err(()) => {
                self.end.failure = Some(failure(s, UpstreamError::InvalidChunked));
                None
            }
        }
    }
}

/// Read and queue the client's bytes while the pipe has room.
async fn read_side(
    mut s: Box<ProxyStream>,
    mut rd: BodyReader,
    pipe: &Pipe<'_>,
) -> (Box<ProxyStream>, ReadEnd) {
    // Time spent waiting on a full memory, to `SPILL_AFTER`.
    let mut stalled = Duration::ZERO;
    loop {
        let mut stall: Option<(Instant, std::pin::Pin<Box<monoio::time::Sleep>>)> = None;
        std::future::poll_fn(|cx| {
            if pipe.stop.get() || pipe.room() {
                return Poll::Ready(());
            }
            if !pipe.file_room_only() {
                return Poll::Pending;
            }
            let (_, timer) = stall.get_or_insert_with(|| {
                let left = SPILL_AFTER.saturating_sub(stalled);
                (Instant::now(), Box::pin(monoio::time::sleep(left)))
            });
            if timer.as_mut().poll(cx).is_ready() {
                pipe.spilling.set(true);
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await;
        if let Some((since, _)) = stall {
            stalled += since.elapsed();
        }
        if pipe.stop.get() {
            break;
        }
        if s.read_buf.capacity() == 0 {
            s.read_buf = pipe.read_buf();
        }
        let step = rd.read(&mut s, || pipe.out_buf()).await;
        pipe.upstream_read.set(rd.read);
        pipe.upstream_body.set(rd.body);
        let Some((data, done)) = step else {
            break;
        };
        pipe.push(data);
        if done {
            break;
        }
    }
    (s, rd.end)
}

/// The client side of a relay: write what the pipe holds until the reader
/// is done and the pipe empty. `false`: the client failed.
async fn write_side<S: crate::worker::ConnIo>(
    client: &mut S,
    pipe: &Pipe<'_>,
    pacer: &mut Option<crate::worker::Pacer>,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
) -> bool {
    loop {
        let next = std::future::poll_fn(|_| match pipe.next() {
            Some(next) => Poll::Ready(Some(next)),
            None if pipe.reader_done.get() => Poll::Ready(None),
            None => Poll::Pending,
        })
        .await;
        let buf = match next {
            None => return true,
            Some(Ok(buf)) => buf,
            Some(Err(())) => return false,
        };
        let len = buf.len();
        pipe.writing.set(true);
        let (ok, returned) = write_out(client, buf, len, pacer, timer.as_mut(), send_timeout).await;
        pipe.writing.set(false);
        pipe.bump();
        if !ok {
            return false;
        }
        pipe.sent.set(pipe.sent.get() + len as u64);
        pipe.recycle(returned);
    }
}

/// Append `input`'s body bytes to `out` as the client gets them. Returns
/// whether the body ended, how many input bytes were body (wire bytes for
/// chunked), and whether bytes followed its end.
fn consume(
    framing: &mut StreamFraming,
    input: &[u8],
    chunked_out: bool,
    decoded: &mut Vec<u8>,
    cache: Option<&mut crate::proxy_cache::CacheFill<'static>>,
    window: Option<&mut Window>,
    out: &mut Vec<u8>,
) -> Result<(bool, usize, bool), ()> {
    let (body, done, used, more) = body_of(framing, input, decoded)?;
    if let Some(fill) = cache {
        fill.write(body);
    }
    let body = match window {
        Some(w) => w.cut(body),
        None => body,
    };
    push_body(out, body, chunked_out);
    Ok((done, used, more))
}

/// The body bytes in `input` (decoded into `decoded` for chunked), and as
/// `consume` returns: whether the body ended, the input bytes used, and
/// whether bytes followed its end.
fn body_of<'a>(
    framing: &mut StreamFraming,
    input: &'a [u8],
    decoded: &'a mut Vec<u8>,
) -> Result<(&'a [u8], bool, usize, bool), ()> {
    match framing {
        StreamFraming::Length(left) => {
            let take = input.len().min(*left as usize);
            *left -= take as u64;
            Ok((&input[..take], *left == 0, take, input.len() > take))
        }
        StreamFraming::Chunked(dec) => {
            decoded.clear();
            let (done, used) = dec.feed(input, decoded)?;
            Ok((&decoded[..], done, used, done && used < input.len()))
        }
        StreamFraming::Close => Ok((input, false, input.len(), false)),
    }
}

/// `consume`, through the compressor when gzip is on: the body's bytes
/// are decoded into `plain`, compressed into `compressed`, and those go
/// out (chunked when `chunked_out`), the end of the member with the last.
#[allow(clippy::too_many_arguments)]
fn consume_out(
    framing: &mut StreamFraming,
    input: &[u8],
    chunked_out: bool,
    decoded: &mut Vec<u8>,
    gzip: Option<(
        &mut crate::worker::gzip::Deflater,
        &mut Vec<u8>,
        &mut Vec<u8>,
    )>,
    cache: Option<&mut crate::proxy_cache::CacheFill<'static>>,
    window: Option<&mut Window>,
    out: &mut Vec<u8>,
) -> Result<(bool, usize, bool), ()> {
    let Some((deflater, plain, compressed)) = gzip else {
        return consume(framing, input, chunked_out, decoded, cache, window, out);
    };
    plain.clear();
    // The range filter leaves a compressed response alone: no window.
    let (done, used, more) = consume(framing, input, false, decoded, cache, None, plain)?;
    compressed.clear();
    deflater.push(plain, compressed, done);
    push_body(out, compressed, chunked_out);
    Ok((done, used, more))
}

/// The relay is over before the pipe: time it, and pool the connection
/// if the body was read exactly.
fn finish(
    s: Box<ProxyStream>,
    mut end: RelayEnd,
    extra: bool,
    head: Vec<u8>,
) -> (RelayEnd, Vec<u8>) {
    end.trailers_due = s.trailers && end.complete;
    let mut passed = Vec::new();
    end.response_ms = release(s, end.complete, extra, &mut end.failure, &mut passed);
    if end.trailers_due {
        end.upstream_trailers = passed;
    }
    (end, head)
}

/// The upstream is done with (`complete`: the client has, or will have,
/// all it gets): take the trailers to pass, warn of bytes past the body,
/// store or go on filling the cache, pool the connection. Returns
/// `$upstream_response_time`.
fn release(
    mut s: Box<ProxyStream>,
    complete: bool,
    extra: bool,
    failure_slot: &mut Option<AttemptFailure>,
    passed: &mut Vec<u8>,
) -> u64 {
    let ms = s.started.elapsed().as_millis() as u64;
    if s.pass_trailers.is_some() {
        *passed = upstream_trailers(&mut s);
    }
    // The client may be done before the body: a range's window.
    let body_done = match &s.framing {
        StreamFraming::Length(left) => *left == 0,
        StreamFraming::Chunked(dec) => dec.done(),
        StreamFraming::Close => complete,
    };
    // nginx warns, and doesn't keep the connection (#512).
    if body_done && extra && failure_slot.is_none() {
        let error = match s.framing {
            StreamFraming::Chunked(_) => UpstreamError::ExtraAfterFinalChunk,
            _ => UpstreamError::ExtraAfterLength,
        };
        *failure_slot = Some(failure(&s, error));
    }
    if s.cache.is_some() {
        // The client went away, or has its range: the cache reads on
        // (nginx's downstream error on a cacheable pipe).
        if !body_done && failure_slot.is_none() {
            fill_detached(s);
            return ms;
        }
        if body_done {
            store(&mut s);
        }
    }
    close(s, body_done, extra);
    ms
}

/// `proxy_pass_trailers`: the trailers the client gets.
#[cold]
#[inline(never)]
fn upstream_trailers(s: &mut ProxyStream) -> Vec<u8> {
    match (&mut s.framing, s.pass_trailers) {
        (StreamFraming::Chunked(dec), Some(rules)) => {
            crate::proxy::passed_trailers(rules, &dec.take_trailers())
        }
        _ => Vec::new(),
    }
}

/// Put a complete body's cache file in place.
#[cold]
#[inline(never)]
fn store(s: &mut ProxyStream) {
    if let Some(fill) = s.cache.take() {
        let _ = fill.finish();
    }
}

/// The upstream connection is done with: back to the pool if the body
/// was read exactly, else closed.
fn close(s: Box<ProxyStream>, complete: bool, extra: bool) {
    let s = *s;
    return_read_buf(s.read_buf);
    if !complete || extra {
        // Closed as it is.
    } else if let Some(pool) = s.pool {
        upstream::pool_release(
            &pool.upstream,
            pool.peer_idx,
            pool.tag,
            upstream::PooledConn {
                stream: s.upstream,
                last_used: Instant::now(),
                opened_at: pool.opened_at,
                requests_served: pool.requests_served + 1,
                slot: s.slot,
            },
        );
    } else if !matches!(s.framing, StreamFraming::Close) {
        // A close-delimited body ended at the upstream's close already.
        upstream::close_after_peer(s.upstream, s.slot);
    }
}

/// The rest of a body only the cache takes, read in a task of its own:
/// the client went away, or got a 304 or a HEAD's answer. nginx reads on
/// for a cacheable response after a downstream error, or for a header-only
/// one (ngx_http_upstream_send_response). Without a cache file the
/// connection just closes.
pub(crate) fn fill_detached(s: Box<ProxyStream>) {
    if s.cache.as_deref().is_some_and(|c| c.writing()) {
        crate::worker::spawn_contained("a proxy_cache store", || {}, fill_cache(s));
    }
}

/// Read the body to its end into the cache file, then store it.
pub(crate) async fn fill_cache(mut s: Box<ProxyStream>) {
    let mut decoded = Vec::new();
    let mut extra = false;
    let pending = std::mem::take(&mut s.pending);
    let mut done = match &s.framing {
        StreamFraming::Length(left) => *left == 0,
        StreamFraming::Chunked(dec) => dec.done(),
        StreamFraming::Close => false,
    };
    if !done && !pending.is_empty() {
        match body_of(&mut s.framing, &pending, &mut decoded) {
            Ok((body, end, _, more)) => {
                if let Some(fill) = s.cache.as_deref_mut() {
                    fill.write(body);
                }
                done = end;
                extra = more;
            }
            Err(()) => return,
        }
    }
    drop(pending);
    if s.read_buf.capacity() < RELAY_BUF {
        crate::proxy::return_proxy_buf(std::mem::replace(&mut s.read_buf, take_relay_buf()));
    }
    while !done {
        if !s.cache.as_deref().is_some_and(|c| c.writing()) {
            return;
        }
        let mut buf = std::mem::take(&mut s.read_buf);
        buf.clear();
        let Ok((res, returned)) = timeout(s.read_timeout, s.upstream.read_now(buf)).await else {
            return;
        };
        s.read_buf = returned;
        let n = match res {
            Ok(0) if matches!(s.framing, StreamFraming::Close) => {
                s.pool = None;
                break;
            }
            Ok(0) | Err(_) => return,
            Ok(n) => n,
        };
        s.paced += n as u64;
        crate::proxy::pace_body_read(s.limit_rate, s.paced, s.pacer_start).await;
        match body_of(&mut s.framing, &s.read_buf[..n], &mut decoded) {
            Ok((body, end, _, more)) => {
                if let Some(fill) = s.cache.as_deref_mut() {
                    fill.write(body);
                }
                done = end;
                extra = more;
            }
            Err(()) => return,
        }
    }
    store(&mut s);
    close(s, true, extra);
}

fn failure(s: &ProxyStream, error: UpstreamError) -> AttemptFailure {
    AttemptFailure {
        error,
        upstream: s.upstream_url.clone(),
    }
}

/// Append body bytes as the client gets them: a chunk, or as they are.
fn push_body(out: &mut Vec<u8>, data: &[u8], chunked_out: bool) {
    if data.is_empty() {
        return;
    }
    if chunked_out {
        let mut hex = [0u8; 16];
        let mut n = data.len();
        let mut i = hex.len();
        loop {
            i -= 1;
            hex[i] = b"0123456789abcdef"[n & 15];
            n >>= 4;
            if n == 0 {
                break;
            }
        }
        out.extend_from_slice(&hex[i..]);
        out.extend_from_slice(b"\r\n");
        out.extend_from_slice(data);
        out.extend_from_slice(b"\r\n");
    } else {
        out.extend_from_slice(data);
    }
}

/// Under `proxy_limit_rate`, a read buffer no larger than what the rate
/// allows so far, as ngx_event_pipe_read_upstream caps each read at
/// `limit_rate * (seconds since the start + 1) - read`: the body then goes
/// out about a second's worth at a time, not a long wait and 64 KiB.
#[cold]
#[inline(never)]
fn paced_read_buf(buf: Vec<u8>, limit_rate: u64, paced: u64, start: std::time::Instant) -> Vec<u8> {
    let allowed = limit_rate
        .saturating_mul(start.elapsed().as_secs() + 1)
        .saturating_sub(paced);
    let cap = (allowed as usize).clamp(1, RELAY_BUF);
    if buf.capacity() > cap || buf.capacity() < cap / 2 {
        return Vec::with_capacity(cap);
    }
    buf
}

/// Write `buf[..len]` with `send_timeout`, under `limit_rate` if any.
async fn write_out<S: crate::worker::ConnIo>(
    client: &mut S,
    buf: Vec<u8>,
    len: usize,
    pacer: &mut Option<crate::worker::Pacer>,
    timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
) -> (bool, Vec<u8>) {
    let (res, returned) = match pacer {
        Some(p) => crate::worker::write_all_paced(client, buf, len, p, timer, send_timeout).await,
        None => crate::worker::write_all_now(client, buf, len, timer, send_timeout).await,
    };
    (res.is_ok(), returned)
}

/// An incremental decoder of a chunked body (RFC 9112 7.1): chunk
/// extensions are dropped, trailers too unless kept (`keeping_trailers`).
#[derive(Default)]
pub(crate) struct ChunkedDecoder {
    state: ChunkState,
    /// A size or trailer line split across reads.
    line: Vec<u8>,
    /// `proxy_pass_trailers`: the trailer lines, CRLF each.
    trailers: Option<Vec<u8>>,
}

/// The trailer section kept, as nginx's `proxy_buffer_size` bounds it
/// (a page by default): past it, "upstream sent too big trailers".
const MAX_TRAILERS: usize = 4096;

#[derive(Default)]
enum ChunkState {
    /// Reading a chunk-size line.
    #[default]
    Size,
    /// This many data bytes left in the chunk.
    Data(u64),
    /// The CRLF after a chunk's data.
    DataEnd,
    /// Trailer lines after the last chunk, up to the empty line.
    Trailer,
    Done,
}

/// Upper bound on a size or trailer line kept across reads.
const MAX_CHUNK_LINE: usize = 4096;

impl ChunkedDecoder {
    /// Decode `input` into `out`. Returns whether the body ended and how
    /// many bytes of `input` it used (the rest is past its end).
    pub(crate) fn feed(&mut self, input: &[u8], out: &mut Vec<u8>) -> Result<(bool, usize), ()> {
        let mut pos = 0;
        while pos < input.len() {
            match self.state {
                ChunkState::Done => break,
                ChunkState::Data(left) => {
                    let take = (input.len() - pos).min(left as usize);
                    out.extend_from_slice(&input[pos..pos + take]);
                    pos += take;
                    self.state = if left == take as u64 {
                        ChunkState::DataEnd
                    } else {
                        ChunkState::Data(left - take as u64)
                    };
                }
                ChunkState::Size | ChunkState::DataEnd | ChunkState::Trailer => {
                    let Some(nl) = input[pos..].iter().position(|&b| b == b'\n') else {
                        self.line.extend_from_slice(&input[pos..]);
                        if self.line.len() > MAX_CHUNK_LINE {
                            return Err(());
                        }
                        pos = input.len();
                        break;
                    };
                    self.line.extend_from_slice(&input[pos..pos + nl]);
                    pos += nl + 1;
                    let line = std::mem::take(&mut self.line);
                    // CRLF only, as nginx since 1.29.4: a bare LF is where
                    // parsers behind other intermediaries disagree on the
                    // body's end (ngx_http_parse_chunked, #585).
                    let Some(line) = line.strip_suffix(b"\r") else {
                        return Err(());
                    };
                    self.state = match self.state {
                        ChunkState::DataEnd => {
                            if !line.is_empty() {
                                return Err(());
                            }
                            ChunkState::Size
                        }
                        ChunkState::Trailer => {
                            if line.is_empty() {
                                ChunkState::Done
                            } else {
                                if let Some(kept) = &mut self.trailers {
                                    keep_trailer(kept, line)?;
                                }
                                ChunkState::Trailer
                            }
                        }
                        _ => {
                            // nginx's rules, past its off_t refused too
                            // (ngx_http_parse_chunked, #508).
                            match crate::http::parse_chunk_size(line) {
                                Some(0) => ChunkState::Trailer,
                                Some(n) => ChunkState::Data(n),
                                None => return Err(()),
                            }
                        }
                    };
                }
            }
        }
        Ok((matches!(self.state, ChunkState::Done), pos))
    }

    /// The last chunk and the trailer are in.
    pub(crate) fn done(&self) -> bool {
        matches!(self.state, ChunkState::Done)
    }

    /// One that keeps the trailer lines (`take_trailers`).
    pub(crate) fn keeping_trailers() -> Self {
        ChunkedDecoder {
            trailers: Some(Vec::new()),
            ..Default::default()
        }
    }

    pub(crate) fn take_trailers(&mut self) -> Vec<u8> {
        self.trailers.take().unwrap_or_default()
    }
}

/// A trailer line, kept if it's a field (nginx's parser skips the rest);
/// a CR or NUL in it is an error.
fn keep_trailer(kept: &mut Vec<u8>, line: &[u8]) -> Result<(), ()> {
    if line.iter().any(|&b| b == b'\r' || b == 0) {
        return Err(());
    }
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return Ok(());
    };
    if colon == 0 || line[..colon].iter().any(|&b| b == b' ' || b == b'\t') {
        return Ok(());
    }
    if kept.len() + line.len() + 2 > MAX_TRAILERS {
        return Err(());
    }
    kept.extend_from_slice(line);
    kept.extend_from_slice(b"\r\n");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_in_pieces(wire: &[u8], piece: usize) -> (Vec<u8>, bool, usize) {
        let mut dec = ChunkedDecoder::default();
        let mut out = Vec::new();
        let mut used_total = 0;
        for part in wire.chunks(piece) {
            let (done, used) = dec.feed(part, &mut out).unwrap();
            used_total += used;
            if done {
                return (out, true, used_total);
            }
        }
        (out, false, used_total)
    }

    #[test]
    fn chunked_decoder_is_split_independent() {
        let wire = b"5;ext=1\r\nhello\r\n10\r\n0123456789abcdef\r\n0\r\nX-T: 1\r\n\r\nNEXT";
        for piece in 1..wire.len() {
            let (out, done, used) = decode_in_pieces(wire, piece);
            assert!(done, "piece {piece}");
            assert_eq!(out, b"hello0123456789abcdef", "piece {piece}");
            assert_eq!(used, wire.len() - 4, "piece {piece}");
        }
    }

    #[test]
    fn chunked_decoder_refuses_garbage() {
        let mut dec = ChunkedDecoder::default();
        assert!(dec.feed(b"zz\r\n", &mut Vec::new()).is_err());
        let mut dec = ChunkedDecoder::default();
        assert!(dec.feed(b"2\r\nabX\r\n", &mut Vec::new()).is_err());
        let mut dec = ChunkedDecoder::default();
        assert!(
            dec.feed(&[b'1'; MAX_CHUNK_LINE + 2], &mut Vec::new())
                .is_err()
        );
    }

    #[test]
    fn chunked_decoder_keeps_trailers() {
        let wire = b"3\r\nabc\r\n0\r\nX-T: 1\r\nno colon\r\n:x\r\nY-T:2\r\n\r\nNEXT";
        for piece in 1..wire.len() {
            let mut dec = ChunkedDecoder::keeping_trailers();
            let mut out = Vec::new();
            for part in wire.chunks(piece) {
                if dec.feed(part, &mut out).unwrap().0 {
                    break;
                }
            }
            assert!(dec.done(), "piece {piece}");
            assert_eq!(out, b"abc");
            assert_eq!(dec.take_trailers(), b"X-T: 1\r\nY-T:2\r\n", "piece {piece}");
        }
        // Too big, or a NUL: an error.
        let mut dec = ChunkedDecoder::keeping_trailers();
        let line = format!("X: {}\r\n", "v".repeat(1000));
        let wire = format!("0\r\n{}", line.repeat(5));
        assert!(dec.feed(wire.as_bytes(), &mut Vec::new()).is_err());
        let mut dec = ChunkedDecoder::keeping_trailers();
        assert!(dec.feed(b"0\r\nX: \0\r\n\r\n", &mut Vec::new()).is_err());
        // Not kept: dropped, whatever they are.
        let mut dec = ChunkedDecoder::default();
        assert!(dec.feed(b"0\r\nX: \0\r\n\r\n", &mut Vec::new()).unwrap().0);
        assert!(dec.take_trailers().is_empty());
    }

    /// A bare LF anywhere in the framing is refused, as nginx 1.29.4+
    /// does (#585): after a size, after data, after the last chunk, in a
    /// trailer.
    #[test]
    fn chunked_decoder_refuses_a_bare_lf() {
        for wire in [
            &b"3\nok!\r\n0\r\n\r\n"[..],
            b"3\r\nok!\n0\r\n\r\n",
            b"3\r\nok!\r\n0\n\r\n",
            b"3\r\nok!\r\n0\r\nX: 1\n\r\n",
            b"3\r\nok!\r\n0\r\n\n",
        ] {
            let mut dec = ChunkedDecoder::default();
            assert!(
                dec.feed(wire, &mut Vec::new()).is_err(),
                "{}",
                String::from_utf8_lossy(wire)
            );
        }
    }

    #[test]
    fn chunks_go_out_with_hex_sizes() {
        let mut out = Vec::new();
        push_body(&mut out, &[b'a'; 26], true);
        assert_eq!(&out[..4], b"1a\r\n");
        assert!(out.ends_with(b"a\r\n"));
        let mut out = Vec::new();
        push_body(&mut out, b"", true);
        assert!(out.is_empty());
    }
}
