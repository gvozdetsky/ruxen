//! A proxied response whose body is relayed to the client as it arrives
//! (#88), instead of being read whole first. `proxy::attempt` hands one
//! over when the body didn't come in with the header and nothing needs it
//! whole (no `add_trailer`, no range to cut); the worker writes the head
//! and calls [`relay`]. gzip compresses it on the way
//! (`ProxyStream::gzip`), and a cacheable one goes into the cache file
//! as well (`ProxyStream::cache`, #463). As in nginx
//! (`ngx_http_upstream_process_non_buffered_*`), once the head is out an
//! upstream error can't become a 502 or a retry: the client connection is
//! closed.

use std::time::Duration;
use std::time::Instant;

use monoio::io::AsyncReadRent;
use monoio::time::timeout;

use crate::proxy::{AttemptFailure, Stage, UpstreamError};
use crate::upstream::{self, LeasedPeer};
use crate::worker::PreparedUpstream;

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
    pub upstream: &'static PreparedUpstream,
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
        matches!(self.framing, StreamFraming::Length(_)) && self.gzip.is_none()
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
}

/// Read buffer of a relay: one read takes whatever the upstream socket
/// holds, up to this, and goes out in one write (nginx reads until EAGAIN
/// before it writes).
const RELAY_BUF: usize = 64 * 1024;
const RELAY_POOL_LIMIT: usize = 32;

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

/// Write `head`, then relay the body: the bytes that came with the
/// header, then each upstream read, re-chunked when `chunked_out`. Each
/// client write is held to `send_timeout` (and `limit_rate` through
/// `pacer`), each upstream read to `proxy_read_timeout`. Returns `head`
/// as written, for the access log.
pub(crate) async fn relay<S: crate::worker::ConnIo>(
    mut s: Box<ProxyStream>,
    client: &mut S,
    mut head: Vec<u8>,
    chunked_out: bool,
    mut pacer: Option<crate::worker::Pacer>,
    mut timer: std::pin::Pin<&mut monoio::time::Sleep>,
    send_timeout: Duration,
) -> (RelayEnd, Vec<u8>) {
    let mut end = RelayEnd {
        body_sent: 0,
        upstream_read: 0,
        upstream_body: 0,
        response_ms: 0,
        failure: None,
        complete: false,
    };
    // Bytes past the end of the body: the connection can't be pooled.
    let mut extra = false;
    // Client bytes when they differ from the input: chunk framing, or the
    // decoded body of a chunked upstream.
    let mut framed = Vec::new();
    let mut decoded = Vec::new();
    // gzip: the body as it decodes, and what the compressor makes of it.
    let mut deflater = s.gzip.map(crate::worker::gzip::Deflater::new);
    let mut plain = Vec::new();
    let mut compressed = Vec::new();

    // The head goes out with whatever body came with it.
    let head_len = head.len();
    let pending = std::mem::take(&mut s.pending);
    let done = match consume_out(
        &mut s.framing,
        &pending,
        chunked_out,
        &mut decoded,
        deflater.as_mut().map(|d| (d, &mut plain, &mut compressed)),
        s.cache.as_deref_mut(),
        &mut head,
    ) {
        Ok((done, _, more)) => {
            extra |= more;
            done
        }
        Err(()) => {
            end.failure = Some(failure(&s, UpstreamError::InvalidChunked));
            return finish(s, end, extra, head);
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
    if done {
        end.complete = true;
        return finish(s, end, extra, head);
    }

    if s.read_buf.capacity() < RELAY_BUF {
        crate::proxy::return_proxy_buf(std::mem::replace(&mut s.read_buf, take_relay_buf()));
    }
    loop {
        let mut buf = std::mem::take(&mut s.read_buf);
        buf.clear();
        if s.limit_rate != 0 {
            buf = paced_read_buf(buf, s.limit_rate, s.paced, s.pacer_start);
        }
        let (res, returned) = match timeout(s.read_timeout, s.upstream.read(buf)).await {
            Ok(pair) => pair,
            Err(_) => {
                end.failure = Some(failure(&s, UpstreamError::TimedOut(Stage::ReadingBody)));
                break;
            }
        };
        s.read_buf = returned;
        let n = match res {
            Ok(0) => {
                if matches!(s.framing, StreamFraming::Close) {
                    // The upstream closed: the body is complete, and
                    // nothing goes back to the pool.
                    s.pool = None;
                    framed.clear();
                    // The rest of the compressed body.
                    if let Some(d) = deflater.as_mut() {
                        compressed.clear();
                        d.push(&[], &mut compressed, true);
                        push_body(&mut framed, &compressed, chunked_out);
                    }
                    if chunked_out {
                        framed.extend_from_slice(b"0\r\n\r\n");
                    }
                    if !framed.is_empty() {
                        let len = framed.len();
                        let (ok, _) = write_out(
                            client,
                            framed,
                            len,
                            &mut pacer,
                            timer.as_mut(),
                            send_timeout,
                        )
                        .await;
                        if !ok {
                            break;
                        }
                        end.body_sent += len as u64;
                    }
                    end.complete = true;
                } else {
                    end.failure = Some(failure(
                        &s,
                        UpstreamError::PrematurelyClosed(Stage::ReadingBody),
                    ));
                }
                break;
            }
            Ok(n) => n,
            Err(e) => {
                end.failure = Some(failure(
                    &s,
                    UpstreamError::RecvFailed(e, Stage::ReadingBody),
                ));
                break;
            }
        };
        end.upstream_read += n as u64;
        s.paced += n as u64;
        // proxy_limit_rate: what was read goes out once it is due, the
        // last read too (#700), as the whole-body path waits after each
        // read.
        crate::proxy::pace_body_read(s.limit_rate, s.paced, s.pacer_start).await;
        // A length-framed body to a client that takes it as it is goes
        // out of the read buffer itself.
        if !chunked_out
            && deflater.is_none()
            && let StreamFraming::Length(left) = &mut s.framing
        {
            let take = n.min(*left as usize);
            extra |= n > take;
            *left -= take as u64;
            let done = *left == 0;
            end.upstream_body += take as u64;
            if let Some(fill) = s.cache.as_deref_mut() {
                fill.write(&s.read_buf[..take]);
            }
            let buf = std::mem::take(&mut s.read_buf);
            let (ok, returned) =
                write_out(client, buf, take, &mut pacer, timer.as_mut(), send_timeout).await;
            s.read_buf = returned;
            if !ok {
                break;
            }
            end.body_sent += take as u64;
            if done {
                end.complete = true;
                break;
            }
            continue;
        }
        framed.clear();
        let input = &s.read_buf[..n];
        let done = match consume_out(
            &mut s.framing,
            input,
            chunked_out,
            &mut decoded,
            deflater.as_mut().map(|d| (d, &mut plain, &mut compressed)),
            s.cache.as_deref_mut(),
            &mut framed,
        ) {
            Ok((done, used, more)) => {
                extra |= more;
                end.upstream_body += used as u64;
                done
            }
            Err(()) => {
                end.failure = Some(failure(&s, UpstreamError::InvalidChunked));
                break;
            }
        };
        if !framed.is_empty() {
            let len = framed.len();
            let (ok, returned) = write_out(
                client,
                framed,
                len,
                &mut pacer,
                timer.as_mut(),
                send_timeout,
            )
            .await;
            framed = returned;
            if !ok {
                break;
            }
            end.body_sent += len as u64;
        }
        if done {
            end.complete = true;
            break;
        }
    }
    finish(s, end, extra, head)
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
    out: &mut Vec<u8>,
) -> Result<(bool, usize, bool), ()> {
    let chunked_in = matches!(framing, StreamFraming::Chunked(_));
    let (body, done, used, more) = body_of(framing, input, decoded)?;
    if let Some(fill) = cache {
        fill.write(body);
    }
    push_body(out, body, chunked_out);
    if done && chunked_out && chunked_in {
        out.extend_from_slice(b"0\r\n\r\n");
    }
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
    out: &mut Vec<u8>,
) -> Result<(bool, usize, bool), ()> {
    let Some((deflater, plain, compressed)) = gzip else {
        return consume(framing, input, chunked_out, decoded, cache, out);
    };
    plain.clear();
    let (done, used, more) = consume(framing, input, false, decoded, cache, plain)?;
    compressed.clear();
    deflater.push(plain, compressed, done);
    push_body(out, compressed, chunked_out);
    if done && chunked_out {
        out.extend_from_slice(b"0\r\n\r\n");
    }
    Ok((done, used, more))
}

/// The relay is over: time it, and pool the connection if the body was
/// read exactly.
fn finish(
    mut s: Box<ProxyStream>,
    mut end: RelayEnd,
    extra: bool,
    head: Vec<u8>,
) -> (RelayEnd, Vec<u8>) {
    end.response_ms = s.started.elapsed().as_millis() as u64;
    // nginx warns, and doesn't keep the connection (#512).
    if end.complete && extra && end.failure.is_none() {
        let error = match s.framing {
            StreamFraming::Chunked(_) => UpstreamError::ExtraAfterFinalChunk,
            _ => UpstreamError::ExtraAfterLength,
        };
        end.failure = Some(failure(&s, error));
    }
    if s.cache.is_some() {
        // The client went away: the cache reads on (nginx's downstream
        // error on a cacheable pipe).
        if !end.complete && end.failure.is_none() {
            fill_detached(s);
            return (end, head);
        }
        if end.complete {
            store(&mut s);
        }
    }
    close(s, end.complete, extra);
    (end, head)
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
    if complete
        && !extra
        && let Some(pool) = s.pool
    {
        upstream::pool_release(
            pool.upstream,
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
        let Ok((res, returned)) = timeout(s.read_timeout, s.upstream.read(buf)).await else {
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
/// extensions and trailers are dropped. Buffered bodies go through it too
/// (`read_chunked_body_with_buf`).
#[derive(Default)]
pub(crate) struct ChunkedDecoder {
    state: ChunkState,
    /// A size or trailer line split across reads.
    line: Vec<u8>,
}

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
