//! A proxied response whose body is relayed to the client as it arrives
//! (#88), instead of being read whole first. `proxy::attempt` hands one
//! over when the body didn't come in with the header and nothing needs it
//! whole (no cache store, no `add_trailer`, no failover or interception on
//! the status); the worker writes the head and calls [`relay`]. gzip
//! compresses it on the way (`ProxyStream::gzip`). As in nginx
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
    pub opened_at: Instant,
    pub requests_served: u32,
    pub tls: Option<crate::upstream_tls::TlsIdentity>,
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
    /// The upstream failed before the body was complete.
    pub failure: Option<AttemptFailure>,
    /// The body reached the client whole.
    pub complete: bool,
}

/// Read buffer of a relay: one read takes whatever the upstream socket
/// holds, up to this, and goes out in one write (nginx reads until EAGAIN
/// before it writes).
const RELAY_BUF: usize = 64 * 1024;

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
        crate::proxy::return_proxy_buf(std::mem::replace(
            &mut s.read_buf,
            Vec::with_capacity(RELAY_BUF),
        ));
    }
    loop {
        // proxy_limit_rate: wait until the body read so far is due.
        crate::proxy::pace_body_read(s.limit_rate, s.paced, s.pacer_start).await;
        let mut buf = std::mem::take(&mut s.read_buf);
        buf.clear();
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
    out: &mut Vec<u8>,
) -> Result<(bool, usize, bool), ()> {
    match framing {
        StreamFraming::Length(left) => {
            let take = input.len().min(*left as usize);
            push_body(out, &input[..take], chunked_out);
            *left -= take as u64;
            Ok((*left == 0, take, input.len() > take))
        }
        StreamFraming::Chunked(dec) => {
            decoded.clear();
            let (done, used) = dec.feed(input, decoded)?;
            push_body(out, decoded, chunked_out);
            if done && chunked_out {
                out.extend_from_slice(b"0\r\n\r\n");
            }
            Ok((done, used, done && used < input.len()))
        }
        StreamFraming::Close => {
            push_body(out, input, chunked_out);
            Ok((false, input.len(), false))
        }
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
    out: &mut Vec<u8>,
) -> Result<(bool, usize, bool), ()> {
    let Some((deflater, plain, compressed)) = gzip else {
        return consume(framing, input, chunked_out, decoded, out);
    };
    plain.clear();
    let (done, used, more) = consume(framing, input, false, decoded, plain)?;
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
    s: Box<ProxyStream>,
    mut end: RelayEnd,
    extra: bool,
    head: Vec<u8>,
) -> (RelayEnd, Vec<u8>) {
    end.response_ms = s.started.elapsed().as_millis() as u64;
    let s = *s;
    crate::proxy::return_proxy_buf(s.read_buf);
    if end.complete
        && !extra
        && let Some(pool) = s.pool
    {
        upstream::pool_release(
            pool.upstream,
            pool.peer_idx,
            upstream::PooledConn {
                stream: s.upstream,
                last_used: Instant::now(),
                opened_at: pool.opened_at,
                requests_served: pool.requests_served + 1,
                slot: s.slot,
                tls: pool.tls,
            },
        );
    }
    (end, head)
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
        None => crate::worker::write_all_timed(client, buf, len, timer, send_timeout).await,
    };
    (res.is_ok(), returned)
}

/// An incremental decoder of a chunked body (RFC 9112 7.1): chunk
/// extensions and trailers are dropped, as `read_chunked_body_with_buf`
/// does for buffered bodies.
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
                    let line = line.strip_suffix(b"\r").unwrap_or(&line);
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
                            let size = line.split(|&b| b == b';').next().unwrap_or(&[]);
                            let size = std::str::from_utf8(size).map_err(|_| ())?.trim();
                            match u64::from_str_radix(size, 16) {
                                Ok(0) => ChunkState::Trailer,
                                // nginx refuses sizes past its off_t
                                // (ngx_http_parse_chunked).
                                Ok(n) if n <= i64::MAX as u64 => ChunkState::Data(n),
                                _ => return Err(()),
                            }
                        }
                    };
                }
            }
        }
        Ok((matches!(self.state, ChunkState::Done), pos))
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
