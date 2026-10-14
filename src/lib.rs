//! The library view of ruxen's sources, for the fuzz targets in `fuzz/`
//! only (#217). With the `fuzzing` feature this compiles the binary's
//! module tree a second time and exposes a few parser entry points in
//! `fuzzing`. Without the feature, which is every normal build, the
//! library is empty.

#![cfg(feature = "fuzzing")]
#![allow(dead_code, unused_imports, unused_variables, unused_macros, unused_mut)]

mod auth;
mod autoindex;
mod config;
mod file;
mod fs_resolve;
mod http;
mod http_date;
mod phase;
mod privileges;
mod proxy;
mod proxy_cache;
mod proxy_protocol;
mod proxy_stream;
mod syslog;
mod tls;
mod tls_certs;
mod tls_session;
mod tls_stream;
mod tls_ticket;
mod upstream;
mod uri;
mod worker;

/// Entry points for the fuzz targets: thin wrappers over the parsers that
/// see untrusted bytes.
pub mod fuzzing {
    /// `http::parse_request` over `data`; `Some(consumed)` when it found a
    /// complete request head, `None` for "need more", panics never.
    pub fn parse_request(data: &[u8]) -> Option<Result<usize, ()>> {
        let mut st = crate::http::ParseState::default();
        match crate::http::parse_request(data, &mut st) {
            crate::http::Parse::Complete(req) => Some(Ok(req.consumed)),
            crate::http::Parse::Incomplete => None,
            _ => Some(Err(())),
        }
    }

    /// The same request fed in two pieces, split at `at`: the incremental
    /// parser must reach the same answer as for the whole buffer.
    pub fn parse_request_split(data: &[u8], at: usize) -> Option<Result<usize, ()>> {
        let at = at.min(data.len());
        let mut st = crate::http::ParseState::default();
        match crate::http::parse_request(&data[..at], &mut st) {
            crate::http::Parse::Incomplete => {}
            crate::http::Parse::Complete(req) => return Some(Ok(req.consumed)),
            _ => return Some(Err(())),
        }
        match crate::http::parse_request(data, &mut st) {
            crate::http::Parse::Complete(req) => Some(Ok(req.consumed)),
            crate::http::Parse::Incomplete => None,
            _ => Some(Err(())),
        }
    }

    /// `http::normalize_host` over the whole of `data`: the host and port
    /// ranges it found.
    pub fn normalize_host(data: &[u8]) -> Option<((usize, usize), Option<(usize, usize)>)> {
        crate::http::normalize_host(data, 0, data.len()).map(|h| (h.host, h.port))
    }

    /// `uri::normalize_with`: `Ok` with the normalized path, or `Err`.
    pub fn normalize_uri(data: &[u8], merge_slashes: bool) -> Result<Vec<u8>, ()> {
        let mut out = Vec::new();
        crate::uri::normalize_with(data, merge_slashes, &mut out)
            .map(|_| out)
            .map_err(drop)
    }

    /// `proxy_protocol::parse`.
    pub fn proxy_protocol(data: &[u8]) {
        let _ = crate::proxy_protocol::parse(data);
    }

    /// The chunked request-body decoder (`read_chunked_request_body`) over
    /// `data`: the first `initial` bytes as already read with the head,
    /// the rest delivered `piece` bytes per read. `Ok((decoded body, raw
    /// bytes consumed))`, or `Err` for a refused body. The decoder must not
    /// depend on how the input was split into reads.
    pub fn chunked_body(
        data: &[u8],
        initial: usize,
        piece: usize,
        max_body: u64,
    ) -> Result<(Vec<u8>, u64), ()> {
        thread_local! {
            static RUNTIME: std::cell::RefCell<
                monoio::Runtime<monoio::time::TimeDriver<monoio::LegacyDriver>>,
            > =
                std::cell::RefCell::new(
                    monoio::RuntimeBuilder::<monoio::LegacyDriver>::new()
                        .enable_timer()
                        .build()
                        .expect("monoio runtime"),
                );
        }
        let initial = initial.min(data.len());
        let mut reader = Pieces {
            data: data[initial..].to_vec(),
            pos: 0,
            piece: piece.max(1),
        };
        RUNTIME.with(|rt| {
            rt.borrow_mut().block_on(async {
                let temp = crate::worker::BodyTempDir::new(None);
                let mut sink = crate::worker::BodySink::with_capacity(0, &temp, false);
                let timer =
                    std::pin::pin!(monoio::time::sleep(std::time::Duration::from_secs(3600)));
                let decoded = crate::worker::read_chunked_request_body(
                    &mut reader,
                    &data[..initial],
                    max_body,
                    &mut sink,
                    timer,
                    std::time::Duration::from_secs(3600),
                )
                .await;
                let (body, _file) = sink.finish();
                match decoded {
                    Ok(done) => Ok((body.to_vec(), done.raw_consumed)),
                    Err(_) => Err(()),
                }
            })
        })
    }

    /// An upstream's response head as the proxy reads it (#217): where it
    /// ends, found in one read and in two split at `at` (the second search
    /// resumes 3 bytes back, as `proxy::attempt` does), which must agree;
    /// then the status and each field as the proxy classifies it. A
    /// summary for the target's checks: (head end, terminator length,
    /// status, field count, content length).
    pub fn upstream_head(
        data: &[u8],
        at: usize,
    ) -> Option<(usize, usize, u16, usize, Option<u64>)> {
        use crate::proxy::*;
        let whole = find_head_end(data, 0);
        let at = at.min(data.len());
        let split =
            find_head_end(&data[..at], 0).or_else(|| find_head_end(data, at.saturating_sub(3)));
        assert_eq!(whole, split, "split at {at}");
        let (end, term) = whole?;
        let head = &data[..end];
        let (first_len, _) = find_line_end(head).unwrap_or((head.len(), 0));
        let status = parse_status_code(&head[..first_len]);
        let mut pos = headers_start(data, first_len, end);
        let mut fields = 0;
        let mut length = None;
        while pos < end {
            let (len, t) = find_line_end(&head[pos..]).unwrap_or((end - pos, 0));
            let line = &head[pos..pos + len];
            if let Some(colon) = line.iter().position(|&b| b == b':') {
                fields += 1;
                if classify_upstream_header(&line[..colon]) == UpstreamHeader::ContentLength {
                    length = parse_content_length(line[colon + 1..].trim_ascii());
                }
            }
            if t == 0 {
                break;
            }
            pos += len + t;
        }
        Some((end, term, status, fields, length))
    }

    /// The decoder of a chunked upstream body relayed to the client
    /// (`proxy_stream::ChunkedDecoder`, #88) over `data` in pieces of
    /// `piece` bytes: (decoded body, whether it ended, bytes used), or
    /// `Err` for a refused body.
    pub fn upstream_chunked(data: &[u8], piece: usize) -> Result<(Vec<u8>, bool, usize), ()> {
        let mut dec = crate::proxy_stream::ChunkedDecoder::default();
        let mut out = Vec::new();
        let mut used = 0;
        for part in data.chunks(piece.max(1)) {
            let (done, n) = dec.feed(part, &mut out)?;
            used += n;
            if done {
                return Ok((out, true, used));
            }
        }
        Ok((out, false, used))
    }

    /// In-memory input delivered at most `piece` bytes per read; EOF after.
    struct Pieces {
        data: Vec<u8>,
        pos: usize,
        piece: usize,
    }

    impl monoio::io::AsyncReadRent for Pieces {
        async fn read<T: monoio::buf::IoBufMut>(
            &mut self,
            mut buf: T,
        ) -> monoio::BufResult<usize, T> {
            let n = self
                .piece
                .min(self.data.len() - self.pos)
                .min(buf.bytes_total());
            // SAFETY: `n` is within both the source and the buffer's
            // capacity, and the bytes are initialized by the copy.
            unsafe {
                std::ptr::copy_nonoverlapping(self.data[self.pos..].as_ptr(), buf.write_ptr(), n);
                buf.set_init(n);
            }
            self.pos += n;
            (Ok(n), buf)
        }

        async fn readv<T: monoio::buf::IoVecBufMut>(
            &mut self,
            buf: T,
        ) -> monoio::BufResult<usize, T> {
            (Err(std::io::ErrorKind::Unsupported.into()), buf)
        }
    }

    /// The configuration parser over `text`. `include` is refused under
    /// the `fuzzing` feature, so nothing outside the input is read.
    pub fn parse_config(text: &str) -> bool {
        crate::config::parse_with_main(
            std::path::PathBuf::from("/nonexistent/ruxen-fuzz.conf"),
            text.to_string(),
            None,
        )
        .is_ok()
    }
}
