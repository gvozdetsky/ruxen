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
mod proxy_protocol;
mod syslog;
mod tls;
mod tls_certs;
mod tls_session;
mod tls_stream;
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
