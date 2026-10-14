//! The `http2_*` directives of `ngx_http_v2_module` (#346), at http and
//! server level; a server's unset ones inherit from http. `http2` itself
//! (on/off) is parsed with the other server settings. The obsolete
//! directives are accepted with nginx's warning and change nothing, as in
//! nginx ≥ 1.25.1 (server push is gone, the timeouts and limits moved to
//! the core module's directives).

use super::*;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Http2Conf {
    /// `http2_max_concurrent_streams` (default 128).
    pub max_concurrent_streams: Option<u32>,
    /// `http2_body_preread_size` (default 64k): the stream window.
    pub body_preread_size: Option<u32>,
    /// `http2_chunk_size` (default 8k): the largest DATA frame sent.
    pub chunk_size: Option<u32>,
}

/// The obsolete ones, with what replaces each (`None`: nothing).
const OBSOLETE: &[(&str, Option<&str>)] = &[
    ("http2_idle_timeout", Some("keepalive_timeout")),
    ("http2_recv_timeout", Some("client_header_timeout")),
    ("http2_max_requests", Some("keepalive_requests")),
    ("http2_max_field_size", Some("large_client_header_buffers")),
    ("http2_max_header_size", Some("large_client_header_buffers")),
    ("http2_push", None),
    ("http2_push_preload", None),
    ("http2_max_concurrent_pushes", None),
];

/// Memory tuning of nginx's own allocator, which ruxen has no use for:
/// accepted, nothing applied.
const NO_OP: &[&str] = &[
    "http2_recv_buffer_size",
    "http2_pool_size",
    "http2_streams_index_size",
];

impl Http2Conf {
    pub(crate) fn takes(name: &str) -> bool {
        matches!(
            name,
            "http2_max_concurrent_streams" | "http2_body_preread_size" | "http2_chunk_size"
        ) || OBSOLETE.iter().any(|(n, _)| *n == name)
            || NO_OP.contains(&name)
    }

    pub(crate) fn inherit(self, parent: &Http2Conf) -> Http2Conf {
        Http2Conf {
            max_concurrent_streams: self
                .max_concurrent_streams
                .or(parent.max_concurrent_streams),
            body_preread_size: self.body_preread_size.or(parent.body_preread_size),
            chunk_size: self.chunk_size.or(parent.chunk_size),
        }
    }

    pub(crate) fn parse(
        &mut self,
        args: &[String],
        warnings: &mut Vec<String>,
    ) -> Result<(), Error> {
        let name = args[0].as_str();
        let what: &'static str = match name {
            "http2_max_concurrent_streams" => "http2_max_concurrent_streams",
            "http2_body_preread_size" => "http2_body_preread_size",
            "http2_chunk_size" => "http2_chunk_size",
            _ => {
                if args.len() != 2 {
                    return Err(Error::BadValue {
                        what: "http2 directive",
                        got: args.join(" "),
                    });
                }
                if let Some((_, instead)) = OBSOLETE.iter().find(|(n, _)| *n == name) {
                    let w = match instead {
                        Some(new) => format!(
                            "the \"{name}\" directive is obsolete, use the \"{new}\" directive instead"
                        ),
                        None => format!("the \"{name}\" directive is obsolete, ignored"),
                    };
                    if !warnings.contains(&w) {
                        warnings.push(w);
                    }
                }
                return Ok(());
            }
        };
        let [_, value] = args else {
            return Err(Error::BadValue {
                what,
                got: args.join(" "),
            });
        };
        let bad = || Error::BadValue {
            what,
            got: value.clone(),
        };
        let slot = match name {
            "http2_max_concurrent_streams" => &mut self.max_concurrent_streams,
            "http2_body_preread_size" => &mut self.body_preread_size,
            _ => &mut self.chunk_size,
        };
        if slot.is_some() {
            return Err(Error::Duplicate(what));
        }
        let n = if name == "http2_max_concurrent_streams" {
            value.parse::<u64>().map_err(|_| bad())?
        } else {
            parse_location::parse_size(value.as_bytes()).ok_or_else(bad)?
        };
        // nginx: the preread size is at most the largest window, and a
        // chunk of 0 is "invalid".
        let n = match name {
            "http2_body_preread_size" if n > (1 << 31) - 1 => {
                return Err(Error::BadValue {
                    what,
                    got: format!("{value}: the maximum body preread buffer size is 2147483647"),
                });
            }
            "http2_chunk_size" if n == 0 => {
                return Err(Error::BadValue {
                    what,
                    got: format!("{value}: the http2 chunk size cannot be zero"),
                });
            }
            _ => u32::try_from(n).map_err(|_| bad())?,
        };
        *slot = Some(n);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(line: &str) -> Vec<String> {
        line.split_whitespace().map(String::from).collect()
    }

    #[test]
    fn tunables_parse_and_inherit() {
        let mut http = Http2Conf::default();
        let mut w = Vec::new();
        http.parse(&args("http2_max_concurrent_streams 64"), &mut w)
            .unwrap();
        http.parse(&args("http2_chunk_size 16k"), &mut w).unwrap();
        let mut server = Http2Conf::default();
        server
            .parse(&args("http2_body_preread_size 0"), &mut w)
            .unwrap();
        let merged = server.inherit(&http);
        assert_eq!(merged.max_concurrent_streams, Some(64));
        assert_eq!(merged.chunk_size, Some(16384));
        assert_eq!(merged.body_preread_size, Some(0));
        assert!(w.is_empty());
        assert!(http.parse(&args("http2_chunk_size 4k"), &mut w).is_err());
        assert!(server.parse(&args("http2_chunk_size 0"), &mut w).is_err());
        assert!(
            server
                .parse(&args("http2_max_concurrent_streams x"), &mut w)
                .is_err()
        );
    }

    #[test]
    fn obsolete_ones_warn_like_nginx() {
        let mut conf = Http2Conf::default();
        let mut w = Vec::new();
        conf.parse(&args("http2_idle_timeout 3m"), &mut w).unwrap();
        conf.parse(&args("http2_push /style.css"), &mut w).unwrap();
        conf.parse(&args("http2_recv_buffer_size 512k"), &mut w)
            .unwrap();
        assert_eq!(
            w,
            vec![
                "the \"http2_idle_timeout\" directive is obsolete, use the \"keepalive_timeout\" directive instead",
                "the \"http2_push\" directive is obsolete, ignored",
            ]
        );
        assert_eq!(conf, Http2Conf::default());
    }
}
