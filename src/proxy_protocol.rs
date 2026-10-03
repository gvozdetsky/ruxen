//! The PROXY protocol header (versions 1 and 2) a load balancer sends
//! ahead of the connection's own bytes, for `listen … proxy_protocol`
//! (nginx's `src/core/ngx_proxy_protocol.c`).
//!
//! The header is read with `MSG_PEEK` first and then consumed exactly, so
//! whatever follows — the HTTP request or a TLS ClientHello — stays in the
//! socket for the usual read path (nginx peeks the same way before its TLS
//! handshake).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;
use std::time::Duration;

/// The client's and the proxy's addresses as the header gives them.
/// `None` for `PROXY UNKNOWN` and v2 `LOCAL` (health checks): the
/// connection is used with its own addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxyHeader {
    pub source: Option<SocketAddr>,
    pub destination: Option<SocketAddr>,
}

/// The v2 signature.
const V2_SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";

/// nginx's limit for a v1 line (`NGX_PROXY_PROTOCOL_V1_MAX_HEADER`).
const V1_MAX: usize = 107;

/// Longest v2 header accepted: the fixed part plus 4 KiB of addresses and
/// TLVs (nginx reads v2 into its regular header buffer too).
const V2_MAX: usize = 16 + 4096;

#[derive(Debug, PartialEq, Eq)]
pub enum Parsed {
    /// A header of this many bytes.
    Header(ProxyHeader, usize),
    /// Cut short. `read` refuses it, as nginx does.
    Incomplete,
    /// Not a PROXY header; the text is for the error log.
    Invalid(&'static str),
}

/// Parse a header at the start of `buf`.
pub fn parse(buf: &[u8]) -> Parsed {
    if buf.starts_with(b"PROXY ") || b"PROXY ".starts_with(buf) {
        return parse_v1(buf);
    }
    let sig = buf.len().min(V2_SIGNATURE.len());
    if buf[..sig] == V2_SIGNATURE[..sig] {
        return parse_v2(buf);
    }
    Parsed::Invalid("broken header")
}

fn parse_v1(buf: &[u8]) -> Parsed {
    let Some(end) = buf.windows(2).position(|w| w == b"\r\n") else {
        return if buf.len() >= V1_MAX {
            Parsed::Invalid("too long header")
        } else {
            Parsed::Incomplete
        };
    };
    let len = end + 2;
    if len > V1_MAX {
        return Parsed::Invalid("too long header");
    }
    let Ok(line) = std::str::from_utf8(&buf[6..end]) else {
        return Parsed::Invalid("broken header");
    };
    let fields: Vec<&str> = line.split(' ').collect();
    let unknown = ProxyHeader {
        source: None,
        destination: None,
    };
    match fields.as_slice() {
        ["UNKNOWN", ..] => Parsed::Header(unknown, len),
        [family @ ("TCP4" | "TCP6"), src, dst, sport, dport] => {
            let v6 = *family == "TCP6";
            let addr = |ip: &str, port: &str| -> Option<SocketAddr> {
                let ip: IpAddr = if v6 {
                    IpAddr::V6(ip.parse::<Ipv6Addr>().ok()?)
                } else {
                    IpAddr::V4(ip.parse::<Ipv4Addr>().ok()?)
                };
                // Ports are decimal without leading zeros, as nginx checks.
                if port.len() > 1 && port.starts_with('0') {
                    return None;
                }
                Some(SocketAddr::new(ip, port.parse().ok()?))
            };
            match (addr(src, sport), addr(dst, dport)) {
                (Some(source), Some(destination)) => Parsed::Header(
                    ProxyHeader {
                        source: Some(source),
                        destination: Some(destination),
                    },
                    len,
                ),
                _ => Parsed::Invalid("broken header"),
            }
        }
        _ => Parsed::Invalid("broken header"),
    }
}

fn parse_v2(buf: &[u8]) -> Parsed {
    if buf.len() < 16 {
        return Parsed::Incomplete;
    }
    let version = buf[12] >> 4;
    let command = buf[12] & 0x0f;
    if version != 2 {
        return Parsed::Invalid("unknown PROXY protocol version");
    }
    let body_len = u16::from_be_bytes([buf[14], buf[15]]) as usize;
    let len = 16 + body_len;
    if len > V2_MAX {
        return Parsed::Invalid("too long header");
    }
    if buf.len() < len {
        return Parsed::Incomplete;
    }
    let body = &buf[16..len];
    let unknown = ProxyHeader {
        source: None,
        destination: None,
    };
    match command {
        // LOCAL: the proxy's own connection (a health check).
        0 => return Parsed::Header(unknown, len),
        1 => {}
        _ => return Parsed::Invalid("unknown command"),
    }
    let header = match buf[13] >> 4 {
        // AF_INET: 4 + 4 + 2 + 2.
        1 if body.len() >= 12 => {
            let ip = |b: &[u8]| IpAddr::V4(Ipv4Addr::new(b[0], b[1], b[2], b[3]));
            let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
            ProxyHeader {
                source: Some(SocketAddr::new(ip(&body[0..4]), port(&body[8..10]))),
                destination: Some(SocketAddr::new(ip(&body[4..8]), port(&body[10..12]))),
            }
        }
        // AF_INET6: 16 + 16 + 2 + 2.
        2 if body.len() >= 36 => {
            let ip = |b: &[u8]| {
                let octets: [u8; 16] = b.try_into().expect("16 bytes");
                IpAddr::V6(Ipv6Addr::from(octets))
            };
            let port = |b: &[u8]| u16::from_be_bytes([b[0], b[1]]);
            ProxyHeader {
                source: Some(SocketAddr::new(ip(&body[0..16]), port(&body[32..34]))),
                destination: Some(SocketAddr::new(ip(&body[16..32]), port(&body[34..36]))),
            }
        }
        // AF_UNSPEC / AF_UNIX: no usable addresses, as nginx.
        0 | 3 => unknown,
        _ => return Parsed::Invalid("broken header"),
    };
    Parsed::Header(header, len)
}

/// `what: "<the bytes>"`, as nginx shows a header it refused: up to the
/// first CR or LF (and, here, at most a v1 line's worth).
fn broken(what: &str, got: &[u8]) -> String {
    let line = got.iter().position(|&b| b == b'\r' || b == b'\n');
    let end = line.unwrap_or(got.len()).min(V1_MAX);
    let shown = String::from_utf8_lossy(&got[..end]).into_owned();
    format!("{what}: \"{}\"", shown.escape_debug())
}

/// Read the PROXY header off `stream` within `timeout`, leaving the bytes
/// after it in the socket. `Err` carries the reason for the error log;
/// the caller closes the connection.
pub async fn read(
    stream: &monoio::net::TcpStream,
    timeout: Duration,
) -> Result<ProxyHeader, String> {
    let deadline = monoio::time::Instant::now() + timeout;
    let fd = stream.as_raw_fd();
    let mut buf = vec![0u8; V2_MAX];
    loop {
        let remaining = deadline.saturating_duration_since(monoio::time::Instant::now());
        if remaining.is_zero() {
            return Err("client timed out while reading PROXY protocol".into());
        }
        if monoio::time::timeout(remaining, stream.readable(false))
            .await
            .is_err()
        {
            return Err("client timed out while reading PROXY protocol".into());
        }
        // SAFETY: recv into our own buffer; MSG_DONTWAIT keeps it from
        // blocking the worker whatever the socket's mode.
        let n = unsafe {
            libc::recv(
                fd,
                buf.as_mut_ptr().cast(),
                buf.len(),
                libc::MSG_PEEK | libc::MSG_DONTWAIT,
            )
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock {
                continue;
            }
            return Err(format!("recv() failed ({e})"));
        }
        if n == 0 {
            return Err("client closed connection while reading PROXY protocol".into());
        }
        match parse(&buf[..n as usize]) {
            Parsed::Header(header, len) => {
                // Consume exactly the header.
                // SAFETY: as above; the bytes are already in the socket.
                let consumed =
                    unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), len, libc::MSG_DONTWAIT) };
                if consumed != len as isize {
                    return Err("recv() of the PROXY protocol header failed".into());
                }
                return Ok(header);
            }
            refused => {
                let got = &buf[..n as usize];
                let reason = match refused {
                    // What arrived first is all nginx looks at: its
                    // ngx_http_wait_request_handler reads once and hands
                    // that to ngx_proxy_protocol_read, so a header cut
                    // short is refused, not waited for. A v2 header whose
                    // addresses didn't all arrive gets nginx's "header is
                    // too large" (sic); anything else is a broken header.
                    Parsed::Incomplete if got.len() >= 16 && got.starts_with(V2_SIGNATURE) => {
                        "header is too large".into()
                    }
                    Parsed::Invalid(what) => broken(what, got),
                    _ => broken("broken header", got),
                };
                // nginx has read these bytes; take them off the socket
                // too, so closing it is a FIN rather than a reset.
                // SAFETY: as above.
                unsafe { libc::recv(fd, buf.as_mut_ptr().cast(), n as usize, libc::MSG_DONTWAIT) };
                return Err(reason);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(src: &str, dst: &str) -> ProxyHeader {
        ProxyHeader {
            source: Some(src.parse().unwrap()),
            destination: Some(dst.parse().unwrap()),
        }
    }

    #[test]
    fn v1() {
        let line = b"PROXY TCP4 192.0.2.1 192.0.2.2 51000 80\r\nGET / HTTP/1.0\r\n";
        assert_eq!(
            parse(line),
            Parsed::Header(header("192.0.2.1:51000", "192.0.2.2:80"), 41)
        );
        let line = b"PROXY TCP6 2001:db8::1 2001:db8::2 1 443\r\n";
        assert_eq!(
            parse(line),
            Parsed::Header(header("[2001:db8::1]:1", "[2001:db8::2]:443"), line.len())
        );
        assert_eq!(
            parse(b"PROXY UNKNOWN\r\n"),
            Parsed::Header(
                ProxyHeader {
                    source: None,
                    destination: None
                },
                15
            )
        );
        assert_eq!(parse(b"PROXY TCP4 192.0.2.1"), Parsed::Incomplete);
        assert_eq!(parse(b"PRO"), Parsed::Incomplete);
        assert!(matches!(parse(b"GET / HTTP/1.0\r\n"), Parsed::Invalid(_)));
        assert!(matches!(
            parse(b"PROXY TCP4 192.0.2.1 192.0.2.2 01 80\r\n"),
            Parsed::Invalid(_)
        ));
        assert!(matches!(
            parse(b"PROXY TCP4 2001:db8::1 192.0.2.2 1 80\r\n"),
            Parsed::Invalid(_)
        ));
        let long = [b"PROXY TCP4 ".as_slice(), &[b'1'; 120]].concat();
        assert!(matches!(parse(&long), Parsed::Invalid("too long header")));
    }

    #[test]
    fn v2() {
        let mut h = V2_SIGNATURE.to_vec();
        h.extend_from_slice(&[0x21, 0x11, 0, 12]);
        h.extend_from_slice(&[192, 0, 2, 1, 192, 0, 2, 2, 0xc7, 0x38, 0, 80]);
        h.extend_from_slice(b"GET");
        assert_eq!(
            parse(&h),
            Parsed::Header(header("192.0.2.1:51000", "192.0.2.2:80"), 28)
        );
        assert_eq!(parse(&h[..20]), Parsed::Incomplete);
        // LOCAL, with a TLV it doesn't need to understand.
        let mut local = V2_SIGNATURE.to_vec();
        local.extend_from_slice(&[0x20, 0x00, 0, 3, 1, 0, 0]);
        assert_eq!(
            parse(&local),
            Parsed::Header(
                ProxyHeader {
                    source: None,
                    destination: None
                },
                19
            )
        );
        let mut bad = V2_SIGNATURE.to_vec();
        bad.extend_from_slice(&[0x31, 0x11, 0, 0]);
        assert!(matches!(parse(&bad), Parsed::Invalid(_)));
    }
}
