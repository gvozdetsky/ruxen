//! The connection to an upstream: plain TCP (a `unix:` socket is carried
//! as one too, #101), or TLS over it for `proxy_pass https://` (#116).
//! One type for `attempt`, the keep-alive pool, a relayed body and the
//! tunnel after a 101, so the plain path stays one branch away from what
//! it was.

use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut};
use monoio::io::{AsyncReadRent, AsyncWriteRent};
use monoio::net::TcpStream;
use rustls::ClientConnection;

use crate::duplex::{OwnedReadHalf, OwnedWriteHalf, into_split};
use crate::tls_stream::TlsStream;

/// A TLS connection to an upstream.
pub type UpstreamTls = TlsStream<TcpStream, ClientConnection>;

/// A TLS connection, with who it was opened as (`TlsPlan::identity`): the
/// keep-alive pool reuses it only for that. Kept in the box rather than in
/// `PooledConn`, so that a plain pooled connection stays small to move
/// (#451).
pub struct UpstreamTlsConn {
    pub stream: UpstreamTls,
    pub identity: crate::upstream_tls::TlsIdentity,
}

pub enum UpstreamIo {
    Plain(TcpStream),
    Tls(Box<UpstreamTlsConn>),
    /// `proxy_http_version 2` (#599): HTTP/1.1 in and out, a stream on an
    /// HTTP/2 connection underneath. Its operations are boxed, so the
    /// other arms' futures don't grow.
    H2(Box<crate::upstream_h2::H2Conn>),
}

impl UpstreamIo {
    pub fn tls_identity(&self) -> Option<&crate::upstream_tls::TlsIdentity> {
        match self {
            UpstreamIo::Plain(_) => None,
            UpstreamIo::Tls(s) => Some(&s.identity),
            UpstreamIo::H2(c) => c.tls_identity(),
        }
    }

    /// `read` for a relayed body: on plain TCP, `recv_now` (#757).
    pub async fn read_now<T: IoBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamIo::Plain(s) => crate::worker::recv_now(s, buf).await,
            UpstreamIo::Tls(s) => s.stream.read(buf).await,
            UpstreamIo::H2(c) => Box::pin(c.read(buf)).await,
        }
    }

    /// The two directions of a tunnel after a 101 (#87), each a half of
    /// the stream (`crate::duplex`).
    pub fn into_tunnel(self) -> (UpstreamRead, UpstreamWrite) {
        match self {
            UpstreamIo::Plain(s) => {
                let (r, w, _) = into_split(s);
                (UpstreamRead::Plain(r), UpstreamWrite::Plain(w))
            }
            UpstreamIo::Tls(s) => {
                let (r, w, _) = into_split(s.stream);
                (UpstreamRead::Tls(r), UpstreamWrite::Tls(w))
            }
            // An HTTP/2 response is never a 101: the plan has no upgrade.
            UpstreamIo::H2(_) => unreachable!("ruxen: no tunnel over an HTTP/2 upstream"),
        }
    }
}

impl AsyncReadRent for UpstreamIo {
    async fn read<T: IoBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamIo::Plain(s) => s.read(buf).await,
            UpstreamIo::Tls(s) => s.stream.read(buf).await,
            UpstreamIo::H2(c) => Box::pin(c.read(buf)).await,
        }
    }

    async fn readv<T: IoVecBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamIo::Plain(s) => s.readv(buf).await,
            UpstreamIo::Tls(s) => s.stream.readv(buf).await,
            UpstreamIo::H2(c) => Box::pin(c.readv(buf)).await,
        }
    }
}

impl AsyncWriteRent for UpstreamIo {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamIo::Plain(s) => s.write(buf).await,
            UpstreamIo::Tls(s) => s.stream.write(buf).await,
            UpstreamIo::H2(c) => Box::pin(c.write(buf)).await,
        }
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamIo::Plain(s) => s.writev(buf).await,
            UpstreamIo::Tls(s) => s.stream.writev(buf).await,
            UpstreamIo::H2(c) => Box::pin(c.writev(buf)).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamIo::Plain(s) => s.flush().await,
            UpstreamIo::Tls(s) => s.stream.flush().await,
            UpstreamIo::H2(_) => Ok(()),
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamIo::Plain(s) => s.shutdown().await,
            UpstreamIo::Tls(s) => s.stream.shutdown().await,
            UpstreamIo::H2(_) => Ok(()),
        }
    }
}

/// The upstream's read direction in a tunnel.
pub enum UpstreamRead {
    Plain(OwnedReadHalf<TcpStream>),
    Tls(OwnedReadHalf<UpstreamTls>),
}

/// The upstream's write direction in a tunnel.
pub enum UpstreamWrite {
    Plain(OwnedWriteHalf<TcpStream>),
    Tls(OwnedWriteHalf<UpstreamTls>),
}

impl AsyncReadRent for UpstreamRead {
    async fn read<T: IoBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamRead::Plain(s) => s.read(buf).await,
            UpstreamRead::Tls(s) => s.read(buf).await,
        }
    }

    async fn readv<T: IoVecBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamRead::Plain(s) => s.readv(buf).await,
            UpstreamRead::Tls(s) => s.readv(buf).await,
        }
    }
}

impl AsyncWriteRent for UpstreamWrite {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamWrite::Plain(s) => s.write(buf).await,
            UpstreamWrite::Tls(s) => s.write(buf).await,
        }
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamWrite::Plain(s) => s.writev(buf).await,
            UpstreamWrite::Tls(s) => s.writev(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamWrite::Plain(s) => s.flush().await,
            UpstreamWrite::Tls(s) => s.flush().await,
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamWrite::Plain(s) => s.shutdown().await,
            UpstreamWrite::Tls(s) => s.shutdown().await,
        }
    }
}
