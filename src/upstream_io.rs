//! The connection to an upstream: plain TCP (a `unix:` socket is carried
//! as one too, #101), or TLS over it for `proxy_pass https://` (#116).
//! One type for `attempt`, the keep-alive pool, a relayed body and the
//! tunnel after a 101, so the plain path stays one branch away from what
//! it was.

use std::cell::UnsafeCell;
use std::rc::Rc;

use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut};
use monoio::io::{AsyncReadRent, AsyncWriteRent, OwnedReadHalf, OwnedWriteHalf, Splitable};
use monoio::net::TcpStream;
use rustls::ClientConnection;

use crate::tls_stream::TlsStream;

/// A TLS connection to an upstream.
pub type UpstreamTls = TlsStream<TcpStream, ClientConnection>;

pub enum UpstreamIo {
    Plain(TcpStream),
    Tls(Box<UpstreamTls>),
}

impl UpstreamIo {
    /// The two directions of a tunnel after a 101 (#87): TCP splits as
    /// monoio splits it; TLS is shared by both, which `begin_tunnel` makes
    /// safe (a read no longer writes to the socket).
    pub fn into_tunnel(self) -> (UpstreamRead, UpstreamWrite) {
        match self {
            UpstreamIo::Plain(s) => {
                let (r, w) = s.into_split();
                (UpstreamRead::Plain(r), UpstreamWrite::Plain(w))
            }
            UpstreamIo::Tls(mut s) => {
                s.begin_tunnel();
                let shared = Rc::new(UnsafeCell::new(*s));
                (
                    UpstreamRead::Tls(shared.clone()),
                    UpstreamWrite::Tls(shared),
                )
            }
        }
    }
}

impl AsyncReadRent for UpstreamIo {
    async fn read<T: IoBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamIo::Plain(s) => s.read(buf).await,
            UpstreamIo::Tls(s) => s.read(buf).await,
        }
    }

    async fn readv<T: IoVecBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamIo::Plain(s) => s.readv(buf).await,
            UpstreamIo::Tls(s) => s.readv(buf).await,
        }
    }
}

impl AsyncWriteRent for UpstreamIo {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamIo::Plain(s) => s.write(buf).await,
            UpstreamIo::Tls(s) => s.write(buf).await,
        }
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamIo::Plain(s) => s.writev(buf).await,
            UpstreamIo::Tls(s) => s.writev(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamIo::Plain(s) => s.flush().await,
            UpstreamIo::Tls(s) => s.flush().await,
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamIo::Plain(s) => s.shutdown().await,
            UpstreamIo::Tls(s) => s.shutdown().await,
        }
    }
}

/// The upstream's read direction in a tunnel.
pub enum UpstreamRead {
    Plain(OwnedReadHalf<TcpStream>),
    Tls(Rc<UnsafeCell<UpstreamTls>>),
}

/// The upstream's write direction in a tunnel.
pub enum UpstreamWrite {
    Plain(OwnedWriteHalf<TcpStream>),
    Tls(Rc<UnsafeCell<UpstreamTls>>),
}

impl AsyncReadRent for UpstreamRead {
    async fn read<T: IoBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamRead::Plain(s) => s.read(buf).await,
            // SAFETY: the tunnel's other direction only writes (see
            // `TlsStream::begin_tunnel`); this is the only reader.
            UpstreamRead::Tls(s) => unsafe { &mut *s.get() }.read(buf).await,
        }
    }

    async fn readv<T: IoVecBufMut>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamRead::Plain(s) => s.readv(buf).await,
            // SAFETY: as in `read`.
            UpstreamRead::Tls(s) => unsafe { &mut *s.get() }.readv(buf).await,
        }
    }
}

impl AsyncWriteRent for UpstreamWrite {
    async fn write<T: IoBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamWrite::Plain(s) => s.write(buf).await,
            // SAFETY: the tunnel's other direction only reads; this is the
            // only writer.
            UpstreamWrite::Tls(s) => unsafe { &mut *s.get() }.write(buf).await,
        }
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        match self {
            UpstreamWrite::Plain(s) => s.writev(buf).await,
            // SAFETY: as in `write`.
            UpstreamWrite::Tls(s) => unsafe { &mut *s.get() }.writev(buf).await,
        }
    }

    async fn flush(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamWrite::Plain(s) => s.flush().await,
            // SAFETY: as in `write`.
            UpstreamWrite::Tls(s) => unsafe { &mut *s.get() }.flush().await,
        }
    }

    async fn shutdown(&mut self) -> std::io::Result<()> {
        match self {
            UpstreamWrite::Plain(s) => s.shutdown().await,
            // SAFETY: as in `write`.
            UpstreamWrite::Tls(s) => unsafe { &mut *s.get() }.shutdown().await,
        }
    }
}
