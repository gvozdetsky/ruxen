//! One read and one write in flight at once on one stream (#501): an
//! HTTP/2 connection (`PollIo`), the tunnel after a 101 (both of its
//! connections).
//!
//! Two `&mut` to one stream, each held by a suspended operation, would be
//! undefined behaviour, however the operations interleave. So the halves
//! keep a raw pointer, and a `Duplex` operation makes a `&mut` from it only
//! to start an I/O or between awaits, never across one: the two directions'
//! references never overlap, since the worker runs one task at a time.

use std::cell::UnsafeCell;
use std::future::Future;
use std::io;
use std::marker::PhantomData;
use std::ptr::NonNull;
use std::rc::Rc;

use monoio::BufResult;
use monoio::buf::{IoBuf, IoBufMut, IoVecBuf, IoVecBufMut, RawBuf};
use monoio::io::{AsyncReadRent, AsyncWriteRent};
use monoio::net::TcpStream;

/// A stream that can run a read alongside a write or shutdown.
///
/// # Safety
///
/// An implementation's futures reach `*this` only through `this` (or
/// pointers projected from it without a reference, `&raw mut`), and keep no
/// reference to it across an await: the other direction makes its own in
/// between.
pub(crate) unsafe trait Duplex: 'static {
    /// Read into `buf`, as `AsyncReadRent::read`.
    ///
    /// # Safety
    ///
    /// `this` is valid until the future is dropped. Meanwhile no reference
    /// to `*this` is live, and at most one other future of this trait, a
    /// `write_raw` or `shutdown_raw`, runs on it.
    unsafe fn read_raw<T: IoBufMut>(
        this: NonNull<Self>,
        buf: T,
    ) -> impl Future<Output = BufResult<usize, T>> + 'static;

    /// Write from `buf`, as `AsyncWriteRent::write`.
    ///
    /// # Safety
    ///
    /// As `read_raw`, with at most one `read_raw` alongside.
    unsafe fn write_raw<T: IoBuf>(
        this: NonNull<Self>,
        buf: T,
    ) -> impl Future<Output = BufResult<usize, T>> + 'static;

    /// Shut the write direction down, as `AsyncWriteRent::shutdown`.
    ///
    /// # Safety
    ///
    /// As `write_raw`.
    unsafe fn shutdown_raw(this: NonNull<Self>) -> impl Future<Output = io::Result<()>> + 'static;
}

// SAFETY: monoio's `TcpStream` (0.2.4) starts the operation in the call:
// `Op::recv` / `Op::send` take a clone of its fd and the buffer, and the
// future holds those, not the stream; `shutdown` is a syscall in the call.
// The `&mut` made here ends with the call. Recheck on a monoio update.
unsafe impl Duplex for TcpStream {
    unsafe fn read_raw<T: IoBufMut>(
        this: NonNull<Self>,
        buf: T,
    ) -> impl Future<Output = BufResult<usize, T>> + 'static {
        // SAFETY: valid (the caller); see above for the reference.
        unsafe { (*this.as_ptr()).read(buf) }
    }

    unsafe fn write_raw<T: IoBuf>(
        this: NonNull<Self>,
        buf: T,
    ) -> impl Future<Output = BufResult<usize, T>> + 'static {
        // SAFETY: as in `read_raw`.
        unsafe { (*this.as_ptr()).write(buf) }
    }

    unsafe fn shutdown_raw(this: NonNull<Self>) -> impl Future<Output = io::Result<()>> + 'static {
        // SAFETY: as in `read_raw`.
        unsafe { (*this.as_ptr()).shutdown() }
    }
}

/// The read direction of a `Duplex` stream; `K` keeps the stream alive.
pub(crate) struct ReadHalf<S, K> {
    stream: NonNull<S>,
    _keep: K,
}

/// The write direction of a `Duplex` stream; `K` keeps the stream alive.
pub(crate) struct WriteHalf<S, K> {
    stream: NonNull<S>,
    _keep: K,
}

pub(crate) type OwnedReadHalf<S> = ReadHalf<S, Rc<UnsafeCell<S>>>;
pub(crate) type OwnedWriteHalf<S> = WriteHalf<S, Rc<UnsafeCell<S>>>;
pub(crate) type BorrowedReadHalf<'a, S> = ReadHalf<S, PhantomData<&'a mut S>>;
pub(crate) type BorrowedWriteHalf<'a, S> = WriteHalf<S, PhantomData<&'a mut S>>;

/// Halves of a borrowed stream, for as long as the borrow.
pub(crate) fn split<S: Duplex>(
    stream: &mut S,
) -> (BorrowedReadHalf<'_, S>, BorrowedWriteHalf<'_, S>) {
    let ptr = NonNull::from(stream);
    (
        ReadHalf {
            stream: ptr,
            _keep: PhantomData,
        },
        WriteHalf {
            stream: ptr,
            _keep: PhantomData,
        },
    )
}

/// Halves that own the stream between them, and a way to take it back
/// once both are dropped.
pub(crate) fn into_split<S: Duplex>(
    stream: S,
) -> (OwnedReadHalf<S>, OwnedWriteHalf<S>, Reclaim<S>) {
    let shared = Rc::new(UnsafeCell::new(stream));
    // SAFETY: `UnsafeCell::get` is never null.
    let ptr = unsafe { NonNull::new_unchecked(shared.get()) };
    (
        ReadHalf {
            stream: ptr,
            _keep: shared.clone(),
        },
        WriteHalf {
            stream: ptr,
            _keep: shared.clone(),
        },
        Reclaim(shared),
    )
}

/// The stream of `into_split`'s halves, once they are gone.
pub(crate) struct Reclaim<S>(Rc<UnsafeCell<S>>);

impl<S> Reclaim<S> {
    /// `None` while a half is alive.
    pub(crate) fn take(self) -> Option<S> {
        Rc::try_unwrap(self.0).ok().map(UnsafeCell::into_inner)
    }
}

// Each half's operations borrow it mutably, so one runs at a time per half,
// and `_keep` outlives them. Nothing else reaches the stream meanwhile: the
// borrow is `split`'s, and `Reclaim` gives it back only once both halves
// are gone.

impl<S: Duplex, K> AsyncReadRent for ReadHalf<S, K> {
    fn read<T: IoBufMut>(&mut self, buf: T) -> impl Future<Output = BufResult<usize, T>> {
        // SAFETY: see above.
        unsafe { S::read_raw(self.stream, buf) }
    }

    async fn readv<T: IoVecBufMut>(&mut self, mut buf: T) -> BufResult<usize, T> {
        // The first iovec only: a short read, which callers handle.
        // SAFETY: `buf` is owned here and outlives `raw`.
        let res = match unsafe { RawBuf::new_from_iovec_mut(&mut buf) } {
            Some(raw) => self.read(raw).await.0,
            None => Ok(0),
        };
        if let Ok(n) = res {
            // SAFETY: `n` bytes of the first iovec were just written.
            unsafe { buf.set_init(n) };
        }
        (res, buf)
    }
}

impl<S: Duplex, K> AsyncWriteRent for WriteHalf<S, K> {
    fn write<T: IoBuf>(&mut self, buf: T) -> impl Future<Output = BufResult<usize, T>> {
        // SAFETY: see above.
        unsafe { S::write_raw(self.stream, buf) }
    }

    async fn writev<T: IoVecBuf>(&mut self, buf: T) -> BufResult<usize, T> {
        // The first iovec only: a short write, which callers handle.
        // SAFETY: `buf` is owned here and outlives `raw`.
        let res = match unsafe { RawBuf::new_from_iovec(&buf) } {
            Some(raw) => self.write(raw).await.0,
            None => Ok(0),
        };
        (res, buf)
    }

    async fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }

    fn shutdown(&mut self) -> impl Future<Output = io::Result<()>> {
        // SAFETY: see above.
        unsafe { S::shutdown_raw(self.stream) }
    }
}

/// `AsyncWriteRentExt::write_all` over `Duplex::write_raw`.
///
/// # Safety
///
/// As `Duplex::write_raw`.
pub(crate) async unsafe fn write_all_raw<S: Duplex>(
    this: NonNull<S>,
    buf: Vec<u8>,
) -> BufResult<usize, Vec<u8>> {
    use monoio::io::AsyncWriteRentExt;
    WriteHalf {
        stream: this,
        _keep: (),
    }
    .write_all(buf)
    .await
}

/// An in-memory `Duplex` stream, and a test of the halves. No io_uring or
/// sockets, so these run under Miri (#501):
/// `cargo +nightly miri test --bin ruxen duplex`, also with
/// `MIRIFLAGS=-Zmiri-tree-borrows`.
#[cfg(test)]
pub(crate) mod testing {
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    use super::*;

    /// Pending once, as an operation waiting on the socket would be.
    #[derive(Default)]
    struct YieldOnce(bool);

    impl Future for YieldOnce {
        type Output = ();
        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if std::mem::replace(&mut self.0, true) {
                return Poll::Ready(());
            }
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    /// `input` comes in reads of at most `piece` bytes, writes take at most
    /// `piece` bytes each; every operation waits once first. Both
    /// directions count in `ops`, as both change a TLS session.
    pub(crate) struct MemStream {
        pub input: Vec<u8>,
        pub pos: usize,
        pub piece: usize,
        pub output: Vec<u8>,
        pub ops: u64,
        pub shut: bool,
    }

    impl MemStream {
        pub(crate) fn new(input: &[u8], piece: usize) -> Self {
            MemStream {
                input: input.to_vec(),
                pos: 0,
                piece,
                output: Vec::new(),
                ops: 0,
                shut: false,
            }
        }
    }

    // SAFETY: a reference to the stream only after the wait.
    unsafe impl Duplex for MemStream {
        async unsafe fn read_raw<T: IoBufMut>(
            this: NonNull<Self>,
            mut buf: T,
        ) -> BufResult<usize, T> {
            YieldOnce::default().await;
            // SAFETY: the caller's.
            let s = unsafe { &mut *this.as_ptr() };
            s.ops += 1;
            let n = (s.input.len() - s.pos).min(s.piece).min(buf.bytes_total());
            // SAFETY: `n` fits both sides.
            unsafe {
                std::ptr::copy_nonoverlapping(s.input[s.pos..].as_ptr(), buf.write_ptr(), n);
                buf.set_init(n);
            }
            s.pos += n;
            (Ok(n), buf)
        }

        async unsafe fn write_raw<T: IoBuf>(this: NonNull<Self>, buf: T) -> BufResult<usize, T> {
            YieldOnce::default().await;
            // SAFETY: the caller's.
            let s = unsafe { &mut *this.as_ptr() };
            s.ops += 1;
            let n = buf.bytes_init().min(s.piece);
            // SAFETY: `IoBuf` has `bytes_init` bytes at `read_ptr`.
            s.output
                .extend_from_slice(unsafe { std::slice::from_raw_parts(buf.read_ptr(), n) });
            (Ok(n), buf)
        }

        async unsafe fn shutdown_raw(this: NonNull<Self>) -> io::Result<()> {
            YieldOnce::default().await;
            // SAFETY: the caller's.
            let s = unsafe { &mut *this.as_ptr() };
            s.ops += 1;
            s.shut = true;
            Ok(())
        }
    }

    /// Poll `f` to the end; nothing here waits on anything but itself.
    pub(crate) fn finish<F: Future>(f: F) -> F::Output {
        let mut f = std::pin::pin!(f);
        let mut cx = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(out) = f.as_mut().poll(&mut cx) {
                return out;
            }
        }
    }

    /// A read and a write in flight together on one stream, polled in
    /// turn; the stream comes back once the halves are gone.
    #[test]
    fn duplex_halves_interleave() {
        use monoio::io::AsyncWriteRentExt;

        let input: Vec<u8> = (0..200u8).collect();
        let (mut r, mut w, reclaim) = into_split(MemStream::new(&input, 7));
        let mut cx = Context::from_waker(Waker::noop());
        let mut got = Vec::new();
        let mut eof = false;
        {
            let mut reading = Box::pin(r.read(Vec::with_capacity(16)));
            let mut writing = Box::pin(w.write_all(vec![b'x'; 50]));
            let mut written = None;
            while !eof || written.is_none() {
                if !eof && let Poll::Ready((res, mut buf)) = reading.as_mut().poll(&mut cx) {
                    eof = res.unwrap() == 0;
                    got.extend_from_slice(&buf);
                    buf.clear();
                    // The previous read is done: the half is free again.
                    drop(reading);
                    reading = Box::pin(r.read(buf));
                }
                if written.is_none()
                    && let Poll::Ready((res, _)) = writing.as_mut().poll(&mut cx)
                {
                    written = Some(res.unwrap());
                }
            }
            assert_eq!(written, Some(50));
        }
        finish(w.shutdown()).unwrap();
        assert_eq!(got, input);
        drop((r, w));
        let s = reclaim.take().expect("halves gone");
        assert_eq!(s.output, vec![b'x'; 50]);
        assert!(s.shut);
    }

    /// The borrowed halves, as the tunnel uses them.
    #[test]
    fn duplex_split_borrows() {
        use monoio::io::AsyncWriteRentExt;

        let mut s = MemStream::new(b"ping", 3);
        {
            let (mut r, mut w) = split(&mut s);
            let read = async {
                let (res, buf) = r.read(Vec::with_capacity(8)).await;
                (res.unwrap(), buf)
            };
            let write = async { w.write_all(b"pong".to_vec()).await.0.unwrap() };
            let ((n, buf), written) = finish(async { futures_join(read, write).await });
            assert_eq!((n, &buf[..]), (3, &b"pin"[..]));
            assert_eq!(written, 4);
        }
        assert_eq!(s.output, b"pong");
    }

    /// Both futures to the end, polled in turn.
    async fn futures_join<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
        let (mut a, mut b) = (std::pin::pin!(a), std::pin::pin!(b));
        let (mut ra, mut rb) = (None, None);
        std::future::poll_fn(|cx| {
            if ra.is_none()
                && let Poll::Ready(v) = a.as_mut().poll(cx)
            {
                ra = Some(v);
            }
            if rb.is_none()
                && let Poll::Ready(v) = b.as_mut().poll(cx)
            {
                rb = Some(v);
            }
            if ra.is_some() && rb.is_some() {
                return Poll::Ready(());
            }
            Poll::Pending
        })
        .await;
        (ra.unwrap(), rb.unwrap())
    }
}
