//! `aio threads` (#526): blocking file I/O moved off the worker thread to a
//! pool of threads, as nginx's thread pools (`ngx_thread_pool.c`).
//!
//! Each worker has its own pools, as each nginx worker process has: a
//! `thread_pool`'s `threads` and `max_queue` are per worker. Threads start
//! on demand, up to `threads`. A finished task's id goes on the worker's
//! done list and a byte down a socket pair; a task on the worker (`pump`)
//! reads that socket while tasks are out, and wakes their futures. monoio's
//! wakers can't be woken from another thread without its `sync` feature,
//! which would cost every wake-up on the hot path.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::task::{Poll, Waker};

use crate::worker::PreparedErrorLog;

/// nginx's `default` pool, when no `thread_pool default` says otherwise.
pub(crate) const DEFAULT_THREADS: usize = 32;
pub(crate) const DEFAULT_MAX_QUEUE: usize = 65536;

/// A `thread_pool`, as prepared.
#[derive(Debug)]
pub struct ThreadPool {
    pub name: String,
    pub threads: usize,
    pub max_queue: usize,
    /// The top-level `error_log`, for the queue overflow line (nginx logs
    /// it to the cycle's log).
    pub log: &'static [PreparedErrorLog],
}

type Task = Box<dyn FnOnce() + Send>;

struct State {
    queue: VecDeque<Task>,
    /// Tasks a thread is running.
    busy: usize,
    idle: usize,
    threads: usize,
    closed: bool,
}

impl State {
    /// nginx's `waiting`: tasks queued less the threads free to take them,
    /// those not started yet counted (nginx starts them all at once).
    fn waiting(&self, pool: &ThreadPool) -> isize {
        (self.queue.len() + self.busy) as isize - pool.threads as isize
    }
}

struct Shared {
    state: Mutex<State>,
    cond: Condvar,
}

/// The worker's side of the threads: finished task ids, and the socket
/// that wakes `pump`.
struct Done {
    ids: Mutex<Vec<u64>>,
    /// A byte is on its way to `pump` (or `pump` is draining): no other.
    signalled: AtomicBool,
    writer: UnixStream,
}

impl Done {
    fn push(&self, id: u64) {
        self.ids.lock().unwrap_or_else(|e| e.into_inner()).push(id);
        if !self.signalled.swap(true, Ordering::SeqCst) {
            // EAGAIN: the socket holds unread bytes already.
            let _ = (&self.writer).write(&[1]);
        }
    }
}

struct Local {
    pools: Vec<(*const ThreadPool, Arc<Shared>)>,
    done: Arc<Done>,
    /// `None` while `pump` holds it.
    reader: Option<monoio::net::UnixStream>,
    wakers: HashMap<u64, Waker>,
    next_id: u64,
    /// Tasks posted whose ids `pump` hasn't taken yet.
    outstanding: usize,
    pumping: bool,
}

impl Drop for Local {
    fn drop(&mut self) {
        for (_, shared) in &self.pools {
            shared
                .state
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .closed = true;
            shared.cond.notify_all();
        }
    }
}

thread_local! {
    static LOCAL: RefCell<Option<Local>> = const { RefCell::new(None) };
}

fn local_init() -> std::io::Result<Local> {
    let (reader, writer) = UnixStream::pair()?;
    reader.set_nonblocking(true)?;
    writer.set_nonblocking(true)?;
    Ok(Local {
        pools: Vec::new(),
        done: Arc::new(Done {
            ids: Mutex::new(Vec::new()),
            signalled: AtomicBool::new(false),
            writer,
        }),
        reader: Some(monoio::net::UnixStream::from_std(reader)?),
        wakers: HashMap::new(),
        next_id: 0,
        outstanding: 0,
        pumping: false,
    })
}

fn worker_loop(shared: Arc<Shared>) {
    let mut state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    loop {
        if let Some(task) = state.queue.pop_front() {
            state.busy += 1;
            drop(state);
            task();
            state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
            state.busy -= 1;
            continue;
        }
        if state.closed {
            state.threads -= 1;
            return;
        }
        state.idle += 1;
        state = shared.cond.wait(state).unwrap_or_else(|e| e.into_inner());
        state.idle -= 1;
    }
}

/// Queue `task` on `shared`, starting a thread when none is idle and the
/// pool has room for one. `Err` with nginx's count of tasks waiting when
/// the queue is full (ngx_thread_task_post).
fn post(pool: &'static ThreadPool, shared: &Arc<Shared>, task: Task) -> Result<(), isize> {
    let mut state = shared.state.lock().unwrap_or_else(|e| e.into_inner());
    let waiting = state.waiting(pool);
    if waiting >= pool.max_queue as isize {
        return Err(waiting);
    }
    state.queue.push_back(task);
    if state.idle < state.queue.len() && state.threads < pool.threads {
        let thread = Arc::clone(shared);
        let started = std::thread::Builder::new()
            // A NUL in the name would make `spawn` panic.
            .name(format!("aio-{}", pool.name.replace('\0', "")))
            .spawn(move || worker_loop(thread));
        if started.is_ok() {
            state.threads += 1;
        }
    }
    if state.threads == 0 {
        // No thread could be started: nobody would ever run it.
        state.queue.pop_back();
        return Err(waiting);
    }
    shared.cond.notify_one();
    Ok(())
}

/// Wakes the futures of finished tasks while any is out; returns when none
/// is, handing the socket back.
async fn pump() {
    use monoio::io::AsyncReadRent;
    let Some((mut reader, done)) = LOCAL.with(|l| {
        let mut l = l.borrow_mut();
        let l = l.as_mut()?;
        Some((l.reader.take()?, Arc::clone(&l.done)))
    }) else {
        return;
    };
    let mut buf = vec![0u8; 64];
    loop {
        done.signalled.store(false, Ordering::SeqCst);
        let ids = std::mem::take(&mut *done.ids.lock().unwrap_or_else(|e| e.into_inner()));
        let idle = LOCAL.with(|l| {
            let mut l = l.borrow_mut();
            let l = l.as_mut().expect("pump runs with the pools set up");
            for id in ids {
                l.outstanding -= 1;
                if let Some(waker) = l.wakers.remove(&id) {
                    waker.wake();
                }
            }
            if l.outstanding == 0 {
                l.pumping = false;
                true
            } else {
                false
            }
        });
        if idle {
            break;
        }
        let (res, b) = reader.read(buf).await;
        buf = b;
        if !matches!(res, Ok(n) if n > 0) {
            // Can't happen while the writer lives; don't spin.
            monoio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }
    LOCAL.with(|l| {
        if let Some(l) = l.borrow_mut().as_mut() {
            l.reader = Some(reader);
        }
    });
}

/// Runs `f` on one of `pool`'s threads and returns its result. Fails when
/// the pool's queue is full (logged as nginx does) or the task panicked.
/// The task runs to its end even when the future is dropped, so `f` owns
/// everything it touches.
pub(crate) async fn run<T, F>(pool: &'static ThreadPool, f: F) -> std::io::Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> T + Send + 'static,
{
    let slot: Arc<Mutex<Option<std::thread::Result<T>>>> = Arc::new(Mutex::new(None));
    let posted = LOCAL.with(|l| -> std::io::Result<Result<u64, isize>> {
        let mut l = l.borrow_mut();
        if l.is_none() {
            *l = Some(local_init()?);
        }
        let l = l.as_mut().expect("set above");
        let key = pool as *const ThreadPool;
        let shared = match l.pools.iter().find(|(k, _)| *k == key) {
            Some((_, shared)) => Arc::clone(shared),
            None => {
                let shared = Arc::new(Shared {
                    state: Mutex::new(State {
                        queue: VecDeque::new(),
                        busy: 0,
                        idle: 0,
                        threads: 0,
                        closed: false,
                    }),
                    cond: Condvar::new(),
                });
                l.pools.push((key, Arc::clone(&shared)));
                shared
            }
        };
        let id = l.next_id;
        let done = Arc::clone(&l.done);
        let out = Arc::clone(&slot);
        let task: Task = Box::new(move || {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
            *out.lock().unwrap_or_else(|e| e.into_inner()) = Some(result);
            done.push(id);
        });
        if let Err(waiting) = post(pool, &shared, task) {
            return Ok(Err(waiting));
        }
        l.next_id += 1;
        l.outstanding += 1;
        if !l.pumping {
            l.pumping = true;
            monoio::spawn(pump());
        }
        Ok(Ok(id))
    })?;
    let id = match posted {
        Ok(id) => id,
        Err(waiting) => {
            overflow(pool, waiting);
            return Err(std::io::Error::other("thread pool queue overflow"));
        }
    };
    let _wait = Wait { id };
    let result = std::future::poll_fn(|cx| {
        if let Some(result) = slot.lock().unwrap_or_else(|e| e.into_inner()).take() {
            return Poll::Ready(result);
        }
        LOCAL.with(|l| {
            if let Some(l) = l.borrow_mut().as_mut() {
                l.wakers.insert(id, cx.waker().clone());
            }
        });
        Poll::Pending
    })
    .await;
    result.map_err(|_| std::io::Error::other("thread pool task panicked"))
}

/// Forgets the waker of a task whose future is gone.
struct Wait {
    id: u64,
}

impl Drop for Wait {
    fn drop(&mut self) {
        let _ = LOCAL.try_with(|l| {
            if let Some(l) = l.borrow_mut().as_mut() {
                l.wakers.remove(&self.id);
            }
        });
    }
}

#[cold]
fn overflow(pool: &ThreadPool, waiting: isize) {
    crate::worker::write_worker_log(
        pool.log,
        crate::config::ErrorLogLevel::Error,
        &format!(
            "thread pool \"{}\" queue overflow: {waiting} tasks waiting",
            pool.name
        ),
    );
}

/// `pread` until `len` bytes are in `buf` from `offset`: `UnexpectedEof`
/// when the file is shorter than that.
pub(crate) fn pread_exact(
    fd: std::os::unix::io::RawFd,
    buf: &mut [u8],
    offset: u64,
) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buf.len() {
        // SAFETY: the pointer/len pair stays within `buf`.
        let n = unsafe {
            libc::pread(
                fd,
                buf[filled..].as_mut_ptr().cast(),
                buf.len() - filled,
                (offset + filled as u64) as libc::off_t,
            )
        };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        if n == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        filled += n as usize;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(threads: usize, max_queue: usize) -> &'static ThreadPool {
        Box::leak(Box::new(ThreadPool {
            name: "test".to_string(),
            threads,
            max_queue,
            log: &[],
        }))
    }

    fn block_on<F: std::future::Future>(f: F) -> F::Output {
        monoio::RuntimeBuilder::<monoio::FusionDriver>::new()
            .enable_timer()
            .build()
            .expect("runtime")
            .block_on(f)
    }

    #[test]
    fn tasks_run_off_the_worker_and_wake_it() {
        let pool = pool(4, 100);
        let worker = std::thread::current().id();
        let got = block_on(async move {
            let mut all = Vec::new();
            for i in 0..20u64 {
                all.push(monoio::spawn(run(pool, move || {
                    assert_ne!(std::thread::current().id(), worker);
                    std::thread::sleep(std::time::Duration::from_millis(5));
                    i * 2
                })));
            }
            let mut sum = 0;
            for h in all {
                sum += h.await.expect("ran");
            }
            sum
        });
        assert_eq!(got, (0..20).map(|i| i * 2).sum::<u64>());
    }

    #[test]
    fn a_full_queue_fails_the_task() {
        let pool = pool(1, 1);
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let wait = Arc::new(Mutex::new(wait));
        block_on(async move {
            let w = Arc::clone(&wait);
            // The thread takes the first; the second waits; the third
            // finds the queue full (nginx's waiting: 2 tasks - 1 thread).
            let first = monoio::spawn(run(pool, move || {
                let _ = w.lock().unwrap().recv();
            }));
            monoio::time::sleep(std::time::Duration::from_millis(50)).await;
            let second = monoio::spawn(run(pool, || ()));
            monoio::time::sleep(std::time::Duration::from_millis(10)).await;
            assert!(run(pool, || ()).await.is_err());
            release.send(()).unwrap();
            assert!(first.await.is_ok());
            assert!(second.await.is_ok());
        });
    }

    #[test]
    fn a_dropped_future_leaves_the_task_to_finish() {
        let pool = pool(1, 10);
        block_on(async move {
            let fut = run(pool, || {
                std::thread::sleep(std::time::Duration::from_millis(30))
            });
            let _ = monoio::time::timeout(std::time::Duration::from_millis(1), fut).await;
            // The next one is served once the first is done.
            assert_eq!(run(pool, || 7).await.unwrap(), 7);
        });
    }
}
