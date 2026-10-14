//! Ownership of what a configuration generation leaks (#343).
//!
//! `prepare` hands every worker and connection `&'static` references into
//! the prepared configuration, so it builds it with leaked boxes. Without
//! more, every reload left the configuration it replaced in memory. Here
//! the leaks made while an arena is open on the current thread (the
//! thread that runs `prepare`) are recorded; once the generation's workers
//! are joined, `main` frees them, as nginx destroys an old cycle's pool
//! (`ngx_clean_old_cycles`).
//!
//! A leak made while no arena is open (a worker's lazy caches, unit tests)
//! stays leaked, as before. So does anything a later generation keeps:
//! those use `Box::leak` directly (the state of `limit_req` / `limit_conn`
//! zones, cache zones, the buffered access-log registry).

use std::cell::RefCell;

type Free = Box<dyn FnOnce() + Send>;

thread_local! {
    static OPEN: RefCell<Option<Vec<Free>>> = const { RefCell::new(None) };
}

/// The leaks recorded between `open` and `close`. Dropping it frees
/// nothing (the memory stays leaked); `free` does.
#[must_use]
pub(crate) struct Arena(Vec<Free>);

impl Arena {
    /// Free everything recorded, newest first.
    ///
    /// # Safety
    /// Nothing that can still run may hold a reference into it: the
    /// generation's workers are joined, and nothing kept for the next
    /// generation points into it.
    pub(crate) unsafe fn free(mut self) {
        while let Some(free) = self.0.pop() {
            free();
        }
    }

    /// How many allocations it holds.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.0.len()
    }
}

/// Start recording this thread's `leak`s.
pub(crate) fn open() {
    OPEN.with(|open| {
        let mut open = open.borrow_mut();
        assert!(open.is_none(), "an arena is already open on this thread");
        *open = Some(Vec::new());
    });
}

/// Stop recording and take what was recorded.
pub(crate) fn close() -> Arena {
    Arena(
        OPEN.with(|open| open.borrow_mut().take())
            .unwrap_or_default(),
    )
}

/// A raw pointer that may cross to the thread that frees it.
struct Owned<T: ?Sized>(*mut T);

// SAFETY: `T: Send`; the pointer is dereferenced once, by `free`.
unsafe impl<T: ?Sized + Send> Send for Owned<T> {}

impl<T: ?Sized> Owned<T> {
    /// # Safety
    /// As `Arena::free`.
    unsafe fn free(self) {
        // SAFETY: from `Box::into_raw` in `leak`, freed once.
        drop(unsafe { Box::from_raw(self.0) });
    }
}

/// `Box::leak`, recorded in this thread's open arena if there is one.
pub(crate) fn leak<T: ?Sized + Send + 'static>(value: Box<T>) -> &'static mut T {
    let ptr = Box::into_raw(value);
    OPEN.with(|open| {
        if let Some(recorded) = open.borrow_mut().as_mut() {
            let owned = Owned(ptr);
            // SAFETY: run only by `Arena::free`, under its contract.
            recorded.push(Box::new(move || unsafe { owned.free() }));
        }
    });
    // SAFETY: from `Box::into_raw` just above; freed only by `Arena::free`.
    unsafe { &mut *ptr }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Counted(Arc<AtomicUsize>);

    impl Drop for Counted {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn frees_what_was_leaked_while_open() {
        let dropped = Arc::new(AtomicUsize::new(0));
        open();
        let _a: &'static Counted = leak(Box::new(Counted(dropped.clone())));
        let _b: &'static [u8] = leak(vec![1u8, 2, 3].into_boxed_slice());
        let arena = close();
        // Not recorded: no arena is open any more.
        let _c: &'static Counted = leak(Box::new(Counted(dropped.clone())));
        assert_eq!(arena.len(), 2);
        // On another thread, as `main` frees a generation.
        std::thread::spawn(move || unsafe { arena.free() })
            .join()
            .unwrap();
        assert_eq!(dropped.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dropping_an_arena_keeps_the_memory() {
        let dropped = Arc::new(AtomicUsize::new(0));
        open();
        let kept: &'static Counted = leak(Box::new(Counted(dropped.clone())));
        drop(close());
        assert_eq!(dropped.load(Ordering::SeqCst), 0);
        assert_eq!(Arc::strong_count(&kept.0), 2);
    }
}
