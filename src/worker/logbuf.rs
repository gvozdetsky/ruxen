//! Buffered access_log files (`buffer=`, `flush=`, `gzip`; #151), as
//! nginx's ngx_http_log_module keeps them: one buffer per file in each
//! worker. A line that doesn't fit makes the buffer go out first; a line
//! larger than the whole buffer is written on its own. The buffer also goes
//! out `flush` after its first line, before the files are reopened
//! (SIGUSR1), when the worker stops, and at SIGTERM. With `gzip` each write
//! is one gzip member, which `zcat` reads as one stream.
//!
//! The worker is a buffer's only writer. It sits behind a mutex only so
//! that the main thread can write what is left at SIGTERM, which ends the
//! process without waiting for the workers.

use std::cell::RefCell;
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::{Arc, Mutex};

use super::{AccessLogSink, PreparedLogBuffer};

type Shared = Arc<Mutex<Vec<u8>>>;

/// Every worker's buffers, for the SIGTERM write.
static ALL: Mutex<Vec<(&'static PreparedLogBuffer, Shared)>> = Mutex::new(Vec::new());

struct Slot {
    buffer: &'static PreparedLogBuffer,
    data: Shared,
    /// Which of the worker's access_log files to write it to (any opened
    /// for this path).
    file_index: usize,
    /// A `flush` timer is pending.
    timer: bool,
}

thread_local! {
    /// This worker's buffers, by `PreparedLogBuffer::slot`.
    static MINE: RefCell<Vec<Option<Slot>>> = const { RefCell::new(Vec::new()) };
}

fn lock(data: &Shared) -> std::sync::MutexGuard<'_, Vec<u8>> {
    data.lock().unwrap_or_else(|e| e.into_inner())
}

/// What `append` leaves to its caller.
pub(crate) struct Appended {
    /// Bytes to write now, in this order, already encoded (a full buffer,
    /// a line too large for it).
    pub(crate) write: Vec<Vec<u8>>,
    /// The buffer just got its first line: arm the `flush` timer.
    pub(crate) arm_timer: bool,
}

/// Add `line` (with its newline) to this worker's buffer for `buffer`.
pub(crate) fn append(
    buffer: &'static PreparedLogBuffer,
    file_index: usize,
    line: &[u8],
) -> Appended {
    MINE.with(|mine| {
        let mut mine = mine.borrow_mut();
        if mine.len() <= buffer.slot {
            mine.resize_with(buffer.slot + 1, || None);
        }
        let slot = mine[buffer.slot].get_or_insert_with(|| {
            let data: Shared = Arc::new(Mutex::new(Vec::with_capacity(buffer.size)));
            ALL.lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((buffer, data.clone()));
            Slot {
                buffer,
                data,
                file_index,
                timer: false,
            }
        });
        let mut data = lock(&slot.data);
        let mut write = Vec::new();
        if line.len() > buffer.size - data.len() && !data.is_empty() {
            write.push(encode(buffer, &std::mem::take(&mut *data)));
            data.reserve(buffer.size);
        }
        let mut arm_timer = false;
        if line.len() <= buffer.size - data.len() {
            arm_timer = data.is_empty() && buffer.flush_ms.is_some() && !slot.timer;
            data.extend_from_slice(line);
        } else {
            write.push(encode(buffer, line));
        }
        drop(data);
        if arm_timer {
            slot.timer = true;
        }
        Appended { write, arm_timer }
    })
}

/// The `flush` timer fired: the buffer's contents to write, if any, and
/// which file to write them to.
pub(crate) fn take_for_timer(buffer: &'static PreparedLogBuffer) -> Option<(usize, Vec<u8>)> {
    MINE.with(|mine| {
        let mut mine = mine.borrow_mut();
        let slot = mine.get_mut(buffer.slot)?.as_mut()?;
        slot.timer = false;
        let data = std::mem::take(&mut *lock(&slot.data));
        (!data.is_empty()).then(|| (slot.file_index, encode(buffer, &data)))
    })
}

fn encode(buffer: &PreparedLogBuffer, data: &[u8]) -> Vec<u8> {
    match buffer.gzip {
        Some(level) => super::gzip::compress_all(data, level, 15),
        None => data.to_vec(),
    }
}

/// Write this worker's buffers through `files` (blocking: before a reopen
/// and when the worker stops, both rare).
pub(crate) fn flush_all(files: &[AccessLogSink]) {
    MINE.with(|mine| {
        let mine = mine.borrow();
        for slot in mine.iter().flatten() {
            let data = std::mem::take(&mut *lock(&slot.data));
            if data.is_empty() {
                continue;
            }
            let Some(AccessLogSink::File(file)) = files.get(slot.file_index) else {
                continue;
            };
            // SAFETY: borrows the worker's open fd for one write; the
            // ManuallyDrop keeps it from being closed here.
            let mut fd = std::mem::ManuallyDrop::new(unsafe {
                std::fs::File::from_raw_fd(file.as_raw_fd())
            });
            let _ = fd.write_all(&encode(slot.buffer, &data));
        }
    });
}

/// At SIGTERM, from the main thread: write what every worker has buffered,
/// to the files by path (the workers' descriptors aren't in this thread's
/// table).
pub(crate) fn flush_at_exit() {
    let all = ALL.lock().unwrap_or_else(|e| e.into_inner());
    for (buffer, data) in all.iter() {
        let data = std::mem::take(&mut *lock(data));
        if data.is_empty() {
            continue;
        }
        if let Ok(mut file) = std::fs::OpenOptions::new().append(true).open(buffer.path) {
            let _ = file.write_all(&encode(buffer, &data));
        }
    }
}
