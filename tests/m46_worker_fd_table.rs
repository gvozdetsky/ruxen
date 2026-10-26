//! M46 — each worker thread runs with a private fd table
//! (`unshare(CLONE_FILES)`), so per-request `open`/`close` don't contend on
//! one process-wide lock. Observable through `/proc/<pid>/task/<tid>/fd`:
//! with private tables, two workers list different fds (each has its own
//! listener and io_uring ring); with `RUXEN_UNSHARE_FILES=0` they list the
//! same table.

mod common;

use std::collections::BTreeSet;
use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::MutexGuard;
use std::thread::sleep;
use std::time::Duration;

struct ServerGuard {
    child: Child,
    dir: PathBuf,
}

impl Drop for ServerGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn pick_port() -> (u16, MutexGuard<'static, ()>) {
    let guard = common::ports::setup_lock();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    (port, guard)
}

fn spawn(unshare: Option<&str>) -> (ServerGuard, u32, u16) {
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ruxen-m46-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::SeqCst)
    ));
    std::fs::create_dir(&dir).unwrap();
    let (port, _lock) = pick_port();
    let conf = dir.join("ruxen.conf");
    std::fs::write(
        &conf,
        format!(
            "pid {d}/ruxen.pid;\nevents {{}}\nhttp {{\n  server {{\n    listen 127.0.0.1:{port};\n    location / {{ return 200 \"ok\"; }}\n  }}\n}}\n",
            d = dir.display()
        ),
    )
    .unwrap();
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_ruxen"));
    cmd.args(["-c", conf.to_str().unwrap()])
        .env("RUXEN_WORKERS", "2")
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    match unshare {
        Some(v) => cmd.env("RUXEN_UNSHARE_FILES", v),
        None => cmd.env_remove("RUXEN_UNSHARE_FILES"),
    };
    let child = cmd.spawn().expect("spawn ruxen");
    let pid = child.id();
    // Owned by the guard before the wait: if it panics, ruxen still stops.
    let mut guard = ServerGuard { child, dir };
    // The configuration sets `pid <dir>/ruxen.pid`.
    let pid_file = guard.dir.join("ruxen.pid");
    common::ports::wait_for_pid_file(&mut guard.child, &pid_file, Duration::from_secs(5));
    (guard, pid, port)
}

/// fd → link target for each `ruxen-worker-*` thread of `pid`. Entries
/// whose link vanished mid-listing are skipped, and the table gets a
/// moment to settle first, so both snapshots see the same steady-state
/// table when it is shared.
fn worker_fd_tables(pid: u32) -> Vec<BTreeSet<(String, String)>> {
    sleep(Duration::from_millis(200));
    let mut tables = Vec::new();
    for task in std::fs::read_dir(format!("/proc/{pid}/task")).unwrap() {
        let task = task.unwrap().path();
        let comm = std::fs::read_to_string(task.join("comm")).unwrap_or_default();
        if !comm.starts_with("ruxen-worker-") {
            continue;
        }
        let mut fds = BTreeSet::new();
        for fd in std::fs::read_dir(task.join("fd")).unwrap() {
            let fd = fd.unwrap();
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            fds.insert((
                fd.file_name().to_string_lossy().into_owned(),
                target.display().to_string(),
            ));
        }
        tables.push(fds);
    }
    tables
}

#[test]
fn workers_have_private_fd_tables_by_default() {
    let (_g, pid, _port) = spawn(None);
    let tables = worker_fd_tables(pid);
    assert_eq!(tables.len(), 2, "expected two worker threads");
    assert_ne!(tables[0], tables[1], "workers share one fd table");
}

#[test]
fn unshare_can_be_disabled_for_ab_runs() {
    let (_g, pid, _port) = spawn(Some("0"));
    let tables = worker_fd_tables(pid);
    assert_eq!(tables.len(), 2, "expected two worker threads");
    assert_eq!(
        tables[0], tables[1],
        "workers should share the process fd table"
    );
}
