//! `user name [group];`: started as root, ruxen serves as another user.
//!
//! nginx keeps root in its master and switches each worker process
//! (`ngx_worker_process_init`: `setgid`, `initgroups`, `setuid`). ruxen's
//! workers are threads of one process, so the whole process switches,
//! once: the workers bind their listeners and open their logs as root,
//! then wait; `main` hands the log files and temp directories to the user,
//! drops root for good and only then lets the workers accept. Everything
//! after that (requests, log reopen on SIGUSR1) runs as the user, as in
//! nginx's workers. What nginx's master still does as root afterwards
//! (recreate rotated logs, remove the pid file) a small root helper
//! process does here, see `start_helper`.

use std::ffi::CString;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::config::UserDirective;

/// The user and group to switch to.
#[derive(Debug)]
pub(crate) struct Credentials {
    pub name: CString,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
}

/// Files and directories the user must be able to reopen or write into
/// after the switch: log files (created at startup as root) and
/// `client_body_temp_path` directories. Noted while preparing the config.
struct Handover {
    files: Vec<PathBuf>,
    temp_dirs: Vec<PathBuf>,
}

static HANDOVER: Mutex<Handover> = Mutex::new(Handover {
    files: Vec::new(),
    temp_dirs: Vec::new(),
});

/// A log file opened at startup; the user reopens it on SIGUSR1.
pub(crate) fn note_file(path: &Path) {
    let mut h = HANDOVER.lock().unwrap_or_else(|e| e.into_inner());
    if !h.files.iter().any(|p| p == path) {
        h.files.push(path.to_path_buf());
    }
}

/// A `client_body_temp_path` directory, made at startup like nginx's
/// `ngx_create_paths`.
pub(crate) fn note_temp_dir(path: &Path) {
    let mut h = HANDOVER.lock().unwrap_or_else(|e| e.into_inner());
    if !h.temp_dirs.iter().any(|p| p == path) {
        h.temp_dirs.push(path.to_path_buf());
    }
}

/// Who to switch to, from `user` and the effective uid (`ngx_set_user`).
/// Not root: the directive is ignored with nginx's warning. Root: `user`,
/// else nginx's default `nobody`. A user that is root with group root
/// means no switch at all.
pub(crate) fn resolve(
    euid: libc::uid_t,
    user: Option<&UserDirective>,
) -> Result<Option<Credentials>, String> {
    if euid != 0 {
        if user.is_some() {
            eprintln!(
                "ruxen: [warn] the \"user\" directive makes sense only if the master \
                 process runs with super-user privileges, ignored"
            );
        }
        return Ok(None);
    }
    let (name, group) = match user {
        Some(u) => (
            u.name.clone(),
            u.group.clone().unwrap_or_else(|| u.name.clone()),
        ),
        None => ("nobody".to_string(), default_group()),
    };
    let c_name = CString::new(name.as_str()).map_err(|_| bad_name("getpwnam", &name))?;
    let c_group = CString::new(group.as_str()).map_err(|_| bad_name("getgrnam", &group))?;
    let uid = user_id(&c_name).ok_or_else(|| bad_name("getpwnam", &name))?;
    let gid = group_id(&c_group).ok_or_else(|| bad_name("getgrnam", &group))?;
    if uid == 0 && gid == 0 {
        return Ok(None);
    }
    Ok(Some(Credentials {
        name: c_name,
        uid,
        gid,
    }))
}

/// `getpwnam_r`: the uid of a user, `None` if there is none. The `_r`
/// forms fill a buffer of ours, where `getpwnam` returns a static record
/// any other thread's lookup may overwrite.
fn user_id(name: &std::ffi::CStr) -> Option<libc::uid_t> {
    lookup(|buf, len, found| {
        let mut pw: libc::passwd = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::passwd = std::ptr::null_mut();
        // SAFETY: NUL-terminated name, a buffer of `len` bytes, and out
        // pointers to locals.
        let rc = unsafe { libc::getpwnam_r(name.as_ptr(), &mut pw, buf, len, &mut result) };
        *found = (!result.is_null()).then_some(pw.pw_uid);
        rc
    })
}

/// `getgrnam_r`: the gid of a group, `None` if there is none.
fn group_id(name: &std::ffi::CStr) -> Option<libc::gid_t> {
    lookup(|buf, len, found| {
        let mut gr: libc::group = unsafe { std::mem::zeroed() };
        let mut result: *mut libc::group = std::ptr::null_mut();
        // SAFETY: as in `user_id`.
        let rc = unsafe { libc::getgrnam_r(name.as_ptr(), &mut gr, buf, len, &mut result) };
        *found = (!result.is_null()).then_some(gr.gr_gid);
        rc
    })
}

/// Runs a `get*nam_r` call with a buffer that grows on `ERANGE` (a group
/// with many members needs more than the usual few KiB).
fn lookup<T>(mut call: impl FnMut(*mut libc::c_char, usize, &mut Option<T>) -> i32) -> Option<T> {
    let mut buf = vec![0 as libc::c_char; 4096];
    loop {
        let mut found = None;
        match call(buf.as_mut_ptr(), buf.len(), &mut found) {
            libc::ERANGE if buf.len() < 1 << 20 => buf.resize(buf.len() * 4, 0),
            _ => return found,
        }
    }
}

fn bad_name(call: &str, name: &str) -> String {
    format!("{call}(\"{name}\") failed")
}

/// nginx's default group is picked when it is built (`auto/unix`):
/// `nogroup` where the system has one (Debian, Ubuntu, Alpine), else
/// `nobody`.
fn default_group() -> String {
    if group_id(c"nogroup").is_none() {
        "nobody".to_string()
    } else {
        "nogroup".to_string()
    }
}

/// Hands the noted files and directories to the user, then switches the
/// whole process to it for good. Any failure is an `[emerg]`: the caller
/// stops instead of serving as root.
pub(crate) fn switch(creds: &Credentials) -> Result<(), String> {
    if creds.uid != 0 {
        let h = HANDOVER.lock().unwrap_or_else(|e| e.into_inner());
        for dir in &h.temp_dirs {
            prepare_temp_dir(dir, creds.uid)?;
        }
        for file in &h.files {
            hand_file(file, creds.uid);
        }
    }
    let user = creds.name.to_string_lossy();
    // glibc applies these to every thread of the process (SIGSETXID).
    // SAFETY: plain credential syscalls with owned arguments.
    unsafe {
        if libc::setgid(creds.gid) != 0 {
            return Err(os_error(&format!("setgid({})", creds.gid)));
        }
        if libc::initgroups(creds.name.as_ptr(), creds.gid) != 0 {
            return Err(os_error(&format!("initgroups({user}, {})", creds.gid)));
        }
        if libc::setuid(creds.uid) != 0 {
            return Err(os_error(&format!("setuid({})", creds.uid)));
        }
    }
    verify(creds)?;
    // As nginx's workers: setuid clears the dumpable flag, which would
    // stop core dumps (worker_rlimit_core) and /proc access by the user.
    // SAFETY: prctl with integer arguments.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 1, 0, 0, 0) };
    Ok(())
}

/// The real, effective and saved IDs all changed, and root can't be
/// regained.
fn verify(creds: &Credentials) -> Result<(), String> {
    let (mut ruid, mut euid, mut suid) = (0, 0, 0);
    let (mut rgid, mut egid, mut sgid) = (0, 0, 0);
    // SAFETY: out-pointers to locals.
    let ok = unsafe {
        libc::getresuid(&mut ruid, &mut euid, &mut suid) == 0
            && libc::getresgid(&mut rgid, &mut egid, &mut sgid) == 0
    };
    if !ok || [ruid, euid, suid] != [creds.uid; 3] || [rgid, egid, sgid] != [creds.gid; 3] {
        return Err(format!(
            "switching to user {} left uids {ruid}/{euid}/{suid}, gids {rgid}/{egid}/{sgid}",
            creds.name.to_string_lossy()
        ));
    }
    // SAFETY: setuid(0) only probes; it must fail once root is gone.
    if creds.uid != 0 && unsafe { libc::setuid(0) } == 0 {
        return Err("root could be regained after switching users".to_string());
    }
    Ok(())
}

/// nginx's `ngx_create_paths`: create the directory (0700), give it to the
/// user, and make sure the user can use it. The directory is opened
/// without following a symlink and changed through its fd, so a path
/// swapped underneath can't redirect the `chown`.
fn prepare_temp_dir(dir: &Path, uid: libc::uid_t) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
    use std::os::unix::io::AsRawFd;
    let shown = dir.display();
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("mkdir() \"{shown}\" failed ({})", errno_text(&e))),
    }
    let fd = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(dir)
        .map_err(|e| format!("open() \"{shown}\" failed ({})", errno_text(&e)))?;
    let meta = fd
        .metadata()
        .map_err(|e| format!("stat() \"{shown}\" failed ({})", errno_text(&e)))?;
    // SAFETY: fchown / fchmod on a directory fd we hold open.
    if meta.uid() != uid && unsafe { libc::fchown(fd.as_raw_fd(), uid, libc::gid_t::MAX) } != 0 {
        return Err(os_error(&format!("chown(\"{shown}\", {uid})")));
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o700 != 0o700 && unsafe { libc::fchmod(fd.as_raw_fd(), mode | 0o700) } != 0 {
        return Err(os_error(&format!("chmod() \"{shown}\"")));
    }
    Ok(())
}

/// Gives a log file to the user, creating it if it is missing, so the
/// user can reopen it after logrotate (nginx's master does the same in
/// `ngx_reopen_files`). Only a regular file with one link is changed, and
/// a symlink is never followed: the user may own the log directory, and
/// must not be able to point root's `chown` at another file. Anything
/// else (a symlink to /dev/stdout, a fifo) is left as it is. A failure
/// only costs the reopen, so it is an `[alert]`, as in nginx.
fn hand_file(path: &Path, uid: libc::uid_t) {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::io::AsRawFd;
    let result = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .and_then(|f| {
            let meta = f.metadata()?;
            if !meta.file_type().is_file() || meta.nlink() != 1 || meta.uid() == uid {
                return Ok(());
            }
            // SAFETY: fchown on a file we hold open; -1 keeps the group.
            if unsafe { libc::fchown(f.as_raw_fd(), uid, libc::gid_t::MAX) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    match result {
        Ok(()) => {}
        // A symlink (O_NOFOLLOW): left alone, see above.
        Err(e) if e.raw_os_error() == Some(libc::ELOOP) => {}
        Err(e) => eprintln!(
            "ruxen: [alert] chown(\"{}\", {uid}) failed ({})",
            path.display(),
            errno_text(&e)
        ),
    }
}

/// The root helper, when ruxen switched users: a child forked before the
/// workers start, which keeps root for the two things nginx's master does
/// as root after startup and a switched process can't. On SIGUSR1 it
/// recreates the log files logrotate moved away and gives them to the
/// user (`ngx_reopen_files`), and on exit it removes the pid file from a
/// directory only root may write (`ngx_delete_pidfile`). It takes no
/// paths or arguments from the server, only one-byte commands, and
/// works on what the configuration named when it was forked; it exits
/// when the server does.
static HELPER: Mutex<Option<std::os::unix::net::UnixStream>> = Mutex::new(None);

const CMD_PID_WRITTEN: u8 = b'P';
const CMD_REOPEN_LOGS: u8 = b'R';
const CMD_EXIT: u8 = b'X';
/// A reload took over: take the log files from a new parse (#498).
const CMD_RELOADED: u8 = b'L';
const ACK: u8 = b'k';

/// Forks the helper. Call while the process has one thread: the child
/// runs Rust code (and allocates) after the fork. `extra_files` are files
/// opened outside the configuration (`-e`).
/// The log files of the configuration as it is on disk, from the helper's
/// own parse; `None` when it doesn't parse.
pub(crate) type LogFiles = Box<dyn Fn() -> Option<Vec<PathBuf>>>;

pub(crate) fn start_helper(
    creds: &Credentials,
    pid_path: Option<&Path>,
    extra_files: &[&Path],
    log_files: LogFiles,
) -> Result<(), String> {
    use std::os::unix::io::AsRawFd;
    for f in extra_files {
        note_file(f);
    }
    // The child runs Rust code (it allocates, takes `HANDOVER`): a lock
    // another thread held at the fork would stay held in it for good, and
    // the helper hang (#527). nginx's master forks from one thread too.
    single_threaded(user_threads())?;
    let (server_end, helper_end) = std::os::unix::net::UnixStream::pair()
        .map_err(|e| format!("socketpair() failed ({})", errno_text(&e)))?;
    // SAFETY: fork while single-threaded (checked above); the child never
    // returns from `helper_main`.
    match unsafe { libc::fork() } {
        -1 => Err(os_error("fork()")),
        0 => {
            drop(server_end);
            let files = HANDOVER
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .files
                .clone();
            let fd = helper_end.as_raw_fd();
            let extra: Vec<PathBuf> = extra_files.iter().map(|f| f.to_path_buf()).collect();
            helper_main(fd, creds.uid, files, &extra, &log_files, pid_path)
        }
        _ => {
            drop(helper_end);
            let _ = server_end.set_read_timeout(Some(std::time::Duration::from_secs(10)));
            *HELPER.lock().unwrap_or_else(|e| e.into_inner()) = Some(server_end);
            Ok(())
        }
    }
}

/// The threads of this process that run its code, from `/proc/self/task`:
/// io_uring's kernel workers (`iou-wrk-*`, `iou-sqp-*`) hold none of its
/// locks and don't count. `None` without `/proc`.
fn user_threads() -> Option<usize> {
    let tasks = std::fs::read_dir("/proc/self/task").ok()?;
    Some(
        tasks
            .filter_map(Result::ok)
            .filter(|task| {
                let comm = std::fs::read_to_string(task.path().join("comm")).unwrap_or_default();
                !is_io_uring_worker(comm.trim_end())
            })
            .count(),
    )
}

fn is_io_uring_worker(comm: &str) -> bool {
    comm.starts_with("iou-wrk-") || comm.starts_with("iou-sqp-")
}

/// `Err` unless the count is one; without `/proc` the check is skipped.
fn single_threaded(threads: Option<usize>) -> Result<(), String> {
    match threads {
        Some(n) if n != 1 => Err(format!("start_helper: {n} threads, the fork needs one")),
        _ => Ok(()),
    }
}

fn helper_main(
    sock: libc::c_int,
    uid: libc::uid_t,
    mut files: Vec<PathBuf>,
    extra: &[PathBuf],
    log_files: &LogFiles,
    pid: Option<&Path>,
) -> ! {
    // SAFETY: signal dispositions, fd and prctl calls in the child, which
    // owns every fd it inherited.
    unsafe {
        // Signals are the server's: a terminal's Ctrl-C or systemd's
        // KillSignal to the whole group must not end the helper before
        // the server has asked it to remove the pid file.
        for sig in [
            libc::SIGINT,
            libc::SIGTERM,
            libc::SIGQUIT,
            libc::SIGHUP,
            libc::SIGUSR1,
            libc::SIGUSR2,
            libc::SIGWINCH,
            libc::SIGPIPE,
        ] {
            libc::signal(sig, libc::SIG_IGN);
        }
        // Keep stdio and the socket; nothing else the server opened so far
        // (certificates, log files) stays reachable from the root process.
        if libc::dup2(sock, 3) == 3 {
            libc::syscall(libc::SYS_close_range, 4u32, u32::MAX, 0u32);
        }
        libc::prctl(libc::PR_SET_NAME, c"ruxen: helper".as_ptr(), 0, 0, 0);
    }
    let mut pid_written = false;
    let mut cmd = [0u8; 1];
    loop {
        // SAFETY: a one-byte read into a local buffer.
        let n = unsafe { libc::read(3, cmd.as_mut_ptr().cast(), 1) };
        if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
            continue;
        }
        if n != 1 {
            // The server is gone without saying goodbye (a crash).
            break;
        }
        match cmd[0] {
            CMD_PID_WRITTEN => pid_written = true,
            CMD_REOPEN_LOGS => {
                for f in &files {
                    hand_file(f, uid);
                }
            }
            // nginx's master reopens the files of the current cycle: the
            // helper parses the configuration the reload took over with.
            // A file it can't parse keeps the list it has.
            CMD_RELOADED => {
                if let Some(mut paths) = log_files() {
                    paths.extend(extra.iter().cloned());
                    files = paths;
                }
            }
            CMD_EXIT => break,
            _ => continue,
        }
        // SAFETY: a one-byte write from a constant.
        unsafe { libc::write(3, [ACK].as_ptr().cast(), 1) };
    }
    if pid_written && let Some(path) = pid {
        remove_pid_file(path);
    }
    // SAFETY: a one-byte write from a constant; the server may be gone.
    unsafe {
        libc::write(3, [ACK].as_ptr().cast(), 1);
        libc::_exit(0)
    }
}

/// Sends one command to the helper and waits for its answer. `false`
/// without a helper or when it doesn't answer.
fn ask_helper(cmd: u8) -> bool {
    use std::io::{Read, Write};
    let mut helper = HELPER.lock().unwrap_or_else(|e| e.into_inner());
    let Some(sock) = helper.as_mut() else {
        return false;
    };
    let mut ack = [0u8; 1];
    let ok = sock.write_all(&[cmd]).is_ok() && sock.read_exact(&mut ack).is_ok() && ack[0] == ACK;
    if !ok {
        eprintln!("ruxen: [alert] the root helper did not answer");
    }
    ok
}

pub(crate) fn helper_running() -> bool {
    HELPER.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// The pid file is written: the helper removes it when ruxen exits.
pub(crate) fn pid_written() {
    if helper_running() {
        ask_helper(CMD_PID_WRITTEN);
    }
}

/// SIGUSR1: the helper recreates moved log files for the user before the
/// workers reopen them.
pub(crate) fn reopen_logs() {
    if helper_running() {
        ask_helper(CMD_REOPEN_LOGS);
    }
}

/// A reload took over: the helper takes the new configuration's log files
/// from its own parse (#498).
pub(crate) fn reloaded() {
    if helper_running() {
        ask_helper(CMD_RELOADED);
    }
}

/// On exit: removes the pid file, through the helper if there is one.
pub(crate) fn remove_pid_file_on_exit(path: &Path) {
    if helper_running() {
        ask_helper(CMD_EXIT);
    } else {
        remove_pid_file(path);
    }
}

/// nginx's `ngx_delete_pidfile`: a failed unlink is an `[alert]`.
fn remove_pid_file(path: &Path) {
    if let Err(e) = std::fs::remove_file(path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        eprintln!(
            "ruxen: [alert] unlink() \"{}\" failed ({})",
            path.display(),
            errno_text(&e)
        );
    }
}

fn os_error(call: &str) -> String {
    format!(
        "{call} failed ({})",
        errno_text(&std::io::Error::last_os_error())
    )
}

fn errno_text(e: &std::io::Error) -> String {
    crate::worker::errno_text(e)
}

/// For tests: the user name of a uid, if the system knows it.
#[cfg(test)]
fn name_of(uid: libc::uid_t) -> Option<String> {
    // SAFETY: getpwuid in a single test thread; the name is copied out.
    let pw = unsafe { libc::getpwuid(uid).as_ref()? };
    Some(
        unsafe { std::ffi::CStr::from_ptr(pw.pw_name) }
            .to_string_lossy()
            .into_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user(name: &str, group: Option<&str>) -> UserDirective {
        UserDirective {
            name: name.into(),
            group: group.map(Into::into),
        }
    }

    #[test]
    fn not_root_ignores_user() {
        assert!(resolve(1000, None).unwrap().is_none());
        assert!(
            resolve(1000, Some(&user("nobody", None)))
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn root_defaults_to_nobody() {
        let c = resolve(0, None).unwrap().expect("a switch");
        assert_eq!(c.name.to_str().unwrap(), "nobody");
        assert_eq!(Some("nobody".to_string()), name_of(c.uid));
    }

    #[test]
    fn root_as_root_is_no_switch() {
        assert!(resolve(0, Some(&user("root", None))).unwrap().is_none());
    }

    #[test]
    fn group_defaults_to_the_user_name() {
        // `root` has a group named `root`; an explicit other group is a
        // switch even for uid 0.
        let err = resolve(0, Some(&user("nobody", Some("no-such-group-ruxen")))).unwrap_err();
        assert_eq!(err, "getgrnam(\"no-such-group-ruxen\") failed");
        let err = resolve(0, Some(&user("no-such-user-ruxen", None))).unwrap_err();
        assert_eq!(err, "getpwnam(\"no-such-user-ruxen\") failed");
    }

    /// The fork of the root helper needs one thread (#527); io_uring's
    /// kernel workers don't count, and without `/proc` there's no check.
    #[test]
    fn the_helper_forks_from_one_thread() {
        assert!(single_threaded(Some(1)).is_ok());
        assert!(single_threaded(None).is_ok());
        assert_eq!(
            single_threaded(Some(3)).unwrap_err(),
            "start_helper: 3 threads, the fork needs one"
        );
        assert!(is_io_uring_worker("iou-wrk-12345"));
        assert!(is_io_uring_worker("iou-sqp-12345"));
        assert!(!is_io_uring_worker("ruxen"));
        // The test harness runs threads of its own, this one at least.
        assert!(user_threads().is_some_and(|n| n >= 1));
    }
}
