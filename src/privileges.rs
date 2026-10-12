//! `user name [group];`: started as root, ruxen serves as another user.
//!
//! nginx keeps root in its master and switches each worker process
//! (`ngx_worker_process_init`: `setgid`, `initgroups`, `setuid`). ruxen's
//! workers are threads of one process, so the whole process switches,
//! once: the workers bind their listeners and open their logs as root,
//! then wait; `main` hands the log files and temp directories to the user,
//! drops root for good and only then lets the workers accept. Everything
//! after that (requests, log reopen on SIGUSR1) runs as the user, as in
//! nginx's workers.

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
    // SAFETY: NUL-terminated names; the returned records are read before
    // any other getpw*/getgr* call. Called before the workers start.
    let uid = unsafe { libc::getpwnam(c_name.as_ptr()).as_ref() }
        .map(|pw| pw.pw_uid)
        .ok_or_else(|| bad_name("getpwnam", &name))?;
    let gid = unsafe { libc::getgrnam(c_group.as_ptr()).as_ref() }
        .map(|gr| gr.gr_gid)
        .ok_or_else(|| bad_name("getgrnam", &group))?;
    if uid == 0 && gid == 0 {
        return Ok(None);
    }
    Ok(Some(Credentials {
        name: c_name,
        uid,
        gid,
    }))
}

fn bad_name(call: &str, name: &str) -> String {
    format!("{call}(\"{name}\") failed")
}

/// nginx's default group is picked when it is built (`auto/unix`):
/// `nogroup` where the system has one (Debian, Ubuntu, Alpine), else
/// `nobody`.
fn default_group() -> String {
    let nogroup = c"nogroup";
    // SAFETY: a NUL-terminated literal; only the null check is used.
    if unsafe { libc::getgrnam(nogroup.as_ptr()) }.is_null() {
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
            chown_file(file, creds.uid);
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
/// user, and make sure the user can use it.
fn prepare_temp_dir(dir: &Path, uid: libc::uid_t) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    let shown = dir.display();
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(format!("mkdir() \"{shown}\" failed ({})", errno_text(&e))),
    }
    let meta = std::fs::metadata(dir)
        .map_err(|e| format!("stat() \"{shown}\" failed ({})", errno_text(&e)))?;
    if meta.uid() != uid {
        std::os::unix::fs::chown(dir, Some(uid), None)
            .map_err(|e| format!("chown(\"{shown}\", {uid}) failed ({})", errno_text(&e)))?;
    }
    let mode = meta.mode();
    if mode & 0o700 != 0o700 {
        std::fs::set_permissions(
            dir,
            std::fs::Permissions::from_mode((mode | 0o700) & 0o7777),
        )
        .map_err(|e| format!("chmod() \"{shown}\" failed ({})", errno_text(&e)))?;
    }
    Ok(())
}

/// Gives a log file to the user so it can reopen it after logrotate
/// (nginx's master does the same in `ngx_reopen_files`). A failure only
/// costs the reopen, so it is an `[alert]`, as there.
fn chown_file(path: &Path, uid: libc::uid_t) {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::io::AsRawFd;
    let result = std::fs::OpenOptions::new()
        .append(true)
        .open(path)
        .and_then(|f| {
            if f.metadata()?.uid() == uid {
                return Ok(());
            }
            // SAFETY: fchown on a file we hold open; -1 keeps the group.
            if unsafe { libc::fchown(f.as_raw_fd(), uid, libc::gid_t::MAX) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    if let Err(e) = result {
        eprintln!(
            "ruxen: [alert] chown(\"{}\", {uid}) failed ({})",
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
}
