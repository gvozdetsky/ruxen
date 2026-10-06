// ruxen — nginx-tests interop bootstrap.
//
// Startup-only surface:
// - nginx-style CLI flags (`-c`, `-p`, `-e`, `-g`, `-t`, `-T`, `-q`, `-V`)
// - config validation mode
// - pid file creation
// - SIGQUIT-driven graceful shutdown, SIGTERM / SIGINT fast shutdown

use std::io;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

mod auth;
mod autoindex;
mod config;
mod file;
mod fs_resolve;
mod http;
mod http_date;
mod phase;
mod proxy;
mod proxy_protocol;
mod syslog;
mod tls;
mod tls_certs;
mod tls_session;
mod tls_stream;
mod upstream;
mod uri;
mod worker;

static SIGQUIT_SEEN: AtomicBool = AtomicBool::new(false);
static SIGTERM_SEEN: AtomicBool = AtomicBool::new(false);
static SIGHUP_SEEN: AtomicBool = AtomicBool::new(false);
static SIGUSR1_SEEN: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
const SIGHUP: i32 = 1;
#[cfg(unix)]
const SIGINT: i32 = 2;
#[cfg(unix)]
const SIGQUIT: i32 = 3;
#[cfg(unix)]
const SIGPIPE: i32 = 13;
#[cfg(unix)]
const SIGUSR1: i32 = 10;
#[cfg(unix)]
const SIGUSR2: i32 = 12;
#[cfg(unix)]
const SIGTERM: i32 = 15;
#[cfg(unix)]
const SIG_UNBLOCK: i32 = 1;
#[cfg(unix)]
const SIG_IGN: usize = 1;

/// Linux glibc `sigset_t` is 128 bytes (16 u64s); only the first element
/// covers signals 1..64, which is all we touch.
#[cfg(unix)]
type SigSet = [u64; 16];

#[cfg(unix)]
unsafe extern "C" {
    fn dup2(oldfd: i32, newfd: i32) -> i32;
    fn signal(signum: i32, handler: usize) -> usize;
    fn sigprocmask(how: i32, set: *const SigSet, oldset: *mut SigSet) -> i32;
}

extern "C" fn sigquit_handler(_sig: i32) {
    SIGQUIT_SEEN.store(true, Ordering::SeqCst);
}

/// SIGTERM and SIGINT.
extern "C" fn sigterm_handler(_sig: i32) {
    SIGTERM_SEEN.store(true, Ordering::SeqCst);
}

extern "C" fn sighup_handler(_sig: i32) {
    SIGHUP_SEEN.store(true, Ordering::SeqCst);
}

extern "C" fn sigusr1_handler(_sig: i32) {
    SIGUSR1_SEEN.store(true, Ordering::SeqCst);
}

struct Cli {
    config_path: PathBuf,
    prefix: Option<PathBuf>,
    errlog: Option<PathBuf>,
    globals: Vec<String>,
    test_only: bool,
    quiet: bool,
    dump: bool,
    show_version: bool,
    signal: Option<String>,
}

impl Default for Cli {
    fn default() -> Self {
        Self {
            config_path: PathBuf::from("ruxen.conf"),
            prefix: None,
            errlog: None,
            globals: Vec::new(),
            test_only: false,
            quiet: false,
            dump: false,
            show_version: false,
            signal: None,
        }
    }
}

fn main() -> ExitCode {
    match real_main() {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Reported) => ExitCode::FAILURE,
        Err(Failure::Io(err)) => {
            eprintln!("ruxen: {err}");
            ExitCode::FAILURE
        }
    }
}

/// Why startup failed. `Reported` errors were already printed as
/// `ruxen: [emerg] …` (plus the `-t` failure tail), so `main` only sets
/// the exit status; anything else is printed by `main`.
enum Failure {
    Reported,
    Io(io::Error),
}

impl From<io::Error> for Failure {
    fn from(err: io::Error) -> Self {
        Failure::Io(err)
    }
}

/// Print a config-time error the way nginx does, with `-t`'s closing line
/// (upstream tests match `qr/file <main> test failed/`). nginx opens the
/// `-e` log before reading the config and writes `[emerg]` to it as well
/// as to stderr; Test::Nginx's end-of-test checks read that file.
fn report_emerg(msg: &str, cli: &Cli, main_path: &Path) -> Failure {
    let line = format!("ruxen: [emerg] {msg}\n");
    eprint!("{line}");
    if let Some(errlog) = &cli.errlog {
        use std::io::Write;
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(errlog)
            .and_then(|mut f| f.write_all(line.as_bytes()));
    }
    if cli.test_only {
        eprintln!(
            "ruxen: configuration file {} test failed",
            main_path.display()
        );
    }
    Failure::Reported
}

/// nginx started as root switches its workers to `user` (default
/// `nobody`). ruxen can't switch users yet, so running as root is allowed
/// only when the config says so with `user root;`; anything else would
/// quietly serve every request with root's file access.
fn check_privileges(euid: u32, user: Option<&str>) -> Result<(), String> {
    const UNPRIVILEGED: &str = "start ruxen as an unprivileged user instead \
        (setcap cap_net_bind_service=+ep allows ports below 1024)";
    match (euid, user) {
        (0, Some("root")) => Ok(()),
        (0, Some(user)) => Err(format!(
            "\"user {user}\" is not supported yet, and ignoring it is unsafe: requests \
             would be served as root; {UNPRIVILEGED}"
        )),
        (0, None) => Err(format!(
            "running as root without \"user root;\": nginx would switch workers to \
             \"nobody\", but ruxen doesn't switch users yet; add \"user root;\" to run as \
             root on purpose, or {UNPRIVILEGED}"
        )),
        (_, Some(_)) => {
            // nginx's wording (ngx_set_user) for the same situation.
            eprintln!(
                "ruxen: [warn] the \"user\" directive makes sense only if the master \
                 process runs with super-user privileges, ignored"
            );
            Ok(())
        }
        (_, None) => Ok(()),
    }
}

fn real_main() -> Result<(), Failure> {
    let cli = parse_cli(std::env::args().skip(1)).map_err(io::Error::other)?;

    if cli.show_version {
        print!("{}", version_output());
        return Ok(());
    }
    let signal = match cli.signal.as_deref() {
        None => None,
        Some(name) => Some(signal_for(name).map_err(io::Error::other)?),
    };

    if let Some(prefix) = &cli.prefix {
        std::env::set_current_dir(prefix)
            .map_err(|e| io::Error::new(e.kind(), format!("chdir {}: {e}", prefix.display())))?;
    }
    // `-e errlog` is the runtime error-log destination — nginx keeps it
    // separate from the pre-init stderr that carries `-t`/`-T` messages.
    // Defer the redirect until after the test/dump short-circuit so config
    // failures still surface on the controlling terminal (and match the
    // upstream `nginx -T` behavior the Test::Nginx helpers rely on).

    let (main_path, file_src) = read_main_config(&cli)?;
    let globals_src = if cli.globals.is_empty() {
        None
    } else {
        let mut merged = String::new();
        for g in &cli.globals {
            merged.push_str(g);
            if !g.ends_with('\n') {
                merged.push('\n');
            }
        }
        Some(merged)
    };

    let cfg = config::parse_with_main(main_path.clone(), file_src, globals_src)
        .map_err(|e| report_emerg(&e.to_string(), &cli, &main_path))?;

    for w in &cfg.warnings {
        eprintln!("ruxen: [warn] {w}");
    }
    if let Some(signal) = signal {
        return signal_process(signal, cfg.runtime.pid.as_deref());
    }
    // nginx's two `-t` lines (ngx_init_cycle, then main once modules are
    // initialised); `-q` silences them.
    let report_test = cli.test_only && !cli.quiet;
    if report_test {
        eprintln!(
            "ruxen: the configuration file {} syntax is ok",
            main_path.display()
        );
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    check_privileges(euid, cfg.runtime.user.as_deref())
        .map_err(|e| report_emerg(&e, &cli, &main_path))?;

    if cli.dump {
        for entry in &cfg.dump_files {
            println!("# configuration file {}:", entry.path.display());
            print!("{}", entry.contents);
            if !entry.contents.ends_with('\n') {
                println!();
            }
            println!();
        }
    }

    let pid_path = cfg.runtime.pid.clone();
    // Resolve `worker_processes` (or `auto`) from the config; nginx
    // defaults to 1 when unset. RUXEN_WORKERS still overrides for
    // benchmarking convenience.
    let config_workers = match cfg.runtime.worker_processes {
        Some(config::WorkerProcesses::Count(n)) => n,
        Some(config::WorkerProcesses::Auto) => std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1),
        None => 1,
    };
    let worker_connections = cfg.runtime.worker_connections.unwrap_or(512);
    let rlimit_nofile = cfg.runtime.worker_rlimit_nofile;
    let rlimit_core = cfg.runtime.worker_rlimit_core;
    // nginx's 0 is "no limit", the same as unset.
    let shutdown_timeout = cfg
        .runtime
        .worker_shutdown_timeout_ms
        .filter(|&ms| ms != 0)
        .map(Duration::from_millis);
    // Load certificates, open roots and log files. `-t` does this too, so
    // it catches everything short of a busy port, like `nginx -t`.
    let http: &'static worker::PreparedHttp =
        worker::prepare(cfg).map_err(|e| report_emerg(&e, &cli, &main_path))?;
    warn_if_fd_limit_too_low(http, worker_connections, rlimit_nofile);
    if cli.test_only {
        if report_test {
            eprintln!(
                "ruxen: configuration file {} test is successful",
                main_path.display()
            );
        }
        return Ok(());
    }

    if let Some(errlog) = &cli.errlog {
        redirect_stderr(errlog)?;
        let _ = worker::STDERR_LOG_PATH.set(errlog.clone());
    }
    // Workers are threads, so the limits are set once for the process.
    // Each worker's fd table is its own (unshare), so RLIMIT_NOFILE then
    // bounds every worker, as nginx's per-worker setrlimit does.
    set_rlimit(true, rlimit_nofile);
    set_rlimit(false, rlimit_core);

    // Workers can't run without io_uring; say why up front instead of
    // letting every worker thread panic on runtime setup.
    if !monoio::utils::detect_uring() {
        eprintln!(
            "ruxen: [emerg] io_uring is not available: it is blocked by seccomp \
             (in Docker, run with --security-opt seccomp=unconfined), disabled \
             via the kernel.io_uring_disabled sysctl, or the kernel is too old"
        );
        return Err(Failure::Reported);
    }

    install_signal_handlers()?;

    let runtime = Arc::new(worker::RuntimeState::default());

    let n_workers: usize = std::env::var("RUXEN_WORKERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(config_workers);
    let pin = matches!(std::env::var("RUXEN_PIN").as_deref(), Ok("1"));

    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let mut handles = Vec::with_capacity(n_workers);
    for i in 0..n_workers {
        let cpu = if pin { Some(i) } else { None };
        let runtime = runtime.clone();
        let ready = ready_tx.clone();
        let handle = thread::Builder::new()
            .name(format!("ruxen-worker-{i}"))
            .spawn(move || worker::run(http, cpu, runtime, ready))?;
        handles.push(handle);
    }
    drop(ready_tx);

    // Each worker reports once its listeners are bound. Wait for all of
    // them: a busy port becomes one `[emerg]` and exit 1 instead of a
    // panic per worker, and the pid file (which Test::Nginx polls for)
    // appears only once the server accepts connections.
    let mut startup_error = None;
    for _ in 0..n_workers {
        match ready_rx.recv() {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                startup_error.get_or_insert(e);
            }
            // A worker died before reporting; the join below says so.
            Err(_) => break,
        }
    }
    if let Some(e) = startup_error {
        eprintln!("ruxen: [emerg] {e}");
        runtime.begin_shutdown();
        for handle in handles {
            let _ = handle.join();
        }
        return Err(Failure::Reported);
    }

    if let Some(path) = &pid_path {
        write_pid_file(path)?;
    }

    let signal_runtime = runtime.clone();
    let reopen_stderr = cli.errlog.clone();
    let monitor_pid_path = pid_path.clone();
    // Runs until the workers have finished (main drops `workers_done`),
    // so SIGTERM still works during a graceful shutdown.
    let (workers_done, monitor_rx) = std::sync::mpsc::channel::<()>();
    let signal_monitor = thread::spawn(move || {
        let mut quit_at = None;
        while let Err(std::sync::mpsc::RecvTimeoutError::Timeout) =
            monitor_rx.recv_timeout(Duration::from_millis(10))
        {
            // SIGTERM / SIGINT: nginx's fast shutdown. Its workers exit
            // without waiting for their requests, and the master deletes
            // the pid file and exits 0. Leaving the process does both.
            // `worker_shutdown_timeout` ends a graceful shutdown the same
            // way: nginx closes the connections still open when it fires
            // (ngx_shutdown_timer_handler), and its workers then exit.
            let timed_out = matches!(
                (quit_at, shutdown_timeout),
                (Some(at), Some(limit)) if Instant::now().duration_since(at) >= limit
            );
            if SIGTERM_SEEN.load(Ordering::SeqCst) || timed_out {
                signal_runtime.begin_shutdown();
                if let Some(path) = &monitor_pid_path {
                    let _ = std::fs::remove_file(path);
                }
                // Request-body temp files in flight have no names (they
                // were unlinked at creation), so the private directory is
                // empty unless `client_body_in_file_only on` kept some.
                http.body_temp.remove_private_if_empty();
                std::process::exit(0);
            }
            if quit_at.is_none() && SIGQUIT_SEEN.load(Ordering::SeqCst) {
                signal_runtime.begin_shutdown();
                quit_at = Some(Instant::now());
            }
            // Drain any pending SIGHUP into a reload-gen bump. The signal
            // handler stores `true`; clearing it here means we coalesce
            // multiple HUPs that arrive within one tick into a single
            // bump, which is fine — the per-connection check is just
            // `gen != start_gen`.
            if SIGHUP_SEEN.swap(false, Ordering::SeqCst) {
                signal_runtime.bump_reload_gen();
            }
            // SIGUSR1 reopens the log files, as nginx does after logrotate
            // moved them: the `-e` file for this thread here, and in each
            // worker (own fd table) before its next error line; the
            // access_log files before a worker's next write. error_log
            // files are opened per write already.
            if SIGUSR1_SEEN.swap(false, Ordering::SeqCst) {
                if let Some(path) = &reopen_stderr
                    && let Err(e) = redirect_stderr(path)
                {
                    eprintln!("ruxen: reopening {} failed: {e}", path.display());
                }
                worker::LOG_REOPEN_GEN.fetch_add(1, Ordering::Relaxed);
            }
        }
    });

    for handle in handles {
        if handle.join().is_err() {
            runtime.begin_shutdown();
            return Err(io::Error::other("worker thread panicked").into());
        }
    }

    runtime.begin_shutdown();
    drop(workers_done);
    let _ = signal_monitor.join();
    http.body_temp.remove_private_if_empty();

    if let Some(path) = &pid_path {
        let _ = std::fs::remove_file(path);
    }
    Ok(())
}

fn parse_cli<I>(args: I) -> Result<Cli, String>
where
    I: IntoIterator<Item = String>,
{
    let mut cli = Cli::default();
    let mut args = args.into_iter();
    let mut saw_positional = false;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" => {
                let value = args.next().ok_or("option `-c` requires a file name")?;
                cli.config_path = PathBuf::from(value);
            }
            "-p" => {
                let value = args.next().ok_or("option `-p` requires a directory")?;
                cli.prefix = Some(PathBuf::from(value));
            }
            "-e" => {
                let value = args.next().ok_or("option `-e` requires a file name")?;
                cli.errlog = Some(PathBuf::from(value));
            }
            "-g" => {
                let value = args.next().ok_or("option `-g` requires directives")?;
                cli.globals.push(value);
            }
            "-t" => cli.test_only = true,
            // nginx: suppress non-error messages during configuration testing.
            "-q" => cli.quiet = true,
            "-T" => {
                cli.test_only = true;
                cli.dump = true;
            }
            "-V" => cli.show_version = true,
            "-s" => {
                let value = args.next().ok_or("option `-s` requires a signal name")?;
                cli.signal = Some(value);
            }
            other if other.starts_with('-') => return Err(format!("unknown option `{other}`")),
            other => {
                if saw_positional {
                    return Err(format!("unexpected extra positional argument `{other}`"));
                }
                cli.config_path = PathBuf::from(other);
                saw_positional = true;
            }
        }
    }

    Ok(cli)
}

fn read_main_config(cli: &Cli) -> io::Result<(PathBuf, String)> {
    let abs = cli.config_path.canonicalize().map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("opening {}: {e}", cli.config_path.display()),
        )
    })?;
    let src = std::fs::read_to_string(&abs)
        .map_err(|e| io::Error::new(e.kind(), format!("reading {}: {e}", abs.display())))?;
    Ok((abs, src))
}

fn version_output() -> &'static str {
    concat!(
        "nginx version: nginx/1.29.2\n",
        "ruxen version: ruxen/",
        env!("CARGO_PKG_VERSION"),
        "\n",
        "TLS SNI support enabled\n",
        "configure arguments:",
        " --with-http_ssl_module",
        " --without-pcre",
        " --without-http-cache",
        " --without-http_charset_module",
        " --without-http_gzip_module",
        " --without-http_ssi_module",
        " --without-http_mirror_module",
        " --without-http_userid_module",
        " --without-http_access_module",
        " --without-http_geo_module",
        " --without-http_referer_module",
        " --without-http_fastcgi_module",
        " --without-http_uwsgi_module",
        " --without-http_scgi_module",
        " --without-http_grpc_module",
        " --without-http_memcached_module",
        " --without-http_limit_conn_module",
        " --without-http_limit_req_module",
        " --without-http_empty_gif_module",
        " --without-http_browser_module",
        " --without-http_upstream_hash_module",
        " --without-http_upstream_ip_hash_module",
        " --without-http_upstream_random_module",
        " --without-http_upstream_zone_module",
        " --without-http_upstream_sticky_module",
        " --without-mail_pop3_module",
        " --without-mail_imap_module",
        " --without-mail_smtp_module",
        "\n",
    )
}

/// `-s NAME`: the signal nginx sends for it. `reload` is refused: SIGHUP
/// only closes idle keep-alive connections, ruxen can't re-read its config.
/// nginx's ngx_event_module_init warning: more `worker_connections` than
/// file descriptors (the `worker_rlimit_nofile` to be set, else the
/// current soft limit). A `[warn]` in the top-level error log, so with
/// nginx's default level (`error`) it isn't shown, as in nginx.
fn warn_if_fd_limit_too_low(
    http: &worker::PreparedHttp,
    worker_connections: usize,
    rlimit_nofile: Option<u64>,
) {
    let mut current = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: getrlimit writes into the struct we pass.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut current) } != 0 {
        return;
    }
    let connections = worker_connections as u64;
    if connections > current.rlim_cur && rlimit_nofile.is_none_or(|n| connections > n) {
        let limit = rlimit_nofile.unwrap_or(current.rlim_cur);
        worker::write_worker_log(
            http.error_logs,
            config::ErrorLogLevel::Warn,
            &format!("{connections} worker_connections exceed open file resource limit: {limit}"),
        );
    }
}

/// `worker_rlimit_nofile` / `worker_rlimit_core`: both soft and hard limits
/// to `value`, as nginx's ngx_worker_process_init; a failure is an
/// `[alert]` and startup carries on.
fn set_rlimit(nofile: bool, value: Option<u64>) {
    let Some(value) = value else {
        return;
    };
    let limit = libc::rlimit {
        rlim_cur: value as libc::rlim_t,
        rlim_max: value as libc::rlim_t,
    };
    // The resource is named in each call: its type differs between glibc
    // and musl.
    // SAFETY: setrlimit reads the struct we pass.
    let (rc, name) = unsafe {
        if nofile {
            (
                libc::setrlimit(libc::RLIMIT_NOFILE, &limit),
                "RLIMIT_NOFILE",
            )
        } else {
            (libc::setrlimit(libc::RLIMIT_CORE, &limit), "RLIMIT_CORE")
        }
    };
    if rc != 0 {
        let e = io::Error::last_os_error();
        eprintln!(
            "ruxen: [alert] setrlimit({name}, {value}) failed ({})",
            worker::errno_text(&e)
        );
    }
}

fn signal_for(name: &str) -> Result<i32, String> {
    match name {
        "stop" => Ok(libc::SIGTERM),
        "quit" => Ok(libc::SIGQUIT),
        "reopen" => Ok(libc::SIGUSR1),
        "reload" => Err(
            "`-s reload` is not supported yet: ruxen can't re-read its configuration; \
             restart it instead"
                .into(),
        ),
        _ => Err(format!("invalid option: \"-s {name}\"")),
    }
}

/// nginx's `ngx_signal_process`: read the running instance's PID from the
/// config's `pid` file and signal it.
fn signal_process(signal: i32, pid_path: Option<&Path>) -> Result<(), Failure> {
    let Some(path) = pid_path else {
        eprintln!("ruxen: [error] no \"pid\" file is configured, so there is no process to signal");
        return Err(Failure::Reported);
    };
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!(
                "ruxen: [error] open() \"{}\" failed ({})",
                path.display(),
                worker::errno_text(&e)
            );
            return Err(Failure::Reported);
        }
    };
    let pid = match text.trim_end_matches('\n').parse::<i32>() {
        Ok(pid) if pid > 0 => pid,
        _ => {
            eprintln!(
                "ruxen: [error] invalid PID number \"{}\" in \"{}\"",
                text.trim_end_matches('\n'),
                path.display()
            );
            return Err(Failure::Reported);
        }
    };
    // SAFETY: kill(2) with a parsed PID and a valid signal number.
    if unsafe { libc::kill(pid, signal) } == -1 {
        let e = io::Error::last_os_error();
        eprintln!(
            "ruxen: [alert] kill({pid}, {signal}) failed ({})",
            worker::errno_text(&e)
        );
        return Err(Failure::Reported);
    }
    Ok(())
}

fn write_pid_file(path: &Path) -> io::Result<()> {
    std::fs::write(path, format!("{}\n", std::process::id())).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!("writing pid file {}: {e}", path.display()),
        )
    })
}

#[cfg(unix)]
fn redirect_stderr(path: &Path) -> io::Result<()> {
    let file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)?;
    let rc = unsafe { dup2(file.as_raw_fd(), 2) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn redirect_stderr(_path: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn install_signal_handlers() -> io::Result<()> {
    let rc = unsafe { signal(SIGQUIT, sigquit_handler as *const () as usize) };
    if rc == usize::MAX {
        return Err(io::Error::last_os_error());
    }
    for sig in [SIGTERM, SIGINT] {
        if unsafe { signal(sig, sigterm_handler as *const () as usize) } == usize::MAX {
            return Err(io::Error::last_os_error());
        }
    }
    // SIGHUP triggers a "reload" — we don't actually re-read config or
    // re-exec workers, but we do bump the reload generation so that
    // already-accepted connections close (idle keepalive bails out, the
    // post-request keepalive check sets `Connection: close`). New
    // connections accepted after the bump keep going.
    if unsafe { signal(SIGHUP, sighup_handler as *const () as usize) } == usize::MAX {
        return Err(io::Error::last_os_error());
    }
    if unsafe { signal(SIGUSR1, sigusr1_handler as *const () as usize) } == usize::MAX {
        return Err(io::Error::last_os_error());
    }
    // SIGUSR2 (binary upgrade) is not implemented, but its default
    // disposition is "terminate" — the upstream test harness sends it and
    // we don't want to die. Ignore it and SIGPIPE.
    for sig in [SIGUSR2, SIGPIPE] {
        if unsafe { signal(sig, SIG_IGN) } == usize::MAX {
            return Err(io::Error::last_os_error());
        }
    }
    // A parent with these masked (some shells, many CI harnesses) would
    // otherwise leave the signal pending forever — the handler is installed
    // but the kernel can't find a thread with it unblocked. Runs on the main
    // thread before workers spawn, so children inherit the unblocked mask.
    let mut set: SigSet = [0; 16];
    set[0] = [SIGQUIT, SIGTERM, SIGINT]
        .iter()
        .fold(0, |bits, sig| bits | 1u64 << (sig - 1));
    if unsafe { sigprocmask(SIG_UNBLOCK, &set, std::ptr::null_mut()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(not(unix))]
fn install_signal_handlers() -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn root_needs_explicit_user_root() {
        assert!(check_privileges(0, Some("root")).is_ok());
        let err = check_privileges(0, None).unwrap_err();
        assert!(
            err.starts_with("running as root without \"user root;\""),
            "{err}"
        );
        let err = check_privileges(0, Some("www-data")).unwrap_err();
        assert!(
            err.starts_with("\"user www-data\" is not supported yet"),
            "{err}"
        );
        assert!(check_privileges(1000, None).is_ok());
        assert!(check_privileges(1000, Some("www-data")).is_ok());
    }

    #[test]
    fn version_output_is_pinned() {
        assert_eq!(
            version_output(),
            concat!(
                "nginx version: nginx/1.29.2\n",
                "ruxen version: ruxen/",
                env!("CARGO_PKG_VERSION"),
                "\n",
                "TLS SNI support enabled\n",
                "configure arguments:",
                " --with-http_ssl_module",
                " --without-pcre",
                " --without-http-cache",
                " --without-http_charset_module",
                " --without-http_gzip_module",
                " --without-http_ssi_module",
                " --without-http_mirror_module",
                " --without-http_userid_module",
                " --without-http_access_module",
                " --without-http_geo_module",
                " --without-http_referer_module",
                " --without-http_fastcgi_module",
                " --without-http_uwsgi_module",
                " --without-http_scgi_module",
                " --without-http_grpc_module",
                " --without-http_memcached_module",
                " --without-http_limit_conn_module",
                " --without-http_limit_req_module",
                " --without-http_empty_gif_module",
                " --without-http_browser_module",
                " --without-http_upstream_hash_module",
                " --without-http_upstream_ip_hash_module",
                " --without-http_upstream_random_module",
                " --without-http_upstream_zone_module",
                " --without-http_upstream_sticky_module",
                " --without-mail_pop3_module",
                " --without-mail_imap_module",
                " --without-mail_smtp_module",
                "\n",
            )
        );
    }

    #[test]
    fn parse_cli_supports_nginx_flags() {
        let cli = parse_cli([
            "-p".into(),
            "/tmp/prefix".into(),
            "-c".into(),
            "nginx.conf".into(),
            "-e".into(),
            "error.log".into(),
            "-g".into(),
            "pid logs/nginx.pid;".into(),
            "-t".into(),
        ])
        .unwrap();
        assert_eq!(cli.prefix.as_deref(), Some(Path::new("/tmp/prefix")));
        assert_eq!(cli.config_path, PathBuf::from("nginx.conf"));
        assert_eq!(cli.errlog.as_deref(), Some(Path::new("error.log")));
        assert_eq!(cli.globals, vec!["pid logs/nginx.pid;"]);
        assert!(cli.test_only);
    }
}
