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

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

mod arena;
mod auth;
mod autoindex;
mod config;
mod file;
mod fs_resolve;
mod http;
mod http_date;
mod phase;
mod privileges;
mod proxy;
mod proxy_cache;
mod proxy_protocol;
mod proxy_stream;
mod syslog;
mod tls;
mod tls_certs;
mod tls_session;
mod tls_stream;
mod tls_ticket;
mod upstream;
mod uri;
mod worker;

/// musl's malloc costs the static build most of its proxy and TLS
/// throughput (#199). glibc builds keep the system allocator.
#[cfg(target_env = "musl")]
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

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

#[derive(Clone)]
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
    /// `--compat`: report everything in the configuration ruxen doesn't
    /// do as nginx (#278).
    compat: bool,
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
            compat: false,
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

    if cli.compat {
        return check_compat(main_path, file_src, globals_src);
    }

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
    // `user`: resolved now, so `-t` reports an unknown user like nginx;
    // switched to once the listeners are bound.
    // SAFETY: geteuid has no preconditions and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let switch_to = privileges::resolve(euid, cfg.runtime.user.as_ref())
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

    let settings = Settings::from_config(&cfg);
    // Load certificates, open roots and log files. `-t` does this too, so
    // it catches everything short of a busy port, like `nginx -t`.
    // What `prepare` leaks is recorded, to be freed once a reload has
    // retired this generation (#343).
    arena::open();
    let prepared = worker::prepare(cfg);
    let arena = arena::close();
    let http: &'static worker::PreparedHttp =
        prepared.map_err(|e| report_emerg(&e, &cli, &main_path))?;
    warn_if_fd_limit_too_low(http, settings.worker_connections, settings.rlimit_nofile);
    if cli.test_only {
        if report_test {
            eprintln!(
                "ruxen: configuration file {} test is successful",
                main_path.display()
            );
        }
        return Ok(());
    }

    // `-e` takes over stderr, unless the configuration logs to stderr
    // itself: then stderr stays, and lines without an error_log of their
    // own go to the `-e` file (nginx's log_use_stderr, ngx_log_redirect_stderr).
    if let Some(errlog) = &cli.errlog {
        if http.uses_stderr_log {
            worker::default_error_log_file(errlog);
        } else {
            redirect_stderr(errlog)?;
            let _ = worker::STDERR_LOG_PATH.set(errlog.clone());
        }
    }
    // Workers are threads, so the limits are set once for the process.
    // Each worker's fd table is its own (unshare), so RLIMIT_NOFILE then
    // bounds every worker, as nginx's per-worker setrlimit does.
    settings.set_rlimits();

    // io_uring, else epoll (monoio's legacy driver, #215). Chosen once, up
    // front, so every worker runs on the same one.
    let driver = choose_driver(http)?;
    worker::set_driver(driver);

    install_signal_handlers()?;

    // The listening sockets, kept across reloads (#89). Fails like nginx
    // when another process already listens on a port.
    let mut listeners = worker::listeners::ListenerSet::default();
    let worker_listeners = listeners
        .open(http, settings.workers)
        .map_err(|e| report_emerg(&e, &cli, &main_path))?;

    // Still one thread here, which the fork needs.
    if let Some(creds) = switch_to.as_ref().filter(|c| c.uid != 0) {
        let extra: Vec<&Path> = cli.errlog.iter().map(PathBuf::as_path).collect();
        privileges::start_helper(creds, settings.pid.as_deref(), &extra)
            .map_err(|e| report_emerg(&e, &cli, &main_path))?;
    }

    // Panic messages go to the error log (#130).
    worker::install_panic_hook(http);
    let (exited_tx, exited_rx) = std::sync::mpsc::channel();

    // Each worker reports once it is ready to accept. Wait for all of
    // them: a failure becomes one `[emerg]` and exit 1 instead of a panic
    // per worker, and the pid file (which Test::Nginx polls for) appears
    // only once the server accepts connections.
    let generation = Generation::start(0, http, arena, &settings, worker_listeners, &exited_tx);
    let mut startup_error = generation.as_ref().err().cloned();
    // The pid file goes where root may write (/run), so before the switch.
    let mut pid_written = false;
    if startup_error.is_none()
        && let Some(path) = &settings.pid
    {
        match write_pid_file(path) {
            Ok(()) => {
                pid_written = true;
                privileges::pid_written();
            }
            Err(e) => startup_error = Some(e.to_string()),
        }
    }
    // Every listener is bound and every log open: drop root for good
    // before a single connection is accepted.
    if startup_error.is_none()
        && let Some(creds) = &switch_to
        && let Err(e) = privileges::switch(creds)
    {
        startup_error = Some(e);
    }
    if let Some(e) = startup_error {
        eprintln!("ruxen: [emerg] {e}");
        if let Ok(generation) = generation {
            generation.stop();
        }
        if pid_written && let Some(path) = &settings.pid {
            privileges::remove_pid_file_on_exit(path);
        }
        listeners.remove_unix_files();
        return Err(Failure::Reported);
    }
    let generation = generation.unwrap_or_else(|_| unreachable!("checked above"));
    generation.state.release_workers();
    // nginx's cache loader and manager, a thread per zone, as the user
    // the workers run as.
    for zone in http.cache_zones {
        proxy_cache::start_manager(zone);
    }

    let reopen_stderr = cli.errlog.clone().filter(|_| !http.uses_stderr_log);
    let mut master = Master {
        cli,
        settings,
        current: generation,
        retiring: Vec::new(),
        listeners,
        exited_tx,
        next_id: 1,
    };
    master.run(exited_rx, reopen_stderr)
}

/// What the main context of a configuration decides, read again on each
/// reload.
struct Settings {
    /// `worker_processes` (or `auto`; nginx's default 1), unless
    /// `RUXEN_WORKERS` overrides it for benchmarks.
    workers: usize,
    pin: bool,
    worker_connections: usize,
    rlimit_nofile: Option<u64>,
    rlimit_core: Option<u64>,
    /// `worker_shutdown_timeout`; nginx's 0 is "no limit", the same as unset.
    shutdown_timeout: Option<Duration>,
    pid: Option<PathBuf>,
}

impl Settings {
    fn from_config(cfg: &config::HttpConfig) -> Settings {
        let config_workers = match cfg.runtime.worker_processes {
            Some(config::WorkerProcesses::Count(n)) => n,
            Some(config::WorkerProcesses::Auto) => std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1),
            None => 1,
        };
        Settings {
            workers: std::env::var("RUXEN_WORKERS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(config_workers),
            pin: matches!(std::env::var("RUXEN_PIN").as_deref(), Ok("1")),
            worker_connections: cfg.runtime.worker_connections.unwrap_or(512),
            rlimit_nofile: cfg.runtime.worker_rlimit_nofile,
            rlimit_core: cfg.runtime.worker_rlimit_core,
            shutdown_timeout: cfg
                .runtime
                .worker_shutdown_timeout_ms
                .filter(|&ms| ms != 0)
                .map(Duration::from_millis),
            pid: cfg.runtime.pid.clone(),
        }
    }

    fn set_rlimits(&self) {
        set_rlimit(true, self.rlimit_nofile);
        set_rlimit(false, self.rlimit_core);
    }
}

/// The workers of one configuration: the one ruxen started with, or one a
/// reload loaded (#89).
struct Generation {
    id: u64,
    http: &'static worker::PreparedHttp,
    /// Lives as long as the process: workers and connections borrow it
    /// instead of counting references on every accept (#128). One per
    /// generation, leaked like its configuration.
    state: &'static worker::RuntimeState,
    workers: usize,
    handles: Vec<thread::JoinHandle<()>>,
    /// Workers not yet gone.
    alive: usize,
    shutdown_timeout: Option<Duration>,
    /// When a reload retired it.
    retired_at: Option<Instant>,
    /// What preparing `http` leaked: freed once the workers are joined.
    /// `None` once freed, or when it must stay (a generation that failed
    /// to start).
    arena: Option<arena::Arena>,
}

impl Generation {
    /// Start the workers and wait until each is ready to accept (or failed:
    /// then the ones started are stopped again, and the first failure is
    /// the error). They accept once `release_workers` lets them.
    fn start(
        id: u64,
        http: &'static worker::PreparedHttp,
        arena: arena::Arena,
        settings: &Settings,
        listeners: Vec<worker::listeners::WorkerListeners>,
        exited_tx: &std::sync::mpsc::Sender<(u64, usize, bool)>,
    ) -> Result<Generation, String> {
        let state: &'static worker::RuntimeState = Box::leak(Box::default());
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let mut generation = Generation {
            id,
            http,
            state,
            workers: settings.workers,
            handles: Vec::with_capacity(settings.workers),
            alive: 0,
            shutdown_timeout: settings.shutdown_timeout,
            retired_at: None,
            arena: Some(arena),
        };
        let mut error = None;
        for (i, own) in listeners.into_iter().enumerate() {
            let cpu = if settings.pin { Some(i) } else { None };
            let ready = ready_tx.clone();
            let exited = WorkerExit(id, i, exited_tx.clone());
            let spawned = thread::Builder::new()
                .name(format!("ruxen-worker-{i}"))
                .spawn(move || {
                    let _exited = exited;
                    worker::run(http, cpu, state, ready, own)
                });
            match spawned {
                Ok(handle) => generation.handles.push(handle),
                Err(e) => {
                    error = Some(format!("spawning a worker thread failed ({e})"));
                    break;
                }
            }
        }
        drop(ready_tx);
        generation.alive = generation.handles.len();
        for _ in 0..generation.handles.len() {
            match ready_rx.recv() {
                Ok(Ok(())) => {}
                Ok(Err(e)) => {
                    error.get_or_insert(e);
                }
                // A worker died before reporting; the join below says so.
                Err(_) => break,
            }
        }
        match error {
            None => Ok(generation),
            Some(e) => {
                generation.stop();
                Err(e)
            }
        }
    }

    /// Stop workers that never accepted and wait for them.
    fn stop(self) {
        self.state.begin_shutdown();
        self.state.release_workers();
        for handle in self.handles {
            let _ = handle.join();
        }
    }
}

/// `main` once the workers run: nginx's master process loop. It waits for
/// signals and for workers to end, and reloads.
struct Master {
    cli: Cli,
    settings: Settings,
    current: Generation,
    /// Generations a reload retired whose workers haven't all finished.
    retiring: Vec<Generation>,
    listeners: worker::listeners::ListenerSet,
    exited_tx: std::sync::mpsc::Sender<(u64, usize, bool)>,
    next_id: u64,
}

impl Master {
    fn run(
        &mut self,
        exited_rx: std::sync::mpsc::Receiver<(u64, usize, bool)>,
        reopen_stderr: Option<PathBuf>,
    ) -> Result<(), Failure> {
        let mut quit_at = None;
        let mut worker_panicked = false;
        loop {
            // Workers say when they are gone, in any order. One that
            // panicked ends the server: the others stop as on SIGQUIT, and
            // ruxen exits 1 for a supervisor to restart it (#130; see
            // worker/panics.rs).
            match exited_rx.recv_timeout(Duration::from_millis(10)) {
                // A generation that failed to start was joined already.
                Ok((id, i, panicked)) => {
                    let Some(generation) = self.generation(id) else {
                        continue;
                    };
                    generation.alive -= 1;
                    let http = generation.http;
                    if panicked && !worker_panicked {
                        worker_panicked = true;
                        worker::write_worker_log(
                            http.error_logs,
                            config::ErrorLogLevel::Alert,
                            &format!("worker {i} exited after a panic, stopping"),
                        );
                        self.begin_shutdown();
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
            }
            self.finish_retired();
            if self.current.alive == 0 && self.retiring.is_empty() {
                break;
            }
            // SIGTERM / SIGINT: nginx's fast shutdown. Its workers exit
            // without waiting for their requests, and the master deletes
            // the pid file and exits 0. Leaving the process does both.
            // `worker_shutdown_timeout` ends a graceful shutdown the same
            // way: nginx closes the connections still open when it fires
            // (ngx_shutdown_timer_handler), and its workers then exit.
            let timed_out = matches!(
                (quit_at, self.settings.shutdown_timeout),
                (Some(at), Some(limit)) if Instant::now().duration_since(at) >= limit
            );
            if SIGTERM_SEEN.load(Ordering::SeqCst) || timed_out {
                self.begin_shutdown();
                if let Some(path) = &self.settings.pid {
                    privileges::remove_pid_file_on_exit(path);
                }
                // Request-body temp files in flight have no names (they
                // were unlinked at creation), so the private directory is
                // empty unless `client_body_in_file_only on` kept some.
                for generation in self.retiring.iter().chain([&self.current]) {
                    generation.http.body_temp.remove_private_if_empty();
                }
                // Buffered access_log lines (#151): nginx's workers write
                // them on their way out.
                worker::logbuf::flush_at_exit();
                self.listeners.remove_unix_files();
                std::process::exit(0);
            }
            if quit_at.is_none() && SIGQUIT_SEEN.load(Ordering::SeqCst) {
                self.begin_shutdown();
                quit_at = Some(Instant::now());
            }
            // Several HUPs within one turn make one reload.
            if SIGHUP_SEEN.swap(false, Ordering::SeqCst) && quit_at.is_none() && !worker_panicked {
                self.reload();
            }
            // SIGUSR1 reopens the log files, as nginx does after logrotate
            // moved them: the `-e` file for this thread here, and in each
            // worker (own fd table) before its next error line; the
            // access_log files before a worker's next write. error_log
            // files are opened per write already.
            if SIGUSR1_SEEN.swap(false, Ordering::SeqCst) {
                // After a switch to `user`, the root helper recreates the
                // files logrotate moved, for the user to open.
                privileges::reopen_logs();
                if let Some(path) = &reopen_stderr
                    && let Err(e) = redirect_stderr(path)
                {
                    eprintln!("ruxen: reopening {} failed: {e}", path.display());
                }
                worker::LOG_REOPEN_GEN.fetch_add(1, Ordering::Relaxed);
            }
        }
        // The loop ends once every generation's workers are gone.
        for handle in std::mem::take(&mut self.current.handles) {
            let _ = handle.join();
        }
        self.current.http.body_temp.remove_private_if_empty();
        self.listeners.remove_unix_files();
        if let Some(path) = &self.settings.pid {
            privileges::remove_pid_file_on_exit(path);
        }
        if worker_panicked {
            return Err(Failure::Reported);
        }
        Ok(())
    }

    fn generation(&mut self, id: u64) -> Option<&mut Generation> {
        if self.current.id == id {
            return Some(&mut self.current);
        }
        self.retiring.iter_mut().find(|g| g.id == id)
    }

    fn begin_shutdown(&self) {
        for generation in self.retiring.iter().chain([&self.current]) {
            generation.state.begin_shutdown();
        }
    }

    /// Retired generations: end their connections once
    /// `worker_shutdown_timeout` has passed, and join the ones whose
    /// workers are all gone.
    fn finish_retired(&mut self) {
        let now = Instant::now();
        for generation in &self.retiring {
            if let (Some(at), Some(limit)) = (generation.retired_at, generation.shutdown_timeout)
                && now.duration_since(at) >= limit
                && !generation.state.is_forced()
            {
                generation.state.force_close();
            }
        }
        let (done, live): (Vec<_>, Vec<_>) = std::mem::take(&mut self.retiring)
            .into_iter()
            .partition(|g| g.alive == 0);
        self.retiring = live;
        for mut generation in done {
            for handle in std::mem::take(&mut generation.handles) {
                let _ = handle.join();
            }
            generation.http.close_root_fds();
            // Keyed by peer address: a freed peer's entry could match a
            // later one at the same address.
            syslog::forget_error_log_sockets();
            if let Some(arena) = generation.arena.take() {
                // SAFETY: its workers are joined, and what a later
                // generation keeps (zone state, cache zones, the buffered
                // log registry) is leaked outside the arena.
                unsafe { arena.free() };
            }
        }
    }

    /// SIGHUP: nginx's reconfiguration (ngx_master_process_cycle). Read
    /// and prepare the configuration again, start a generation of workers
    /// with it on the same listening sockets, then retire the running one:
    /// it stops accepting, closes idle connections and finishes its
    /// requests. A configuration that fails anywhere on the way is logged,
    /// and the running one stays, as nginx keeps its old cycle.
    fn reload(&mut self) {
        let log = |http: &worker::PreparedHttp, level, message: &str| {
            worker::write_worker_log(http.error_logs, level, message)
        };
        let old_http = self.current.http;
        log(
            old_http,
            config::ErrorLogLevel::Notice,
            "signal 1 (SIGHUP) received, reconfiguring",
        );
        let cli = self.cli.clone();
        // Its own thread: parsing and preparing keep state in thread
        // locals, which then start empty, as at startup.
        let loaded = thread::Builder::new()
            .name("ruxen-reload".into())
            .spawn(move || load_for_reload(&cli))
            .map_err(|e| format!("spawning a thread failed ({e})"))
            .and_then(|t| {
                t.join()
                    .unwrap_or_else(|_| Err("reading the configuration panicked".into()))
            });
        let (settings, http, arena, warnings) = match loaded {
            Ok(loaded) => loaded,
            Err(e) => return log(old_http, config::ErrorLogLevel::Emerg, &e),
        };
        for w in &warnings {
            log(old_http, config::ErrorLogLevel::Warn, w);
        }
        let worker_listeners = match self.listeners.open(http, settings.workers) {
            Ok(l) => l,
            Err(e) => {
                http.close_root_fds();
                return log(old_http, config::ErrorLogLevel::Emerg, &e);
            }
        };
        let id = self.next_id;
        self.next_id += 1;
        let generation = match Generation::start(
            id,
            http,
            arena,
            &settings,
            worker_listeners,
            &self.exited_tx,
        ) {
            Ok(g) => g,
            Err(e) => {
                self.listeners
                    .retain(self.current.http, self.current.workers);
                http.close_root_fds();
                return log(old_http, config::ErrorLogLevel::Emerg, &e);
            }
        };
        generation.state.release_workers();
        worker::set_panic_hook_config(http);
        let mut old = std::mem::replace(&mut self.current, generation);
        old.state.begin_shutdown();
        old.state.bump_reload_gen();
        old.retired_at = Some(Instant::now());
        self.retiring.push(old);
        self.listeners.retain(http, settings.workers);
        for zone in http.cache_zones {
            proxy_cache::start_manager(zone);
        }
        proxy_cache::retire_zones_but(http.cache_zones);
        settings.set_rlimits();
        if settings.pid != self.settings.pid {
            if let Some(path) = &settings.pid
                && let Err(e) = write_pid_file(path)
            {
                log(http, config::ErrorLogLevel::Alert, &e.to_string());
            }
            if let Some(path) = &self.settings.pid
                && !privileges::helper_running()
            {
                let _ = std::fs::remove_file(path);
            }
        }
        self.settings = settings;
    }
}

/// Read, parse and prepare the configuration as at startup, for a reload.
fn load_for_reload(
    cli: &Cli,
) -> Result<
    (
        Settings,
        &'static worker::PreparedHttp,
        arena::Arena,
        Vec<String>,
    ),
    String,
> {
    let (main_path, file_src) = read_main_config(cli).map_err(|e| e.to_string())?;
    let globals_src = (!cli.globals.is_empty()).then(|| {
        cli.globals
            .iter()
            .map(|g| {
                if g.ends_with('\n') {
                    g.clone()
                } else {
                    format!("{g}\n")
                }
            })
            .collect::<String>()
    });
    let cfg =
        config::parse_with_main(main_path, file_src, globals_src).map_err(|e| e.to_string())?;
    let settings = Settings::from_config(&cfg);
    let warnings = cfg.warnings.clone();
    arena::open();
    let prepared = worker::prepare(cfg);
    // On an error the arena is dropped: what was leaked stays.
    let arena = arena::close();
    Ok((settings, prepared?, arena, warnings))
}

/// Held by a worker thread: tells `main` the worker (generation, index) is
/// gone, and whether it unwound from a panic, when the thread ends either
/// way.
struct WorkerExit(u64, usize, std::sync::mpsc::Sender<(u64, usize, bool)>);

impl Drop for WorkerExit {
    fn drop(&mut self) {
        let _ = self.2.send((self.0, self.1, thread::panicking()));
    }
}

/// `ruxen --compat`: parse the whole configuration, collecting what ruxen
/// doesn't support or does differently instead of stopping at the first
/// unknown directive, then load it as `-t` does (certificates, roots,
/// logs) if nothing unsupported was found. The report goes to stdout;
/// the exit status is 0 when ruxen starts with the configuration.
fn check_compat(
    main_path: PathBuf,
    file_src: String,
    globals_src: Option<String>,
) -> Result<(), Failure> {
    println!(
        "ruxen {}: checking {}",
        env!("CARGO_PKG_VERSION"),
        main_path.display()
    );
    config::compat::begin();
    let parsed = config::parse_with_main(main_path, file_src, globals_src);
    let findings = config::compat::finish();
    let cfg = match parsed {
        Ok(cfg) => cfg,
        Err(e) => {
            print!(
                "{}",
                config::compat::report(&findings, &[], Some(&e.to_string()), None)
            );
            return Err(Failure::Reported);
        }
    };
    let warnings = cfg.warnings.clone();
    let unsupported = findings
        .iter()
        .any(|f| f.severity == config::compat::Severity::Unsupported);
    let prepare_error = if unsupported {
        None
    } else {
        worker::prepare(cfg).err()
    };
    print!(
        "{}",
        config::compat::report(&findings, &warnings, None, prepare_error.as_deref())
    );
    if unsupported || prepare_error.is_some() {
        return Err(Failure::Reported);
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
            "--compat" => {
                cli.compat = true;
                cli.test_only = true;
            }
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
        " --with-http_realip_module",
        " --with-http_stub_status_module",
        " --with-http_v2_module",
        " --without-pcre",
        " --without-http_charset_module",
        " --without-http_ssi_module",
        " --without-http_mirror_module",
        " --without-http_userid_module",
        " --without-http_geo_module",
        " --without-http_referer_module",
        " --without-http_fastcgi_module",
        " --without-http_uwsgi_module",
        " --without-http_scgi_module",
        " --without-http_grpc_module",
        " --without-http_memcached_module",
        " --without-http_empty_gif_module",
        " --without-http_browser_module",
        " --without-http_upstream_random_module",
        " --without-http_upstream_sticky_module",
        " --without-mail_pop3_module",
        " --without-mail_imap_module",
        " --without-mail_smtp_module",
        "\n",
    )
}

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

/// The I/O driver (#215): io_uring where the kernel and seccomp allow it,
/// else epoll, with a `[notice]` saying why. `RUXEN_DRIVER=epoll` picks
/// epoll anyway; `RUXEN_DRIVER=io_uring` refuses to start without
/// io_uring. `events { use epoll; }` doesn't choose: configurations
/// written for nginx set it because it's the best method nginx has on
/// Linux.
fn choose_driver(http: &worker::PreparedHttp) -> Result<worker::Driver, Failure> {
    const WHY: &str = "it is blocked by seccomp (Docker's default profile denies it: \
                       use contrib/docker/seccomp-io_uring.json from the ruxen repository), \
                       disabled via the kernel.io_uring_disabled sysctl, or the kernel is too old";
    let wanted = std::env::var("RUXEN_DRIVER").unwrap_or_default();
    match wanted.as_str() {
        "epoll" => return Ok(worker::Driver::Epoll),
        "io_uring" | "" => {}
        other => {
            eprintln!(
                "ruxen: [emerg] RUXEN_DRIVER=\"{other}\" is not a driver (io_uring or epoll)"
            );
            return Err(Failure::Reported);
        }
    }
    if monoio::utils::detect_uring() {
        return Ok(worker::Driver::IoUring);
    }
    if wanted == "io_uring" {
        eprintln!("ruxen: [emerg] io_uring is not available: {WHY}");
        return Err(Failure::Reported);
    }
    worker::write_worker_log(
        http.error_logs,
        config::ErrorLogLevel::Notice,
        &format!("io_uring is not available, using epoll: {WHY}"),
    );
    Ok(worker::Driver::Epoll)
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

/// `-s NAME`: the signal nginx sends for it.
fn signal_for(name: &str) -> Result<i32, String> {
    match name {
        "stop" => Ok(libc::SIGTERM),
        "quit" => Ok(libc::SIGQUIT),
        "reopen" => Ok(libc::SIGUSR1),
        "reload" => Ok(libc::SIGHUP),
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
    // SIGHUP: reload the configuration (`Master::reload`).
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
    set[0] = [SIGQUIT, SIGTERM, SIGINT, SIGHUP, SIGUSR1]
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
                " --with-http_realip_module",
                " --with-http_stub_status_module",
                " --with-http_v2_module",
                " --without-pcre",
                " --without-http_charset_module",
                " --without-http_ssi_module",
                " --without-http_mirror_module",
                " --without-http_userid_module",
                " --without-http_geo_module",
                " --without-http_referer_module",
                " --without-http_fastcgi_module",
                " --without-http_uwsgi_module",
                " --without-http_scgi_module",
                " --without-http_grpc_module",
                " --without-http_memcached_module",
                " --without-http_empty_gif_module",
                " --without-http_browser_module",
                " --without-http_upstream_random_module",
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
