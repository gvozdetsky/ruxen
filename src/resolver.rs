//! Runtime DNS for `proxy_pass` with variables (#133), as nginx's resolver
//! (src/core/ngx_resolver.c) answers ngx_http_upstream_init_request:
//!
//! - One `Resolver` per `resolver` directive; the locations that inherit
//!   it share its cache. The cache and the queries are per worker, as
//!   everything else that changes at run time.
//! - A name is asked for A, and for AAAA unless `ipv6=off`, from the
//!   servers in turn: each new name goes to the next server, and a query
//!   without an answer is sent to the next one every 5 seconds. Requests
//!   waiting for the same name share one query; each gives up on its own
//!   after `resolver_timeout`.
//! - A truncated answer is asked again over TCP. CNAMEs are followed (50
//!   at most). Answers are cached by their TTL, or by `valid=`; errors
//!   aren't cached.
//! - An answer counts only if it comes from the server asked, to the port
//!   the query left from, with the query's random id and question. Each
//!   query has a socket of its own, so a fresh source port too (nginx
//!   keeps one socket per server). A malformed one is logged and ignored,
//!   as nginx does, so the query waits on.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use crate::config::ErrorLogLevel;

/// nginx's `r->resend_timeout`, and `r->tcp_timeout` for a TCP query.
const RESEND: Duration = Duration::from_secs(5);
/// NGX_RESOLVER_MAX_RECURSION: CNAMEs followed for one request.
const MAX_RECURSION: u32 = 50;
/// NGX_RESOLVER_UDP_SIZE.
const UDP_SIZE: usize = 4096;
/// Cached names kept per worker and resolver past their use: the names
/// may come from the client. nginx drops a name 30 seconds after its
/// last use (`r->expire`), a few at a time.
const CACHE_MAX: usize = 4096;
const EXPIRE: Duration = Duration::from_secs(30);

const TYPE_A: u16 = 1;
const TYPE_CNAME: u16 = 5;
const TYPE_AAAA: u16 = 28;
const TYPE_DNAME: u16 = 39;

/// rcodes, and NGX_RESOLVE_TIMEDOUT (NGX_ETIMEDOUT).
pub(crate) const FORMERR: u16 = 1;
pub(crate) const SERVFAIL: u16 = 2;
pub(crate) const NXDOMAIN: u16 = 3;
pub(crate) const REFUSED: u16 = 5;
pub(crate) const TIMEDOUT: u16 = 110;

/// A `resolver` directive, prepared.
#[derive(Debug)]
pub struct Resolver {
    /// The name servers, in the directive's order (a name in it stands
    /// for all its addresses).
    pub servers: Box<[SocketAddr]>,
    /// `valid=`: how long answers are kept, whatever their TTL.
    pub valid: Option<Duration>,
    pub ipv4: bool,
    pub ipv6: bool,
}

/// Why a name gave no addresses: an rcode, or `TIMEDOUT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failure(pub u16);

impl std::fmt::Display for Failure {
    /// `3: Host not found`, as ngx_resolver_strerror.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self.0 {
            FORMERR => "Format error",
            SERVFAIL => "Server failure",
            NXDOMAIN => "Host not found",
            4 => "Unimplemented",
            REFUSED => "Operation refused",
            TIMEDOUT => "Operation timed out",
            _ => "Unknown error",
        };
        write!(f, "{}: {text}", self.0)
    }
}

/// The addresses of `name`, as nginx hands them to the upstream: A
/// records first, then AAAA; from the cache in a random rotation. `name`
/// is matched without case and without a trailing dot.
pub(crate) async fn resolve(
    resolver: &'static Resolver,
    name: &[u8],
    timeout: Duration,
) -> Result<Vec<IpAddr>, Failure> {
    let name = normalize(name);
    match monoio::time::timeout(timeout, lookup(resolver, name)).await {
        Ok(result) => result,
        Err(_) => Err(Failure(TIMEDOUT)),
    }
}

/// The name as nginx asks for it: without a trailing dot, in lower case.
pub(crate) fn normalize(name: &[u8]) -> Box<[u8]> {
    let name = name.strip_suffix(b".").unwrap_or(name);
    name.to_ascii_lowercase().into_boxed_slice()
}

async fn lookup(resolver: &'static Resolver, mut name: Box<[u8]>) -> Result<Vec<IpAddr>, Failure> {
    let state = worker_state(resolver);
    let mut recursion = 0;
    loop {
        let found = state.borrow_mut().find(&name, Instant::now());
        let (answer, cached) = match found {
            Found::Cached(answer) => (answer, true),
            Found::Pending(pending) => match Wait::new(pending).await {
                Outcome::Answer(answer) => (answer, false),
                Outcome::Failed(failure) => return Err(failure),
            },
            Found::New(pending) => {
                if let Some(query) = Queries::new(resolver, &name) {
                    let server = state.borrow_mut().next_server(resolver);
                    crate::worker::spawn_contained(
                        "a resolver query",
                        || {},
                        drive(
                            resolver,
                            state.clone(),
                            pending.clone(),
                            name.clone(),
                            query,
                            server,
                        ),
                    );
                } else {
                    // ngx_resolver_create_name_query declines it.
                    state.borrow_mut().pending.remove(&name);
                    return Err(Failure(NXDOMAIN));
                }
                match Wait::new(pending).await {
                    Outcome::Answer(answer) => (answer, false),
                    Outcome::Failed(failure) => return Err(failure),
                }
            }
        };
        match answer {
            Answer::Addrs(addrs) if cached => return Ok(rotate(&addrs)),
            Answer::Addrs(addrs) => return Ok(addrs.to_vec()),
            Answer::Cname(target) => {
                recursion += 1;
                if recursion > MAX_RECURSION {
                    return Err(Failure(NXDOMAIN));
                }
                name = target;
            }
        }
    }
}

/// ngx_resolver_export with `rotate`: the A and the AAAA lists each start
/// at a random entry, and the whole list at a random place.
fn rotate(addrs: &[IpAddr]) -> Vec<IpAddr> {
    let n = addrs.len();
    if n < 2 {
        return addrs.to_vec();
    }
    let split = addrs.iter().take_while(|a| a.is_ipv4()).count();
    let (v4, v6) = addrs.split_at(split);
    let mut out = vec![addrs[0]; n];
    let mut d = random_u16() as usize % n;
    for list in [v4, v6] {
        if list.is_empty() {
            continue;
        }
        let start = random_u16() as usize % list.len();
        for i in 0..list.len() {
            out[d] = list[(start + i) % list.len()];
            d = (d + 1) % n;
        }
    }
    out
}

#[derive(Clone)]
enum Answer {
    Addrs(Rc<[IpAddr]>),
    Cname(Box<[u8]>),
}

#[derive(Clone)]
enum Outcome {
    Answer(Answer),
    Failed(Failure),
}

struct Entry {
    answer: Answer,
    valid_until: Instant,
    used: Instant,
}

/// A name being asked: the requests waiting for it, and the query's task.
#[derive(Default)]
struct Pending {
    outcome: RefCell<Option<Outcome>>,
    waiters: Cell<usize>,
    wakers: RefCell<Vec<Waker>>,
    /// The query's task, woken when the last request stops waiting.
    driver: RefCell<Option<Waker>>,
}

impl Pending {
    fn finish(&self, outcome: Outcome) {
        if self.outcome.borrow().is_some() {
            return;
        }
        *self.outcome.borrow_mut() = Some(outcome);
        for waker in self.wakers.take() {
            waker.wake();
        }
    }
}

/// One request waiting on a `Pending`.
struct Wait {
    pending: Rc<Pending>,
}

impl Wait {
    fn new(pending: Rc<Pending>) -> Self {
        pending.waiters.set(pending.waiters.get() + 1);
        Wait { pending }
    }
}

impl Future for Wait {
    type Output = Outcome;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Outcome> {
        if let Some(outcome) = self.pending.outcome.borrow().as_ref() {
            return Poll::Ready(outcome.clone());
        }
        let mut wakers = self.pending.wakers.borrow_mut();
        if !wakers.iter().any(|w| w.will_wake(cx.waker())) {
            wakers.push(cx.waker().clone());
        }
        Poll::Pending
    }
}

impl Drop for Wait {
    fn drop(&mut self) {
        let left = self.pending.waiters.get() - 1;
        self.pending.waiters.set(left);
        if left == 0
            && let Some(driver) = self.pending.driver.take()
        {
            driver.wake();
        }
    }
}

enum Found {
    Cached(Answer),
    Pending(Rc<Pending>),
    /// Nobody asks for it yet: the caller starts the query.
    New(Rc<Pending>),
}

/// A resolver's cache and queries in one worker.
#[derive(Default)]
struct State {
    cache: HashMap<Box<[u8]>, Entry>,
    pending: HashMap<Box<[u8]>, Rc<Pending>>,
    /// nginx's `r->last_connection`: the server the next name goes to.
    next: usize,
}

impl State {
    fn find(&mut self, name: &[u8], now: Instant) -> Found {
        if let Some(entry) = self.cache.get_mut(name) {
            if entry.valid_until > now {
                entry.used = now;
                return Found::Cached(entry.answer.clone());
            }
            self.cache.remove(name);
        }
        if let Some(pending) = self.pending.get(name) {
            return Found::Pending(pending.clone());
        }
        let pending = Rc::new(Pending::default());
        self.pending.insert(name.into(), pending.clone());
        Found::New(pending)
    }

    fn next_server(&mut self, resolver: &Resolver) -> usize {
        let server = self.next % resolver.servers.len();
        self.next = (server + 1) % resolver.servers.len();
        server
    }

    fn store(&mut self, name: Box<[u8]>, answer: Answer, valid_until: Instant) {
        let now = Instant::now();
        if self.cache.len() >= CACHE_MAX {
            self.cache
                .retain(|_, e| e.valid_until > now && now.duration_since(e.used) < EXPIRE);
        }
        if self.cache.len() >= CACHE_MAX {
            // Still full of names in use: the least recently used goes.
            if let Some(oldest) = self
                .cache
                .iter()
                .min_by_key(|(_, e)| e.used)
                .map(|(k, _)| k.clone())
            {
                self.cache.remove(&oldest);
            }
        }
        self.cache.insert(
            name,
            Entry {
                answer,
                valid_until,
                used: now,
            },
        );
    }
}

thread_local! {
    /// Per worker, by resolver.
    static STATES: RefCell<HashMap<*const Resolver, Rc<RefCell<State>>>> =
        RefCell::new(HashMap::new());
}

fn worker_state(resolver: &'static Resolver) -> Rc<RefCell<State>> {
    STATES.with(|s| {
        s.borrow_mut()
            .entry(resolver as *const Resolver)
            .or_default()
            .clone()
    })
}

/// Ends a query: whatever happened to its task, the name is no longer
/// pending, and anyone still waiting hears about it.
struct Finish {
    state: Rc<RefCell<State>>,
    pending: Rc<Pending>,
    name: Box<[u8]>,
}

impl Drop for Finish {
    fn drop(&mut self) {
        let mut state = self.state.borrow_mut();
        if state
            .pending
            .get(&self.name)
            .is_some_and(|p| Rc::ptr_eq(p, &self.pending))
        {
            state.pending.remove(&self.name);
        }
        drop(state);
        self.pending.finish(Outcome::Failed(Failure(0)));
    }
}

/// The task asking for one name, until it has an answer or nobody waits
/// for it any more.
async fn drive(
    resolver: &'static Resolver,
    state: Rc<RefCell<State>>,
    pending: Rc<Pending>,
    name: Box<[u8]>,
    mut queries: Queries,
    first: usize,
) {
    let finish = Finish {
        state,
        pending,
        name,
    };
    let Some(done) = queries.run(resolver, &finish.pending, first).await else {
        return;
    };
    let outcome = match done {
        Ok((answer, valid_until)) => {
            finish
                .state
                .borrow_mut()
                .store(finish.name.clone(), answer.clone(), valid_until);
            Outcome::Answer(answer)
        }
        Err(code) => Outcome::Failed(Failure(code)),
    };
    finish.pending.finish(outcome);
}

/// A name's answer and until when it holds, or the rcode that failed it.
type Done = Result<(Answer, Instant), u16>;

enum Step {
    /// Nothing decided yet (or the response was ignored).
    Wait,
    Done(Done),
    /// Query `i` came back truncated: ask again over TCP.
    Tcp(usize),
}

/// What one query type got.
enum Got {
    Waiting,
    Error,
    Answer { addrs: Vec<IpAddr> },
}

struct Query {
    qtype: u16,
    id: u16,
    /// Over TCP from now on: an answer came truncated.
    tcp: bool,
    got: Got,
}

/// The A and AAAA queries for one name (ngx_resolver_node_t).
struct Queries {
    /// The question, `\3www\7example\3com\0`.
    qname: Vec<u8>,
    name: Box<[u8]>,
    queries: Vec<Query>,
    valid: Option<Duration>,
    /// nginx's `rn->code`: the last error an answer had.
    code: u16,
    /// nginx's `rn->ttl`: the smallest TTL of the records seen.
    ttl: u32,
}

impl Queries {
    /// `None` for a name that can't be asked: an empty label, or one
    /// longer than 63 bytes.
    fn new(resolver: &Resolver, name: &[u8]) -> Option<Queries> {
        let qname = encode_name(name)?;
        let mut queries = Vec::with_capacity(2);
        for (on, qtype) in [(resolver.ipv4, TYPE_A), (resolver.ipv6, TYPE_AAAA)] {
            if on {
                queries.push(Query {
                    qtype,
                    id: 0,
                    tcp: false,
                    got: Got::Waiting,
                });
            }
        }
        Some(Queries {
            qname,
            name: name.into(),
            queries,
            valid: resolver.valid,
            code: 0,
            ttl: u32::MAX,
        })
    }

    /// Query `i` with a fresh id.
    fn packet(&mut self, i: usize) -> Vec<u8> {
        let query = &mut self.queries[i];
        query.id = random_u16();
        let mut p = Vec::with_capacity(12 + self.qname.len() + 4);
        p.extend_from_slice(&query.id.to_be_bytes());
        // A recursive query with one question.
        p.extend_from_slice(&[1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        p.extend_from_slice(&self.qname);
        p.extend_from_slice(&query.qtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p
    }

    fn waiting(&self, i: usize) -> bool {
        matches!(self.queries[i].got, Got::Waiting)
    }

    /// Ask the servers in turn from `server` on, each for `RESEND`, until
    /// the name is decided. `None` once nobody waits for it.
    async fn run(
        &mut self,
        resolver: &'static Resolver,
        pending: &Pending,
        mut server: usize,
    ) -> Option<Done> {
        let servers = &resolver.servers;
        loop {
            let addr = servers[server];
            let mut deadline = Instant::now() + RESEND;
            let mut udp = None;
            if (0..self.queries.len()).any(|i| self.waiting(i) && !self.queries[i].tcp) {
                match self.send_udp(addr).await {
                    Ok(socket) => udp = Some(socket),
                    Err(e) => log_server(
                        addr,
                        &format!("send() failed ({})", crate::worker::errno_text(&e)),
                    ),
                }
            }
            for i in 0..self.queries.len() {
                if self.waiting(i)
                    && self.queries[i].tcp
                    && let Some(done) = self.ask_tcp(i, addr, pending, deadline).await?
                {
                    return Some(done);
                }
            }
            loop {
                match next_event(udp.as_ref(), pending, deadline).await {
                    Event::Abandoned => return None,
                    Event::Resend => break,
                    Event::Packet(Err(e)) => {
                        log_server(
                            addr,
                            &format!("recv() failed ({})", crate::worker::errno_text(&e)),
                        );
                        udp = None;
                    }
                    Event::Packet(Ok(packet)) => match self.process(&packet, false) {
                        Step::Wait => {}
                        Step::Done(done) => return Some(done),
                        Step::Tcp(i) => {
                            deadline = Instant::now() + RESEND;
                            if let Some(done) = self.ask_tcp(i, addr, pending, deadline).await? {
                                return Some(done);
                            }
                        }
                    },
                }
            }
            server = (server + 1) % servers.len();
        }
    }

    /// A socket of its own for this round, with the waiting UDP queries
    /// sent on it.
    async fn send_udp(&mut self, addr: SocketAddr) -> std::io::Result<monoio::net::udp::UdpSocket> {
        let local: SocketAddr = if addr.is_ipv4() {
            (Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let socket = monoio::net::udp::UdpSocket::bind(local)?;
        socket.connect(addr).await?;
        for i in 0..self.queries.len() {
            if self.waiting(i) && !self.queries[i].tcp {
                let packet = self.packet(i);
                let (sent, _) = socket.send(packet).await;
                sent?;
            }
        }
        Ok(socket)
    }

    /// Ask query `i` over TCP and take what comes back
    /// (ngx_resolver_send_tcp_query). `None` once nobody waits; `Some(None)`
    /// while the name is undecided.
    async fn ask_tcp(
        &mut self,
        i: usize,
        addr: SocketAddr,
        pending: &Pending,
        deadline: Instant,
    ) -> Option<Option<Done>> {
        let packet = self.packet(i);
        let exchange = monoio::time::timeout(
            deadline.saturating_duration_since(Instant::now()),
            tcp_exchange(addr, packet),
        );
        let response = match abandonable(exchange, pending).await? {
            Ok(Ok(response)) => response,
            Ok(Err(e)) => {
                log_server(
                    addr,
                    &format!("TCP query failed ({})", crate::worker::errno_text(&e)),
                );
                return Some(None);
            }
            Err(_) => {
                log_server(addr, "TCP query timed out");
                return Some(None);
            }
        };
        match self.process(&response, true) {
            Step::Done(done) => Some(Some(done)),
            Step::Wait | Step::Tcp(_) => Some(None),
        }
    }

    /// Take one response, as ngx_resolver_process_response and
    /// ngx_resolver_process_a do.
    fn process(&mut self, packet: &[u8], tcp: bool) -> Step {
        let head = match parse_head(packet, tcp) {
            Ok(head) => head,
            Err(message) => {
                log(&message);
                return Step::Wait;
            }
        };
        let unexpected = || {
            log(&format!(
                "unexpected DNS response for {}",
                String::from_utf8_lossy(&head.qname)
            ));
            Step::Wait
        };
        if *head.qname != *self.name {
            return unexpected();
        }
        let Some(i) = (0..self.queries.len())
            .find(|&i| self.queries[i].qtype == head.qtype && self.waiting(i))
        else {
            return unexpected();
        };
        if head.trunc && self.queries[i].tcp {
            return Step::Wait;
        }
        if head.id != self.queries[i].id {
            log(&format!(
                "wrong ident {} in DNS response for {}, expect {}",
                head.id,
                String::from_utf8_lossy(&head.qname),
                self.queries[i].id
            ));
            return Step::Wait;
        }
        if head.trunc {
            self.queries[i].tcp = true;
            return Step::Tcp(i);
        }
        if head.code != 0 {
            self.code = head.code;
            self.queries[i].got = Got::Error;
            return self.decide(Ok(None));
        }
        if head.answers == 0 {
            self.queries[i].got = Got::Answer { addrs: Vec::new() };
            return self.decide(Err(()));
        }
        let answers = match parse_answers(packet, &head) {
            Ok(answers) => answers,
            Err(message) => {
                log(&message);
                return Step::Wait;
            }
        };
        for rtype in &answers.unexpected {
            log(&format!("unexpected RR type {rtype} in DNS response"));
        }
        self.ttl = self.ttl.min(answers.ttl);
        self.queries[i].got = Got::Answer {
            addrs: answers.addrs,
        };
        self.decide(Ok(answers.cname.map(|at| (packet, at))))
    }

    /// Once every type has its answer: an error if any had one, the
    /// addresses if any came, else the CNAME of the answer that came last.
    /// `last` is that answer's CNAME, or `Err` for an empty answer.
    fn decide(&self, last: Result<Option<(&[u8], usize)>, ()>) -> Step {
        if (0..self.queries.len()).any(|i| self.waiting(i)) {
            return Step::Wait;
        }
        if self.code != 0 {
            return Step::Done(Err(self.code));
        }
        let addrs: Vec<IpAddr> = self
            .queries
            .iter()
            .flat_map(|q| match &q.got {
                Got::Answer { addrs } => addrs.as_slice(),
                _ => &[],
            })
            .copied()
            .collect();
        let valid_until = Instant::now()
            + self
                .valid
                .unwrap_or(Duration::from_secs(u64::from(self.ttl)));
        if !addrs.is_empty() {
            return Step::Done(Ok((Answer::Addrs(addrs.into()), valid_until)));
        }
        match last {
            Ok(Some((packet, at))) => match copy_name(packet, at) {
                Ok(target) => Step::Done(Ok((Answer::Cname(target), valid_until))),
                Err(message) => {
                    log(&message);
                    Step::Done(Err(NXDOMAIN))
                }
            },
            // nginx waits on after this line, until the request times out.
            Ok(None) => {
                log("no A or CNAME types in DNS response");
                Step::Done(Err(NXDOMAIN))
            }
            Err(()) => Step::Done(Err(NXDOMAIN)),
        }
    }
}

enum Event {
    Packet(std::io::Result<Vec<u8>>),
    /// Time to ask the next server.
    Resend,
    /// Nobody waits for the name any more.
    Abandoned,
}

async fn next_event(
    udp: Option<&monoio::net::udp::UdpSocket>,
    pending: &Pending,
    deadline: Instant,
) -> Event {
    let mut recv = udp.map(|s| Box::pin(s.recv(Vec::with_capacity(UDP_SIZE))));
    let mut sleep = std::pin::pin!(monoio::time::sleep(
        deadline.saturating_duration_since(Instant::now())
    ));
    std::future::poll_fn(|cx| {
        if pending.waiters.get() == 0 {
            return Poll::Ready(Event::Abandoned);
        }
        if let Some(recv) = recv.as_mut()
            && let Poll::Ready((read, buf)) = recv.as_mut().poll(cx)
        {
            return Poll::Ready(Event::Packet(read.map(|n| {
                let mut buf = buf;
                buf.truncate(n);
                buf
            })));
        }
        if sleep.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Event::Resend);
        }
        *pending.driver.borrow_mut() = Some(cx.waker().clone());
        Poll::Pending
    })
    .await
}

/// `fut`, unless the last request stops waiting first (`None`).
async fn abandonable<F: Future>(fut: F, pending: &Pending) -> Option<F::Output> {
    let mut fut = std::pin::pin!(fut);
    std::future::poll_fn(|cx| {
        if pending.waiters.get() == 0 {
            return Poll::Ready(None);
        }
        if let Poll::Ready(out) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(out));
        }
        *pending.driver.borrow_mut() = Some(cx.waker().clone());
        Poll::Pending
    })
    .await
}

/// One query over a TCP connection of its own: two length bytes before
/// the message, both ways.
async fn tcp_exchange(addr: SocketAddr, packet: Vec<u8>) -> std::io::Result<Vec<u8>> {
    use monoio::io::{AsyncReadRent, AsyncWriteRentExt};
    let mut stream = monoio::net::TcpStream::connect(addr).await?;
    let mut message = Vec::with_capacity(2 + packet.len());
    message.extend_from_slice(&(packet.len() as u16).to_be_bytes());
    message.extend_from_slice(&packet);
    let (written, _) = stream.write_all(message).await;
    written?;
    let mut response = Vec::new();
    let mut buf = vec![0u8; UDP_SIZE];
    loop {
        if let [hi, lo, rest @ ..] = response.as_slice() {
            let len = usize::from(u16::from_be_bytes([*hi, *lo]));
            if rest.len() >= len {
                response.drain(..2);
                response.truncate(len);
                return Ok(response);
            }
        }
        let (read, b) = stream.read(buf).await;
        buf = b;
        match read? {
            0 => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "connection closed",
                ));
            }
            n => response.extend_from_slice(&buf[..n]),
        }
    }
}

/// `\3www\7example\3com\0` for `www.example.com`; `None` for an empty
/// name, an empty label, a label over 63 bytes or a name over 255.
pub(crate) fn encode_name(name: &[u8]) -> Option<Vec<u8>> {
    if name.is_empty() || name.len() > 255 {
        return None;
    }
    let mut out = Vec::with_capacity(name.len() + 2);
    for label in name.split(|&b| b == b'.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        out.push(label.len() as u8);
        out.extend_from_slice(label);
    }
    out.push(0);
    Some(out)
}

/// A response's header and question.
#[derive(Debug)]
pub(crate) struct Head {
    pub id: u16,
    pub code: u16,
    pub trunc: bool,
    pub answers: u16,
    /// The question's name, in lower case, without the trailing dot.
    pub qname: Box<[u8]>,
    pub qtype: u16,
    /// Where the answer section starts.
    pub at: usize,
}

/// Check a response the way ngx_resolver_process_response does; `Err` is
/// the line to log, and the response is ignored.
pub(crate) fn parse_head(buf: &[u8], tcp: bool) -> Result<Head, String> {
    const SHORT: &str = "short DNS response";
    if buf.len() < 12 {
        return Err(SHORT.into());
    }
    let word = |i: usize| u16::from_be_bytes([buf[i], buf[i + 1]]);
    let (id, flags, questions, answers) = (word(0), word(2), word(4), word(6));
    let trunc = flags & 0x0200 != 0;
    // A response (QR) to a standard query, no reserved bits.
    if flags & 0xf870 != 0x8000 || (trunc && tcp) {
        return Err(format!(
            "invalid {} DNS response {id} fl:{flags:04X}",
            if tcp { "TCP" } else { "UDP" }
        ));
    }
    let code = flags & 0xf;
    if code == FORMERR || code > REFUSED {
        return Err(format!("DNS error ({}), query id:{id}", Failure(code)));
    }
    if questions != 1 {
        return Err("invalid number of questions in DNS response".into());
    }
    let mut i = 12;
    loop {
        let Some(&len) = buf.get(i) else {
            return Err(SHORT.into());
        };
        if len & 0xc0 != 0 {
            return Err("unexpected compression pointer in DNS response".into());
        }
        if len == 0 {
            break;
        }
        i += 1 + usize::from(len);
    }
    if i == 12 {
        return Err("zero-length domain name in DNS response".into());
    }
    i += 1;
    if i + 4 + usize::from(answers) * 12 > buf.len() {
        return Err(SHORT.into());
    }
    let qtype = word(i);
    let qclass = word(i + 2);
    if qclass != 1 {
        return Err(format!("unknown query class {qclass} in DNS response"));
    }
    if qtype != TYPE_A && qtype != TYPE_AAAA {
        return Err(format!("unknown query type {qtype} in DNS response"));
    }
    let qname = copy_name(buf, 12)?;
    Ok(Head {
        id,
        code,
        trunc,
        answers,
        qname,
        qtype,
        at: i + 4,
    })
}

/// The records of an answer (ngx_resolver_process_a).
#[derive(Debug, Default)]
pub(crate) struct Answers {
    pub addrs: Vec<IpAddr>,
    /// Where the last CNAME's target starts.
    pub cname: Option<usize>,
    /// The smallest TTL of all the records.
    pub ttl: u32,
    /// Record types nginx logs as unexpected, and skips.
    pub unexpected: Vec<u16>,
}

/// Walk the answer section. Addresses of the type asked are taken
/// whatever name they are for, as nginx does: the question was checked,
/// and the cache keeps them only under that name.
pub(crate) fn parse_answers(buf: &[u8], head: &Head) -> Result<Answers, String> {
    const SHORT: &str = "short DNS response";
    let n = buf.len();
    let mut out = Answers {
        ttl: u32::MAX,
        ..Answers::default()
    };
    let mut i = head.at;
    for _ in 0..head.answers {
        // The owner name: labels, up to the root or a pointer.
        let start = i;
        loop {
            let Some(&len) = buf.get(i) else {
                return Err(SHORT.into());
            };
            if len & 0xc0 != 0 {
                i += 2;
                break;
            }
            if len == 0 {
                i += 1;
                if i - start < 2 {
                    return Err("invalid name in DNS response".into());
                }
                break;
            }
            i += 1 + usize::from(len);
        }
        if i + 10 >= n {
            return Err(SHORT.into());
        }
        let word = |at: usize| u16::from_be_bytes([buf[at], buf[at + 1]]);
        let rtype = word(i);
        let class = word(i + 2);
        let ttl = u32::from_be_bytes([buf[i + 4], buf[i + 5], buf[i + 6], buf[i + 7]]);
        let len = usize::from(word(i + 8));
        if class != 1 {
            return Err(format!("unexpected RR class {class} in DNS response"));
        }
        // A negative TTL counts as 0.
        out.ttl = out.ttl.min(if ttl > i32::MAX as u32 { 0 } else { ttl });
        i += 10;
        match rtype {
            TYPE_A | TYPE_AAAA => {
                let (size, name) = if rtype == TYPE_A {
                    (4, "A")
                } else {
                    (16, "AAAA")
                };
                if rtype != head.qtype {
                    return Err(format!("unexpected {name} record in DNS response"));
                }
                if len != size {
                    return Err(format!("invalid {name} record in DNS response"));
                }
                let Some(data) = buf.get(i..i + size) else {
                    return Err(SHORT.into());
                };
                out.addrs.push(if size == 4 {
                    IpAddr::from(<[u8; 4]>::try_from(data).expect("4 bytes"))
                } else {
                    IpAddr::from(<[u8; 16]>::try_from(data).expect("16 bytes"))
                });
            }
            TYPE_CNAME => out.cname = Some(i),
            TYPE_DNAME => {}
            other => out.unexpected.push(other),
        }
        i += len;
    }
    Ok(out)
}

/// The name at `at`, following compression pointers (ngx_resolver_copy):
/// in lower case, labels joined with dots, no trailing dot.
pub(crate) fn copy_name(buf: &[u8], at: usize) -> Result<Box<[u8]>, String> {
    let mut out = Vec::new();
    let mut p = at;
    // Pointers can loop: 128 steps are enough for a 255-byte name.
    for _ in 0..128 {
        let Some(&len) = buf.get(p) else {
            return Err("name is out of DNS response".into());
        };
        p += 1;
        if len == 0 {
            out.pop();
            return Ok(out.into_boxed_slice());
        }
        if len & 0xc0 != 0 {
            if len & 0xc0 != 0xc0 {
                return Err("invalid label type in DNS response".into());
            }
            let Some(&lo) = buf.get(p) else {
                return Err("name is out of DNS response".into());
            };
            p = (usize::from(len & 0x3f) << 8) | usize::from(lo);
        } else {
            let label = buf
                .get(p..p + usize::from(len))
                .ok_or("name is out of DNS response")?;
            out.extend(label.iter().map(u8::to_ascii_lowercase));
            out.push(b'.');
            p += usize::from(len);
        }
        if p >= buf.len() {
            return Err("name is out of DNS response".into());
        }
    }
    Err("compression pointers loop in DNS response".into())
}

fn random_u16() -> u16 {
    let mut bytes = [0u8; 2];
    if aws_lc_rs::rand::fill(&mut bytes).is_err() {
        // SAFETY: getrandom fills at most the buffer's length.
        unsafe { libc::getrandom(bytes.as_mut_ptr().cast(), 2, 0) };
    }
    u16::from_be_bytes(bytes)
}

/// A line about the resolver, to the worker's error log (nginx's
/// `r->log`, the main log).
fn log(message: &str) {
    let logs = crate::worker::worker_http().map_or(&[][..], |h| h.error_logs);
    crate::worker::write_worker_log(logs, ErrorLogLevel::Error, message);
}

/// A line about talking to one server (ngx_resolver_log_error).
fn log_server(addr: SocketAddr, message: &str) {
    log(&format!("{message} while resolving, resolver: {addr}"));
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A response to `id` for `name`/`qtype`, with `rcode`, the header
    /// flags `extra` and the answer records `rrs` (built by `rr`).
    fn response(
        id: u16,
        extra: u16,
        rcode: u16,
        name: &str,
        qtype: u16,
        rrs: &[Vec<u8>],
    ) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&(0x8180 | extra | rcode).to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        p.extend_from_slice(&(rrs.len() as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0, 0, 0]);
        p.extend_from_slice(&encode_name(name.as_bytes()).unwrap());
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&1u16.to_be_bytes());
        for rr in rrs {
            p.extend_from_slice(rr);
        }
        p
    }

    /// A record owned by the question's name (a pointer to offset 12).
    fn rr(rtype: u16, ttl: u32, data: &[u8]) -> Vec<u8> {
        let mut r = vec![0xc0, 12];
        r.extend_from_slice(&rtype.to_be_bytes());
        r.extend_from_slice(&1u16.to_be_bytes());
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&(data.len() as u16).to_be_bytes());
        r.extend_from_slice(data);
        r
    }

    fn resolver(ipv6: bool) -> Resolver {
        Resolver {
            servers: vec!["127.0.0.1:53".parse().unwrap()].into_boxed_slice(),
            valid: None,
            ipv4: true,
            ipv6,
        }
    }

    /// Queries for `name` with ids 1 (A) and 2 (AAAA).
    fn queries(name: &str, ipv6: bool) -> Queries {
        let mut q = Queries::new(&resolver(ipv6), name.as_bytes()).unwrap();
        for (i, query) in q.queries.iter_mut().enumerate() {
            query.id = i as u16 + 1;
        }
        q
    }

    fn addrs(step: Step) -> Vec<IpAddr> {
        match step {
            Step::Done(Ok((Answer::Addrs(a), _))) => a.to_vec(),
            Step::Done(Ok((Answer::Cname(c), _))) => panic!("cname {c:?}"),
            Step::Done(Err(code)) => panic!("error {code}"),
            Step::Wait => panic!("wait"),
            Step::Tcp(i) => panic!("tcp {i}"),
        }
    }

    #[test]
    fn names() {
        assert_eq!(
            encode_name(b"www.example.com").unwrap(),
            b"\x03www\x07example\x03com\x00"
        );
        assert_eq!(encode_name(b""), None);
        assert_eq!(encode_name(b"a..b"), None);
        assert_eq!(encode_name(&[b'a'; 64]), None);
        assert!(encode_name(&[b'a'; 63]).is_some());
        assert_eq!(&*normalize(b"Example.NET."), b"example.net");
    }

    #[test]
    fn heads() {
        let ok = response(7, 0, 0, "A.Example", TYPE_A, &[]);
        let head = parse_head(&ok, false).unwrap();
        assert_eq!((head.id, head.code, head.answers), (7, 0, 0));
        assert_eq!(&*head.qname, b"a.example");
        // Not a response; a reserved bit; truncated over TCP.
        let mut query = ok.clone();
        query[2] &= 0x7f;
        assert!(parse_head(&query, false).is_err());
        assert!(parse_head(&response(7, 0x0040, 0, "a", TYPE_A, &[]), false).is_err());
        let tc = response(7, 0x0200, 0, "a", TYPE_A, &[]);
        assert!(parse_head(&tc, false).unwrap().trunc);
        assert!(parse_head(&tc, true).is_err());
        // FORMERR and unknown rcodes are ignored; SERVFAIL is an answer.
        assert!(parse_head(&response(7, 0, FORMERR, "a", TYPE_A, &[]), false).is_err());
        assert!(parse_head(&response(7, 0, 9, "a", TYPE_A, &[]), false).is_err());
        assert_eq!(
            parse_head(&response(7, 0, SERVFAIL, "a", TYPE_A, &[]), false)
                .unwrap()
                .code,
            SERVFAIL
        );
        // Other query types and classes, and short packets.
        assert!(parse_head(&response(7, 0, 0, "a", 16, &[]), false).is_err());
        for n in 0..ok.len() {
            assert!(parse_head(&ok[..n], false).is_err(), "{n}");
        }
        // Answers counted that can't fit.
        let mut lying = ok.clone();
        lying[7] = 5;
        assert!(parse_head(&lying, false).is_err());
    }

    #[test]
    fn answers() {
        let cname_target = b"\x05alias\xc0\x0e";
        let packet = response(
            1,
            0,
            0,
            "x.example",
            TYPE_A,
            &[
                rr(TYPE_CNAME, 30, cname_target),
                rr(TYPE_A, 300, &[10, 0, 0, 1]),
                rr(TYPE_DNAME, 600, b"\x00"),
                rr(99, 900, b"zz"),
                rr(TYPE_A, 60, &[10, 0, 0, 2]),
            ],
        );
        let head = parse_head(&packet, false).unwrap();
        let a = parse_answers(&packet, &head).unwrap();
        assert_eq!(
            a.addrs,
            [
                "10.0.0.1".parse::<IpAddr>().unwrap(),
                "10.0.0.2".parse().unwrap()
            ]
        );
        assert_eq!(a.ttl, 30);
        assert_eq!(a.unexpected, [99]);
        assert_eq!(
            &*copy_name(&packet, a.cname.unwrap()).unwrap(),
            b"alias.example"
        );
        // Every cut of it is refused, never read past.
        for n in head.at..packet.len() {
            let _ = parse_answers(&packet[..n], &head);
        }
        // An AAAA in an A answer, a short A, another class.
        for bad in [rr(TYPE_AAAA, 1, &[0; 16]), rr(TYPE_A, 1, &[1, 2, 3]), {
            let mut r = rr(TYPE_A, 1, &[1, 2, 3, 4]);
            r[5] = 3;
            r
        }] {
            let p = response(1, 0, 0, "x", TYPE_A, &[bad]);
            assert!(parse_answers(&p, &parse_head(&p, false).unwrap()).is_err());
        }
        // A TTL with the sign bit set counts as 0.
        let p = response(
            1,
            0,
            0,
            "x",
            TYPE_A,
            &[rr(TYPE_A, 0x8000_0000, &[1, 2, 3, 4])],
        );
        assert_eq!(
            parse_answers(&p, &parse_head(&p, false).unwrap())
                .unwrap()
                .ttl,
            0
        );
    }

    #[test]
    fn compressed_names() {
        // A pointer to itself, a pointer past the end, a reserved label type.
        assert!(copy_name(b"\xc0\x00", 0).is_err());
        assert!(copy_name(b"\x01a\xc0\x09", 0).is_err());
        assert!(copy_name(b"\x41a\x00", 0).is_err());
        assert!(copy_name(b"\x05ab", 0).is_err());
        assert_eq!(&*copy_name(b"\x01A\x01b\x00", 0).unwrap(), b"a.b");
        assert_eq!(&*copy_name(b"\x00", 0).unwrap(), b"");
        // Two names pointing at each other loop.
        assert!(copy_name(b"\x01a\xc0\x04\x01b\xc0\x00", 0).is_err());
    }

    #[test]
    fn a_and_aaaa_together() {
        let six: IpAddr = "fe80::1".parse().unwrap();
        let four: IpAddr = "127.0.0.2".parse().unwrap();
        let a = || response(1, 0, 0, "n", TYPE_A, &[rr(TYPE_A, 10, &[127, 0, 0, 2])]);
        let aaaa = || response(2, 0, 0, "n", TYPE_AAAA, &[rr(TYPE_AAAA, 5, &six_bytes())]);
        let empty = |id, qtype| response(id, 0, 0, "n", qtype, &[]);
        fn six_bytes() -> [u8; 16] {
            "fe80::1".parse::<Ipv6Addr>().unwrap().octets()
        }

        // Both answer: A first, whichever came first.
        let mut q = queries("n", true);
        assert!(matches!(q.process(&aaaa(), false), Step::Wait));
        assert_eq!(addrs(q.process(&a(), false)), [four, six]);
        assert_eq!(q.ttl, 5);

        // One empty: the other's addresses.
        let mut q = queries("n", true);
        assert!(matches!(q.process(&a(), false), Step::Wait));
        assert_eq!(addrs(q.process(&empty(2, TYPE_AAAA), false)), [four]);

        // Both empty: Host not found.
        let mut q = queries("n", true);
        q.process(&empty(1, TYPE_A), false);
        assert!(matches!(
            q.process(&empty(2, TYPE_AAAA), false),
            Step::Done(Err(NXDOMAIN))
        ));

        // An error in either fails the name.
        let mut q = queries("n", true);
        q.process(&response(1, 0, SERVFAIL, "n", TYPE_A, &[]), false);
        assert!(matches!(
            q.process(&aaaa(), false),
            Step::Done(Err(SERVFAIL))
        ));
        let mut q = queries("n", true);
        q.process(&a(), false);
        assert!(matches!(
            q.process(&response(2, 0, REFUSED, "n", TYPE_AAAA, &[]), false),
            Step::Done(Err(REFUSED))
        ));

        // A CNAME counts when it comes last, and nothing has addresses.
        let cname = |id, qtype, target: &[u8]| {
            let mut data = vec![target.len() as u8];
            data.extend_from_slice(target);
            data.push(0);
            response(id, 0, 0, "n", qtype, &[rr(TYPE_CNAME, 7, &data)])
        };
        let mut q = queries("n", true);
        q.process(&cname(1, TYPE_A, b"four"), false);
        match q.process(&cname(2, TYPE_AAAA, b"six"), false) {
            Step::Done(Ok((Answer::Cname(t), _))) => assert_eq!(&*t, b"six"),
            _ => panic!("no cname"),
        }
        let mut q = queries("n", true);
        q.process(&cname(1, TYPE_A, b"four"), false);
        assert_eq!(addrs(q.process(&aaaa(), false)), [six]);
        // nginx's `c-z`: a CNAME, then an empty answer.
        let mut q = queries("n", true);
        q.process(&cname(1, TYPE_A, b"four"), false);
        assert!(matches!(
            q.process(&empty(2, TYPE_AAAA), false),
            Step::Done(Err(NXDOMAIN))
        ));
    }

    #[test]
    fn answers_that_dont_count() {
        let a = |id, name: &str| response(id, 0, 0, name, TYPE_A, &[rr(TYPE_A, 10, &[1, 2, 3, 4])]);
        let mut q = queries("n.example", false);
        // Another name, a wrong id, a type not asked: ignored.
        assert!(matches!(q.process(&a(1, "m.example"), false), Step::Wait));
        assert!(matches!(q.process(&a(9, "n.example"), false), Step::Wait));
        let aaaa = response(1, 0, 0, "n.example", TYPE_AAAA, &[]);
        assert!(matches!(q.process(&aaaa, false), Step::Wait));
        // The name matches without case.
        assert_eq!(
            addrs(q.process(&a(1, "N.Example"), false)),
            ["1.2.3.4".parse::<IpAddr>().unwrap()]
        );

        // Truncated: over TCP, where a truncated answer is ignored.
        let mut q = queries("n", false);
        let tc = response(1, 0x0200, 0, "n", TYPE_A, &[]);
        assert!(matches!(q.process(&tc, false), Step::Tcp(0)));
        assert!(q.queries[0].tcp);
        assert!(matches!(q.process(&tc, false), Step::Wait));
        assert!(matches!(q.process(&a(1, "n"), true), Step::Done(Ok(_))));
    }

    #[test]
    fn rotation_keeps_every_address() {
        let list: Vec<IpAddr> = ["1.1.1.1", "2.2.2.2", "3.3.3.3", "::1", "::2"]
            .iter()
            .map(|a| a.parse().unwrap())
            .collect();
        for _ in 0..50 {
            let mut out = rotate(&list);
            out.sort();
            let mut sorted = list.clone();
            sorted.sort();
            assert_eq!(out, sorted);
        }
    }
}
