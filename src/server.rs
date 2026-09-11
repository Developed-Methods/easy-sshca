//! The gRPC server: rate limiting, request routing to the single database
//! worker thread, and listener lifecycle.

use crate::{
    auth,
    config::ServerConfig,
    error::{Error, Result},
    protocol::{self, Command, Operation, Reply},
    storage::{Database, DatabaseLock},
};
use anyhow::Context;
use std::{
    collections::HashMap,
    net::IpAddr,
    ops::Deref,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status, metadata::MetadataMap};
use zeroize::{Zeroize, Zeroizing};

type RpcResult = std::result::Result<Response<Reply>, Status>;

const MAX_REPLY_BYTES: usize = 1_048_576;
const CONCURRENCY_PER_CONNECTION: usize = 64;
const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);

const RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_RATE_BUCKETS: usize = 10_000;
/// Requests per window from one source address, across all operations.
const SOURCE_LIMIT: u32 = 300;
/// Requests per window with one API key, across all operations.
const KEY_LIMIT: u32 = 120;

fn source_operation_limit(op: Operation) -> u32 {
    use Operation::*;
    match op {
        Unlock => 5,
        ConfirmTotpEnrollment | RotateToken | BeginTotpEnrollment => 10,
        _ => 120,
    }
}

fn key_operation_limit(op: Operation) -> u32 {
    use Operation::*;
    match op {
        SignCertificate | ConfirmTotpEnrollment | RotateToken => 10,
        _ => 120,
    }
}

#[derive(Clone, Copy, Default)]
pub struct Outcome {
    pub count: u64,
    pub micros: u64,
}

#[derive(Default)]
pub struct Metrics {
    pub requests: AtomicU64,
    pub failures: AtomicU64,
    pub issued: AtomicU64,
    pub rate_limited: AtomicU64,
    pub micros: AtomicU64,
    outcomes: Mutex<HashMap<(Operation, &'static str), Outcome>>,
}

impl Metrics {
    fn record(&self, op: Operation, reason: &'static str, latency_micros: u64) {
        self.micros.fetch_add(latency_micros, Ordering::Relaxed);
        if let Ok(mut outcomes) = self.outcomes.lock() {
            let outcome = outcomes.entry((op, reason)).or_default();
            outcome.count += 1;
            outcome.micros += latency_micros;
        }
    }

    /// Per-operation outcomes, sorted for stable output.
    pub fn outcomes(&self) -> Vec<(Operation, &'static str, Outcome)> {
        let mut outcomes: Vec<_> = self
            .outcomes
            .lock()
            .map(|outcomes| {
                outcomes
                    .iter()
                    .map(|((op, reason), outcome)| (*op, *reason, *outcome))
                    .collect()
            })
            .unwrap_or_default();
        outcomes.sort_by_key(|(op, reason, _)| (op.name(), *reason));
        outcomes
    }
}

/// Fixed-window request counters keyed by source address or API key.
#[derive(Default)]
struct RateLimiter {
    windows: HashMap<String, Window>,
}

struct Window {
    start: Instant,
    count: u32,
}

impl RateLimiter {
    /// Count one request in `bucket`; `false` means the limit is exhausted.
    fn admit(&mut self, bucket: String, max: u32) -> bool {
        if self.windows.len() >= MAX_RATE_BUCKETS {
            self.windows
                .retain(|_, window| window.start.elapsed() < RATE_WINDOW);
        }
        if self.windows.len() >= MAX_RATE_BUCKETS && !self.windows.contains_key(&bucket) {
            // Evict the oldest window so a new source can never be starved.
            let oldest = self
                .windows
                .iter()
                .min_by_key(|(_, window)| window.start)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                self.windows.remove(&oldest);
            }
        }
        let window = self.windows.entry(bucket).or_insert(Window {
            start: Instant::now(),
            count: 0,
        });
        if window.start.elapsed() >= RATE_WINDOW {
            window.start = Instant::now();
            window.count = 0;
        }
        if window.count >= max {
            return false;
        }
        window.count += 1;
        true
    }
}

/// Group clients by IPv4 address or IPv6 /64 prefix.
fn source_bucket(source: Option<IpAddr>) -> String {
    match source {
        None => "local".into(),
        Some(IpAddr::V4(ip)) => ip.to_string(),
        Some(IpAddr::V6(ip)) => match ip.to_ipv4_mapped() {
            Some(ip) => ip.to_string(),
            None => {
                let [a, b, c, d, ..] = ip.segments();
                format!("{a:x}:{b:x}:{c:x}:{d:x}::/64")
            }
        },
    }
}

fn bearer_token(metadata: &MetadataMap) -> String {
    metadata
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .unwrap_or_default()
        .to_owned()
}

/// A command whose secret fields are wiped when it is dropped.
struct SecretCommand(Command);

impl Deref for SecretCommand {
    type Target = Command;

    fn deref(&self) -> &Command {
        &self.0
    }
}

impl Drop for SecretCommand {
    fn drop(&mut self) {
        self.0.secret.zeroize();
        self.0.totp.zeroize();
        self.0.replacement_key.zeroize();
    }
}

struct Job {
    op: Operation,
    credential: Zeroizing<String>,
    command: SecretCommand,
    response: oneshot::Sender<Result<Reply>>,
    deadline: Instant,
    unlock_guard: Option<FlagGuard>,
}

/// Clears a flag when dropped.
struct FlagGuard(Arc<AtomicBool>);

impl Drop for FlagGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// The single thread that owns the SQLCipher connection.
struct Worker {
    path: PathBuf,
    lock: DatabaseLock,
    database: Option<Database>,
    ready: Arc<AtomicBool>,
    metrics: Arc<Metrics>,
}

impl Worker {
    fn run(mut self, mut jobs: mpsc::Receiver<Job>) {
        let _ready_guard = FlagGuard(self.ready.clone());
        while let Some(job) = jobs.blocking_recv() {
            if job.response.is_closed() || Instant::now() > job.deadline {
                continue;
            }
            let result = self.handle(&job);
            if let Some(database) = &self.database {
                self.metrics
                    .issued
                    .store(database.issuance_count, Ordering::Relaxed);
            }
            let Job {
                response,
                unlock_guard,
                ..
            } = job;
            // Release the unlock slot before the client learns the outcome.
            drop(unlock_guard);
            let _ = response.send(result);
        }
        tracing::info!(state = "STOPPED", "Database worker stopped");
    }

    fn handle(&mut self, job: &Job) -> Result<Reply> {
        if job.op == Operation::Unlock {
            return self.unlock(&job.command, job.deadline);
        }
        let database = self.database.as_mut().ok_or_else(Error::locked)?;
        database.execute_until(job.deadline, job.op, &job.credential, &job.command)
    }

    fn unlock(&mut self, command: &Command, deadline: Instant) -> Result<Reply> {
        if self.database.is_some() {
            return Err(already_ready());
        }
        let database =
            Database::open_with_lock(&self.path, &command.secret, self.lock.clone(), deadline)?;
        self.metrics
            .issued
            .store(database.issuance_count, Ordering::Relaxed);
        self.database = Some(database);
        self.ready.store(true, Ordering::Release);
        tracing::info!(
            state = "READY",
            "Database unlocked; server ready for administration and signing"
        );
        Ok(Reply {
            request_id: command.request_id.clone(),
            state: "READY".into(),
            ..Default::default()
        })
    }
}

fn already_ready() -> Error {
    Error::failed_precondition("ALREADY_READY", "server is already ready")
}

#[derive(Clone)]
pub struct State {
    server: String,
    sender: mpsc::Sender<Job>,
    ready: Arc<AtomicBool>,
    unlocking: Arc<AtomicBool>,
    limiter: Arc<Mutex<RateLimiter>>,
    pub metrics: Arc<Metrics>,
    timeout: Duration,
}

impl State {
    /// Lock process memory, take the database lock and start the worker thread.
    pub fn new(path: PathBuf, queue: usize, timeout: Duration) -> anyhow::Result<Self> {
        crate::memory::protect()?;
        if queue == 0 || timeout.is_zero() {
            anyhow::bail!("queue capacity and timeout must be positive");
        }
        let metadata = std::fs::metadata(&path).with_context(|| {
            format!(
                "cannot access database {}. Check the database path in your server configuration. For a new installation, run easy-sshca server init --name NAME --folder NEW_FOLDER",
                path.display()
            )
        })?;
        if !metadata.is_file() {
            anyhow::bail!("database {} must be a regular file", path.display());
        }
        let lock = crate::storage::lock(&path)?;
        tracing::info!(
            queue_capacity = queue,
            timeout_seconds = timeout.as_secs(),
            "Database worker starting"
        );
        let (sender, receiver) = mpsc::channel(queue);
        let ready = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(Metrics::default());
        let worker = Worker {
            path,
            lock,
            database: None,
            ready: ready.clone(),
            metrics: metrics.clone(),
        };
        std::thread::Builder::new()
            .name("sqlcipher".into())
            .spawn(move || worker.run(receiver))
            .context("cannot start database worker thread")?;
        Ok(Self {
            server: String::new(),
            sender,
            ready,
            unlocking: Arc::new(AtomicBool::new(false)),
            limiter: Arc::default(),
            metrics,
            timeout,
        })
    }

    pub fn is_ready(&self) -> bool {
        self.ready.load(Ordering::Acquire)
    }

    pub fn queue_depth(&self) -> usize {
        self.sender.max_capacity() - self.sender.capacity()
    }

    fn rate(&self, bucket: String, max: u32) -> Result<()> {
        let admitted = self
            .limiter
            .lock()
            .map_err(|_| Error::internal())?
            .admit(bucket, max);
        if !admitted {
            self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(Error::exhausted("RATE_LIMIT", "retry after one minute"));
        }
        Ok(())
    }

    fn begin_unlock(&self) -> Result<FlagGuard> {
        if self.is_ready() {
            return Err(already_ready());
        }
        self.unlocking
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                Error::new(
                    tonic::Code::Aborted,
                    "UNLOCK_IN_PROGRESS",
                    "unlock already in progress",
                )
            })?;
        Ok(FlagGuard(self.unlocking.clone()))
    }

    /// Apply rate limits, then run `op` on the database worker.
    pub async fn call(
        &self,
        op: Operation,
        credential: String,
        command: Command,
        source: Option<IpAddr>,
    ) -> Result<Reply> {
        auth::validate_request_id(&command.request_id)?;
        if op == Operation::GetStatus {
            let state = if self.is_ready() { "READY" } else { "LOCKED" };
            return Ok(Reply {
                request_id: command.request_id,
                state: state.into(),
                ..Default::default()
            });
        }
        if op != Operation::Unlock && !self.is_ready() {
            return Err(Error::locked());
        }
        let source = source_bucket(source);
        self.rate(format!("ip:{source}"), SOURCE_LIMIT)?;
        self.rate(format!("ip:{source}:{op}"), source_operation_limit(op))?;
        if !op.is_anonymous()
            && let Ok(key) = auth::parse_key(&credential)
        {
            self.rate(format!("key:{}", key.id), KEY_LIMIT)?;
            self.rate(format!("key:{}:{op}", key.id), key_operation_limit(op))?;
        }
        let unlock_guard = if op == Operation::Unlock {
            Some(self.begin_unlock()?)
        } else {
            None
        };
        let (response, receiver) = oneshot::channel();
        self.sender
            .try_send(Job {
                op,
                credential: Zeroizing::new(credential),
                command: SecretCommand(command),
                response,
                deadline: Instant::now() + self.timeout,
                unlock_guard,
            })
            .map_err(|_| Error::exhausted("QUEUE_FULL", "database queue is full"))?;
        match tokio::time::timeout(self.timeout, receiver).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(Error::unavailable(
                "WORKER_STOPPED",
                "database worker unavailable",
            )),
            Err(_) => Err(Error::timeout(
                "operation timed out; retry with the same request UUID",
            )),
        }
    }

    async fn rpc(&self, op: Operation, request: Request<Command>) -> RpcResult {
        let started = Instant::now();
        let source = request.remote_addr().map(|address| address.ip());
        let credential = bearer_token(request.metadata());
        let caller = auth::parse_key(&credential).ok();
        let mut command = request.into_inner();
        if command.request_id.is_empty() && op.is_read() {
            command.request_id = auth::new_id();
        }
        // Only a well-formed client id is echoed into logs and metadata.
        let request_id = if auth::validate_request_id(&command.request_id).is_ok() {
            command.request_id.clone()
        } else {
            auth::new_id()
        };
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);
        let result = self.call(op, credential, command, source).await;
        let reason = match &result {
            Ok(_) => "OK",
            Err(error) => error.reason,
        };
        let latency = started.elapsed().as_micros() as u64;
        self.metrics.record(op, reason, latency);
        // tracing needs a constant level per call site, hence the macro.
        macro_rules! log_completed {
            ($level:expr) => {
                tracing::event!(
                    $level,
                    request_id = %request_id,
                    operation = op.name(),
                    actor_type = caller.as_ref().map_or("public", |key| key.kind.tag()),
                    actor_id = caller.as_ref().map_or("", |key| key.id.as_str()),
                    result = reason,
                    latency_us = latency,
                    "RPC completed"
                )
            };
        }
        match &result {
            Ok(_) => log_completed!(tracing::Level::INFO),
            Err(error)
                if matches!(error.code, tonic::Code::Internal | tonic::Code::Unavailable) =>
            {
                log_completed!(tracing::Level::ERROR)
            }
            Err(_) => log_completed!(tracing::Level::WARN),
        }
        match result {
            Ok(mut reply) => {
                if op == Operation::CreateAccessToken {
                    reply.server = self.server.clone();
                }
                let mut response = Response::new(reply);
                response
                    .metadata_mut()
                    .insert("x-request-id", request_id.parse().expect("UUID metadata"));
                Ok(response)
            }
            Err(error) => {
                self.metrics.failures.fetch_add(1, Ordering::Relaxed);
                Err(error.status(&request_id))
            }
        }
    }
}

macro_rules! implement_service {
    ($service:path { $($method:ident => $op:ident),* $(,)? }) => {
        #[tonic::async_trait]
        impl $service for State {
            $(
                async fn $method(&self, request: Request<Command>) -> RpcResult {
                    self.rpc(Operation::$op, request).await
                }
            )*
        }
    };
}

implement_service!(protocol::bootstrap_service_server::BootstrapService {
    get_status => GetStatus,
    unlock => Unlock,
});

implement_service!(protocol::admin_service_server::AdminService {
    create_zone => CreateZone,
    import_zone => ImportZone,
    list_zones => ListZones,
    update_zone => UpdateZone,
    remove_zone => RemoveZone,
    create_user => CreateUser,
    list_users => ListUsers,
    update_user => UpdateUser,
    remove_user => RemoveUser,
    grant_zone => GrantZone,
    list_user_zones => ListUserZones,
    revoke_zone => RevokeZone,
    create_access_token => CreateAccessToken,
    list_access_tokens => ListAccessTokens,
    update_access_token => UpdateAccessToken,
    remove_access_token => RemoveAccessToken,
    clear_totp => ClearTotp,
    rotate_admin_key => RotateAdminKey,
});

implement_service!(protocol::user_service_server::UserService {
    begin_totp_enrollment => BeginTotpEnrollment,
    confirm_totp_enrollment => ConfirmTotpEnrollment,
    rotate_token => RotateToken,
});

implement_service!(protocol::signing_service_server::SigningService {
    sign_certificate => SignCertificate,
});

implement_service!(protocol::ca_service_server::CaService {
    get_public_key => GetPublicKey,
});

/// Serve until SIGINT or SIGTERM, or until a listener fails.
pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    if config
        .metrics_listen
        .is_some_and(|address| !address.ip().is_loopback())
    {
        anyhow::bail!("metrics_listen must use a loopback address");
    }
    let metrics_listener = match config.metrics_listen {
        Some(address) => Some(
            tokio::net::TcpListener::bind(address)
                .await
                .context("cannot bind metrics listener")?,
        ),
        None => None,
    };
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut state = State::new(
        config.database.clone(),
        config.limits.database_queue,
        Duration::from_secs(auth::parse_duration(&config.limits.rpc_timeout)?),
    )?;
    state.server = config.server.clone();

    let certificate = config.certificate_pem()?;
    let private_key = config.private_key_pem()?;
    let https_tls = axum_server::tls_rustls::RustlsConfig::from_pem(
        certificate.clone(),
        private_key.as_bytes().to_vec(),
    )
    .await
    .with_context(|| {
        let certificate_source = source_name(&config.tls.certificate, "tls.certificate_pem");
        let private_key_source = source_name(&config.tls.private_key, "tls.private_key_pem");
        format!(
            "cannot configure TLS with certificate {certificate_source} and private key {private_key_source}. Supply a matching PEM certificate and private key"
        )
    })?;
    tracing::info!("TLS certificate and private key loaded");
    let rpc_tls = tonic::transport::ServerTlsConfig::new().identity(
        tonic::transport::Identity::from_pem(certificate, private_key.as_bytes()),
    );

    let rpc_listener = tokio::net::TcpListener::bind(config.rpc_listen)
        .await
        .with_context(|| listener_failure("RPC", config.rpc_listen, "rpc_listen"))?;
    let https_listener = std::net::TcpListener::bind(config.https_listen)
        .with_context(|| listener_failure("HTTPS", config.https_listen, "https_listen"))?;
    https_listener
        .set_nonblocking(true)
        .context("cannot configure HTTPS listener")?;
    tracing::info!(listener = "RPC", address = %rpc_listener.local_addr()?, "Listener bound");
    tracing::info!(listener = "HTTPS", address = %https_listener.local_addr()?, "Listener bound");
    tracing::info!(
        state = "LOCKED",
        "Server waiting for unlock; use easy-sshca server unlock"
    );

    let http_handle = axum_server::Handle::new();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::watch::channel(false);
    let terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("cannot register SIGTERM handler")?;
    let signal = tokio::spawn(await_shutdown_signal(
        terminate,
        http_handle.clone(),
        shutdown_tx,
    ));

    let http = axum_server::from_tcp_rustls(https_listener, https_tls)
        .context("cannot initialize HTTPS listener")?
        .handle(http_handle.clone())
        .serve(
            crate::http::router(state.clone())
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        );
    let metrics_router = crate::http::metrics_router(state.clone());
    let metrics = async move {
        match metrics_listener {
            Some(listener) => axum::serve(listener, metrics_router).await,
            None => std::future::pending().await,
        }
    };
    let limit = config.limits.request_bytes;
    macro_rules! service {
        ($server:ty) => {
            <$server>::new(state.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(MAX_REPLY_BYTES)
        };
    }
    let rpc = tonic::transport::Server::builder()
        .tls_config(rpc_tls)
        .context("cannot configure RPC TLS; check the certificate and private key")?
        .timeout(state.timeout)
        .concurrency_limit_per_connection(CONCURRENCY_PER_CONNECTION)
        .add_service(service!(
            protocol::bootstrap_service_server::BootstrapServiceServer<State>
        ))
        .add_service(service!(
            protocol::admin_service_server::AdminServiceServer<State>
        ))
        .add_service(service!(
            protocol::user_service_server::UserServiceServer<State>
        ))
        .add_service(service!(
            protocol::signing_service_server::SigningServiceServer<State>
        ))
        .add_service(service!(
            protocol::ca_service_server::CaServiceServer<State>
        ))
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(rpc_listener),
            async move {
                let _ = shutdown_rx.changed().await;
            },
        );

    let result = tokio::select! {
        result = metrics => result.context("metrics listener failed"),
        result = http => result.with_context(|| listener_failure("HTTPS", config.https_listen, "https_listen")),
        result = rpc => result.with_context(|| listener_failure("RPC", config.rpc_listen, "rpc_listen")),
    };
    http_handle.shutdown();
    signal.abort();
    if result.is_ok() {
        tracing::info!(state = "STOPPED", "Server stopped");
    } else {
        tracing::error!("Listener failed; server stopping");
    }
    result
}

async fn await_shutdown_signal(
    mut terminate: tokio::signal::unix::Signal,
    http_handle: axum_server::Handle<std::net::SocketAddr>,
    shutdown: tokio::sync::watch::Sender<bool>,
) {
    let received = tokio::select! {
        result = tokio::signal::ctrl_c() => {
            if result.is_err() {
                tracing::error!("Shutdown signal handler failed");
            }
            "SIGINT"
        },
        _ = terminate.recv() => "SIGTERM",
    };
    tracing::info!(signal = received, "Server shutting down");
    http_handle.graceful_shutdown(Some(SHUTDOWN_GRACE));
    let _ = shutdown.send(true);
}

fn source_name(path: &Option<PathBuf>, inline: &str) -> String {
    path.as_ref()
        .map_or(inline.to_owned(), |path| path.display().to_string())
}

fn listener_failure(name: &str, address: std::net::SocketAddr, field: &str) -> String {
    let flag = field.replace('_', "-");
    format!(
        "{name} listener {address} failed. Check that the address is local and the port is available; change {field} or --{flag}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state() -> (State, mpsc::Receiver<Job>) {
        let (sender, receiver) = mpsc::channel(512);
        let state = State {
            server: String::new(),
            sender,
            ready: Arc::new(AtomicBool::new(true)),
            unlocking: Arc::new(AtomicBool::new(false)),
            limiter: Arc::default(),
            metrics: Arc::new(Metrics::default()),
            timeout: Duration::from_secs(2),
        };
        (state, receiver)
    }

    #[test]
    fn full_rate_table_admits_newcomers_and_preserves_existing_limits() {
        let (state, _receiver) = state();
        state.rate("oldest".into(), 1).unwrap();
        for i in 0..9999 {
            state.rate(format!("source:{i}"), 1).unwrap();
        }
        assert_eq!(
            state.rate("source:9998".into(), 1).unwrap_err().reason,
            "RATE_LIMIT"
        );
        state.rate("newcomer".into(), 1).unwrap();
        {
            let limiter = state.limiter.lock().unwrap();
            assert_eq!(limiter.windows.len(), 10000);
            assert!(!limiter.windows.contains_key("oldest"));
            assert!(limiter.windows.contains_key("newcomer"));
        }
        assert_eq!(
            state.rate("newcomer".into(), 1).unwrap_err().reason,
            "RATE_LIMIT"
        );
    }

    #[tokio::test]
    async fn ipv6_prefix_shares_limits_and_malformed_credentials_reach_worker() {
        let (state, mut receiver) = state();
        let worker = tokio::spawn(async move {
            while let Some(job) = receiver.recv().await {
                assert_eq!(job.credential.as_str(), "not-a-key");
                let _ = job.response.send(Ok(Reply::default()));
            }
        });
        let list = |address: &str| {
            state.call(
                Operation::ListZones,
                "not-a-key".into(),
                Command {
                    request_id: auth::new_id(),
                    ..Default::default()
                },
                Some(address.parse().unwrap()),
            )
        };
        for i in 1..=120 {
            list(&format!("2001:db8:1:2::{i:x}")).await.unwrap();
        }
        assert_eq!(
            list("2001:db8:1:2::ffff").await.unwrap_err().reason,
            "RATE_LIMIT"
        );
        list("2001:db8:1:3::1").await.unwrap();
        worker.abort();
    }
}
