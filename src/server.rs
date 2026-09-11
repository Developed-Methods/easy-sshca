use crate::{
    auth,
    config::ServerConfig,
    error::{Error, Result},
    protocol::{self, Command, Reply},
    storage::Database,
};
use anyhow::Context;
use std::{
    collections::HashMap,
    net::IpAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::sync::{mpsc, oneshot};
use tonic::{Request, Response, Status};
use zeroize::{Zeroize, Zeroizing};

#[derive(Default)]
pub struct Metrics {
    pub requests: AtomicU64,
    pub failures: AtomicU64,
    pub issued: AtomicU64,
    pub rate_limited: AtomicU64,
    pub micros: AtomicU64,
    pub outcomes: Mutex<HashMap<(String, String), (u64, u64)>>,
}
#[derive(Clone)]
pub struct State {
    server: String,
    sender: mpsc::Sender<Job>,
    pub ready: Arc<AtomicBool>,
    unlocking: Arc<AtomicBool>,
    limits: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
    pub metrics: Arc<Metrics>,
    timeout: Duration,
}
struct Job {
    op: String,
    credential: Zeroizing<String>,
    command: Command,
    response: oneshot::Sender<Result<Reply>>,
    deadline: Instant,
    unlock_guard: Option<UnlockGuard>,
}
impl Drop for Job {
    fn drop(&mut self) {
        self.command.secret.zeroize();
        self.command.totp.zeroize();
        self.command.replacement_key.zeroize();
    }
}
struct UnlockGuard(Arc<AtomicBool>);
impl Drop for UnlockGuard {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}
impl State {
    pub fn new(path: PathBuf, queue: usize, timeout: Duration) -> anyhow::Result<Self> {
        crate::memory::protect()?;
        if queue == 0 || timeout.is_zero() {
            anyhow::bail!("queue capacity and timeout must be positive");
        }
        let metadata = std::fs::metadata(&path).with_context(|| format!(
            "cannot access database {}. Check the database path in your server configuration. For a new installation, run easy-sshca server init --name NAME --folder NEW_FOLDER",
            path.display()
        ))?;
        if !metadata.is_file() {
            anyhow::bail!("database {} must be a regular file", path.display());
        }
        let lock = crate::storage::lock(&path)?;
        tracing::info!(
            queue_capacity = queue,
            timeout_seconds = timeout.as_secs(),
            "Database worker starting"
        );
        let (sender, mut receiver) = mpsc::channel::<Job>(queue);
        let ready = Arc::new(AtomicBool::new(false));
        let worker_ready = ready.clone();
        let metrics = Arc::new(Metrics::default());
        let worker_metrics = metrics.clone();
        std::thread::Builder::new()
            .name("sqlcipher".into())
            .spawn(move || {
                let _readiness_guard = UnlockGuard(worker_ready.clone());
                let mut db: Option<Database> = None;
                while let Some(mut job) = receiver.blocking_recv() {
                    if job.response.is_closed() || Instant::now() > job.deadline {
                        continue;
                    }
                    let result = if job.op == "Unlock" {
                        if db.is_some() {
                            Err(Error::new(
                                tonic::Code::FailedPrecondition,
                                "ALREADY_READY",
                                "server is already ready",
                            ))
                        } else {
                            Database::open_with_lock_until(
                                &path,
                                &job.command.secret,
                                lock.clone(),
                                job.deadline,
                            )
                            .map(|candidate| {
                                worker_metrics
                                    .issued
                                    .store(candidate.issuance_count, Ordering::Relaxed);
                                db = Some(candidate);
                                worker_ready.store(true, Ordering::Release);
                                tracing::info!(
                                    state = "READY",
                                    "Database unlocked; server ready for administration and signing"
                                );
                                Reply {
                                    request_id: job.command.request_id.clone(),
                                    state: "READY".into(),
                                    ..Default::default()
                                }
                            })
                        }
                    } else {
                        db.as_mut().ok_or_else(Error::locked).and_then(|db| {
                            let deadline = job.deadline;
                            db.connection
                                .progress_handler(1000, Some(move || Instant::now() >= deadline))?;
                            let result = db.execute(&job.op, &job.credential, &job.command);
                            db.connection.progress_handler(0, None::<fn() -> bool>)?;
                            result
                        })
                    };
                    if let Some(db) = &db {
                        worker_metrics
                            .issued
                            .store(db.issuance_count, Ordering::Relaxed);
                    }
                    job.unlock_guard.take();
                    let (placeholder, _) = oneshot::channel();
                    let response = std::mem::replace(&mut job.response, placeholder);
                    let _ = response.send(result);
                }
                worker_ready.store(false, Ordering::Release);
                tracing::info!(state = "STOPPED", "Database worker stopped");
            })
            .context("cannot start database worker thread")?;
        Ok(Self {
            server: String::new(),
            sender,
            ready,
            unlocking: Arc::new(AtomicBool::new(false)),
            limits: Arc::new(Mutex::new(HashMap::new())),
            metrics,
            timeout,
        })
    }
    pub fn queue_depth(&self) -> usize {
        self.sender.max_capacity() - self.sender.capacity()
    }
    fn rate(&self, bucket: String, max: u32) -> Result<()> {
        let mut limits = self.limits.lock().map_err(|_| Error::internal())?;
        if limits.len() >= 10000 {
            limits.retain(|_, (start, _)| start.elapsed() < Duration::from_secs(60));
        }
        if limits.len() >= 10000 && !limits.contains_key(&bucket) {
            return Err(Error::new(
                tonic::Code::ResourceExhausted,
                "RATE_LIMIT",
                "rate limit capacity reached",
            ));
        }
        let (start, count) = limits.entry(bucket).or_insert((Instant::now(), 0));
        if start.elapsed() >= Duration::from_secs(60) {
            *start = Instant::now();
            *count = 0;
        }
        if *count >= max {
            self.metrics.rate_limited.fetch_add(1, Ordering::Relaxed);
            return Err(Error::new(
                tonic::Code::ResourceExhausted,
                "RATE_LIMIT",
                "retry after one minute",
            ));
        }
        *count += 1;
        Ok(())
    }
    pub async fn call(
        &self,
        op: &str,
        credential: String,
        command: Command,
        source: Option<IpAddr>,
    ) -> Result<Reply> {
        auth::request_id(&command.request_id)?;
        let source = source
            .map(|x| x.to_string())
            .unwrap_or_else(|| "local".into());
        if op == "GetStatus" {
            return Ok(Reply {
                request_id: command.request_id,
                state: if self.ready.load(Ordering::Acquire) {
                    "READY"
                } else {
                    "LOCKED"
                }
                .into(),
                ..Default::default()
            });
        }
        if op != "Unlock" && !self.ready.load(Ordering::Acquire) {
            return Err(Error::locked());
        }
        self.rate(format!("ip:{source}"), 300)?;
        self.rate(
            format!("ip:{source}:{op}"),
            if op == "Unlock" {
                5
            } else if matches!(
                op,
                "ConfirmTotpEnrollment" | "RotateToken" | "BeginTotpEnrollment"
            ) {
                10
            } else {
                120
            },
        )?;
        if !credential.is_empty() && !matches!(op, "GetPublicKey" | "Unlock") {
            let key = auth::key(&credential)?;
            self.rate(format!("key:{}", key.id), 120)?;
            self.rate(
                format!("key:{}:{op}", key.id),
                if matches!(
                    op,
                    "SignCertificate" | "ConfirmTotpEnrollment" | "RotateToken"
                ) {
                    10
                } else {
                    120
                },
            )?;
        }
        let unlock_guard = if op == "Unlock" {
            if self.ready.load(Ordering::Acquire) {
                return Err(Error::new(
                    tonic::Code::FailedPrecondition,
                    "ALREADY_READY",
                    "server is already ready",
                ));
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
            Some(UnlockGuard(self.unlocking.clone()))
        } else {
            None
        };
        let (response, rx) = oneshot::channel();
        self.sender
            .try_send(Job {
                op: op.into(),
                credential: Zeroizing::new(credential),
                command,
                response,
                deadline: Instant::now() + self.timeout,
                unlock_guard,
            })
            .map_err(|_| {
                Error::new(
                    tonic::Code::ResourceExhausted,
                    "QUEUE_FULL",
                    "database queue is full",
                )
            })?;
        tokio::time::timeout(self.timeout, rx)
            .await
            .map_err(|_| {
                Error::new(
                    tonic::Code::DeadlineExceeded,
                    "TIMEOUT",
                    "operation timed out; retry with the same request UUID",
                )
            })?
            .map_err(|_| {
                Error::new(
                    tonic::Code::Unavailable,
                    "WORKER_STOPPED",
                    "database worker unavailable",
                )
            })?
    }
    async fn rpc(
        &self,
        op: &str,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        let started = Instant::now();
        let id = if request.get_ref().request_id.is_empty()
            && matches!(
                op,
                "GetStatus"
                    | "GetPublicKey"
                    | "ListZones"
                    | "ListUsers"
                    | "ListAccessTokens"
                    | "ListUserZones"
            ) {
            auth::id()
        } else {
            request.get_ref().request_id.clone()
        };
        let safe_id = if auth::request_id(&id).is_ok() {
            id.clone()
        } else {
            auth::id()
        };
        let source = request.remote_addr().map(|x| x.ip());
        let credential = request
            .metadata()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .unwrap_or("")
            .to_owned();
        let actor = auth::key(&credential).ok().map(|x| (x.kind, x.id));
        let mut command = request.into_inner();
        command.request_id = id;
        self.metrics.requests.fetch_add(1, Ordering::Relaxed);
        let result = self.call(op, credential, command, source).await;
        let reason = result.as_ref().map(|_| "OK").unwrap_or_else(|e| e.reason);
        let latency = started.elapsed().as_micros() as u64;
        self.metrics.micros.fetch_add(latency, Ordering::Relaxed);
        if let Ok(mut outcomes) = self.metrics.outcomes.lock() {
            let entry = outcomes.entry((op.into(), reason.into())).or_default();
            entry.0 += 1;
            entry.1 += latency;
        }
        macro_rules! log_rpc {
            ($level:expr) => {
                tracing::event!($level,
                    request_id = %safe_id,
                    operation = op,
                    actor_type = actor.as_ref().map(|a| a.0.as_str()).unwrap_or("public"),
                    actor_id = actor.as_ref().map(|a| a.1.as_str()).unwrap_or(""),
                    result = reason,
                    latency_us = latency,
                    "RPC completed"
                )
            };
        }
        match &result {
            Ok(_) => log_rpc!(tracing::Level::INFO),
            Err(e) if matches!(e.code, tonic::Code::Internal | tonic::Code::Unavailable) => {
                log_rpc!(tracing::Level::ERROR)
            }
            Err(_) => log_rpc!(tracing::Level::WARN),
        }
        match result {
            Ok(reply) => {
                let mut response = Response::new(reply);
                response
                    .metadata_mut()
                    .insert("x-request-id", safe_id.parse().expect("UUID metadata"));
                Ok(response)
            }
            Err(error) => {
                self.metrics.failures.fetch_add(1, Ordering::Relaxed);
                Err(error.status(&safe_id))
            }
        }
    }
}

#[tonic::async_trait]
impl protocol::bootstrap_service_server::BootstrapService for State {
    async fn get_status(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("GetStatus", request).await
    }
    async fn unlock(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("Unlock", request).await
    }
}

#[tonic::async_trait]
impl protocol::admin_service_server::AdminService for State {
    async fn create_zone(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("CreateZone", request).await
    }
    async fn import_zone(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("ImportZone", request).await
    }
    async fn list_zones(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("ListZones", request).await
    }
    async fn update_zone(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("UpdateZone", request).await
    }
    async fn create_user(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("CreateUser", request).await
    }
    async fn list_users(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("ListUsers", request).await
    }
    async fn update_user(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("UpdateUser", request).await
    }
    async fn remove_user(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("RemoveUser", request).await
    }
    async fn grant_zone(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("GrantZone", request).await
    }
    async fn list_user_zones(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("ListUserZones", request).await
    }
    async fn revoke_zone(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("RevokeZone", request).await
    }
    async fn create_access_token(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        let mut response = self.rpc("CreateAccessToken", request).await?;
        response.get_mut().server = self.server.clone();
        Ok(response)
    }
    async fn list_access_tokens(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("ListAccessTokens", request).await
    }
    async fn update_access_token(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("UpdateAccessToken", request).await
    }
    async fn remove_access_token(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("RemoveAccessToken", request).await
    }
    async fn clear_totp(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("ClearTotp", request).await
    }
    async fn rotate_admin_key(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("RotateAdminKey", request).await
    }
}

#[tonic::async_trait]
impl protocol::user_service_server::UserService for State {
    async fn begin_totp_enrollment(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("BeginTotpEnrollment", request).await
    }
    async fn confirm_totp_enrollment(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("ConfirmTotpEnrollment", request).await
    }
    async fn rotate_token(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("RotateToken", request).await
    }
}

#[tonic::async_trait]
impl protocol::signing_service_server::SigningService for State {
    async fn sign_certificate(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("SignCertificate", request).await
    }
}

#[tonic::async_trait]
impl protocol::ca_service_server::CaService for State {
    async fn get_public_key(
        &self,
        request: Request<Command>,
    ) -> std::result::Result<Response<Reply>, Status> {
        self.rpc("GetPublicKey", request).await
    }
}

pub async fn run(config: ServerConfig) -> anyhow::Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let mut state = State::new(
        config.database.clone(),
        config.limits.database_queue,
        Duration::from_secs(auth::parse_duration(&config.limits.rpc_timeout)?),
    )?;
    state.server = config.server.clone();
    let cert = config.certificate_pem()?;
    let key = config.private_key_pem()?;
    let certificate_source = config
        .tls
        .certificate
        .as_ref()
        .map_or("tls.certificate_pem".to_owned(), |path| {
            path.display().to_string()
        });
    let private_key_source = config
        .tls
        .private_key
        .as_ref()
        .map_or("tls.private_key_pem".to_owned(), |path| {
            path.display().to_string()
        });
    let https_tls =
        axum_server::tls_rustls::RustlsConfig::from_pem(cert.clone(), key.as_bytes().to_vec())
            .await.with_context(|| format!(
                "cannot configure TLS with certificate {certificate_source} and private key {private_key_source}. Supply a matching PEM certificate and private key"
            ))?;
    tracing::info!("TLS certificate and private key loaded");
    let rpc_tls = tonic::transport::ServerTlsConfig::new()
        .identity(tonic::transport::Identity::from_pem(cert, key.as_bytes()));
    let rpc_listener = tokio::net::TcpListener::bind(config.rpc_listen).await
        .with_context(|| format!("RPC listener {} failed. Check that the address is local and the port is available; change rpc_listen or --rpc-listen", config.rpc_listen))?;
    let https_listener = std::net::TcpListener::bind(config.https_listen)
        .with_context(|| format!("HTTPS listener {} failed. Check that the address is local and the port is available; change https_listen or --https-listen", config.https_listen))?;
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
    let shutdown_handle = http_handle.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("cannot register SIGTERM handler")?;
    let signal = tokio::spawn(async move {
        let received = tokio::select! {
            result = tokio::signal::ctrl_c() => {
                if result.is_err() {
                    tracing::error!("Shutdown signal handler failed");
                }
                "SIGINT"
            },
            _ = term.recv() => "SIGTERM",
        };
        tracing::info!(signal = received, "Server shutting down");
        shutdown_handle.graceful_shutdown(Some(Duration::from_secs(10)));
        let _ = shutdown_tx.send(true);
    });
    let http = axum_server::from_tcp_rustls(https_listener, https_tls)
        .context("cannot initialize HTTPS listener")?
        .handle(http_handle.clone())
        .serve(
            crate::http::router(state.clone())
                .into_make_service_with_connect_info::<std::net::SocketAddr>(),
        );
    let limit = config.limits.request_bytes;
    let rpc = tonic::transport::Server::builder()
        .tls_config(rpc_tls)
        .context("cannot configure RPC TLS; check the certificate and private key")?
        .timeout(state.timeout)
        .concurrency_limit_per_connection(64)
        .add_service(
            protocol::bootstrap_service_server::BootstrapServiceServer::new(state.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(1048576),
        )
        .add_service(
            protocol::admin_service_server::AdminServiceServer::new(state.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(1048576),
        )
        .add_service(
            protocol::user_service_server::UserServiceServer::new(state.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(1048576),
        )
        .add_service(
            protocol::signing_service_server::SigningServiceServer::new(state.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(1048576),
        )
        .add_service(
            protocol::ca_service_server::CaServiceServer::new(state.clone())
                .max_decoding_message_size(limit)
                .max_encoding_message_size(1048576),
        )
        .serve_with_incoming_shutdown(
            tokio_stream::wrappers::TcpListenerStream::new(rpc_listener),
            async move {
                let mut rx = shutdown_rx;
                let _ = rx.changed().await;
            },
        );
    let result = tokio::select! {
        r = http => r.with_context(|| format!("HTTPS listener {} failed. Check that the address is local and the port is available; change https_listen or --https-listen", config.https_listen)),
        r = rpc => r.with_context(|| format!("RPC listener {} failed. Check that the address is local and the port is available; change rpc_listen or --rpc-listen", config.rpc_listen)),
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
