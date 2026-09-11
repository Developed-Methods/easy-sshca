//! Command-line interface: argument definitions, the gRPC client, and the
//! workflows that combine them.

use crate::{
    auth::{self, KeyKind},
    config::{self, ClientConfig},
    protocol::{self, Command, ErrorDetail, Operation, Reply},
    storage,
    terminal::{read_secret, read_totp},
};
use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use prost::Message;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, IsTerminal, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tonic::{
    Request,
    transport::{Channel, ClientTlsConfig},
};
use zeroize::Zeroizing;

const RPC_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_SERVER_CONFIG: &str = "/etc/easy-sshca/server.yaml";
const DEFAULT_CERTIFICATE_DURATION: &str = "1d";
const STDIN_PATH: &str = "-";
/// Retries for a rotation whose outcome is unknown after a transport failure.
const ROTATION_RETRIES: usize = 2;

#[derive(Parser)]
#[command(version, about = "Encrypted SSH certificate authority")]
pub struct Cli {
    #[arg(
        long,
        global = true,
        help = "Configuration path (use - to read YAML or JSON from stdin)"
    )]
    pub config: Option<PathBuf>,
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(
        long,
        short = 'v',
        global = true,
        help = "Show internal UUIDs in human-readable output"
    )]
    pub verbose: bool,
    #[command(subcommand)]
    pub command: Action,
}

#[derive(Subcommand)]
pub enum Action {
    Server {
        #[command(subcommand)]
        command: Server,
    },
    Admin {
        #[command(subcommand)]
        command: Admin,
    },
    Configure(ConfigureArgs),
    GenKey {
        #[arg(long)]
        file: Option<PathBuf>,
        #[arg(long, default_value = "easy-sshca")]
        comment: String,
    },
    PubKey {
        zone: Option<String>,
        #[command(flatten)]
        connection: ConnectionArgs,
    },
    Sign(SignArgs),
    Totp {
        #[command(subcommand)]
        command: Totp,
    },
    RotateToken {
        #[arg(long)]
        totp_stdin: bool,
    },
}

impl Action {
    pub fn is_server_start(&self) -> bool {
        matches!(
            self,
            Action::Server {
                command: Server::Start(_)
            }
        )
    }

    /// Commands that rewrite the configuration file in place.
    fn writes_config(&self) -> bool {
        matches!(
            self,
            Action::Configure(_)
                | Action::RotateToken { .. }
                | Action::Admin {
                    command: Admin::Key {
                        command: AdminKey::RotateAdmin,
                    },
                }
        )
    }

    /// Commands that never read the client configuration.
    fn ignores_config(&self) -> bool {
        matches!(
            self,
            Action::GenKey { .. }
                | Action::Server {
                    command: Server::Init(_) | Server::ResetAdmin { .. },
                }
        )
    }

    /// Commands that may run before the configuration file exists.
    fn creates_config(&self) -> bool {
        self.ignores_config()
            || matches!(
                self,
                Action::Configure(_)
                    | Action::Server {
                        command: Server::Start(_)
                    }
            )
    }

    /// Commands that read a secret, code or key from stdin.
    fn reads_stdin(&self) -> bool {
        match self {
            Action::Sign(SignArgs { totp_stdin, .. }) => *totp_stdin,
            Action::Totp {
                command: Totp::Confirm { totp_stdin },
            } => *totp_stdin,
            Action::Server {
                command: Server::Unlock { secret_stdin, .. },
            } => *secret_stdin,
            Action::Admin {
                command:
                    Admin::Zone {
                        command: Zone::Import { source, .. },
                    },
            } => source.uses_stdin(),
            _ => false,
        }
    }
}

#[derive(Args)]
pub struct ConfigureArgs {
    #[arg(long)]
    server: String,
    #[arg(long)]
    api_key_stdin: bool,
    #[arg(long)]
    tls_ca: Option<PathBuf>,
    #[arg(long)]
    tls_server_name: Option<String>,
    #[arg(long)]
    zone: Option<String>,
    #[arg(long)]
    public_key: Option<PathBuf>,
    #[arg(long)]
    duration: Option<String>,
}

#[derive(Args)]
pub struct SignArgs {
    zone: Option<String>,
    #[arg(long)]
    file: Option<PathBuf>,
    #[arg(long)]
    duration: Option<String>,
    #[arg(long)]
    totp_stdin: bool,
    #[arg(long)]
    force: bool,
    #[command(flatten)]
    connection: ConnectionArgs,
}

#[derive(Args, Default)]
pub struct ConnectionArgs {
    #[arg(long)]
    server: Option<String>,
    #[arg(long)]
    tls_ca: Option<PathBuf>,
    #[arg(long)]
    tls_server_name: Option<String>,
}

impl ConnectionArgs {
    fn apply(self, config: &mut ClientConfig) -> anyhow::Result<()> {
        if let Some(server) = self.server {
            config.server = server;
        }
        if let Some(tls_ca) = self.tls_ca {
            config.tls_ca = Some(config::resolve(&tls_ca, &std::env::current_dir()?)?);
            config.tls_ca_pem = None;
        }
        if let Some(name) = self.tls_server_name {
            config.tls_server_name = Some(name);
        }
        Ok(())
    }
}

#[derive(Subcommand)]
pub enum Server {
    Init(InitArgs),
    Start(StartArgs),
    Status {
        #[command(flatten)]
        connection: ConnectionArgs,
    },
    Unlock {
        #[arg(long)]
        secret_stdin: bool,
        #[command(flatten)]
        connection: ConnectionArgs,
    },
    ResetAdmin {
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        secret_stdin: bool,
        #[arg(long)]
        admin_output: PathBuf,
    },
}

#[derive(Args)]
pub struct InitArgs {
    #[arg(long)]
    name: String,
    #[arg(long)]
    folder: PathBuf,
    #[arg(long)]
    admin_api_key_file: Option<PathBuf>,
    #[arg(
        long,
        alias = "server-address",
        default_value = "localhost",
        help = "Address used in generated client configs (HOST[:PORT] or HTTPS origin)"
    )]
    server: String,
    #[arg(long, help = "Override the port in the server address")]
    port: Option<u16>,
    #[arg(
        long,
        help = "gRPC bind address (default: 127.0.0.1 and the server address port)"
    )]
    rpc_listen: Option<SocketAddr>,
    #[arg(long, help = "HTTPS bind address (default: 127.0.0.1:9444)")]
    https_listen: Option<SocketAddr>,
}

#[derive(Args)]
pub struct StartArgs {
    #[arg(long)]
    db: Option<PathBuf>,
    #[arg(long)]
    rpc_listen: Option<SocketAddr>,
    #[arg(long)]
    https_listen: Option<SocketAddr>,
}

#[derive(Subcommand)]
pub enum Admin {
    Zone {
        #[command(subcommand)]
        command: Zone,
    },
    User {
        #[command(subcommand)]
        command: User,
    },
    AccessToken {
        #[command(subcommand)]
        command: AccessToken,
    },
    Key {
        #[command(subcommand)]
        command: AdminKey,
    },
}

#[derive(Subcommand)]
pub enum Zone {
    Add {
        name: String,
        #[arg(long, default_value = "1d")]
        max_duration: String,
    },
    Import {
        name: String,
        #[arg(long, default_value = "1d")]
        max_duration: String,
        #[command(flatten)]
        source: ImportKeySource,
    },
    List {
        #[command(flatten)]
        page: Page,
    },
    Update {
        name: String,
        #[command(flatten)]
        update: Update,
    },
    Remove {
        name: String,
    },
}

#[derive(Args)]
#[group(required = true, multiple = false)]
pub struct ImportKeySource {
    #[arg(
        long,
        value_name = "PATH",
        help = "Read an unencrypted Ed25519 OpenSSH private key (use - for stdin)"
    )]
    file: Option<PathBuf>,
    #[arg(long, help = "Read the private key from stdin")]
    stdin: bool,
}

impl ImportKeySource {
    fn uses_stdin(&self) -> bool {
        self.stdin || self.file.as_deref() == Some(Path::new(STDIN_PATH))
    }

    fn read(&self) -> anyhow::Result<Zeroizing<String>> {
        match &self.file {
            Some(path) if !self.uses_stdin() => Ok(Zeroizing::new(config::secure_read(path)?)),
            _ => Ok(read_secret(true, "")?),
        }
    }
}

#[derive(Args, Default)]
pub struct Page {
    #[arg(long, default_value_t = 100)]
    page_size: u32,
    #[arg(long, default_value = "")]
    page_token: String,
}

impl Page {
    fn apply(self, command: &mut Command) {
        command.page_size = self.page_size;
        command.page_token = self.page_token;
    }
}

#[derive(Args)]
#[group(id = "ResourceUpdate")]
pub struct Update {
    #[arg(long)]
    max_duration: Option<String>,
    #[arg(long)]
    active: Option<bool>,
}

impl Update {
    fn apply(self, command: &mut Command) -> anyhow::Result<()> {
        command.max_duration = self
            .max_duration
            .map(|value| auth::parse_duration(&value))
            .transpose()?
            .unwrap_or(0);
        command.active = self.active;
        Ok(())
    }
}

#[derive(Subcommand)]
pub enum User {
    Add {
        name: String,
        #[arg(long, default_value = "1d")]
        max_duration: String,
    },
    List {
        #[command(flatten)]
        page: Page,
    },
    Update {
        name: String,
        #[command(flatten)]
        update: Update,
    },
    Remove {
        name: String,
    },
    Zone {
        #[command(subcommand)]
        command: UserZone,
    },
    Totp {
        #[command(subcommand)]
        command: AdminTotp,
    },
}

#[derive(Subcommand)]
pub enum UserZone {
    Grant {
        user: String,
        zone: String,
    },
    Revoke {
        user: String,
        zone: String,
    },
    List {
        user: String,
        #[command(flatten)]
        page: Page,
    },
}

#[derive(Subcommand)]
pub enum AdminTotp {
    Clear { user: String },
}

#[derive(Subcommand)]
pub enum AdminKey {
    RotateAdmin,
}

#[derive(Subcommand)]
pub enum AccessToken {
    Add {
        #[arg(long)]
        user: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        max_duration: String,
        #[arg(
            short,
            long,
            help = "Save a self-contained client config (.json for JSON, otherwise YAML)"
        )]
        output: Option<PathBuf>,
    },
    List {
        #[arg(long)]
        user: String,
        #[command(flatten)]
        page: Page,
    },
    Update {
        #[arg(long)]
        user: String,
        #[arg(long)]
        name: String,
        #[command(flatten)]
        update: Update,
    },
    Remove {
        #[arg(long)]
        user: String,
        #[arg(long)]
        name: String,
    },
}

#[derive(Subcommand)]
pub enum Totp {
    Enroll,
    Confirm {
        #[arg(long)]
        totp_stdin: bool,
    },
}

/// A command with a fresh request UUID and no other fields set.
fn new_command() -> Command {
    Command {
        request_id: auth::new_id(),
        ..Default::default()
    }
}

/// Open a TLS channel to the configured server.
pub async fn channel(config: &ClientConfig) -> anyhow::Result<Channel> {
    config.validate()?;
    let endpoint = Channel::from_shared(config.server.clone())?;
    let mut tls = ClientTlsConfig::new();
    if let Some(name) = &config.tls_server_name {
        tls = tls.domain_name(name);
    }
    let endpoint = match config.tls_pem()? {
        Some(pem) => endpoint.tls_config_with_verifier(
            tls,
            std::sync::Arc::new(crate::tls::CertificateVerifier::from_pem(&pem)?),
        )?,
        None => endpoint.tls_config(tls.with_native_roots())?,
    };
    Ok(endpoint
        .timeout(RPC_TIMEOUT)
        .connect_timeout(RPC_TIMEOUT)
        .connect()
        .await?)
}

/// Send one RPC, authenticating with the configured API key when present.
pub async fn rpc(config: &ClientConfig, op: Operation, command: Command) -> anyhow::Result<Reply> {
    use Operation::*;
    use protocol::{
        admin_service_client::AdminServiceClient, bootstrap_service_client::BootstrapServiceClient,
        ca_service_client::CaServiceClient, signing_service_client::SigningServiceClient,
        user_service_client::UserServiceClient,
    };
    let channel = channel(config).await?;
    let mut request = Request::new(command);
    request.set_timeout(RPC_TIMEOUT);
    if let Some(key) = config.api_key_value()? {
        let mut bearer = Zeroizing::new(format!("Bearer {}", key.as_str()))
            .parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>()?;
        bearer.set_sensitive(true);
        request.metadata_mut().insert("authorization", bearer);
    }
    let mut bootstrap = BootstrapServiceClient::new(channel.clone());
    let mut admin = AdminServiceClient::new(channel.clone());
    let mut user = UserServiceClient::new(channel.clone());
    let mut signing = SigningServiceClient::new(channel.clone());
    let mut ca = CaServiceClient::new(channel);
    let response = match op {
        GetStatus => bootstrap.get_status(request).await?,
        Unlock => bootstrap.unlock(request).await?,
        CreateZone => admin.create_zone(request).await?,
        ImportZone => admin.import_zone(request).await?,
        ListZones => admin.list_zones(request).await?,
        UpdateZone => admin.update_zone(request).await?,
        RemoveZone => admin.remove_zone(request).await?,
        CreateUser => admin.create_user(request).await?,
        ListUsers => admin.list_users(request).await?,
        UpdateUser => admin.update_user(request).await?,
        RemoveUser => admin.remove_user(request).await?,
        GrantZone => admin.grant_zone(request).await?,
        RevokeZone => admin.revoke_zone(request).await?,
        ListUserZones => admin.list_user_zones(request).await?,
        CreateAccessToken => admin.create_access_token(request).await?,
        ListAccessTokens => admin.list_access_tokens(request).await?,
        UpdateAccessToken => admin.update_access_token(request).await?,
        RemoveAccessToken => admin.remove_access_token(request).await?,
        ClearTotp => admin.clear_totp(request).await?,
        RotateAdminKey => admin.rotate_admin_key(request).await?,
        BeginTotpEnrollment => user.begin_totp_enrollment(request).await?,
        ConfirmTotpEnrollment => user.confirm_totp_enrollment(request).await?,
        RotateToken => user.rotate_token(request).await?,
        SignCertificate => signing.sign_certificate(request).await?,
        GetPublicKey => ca.get_public_key(request).await?,
    };
    Ok(response.into_inner())
}

/// The structured error attached to a failed RPC, if any.
fn error_detail(error: &anyhow::Error) -> Option<ErrorDetail> {
    let status = error.downcast_ref::<tonic::Status>()?;
    ErrorDetail::decode(status.details()).ok()
}

fn totp_required(error: &anyhow::Error) -> bool {
    error_detail(error).is_some_and(|detail| detail.totp_required)
}

/// Global options and the configuration path shared by every command.
struct Session {
    config_path: PathBuf,
    explicit_config: bool,
    json: bool,
    verbose: bool,
}

pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let session = Session {
        config_path: cli.config.clone().map_or_else(config::default_path, Ok)?,
        explicit_config: cli.config.is_some(),
        json: cli.json,
        verbose: cli.verbose,
    };
    session.check_config_source(&cli.command)?;
    match cli.command {
        Action::Server {
            command: Server::Init(args),
        } => session.server_init(args),
        Action::Server {
            command: Server::Start(args),
        } => session.server_start(args).await,
        Action::Server {
            command:
                Server::ResetAdmin {
                    db,
                    secret_stdin,
                    admin_output,
                },
        } => session.reset_admin(&db, secret_stdin, &admin_output),
        Action::Server {
            command: Server::Status { connection },
        } => {
            let config = session.load(connection)?;
            let reply = rpc(&config, Operation::GetStatus, new_command()).await?;
            session.print_reply(None, &reply)
        }
        Action::Server {
            command:
                Server::Unlock {
                    secret_stdin,
                    connection,
                },
        } => session.unlock(secret_stdin, connection).await,
        Action::Configure(args) => session.configure(args),
        Action::GenKey { file, comment } => session.gen_key(file, &comment),
        Action::PubKey { zone, connection } => {
            let config = session.load(connection)?;
            let mut command = new_command();
            command.zone = zone
                .or_else(|| config.defaults.zone.clone())
                .context("zone is required")?;
            let reply = rpc(&config, Operation::GetPublicKey, command).await?;
            session.print_reply(None, &reply)
        }
        Action::Sign(args) => session.sign(args).await,
        Action::Totp {
            command: Totp::Enroll,
        } => session.totp_enroll().await,
        Action::Totp {
            command: Totp::Confirm { totp_stdin },
        } => {
            let config = session.load(ConnectionArgs::default())?;
            let mut command = new_command();
            command.totp = read_totp(totp_stdin, "Confirm TOTP code: ")?.to_string();
            let reply = rpc(&config, Operation::ConfirmTotpEnrollment, command).await?;
            session.print_reply(None, &reply)
        }
        Action::RotateToken { totp_stdin } => {
            session.rotate(Operation::RotateToken, totp_stdin).await
        }
        Action::Admin {
            command: Admin::Key {
                command: AdminKey::RotateAdmin,
            },
        } => session.rotate(Operation::RotateAdminKey, false).await,
        Action::Admin { command } => session.admin(command).await,
    }
}

impl Session {
    fn reads_config_from_stdin(&self) -> bool {
        self.config_path == Path::new(STDIN_PATH)
    }

    /// Reject combinations of `--config` and the command that cannot work.
    fn check_config_source(&self, action: &Action) -> anyhow::Result<()> {
        if self.reads_config_from_stdin() {
            if action.writes_config() {
                bail!(
                    "this command requires a writable configuration file; --config - is not supported"
                );
            }
            if action.ignores_config() {
                bail!("this command does not read configuration; --config - is not supported");
            }
            if action.reads_stdin() {
                bail!("--config - cannot be combined with another stdin input");
            }
        } else if self.explicit_config && !self.config_path.exists() && !action.creates_config() {
            bail!(
                "explicit configuration file does not exist: {}",
                self.config_path.display()
            );
        }
        Ok(())
    }

    fn print(&self, value: impl Serialize, human: &str) -> anyhow::Result<()> {
        if self.json {
            let envelope = serde_json::json!({"version": 1, "result": value});
            println!("{}", serde_json::to_string(&envelope)?);
        } else {
            println!("{human}");
        }
        Ok(())
    }

    fn print_reply(&self, op: Option<Operation>, reply: &Reply) -> anyhow::Result<()> {
        if self.json {
            return self.print(reply, "");
        }
        if !reply.api_key.is_empty() {
            println!("{}", reply.api_key);
        } else if !reply.state.is_empty() {
            println!("{}", reply.state);
        } else if !reply.public_key.is_empty() {
            println!("{}\n{}", reply.public_key, reply.fingerprint);
        } else if !reply.resources.is_empty() {
            println!("{}", resource_table(&reply.resources, self.verbose));
            if !reply.next_page_token.is_empty() {
                eprintln!("Next page: --page-token {}", reply.next_page_token);
            }
        } else if op.is_some_and(Operation::is_list) {
            println!("No results.");
        } else if self.verbose && !reply.request_id.is_empty() {
            println!("OK {}", reply.request_id);
        } else {
            println!("OK");
        }
        Ok(())
    }

    /// Load the client configuration, or build one from `--server` when the
    /// file does not exist.
    fn load(&self, overrides: ConnectionArgs) -> anyhow::Result<ClientConfig> {
        let path = &self.config_path;
        let mut config = if self.reads_config_from_stdin() || path.exists() {
            ClientConfig::load(path)?
        } else if let Some(server) = &overrides.server {
            ClientConfig::new(server.clone())
        } else {
            return ClientConfig::load(path);
        };
        overrides.apply(&mut config)?;
        config.validate()?;
        Ok(config)
    }

    fn server_init(&self, args: InitArgs) -> anyhow::Result<()> {
        use std::os::unix::fs::DirBuilderExt;
        storage::validate_instance_name(&args.name)?;
        let server_address = config::server_address(&args.server, args.port)?;
        let server_port = url::Url::parse(&server_address)?
            .port_or_known_default()
            .context("server address has no port")?;
        let rpc_listen = args
            .rpc_listen
            .unwrap_or(([127, 0, 0, 1], server_port).into());
        let https_listen = args
            .https_listen
            .unwrap_or(([127, 0, 0, 1], config::DEFAULT_HTTPS_PORT).into());
        let folder = config::resolve(&args.folder, Path::new("."))?;
        let executable = std::env::current_exe().context("cannot locate the server executable")?;
        let server_config = folder.join("server.yaml");
        let admin_config = folder.join("admin.yaml");
        let db = folder.join("ca.db");
        let start_command = format!(
            "{} server start --config {}",
            shell_quote(&executable)?,
            shell_quote(&server_config)?
        );
        let unlock_command = format!(
            "{} --config {} server unlock",
            shell_quote(&executable)?,
            shell_quote(&admin_config)?
        );
        let secret = auth::random_secret();
        let admin = match &args.admin_api_key_file {
            Some(path) => Zeroizing::new(config::secure_read(path)?.trim().to_owned()),
            None => auth::new_key(KeyKind::Admin),
        };
        if auth::parse_key(&admin)?.kind != KeyKind::Admin {
            bail!("supplied credential must be an admin key");
        }
        let tls = rcgen::generate_simple_self_signed(vec![
            "localhost".into(),
            "127.0.0.1".into(),
            "::1".into(),
        ])
        .context("cannot generate localhost TLS certificate")?;
        config::private_parent(&folder)?;
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&folder)
            .with_context(|| {
                format!(
                    "cannot create initialization folder {}. Choose a new folder; existing folders are never overwritten",
                    folder.display()
                )
            })?;
        let populate = || -> anyhow::Result<()> {
            let private_key = Zeroizing::new(tls.signing_key.serialize_pem());
            storage::Database::initialize(&db, &secret, &admin, &args.name)?;
            let server = config::ServerConfig {
                version: 1,
                database: PathBuf::from("ca.db"),
                server: server_address.clone(),
                rpc_listen,
                https_listen,
                metrics_listen: None,
                tls: config::Tls {
                    certificate: None,
                    certificate_pem: Some(tls.cert.pem()),
                    private_key: None,
                    private_key_pem: Some(private_key.to_string()),
                },
                limits: config::Limits {
                    request_bytes: 65536,
                    rpc_timeout: "10s".into(),
                    database_queue: 128,
                },
            };
            let server_yaml = Zeroizing::new(serde_saphyr::to_string(&server)?);
            config::exclusive(&server_config, server_yaml.as_bytes(), 0o600)?;
            let mut client = ClientConfig::new(server_address.clone());
            client.api_key = Some(admin.to_string());
            client.bootstrap_secret = Some(secret.to_string());
            client.tls_ca_pem = Some(tls.cert.pem());
            let client_yaml = client.serialize_for(&admin_config)?;
            config::exclusive(&admin_config, client_yaml.as_bytes(), 0o600)?;
            config::sync_parent(&server_config)?;
            config::sync_parent(&folder)?;
            Ok(())
        };
        populate().with_context(|| {
            format!(
                "initialization failed in {}. Partial files remain for inspection; retry with a new folder",
                folder.display()
            )
        })?;
        self.print(
            serde_json::json!({
                "database": db,
                "server_config": server_config,
                "admin_config": admin_config,
                "start_command": start_command,
                "unlock_command": unlock_command,
            }),
            &format!(
                "Initialized {}\nServer configuration: {}\nAdmin configuration: {}\nServer address: {server_address}\nListeners: gRPC {rpc_listen}, HTTPS {https_listen}\nTLS: self-signed\n\nStart the server:\n{start_command}\n\nThen unlock it from another terminal:\n{unlock_command}",
                folder.display(),
                server_config.display(),
                admin_config.display(),
            ),
        )
    }

    async fn server_start(&self, args: StartArgs) -> anyhow::Result<()> {
        let path = if self.explicit_config {
            self.config_path.clone()
        } else {
            PathBuf::from(DEFAULT_SERVER_CONFIG)
        };
        let mut server = config::ServerConfig::load(&path)?;
        tracing::info!(config = %path.display(), "Server configuration loaded");
        if let Some(db) = args.db {
            server.database = db;
        }
        if let Some(address) = args.rpc_listen {
            server.rpc_listen = address;
        }
        if let Some(address) = args.https_listen {
            server.https_listen = address;
        }
        crate::server::run(server).await
    }

    fn reset_admin(&self, db: &Path, secret_stdin: bool, output: &Path) -> anyhow::Result<()> {
        let secret = read_secret(secret_stdin, "Bootstrap secret: ")?;
        let mut database = storage::Database::open(db, &secret)?;
        let replacement = auth::new_key(KeyKind::Admin);
        config::exclusive(output, format!("{}\n", *replacement).as_bytes(), 0o600)?;
        database.reset_admin(&replacement)?;
        self.print(
            serde_json::json!({"admin_key_file": output}),
            &format!("Admin key saved to {}", output.display()),
        )
    }

    async fn unlock(&self, secret_stdin: bool, connection: ConnectionArgs) -> anyhow::Result<()> {
        let config = self.load(connection)?;
        let secret = if secret_stdin {
            read_secret(true, "")?
        } else if let Some(secret) = config.bootstrap_secret_value()? {
            secret
        } else {
            read_secret(false, "Bootstrap secret: ")?
        };
        let mut command = new_command();
        command.secret = secret.to_string();
        let reply = rpc(&config, Operation::Unlock, command).await?;
        self.print_reply(None, &reply)
    }

    fn configure(&self, args: ConfigureArgs) -> anyhow::Result<()> {
        let path = &self.config_path;
        config::private_parent(path)?;
        let _lock = storage::lock(path)?;
        if path.with_extension("rotation.yaml").exists() {
            bail!("finish the pending credential rotation before replacing this configuration");
        }
        if path.exists() {
            confirm_replacement(path)?;
        }
        let key = read_secret(
            args.api_key_stdin,
            "API key (leave empty for public commands): ",
        )?;
        let cwd = std::env::current_dir()?;
        let mut client = ClientConfig::new(args.server);
        client.api_key = (!key.is_empty()).then(|| key.to_string());
        client.tls_ca = args
            .tls_ca
            .map(|tls_ca| config::resolve(&tls_ca, &cwd))
            .transpose()?;
        client.tls_server_name = args.tls_server_name;
        client.defaults = config::Defaults {
            zone: args.zone,
            public_key: args
                .public_key
                .map(|key| config::resolve(&key, &cwd))
                .transpose()?,
            duration: args.duration,
        };
        client.validate()?;
        if let Some(tls_ca) = &client.tls_ca {
            fs::read(tls_ca).context("cannot read TLS CA")?;
        }
        config::atomic(path, client.serialize_for(path)?.as_bytes())?;
        self.print(
            serde_json::json!({"config": path}),
            &format!("Saved {}", path.display()),
        )
    }

    fn gen_key(&self, file: Option<PathBuf>, comment: &str) -> anyhow::Result<()> {
        let private = match file {
            Some(file) => file,
            None => home::home_dir()
                .context("home directory unavailable")?
                .join(".ssh/id_ed25519"),
        };
        let public = PathBuf::from(format!("{}.pub", private.display()));
        if private.exists() || public.exists() {
            bail!("key files already exist");
        }
        let key = crate::signing::generate(comment)?;
        let pem = key.to_openssh(ssh_key::LineEnding::LF)?;
        config::exclusive(&private, pem.as_bytes(), 0o600)?;
        config::exclusive(
            &public,
            format!("{}\n", key.public_key().to_openssh()?).as_bytes(),
            0o644,
        )?;
        self.print(
            serde_json::json!({"private_key": private, "public_key": public}),
            &format!("Created {} and {}", private.display(), public.display()),
        )
    }

    async fn sign(&self, args: SignArgs) -> anyhow::Result<()> {
        let config = self.load(args.connection)?;
        let public_key = match args.file.or_else(|| config.defaults.public_key.clone()) {
            Some(path) => config::resolve(&path, &std::env::current_dir()?)?,
            None => discover_key(
                &home::home_dir()
                    .context("home directory unavailable")?
                    .join(".ssh"),
            )?,
        };
        let certificate = certificate_path(&public_key)?;
        if certificate.exists() && !args.force {
            bail!("certificate exists; pass --force to replace it");
        }
        let mut command = new_command();
        command.zone = args
            .zone
            .or_else(|| config.defaults.zone.clone())
            .context("zone is required")?;
        command.duration = auth::parse_duration(
            args.duration
                .as_deref()
                .or(config.defaults.duration.as_deref())
                .unwrap_or(DEFAULT_CERTIFICATE_DURATION),
        )?;
        command.public_key = fs::read_to_string(&public_key)?;
        if args.totp_stdin {
            command.totp = read_totp(true, "")?.to_string();
        }
        let reply = match rpc(&config, Operation::SignCertificate, command.clone()).await {
            Err(error) if !args.totp_stdin && totp_required(&error) => {
                command.totp = read_totp(false, "TOTP code: ")?.to_string();
                rpc(&config, Operation::SignCertificate, command).await?
            }
            result => result?,
        };
        let contents = format!("{}\n", reply.certificate);
        if args.force {
            config::atomic(&certificate, contents.as_bytes())?;
        } else {
            config::exclusive(&certificate, contents.as_bytes(), 0o644)?;
        }
        self.print(
            serde_json::json!({
                "request_id": reply.request_id,
                "certificate_file": certificate,
                "expires_at": reply.expires_at,
                "effective_duration": reply.effective_duration,
            }),
            &format!(
                "Saved {} ({}s; expires {})",
                certificate.display(),
                reply.effective_duration,
                reply.expires_at
            ),
        )
    }

    async fn totp_enroll(&self) -> anyhow::Result<()> {
        let config = self.load(ConnectionArgs::default())?;
        let enrollment = rpc(&config, Operation::BeginTotpEnrollment, new_command()).await?;
        if self.json {
            return self.print_reply(None, &enrollment);
        }
        print_enrollment_qr(&enrollment.otpauth_uri)?;
        println!("\n{}\n", enrollment.secret);
        let mut command = new_command();
        command.totp = read_totp(false, "Confirm TOTP code: ")?.to_string();
        let reply = rpc(&config, Operation::ConfirmTotpEnrollment, command).await?;
        self.print_reply(None, &reply)
    }

    async fn admin(&self, admin: Admin) -> anyhow::Result<()> {
        let config = self.load(ConnectionArgs::default())?;
        let export = match &admin {
            Admin::AccessToken {
                command: AccessToken::Add { output, .. },
            } => output.clone(),
            _ => None,
        };
        let (op, command) = admin_command(admin)?;
        match export {
            Some(destination) => {
                self.export_access_token(&config, command, &destination)
                    .await
            }
            None => self.print_reply(Some(op), &rpc(&config, op, command).await?),
        }
    }

    /// Create an access token and write a self-contained client configuration
    /// for it. The destination is reserved before the token exists so a
    /// write failure cannot lose the only copy of the key.
    async fn export_access_token(
        &self,
        admin: &ClientConfig,
        command: Command,
        path: &Path,
    ) -> anyhow::Result<()> {
        match fs::symlink_metadata(path) {
            Ok(_) => bail!(
                "output already exists: {}; choose a new file",
                path.display()
            ),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot inspect output {}", path.display()));
            }
        }
        let mut client = ClientConfig::new(admin.server.clone());
        client.tls_ca_pem = admin.tls_pem()?;
        client.tls_server_name = admin.tls_server_name.clone();
        client.defaults.duration =
            Some(humantime::format_duration(Duration::from_secs(command.max_duration)).to_string());
        let mut staged = config::staged(path, b"")?;
        let mut reply = rpc(admin, Operation::CreateAccessToken, command).await?;
        if !reply.server.is_empty() {
            client.server = std::mem::take(&mut reply.server);
        }
        client.api_key = Some(std::mem::take(&mut reply.api_key));
        let mut write = || -> anyhow::Result<()> {
            let text = client.serialize_for(path)?;
            staged.write_all(text.as_bytes())?;
            staged.as_file().sync_all()?;
            Ok(())
        };
        write().context(
            "token created but configuration could not be written; revoke the token and retry",
        )?;
        if let Err(error) = staged.persist_noclobber(path) {
            let (_, recovery) = error.file.keep().context(
                "token created but configuration could not be retained; revoke the token and retry",
            )?;
            return Err(error.error).with_context(|| {
                format!(
                    "token created; client configuration retained at {}. Could not install it at {}",
                    recovery.display(),
                    path.display()
                )
            });
        }
        config::sync_parent(path)
            .context("client configuration saved, but directory sync failed")?;
        self.print(
            serde_json::json!({"config": path}),
            &format!("Client configuration saved to {}", path.display()),
        )
    }

    /// Replace the API key with a fresh one. Progress is journaled beside the
    /// configuration so an interrupted rotation can be resumed by rerunning
    /// the same command.
    async fn rotate(&self, op: Operation, totp_stdin: bool) -> anyhow::Result<()> {
        let path = &self.config_path;
        let _lock = storage::lock(path)?;
        let current = ClientConfig::load(path)?;
        let pending_path = path.with_extension("rotation.yaml");
        let candidate_path = path.with_extension("candidate.yaml");
        let recovering = pending_path.exists();
        let mut pending = if recovering {
            let data = Zeroizing::new(config::secure_read(&pending_path)?);
            let pending: PendingRotation = serde_saphyr::from_str(&data)
                .map_err(|_| anyhow::anyhow!("invalid pending rotation file"))?;
            if pending.operation != op.name() || pending.config.server != current.server {
                bail!("pending rotation belongs to a different operation or server");
            }
            pending
        } else {
            let old = auth::parse_key(current.api_key.as_deref().context("API key required")?)?;
            let expected = if op == Operation::RotateToken {
                KeyKind::AccessToken
            } else {
                KeyKind::Admin
            };
            if old.kind != expected {
                bail!("wrong credential kind for rotation");
            }
            let mut command = new_command();
            command.replacement_key = auth::new_key(expected).to_string();
            if totp_stdin {
                command.totp = read_totp(true, "")?.to_string();
            }
            let mut replacement = current.clone();
            replacement.api_key = Some(command.replacement_key.clone());
            let pending = PendingRotation {
                operation: op.name().into(),
                command,
                config: replacement,
            };
            config::exclusive(
                &pending_path,
                Zeroizing::new(serde_saphyr::to_string(&pending)?).as_bytes(),
                0o600,
            )?;
            pending
        };
        config::atomic(
            &candidate_path,
            pending.config.serialize_for(path)?.as_bytes(),
        )?;
        let mut result = rpc(&current, op, pending.command.clone()).await;
        let needs_totp = result.as_ref().is_err_and(|error| {
            error_detail(error).is_some_and(|detail| {
                matches!(detail.reason.as_str(), "TOTP_REQUIRED" | "INVALID_TOTP")
            })
        });
        if needs_totp && (!totp_stdin || recovering) {
            pending.command.totp = read_totp(totp_stdin, "TOTP code: ")?.to_string();
            config::atomic(
                &pending_path,
                Zeroizing::new(serde_saphyr::to_string(&pending)?).as_bytes(),
            )?;
            result = rpc(&current, op, pending.command.clone()).await;
        }
        for _ in 0..ROTATION_RETRIES {
            if !result.as_ref().is_err_and(is_transient) {
                break;
            }
            result = rpc(&current, op, pending.command.clone()).await;
        }
        let reply = result.with_context(|| {
            format!(
                "rotation recovery saved to {}; rerun the same rotation command",
                pending_path.display()
            )
        })?;
        fs::rename(&candidate_path, path)?;
        config::sync_parent(path)?;
        fs::remove_file(&pending_path)?;
        config::sync_parent(path)?;
        self.print_reply(None, &reply)
    }
}

/// Transport failures and timeouts, where the server may or may not have
/// applied the request.
fn is_transient(error: &anyhow::Error) -> bool {
    error.downcast_ref::<tonic::Status>().is_none_or(|status| {
        matches!(
            status.code(),
            tonic::Code::Unavailable | tonic::Code::DeadlineExceeded
        )
    })
}

fn confirm_replacement(path: &Path) -> anyhow::Result<()> {
    if !io::stdin().is_terminal() {
        bail!("configuration exists; use an interactive terminal to confirm replacement");
    }
    eprint!("Replace {}? [y/N] ", path.display());
    io::stderr().flush()?;
    let mut answer = String::new();
    io::stdin().read_line(&mut answer)?;
    if answer.trim() != "y" {
        bail!("configuration replacement cancelled");
    }
    Ok(())
}

fn shell_quote(path: &Path) -> anyhow::Result<String> {
    let text = path
        .to_str()
        .context("initialization paths must be valid UTF-8")?;
    Ok(format!("'{}'", text.replace('\'', "'\\''")))
}

fn resource_table(resources: &[protocol::Resource], verbose: bool) -> comfy_table::Table {
    let show_user = resources.iter().any(|resource| !resource.user.is_empty());
    let mut table = comfy_table::Table::new();
    table.load_style(comfy_table::presets::UTF8_FULL_CONDENSED);
    let mut header = vec!["Name", "Max duration", "Status"];
    if show_user {
        header.push("User");
    }
    if verbose {
        header.push("ID");
    }
    table.set_header(header);
    for resource in resources {
        let status = if resource.active {
            "active"
        } else {
            "disabled"
        };
        let mut row = vec![
            resource.name.clone(),
            humantime::format_duration(Duration::from_secs(resource.max_duration)).to_string(),
            status.into(),
        ];
        if show_user {
            row.push(resource.user.clone());
        }
        if verbose {
            row.push(resource.id.clone());
        }
        table.add_row(row);
    }
    table
}

/// The OpenSSH certificate path for a public key: `id_ed25519.pub` becomes
/// `id_ed25519-cert.pub`.
pub fn certificate_path(public_key: &Path) -> anyhow::Result<PathBuf> {
    let name = public_key
        .file_name()
        .and_then(|name| name.to_str())
        .context("invalid public key filename")?;
    let stem = name
        .strip_suffix(".pub")
        .filter(|stem| !stem.ends_with("-cert"))
        .context("public key path must end with .pub and must not be a certificate")?;
    Ok(public_key.with_file_name(format!("{stem}-cert.pub")))
}

/// Find the single public key in an SSH directory.
pub fn discover_key(ssh_dir: &Path) -> anyhow::Result<PathBuf> {
    const CANDIDATES: [&str; 6] = [
        "id_ed25519.pub",
        "id_ecdsa.pub",
        "id_rsa.pub",
        "id_dsa.pub",
        "id_ed25519_sk.pub",
        "id_ecdsa_sk.pub",
    ];
    let found: Vec<PathBuf> = CANDIDATES
        .iter()
        .map(|name| ssh_dir.join(name))
        .filter(|path| path.is_file())
        .collect();
    match found.as_slice() {
        [path] => Ok(path.clone()),
        [] => bail!("no SSH public key found; run easy-sshca gen-key"),
        _ => bail!("multiple SSH public keys found; select one with --file"),
    }
}

fn admin_command(admin: Admin) -> anyhow::Result<(Operation, Command)> {
    let mut command = new_command();
    let op = match admin {
        Admin::Zone { command: zone } => match zone {
            Zone::Add { name, max_duration } => {
                command.name = name;
                command.max_duration = auth::parse_duration(&max_duration)?;
                Operation::CreateZone
            }
            Zone::Import {
                name,
                max_duration,
                source,
            } => {
                auth::validate_name(&name)?;
                command.name = name;
                command.max_duration = auth::parse_duration(&max_duration)?;
                let pem = source.read()?;
                crate::signing::import(&pem)?;
                command.secret = pem.to_string();
                Operation::ImportZone
            }
            Zone::List { page } => {
                page.apply(&mut command);
                Operation::ListZones
            }
            Zone::Update { name, update } => {
                command.name = name;
                update.apply(&mut command)?;
                Operation::UpdateZone
            }
            Zone::Remove { name } => {
                command.name = name;
                Operation::RemoveZone
            }
        },
        Admin::User { command: user } => match user {
            User::Add { name, max_duration } => {
                command.name = name;
                command.max_duration = auth::parse_duration(&max_duration)?;
                Operation::CreateUser
            }
            User::List { page } => {
                page.apply(&mut command);
                Operation::ListUsers
            }
            User::Update { name, update } => {
                command.name = name;
                update.apply(&mut command)?;
                Operation::UpdateUser
            }
            User::Remove { name } => {
                command.name = name;
                Operation::RemoveUser
            }
            User::Zone {
                command: UserZone::Grant { user, zone },
            } => {
                command.user = user;
                command.zone = zone;
                Operation::GrantZone
            }
            User::Zone {
                command: UserZone::Revoke { user, zone },
            } => {
                command.user = user;
                command.zone = zone;
                Operation::RevokeZone
            }
            User::Zone {
                command: UserZone::List { user, page },
            } => {
                command.user = user;
                page.apply(&mut command);
                Operation::ListUserZones
            }
            User::Totp {
                command: AdminTotp::Clear { user },
            } => {
                command.user = user;
                Operation::ClearTotp
            }
        },
        Admin::AccessToken { command: token } => match token {
            AccessToken::Add {
                user,
                name,
                max_duration,
                ..
            } => {
                command.user = user;
                command.name = name;
                command.max_duration = auth::parse_duration(&max_duration)?;
                Operation::CreateAccessToken
            }
            AccessToken::List { user, page } => {
                command.user = user;
                page.apply(&mut command);
                Operation::ListAccessTokens
            }
            AccessToken::Update { user, name, update } => {
                command.user = user;
                command.name = name;
                update.apply(&mut command)?;
                Operation::UpdateAccessToken
            }
            AccessToken::Remove { user, name } => {
                command.user = user;
                command.name = name;
                Operation::RemoveAccessToken
            }
        },
        Admin::Key { .. } => bail!("rotation requires its recovery workflow"),
    };
    Ok((op, command))
}

/// The journal of an in-progress key rotation.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRotation {
    operation: String,
    command: Command,
    config: ClientConfig,
}

fn print_enrollment_qr(uri: &str) -> anyhow::Result<()> {
    let code = qrcode::QrCode::new(uri)?;
    let rendered = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    let terminal = io::stdout().is_terminal();
    for line in rendered.lines() {
        if terminal {
            // Force black on white so inverted terminal themes keep the code scannable.
            println!("\x1b[30;47m{line}\x1b[0m");
        } else {
            println!("{line}");
        }
    }
    Ok(())
}
