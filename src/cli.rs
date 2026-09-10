use crate::{
    auth,
    config::{self, ClientConfig},
    protocol::{self, Command, Reply},
};
use anyhow::{Context, bail};
use clap::{Args, Parser, Subcommand};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, IsTerminal, Read, Write},
    path::{Path, PathBuf},
    time::Duration,
};
use tonic::{
    Request,
    transport::{Certificate, Channel, ClientTlsConfig},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(version, about = "Encrypted SSH certificate authority")]
pub struct Cli {
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
    #[arg(long, global = true)]
    pub json: bool,
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
    Configure {
        #[arg(long)]
        server: String,
        #[arg(long)]
        api_key_stdin: bool,
        #[arg(long)]
        tls_ca: Option<PathBuf>,
        #[arg(long)]
        zone: Option<String>,
        #[arg(long)]
        public_key: Option<PathBuf>,
        #[arg(long)]
        duration: Option<String>,
    },
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
    Sign {
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
    },
    Totp {
        #[command(subcommand)]
        command: Totp,
    },
    RotateToken {
        #[arg(long)]
        totp_stdin: bool,
    },
}
#[derive(Args, Default)]
pub struct ConnectionArgs {
    #[arg(long)]
    server: Option<String>,
    #[arg(long)]
    tls_ca: Option<PathBuf>,
}
#[derive(Subcommand)]
pub enum Server {
    Init {
        #[arg(long)]
        name: String,
        #[arg(long)]
        db: PathBuf,
        #[arg(long)]
        admin_api_key_file: Option<PathBuf>,
        #[arg(long)]
        secret_output: Option<PathBuf>,
        #[arg(long)]
        admin_output: Option<PathBuf>,
    },
    Start {
        #[arg(long)]
        db: Option<PathBuf>,
        #[arg(long)]
        rpc_listen: Option<std::net::SocketAddr>,
        #[arg(long)]
        https_listen: Option<std::net::SocketAddr>,
    },
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
    List {
        #[command(flatten)]
        page: Page,
    },
    Update {
        name: String,
        #[command(flatten)]
        update: Update,
    },
}
#[derive(Args, Default)]
pub struct Page {
    #[arg(long, default_value_t = 100)]
    page_size: u32,
    #[arg(long, default_value = "")]
    page_token: String,
}
#[derive(Args)]
pub struct Update {
    #[arg(long)]
    max_duration: Option<String>,
    #[arg(long)]
    active: Option<bool>,
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
    GrantZone {
        user: String,
        zone: String,
    },
    RevokeZone {
        user: String,
        zone: String,
    },
    Totp {
        #[command(subcommand)]
        command: AdminTotp,
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

pub fn read_secret(stdin: bool, prompt: &str) -> anyhow::Result<Zeroizing<String>> {
    let value = if stdin {
        let mut value = String::new();
        io::stdin().take(4097).read_to_string(&mut value)?;
        if value.len() > 4096 {
            bail!("secret input exceeds 4096 bytes");
        }
        value.trim_end_matches(['\r', '\n']).to_owned()
    } else {
        rpassword::prompt_password(prompt)?
    };
    Ok(Zeroizing::new(value))
}
fn command() -> Command {
    Command {
        request_id: auth::id(),
        ..Default::default()
    }
}
fn output(json: bool, value: impl Serialize, human: &str) -> anyhow::Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string(&serde_json::json!({"version":1,"result":value}))?
        );
    } else {
        println!("{human}");
    }
    Ok(())
}
fn output_reply(json: bool, reply: &Reply) -> anyhow::Result<()> {
    if json {
        return output(true, reply, "");
    }
    if !reply.api_key.is_empty() {
        println!("{}", reply.api_key);
    } else if !reply.state.is_empty() {
        println!("{}", reply.state);
    } else if !reply.public_key.is_empty() {
        println!("{}\n{}", reply.public_key, reply.fingerprint);
    } else if !reply.resources.is_empty() {
        for r in &reply.resources {
            println!(
                "{}\t{}\t{}s\t{}\t{}",
                r.id,
                r.name,
                r.max_duration,
                if r.active { "active" } else { "disabled" },
                r.user
            );
        }
        if !reply.next_page_token.is_empty() {
            eprintln!("Next page: --page-token {}", reply.next_page_token);
        }
    } else {
        println!("OK {}", reply.request_id);
    }
    Ok(())
}
fn load(path: &Path, overrides: ConnectionArgs) -> anyhow::Result<ClientConfig> {
    let mut c = if path.exists() {
        ClientConfig::load(path)?
    } else if let Some(server) = &overrides.server {
        ClientConfig {
            version: 1,
            server: server.clone(),
            api_key: None,
            tls_ca: None,
            defaults: Default::default(),
        }
    } else {
        return ClientConfig::load(path);
    };
    if let Some(s) = overrides.server {
        c.server = s;
    }
    if let Some(p) = overrides.tls_ca {
        c.tls_ca = Some(config::resolve(&p, &std::env::current_dir()?)?);
    }
    c.validate()?;
    Ok(c)
}
pub async fn channel(c: &ClientConfig) -> anyhow::Result<Channel> {
    c.validate()?;
    let mut tls = ClientTlsConfig::new().with_native_roots();
    if let Some(ca) = &c.tls_ca {
        tls = ClientTlsConfig::new().ca_certificate(Certificate::from_pem(fs::read(ca)?));
    }
    Ok(Channel::from_shared(c.server.clone())?
        .tls_config(tls)?
        .timeout(Duration::from_secs(10))
        .connect_timeout(Duration::from_secs(10))
        .connect()
        .await?)
}
pub async fn rpc(c: &ClientConfig, op: &str, cmd: Command) -> anyhow::Result<Reply> {
    let channel = channel(c).await?;
    let mut request = Request::new(cmd);
    request.set_timeout(Duration::from_secs(10));
    if let Some(key) = &c.api_key {
        let mut metadata = Zeroizing::new(format!("Bearer {key}"))
            .parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>()?;
        metadata.set_sensitive(true);
        request.metadata_mut().insert("authorization", metadata);
    }
    let response = match op {
        "GetStatus" => {
            protocol::bootstrap_service_client::BootstrapServiceClient::new(channel)
                .get_status(request)
                .await?
        }
        "Unlock" => {
            protocol::bootstrap_service_client::BootstrapServiceClient::new(channel)
                .unlock(request)
                .await?
        }
        "CreateZone" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .create_zone(request)
                .await?
        }
        "ListZones" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .list_zones(request)
                .await?
        }
        "UpdateZone" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .update_zone(request)
                .await?
        }
        "CreateUser" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .create_user(request)
                .await?
        }
        "ListUsers" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .list_users(request)
                .await?
        }
        "UpdateUser" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .update_user(request)
                .await?
        }
        "RemoveUser" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .remove_user(request)
                .await?
        }
        "GrantZone" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .grant_zone(request)
                .await?
        }
        "RevokeZone" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .revoke_zone(request)
                .await?
        }
        "CreateAccessToken" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .create_access_token(request)
                .await?
        }
        "ListAccessTokens" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .list_access_tokens(request)
                .await?
        }
        "UpdateAccessToken" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .update_access_token(request)
                .await?
        }
        "RemoveAccessToken" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .remove_access_token(request)
                .await?
        }
        "ClearTotp" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .clear_totp(request)
                .await?
        }
        "RotateAdminKey" => {
            protocol::admin_service_client::AdminServiceClient::new(channel)
                .rotate_admin_key(request)
                .await?
        }
        "BeginTotpEnrollment" => {
            protocol::user_service_client::UserServiceClient::new(channel)
                .begin_totp_enrollment(request)
                .await?
        }
        "ConfirmTotpEnrollment" => {
            protocol::user_service_client::UserServiceClient::new(channel)
                .confirm_totp_enrollment(request)
                .await?
        }
        "RotateToken" => {
            protocol::user_service_client::UserServiceClient::new(channel)
                .rotate_token(request)
                .await?
        }
        "SignCertificate" => {
            protocol::signing_service_client::SigningServiceClient::new(channel)
                .sign_certificate(request)
                .await?
        }
        "GetPublicKey" => {
            protocol::ca_service_client::CaServiceClient::new(channel)
                .get_public_key(request)
                .await?
        }
        _ => bail!("unknown RPC operation"),
    };
    Ok(response.into_inner())
}
pub async fn run(cli: Cli) -> anyhow::Result<()> {
    let path = cli
        .config
        .clone()
        .map(Ok)
        .unwrap_or_else(config::default_path)?;
    let json = cli.json;
    if cli.config.is_some()
        && !path.exists()
        && !matches!(
            &cli.command,
            Action::Configure { .. }
                | Action::GenKey { .. }
                | Action::Server {
                    command: Server::Init { .. } | Server::ResetAdmin { .. } | Server::Start { .. }
                }
        )
    {
        bail!(
            "explicit configuration file does not exist: {}",
            path.display()
        );
    }
    match cli.command {
        Action::Server {
            command:
                Server::Init {
                    name,
                    db,
                    admin_api_key_file,
                    secret_output,
                    admin_output,
                },
        } => {
            let secret = auth::random_secret();
            let supplied = admin_api_key_file.is_some();
            let admin = if let Some(p) = admin_api_key_file {
                Zeroizing::new(config::secure_read(&p)?.trim().into())
            } else {
                auth::new_key("ad")
            };
            if auth::key(&admin)?.kind != "ad" {
                bail!("supplied credential must be an admin key");
            }
            let secret_path =
                secret_output.unwrap_or_else(|| db.with_extension("bootstrap-secret"));
            let admin_path = admin_output.unwrap_or_else(|| db.with_extension("admin-key"));
            if db.exists() {
                bail!("database already exists");
            }
            config::exclusive(&secret_path, format!("{}\n", *secret).as_bytes(), 0o600)?;
            if !supplied {
                config::exclusive(&admin_path, format!("{}\n", *admin).as_bytes(), 0o600)?;
            }
            crate::storage::Database::initialize(&db, &secret, &admin, &name).context(
                "initialization failed; protected credential files remain for inspection",
            )?;
            output(
                json,
                serde_json::json!({"database":db,"bootstrap_secret_file":secret_path,"admin_key_file":if supplied {None}else{Some(&admin_path)}}),
                &format!(
                    "Initialized {}\nBootstrap secret: {}{}",
                    db.display(),
                    secret_path.display(),
                    if supplied {
                        String::new()
                    } else {
                        format!("\nAdmin key: {}", admin_path.display())
                    }
                ),
            )
        }
        Action::Server {
            command:
                Server::Start {
                    db,
                    rpc_listen,
                    https_listen,
                },
        } => {
            let server_path = cli
                .config
                .unwrap_or_else(|| PathBuf::from("/etc/easy-sshca/server.yaml"));
            let mut c = config::ServerConfig::load(&server_path)?;
            if let Some(db) = db {
                c.database = db;
            }
            if let Some(addr) = rpc_listen {
                c.rpc_listen = addr;
            }
            if let Some(addr) = https_listen {
                c.https_listen = addr;
            }
            crate::server::run(c).await
        }
        Action::Server {
            command:
                Server::ResetAdmin {
                    db,
                    secret_stdin,
                    admin_output,
                },
        } => {
            let secret = read_secret(secret_stdin, "Bootstrap secret: ")?;
            let mut database = crate::storage::Database::open(&db, &secret)?;
            let replacement = auth::new_key("ad");
            config::exclusive(
                &admin_output,
                format!("{}\n", *replacement).as_bytes(),
                0o600,
            )?;
            database.reset_admin(&replacement)?;
            output(
                json,
                serde_json::json!({"admin_key_file":admin_output}),
                &format!("Admin key saved to {}", admin_output.display()),
            )
        }
        Action::Server {
            command: Server::Status { connection },
        } => {
            let c = load(&path, connection)?;
            output_reply(json, &rpc(&c, "GetStatus", command()).await?)
        }
        Action::Server {
            command:
                Server::Unlock {
                    secret_stdin,
                    connection,
                },
        } => {
            let c = load(&path, connection)?;
            let mut cmd = command();
            cmd.secret = read_secret(secret_stdin, "Bootstrap secret: ")?.to_string();
            output_reply(json, &rpc(&c, "Unlock", cmd).await?)
        }
        Action::Configure {
            server,
            api_key_stdin,
            tls_ca,
            zone,
            public_key,
            duration,
        } => {
            config::private_parent(&path)?;
            let _lock = crate::storage::lock(&path)?;
            if path.with_extension("rotation.yaml").exists() {
                bail!("finish the pending credential rotation before replacing this configuration");
            }
            if path.exists() {
                if !io::stdin().is_terminal() {
                    bail!(
                        "configuration exists; use an interactive terminal to confirm replacement"
                    );
                }
                eprint!("Replace {}? [y/N] ", path.display());
                io::stderr().flush()?;
                let mut answer = String::new();
                io::stdin().read_line(&mut answer)?;
                if answer.trim() != "y" {
                    bail!("configuration replacement cancelled");
                }
            }
            let key = read_secret(api_key_stdin, "API key (leave empty for public commands): ")?;
            let cwd = std::env::current_dir()?;
            let c = ClientConfig {
                version: 1,
                server,
                api_key: if key.is_empty() {
                    None
                } else {
                    Some(key.to_string())
                },
                tls_ca: tls_ca.map(|p| config::resolve(&p, &cwd)).transpose()?,
                defaults: config::Defaults {
                    zone,
                    public_key: public_key.map(|p| config::resolve(&p, &cwd)).transpose()?,
                    duration,
                },
            };
            c.validate()?;
            if let Some(p) = &c.tls_ca {
                fs::read(p).context("cannot read TLS CA")?;
            }
            config::atomic(
                &path,
                Zeroizing::new(serde_saphyr::to_string(&c)?).as_bytes(),
            )?;
            output(
                json,
                serde_json::json!({"config":path}),
                &format!("Saved {}", path.display()),
            )
        }
        Action::GenKey { file, comment } => {
            let file = file.unwrap_or(
                home::home_dir()
                    .context("home directory unavailable")?
                    .join(".ssh/id_ed25519"),
            );
            let public = PathBuf::from(format!("{}.pub", file.display()));
            if file.exists() || public.exists() {
                bail!("key files already exist");
            }
            let key = crate::signing::generate(&comment)?;
            let pem = key.to_openssh(ssh_key::LineEnding::LF)?;
            config::exclusive(&file, pem.as_bytes(), 0o600)?;
            config::exclusive(
                &public,
                format!("{}\n", key.public_key().to_openssh()?).as_bytes(),
                0o644,
            )?;
            output(
                json,
                serde_json::json!({"private_key":file,"public_key":public}),
                &format!("Created {} and {}", file.display(), public.display()),
            )
        }
        Action::PubKey { zone, connection } => {
            let c = load(&path, connection)?;
            let mut cmd = command();
            cmd.zone = zone
                .or(c.defaults.zone.clone())
                .context("zone is required")?;
            output_reply(json, &rpc(&c, "GetPublicKey", cmd).await?)
        }
        Action::Sign {
            zone,
            file,
            duration,
            totp_stdin,
            force,
            connection,
        } => {
            let c = load(&path, connection)?;
            let file = match file.or(c.defaults.public_key.clone()) {
                Some(p) => config::resolve(&p, &std::env::current_dir()?)?,
                None => discover_key(
                    &home::home_dir()
                        .context("home directory unavailable")?
                        .join(".ssh"),
                )?,
            };
            let cert = certificate_path(&file)?;
            if cert.exists() && !force {
                bail!("certificate exists; pass --force to replace it");
            }
            let mut cmd = command();
            cmd.zone = zone
                .or(c.defaults.zone.clone())
                .context("zone is required")?;
            cmd.duration = auth::parse_duration(
                &duration
                    .or(c.defaults.duration.clone())
                    .unwrap_or_else(|| "1d".into()),
            )?;
            cmd.public_key = fs::read_to_string(&file)?;
            if totp_stdin {
                cmd.totp = read_secret(true, "")?.to_string();
            }
            let reply = match rpc(&c, "SignCertificate", cmd.clone()).await {
                Err(e) if !totp_stdin && totp_required(&e) => {
                    cmd.totp = read_secret(false, "TOTP code: ")?.to_string();
                    rpc(&c, "SignCertificate", cmd).await?
                }
                result => result?,
            };
            if force {
                config::atomic(&cert, format!("{}\n", reply.certificate).as_bytes())?;
            } else {
                config::exclusive(&cert, format!("{}\n", reply.certificate).as_bytes(), 0o644)?;
            }
            output(
                json,
                serde_json::json!({"request_id":reply.request_id,"certificate_file":cert,"expires_at":reply.expires_at,"effective_duration":reply.effective_duration}),
                &format!(
                    "Saved {} ({}s; expires {})",
                    cert.display(),
                    reply.effective_duration,
                    reply.expires_at
                ),
            )
        }
        Action::Totp {
            command: Totp::Enroll,
        } => {
            let c = load(&path, ConnectionArgs::default())?;
            let enrollment = rpc(&c, "BeginTotpEnrollment", command()).await?;
            if json {
                return output_reply(true, &enrollment);
            }
            print_enrollment_qr(&enrollment.otpauth_uri)?;
            println!("\n{}\n", enrollment.secret);
            let mut cmd = command();
            cmd.totp = read_secret(false, "Confirm TOTP code: ")?.to_string();
            output_reply(false, &rpc(&c, "ConfirmTotpEnrollment", cmd).await?)
        }
        Action::Totp {
            command: Totp::Confirm { totp_stdin },
        } => {
            let c = load(&path, ConnectionArgs::default())?;
            let mut cmd = command();
            cmd.totp = read_secret(totp_stdin, "Confirm TOTP code: ")?.to_string();
            output_reply(json, &rpc(&c, "ConfirmTotpEnrollment", cmd).await?)
        }
        Action::RotateToken { totp_stdin } => rotate(&path, "RotateToken", totp_stdin, json).await,
        Action::Admin {
            command: Admin::Key {
                command: AdminKey::RotateAdmin,
            },
        } => rotate(&path, "RotateAdminKey", false, json).await,
        Action::Admin { command: admin } => {
            let c = load(&path, ConnectionArgs::default())?;
            let (op, cmd) = admin_command(admin)?;
            output_reply(json, &rpc(&c, op, cmd).await?)
        }
    }
}
fn totp_required(e: &anyhow::Error) -> bool {
    use prost::Message;
    e.downcast_ref::<tonic::Status>()
        .and_then(|s| protocol::ErrorDetail::decode(s.details()).ok())
        .is_some_and(|d| d.totp_required)
}
pub fn certificate_path(public: &Path) -> anyhow::Result<PathBuf> {
    let name = public
        .file_name()
        .and_then(|s| s.to_str())
        .context("invalid public key filename")?;
    let stem = name
        .strip_suffix(".pub")
        .filter(|s| !s.ends_with("-cert"))
        .context("public key path must end with .pub and must not be a certificate")?;
    Ok(public.with_file_name(format!("{stem}-cert.pub")))
}
pub fn discover_key(ssh: &Path) -> anyhow::Result<PathBuf> {
    let candidates = [
        "id_ed25519.pub",
        "id_ecdsa.pub",
        "id_rsa.pub",
        "id_dsa.pub",
        "id_ed25519_sk.pub",
        "id_ecdsa_sk.pub",
    ]
    .iter()
    .map(|p| ssh.join(p))
    .filter(|p| p.is_file())
    .collect::<Vec<_>>();
    match candidates.as_slice() {
        [p] => Ok(p.clone()),
        [] => bail!("no SSH public key found; run easy-sshca gen-key"),
        _ => bail!("multiple SSH public keys found; select one with --file"),
    }
}
fn admin_command(admin: Admin) -> anyhow::Result<(&'static str, Command)> {
    let mut c = command();
    let op = match admin {
        Admin::Zone {
            command: Zone::Add { name, max_duration },
        } => {
            c.name = name;
            c.max_duration = auth::parse_duration(&max_duration)?;
            "CreateZone"
        }
        Admin::Zone {
            command: Zone::List { page },
        } => {
            c.page_size = page.page_size;
            c.page_token = page.page_token;
            "ListZones"
        }
        Admin::Zone {
            command: Zone::Update { name, update },
        } => {
            c.name = name;
            apply_update(&mut c, update)?;
            "UpdateZone"
        }
        Admin::User {
            command: User::Add { name, max_duration },
        } => {
            c.name = name;
            c.max_duration = auth::parse_duration(&max_duration)?;
            "CreateUser"
        }
        Admin::User {
            command: User::List { page },
        } => {
            c.page_size = page.page_size;
            c.page_token = page.page_token;
            "ListUsers"
        }
        Admin::User {
            command: User::Update { name, update },
        } => {
            c.name = name;
            apply_update(&mut c, update)?;
            "UpdateUser"
        }
        Admin::User {
            command: User::Remove { name },
        } => {
            c.name = name;
            "RemoveUser"
        }
        Admin::User {
            command: User::GrantZone { user, zone },
        } => {
            c.user = user;
            c.zone = zone;
            "GrantZone"
        }
        Admin::User {
            command: User::RevokeZone { user, zone },
        } => {
            c.user = user;
            c.zone = zone;
            "RevokeZone"
        }
        Admin::User {
            command: User::Totp {
                command: AdminTotp::Clear { user },
            },
        } => {
            c.user = user;
            "ClearTotp"
        }
        Admin::AccessToken {
            command:
                AccessToken::Add {
                    user,
                    name,
                    max_duration,
                },
        } => {
            c.user = user;
            c.name = name;
            c.max_duration = auth::parse_duration(&max_duration)?;
            "CreateAccessToken"
        }
        Admin::AccessToken {
            command: AccessToken::List { user, page },
        } => {
            c.user = user;
            c.page_size = page.page_size;
            c.page_token = page.page_token;
            "ListAccessTokens"
        }
        Admin::AccessToken {
            command: AccessToken::Update { user, name, update },
        } => {
            c.user = user;
            c.name = name;
            apply_update(&mut c, update)?;
            "UpdateAccessToken"
        }
        Admin::AccessToken {
            command: AccessToken::Remove { user, name },
        } => {
            c.user = user;
            c.name = name;
            "RemoveAccessToken"
        }
        Admin::Key { .. } => bail!("rotation requires its recovery workflow"),
    };
    Ok((op, c))
}
fn apply_update(c: &mut Command, update: Update) -> anyhow::Result<()> {
    c.max_duration = update
        .max_duration
        .map(|s| auth::parse_duration(&s))
        .transpose()?
        .unwrap_or(0);
    c.active = update.active;
    Ok(())
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingRotation {
    operation: String,
    command: Command,
    config: ClientConfig,
}
async fn rotate(path: &Path, op: &str, totp_stdin: bool, json: bool) -> anyhow::Result<()> {
    let _lock = crate::storage::lock(path)?;
    let current = ClientConfig::load(path)?;
    let pending_path = path.with_extension("rotation.yaml");
    let candidate_path = path.with_extension("candidate.yaml");
    let recovering = pending_path.exists();
    let mut pending = if recovering {
        let data = Zeroizing::new(config::secure_read(&pending_path)?);
        let p: PendingRotation = serde_saphyr::from_str(&data)
            .map_err(|_| anyhow::anyhow!("invalid pending rotation file"))?;
        if p.operation != op || p.config.server != current.server {
            bail!("pending rotation belongs to a different operation or server");
        }
        p
    } else {
        let old = auth::key(current.api_key.as_deref().context("API key required")?)?;
        let expected = if op == "RotateToken" { "at" } else { "ad" };
        if old.kind != expected {
            bail!("wrong credential kind for rotation");
        }
        let mut cmd = command();
        cmd.replacement_key = auth::new_key(expected).to_string();
        if totp_stdin {
            cmd.totp = read_secret(true, "")?.to_string();
        }
        let mut replacement = current.clone();
        replacement.api_key = Some(cmd.replacement_key.clone());
        let p = PendingRotation {
            operation: op.into(),
            command: cmd,
            config: replacement,
        };
        config::exclusive(
            &pending_path,
            Zeroizing::new(serde_saphyr::to_string(&p)?).as_bytes(),
            0o600,
        )?;
        p
    };
    config::atomic(
        &candidate_path,
        Zeroizing::new(serde_saphyr::to_string(&pending.config)?).as_bytes(),
    )?;
    let mut result = rpc(&current, op, pending.command.clone()).await;
    if result.as_ref().is_err_and(|e| {
        use prost::Message;
        e.downcast_ref::<tonic::Status>()
            .and_then(|s| protocol::ErrorDetail::decode(s.details()).ok())
            .is_some_and(|d| matches!(d.reason.as_str(), "TOTP_REQUIRED" | "INVALID_TOTP"))
    }) && (!totp_stdin || recovering)
    {
        pending.command.totp = read_secret(totp_stdin, "TOTP code: ")?.to_string();
        config::atomic(
            &pending_path,
            Zeroizing::new(serde_saphyr::to_string(&pending)?).as_bytes(),
        )?;
        result = rpc(&current, op, pending.command.clone()).await;
    }
    for _ in 0..2 {
        if result.as_ref().is_err_and(|e| {
            e.downcast_ref::<tonic::Status>().is_none_or(|s| {
                matches!(
                    s.code(),
                    tonic::Code::Unavailable | tonic::Code::DeadlineExceeded
                )
            })
        }) {
            result = rpc(&current, op, pending.command.clone()).await;
        } else {
            break;
        }
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
    output_reply(json, &reply)
}

fn print_enrollment_qr(uri: &str) -> anyhow::Result<()> {
    let code = qrcode::QrCode::new(uri)?;
    let rendered = code
        .render::<qrcode::render::unicode::Dense1x2>()
        .quiet_zone(true)
        .build();
    for line in rendered.lines() {
        if io::stdout().is_terminal() {
            println!("\x1b[30;47m{line}\x1b[0m");
        } else {
            println!("{line}");
        }
    }
    Ok(())
}
