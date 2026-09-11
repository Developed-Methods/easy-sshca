//! Client and server configuration files, plus the private-file helpers they share.

use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::{Zeroize, Zeroizing};

pub const DEFAULT_RPC_PORT: u16 = 9443;
pub const DEFAULT_HTTPS_PORT: u16 = 9444;
const CONFIG_VERSION: u32 = 1;
const MAX_FILE_BYTES: usize = 1024 * 1024;
const STDIN_PATH: &str = "-";

pub fn default_server() -> String {
    format!("https://localhost:{DEFAULT_RPC_PORT}")
}

/// Normalise `HOST[:PORT]` or an HTTPS origin into `https://HOST:PORT`.
pub fn server_address(address: &str, port: Option<u16>) -> anyhow::Result<String> {
    let address = if address.contains("://") {
        address.to_owned()
    } else {
        format!("https://{address}")
    };
    validate_server(&address)?;
    let url = url::Url::parse(&address)?;
    // Parse the authority separately to preserve an explicit HTTPS port of 443.
    let authority = address
        .split_once("://")
        .map(|(_, rest)| rest.trim_end_matches('/'))
        .unwrap_or_default();
    let authority: tonic::codegen::http::uri::Authority =
        authority.parse().context("invalid server address")?;
    let port = port.or(authority.port_u16()).unwrap_or(DEFAULT_RPC_PORT);
    if port == 0 {
        bail!("server port must be between 1 and 65535");
    }
    let host = url.host_str().context("invalid server address")?;
    Ok(format!("https://{host}:{port}"))
}

pub fn validate_server(value: &str) -> anyhow::Result<()> {
    let url = url::Url::parse(value).context("invalid server URL")?;
    let is_origin = url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/";
    if !is_origin {
        bail!("server must be an HTTPS origin without credentials, path, query or fragment");
    }
    Ok(())
}

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub version: u32,
    pub server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_secret_file: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ca_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_server_name: Option<String>,
    #[serde(default)]
    pub defaults: Defaults,
}

#[derive(Serialize, Deserialize, Clone, Default)]
#[serde(deny_unknown_fields)]
pub struct Defaults {
    pub zone: Option<String>,
    pub public_key: Option<PathBuf>,
    pub duration: Option<String>,
}

impl ClientConfig {
    /// A configuration that only knows the server; credentials and trust are unset.
    pub fn new(server: String) -> Self {
        Self {
            version: CONFIG_VERSION,
            server,
            api_key: None,
            api_key_file: None,
            bootstrap_secret: None,
            bootstrap_secret_file: None,
            tls_ca: None,
            tls_ca_pem: None,
            tls_server_name: None,
            defaults: Defaults::default(),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != CONFIG_VERSION {
            bail!("unsupported config version; use version 1 or upgrade easy-sshca");
        }
        validate_server(&self.server)?;
        if let Some(name) = &self.tls_server_name {
            rustls::pki_types::ServerName::try_from(name.as_str())
                .context("tls_server_name must be a DNS name or IP address")?;
        }
        if self.tls_ca.is_some() && self.tls_ca_pem.is_some() {
            bail!("configure only one of tls_ca and tls_ca_pem");
        }
        if self.api_key.is_some() && self.api_key_file.is_some() {
            bail!("configure only one of api_key and api_key_file");
        }
        if self.bootstrap_secret.is_some() && self.bootstrap_secret_file.is_some() {
            bail!("configure only one of bootstrap_secret and bootstrap_secret_file");
        }
        if is_blank(&self.tls_ca_pem) {
            bail!("tls_ca_pem must contain a PEM certificate");
        }
        if let Some(key) = &self.api_key {
            crate::auth::parse_key(key)?;
        }
        if let Some(secret) = &self.bootstrap_secret {
            crate::auth::parse_bootstrap_secret(secret)?;
        }
        if let Some(zone) = &self.defaults.zone {
            crate::auth::validate_name(zone)?;
        }
        if let Some(duration) = &self.defaults.duration {
            crate::auth::parse_duration(duration)?;
        }
        Ok(())
    }

    /// Serialize as JSON when `path` has a `.json` extension, otherwise as YAML.
    pub fn serialize_for(&self, path: &Path) -> anyhow::Result<Zeroizing<String>> {
        let text = if is_json(path) {
            serde_json::to_string_pretty(self)?
        } else {
            serde_saphyr::to_string(self)?
        };
        Ok(Zeroizing::new(text))
    }

    /// The trusted TLS certificate PEM, from file or inline, if any.
    pub fn tls_pem(&self) -> anyhow::Result<Option<String>> {
        self.validate()?;
        match &self.tls_ca {
            Some(path) => fs::read_to_string(path)
                .with_context(|| format!("cannot read TLS CA certificate {}", path.display()))
                .map(Some),
            None => Ok(self.tls_ca_pem.clone()),
        }
    }

    pub fn api_key_value(&self) -> anyhow::Result<Option<Zeroizing<String>>> {
        let value = secret_from(&self.api_key, &self.api_key_file, "api_key")?;
        if let Some(value) = &value {
            crate::auth::parse_key(value)?;
        }
        Ok(value)
    }

    pub fn bootstrap_secret_value(&self) -> anyhow::Result<Option<Zeroizing<String>>> {
        let value = secret_from(
            &self.bootstrap_secret,
            &self.bootstrap_secret_file,
            "bootstrap_secret",
        )?;
        if let Some(value) = &value {
            crate::auth::parse_bootstrap_secret(value)?;
        }
        Ok(value)
    }

    /// Load and validate a client configuration, resolving relative paths
    /// against the configuration file's directory.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = read_config(path).with_context(|| {
            format!(
                "cannot load {}; run easy-sshca configure --server https://HOST:9443 --api-key-stdin",
                path.display()
            )
        })?;
        let mut config: Self = if is_json(path) {
            serde_json::from_str(&text).map_err(|_| {
                anyhow::anyhow!("invalid client JSON: check fields, duplicate keys and types")
            })?
        } else {
            serde_saphyr::from_str(&text).map_err(|_| {
                anyhow::anyhow!("invalid client YAML: check fields, duplicate keys and types")
            })?
        };
        config.validate()?;
        let base = path.parent().unwrap_or(Path::new("."));
        if let Some(tls_ca) = &mut config.tls_ca {
            *tls_ca = resolve(tls_ca, base)?;
            fs::read(&*tls_ca).context("cannot read TLS CA")?;
        }
        for file in [
            &mut config.api_key_file,
            &mut config.bootstrap_secret_file,
            &mut config.defaults.public_key,
        ]
        .into_iter()
        .flatten()
        {
            *file = resolve(file, base)?;
        }
        config.api_key_value()?;
        config.bootstrap_secret_value()?;
        Ok(config)
    }
}

impl Drop for ClientConfig {
    fn drop(&mut self) {
        self.api_key.zeroize();
        self.bootstrap_secret.zeroize();
    }
}

/// Read a secret from an inline value or a private file, never both.
fn secret_from(
    inline: &Option<String>,
    file: &Option<PathBuf>,
    field: &str,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    match (inline, file) {
        (Some(value), None) => Ok(Some(Zeroizing::new(value.clone()))),
        (None, Some(path)) => Ok(Some(Zeroizing::new(secure_read(path)?.trim().to_owned()))),
        (None, None) => Ok(None),
        (Some(_), Some(_)) => bail!("configure only one of {field} and {field}_file"),
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub version: u32,
    #[serde(default = "default_server")]
    pub server: String,
    pub database: PathBuf,
    pub rpc_listen: SocketAddr,
    pub https_listen: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metrics_listen: Option<SocketAddr>,
    pub tls: Tls,
    pub limits: Limits,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_pem: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_pem: Option<String>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub request_bytes: usize,
    pub rpc_timeout: String,
    pub database_queue: usize,
}

impl ServerConfig {
    /// Load and validate a server configuration, resolving relative paths
    /// against the configuration file's directory.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = read_config(path).with_context(|| {
            format!(
                "cannot read server configuration {}. For a new server, run easy-sshca server init --name NAME --folder NEW_FOLDER. Otherwise, select an existing file with --config PATH",
                path.display()
            )
        })?;
        let mut config: Self = serde_saphyr::from_str(&text).map_err(|_| {
            anyhow::anyhow!(
                "invalid server YAML in {}; check field names, types and duplicate keys",
                path.display()
            )
        })?;
        config.validate(path)?;
        config.server = server_address(&config.server, None)
            .context("invalid server address in server configuration")?;
        let base = path.parent().unwrap_or(Path::new("."));
        config.database = resolve(&config.database, base)?;
        if let Some(certificate) = &mut config.tls.certificate {
            *certificate = resolve(certificate, base)?;
            fs::read(&*certificate).with_context(|| {
                format!(
                    "cannot read TLS certificate {}; check tls.certificate in {} and file read permissions",
                    certificate.display(),
                    path.display()
                )
            })?;
        }
        if let Some(private_key) = &mut config.tls.private_key {
            *private_key = resolve(private_key, base)?;
            secure_read(private_key).with_context(|| {
                format!(
                    "cannot read TLS private key {}; check tls.private_key in {}",
                    private_key.display(),
                    path.display()
                )
            })?;
        }
        Ok(config)
    }

    fn validate(&self, path: &Path) -> anyhow::Result<()> {
        let at = path.display();
        if self.version != CONFIG_VERSION {
            bail!(
                "{at}: unsupported version {}; expected version: 1",
                self.version
            );
        }
        if !(1024..=1_048_576).contains(&self.limits.request_bytes) {
            bail!(
                "{at}: limits.request_bytes must be between 1024 and 1048576; got {}",
                self.limits.request_bytes
            );
        }
        if !(1..=4096).contains(&self.limits.database_queue) {
            bail!(
                "{at}: limits.database_queue must be between 1 and 4096; got {}",
                self.limits.database_queue
            );
        }
        crate::auth::parse_duration(&self.limits.rpc_timeout).with_context(|| {
            format!("{at}: invalid limits.rpc_timeout; use a positive duration such as 10s")
        })?;
        if self.tls.certificate.is_some() == self.tls.certificate_pem.is_some() {
            bail!("{at}: configure exactly one of tls.certificate and tls.certificate_pem");
        }
        if self.tls.private_key.is_some() == self.tls.private_key_pem.is_some() {
            bail!("{at}: configure exactly one of tls.private_key and tls.private_key_pem");
        }
        if is_blank(&self.tls.certificate_pem) {
            bail!("{at}: tls.certificate_pem must contain a PEM certificate");
        }
        if is_blank(&self.tls.private_key_pem) {
            bail!("{at}: tls.private_key_pem must contain a PEM private key");
        }
        Ok(())
    }

    pub fn certificate_pem(&self) -> anyhow::Result<Vec<u8>> {
        match (&self.tls.certificate, &self.tls.certificate_pem) {
            (Some(path), None) => fs::read(path)
                .with_context(|| format!("cannot read TLS certificate {}", path.display())),
            (None, Some(pem)) => Ok(pem.as_bytes().to_vec()),
            _ => bail!("configure exactly one TLS certificate source"),
        }
    }

    pub fn private_key_pem(&self) -> anyhow::Result<Zeroizing<String>> {
        match (&self.tls.private_key, &self.tls.private_key_pem) {
            (Some(path), None) => secure_read(path).map(Zeroizing::new),
            (None, Some(pem)) => Ok(Zeroizing::new(pem.clone())),
            _ => bail!("configure exactly one TLS private-key source"),
        }
    }
}

impl Drop for ServerConfig {
    fn drop(&mut self) {
        self.tls.private_key_pem.zeroize();
    }
}

fn is_json(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
}

fn is_blank(value: &Option<String>) -> bool {
    value.as_ref().is_some_and(|text| text.trim().is_empty())
}

pub fn default_path() -> anyhow::Result<PathBuf> {
    let root = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(dir) => PathBuf::from(dir),
        None => home::home_dir()
            .context("home directory unavailable")?
            .join(".config"),
    };
    Ok(root.join("easy-sshca/config.yaml"))
}

/// Make `path` absolute: expand a leading `~/`, otherwise join it to `base`.
pub fn resolve(path: &Path, base: &Path) -> anyhow::Result<PathBuf> {
    if let Ok(suffix) = path.strip_prefix("~/") {
        return Ok(home::home_dir()
            .context("home directory unavailable")?
            .join(suffix));
    }
    Ok(if path.is_absolute() {
        path.into()
    } else if base.is_absolute() {
        base.join(path)
    } else {
        std::env::current_dir()?.join(base).join(path)
    })
}

/// Read a regular file that only its owner can access, refusing symlinks.
pub fn secure_read(path: &Path) -> anyhow::Result<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .with_context(|| {
            format!(
                "cannot open private file {}; check file existence and read permissions (symbolic links are not allowed)",
                path.display()
            )
        })?;
    let meta = file
        .metadata()
        .with_context(|| format!("cannot inspect {}", path.display()))?;
    if !meta.is_file() {
        bail!("{} must be a regular file", path.display());
    }
    if meta.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} is readable or writable by other users; restrict permissions with chmod 600 {}",
            path.display(),
            path.display()
        );
    }
    let mut data = String::new();
    let within_limit = read_bounded(file, &mut data)
        .with_context(|| format!("cannot read {} as UTF-8 text", path.display()))?;
    if !within_limit {
        bail!("{} exceeds the 1 MiB file limit", path.display());
    }
    Ok(data)
}

/// Read UTF-8 text into `buffer`, stopping just past the file limit.
/// Returns `false` when the input was larger than the limit.
///
/// The caller owns the buffer so secrets can be read into zeroizing memory,
/// including input that is then rejected.
fn read_bounded(reader: impl Read, buffer: &mut String) -> std::io::Result<bool> {
    reader
        .take(MAX_FILE_BYTES as u64 + 1)
        .read_to_string(buffer)?;
    Ok(buffer.len() <= MAX_FILE_BYTES)
}

fn read_config(path: &Path) -> anyhow::Result<Zeroizing<String>> {
    if path != Path::new(STDIN_PATH) {
        return secure_read(path).map(Zeroizing::new);
    }
    let mut text = Zeroizing::new(String::new());
    let within_limit = read_bounded(std::io::stdin().lock(), &mut text)
        .context("cannot read configuration from stdin as UTF-8 text")?;
    if !within_limit {
        bail!("configuration from stdin exceeds the 1 MiB file limit");
    }
    Ok(text)
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}

/// Create the parent directory of `path` with mode 0700 if it does not exist.
pub fn private_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)?;
    }
    Ok(())
}

/// Create a new file with `mode`, failing if it already exists.
pub fn exclusive(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    private_parent(path)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(path)
        .with_context(|| format!("cannot exclusively create {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    sync_parent(path)
}

/// Write `bytes` to a private temporary file beside `path`, ready to persist.
pub fn staged(path: &Path, bytes: &[u8]) -> anyhow::Result<tempfile::NamedTempFile> {
    private_parent(path)?;
    let mut file = tempfile::NamedTempFile::new_in(parent_dir(path))?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    Ok(file)
}

pub fn sync_parent(path: &Path) -> anyhow::Result<()> {
    fs::File::open(parent_dir(path))?.sync_all()?;
    Ok(())
}

/// Replace `path` atomically with a private file containing `bytes`.
pub fn atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    staged(path, bytes)?.persist(path)?;
    sync_parent(path)
}
