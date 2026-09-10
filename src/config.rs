use anyhow::{Context, bail};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    net::SocketAddr,
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    pub version: u32,
    pub server: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ca: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_ca_pem: Option<String>,
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
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub version: u32,
    pub database: PathBuf,
    pub rpc_listen: SocketAddr,
    pub https_listen: SocketAddr,
    pub tls: Tls,
    pub limits: Limits,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub certificate: PathBuf,
    pub private_key: PathBuf,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub request_bytes: usize,
    pub rpc_timeout: String,
    pub database_queue: usize,
}
pub fn default_path() -> anyhow::Result<PathBuf> {
    let root = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(x) => PathBuf::from(x),
        None => home::home_dir()
            .context("home directory unavailable")?
            .join(".config"),
    };
    Ok(root.join("easy-sshca/config.yaml"))
}
pub fn resolve(path: &Path, parent: &Path) -> anyhow::Result<PathBuf> {
    if let Ok(suffix) = path.strip_prefix("~/") {
        return Ok(home::home_dir()
            .context("home directory unavailable")?
            .join(suffix));
    }
    Ok(if path.is_absolute() {
        path.into()
    } else if parent.is_absolute() {
        parent.join(path)
    } else {
        std::env::current_dir()?.join(parent).join(path)
    })
}
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
    use std::io::Read;
    let mut data = String::new();
    file.take(1024 * 1024 + 1)
        .read_to_string(&mut data)
        .with_context(|| format!("cannot read {} as UTF-8 text", path.display()))?;
    if data.len() > 1024 * 1024 {
        bail!("{} exceeds the 1 MiB file limit", path.display());
    }
    Ok(data)
}
pub fn validate_server(value: &str) -> anyhow::Result<()> {
    let u = url::Url::parse(value).context("invalid server URL")?;
    if u.scheme() != "https"
        || u.host_str().is_none()
        || !u.username().is_empty()
        || u.password().is_some()
        || u.query().is_some()
        || u.fragment().is_some()
        || u.path() != "/"
    {
        bail!("server must be an HTTPS origin without credentials, path, query or fragment");
    }
    Ok(())
}
impl ClientConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        if self.version != 1 {
            bail!("unsupported config version; use version 1 or upgrade easy-sshca");
        }
        validate_server(&self.server)?;
        if self.tls_ca.is_some() && self.tls_ca_pem.is_some() {
            bail!("configure only one of tls_ca and tls_ca_pem");
        }
        if self
            .tls_ca_pem
            .as_ref()
            .is_some_and(|pem| pem.trim().is_empty())
        {
            bail!("tls_ca_pem must contain a PEM certificate");
        }
        if let Some(x) = &self.api_key {
            crate::auth::key(x)?;
        }
        if let Some(x) = &self.defaults.zone {
            crate::auth::name(x)?;
        }
        if let Some(x) = &self.defaults.duration {
            crate::auth::parse_duration(x)?;
        }
        Ok(())
    }
    pub fn serialize_for(&self, path: &Path) -> anyhow::Result<zeroize::Zeroizing<String>> {
        let text = if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            serde_json::to_string_pretty(self)?
        } else {
            serde_saphyr::to_string(self)?
        };
        Ok(zeroize::Zeroizing::new(text))
    }
    pub fn tls_pem(&self) -> anyhow::Result<Option<String>> {
        self.validate()?;
        if let Some(path) = &self.tls_ca {
            Ok(Some(fs::read_to_string(path).with_context(|| {
                format!("cannot read TLS CA certificate {}", path.display())
            })?))
        } else {
            Ok(self.tls_ca_pem.clone())
        }
    }
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text=zeroize::Zeroizing::new(secure_read(path).with_context(||format!("cannot load {}; run easy-sshca configure --server https://HOST:9443 --api-key-stdin",path.display()))?);
        let mut config: Self = if path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("json"))
        {
            serde_json::from_str(&text).map_err(|_| {
                anyhow::anyhow!("invalid client JSON: check fields, duplicate keys and types")
            })?
        } else {
            serde_saphyr::from_str(&text).map_err(|_| {
                anyhow::anyhow!("invalid client YAML: check fields, duplicate keys and types")
            })?
        };
        config.validate()?;
        let parent = path.parent().unwrap_or(Path::new("."));
        if let Some(x) = &mut config.tls_ca {
            *x = resolve(x, parent)?;
            fs::read(&*x).context("cannot read TLS CA")?;
        }
        if let Some(x) = &mut config.defaults.public_key {
            *x = resolve(x, parent)?;
        }
        Ok(config)
    }
}
impl Drop for ClientConfig {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(s) = &mut self.api_key {
            s.zeroize();
        }
    }
}
impl ServerConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = fs::read_to_string(path).with_context(|| {
            format!(
                "cannot read server configuration {}. For a new server, run easy-sshca server init --name NAME --folder NEW_FOLDER. Otherwise, select an existing file with --config PATH",
                path.display()
            )
        })?;
        let mut c: Self = serde_saphyr::from_str(&text).map_err(|_| {
            anyhow::anyhow!(
                "invalid server YAML in {}; check field names, types and duplicate keys",
                path.display()
            )
        })?;
        if c.version != 1 {
            bail!(
                "{}: unsupported version {}; expected version: 1",
                path.display(),
                c.version
            );
        }
        if !(1024..=1048576).contains(&c.limits.request_bytes) {
            bail!(
                "{}: limits.request_bytes must be between 1024 and 1048576; got {}",
                path.display(),
                c.limits.request_bytes
            );
        }
        if !(1..=4096).contains(&c.limits.database_queue) {
            bail!(
                "{}: limits.database_queue must be between 1 and 4096; got {}",
                path.display(),
                c.limits.database_queue
            );
        }
        crate::auth::parse_duration(&c.limits.rpc_timeout).with_context(|| {
            format!(
                "{}: invalid limits.rpc_timeout; use a positive duration such as 10s",
                path.display()
            )
        })?;
        let parent = path.parent().unwrap_or(Path::new("."));
        c.database = resolve(&c.database, parent)?;
        c.tls.certificate = resolve(&c.tls.certificate, parent)?;
        c.tls.private_key = resolve(&c.tls.private_key, parent)?;
        fs::read(&c.tls.certificate).with_context(|| format!("cannot read TLS certificate {}; check tls.certificate in {} and file read permissions", c.tls.certificate.display(), path.display()))?;
        secure_read(&c.tls.private_key).with_context(|| {
            format!(
                "cannot read TLS private key {}; check tls.private_key in {}",
                c.tls.private_key.display(),
                path.display()
            )
        })?;
        Ok(c)
    }
}
pub fn private_parent(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder.create(parent)?;
    }
    Ok(())
}
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
    sync_parent(path)?;
    Ok(())
}
pub fn staged(path: &Path, bytes: &[u8]) -> anyhow::Result<tempfile::NamedTempFile> {
    private_parent(path)?;
    let mut f = tempfile::NamedTempFile::new_in(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?;
    f.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    f.write_all(bytes)?;
    f.as_file().sync_all()?;
    Ok(f)
}
pub fn sync_parent(path: &Path) -> anyhow::Result<()> {
    fs::File::open(
        path.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new(".")),
    )?
    .sync_all()?;
    Ok(())
}
pub fn atomic(path: &Path, bytes: &[u8]) -> anyhow::Result<()> {
    staged(path, bytes)?.persist(path)?;
    sync_parent(path)
}
