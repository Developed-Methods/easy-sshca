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
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.permissions().mode() & 0o077 != 0 {
        bail!(
            "{} must be a private regular file; run chmod 600 {}",
            path.display(),
            path.display()
        );
    }
    use std::io::Read;
    let mut data = String::new();
    file.take(1024 * 1024 + 1).read_to_string(&mut data)?;
    if data.len() > 1024 * 1024 {
        bail!("file exceeds 1 MiB");
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
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text=zeroize::Zeroizing::new(secure_read(path).with_context(||format!("cannot load {}; run easy-sshca configure --server https://HOST:9443 --api-key-stdin",path.display()))?);
        let mut config: Self = serde_saphyr::from_str(&text).map_err(|_| {
            anyhow::anyhow!("invalid client YAML: check fields, duplicate keys and types")
        })?;
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
        let mut c: Self =
            serde_saphyr::from_str(&fs::read_to_string(path)?).context("invalid server YAML")?;
        if c.version != 1 {
            bail!("unsupported server configuration version");
        }
        if !(1024..=1048576).contains(&c.limits.request_bytes)
            || !(1..=4096).contains(&c.limits.database_queue)
        {
            bail!("invalid request or database queue limit");
        }
        crate::auth::parse_duration(&c.limits.rpc_timeout)?;
        let parent = path.parent().unwrap_or(Path::new("."));
        c.database = resolve(&c.database, parent)?;
        c.tls.certificate = resolve(&c.tls.certificate, parent)?;
        c.tls.private_key = resolve(&c.tls.private_key, parent)?;
        fs::read(&c.tls.certificate).context("cannot read TLS certificate")?;
        secure_read(&c.tls.private_key).context("cannot read TLS private key")?;
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
