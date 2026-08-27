use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::{
    server_config::{Client, ServerConfig, Target, User},
    server_database::DatabaseError,
};

pub async fn load_legacy_config(path: impl AsRef<Path>) -> Result<ServerConfig, DatabaseError> {
    let path = path.as_ref();
    let content = tokio::fs::read(path).await?;
    let legacy: LegacyConfig = if matches!(
        path.extension().and_then(|value| value.to_str()),
        Some("yml" | "yaml")
    ) {
        serde_yml::from_slice(&content).map_err(|error| {
            DatabaseError::InvalidData(format!("invalid YAML configuration: {error}"))
        })?
    } else {
        serde_json::from_slice(&content).map_err(|error| {
            DatabaseError::InvalidData(format!("invalid JSON configuration: {error}"))
        })?
    };

    let tls_cert = tokio::fs::read(&legacy.paths.tls_cert).await?;
    let tls_key = tokio::fs::read(&legacy.paths.tls_key).await?;

    let mut clients = Vec::with_capacity(legacy.clients.len());
    for mut client in legacy.clients {
        if client.api_key.is_empty() {
            let path = legacy.paths.api_path(&client.name)?;
            client.api_key = tokio::fs::read_to_string(path).await?;
        }
        clients.push(client);
    }

    let mut targets = Vec::with_capacity(legacy.targets.len());
    for mut target in legacy.targets {
        if target.ca_private_key.is_empty() {
            let path = legacy.paths.ca_private_path(&target.name)?;
            target.ca_private_key = tokio::fs::read_to_string(path).await?;
        }
        if target.ca_public_key.is_empty() {
            let path = legacy.paths.ca_public_path(&target.name)?;
            target.ca_public_key = tokio::fs::read_to_string(path).await?;
        }
        targets.push(target);
    }

    let mut users = Vec::with_capacity(legacy.users.len());
    for mut user in legacy.users {
        if user.totp_secret.is_none() {
            let path = legacy.paths.totp_path(&user.name)?;
            user.totp_secret = match tokio::fs::read_to_string(path).await {
                Ok(value) => Some(value),
                Err(error)
                    if error.kind() == std::io::ErrorKind::NotFound && user.allow_missing_totp =>
                {
                    None
                }
                Err(error) => return Err(error.into()),
            };
        }
        users.push(user);
    }

    Ok(ServerConfig {
        listen_addr: legacy.listen_addr,
        tls_cert,
        tls_key,
        users,
        clients,
        targets,
    })
}

#[derive(Deserialize)]
struct LegacyConfig {
    listen_addr: std::net::SocketAddr,
    #[serde(default)]
    users: Vec<User>,
    #[serde(default)]
    clients: Vec<Client>,
    #[serde(default)]
    targets: Vec<Target>,
    paths: LegacyPaths,
}

#[derive(Deserialize)]
struct LegacyPaths {
    root: Option<PathBuf>,
    #[serde(alias = "totp")]
    totp_secret: Option<PathBuf>,
    #[serde(alias = "ca")]
    ca_secret: Option<PathBuf>,
    #[serde(alias = "api")]
    api_secret: Option<PathBuf>,
    #[serde(alias = "tls_crt")]
    tls_cert: PathBuf,
    tls_key: PathBuf,
}

impl LegacyPaths {
    fn totp_path(&self, user: &str) -> Result<PathBuf, DatabaseError> {
        self.secret_path(&self.totp_secret, "totp", user, "totp")
    }

    fn api_path(&self, client: &str) -> Result<PathBuf, DatabaseError> {
        self.secret_path(&self.api_secret, "api", client, "key")
    }

    fn ca_private_path(&self, target: &str) -> Result<PathBuf, DatabaseError> {
        let directory = self.directory(&self.ca_secret, "ca")?;
        Ok(directory.join(target))
    }

    fn ca_public_path(&self, target: &str) -> Result<PathBuf, DatabaseError> {
        self.secret_path(&self.ca_secret, "ca", target, "pub")
    }

    fn secret_path(
        &self,
        configured: &Option<PathBuf>,
        root_directory: &str,
        name: &str,
        extension: &str,
    ) -> Result<PathBuf, DatabaseError> {
        let directory = self.directory(configured, root_directory)?;
        Ok(directory.join(format!("{name}.{extension}")))
    }

    fn directory(
        &self,
        configured: &Option<PathBuf>,
        root_directory: &str,
    ) -> Result<PathBuf, DatabaseError> {
        configured
            .clone()
            .or_else(|| self.root.as_ref().map(|root| root.join(root_directory)))
            .ok_or_else(|| {
                DatabaseError::InvalidData(format!(
                    "legacy configuration has no {root_directory} path"
                ))
            })
    }
}

#[cfg(test)]
mod tests {
    use indoc::formatdoc;

    use super::*;

    #[test]
    fn legacy_paths_use_their_matching_directories() {
        let paths = LegacyPaths {
            root: Some(PathBuf::from("/root")),
            totp_secret: Some(PathBuf::from("/secrets/totp")),
            ca_secret: Some(PathBuf::from("/secrets/ca")),
            api_secret: Some(PathBuf::from("/secrets/api")),
            tls_cert: PathBuf::from("cert"),
            tls_key: PathBuf::from("key"),
        };

        assert_eq!(
            paths.ca_private_path("production").unwrap(),
            PathBuf::from("/secrets/ca/production")
        );
        assert_eq!(
            paths.api_path("laptop").unwrap(),
            PathBuf::from("/secrets/api/laptop.key")
        );
    }

    #[tokio::test]
    async fn legacy_configuration_imports_referenced_files() {
        let directory = temp_dir::TempDir::new().unwrap();
        let root = directory.path();
        for child in ["api", "ca", "totp"] {
            tokio::fs::create_dir(root.join(child)).await.unwrap();
        }

        tokio::fs::write(root.join("tls.crt"), "certificate")
            .await
            .unwrap();
        tokio::fs::write(root.join("tls.key"), "TLS key")
            .await
            .unwrap();
        tokio::fs::write(root.join("api/laptop.key"), "API key")
            .await
            .unwrap();
        tokio::fs::write(root.join("ca/production"), "CA private key")
            .await
            .unwrap();
        tokio::fs::write(root.join("ca/production.pub"), "CA public key")
            .await
            .unwrap();
        tokio::fs::write(root.join("totp/alice.totp"), "TOTP secret")
            .await
            .unwrap();

        let source = root.join("config.yml");
        tokio::fs::write(
            &source,
            formatdoc!(
                "
                listen_addr: 127.0.0.1:9292
                users:
                  - name: alice
                    targets: [production]
                    clients: [laptop]
                clients:
                  - name: laptop
                targets:
                  - name: production
                paths:
                  root: {}
                  tls_crt: {}
                  tls_key: {}
                ",
                root.display(),
                root.join("tls.crt").display(),
                root.join("tls.key").display(),
            ),
        )
        .await
        .unwrap();

        let imported = load_legacy_config(source).await.unwrap();

        assert_eq!(imported.tls_cert, b"certificate");
        assert_eq!(imported.clients[0].api_key, "API key");
        assert_eq!(imported.targets[0].ca_private_key, "CA private key");
        assert_eq!(imported.targets[0].ca_public_key, "CA public key");
        assert_eq!(
            imported.users[0].totp_secret.as_deref(),
            Some("TOTP secret")
        );
    }
}
