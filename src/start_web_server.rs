use std::time::Duration;

use super::server_config::ServerConfig;
use super::web_server::WebServer;
use http_app::{HttpServer, HttpServerSettings, HttpTls};
use tokio::task::JoinHandle;

pub struct StartWebServerConfig {
    pub config_path: String,
}

impl StartWebServerConfig {
    pub async fn start(self) -> Result<JoinHandle<()>, std::io::Error> {
        let config_path = self.config_path;

        let mut current_config = Self::load_confg(&config_path)
            .await?
            .validate()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let listen_addr = current_config.as_config().listen_addr;
        let cert_data = tokio::fs::read(&current_config.as_config().paths.tls_cert).await?;
        let key_data = tokio::fs::read(&current_config.as_config().paths.tls_key).await?;

        let web = WebServer::new(current_config.clone());
        let server = HttpServer::new(
            web.clone(),
            HttpServerSettings {
                tls: Some(HttpTls::WithBytes {
                    cert: cert_data,
                    key: key_data,
                }),
                ..Default::default()
            },
        );

        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;

                let loaded = match Self::load_confg(&config_path).await {
                    Ok(config) => config,
                    Err(error) => {
                        tracing::error!(?error, "failed to load config");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }
                };

                if loaded.eq(current_config.as_config()) {
                    continue;
                }

                let valid = match loaded.validate() {
                    Ok(valid) => valid,
                    Err(error) => {
                        tracing::error!(?error, "loaded config is invalid");
                        tokio::time::sleep(Duration::from_secs(3)).await;
                        continue;
                    }
                };

                current_config = valid.clone();
                web.update_config(valid).await;
                tracing::info!("config updated");
            }
        });

        server.start(listen_addr).await?;
        Ok(handle)
    }

    async fn load_confg(path: &str) -> Result<ServerConfig, std::io::Error> {
        let data = tokio::fs::read(path).await?;
        if path.ends_with(".yml") || path.ends_with(".yaml") {
            serde_yml::from_slice(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        } else {
            serde_json::from_slice(&data)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        }
    }
}
