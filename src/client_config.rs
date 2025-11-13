use std::borrow::Cow;

use home::home_dir;
use serde::{Deserialize, Serialize};

use crate::config_file::read_config;

#[derive(Serialize, Deserialize)]
pub struct ClientConfig {
    pub client_name: String,
    pub api_key: String,
    pub server_addr: String,
    pub server_crt: String,
}

impl ClientConfig {
    pub async fn load(config_path: Option<String>) -> Result<Self, ClientConfigError> {
        let (path, rel) = 'find_path: {
            match home_dir() {
                None => (
                    config_path.ok_or(ClientConfigError::MissingConfigPath)?,
                    Cow::Borrowed("./"),
                ),
                Some(homedir) => {
                    let dir = homedir
                        .to_str()
                        .ok_or(ClientConfigError::MissingConfigPath)?;
                    let dir = format!("{dir}/.config/easy_sshca");

                    let base_path = format!("{dir}/config");

                    let json_path = format!("{base_path}.json");
                    if tokio::fs::try_exists(&json_path).await.unwrap_or(false) {
                        break 'find_path (json_path, Cow::Owned(dir.to_string()));
                    }

                    let yml_path = format!("{base_path}.yml");
                    if tokio::fs::try_exists(&yml_path).await.unwrap_or(false) {
                        break 'find_path (yml_path, Cow::Owned(dir.to_string()));
                    }

                    let yaml_path = format!("{base_path}.yaml");
                    if tokio::fs::try_exists(&yaml_path).await.unwrap_or(false) {
                        break 'find_path (yaml_path, Cow::Owned(dir.to_string()));
                    }

                    return Err(ClientConfigError::MissingConfigPath);
                }
            }
        };

        let mut config = read_config::<ClientConfig>(&path)
            .await
            .ok_or(ClientConfigError::FailedToParseConfig)?;

        config.client_name = value_or_file(&config.client_name, &rel)
            .await
            .map_err(|e| ClientConfigError::FailedToReadFile("client_name", e))?;

        config.api_key = value_or_file(&config.api_key, &rel)
            .await
            .map_err(|e| ClientConfigError::FailedToReadFile("api_key", e))?;

        config.server_addr = value_or_file(&config.server_addr, &rel)
            .await
            .map_err(|e| ClientConfigError::FailedToReadFile("server_addr", e))?;

        config.server_crt = value_or_file(&config.server_crt, &rel)
            .await
            .map_err(|e| ClientConfigError::FailedToReadFile("server_crt", e))?;

        Ok(config)
    }
}

#[derive(Debug)]
pub enum ClientConfigError {
    MissingConfigPath,
    FailedToParseConfig,
    FailedToReadFile(&'static str, std::io::Error),
}

async fn value_or_file(s: &str, rel_folder: &str) -> Result<String, std::io::Error> {
    let s = s.trim();
    if let Some(mut path) = s.strip_prefix("file:") {
        path = path.trim();

        let path_res = if let Some(rel_path) = path.strip_prefix("./") {
            Cow::Owned(format!("{}/{}", rel_folder, rel_path))
        } else {
            Cow::Borrowed(path)
        };

        return match tokio::fs::read_to_string(&*path_res).await {
            Ok(v) => Ok(v),
            Err(error) => Err(error),
        };
    }

    Ok(s.to_string())
}
