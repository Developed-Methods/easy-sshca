use std::{collections::HashMap, fmt::Display, net::SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct ValidatedConfig(Config);

impl ValidatedConfig {
    pub fn into_config(self) -> Config {
        self.0
    }

    pub fn as_config(&self) -> &Config {
        &self.0
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Config {
    pub listen_addr: SocketAddr,
    pub users: Vec<User>,
    pub clients: Vec<Client>,
    pub targets: Vec<Target>,
    pub paths: Paths,
}

impl Config {
    pub fn validate(&self) -> Result<ValidatedConfig, ConfigValidateError> {
        if self.paths.root.is_none() {
            if self.paths.totp_secret.is_none() {
                return Err(ConfigValidateError::MissingPath("totp"));
            }

            if self.paths.ca_secret.is_none() {
                return Err(ConfigValidateError::MissingPath("ca"));
            }

            if self.paths.api_secret.is_none() {
                return Err(ConfigValidateError::MissingPath("api"));
            }
        }

        let mut users = HashMap::new();
        let mut clients = HashMap::new();
        let mut targets = HashMap::new();

        for user in &self.users {
            assert_validname(&user.name).map_err(|n| ConfigValidateError::InvalidName(ConfigSource::User, n))?;
            if let Some(existing) = users.insert(&user.name, user) {
                return Err(ConfigValidateError::DuplicateName(ConfigSource::User, existing.name.clone()));
            }
        }

        for client in &self.clients {
            assert_validname(&client.name).map_err(|n| ConfigValidateError::InvalidName(ConfigSource::Client, n))?;
            if let Some(existing) = clients.insert(&client.name, client) {
                return Err(ConfigValidateError::DuplicateName(ConfigSource::Client, existing.name.clone()));
            }
        }

        for target in &self.targets {
            assert_validname(&target.name).map_err(|n| ConfigValidateError::InvalidName(ConfigSource::Target, n))?;
            if let Some(existing) = targets.insert(&target.name, target) {
                return Err(ConfigValidateError::DuplicateName(ConfigSource::Target, existing.name.clone()));
            }
        }

        for user in &self.users {
            for client in &user.allowed_clients {
                if !clients.contains_key(client) {
                    return Err(ConfigValidateError::NotFound(ConfigSource::User, user.name.clone(), ConfigSource::Client, client.clone()));
                }
            }
            for target in &user.allowed_targets {
                if !targets.contains_key(target) {
                    return Err(ConfigValidateError::NotFound(ConfigSource::User, user.name.clone(), ConfigSource::Target, target.clone()));
                }
            }
        }

        Ok(ValidatedConfig(self.clone()))
    }
}

pub fn assert_validname(s: &str) -> Result<(), String> {
    if s.as_bytes().iter().any(|c| !c.is_ascii_alphanumeric() && *c != b'_' && *c != b'-') {
        Err(s.to_string())
    } else {
        Ok(())
    }
}

#[derive(Debug)]
pub enum ConfigValidateError {
    InvalidName(ConfigSource, String),
    DuplicateName(ConfigSource, String),
    NotFound(ConfigSource, String, ConfigSource, String),
    MissingPath(&'static str),
}

impl Display for ConfigValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for ConfigValidateError {
}

#[derive(Debug)]
pub enum ConfigSource {
    User,
    Client,
    Target
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct User {
    pub name: String,
    #[serde(alias = "targets")]
    pub allowed_targets: Vec<String>,
    #[serde(alias = "clients")]
    pub allowed_clients: Vec<String>,
    #[serde(default)]
    pub max_duration: SignDuration,
    #[serde(default)]
    pub allow_missing_totp: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Paths {
    pub root: Option<String>,

    #[serde(alias = "totp")]
    pub totp_secret: Option<String>,
    #[serde(alias = "ca")]
    pub ca_secret: Option<String>,
    #[serde(alias = "api")]
    pub api_secret: Option<String>,

    #[serde(alias = "tls_crt")]
    pub tls_cert: String,
    pub tls_key: String,
}

impl Paths {
    pub fn totp_path(&self, user: &str) -> String {
        assert_eq!(assert_validname(user), Ok(()));

        if let Some(base) = &self.totp_secret {
            format!("{}/{}.totp", base, user)
        } else if let Some(root) = &self.root {
            format!("{}/totp/{}.totp", root, user)
        } else {
            panic!("root and totp paths not defined")
        }
    }

    pub fn ca_path(&self, target: &str) -> String {
        assert_eq!(assert_validname(target), Ok(()));

        if let Some(base) = &self.totp_secret {
            format!("{}/{}.pub", base, target)
        } else if let Some(root) = &self.root {
            format!("{}/ca/{}.pub", root, target)
        } else {
            panic!("root and ca paths not defined")
        }
    }

    pub fn ca_priv_path(&self, target: &str) -> String {
        assert_eq!(assert_validname(target), Ok(()));

        if let Some(base) = &self.totp_secret {
            format!("{}/{}", base, target)
        } else if let Some(root) = &self.root {
            format!("{}/ca/{}", root, target)
        } else {
            panic!("root and ca paths not defined")
        }
    }

    pub fn api_path(&self, client: &str) -> String {
        assert_eq!(assert_validname(client), Ok(()));

        if let Some(base) = &self.totp_secret {
            format!("{}/{}.key", base, client)
        } else if let Some(root) = &self.root {
            format!("{}/api/{}.key", root, client)
        } else {
            panic!("root and api paths not defined")
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Client {
    pub name: String,
    #[serde(default)]
    pub max_duration: SignDuration,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    #[serde(default)]
    pub max_duration: SignDuration,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, clap::ValueEnum)]
pub enum SignDuration {
    #[serde(alias = "minute")]
    Minute,
    #[serde(alias = "hour")]
    Hour,
    #[serde(alias = "day")]
    #[default]
    Day,
    #[serde(alias = "week")]
    Week,
}

impl SignDuration {
    pub fn openssh_str(&self) -> &'static str {
        match self {
            SignDuration::Minute => "+1m",
            SignDuration::Hour => "+1h",
            SignDuration::Day => "+1d",
            SignDuration::Week => "+7d",
        }
    }

    pub fn param_str(&self) -> &'static str {
        match self {
            SignDuration::Minute => "m",
            SignDuration::Hour => "h",
            SignDuration::Day => "d",
            SignDuration::Week => "w",
        }
    }

    pub fn from_param_str(s: &str) -> Option<Self> {
        match s {
            "minute" | "m" => Some(SignDuration::Minute),
            "hour" | "h" => Some(SignDuration::Hour),
            "day" | "d" => Some(SignDuration::Day),
            "week" | "w" => Some(SignDuration::Week),
            _ => None,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn config_parse_yml_test() {
        let parsed = serde_yml::from_str::<Config>(include_str!("./res/config.yml")).unwrap();
        println!("Parsed:\n{:?}", parsed);
    }
}
