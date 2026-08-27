use std::{collections::HashMap, fmt::Display, net::SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatedConfig(ServerConfig);

impl ValidatedConfig {
    pub fn into_config(self) -> ServerConfig {
        self.0
    }

    pub fn as_config(&self) -> &ServerConfig {
        &self.0
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerConfig {
    pub listen_addr: SocketAddr,
    pub tls_cert: Vec<u8>,
    pub tls_key: Vec<u8>,
    pub users: Vec<User>,
    pub clients: Vec<Client>,
    pub targets: Vec<Target>,
}

impl ServerConfig {
    pub fn validate(&self) -> Result<ValidatedConfig, ConfigValidateError> {
        let mut users = HashMap::new();
        let mut clients = HashMap::new();
        let mut targets = HashMap::new();

        for user in &self.users {
            validate_name(&user.name, ConfigSource::User)?;
            if let Some(existing) = users.insert(&user.name, user) {
                return Err(ConfigValidateError::DuplicateName(
                    ConfigSource::User,
                    existing.name.clone(),
                ));
            }
        }

        for client in &self.clients {
            validate_name(&client.name, ConfigSource::Client)?;
            if let Some(existing) = clients.insert(&client.name, client) {
                return Err(ConfigValidateError::DuplicateName(
                    ConfigSource::Client,
                    existing.name.clone(),
                ));
            }
        }

        for target in &self.targets {
            validate_name(&target.name, ConfigSource::Target)?;
            if let Some(existing) = targets.insert(&target.name, target) {
                return Err(ConfigValidateError::DuplicateName(
                    ConfigSource::Target,
                    existing.name.clone(),
                ));
            }
        }

        for user in &self.users {
            for client in &user.allowed_clients {
                if !clients.contains_key(client) {
                    return Err(ConfigValidateError::NotFound(
                        ConfigSource::User,
                        user.name.clone(),
                        ConfigSource::Client,
                        client.clone(),
                    ));
                }
            }

            for target in &user.allowed_targets {
                if !targets.contains_key(target) {
                    return Err(ConfigValidateError::NotFound(
                        ConfigSource::User,
                        user.name.clone(),
                        ConfigSource::Target,
                        target.clone(),
                    ));
                }
            }
        }

        Ok(ValidatedConfig(self.clone()))
    }
}

fn validate_name(name: &str, source: ConfigSource) -> Result<(), ConfigValidateError> {
    assert_validname(name).map_err(|name| ConfigValidateError::InvalidName(source, name))
}

pub fn assert_validname(s: &str) -> Result<(), String> {
    if s.is_empty()
        || s.as_bytes()
            .iter()
            .any(|c| !c.is_ascii_alphanumeric() && *c != b'_' && *c != b'-')
    {
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
}

impl Display for ConfigValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}

impl std::error::Error for ConfigValidateError {}

#[derive(Debug)]
pub enum ConfigSource {
    User,
    Client,
    Target,
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
    #[serde(default)]
    pub totp_secret: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Client {
    pub name: String,
    #[serde(default)]
    pub max_duration: SignDuration,
    #[serde(default)]
    pub api_key: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Target {
    pub name: String,
    #[serde(default)]
    pub max_duration: SignDuration,
    #[serde(default)]
    pub ca_private_key: String,
    #[serde(default)]
    pub ca_public_key: String,
}

#[derive(
    Default,
    Debug,
    Serialize,
    Deserialize,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    clap::ValueEnum,
)]
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

    pub fn database_str(&self) -> &'static str {
        match self {
            SignDuration::Minute => "minute",
            SignDuration::Hour => "hour",
            SignDuration::Day => "day",
            SignDuration::Week => "week",
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
mod tests {
    use super::*;

    #[test]
    fn empty_names_are_invalid() {
        assert!(assert_validname("").is_err());
    }

    #[test]
    fn database_durations_round_trip() {
        for duration in [
            SignDuration::Minute,
            SignDuration::Hour,
            SignDuration::Day,
            SignDuration::Week,
        ] {
            assert_eq!(
                SignDuration::from_param_str(duration.database_str()),
                Some(duration)
            );
        }
    }
}
