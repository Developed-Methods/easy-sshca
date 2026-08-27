use std::{
    fmt::{Display, Formatter},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use indoc::indoc;
use rusqlite::{Connection, OptionalExtension, params, types::Type};

use crate::server_config::{Client, ConfigValidateError, ServerConfig, SignDuration, Target, User};

#[derive(Clone)]
pub struct ServerDatabase {
    path: Arc<PathBuf>,
}

impl ServerDatabase {
    pub async fn open(path: impl AsRef<Path>) -> Result<Self, DatabaseError> {
        let database = Self {
            path: Arc::new(path.as_ref().to_path_buf()),
        };
        database.initialize_schema().await?;
        let mut permissions = tokio::fs::metadata(database.path()).await?.permissions();
        permissions.set_mode(0o600);
        tokio::fs::set_permissions(database.path(), permissions).await?;
        Ok(database)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    async fn initialize_schema(&self) -> Result<(), DatabaseError> {
        self.with_connection(|connection| {
            #[rustfmt::skip]
            connection.execute_batch(indoc!("
                PRAGMA foreign_keys = ON;

                CREATE TABLE IF NOT EXISTS server_settings (
                    id          INTEGER PRIMARY KEY CHECK (id = 1),
                    listen_addr TEXT NOT NULL,
                    tls_cert    BLOB NOT NULL,
                    tls_key     BLOB NOT NULL
                );

                CREATE TABLE IF NOT EXISTS clients (
                    name         TEXT PRIMARY KEY
                                 CHECK (name <> '' AND name NOT GLOB '*[^A-Za-z0-9_-]*'),
                    max_duration TEXT NOT NULL DEFAULT 'day'
                                 CHECK (max_duration IN ('minute', 'hour', 'day', 'week')),
                    api_key      TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS targets (
                    name           TEXT PRIMARY KEY
                                   CHECK (name <> '' AND name NOT GLOB '*[^A-Za-z0-9_-]*'),
                    max_duration   TEXT NOT NULL DEFAULT 'day'
                                   CHECK (max_duration IN ('minute', 'hour', 'day', 'week')),
                    ca_private_key TEXT NOT NULL,
                    ca_public_key  TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS users (
                    name               TEXT PRIMARY KEY
                                       CHECK (name <> '' AND name NOT GLOB '*[^A-Za-z0-9_-]*'),
                    max_duration       TEXT NOT NULL DEFAULT 'day'
                                       CHECK (max_duration IN ('minute', 'hour', 'day', 'week')),
                    allow_missing_totp INTEGER NOT NULL DEFAULT 0
                                       CHECK (allow_missing_totp IN (0, 1)),
                    totp_secret        TEXT
                );

                CREATE TABLE IF NOT EXISTS user_clients (
                    user_name   TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
                    client_name TEXT NOT NULL REFERENCES clients(name) ON DELETE CASCADE,
                    PRIMARY KEY (user_name, client_name)
                );

                CREATE TABLE IF NOT EXISTS user_targets (
                    user_name   TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
                    target_name TEXT NOT NULL REFERENCES targets(name) ON DELETE CASCADE,
                    PRIMARY KEY (user_name, target_name)
                );
            "))?;
            Ok(())
        })
        .await
    }

    pub async fn save_config(&self, config: &ServerConfig) -> Result<(), DatabaseError> {
        config.validate()?;
        let config = config.clone();

        self.with_connection(move |connection| {
            let transaction = connection.transaction()?;

            transaction.execute("DELETE FROM user_clients", [])?;
            transaction.execute("DELETE FROM user_targets", [])?;
            transaction.execute("DELETE FROM users", [])?;
            transaction.execute("DELETE FROM clients", [])?;
            transaction.execute("DELETE FROM targets", [])?;

            #[rustfmt::skip]
            transaction.execute(indoc!("
                INSERT INTO server_settings (
                    id,
                    listen_addr,
                    tls_cert,
                    tls_key
                ) VALUES (1, ?1, ?2, ?3)
                ON CONFLICT (id) DO UPDATE SET
                    listen_addr = excluded.listen_addr,
                    tls_cert = excluded.tls_cert,
                    tls_key = excluded.tls_key
            "), params![
                config.listen_addr.to_string(),
                config.tls_cert,
                config.tls_key,
            ])?;

            for client in config.clients {
                #[rustfmt::skip]
                transaction.execute(indoc!("
                    INSERT INTO clients (
                        name,
                        max_duration,
                        api_key
                    ) VALUES (?1, ?2, ?3)
                "), params![
                    client.name,
                    client.max_duration.database_str(),
                    client.api_key,
                ])?;
            }

            for target in config.targets {
                #[rustfmt::skip]
                transaction.execute(indoc!("
                    INSERT INTO targets (
                        name,
                        max_duration,
                        ca_private_key,
                        ca_public_key
                    ) VALUES (?1, ?2, ?3, ?4)
                "), params![
                    target.name,
                    target.max_duration.database_str(),
                    target.ca_private_key,
                    target.ca_public_key,
                ])?;
            }

            for user in config.users {
                #[rustfmt::skip]
                transaction.execute(indoc!("
                    INSERT INTO users (
                        name,
                        max_duration,
                        allow_missing_totp,
                        totp_secret
                    ) VALUES (?1, ?2, ?3, ?4)
                "), params![
                    user.name,
                    user.max_duration.database_str(),
                    user.allow_missing_totp,
                    user.totp_secret,
                ])?;

                for client in user.allowed_clients {
                    #[rustfmt::skip]
                    transaction.execute(indoc!("
                        INSERT INTO user_clients (
                            user_name,
                            client_name
                        ) VALUES (?1, ?2)
                    "), params![
                        user.name,
                        client,
                    ])?;
                }

                for target in user.allowed_targets {
                    #[rustfmt::skip]
                    transaction.execute(indoc!("
                        INSERT INTO user_targets (
                            user_name,
                            target_name
                        ) VALUES (?1, ?2)
                    "), params![
                        user.name,
                        target,
                    ])?;
                }
            }

            transaction.commit()?;
            Ok(())
        })
        .await
    }

    pub async fn load_config(&self) -> Result<ServerConfig, DatabaseError> {
        let raw = self
            .with_connection(|connection| {
                let transaction = connection.transaction()?;

                #[rustfmt::skip]
                let settings = transaction.query_row(indoc!("
                    SELECT
                        listen_addr,
                        tls_cert,
                        tls_key
                    FROM server_settings
                    WHERE id = 1
                "), [], |row| {
                    Ok((row.get::<_, String>(0)?, row.get(1)?, row.get(2)?))
                }).optional()?;

                let Some((listen_addr, tls_cert, tls_key)) = settings else {
                    return Ok(None);
                };

                #[rustfmt::skip]
                let mut client_query = transaction.prepare(indoc!("
                    SELECT
                        name,
                        max_duration,
                        api_key
                    FROM clients
                    ORDER BY name
                "))?;
                let clients = client_query
                    .query_map([], |row| {
                        Ok(Client {
                            name: row.get(0)?,
                            max_duration: duration_from_row(row, 1)?,
                            api_key: row.get(2)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                #[rustfmt::skip]
                let mut target_query = transaction.prepare(indoc!("
                    SELECT
                        name,
                        max_duration,
                        ca_private_key,
                        ca_public_key
                    FROM targets
                    ORDER BY name
                "))?;
                let targets = target_query
                    .query_map([], |row| {
                        Ok(Target {
                            name: row.get(0)?,
                            max_duration: duration_from_row(row, 1)?,
                            ca_private_key: row.get(2)?,
                            ca_public_key: row.get(3)?,
                        })
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                #[rustfmt::skip]
                let mut user_query = transaction.prepare(indoc!("
                    SELECT
                        name,
                        max_duration,
                        allow_missing_totp,
                        totp_secret
                    FROM users
                    ORDER BY name
                "))?;
                let raw_users = user_query
                    .query_map([], |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            duration_from_row(row, 1)?,
                            row.get::<_, bool>(2)?,
                            row.get::<_, Option<String>>(3)?,
                        ))
                    })?
                    .collect::<Result<Vec<_>, _>>()?;

                let mut users = Vec::with_capacity(raw_users.len());
                for (name, max_duration, allow_missing_totp, totp_secret) in raw_users {
                    #[rustfmt::skip]
                    let mut clients_query = transaction.prepare(indoc!("
                        SELECT client_name
                        FROM user_clients
                        WHERE user_name = ?1
                        ORDER BY client_name
                    "))?;
                    let allowed_clients = clients_query
                        .query_map([&name], |row| row.get(0))?
                        .collect::<Result<Vec<_>, _>>()?;

                    #[rustfmt::skip]
                    let mut targets_query = transaction.prepare(indoc!("
                        SELECT target_name
                        FROM user_targets
                        WHERE user_name = ?1
                        ORDER BY target_name
                    "))?;
                    let allowed_targets = targets_query
                        .query_map([&name], |row| row.get(0))?
                        .collect::<Result<Vec<_>, _>>()?;

                    users.push(User {
                        name,
                        allowed_targets,
                        allowed_clients,
                        max_duration,
                        allow_missing_totp,
                        totp_secret,
                    });
                }

                Ok(Some(RawConfig {
                    listen_addr,
                    tls_cert,
                    tls_key,
                    users,
                    clients,
                    targets,
                }))
            })
            .await?
            .ok_or(DatabaseError::MissingServerSettings)?;

        let listen_addr = raw.listen_addr.parse().map_err(|error| {
            DatabaseError::InvalidData(format!("invalid listen address: {error}"))
        })?;
        let config = ServerConfig {
            listen_addr,
            tls_cert: raw.tls_cert,
            tls_key: raw.tls_key,
            users: raw.users,
            clients: raw.clients,
            targets: raw.targets,
        };
        config.validate()?;
        Ok(config)
    }

    async fn with_connection<T, F>(&self, operation: F) -> Result<T, DatabaseError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> rusqlite::Result<T> + Send + 'static,
    {
        let path = self.path.clone();
        tokio::task::spawn_blocking(move || {
            let mut connection = Connection::open(path.as_ref())?;
            connection.busy_timeout(Duration::from_secs(5))?;
            connection.pragma_update(None, "foreign_keys", true)?;
            operation(&mut connection)
        })
        .await?
        .map_err(DatabaseError::from)
    }
}

struct RawConfig {
    listen_addr: String,
    tls_cert: Vec<u8>,
    tls_key: Vec<u8>,
    users: Vec<User>,
    clients: Vec<Client>,
    targets: Vec<Target>,
}

fn duration_from_row(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<SignDuration> {
    let value = row.get::<_, String>(index)?;
    SignDuration::from_param_str(&value).ok_or_else(|| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            Type::Text,
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid duration: {value}"),
            )
            .into(),
        )
    })
}

#[derive(Debug)]
pub enum DatabaseError {
    Sqlite(rusqlite::Error),
    Task(tokio::task::JoinError),
    Config(ConfigValidateError),
    MissingServerSettings,
    InvalidData(String),
    Io(std::io::Error),
}

impl Display for DatabaseError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            DatabaseError::Sqlite(error) => write!(formatter, "SQLite error: {error}"),
            DatabaseError::Task(error) => write!(formatter, "database task failed: {error}"),
            DatabaseError::Config(error) => {
                write!(formatter, "invalid server configuration: {error}")
            }
            DatabaseError::MissingServerSettings => {
                write!(formatter, "server settings are missing")
            }
            DatabaseError::InvalidData(message) => formatter.write_str(message),
            DatabaseError::Io(error) => write!(formatter, "I/O error: {error}"),
        }
    }
}

impl std::error::Error for DatabaseError {}

impl From<rusqlite::Error> for DatabaseError {
    fn from(error: rusqlite::Error) -> Self {
        DatabaseError::Sqlite(error)
    }
}

impl From<tokio::task::JoinError> for DatabaseError {
    fn from(error: tokio::task::JoinError) -> Self {
        DatabaseError::Task(error)
    }
}

impl From<ConfigValidateError> for DatabaseError {
    fn from(error: ConfigValidateError) -> Self {
        DatabaseError::Config(error)
    }
}

impl From<std::io::Error> for DatabaseError {
    fn from(error: std::io::Error) -> Self {
        DatabaseError::Io(error)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    fn sample_config() -> ServerConfig {
        ServerConfig {
            listen_addr: (IpAddr::V4(Ipv4Addr::LOCALHOST), 9292).into(),
            tls_cert: b"certificate".to_vec(),
            tls_key: b"private key".to_vec(),
            users: vec![User {
                name: "alice".to_string(),
                allowed_targets: vec!["production".to_string()],
                allowed_clients: vec!["laptop".to_string()],
                max_duration: SignDuration::Hour,
                allow_missing_totp: false,
                totp_secret: Some("otpauth://totp/example".to_string()),
            }],
            clients: vec![Client {
                name: "laptop".to_string(),
                max_duration: SignDuration::Day,
                api_key: "client-secret".to_string(),
            }],
            targets: vec![Target {
                name: "production".to_string(),
                max_duration: SignDuration::Week,
                ca_private_key: "private".to_string(),
                ca_public_key: "public".to_string(),
            }],
        }
    }

    #[tokio::test]
    async fn configuration_round_trips_through_sqlite() {
        let directory = temp_dir::TempDir::new().unwrap();
        let path = directory.path().join("server.db");
        let database = ServerDatabase::open(path).await.unwrap();
        let expected = sample_config();

        database.save_config(&expected).await.unwrap();

        assert_eq!(database.load_config().await.unwrap(), expected);
    }

    #[tokio::test]
    async fn a_new_database_has_no_server_settings() {
        let directory = temp_dir::TempDir::new().unwrap();
        let path = directory.path().join("server.db");
        let database = ServerDatabase::open(path).await.unwrap();

        assert!(matches!(
            database.load_config().await,
            Err(DatabaseError::MissingServerSettings)
        ));
        assert_eq!(
            tokio::fs::metadata(database.path())
                .await
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
