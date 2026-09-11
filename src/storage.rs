//! The encrypted SQLite database: schema, authentication, and every operation
//! that reads or changes CA state.

use crate::{
    auth::{self, KeyKind},
    error::{Error, Result},
    protocol::{Command, Operation, Reply, Resource},
    signing::{self, CertificateRequest},
};
use anyhow::Context;
use fs2::FileExt;
use indoc::indoc;
use prost::Message;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use ssh_key::{HashAlg, PrivateKey};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tonic::Code;
use zeroize::{Zeroize, Zeroizing};

const SCHEMA_VERSION: i64 = 1;
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const BUSY_TIMEOUT: Duration = Duration::from_secs(2);
/// SQLite VM instructions between deadline checks.
const PROGRESS_INTERVAL: i32 = 1000;
const IDEMPOTENCY_TTL_SECS: u64 = 86_400;
const MAX_IDEMPOTENCY_RECORDS: u64 = 100_000;
const MAX_AUDIT_EVENTS: u64 = 10_000;
const TOTP_ENROLLMENT_TTL_SECS: u64 = 600;
const DEFAULT_CERTIFICATE_SECS: u64 = 86_400;
/// Certificates are backdated by this much to tolerate host clock skew.
const CERTIFICATE_SKEW_SECS: u64 = 300;
const MAX_PAGE_SIZE: u32 = 100;
const MAX_INSTANCE_NAME_LEN: usize = 128;

/// An open, unlocked database holding the zone CA keys in memory.
pub struct Database {
    connection: Connection,
    pub issuance_count: u64,
    keys: HashMap<String, PrivateKey>,
    _lock: DatabaseLock,
}

/// An exclusive advisory lock on the database file, shared by clones.
#[derive(Clone)]
pub struct DatabaseLock {
    _file: Arc<LockedFile>,
}

struct LockedFile(File);

impl Drop for LockedFile {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.0);
    }
}

pub fn lock(path: &Path) -> anyhow::Result<DatabaseLock> {
    let lock_path = path.with_extension("db.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&lock_path)
        .with_context(|| {
            format!(
                "cannot open lock file {}; check directory existence and write permissions",
                lock_path.display()
            )
        })?;
    file.try_lock_exclusive().with_context(|| {
        format!(
            "cannot acquire lock {}. Another process may be using {}; stop it before starting another server or performing offline maintenance",
            lock_path.display(),
            path.display()
        )
    })?;
    Ok(DatabaseLock {
        _file: Arc::new(LockedFile(file)),
    })
}

pub fn validate_instance_name(name: &str) -> anyhow::Result<()> {
    if name.trim().is_empty()
        || name.len() > MAX_INSTANCE_NAME_LEN
        || name.chars().any(char::is_control)
    {
        anyhow::bail!("instance name requires 1–128 printable characters");
    }
    Ok(())
}

fn connect(path: &Path, secret: &str) -> Result<Connection> {
    let raw = auth::parse_bootstrap_secret(secret)?;
    let connection = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let key = Zeroizing::new(format!("x'{}'", hex::encode(&*raw)));
    connection.pragma_update(None, "cipher_log_level", "NONE")?;
    connection.pragma_update(None, "key", &*key)?;
    let cipher: String = connection
        .query_row("PRAGMA cipher_version", [], |row| row.get(0))
        .map_err(|_| Error::internal())?;
    if cipher.is_empty() {
        return Err(Error::internal());
    }
    #[rustfmt::skip]
    connection.execute_batch(indoc!("
        PRAGMA temp_store = MEMORY;
        PRAGMA journal_mode = DELETE;
        PRAGMA foreign_keys = ON;
        PRAGMA secure_delete = ON;
        PRAGMA cipher_memory_security = ON;
    "))?;
    connection.busy_timeout(BUSY_TIMEOUT)?;
    Ok(connection)
}

impl Database {
    /// Create and encrypt a new database with its first admin credential.
    pub fn initialize(path: &Path, secret: &str, admin: &str, name: &str) -> anyhow::Result<()> {
        validate_instance_name(name)?;
        let credential = auth::parse_key(admin)?;
        if credential.kind != KeyKind::Admin {
            anyhow::bail!("an admin key must use the esca_ad format");
        }
        auth::parse_bootstrap_secret(secret)?;
        crate::config::private_parent(path)?;
        let _lock = lock(path)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let populate = || -> anyhow::Result<()> {
            let mut connection = connect(path, secret)?;
            let tx = connection.transaction()?;
            tx.execute_batch(include_str!("schema.sql"))?;
            let now = auth::now();
            #[rustfmt::skip]
            tx.execute(indoc!("
                INSERT INTO metadata (version, id, name, created_at)
                VALUES (1, ?1, ?2, ?3)
            "), params![
                auth::new_id(),
                name,
                now,
            ])?;
            insert_admin_credential(&tx, &credential, now)?;
            tx.commit()?;
            file.sync_all()?;
            crate::config::sync_parent(path)?;
            Ok(())
        };
        let result = populate();
        if result.is_err() {
            drop(file);
            let _ = std::fs::remove_file(path);
        }
        result
    }

    pub fn open(path: &Path, secret: &str) -> Result<Self> {
        let lock =
            lock(path).map_err(|_| Error::unavailable("DATABASE_BUSY", "database is in use"))?;
        Self::open_with_lock(path, secret, lock, Instant::now() + OPEN_TIMEOUT)
    }

    /// Open with a lock the caller already holds, giving up at `deadline`.
    pub fn open_with_lock(
        path: &Path,
        secret: &str,
        lock: DatabaseLock,
        deadline: Instant,
    ) -> Result<Self> {
        let mut connection = connect(path, secret).map_err(|_| Error::auth())?;
        set_deadline(&connection, Some(deadline))?;
        let version: i64 = connection
            .query_row("SELECT version FROM metadata", [], |row| row.get(0))
            .map_err(|_| Error::auth())?;
        if version != SCHEMA_VERSION {
            return Err(Error::failed_precondition(
                "SCHEMA_VERSION",
                "unsupported database schema version",
            ));
        }
        verify_integrity(&connection)?;
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        prune_audit(&tx)?;
        upgrade_schema(&tx)?;
        let keys = load_zone_keys(&tx)?;
        tx.commit()?;
        let issuance_count =
            connection.query_row("SELECT count(*) FROM issued_certificates", [], |row| {
                row.get(0)
            })?;
        set_deadline(&connection, None)?;
        Ok(Self {
            connection,
            issuance_count,
            keys,
            _lock: lock,
        })
    }

    /// Replace every admin credential with `replacement` while the server is offline.
    pub fn reset_admin(&mut self, replacement: &str) -> Result<()> {
        let key = auth::parse_key(replacement)?;
        if key.kind != KeyKind::Admin {
            return Err(Error::input("admin key required"));
        }
        let tx = self.connection.transaction()?;
        let now = auth::now();
        #[rustfmt::skip]
        tx.execute(indoc!("
            UPDATE admin_credentials
            SET active = 0,
                updated_at = ?1
        "), [now])?;
        insert_admin_credential(&tx, &key, now)?;
        audit(
            &tx,
            "offline",
            "operator",
            "ResetAdminKey",
            "OK",
            &auth::new_id(),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Direct read access for inspection and offline maintenance.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// Run `execute`, interrupting SQLite once `deadline` passes.
    pub fn execute_until(
        &mut self,
        deadline: Instant,
        op: Operation,
        credential: &str,
        command: &Command,
    ) -> Result<Reply> {
        set_deadline(&self.connection, Some(deadline))?;
        let result = self.execute(op, credential, command);
        set_deadline(&self.connection, None)?;
        result
    }

    /// Authenticate `credential`, run `op`, and record the outcome in the audit log.
    pub fn execute(&mut self, op: Operation, credential: &str, command: &Command) -> Result<Reply> {
        auth::validate_request_id(&command.request_id)?;
        if op == Operation::GetPublicKey {
            return public_key(&self.connection, &command.zone, &command.request_id);
        }
        let key = auth::parse_key(credential).inspect_err(|_| {
            let _ = audit(
                &self.connection,
                "",
                "",
                op.name(),
                "MALFORMED_CREDENTIAL",
                &command.request_id,
            );
        })?;
        let actor = self.authenticate(op, &key, command).inspect_err(|error| {
            let _ = audit(
                &self.connection,
                key.kind.tag(),
                &key.id,
                op.name(),
                error.reason,
                &command.request_id,
            );
        })?;
        let result = self.execute_as(op, &key, &actor, command);
        if let Err(error) = &result {
            audit(
                &self.connection,
                actor.kind(),
                actor.id(),
                op.name(),
                error.reason,
                &command.request_id,
            )?;
        }
        result
    }

    fn authenticate(&self, op: Operation, key: &auth::Key, command: &Command) -> Result<Actor> {
        match authenticate(&self.connection, key, op) {
            Err(error) if error.code == Code::Unauthenticated && op.is_rotation() => {
                self.replayed_rotation_actor(op, key, command)?.ok_or(error)
            }
            result => result,
        }
    }

    /// A rotation retried after the client already switched to the replacement
    /// key still authenticates with the old key. Accept it when the stored
    /// idempotency record proves the rotation completed with that old key.
    fn replayed_rotation_actor(
        &self,
        op: Operation,
        old: &auth::Key,
        command: &Command,
    ) -> Result<Option<Actor>> {
        let Ok(replacement) = auth::parse_key(&command.replacement_key) else {
            return Ok(None);
        };
        let Ok(actor) = authenticate(&self.connection, &replacement, op) else {
            return Ok(None);
        };
        #[rustfmt::skip]
        let digest: Option<Vec<u8>> = self.connection.query_row(indoc!("
            SELECT auth_digest
            FROM idempotency_records
            WHERE actor = ?1
              AND operation = ?2
              AND request_id = ?3
              AND expires_at > ?4
        "), params![
            actor.id(),
            op.name(),
            command.request_id,
            auth::now(),
        ], |row| row.get(0)).optional()?;
        let proven = digest.is_some_and(|digest| auth::constant_time_eq(&digest, &old.digest));
        Ok(proven.then_some(actor))
    }

    fn execute_as(
        &mut self,
        op: Operation,
        key: &auth::Key,
        actor: &Actor,
        command: &Command,
    ) -> Result<Reply> {
        if op.is_list() {
            return list(&self.connection, op, command);
        }
        let payload = auth::hash(&Zeroizing::new(command.encode_to_vec()));
        let tx = self.connection.transaction()?;
        expire_idempotency_records(&tx)?;
        if let Some(reply) = replay(&tx, op, actor, command, &payload)? {
            return Ok(reply);
        }
        ensure_idempotency_capacity(&tx)?;
        let now = auth::now();
        let mut mutation = Mutation {
            db: &tx,
            actor,
            now,
            reply: Reply {
                request_id: command.request_id.clone(),
                ..Default::default()
            },
        };
        let cache_update = mutation.apply(op, key, command, &self.keys)?;
        mutation.record_idempotency(op, key, command, &payload)?;
        let reply = mutation.reply;
        audit(
            &tx,
            actor.kind(),
            actor.id(),
            op.name(),
            "OK",
            &command.request_id,
        )?;
        tx.commit()?;
        if op == Operation::SignCertificate {
            self.issuance_count += 1;
        }
        match cache_update {
            CacheUpdate::Unchanged => {}
            CacheUpdate::Insert(id, ca) => {
                self.keys.insert(id, *ca);
            }
            CacheUpdate::Remove(id) => {
                self.keys.remove(&id);
            }
        }
        Ok(reply)
    }
}

fn set_deadline(connection: &Connection, deadline: Option<Instant>) -> Result<()> {
    match deadline {
        Some(deadline) => connection
            .progress_handler(PROGRESS_INTERVAL, Some(move || Instant::now() >= deadline))?,
        None => connection.progress_handler(0, None::<fn() -> bool>)?,
    }
    Ok(())
}

fn verify_integrity(connection: &Connection) -> Result<()> {
    let integrity: String = connection.query_row("PRAGMA integrity_check", [], |row| row.get(0))?;
    if integrity != "ok" {
        return Err(Error::internal());
    }
    for check in ["PRAGMA cipher_integrity_check", "PRAGMA foreign_key_check"] {
        let mut statement = connection.prepare(check)?;
        if statement.query([])?.next()?.is_some() {
            return Err(Error::internal());
        }
    }
    Ok(())
}

/// Add objects introduced after the first release to databases that predate them.
fn upgrade_schema(tx: &Transaction<'_>) -> Result<()> {
    #[rustfmt::skip]
    tx.execute_batch(indoc!("
        CREATE TABLE IF NOT EXISTS zone_removals (
            zone_id TEXT PRIMARY KEY REFERENCES zones(id),
            removed_at INTEGER NOT NULL
        );
    "))?;
    Ok(())
}

/// Load the CA key of every zone that has not been removed, verifying that
/// stored fingerprints match the keys and that no two zones share a CA.
fn load_zone_keys(tx: &Transaction<'_>) -> Result<HashMap<String, PrivateKey>> {
    #[rustfmt::skip]
    let mut statement = tx.prepare(indoc!("
        SELECT
            id,
            private_key,
            name,
            fingerprint,
            id IN (SELECT zone_id FROM zone_removals)
        FROM zones
    "))?;
    let rows = statement.query_map([], |row| {
        Ok((
            row.get::<_, String>(0)?,
            Zeroizing::new(row.get::<_, String>(1)?),
            row.get::<_, String>(2)?,
            row.get::<_, String>(3)?,
            row.get::<_, bool>(4)?,
        ))
    })?;
    let mut owners: HashMap<String, String> = HashMap::new();
    let mut keys = HashMap::new();
    for row in rows {
        let (id, pem, name, stored_fingerprint, removed) = row?;
        let ca = PrivateKey::from_openssh(pem.as_bytes())?;
        let fingerprint = ca.fingerprint(HashAlg::Sha256).to_string();
        if let Some(other) = owners.insert(fingerprint.clone(), name.clone()) {
            return Err(Error::failed_precondition(
                "DUPLICATE_CA",
                format!(
                    "zones {other:?} and {name:?} share CA {fingerprint}; separate their CA keys and host trust before unlocking"
                ),
            ));
        }
        if fingerprint != stored_fingerprint {
            return Err(Error::failed_precondition(
                "CA_IDENTITY_MISMATCH",
                format!("zone {name:?} has an inconsistent CA fingerprint"),
            ));
        }
        if !removed {
            keys.insert(id, ca);
        }
    }
    #[rustfmt::skip]
    tx.execute_batch(indoc!("
        CREATE UNIQUE INDEX IF NOT EXISTS zone_ca_public_key ON zones(public_key);
        CREATE UNIQUE INDEX IF NOT EXISTS zone_ca_fingerprint ON zones(fingerprint);
    "))?;
    Ok(keys)
}

fn insert_admin_credential(db: &Connection, key: &auth::Key, now: u64) -> Result<()> {
    #[rustfmt::skip]
    db.execute(indoc!("
        INSERT INTO admin_credentials (id, key_id, digest, active, created_at, updated_at)
        VALUES (?1, ?2, ?3, 1, ?4, ?4)
    "), params![
        auth::new_id(),
        key.id,
        key.digest,
        now,
    ])?;
    Ok(())
}

/// The authenticated caller of an operation.
enum Actor {
    Admin { credential_id: String },
    Token(TokenActor),
}

struct TokenActor {
    id: String,
    user_id: String,
    username: String,
    user_limit: u64,
    token_limit: u64,
    totp: Option<Zeroizing<String>>,
    last_step: i64,
}

impl Actor {
    fn id(&self) -> &str {
        match self {
            Actor::Admin { credential_id } => credential_id,
            Actor::Token(token) => &token.id,
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Actor::Admin { .. } => "admin",
            Actor::Token(_) => "access_token",
        }
    }

    fn token(&self) -> Result<&TokenActor> {
        match self {
            Actor::Token(token) => Ok(token),
            Actor::Admin { .. } => Err(Error::denied()),
        }
    }
}

fn authenticate(db: &Connection, key: &auth::Key, op: Operation) -> Result<Actor> {
    let required = if op.is_admin() {
        KeyKind::Admin
    } else {
        KeyKind::AccessToken
    };
    if key.kind != required {
        return Err(Error::denied());
    }
    match key.kind {
        KeyKind::Admin => authenticate_admin(db, key),
        KeyKind::AccessToken => authenticate_token(db, key),
    }
}

fn authenticate_admin(db: &Connection, key: &auth::Key) -> Result<Actor> {
    #[rustfmt::skip]
    let (credential_id, digest): (String, Vec<u8>) = db.query_row(indoc!("
        SELECT id, digest
        FROM admin_credentials
        WHERE key_id = ?1
          AND active = 1
    "), [
        &key.id,
    ], |row| Ok((row.get(0)?, row.get(1)?))).optional()?.ok_or_else(Error::auth)?;
    if !auth::constant_time_eq(&digest, &key.digest) {
        return Err(Error::auth());
    }
    Ok(Actor::Admin { credential_id })
}

fn authenticate_token(db: &Connection, key: &auth::Key) -> Result<Actor> {
    #[rustfmt::skip]
    let (digest, actor): (Vec<u8>, TokenActor) = db.query_row(indoc!("
        SELECT
            t.id,
            t.digest,
            u.id,
            u.name,
            u.max_duration,
            t.max_duration,
            u.totp_secret,
            u.last_step
        FROM access_tokens AS t
        JOIN users AS u ON u.id = t.user_id
        WHERE t.key_id = ?1
          AND t.active = 1
          AND t.removed = 0
          AND u.active = 1
          AND u.removed = 0
    "), [
        &key.id,
    ], |row| {
        Ok((
            row.get(1)?,
            TokenActor {
                id: row.get(0)?,
                user_id: row.get(2)?,
                username: row.get(3)?,
                user_limit: row.get(4)?,
                token_limit: row.get(5)?,
                totp: row.get::<_, Option<String>>(6)?.map(Zeroizing::new),
                last_step: row.get(7)?,
            },
        ))
    }).optional()?.ok_or_else(Error::auth)?;
    if !auth::constant_time_eq(&digest, &key.digest) {
        return Err(Error::auth());
    }
    Ok(Actor::Token(actor))
}

/// Return the stored reply when `command.request_id` already completed.
fn replay(
    tx: &Transaction<'_>,
    op: Operation,
    actor: &Actor,
    command: &Command,
    payload: &[u8],
) -> Result<Option<Reply>> {
    #[rustfmt::skip]
    let existing: Option<(Vec<u8>, Vec<u8>, bool)> = tx.query_row(indoc!("
        SELECT payload_digest, response, secret_response
        FROM idempotency_records
        WHERE actor = ?1
          AND operation = ?2
          AND request_id = ?3
    "), params![
        actor.id(),
        op.name(),
        command.request_id,
    ], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?))).optional()?;
    let Some((digest, response, secret_delivered)) = existing else {
        return Ok(None);
    };
    if !auth::constant_time_eq(&digest, payload) {
        return Err(Error::already_exists(
            "REQUEST_CONFLICT",
            "request UUID was already used with different input",
        ));
    }
    if secret_delivered {
        return Err(Error::already_exists(
            "SECRET_ALREADY_DELIVERED",
            "one-time secret was already delivered; remove and recreate the token or restart enrollment",
        ));
    }
    if op == Operation::SignCertificate {
        // A replayed certificate must still be permitted today.
        signing_zone(tx, &command.zone, &actor.token()?.user_id)?;
    }
    Reply::decode(response.as_slice())
        .map(Some)
        .map_err(|_| Error::internal())
}

fn expire_idempotency_records(tx: &Transaction<'_>) -> Result<()> {
    #[rustfmt::skip]
    tx.execute(indoc!("
        DELETE FROM idempotency_records
        WHERE expires_at <= ?1
    "), [auth::now()])?;
    Ok(())
}

fn ensure_idempotency_capacity(tx: &Transaction<'_>) -> Result<()> {
    let count: u64 = tx.query_row("SELECT count(*) FROM idempotency_records", [], |row| {
        row.get(0)
    })?;
    if count >= MAX_IDEMPOTENCY_RECORDS {
        return Err(Error::exhausted(
            "IDEMPOTENCY_FULL",
            "retry storage is full",
        ));
    }
    Ok(())
}

/// A change to the in-memory CA key cache, applied after the transaction commits.
enum CacheUpdate {
    Unchanged,
    Insert(String, Box<PrivateKey>),
    Remove(String),
}

/// One state-changing operation inside an open transaction.
struct Mutation<'a> {
    db: &'a Connection,
    actor: &'a Actor,
    now: u64,
    reply: Reply,
}

impl<'a> Mutation<'a> {
    fn apply(
        &mut self,
        op: Operation,
        key: &auth::Key,
        command: &Command,
        keys: &HashMap<String, PrivateKey>,
    ) -> Result<CacheUpdate> {
        use Operation::*;
        match op {
            CreateZone | ImportZone => return self.create_zone(op, command),
            RemoveZone => return self.remove_zone(command),
            CreateUser => self.create_user(command)?,
            UpdateZone => self.update_zone(command)?,
            UpdateUser => self.update_user(command)?,
            RemoveUser => self.remove_user(command)?,
            GrantZone => self.grant_zone(command)?,
            RevokeZone => self.revoke_zone(command)?,
            CreateAccessToken => self.create_access_token(command)?,
            UpdateAccessToken => self.update_access_token(command)?,
            RemoveAccessToken => self.remove_access_token(command)?,
            ClearTotp => self.clear_totp(command)?,
            BeginTotpEnrollment => self.begin_totp_enrollment()?,
            ConfirmTotpEnrollment => self.confirm_totp_enrollment(command)?,
            RotateToken | RotateAdminKey => self.rotate_key(op, key, command)?,
            SignCertificate => self.sign_certificate(command, keys)?,
            GetStatus | Unlock | GetPublicKey | ListZones | ListUsers | ListUserZones
            | ListAccessTokens => return Err(Error::input("unknown operation")),
        }
        Ok(CacheUpdate::Unchanged)
    }

    fn token_actor(&self) -> Result<&'a TokenActor> {
        self.actor.token()
    }

    /// Store the reply so a retry with the same request UUID returns it.
    fn record_idempotency(
        &self,
        op: Operation,
        key: &auth::Key,
        command: &Command,
        payload: &[u8],
    ) -> Result<()> {
        // One-time secrets are never stored; a replay reports them as delivered.
        let secret_delivered = !self.reply.api_key.is_empty() || !self.reply.secret.is_empty();
        let mut stored = self.reply.clone();
        stored.api_key.zeroize();
        stored.secret.zeroize();
        stored.otpauth_uri.zeroize();
        #[rustfmt::skip]
        self.db.execute(indoc!("
            INSERT INTO idempotency_records (
                actor, operation, request_id, payload_digest,
                auth_digest, response, secret_response, expires_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
        "), params![
            self.actor.id(),
            op.name(),
            command.request_id,
            payload,
            key.digest,
            stored.encode_to_vec(),
            secret_delivered,
            self.now + IDEMPOTENCY_TTL_SECS,
        ])?;
        Ok(())
    }

    fn create_zone(&mut self, op: Operation, command: &Command) -> Result<CacheUpdate> {
        auth::validate_name(&command.name)?;
        auth::validate_duration(command.max_duration)?;
        let id = auth::new_id();
        let ca = if op == Operation::ImportZone {
            signing::import(&command.secret)?
        } else {
            signing::generate(&command.name)?
        };
        let pem = ca.to_openssh(ssh_key::LineEnding::LF)?;
        let public_key = ca.public_key().to_openssh()?;
        let fingerprint = ca.public_key().fingerprint(HashAlg::Sha256).to_string();
        #[rustfmt::skip]
        let duplicate: bool = self.db.query_row(indoc!("
            SELECT EXISTS(SELECT 1 FROM zones WHERE fingerprint = ?1)
        "), [
            &fingerprint,
        ], |row| row.get(0))?;
        if duplicate {
            return Err(Error::already_exists(
                "DUPLICATE_CA",
                "CA key already belongs to a zone, including inactive zones",
            ));
        }
        #[rustfmt::skip]
        self.db.execute(indoc!("
            INSERT INTO zones (
                id, name, private_key, public_key, fingerprint,
                max_duration, next_serial, active, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, 1, 1, ?7, ?7)
        "), params![
            id,
            command.name,
            &*pem,
            public_key,
            fingerprint,
            command.max_duration,
            self.now,
        ])?;
        self.reply.resources.push(Resource {
            id: id.clone(),
            name: command.name.clone(),
            max_duration: command.max_duration,
            active: true,
            fingerprint,
            ..Default::default()
        });
        Ok(CacheUpdate::Insert(id, Box::new(ca)))
    }

    fn remove_zone(&mut self, command: &Command) -> Result<CacheUpdate> {
        let zone = zone_id(self.db, &command.name)?;
        #[rustfmt::skip]
        self.db.execute(indoc!("
            UPDATE zones
            SET active = 0,
                updated_at = ?1
            WHERE id = ?2
        "), params![
            self.now,
            zone,
        ])?;
        self.db
            .execute("DELETE FROM user_zones WHERE zone_id = ?1", [&zone])?;
        #[rustfmt::skip]
        self.db.execute(indoc!("
            INSERT INTO zone_removals (zone_id, removed_at)
            VALUES (?1, ?2)
        "), params![
            zone,
            self.now,
        ])?;
        Ok(CacheUpdate::Remove(zone))
    }

    fn create_user(&mut self, command: &Command) -> Result<()> {
        auth::validate_name(&command.name)?;
        auth::validate_duration(command.max_duration)?;
        let id = auth::new_id();
        #[rustfmt::skip]
        self.db.execute(indoc!("
            INSERT INTO users (id, name, max_duration, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?4, ?4)
        "), params![
            id,
            command.name,
            command.max_duration,
            self.now,
        ])?;
        self.reply.resources.push(Resource {
            id,
            name: command.name.clone(),
            max_duration: command.max_duration,
            active: true,
            ..Default::default()
        });
        Ok(())
    }

    fn update_zone(&mut self, command: &Command) -> Result<()> {
        auth::validate_name(&command.name)?;
        let (max_duration, active) = update_fields(command)?;
        #[rustfmt::skip]
        let changed = self.db.execute(indoc!("
            UPDATE zones
            SET max_duration = coalesce(?1, max_duration),
                active = coalesce(?2, active),
                updated_at = ?3
            WHERE name = ?4
              AND id NOT IN (SELECT zone_id FROM zone_removals)
        "), params![
            max_duration,
            active,
            self.now,
            command.name,
        ])?;
        ensure_updated(changed)
    }

    fn update_user(&mut self, command: &Command) -> Result<()> {
        auth::validate_name(&command.name)?;
        let (max_duration, active) = update_fields(command)?;
        #[rustfmt::skip]
        let changed = self.db.execute(indoc!("
            UPDATE users
            SET max_duration = coalesce(?1, max_duration),
                active = coalesce(?2, active),
                updated_at = ?3
            WHERE name = ?4
              AND removed = 0
        "), params![
            max_duration,
            active,
            self.now,
            command.name,
        ])?;
        ensure_updated(changed)
    }

    fn remove_user(&mut self, command: &Command) -> Result<()> {
        let user = user_id(self.db, &command.name)?;
        #[rustfmt::skip]
        self.db.execute(indoc!("
            UPDATE users
            SET active = 0,
                removed = 1,
                totp_secret = NULL,
                pending_secret = NULL,
                updated_at = ?1
            WHERE id = ?2
        "), params![
            self.now,
            user,
        ])?;
        #[rustfmt::skip]
        self.db.execute(indoc!("
            UPDATE access_tokens
            SET active = 0,
                removed = 1,
                updated_at = ?1
            WHERE user_id = ?2
        "), params![
            self.now,
            user,
        ])?;
        self.db
            .execute("DELETE FROM user_zones WHERE user_id = ?1", [user])?;
        Ok(())
    }

    fn grant_zone(&mut self, command: &Command) -> Result<()> {
        let user = user_id(self.db, &command.user)?;
        let zone = zone_id(self.db, &command.zone)?;
        #[rustfmt::skip]
        self.db.execute(indoc!("
            INSERT OR IGNORE INTO user_zones (user_id, zone_id)
            VALUES (?1, ?2)
        "), params![
            user,
            zone,
        ])?;
        Ok(())
    }

    fn revoke_zone(&mut self, command: &Command) -> Result<()> {
        let user = user_id(self.db, &command.user)?;
        let zone = zone_id(self.db, &command.zone)?;
        #[rustfmt::skip]
        self.db.execute(indoc!("
            DELETE FROM user_zones
            WHERE user_id = ?1
              AND zone_id = ?2
        "), params![
            user,
            zone,
        ])?;
        Ok(())
    }

    fn create_access_token(&mut self, command: &Command) -> Result<()> {
        auth::validate_name(&command.name)?;
        auth::validate_duration(command.max_duration)?;
        let user = user_id(self.db, &command.user)?;
        let secret = auth::new_key(KeyKind::AccessToken);
        let key = auth::parse_key(&secret)?;
        let id = auth::new_id();
        #[rustfmt::skip]
        self.db.execute(indoc!("
            INSERT INTO access_tokens (
                id, user_id, name, active, removed,
                max_duration, key_id, digest, created_at, updated_at
            )
            VALUES (?1, ?2, ?3, 1, 0, ?4, ?5, ?6, ?7, ?7)
        "), params![
            id,
            user,
            command.name,
            command.max_duration,
            key.id,
            key.digest,
            self.now,
        ])?;
        self.reply.api_key = secret.to_string();
        self.reply.resources.push(Resource {
            id,
            name: command.name.clone(),
            user: command.user.clone(),
            max_duration: command.max_duration,
            active: true,
            ..Default::default()
        });
        Ok(())
    }

    fn update_access_token(&mut self, command: &Command) -> Result<()> {
        auth::validate_name(&command.name)?;
        let user = user_id(self.db, &command.user)?;
        let (max_duration, active) = update_fields(command)?;
        #[rustfmt::skip]
        let changed = self.db.execute(indoc!("
            UPDATE access_tokens
            SET max_duration = coalesce(?1, max_duration),
                active = coalesce(?2, active),
                updated_at = ?3
            WHERE user_id = ?4
              AND name = ?5
              AND removed = 0
        "), params![
            max_duration,
            active,
            self.now,
            user,
            command.name,
        ])?;
        ensure_updated(changed)
    }

    fn remove_access_token(&mut self, command: &Command) -> Result<()> {
        auth::validate_name(&command.name)?;
        let user = user_id(self.db, &command.user)?;
        #[rustfmt::skip]
        let changed = self.db.execute(indoc!("
            UPDATE access_tokens
            SET active = 0,
                removed = 1,
                updated_at = ?1
            WHERE user_id = ?2
              AND name = ?3
              AND removed = 0
        "), params![
            self.now,
            user,
            command.name,
        ])?;
        ensure_updated(changed)
    }

    fn clear_totp(&mut self, command: &Command) -> Result<()> {
        let user = user_id(self.db, &command.user)?;
        #[rustfmt::skip]
        self.db.execute(indoc!("
            UPDATE users
            SET totp_secret = NULL,
                pending_secret = NULL,
                pending_expires = NULL,
                last_step = -1,
                updated_at = ?1
            WHERE id = ?2
        "), params![
            self.now,
            user,
        ])?;
        Ok(())
    }

    fn begin_totp_enrollment(&mut self) -> Result<()> {
        let actor = self.token_actor()?;
        if actor.totp.is_some() {
            return Err(Error::failed_precondition(
                "TOTP_ENROLLED",
                "only an administrator can clear confirmed TOTP",
            ));
        }
        let secret = auth::totp_secret();
        #[rustfmt::skip]
        self.db.execute(indoc!("
            UPDATE users
            SET pending_secret = ?1,
                pending_expires = ?2,
                updated_at = ?3
            WHERE id = ?4
        "), params![
            &*secret,
            self.now + TOTP_ENROLLMENT_TTL_SECS,
            self.now,
            actor.user_id,
        ])?;
        let issuer: String = self
            .db
            .query_row("SELECT name FROM metadata", [], |row| row.get(0))?;
        self.reply.otpauth_uri = otpauth_uri(&issuer, &actor.username, &secret)?;
        self.reply.secret = secret.to_string();
        Ok(())
    }

    fn confirm_totp_enrollment(&mut self, command: &Command) -> Result<()> {
        let actor = self.token_actor()?;
        if actor.totp.is_some() {
            return Err(Error::failed_precondition(
                "TOTP_ENROLLED",
                "TOTP already enrolled",
            ));
        }
        #[rustfmt::skip]
        let (secret, expires): (Option<String>, Option<u64>) = self.db.query_row(indoc!("
            SELECT pending_secret, pending_expires
            FROM users
            WHERE id = ?1
        "), [
            &actor.user_id,
        ], |row| Ok((row.get(0)?, row.get(1)?)))?;
        let secret = secret
            .map(Zeroizing::new)
            .filter(|_| expires.is_some_and(|expires| expires > self.now))
            .ok_or_else(|| {
                Error::failed_precondition("ENROLLMENT_EXPIRED", "start a new TOTP enrollment")
            })?;
        let step = auth::verify_totp(&secret, &command.totp, -1, self.now)?;
        #[rustfmt::skip]
        self.db.execute(indoc!("
            UPDATE users
            SET totp_secret = ?1,
                pending_secret = NULL,
                pending_expires = NULL,
                last_step = ?2,
                updated_at = ?3
            WHERE id = ?4
        "), params![
            &*secret,
            step,
            self.now,
            actor.user_id,
        ])?;
        Ok(())
    }

    fn rotate_key(&mut self, op: Operation, key: &auth::Key, command: &Command) -> Result<()> {
        let replacement = auth::parse_key(&command.replacement_key)?;
        if replacement.kind != key.kind || replacement.id == key.id {
            return Err(Error::input(
                "replacement must be a fresh key of the same kind",
            ));
        }
        if op == Operation::RotateToken {
            let actor = self.token_actor()?;
            check_totp(self.db, actor, &command.totp, self.now)?;
            #[rustfmt::skip]
            self.db.execute(indoc!("
                UPDATE access_tokens
                SET key_id = ?1,
                    digest = ?2,
                    updated_at = ?3
                WHERE id = ?4
            "), params![
                replacement.id,
                replacement.digest,
                self.now,
                actor.id,
            ])?;
        } else {
            #[rustfmt::skip]
            self.db.execute(indoc!("
                UPDATE admin_credentials
                SET key_id = ?1,
                    digest = ?2,
                    updated_at = ?3
                WHERE id = ?4
            "), params![
                replacement.id,
                replacement.digest,
                self.now,
                self.actor.id(),
            ])?;
        }
        Ok(())
    }

    fn sign_certificate(
        &mut self,
        command: &Command,
        keys: &HashMap<String, PrivateKey>,
    ) -> Result<()> {
        let actor = self.token_actor()?;
        auth::validate_name(&command.zone)?;
        let requested = if command.duration == 0 {
            DEFAULT_CERTIFICATE_SECS
        } else {
            auth::validate_duration(command.duration)?
        };
        let zone = signing_zone(self.db, &command.zone, &actor.user_id)?;
        check_totp(self.db, actor, &command.totp, self.now)?;
        let duration = requested
            .min(zone.max_duration)
            .min(actor.user_limit)
            .min(actor.token_limit);
        if zone.next_serial >= i64::MAX as u64 {
            return Err(Error::exhausted(
                "SERIAL_EXHAUSTED",
                "certificate serial limit reached",
            ));
        }
        let ca = keys.get(&zone.id).ok_or_else(Error::internal)?;
        let certificate = signing::sign(
            ca,
            &CertificateRequest {
                public_key: &command.public_key,
                principal: &actor.username,
                serial: zone.next_serial,
                request_id: &command.request_id,
                now: self.now,
                duration,
            },
        )?;
        let fingerprint = ssh_key::PublicKey::from_openssh(&command.public_key)?
            .fingerprint(HashAlg::Sha256)
            .to_string();
        #[rustfmt::skip]
        self.db.execute(indoc!("
            UPDATE zones
            SET next_serial = next_serial + 1
            WHERE id = ?1
        "), [
            &zone.id,
        ])?;
        #[rustfmt::skip]
        self.db.execute(indoc!("
            INSERT INTO issued_certificates (
                zone_id, serial, user_id, token_id, fingerprint,
                valid_after, valid_before, request_id, created_at
            )
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
        "), params![
            zone.id,
            zone.next_serial,
            actor.user_id,
            actor.id,
            fingerprint,
            self.now.saturating_sub(CERTIFICATE_SKEW_SECS),
            self.now + duration,
            command.request_id,
            self.now,
        ])?;
        self.reply.certificate = certificate;
        self.reply.expires_at = self.now + duration;
        self.reply.effective_duration = duration;
        Ok(())
    }
}

/// The optional fields of an update; at least one must be present.
fn update_fields(command: &Command) -> Result<(Option<u64>, Option<bool>)> {
    let max_duration = (command.max_duration != 0)
        .then(|| auth::validate_duration(command.max_duration))
        .transpose()?;
    if max_duration.is_none() && command.active.is_none() {
        return Err(Error::input("an update requires a duration or state"));
    }
    Ok((max_duration, command.active))
}

fn ensure_updated(rows: usize) -> Result<()> {
    if rows == 0 {
        return Err(Error::not_found());
    }
    Ok(())
}

fn otpauth_uri(issuer: &str, account: &str, secret: &str) -> Result<String> {
    let mut uri = url::Url::parse("otpauth://totp/").map_err(|_| Error::internal())?;
    uri.set_path(&format!("{issuer}:{account}"));
    uri.query_pairs_mut()
        .append_pair("secret", secret)
        .append_pair("issuer", issuer)
        .append_pair("algorithm", "SHA1")
        .append_pair("digits", "6")
        .append_pair("period", "30");
    Ok(uri.to_string())
}

struct SigningZone {
    id: String,
    max_duration: u64,
    next_serial: u64,
}

/// The zone `user_id` may sign for, or an access-denied error.
fn signing_zone(db: &Connection, zone: &str, user_id: &str) -> Result<SigningZone> {
    #[rustfmt::skip]
    let found = db.query_row(indoc!("
        SELECT z.id, z.max_duration, z.next_serial
        FROM zones AS z
        JOIN user_zones AS g ON g.zone_id = z.id
        WHERE z.name = ?1
          AND z.active = 1
          AND z.id NOT IN (SELECT zone_id FROM zone_removals)
          AND g.user_id = ?2
    "), params![
        zone,
        user_id,
    ], |row| {
        Ok(SigningZone {
            id: row.get(0)?,
            max_duration: row.get(1)?,
            next_serial: row.get(2)?,
        })
    }).optional()?;
    found.ok_or_else(Error::denied)
}

fn user_id(db: &Connection, name: &str) -> Result<String> {
    auth::validate_name(name)?;
    #[rustfmt::skip]
    let id = db.query_row(indoc!("
        SELECT id
        FROM users
        WHERE name = ?1
          AND removed = 0
    "), [
        name,
    ], |row| row.get(0))?;
    Ok(id)
}

fn zone_id(db: &Connection, name: &str) -> Result<String> {
    auth::validate_name(name)?;
    #[rustfmt::skip]
    let id = db.query_row(indoc!("
        SELECT id
        FROM zones
        WHERE name = ?1
          AND id NOT IN (SELECT zone_id FROM zone_removals)
    "), [
        name,
    ], |row| row.get(0))?;
    Ok(id)
}

fn check_totp(db: &Connection, actor: &TokenActor, code: &str, now: u64) -> Result<()> {
    let Some(secret) = &actor.totp else {
        return Ok(());
    };
    let step = auth::verify_totp(secret, code, actor.last_step, now)?;
    #[rustfmt::skip]
    db.execute(indoc!("
        UPDATE users
        SET last_step = ?1
        WHERE id = ?2
    "), params![
        step,
        actor.user_id,
    ])?;
    Ok(())
}

fn prune_audit(db: &Connection) -> Result<()> {
    #[rustfmt::skip]
    db.execute(indoc!("
        DELETE FROM audit_events
        WHERE rowid <= (
            SELECT rowid
            FROM audit_events
            ORDER BY rowid DESC
            LIMIT 1 OFFSET ?1
        )
    "), [MAX_AUDIT_EVENTS])?;
    Ok(())
}

fn audit(
    db: &Connection,
    actor_type: &str,
    actor_id: &str,
    operation: &str,
    result: &str,
    request_id: &str,
) -> Result<()> {
    #[rustfmt::skip]
    db.execute(indoc!("
        INSERT INTO audit_events (
            id, actor_type, actor_id, operation, result, request_id, created_at
        )
        VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
    "), params![
        auth::new_id(),
        actor_type,
        actor_id,
        operation,
        result,
        request_id,
        auth::now(),
    ])?;
    prune_audit(db)
}

fn public_key(db: &Connection, zone: &str, request_id: &str) -> Result<Reply> {
    auth::validate_name(zone)?;
    #[rustfmt::skip]
    let (public_key, fingerprint) = db.query_row(indoc!("
        SELECT public_key, fingerprint
        FROM zones
        WHERE name = ?1
          AND active = 1
          AND id NOT IN (SELECT zone_id FROM zone_removals)
    "), [
        zone,
    ], |row| Ok((row.get(0)?, row.get(1)?)))?;
    Ok(Reply {
        request_id: request_id.into(),
        public_key,
        fingerprint,
        ..Default::default()
    })
}

/// Page tokens carry the operation and user so a token cannot be reused
/// against a different listing.
fn decode_page_token(op: Operation, command: &Command) -> Result<String> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    if command.page_token.is_empty() {
        return Ok(String::new());
    }
    let raw = URL_SAFE_NO_PAD
        .decode(&command.page_token)
        .map_err(|_| Error::input("invalid page token"))?;
    let raw = String::from_utf8(raw).map_err(|_| Error::input("invalid page token"))?;
    let prefix = format!("{op}:{}:", command.user);
    let id = raw
        .strip_prefix(&prefix)
        .ok_or_else(|| Error::input("page token belongs to another query"))?;
    auth::validate_request_id(id)?;
    Ok(id.into())
}

fn encode_page_token(op: Operation, command: &Command, last_id: &str) -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    URL_SAFE_NO_PAD.encode(format!("{op}:{}:{last_id}", command.user))
}

fn list(db: &Connection, op: Operation, command: &Command) -> Result<Reply> {
    let page_size = if command.page_size == 0 {
        MAX_PAGE_SIZE
    } else {
        command.page_size.min(MAX_PAGE_SIZE)
    };
    let cursor = decode_page_token(op, command)?;
    // Every listing yields the same seven columns so rows map to one Resource shape.
    #[rustfmt::skip]
    let sql = match op {
        Operation::ListZones => indoc!("
            SELECT id, name, '', max_duration, active, 0, fingerprint
            FROM zones
            WHERE id > ?1
              AND id NOT IN (SELECT zone_id FROM zone_removals)
            ORDER BY id
            LIMIT ?2
        "),
        Operation::ListUsers => indoc!("
            SELECT id, name, '', max_duration, active, totp_secret IS NOT NULL, ''
            FROM users
            WHERE removed = 0
              AND id > ?1
            ORDER BY id
            LIMIT ?2
        "),
        Operation::ListUserZones => include_str!("queries/list_user_zones.sql"),
        Operation::ListAccessTokens => indoc!("
            SELECT t.id, t.name, u.name, t.max_duration, t.active, 0, ''
            FROM access_tokens AS t
            JOIN users AS u ON u.id = t.user_id
            WHERE t.removed = 0
              AND t.id > ?1
              AND u.name = ?3
            ORDER BY t.id
            LIMIT ?2
        "),
        _ => return Err(Error::input("unknown list operation")),
    };
    let scoped_to_user = matches!(op, Operation::ListAccessTokens | Operation::ListUserZones);
    let mut statement = db.prepare(sql)?;
    let mut rows = if scoped_to_user {
        user_id(db, &command.user)?;
        statement.query(params![cursor, page_size + 1, command.user])?
    } else {
        statement.query(params![cursor, page_size + 1])?
    };
    let mut resources = Vec::new();
    while let Some(row) = rows.next()? {
        let mut resource = Resource {
            id: row.get(0)?,
            name: row.get(1)?,
            user: row.get(2)?,
            max_duration: row.get(3)?,
            active: row.get(4)?,
            totp_enrolled: row.get(5)?,
            fingerprint: row.get(6)?,
            ..Default::default()
        };
        if op == Operation::ListUsers {
            resource.zones = granted_zones(db, &resource.id)?;
        }
        resources.push(resource);
    }
    let next_page_token = if resources.len() > page_size as usize {
        resources.pop();
        let last = resources.last().ok_or_else(Error::internal)?;
        encode_page_token(op, command, &last.id)
    } else {
        String::new()
    };
    Ok(Reply {
        request_id: command.request_id.clone(),
        resources,
        next_page_token,
        ..Default::default()
    })
}

fn granted_zones(db: &Connection, user_id: &str) -> Result<Vec<String>> {
    #[rustfmt::skip]
    let mut statement = db.prepare(indoc!("
        SELECT z.name
        FROM user_zones AS g
        JOIN zones AS z ON z.id = g.zone_id
        WHERE g.user_id = ?1
        ORDER BY z.name
    "))?;
    let names = statement
        .query_map([user_id], |row| row.get(0))?
        .collect::<std::result::Result<_, _>>()?;
    Ok(names)
}
