use crate::{
    auth,
    error::{Error, Result},
    protocol::{Command, Reply, Resource},
};
use anyhow::Context;
use fs2::FileExt;
use prost::Message;
use rusqlite::{Connection, OptionalExtension, params};
use std::{
    collections::HashMap,
    fs::{File, OpenOptions},
    os::unix::fs::OpenOptionsExt,
    path::Path,
};
use zeroize::{Zeroize, Zeroizing};

pub struct Database {
    pub connection: Connection,
    pub issuance_count: u64,
    keys: HashMap<String, ssh_key::PrivateKey>,
    _lock: DatabaseLock,
}
#[derive(Clone)]
pub struct DatabaseLock {
    _inner: std::sync::Arc<LockedFile>,
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
    file.try_lock_exclusive().with_context(|| format!(
        "cannot acquire lock {}. Another process may be using {}; stop it before starting another server or performing offline maintenance",
        lock_path.display(), path.display()
    ))?;
    Ok(DatabaseLock {
        _inner: std::sync::Arc::new(LockedFile(file)),
    })
}
fn connect(path: &Path, secret: &str) -> Result<Connection> {
    let raw = auth::bootstrap(secret)?;
    let conn = Connection::open_with_flags(
        path,
        rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    let key = Zeroizing::new(format!("x'{}'", hex::encode(&*raw)));
    conn.pragma_update(None, "cipher_log_level", "NONE")?;
    conn.pragma_update(None, "key", &*key)?;
    let cipher: String = conn
        .query_row("PRAGMA cipher_version", [], |r| r.get(0))
        .map_err(|_| Error::internal())?;
    if cipher.is_empty() {
        return Err(Error::internal());
    }
    conn.execute_batch("PRAGMA temp_store=MEMORY; PRAGMA journal_mode=DELETE; PRAGMA foreign_keys=ON; PRAGMA secure_delete=ON; PRAGMA cipher_memory_security=ON;")?;
    conn.busy_timeout(std::time::Duration::from_secs(2))?;
    Ok(conn)
}
impl Database {
    pub fn initialize(path: &Path, secret: &str, admin: &str, name: &str) -> anyhow::Result<()> {
        if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
            anyhow::bail!("instance name requires 1–128 printable characters");
        }
        let credential = auth::key(admin)?;
        if credential.kind != "ad" {
            anyhow::bail!("an admin key must use the esca_ad format");
        }
        auth::bootstrap(secret)?;
        crate::config::private_parent(path)?;
        let _lock = lock(path)?;
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)?;
        let result = (|| -> anyhow::Result<()> {
            let mut conn = connect(path, secret)?;
            let tx = conn.transaction()?;
            tx.execute_batch(include_str!("schema.sql"))?;
            let now = auth::now();
            tx.execute(
                "INSERT INTO metadata VALUES(1,?1,?2,?3)",
                params![auth::id(), name, now],
            )?;
            tx.execute(
                "INSERT INTO admin_credentials VALUES(?1,?2,?3,1,?4,?4)",
                params![auth::id(), credential.id, credential.digest, now],
            )?;
            tx.commit()?;
            file.sync_all()?;
            crate::config::sync_parent(path)?;
            Ok(())
        })();
        if result.is_err() {
            drop(file);
            let _ = std::fs::remove_file(path);
        }
        result
    }
    pub fn open(path: &Path, secret: &str) -> Result<Self> {
        let lock = lock(path).map_err(|_| {
            Error::new(
                tonic::Code::Unavailable,
                "DATABASE_BUSY",
                "database is in use",
            )
        })?;
        Self::open_with_lock(path, secret, lock)
    }
    pub fn open_with_lock(path: &Path, secret: &str, lock: DatabaseLock) -> Result<Self> {
        Self::open_with_lock_until(
            path,
            secret,
            lock,
            std::time::Instant::now() + std::time::Duration::from_secs(10),
        )
    }
    pub fn open_with_lock_until(
        path: &Path,
        secret: &str,
        lock: DatabaseLock,
        deadline: std::time::Instant,
    ) -> Result<Self> {
        let mut connection = connect(path, secret).map_err(|_| Error::auth())?;
        connection.progress_handler(1000, Some(move || std::time::Instant::now() >= deadline))?;
        let version: i64 = connection
            .query_row("SELECT version FROM metadata", [], |r| r.get(0))
            .map_err(|_| Error::auth())?;
        if version != 1 {
            return Err(Error::new(
                tonic::Code::FailedPrecondition,
                "SCHEMA_VERSION",
                "unsupported database schema version",
            ));
        }
        let integrity: String = connection.query_row("PRAGMA integrity_check", [], |r| r.get(0))?;
        if integrity != "ok" {
            return Err(Error::internal());
        }
        if connection
            .prepare("PRAGMA cipher_integrity_check")?
            .query([])?
            .next()?
            .is_some()
        {
            return Err(Error::internal());
        }
        if connection
            .prepare("PRAGMA foreign_key_check")?
            .query([])?
            .next()?
            .is_some()
        {
            return Err(Error::internal());
        }
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        prune_audit(&tx)?;
        let mut fingerprints = HashMap::new();
        let mut keys = HashMap::new();
        {
            let mut stmt = tx.prepare("SELECT id,private_key,name,fingerprint FROM zones")?;
            for row in stmt.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })? {
                let (id, pem, name, stored_fingerprint) = row?;
                let pem = Zeroizing::new(pem);
                let ca = ssh_key::PrivateKey::from_openssh(pem.as_bytes())?;
                let fingerprint = ca.fingerprint(ssh_key::HashAlg::Sha256).to_string();
                if let Some(other) = fingerprints.insert(fingerprint.clone(), name.clone()) {
                    return Err(Error::new(
                        tonic::Code::FailedPrecondition,
                        "DUPLICATE_CA",
                        format!(
                            "zones {other:?} and {name:?} share CA {fingerprint}; separate their CA keys and host trust before unlocking"
                        ),
                    ));
                }
                if fingerprint != stored_fingerprint {
                    return Err(Error::new(
                        tonic::Code::FailedPrecondition,
                        "CA_IDENTITY_MISMATCH",
                        format!("zone {name:?} has an inconsistent CA fingerprint"),
                    ));
                }
                keys.insert(id, ca);
            }
        }
        tx.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS zone_ca_public_key ON zones(public_key)",
            [],
        )?;
        tx.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS zone_ca_fingerprint ON zones(fingerprint)",
            [],
        )?;
        tx.commit()?;
        let issuance_count =
            connection.query_row("SELECT count(*) FROM issued_certificates", [], |r| r.get(0))?;
        connection.progress_handler(0, None::<fn() -> bool>)?;
        Ok(Self {
            connection,
            issuance_count,
            keys,
            _lock: lock,
        })
    }
    pub fn reset_admin(&mut self, replacement: &str) -> Result<()> {
        let key = auth::key(replacement)?;
        if key.kind != "ad" {
            return Err(Error::input("admin key required"));
        }
        let tx = self.connection.transaction()?;
        tx.execute(
            "UPDATE admin_credentials SET active=0,updated_at=?1",
            [auth::now()],
        )?;
        tx.execute(
            "INSERT INTO admin_credentials VALUES(?1,?2,?3,1,?4,?4)",
            params![auth::id(), key.id, key.digest, auth::now()],
        )?;
        audit(
            &tx,
            "offline",
            "operator",
            "ResetAdminKey",
            "OK",
            &auth::id(),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn execute(
        &mut self,
        operation: &str,
        credential: &str,
        command: &Command,
    ) -> Result<Reply> {
        auth::request_id(&command.request_id)?;
        if operation == "GetPublicKey" {
            return public_key(&self.connection, &command.zone, &command.request_id);
        }
        let admin = is_admin(operation);
        let parsed = auth::key(credential).inspect_err(|_| {
            let _ = audit(
                &self.connection,
                "",
                "",
                operation,
                "MALFORMED_CREDENTIAL",
                &command.request_id,
            );
        })?;
        let mut actor = authenticate(&self.connection, &parsed, admin);
        if actor
            .as_ref()
            .is_err_and(|e| e.code == tonic::Code::Unauthenticated)
            && matches!(operation, "RotateToken" | "RotateAdminKey")
            && let Ok(candidate) = auth::key(&command.replacement_key)
            && let Ok(a) = authenticate(&self.connection, &candidate, admin)
        {
            let digest:Option<Vec<u8>>=self.connection.query_row("SELECT auth_digest FROM idempotency_records WHERE actor=?1 AND operation=?2 AND request_id=?3 AND expires_at>?4",params![a.id,operation,command.request_id,auth::now()],|r|r.get(0)).optional()?;
            if digest.is_some_and(|d| auth::equal(&d, &parsed.digest)) {
                actor = Ok(a);
            }
        }
        let actor = actor.inspect_err(|error| {
            let _ = audit(
                &self.connection,
                &parsed.kind,
                &parsed.id,
                operation,
                error.reason,
                &command.request_id,
            );
        })?;
        let result = self.execute_as(operation, &parsed, &actor, command);
        if let Err(ref error) = result {
            audit(
                &self.connection,
                &actor.kind,
                &actor.id,
                operation,
                error.reason,
                &command.request_id,
            )?;
        }
        result
    }
    fn execute_as(
        &mut self,
        op: &str,
        key: &auth::Key,
        actor: &Actor,
        c: &Command,
    ) -> Result<Reply> {
        if op.starts_with("List") {
            return list(&self.connection, op, c);
        }
        let payload = auth::hash(&Zeroizing::new(c.encode_to_vec()));
        let tx = self.connection.transaction()?;
        tx.execute(
            "DELETE FROM idempotency_records WHERE expires_at<=?1",
            [auth::now()],
        )?;
        let existing:Option<(Vec<u8>,Vec<u8>,bool)>=tx.query_row("SELECT payload_digest,response,secret_response FROM idempotency_records WHERE actor=?1 AND operation=?2 AND request_id=?3",params![actor.id,op,c.request_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        if let Some((hash, response, secret)) = existing {
            if !auth::equal(&hash, &payload) {
                return Err(Error::new(
                    tonic::Code::AlreadyExists,
                    "REQUEST_CONFLICT",
                    "request UUID was already used with different input",
                ));
            }
            if secret {
                return Err(Error::new(
                    tonic::Code::AlreadyExists,
                    "SECRET_ALREADY_DELIVERED",
                    "one-time secret was already delivered; remove and recreate the token or restart enrollment",
                ));
            }
            if op == "SignCertificate" {
                signing_zone(&tx, &c.zone, &actor.user_id)?;
            }
            return Reply::decode(response.as_slice()).map_err(|_| Error::internal());
        }
        let count: u64 =
            tx.query_row("SELECT count(*) FROM idempotency_records", [], |r| r.get(0))?;
        if count >= 100_000 {
            return Err(Error::new(
                tonic::Code::ResourceExhausted,
                "IDEMPOTENCY_FULL",
                "retry storage is full",
            ));
        }
        let mut reply = Reply {
            request_id: c.request_id.clone(),
            ..Default::default()
        };
        let now = auth::now();
        let mut new_ca = None;
        match op {
            "CreateZone" | "ImportZone" => {
                auth::name(&c.name)?;
                auth::duration(c.max_duration)?;
                let id = auth::id();
                let ca = if op == "ImportZone" {
                    crate::signing::import(&c.secret)?
                } else {
                    crate::signing::generate(&c.name)?
                };
                let pem = ca.to_openssh(ssh_key::LineEnding::LF)?;
                let public = ca.public_key().to_openssh()?;
                let fingerprint = ca
                    .public_key()
                    .fingerprint(ssh_key::HashAlg::Sha256)
                    .to_string();
                let duplicate: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM zones WHERE fingerprint=?1)",
                    [&fingerprint],
                    |r| r.get(0),
                )?;
                if duplicate {
                    return Err(Error::new(
                        tonic::Code::AlreadyExists,
                        "DUPLICATE_CA",
                        "CA key already belongs to a zone, including inactive zones",
                    ));
                }
                tx.execute(
                    "INSERT INTO zones VALUES(?1,?2,?3,?4,?5,?6,1,1,?7,?7)",
                    params![id, c.name, &*pem, public, fingerprint, c.max_duration, now],
                )?;
                reply.resources.push(Resource {
                    id: id.clone(),
                    name: c.name.clone(),
                    max_duration: c.max_duration,
                    active: true,
                    fingerprint,
                    ..Default::default()
                });
                new_ca = Some((id, ca));
            }
            "CreateUser" => {
                auth::name(&c.name)?;
                auth::duration(c.max_duration)?;
                let id = auth::id();
                tx.execute("INSERT INTO users(id,name,max_duration,created_at,updated_at) VALUES(?1,?2,?3,?4,?4)",params![id,c.name,c.max_duration,now])?;
                reply.resources.push(Resource {
                    id,
                    name: c.name.clone(),
                    max_duration: c.max_duration,
                    active: true,
                    ..Default::default()
                });
            }
            "UpdateZone" | "UpdateUser" => {
                auth::name(&c.name)?;
                if c.max_duration != 0 {
                    auth::duration(c.max_duration)?;
                }
                if c.max_duration == 0 && c.active.is_none() {
                    return Err(Error::input("an update requires a duration or state"));
                }
                let sql = if op == "UpdateZone" {
                    "UPDATE zones SET max_duration=CASE WHEN ?1=0 THEN max_duration ELSE ?1 END,active=coalesce(?2,active),updated_at=?3 WHERE name=?4"
                } else {
                    "UPDATE users SET max_duration=CASE WHEN ?1=0 THEN max_duration ELSE ?1 END,active=coalesce(?2,active),updated_at=?3 WHERE name=?4 AND removed=0"
                };
                changed(tx.execute(sql, params![c.max_duration, c.active, now, c.name])?)?;
            }
            "RemoveUser" => {
                let user = user_id(&tx, &c.name)?;
                tx.execute("UPDATE users SET active=0,removed=1,totp_secret=NULL,pending_secret=NULL,updated_at=?1 WHERE id=?2",params![now,user])?;
                tx.execute(
                    "UPDATE access_tokens SET active=0,removed=1,updated_at=?1 WHERE user_id=?2",
                    params![now, user],
                )?;
                tx.execute("DELETE FROM user_zones WHERE user_id=?1", [user])?;
            }
            "GrantZone" | "RevokeZone" => {
                let user = user_id(&tx, &c.user)?;
                let zone = zone_id(&tx, &c.zone)?;
                if op == "GrantZone" {
                    tx.execute(
                        "INSERT OR IGNORE INTO user_zones VALUES(?1,?2)",
                        params![user, zone],
                    )?;
                } else {
                    tx.execute(
                        "DELETE FROM user_zones WHERE user_id=?1 AND zone_id=?2",
                        params![user, zone],
                    )?;
                }
            }
            "CreateAccessToken" => {
                auth::name(&c.name)?;
                auth::duration(c.max_duration)?;
                let user = user_id(&tx, &c.user)?;
                let secret = auth::new_key("at");
                let key = auth::key(&secret)?;
                let id = auth::id();
                tx.execute(
                    "INSERT INTO access_tokens VALUES(?1,?2,?3,1,0,?4,?5,?6,?7,?7)",
                    params![id, user, c.name, c.max_duration, key.id, key.digest, now],
                )?;
                reply.api_key = secret.to_string();
                reply.resources.push(Resource {
                    id,
                    name: c.name.clone(),
                    user: c.user.clone(),
                    max_duration: c.max_duration,
                    active: true,
                    ..Default::default()
                });
            }
            "UpdateAccessToken" | "RemoveAccessToken" => {
                auth::name(&c.name)?;
                let user = user_id(&tx, &c.user)?;
                if op == "RemoveAccessToken" {
                    changed(tx.execute("UPDATE access_tokens SET active=0,removed=1,updated_at=?1 WHERE user_id=?2 AND name=?3 AND removed=0",params![now,user,c.name])?)?;
                } else {
                    if c.max_duration != 0 {
                        auth::duration(c.max_duration)?;
                    }
                    if c.max_duration == 0 && c.active.is_none() {
                        return Err(Error::input("an update requires a duration or state"));
                    }
                    changed(tx.execute("UPDATE access_tokens SET max_duration=CASE WHEN ?1=0 THEN max_duration ELSE ?1 END,active=coalesce(?2,active),updated_at=?3 WHERE user_id=?4 AND name=?5 AND removed=0",params![c.max_duration,c.active,now,user,c.name])?)?;
                }
            }
            "ClearTotp" => {
                let user = user_id(&tx, &c.user)?;
                tx.execute("UPDATE users SET totp_secret=NULL,pending_secret=NULL,pending_expires=NULL,last_step=-1,updated_at=?1 WHERE id=?2",params![now,user])?;
            }
            "BeginTotpEnrollment" => {
                if actor.totp.is_some() {
                    return Err(Error::new(
                        tonic::Code::FailedPrecondition,
                        "TOTP_ENROLLED",
                        "only an administrator can clear confirmed TOTP",
                    ));
                }
                let secret = auth::totp_secret();
                tx.execute("UPDATE users SET pending_secret=?1,pending_expires=?2,updated_at=?3 WHERE id=?4",params![&*secret,now+600,now,actor.user_id])?;
                let instance: String =
                    tx.query_row("SELECT name FROM metadata", [], |r| r.get(0))?;
                let mut uri = url::Url::parse("otpauth://totp/").map_err(|_| Error::internal())?;
                uri.set_path(&format!("{instance}:{}", actor.username));
                uri.query_pairs_mut()
                    .append_pair("secret", &secret)
                    .append_pair("issuer", &instance)
                    .append_pair("algorithm", "SHA1")
                    .append_pair("digits", "6")
                    .append_pair("period", "30");
                reply.secret = secret.to_string();
                reply.otpauth_uri = uri.to_string();
            }
            "ConfirmTotpEnrollment" => {
                if actor.totp.is_some() {
                    return Err(Error::new(
                        tonic::Code::FailedPrecondition,
                        "TOTP_ENROLLED",
                        "TOTP already enrolled",
                    ));
                }
                let (secret, expiry): (Option<String>, Option<u64>) = tx.query_row(
                    "SELECT pending_secret,pending_expires FROM users WHERE id=?1",
                    [&actor.user_id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )?;
                let secret = Zeroizing::new(
                    secret
                        .filter(|_| expiry.is_some_and(|x| x > now))
                        .ok_or_else(|| {
                            Error::new(
                                tonic::Code::FailedPrecondition,
                                "ENROLLMENT_EXPIRED",
                                "start a new TOTP enrollment",
                            )
                        })?,
                );
                let step = auth::totp_step(&secret, &c.totp, -1, now)?;
                tx.execute("UPDATE users SET totp_secret=?1,pending_secret=NULL,pending_expires=NULL,last_step=?2,updated_at=?3 WHERE id=?4",params![&*secret,step,now,actor.user_id])?;
            }
            "RotateToken" | "RotateAdminKey" => {
                let replacement = auth::key(&c.replacement_key)?;
                if replacement.kind != key.kind || replacement.id == key.id {
                    return Err(Error::input(
                        "replacement must be a fresh key of the same kind",
                    ));
                }
                if op == "RotateToken" {
                    check_totp(&tx, actor, &c.totp, now)?;
                    tx.execute(
                        "UPDATE access_tokens SET key_id=?1,digest=?2,updated_at=?3 WHERE id=?4",
                        params![replacement.id, replacement.digest, now, actor.id],
                    )?;
                } else {
                    tx.execute("UPDATE admin_credentials SET key_id=?1,digest=?2,updated_at=?3 WHERE id=?4",params![replacement.id,replacement.digest,now,actor.id])?;
                }
            }
            "SignCertificate" => {
                auth::name(&c.zone)?;
                let requested = if c.duration == 0 {
                    86400
                } else {
                    auth::duration(c.duration)?
                };
                let (zone, limit, serial) = signing_zone(&tx, &c.zone, &actor.user_id)?;
                check_totp(&tx, actor, &c.totp, now)?;
                let effective = requested
                    .min(limit)
                    .min(actor.user_limit)
                    .min(actor.token_limit);
                if serial >= i64::MAX as u64 {
                    return Err(Error::new(
                        tonic::Code::ResourceExhausted,
                        "SERIAL_EXHAUSTED",
                        "certificate serial limit reached",
                    ));
                }
                let ca = self.keys.get(&zone).ok_or_else(Error::internal)?;
                reply.certificate = crate::signing::sign(
                    ca,
                    &c.public_key,
                    &actor.username,
                    serial,
                    &c.request_id,
                    now,
                    effective,
                )?;
                let fingerprint = ssh_key::PublicKey::from_openssh(&c.public_key)?
                    .fingerprint(ssh_key::HashAlg::Sha256)
                    .to_string();
                tx.execute(
                    "UPDATE zones SET next_serial=next_serial+1 WHERE id=?1",
                    [&zone],
                )?;
                tx.execute(
                    "INSERT INTO issued_certificates VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                    params![
                        zone,
                        serial,
                        actor.user_id,
                        actor.id,
                        fingerprint,
                        now.saturating_sub(300),
                        now + effective,
                        c.request_id,
                        now
                    ],
                )?;
                reply.expires_at = now + effective;
                reply.effective_duration = effective;
            }
            _ => return Err(Error::input("unknown operation")),
        }
        let secret = !reply.api_key.is_empty() || !reply.secret.is_empty();
        let mut saved = reply.clone();
        saved.api_key.zeroize();
        saved.secret.zeroize();
        saved.otpauth_uri.zeroize();
        tx.execute(
            "INSERT INTO idempotency_records VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
            params![
                actor.id,
                op,
                c.request_id,
                payload,
                key.digest,
                saved.encode_to_vec(),
                secret,
                now + 86400
            ],
        )?;
        audit(&tx, &actor.kind, &actor.id, op, "OK", &c.request_id)?;
        tx.commit()?;
        if op == "SignCertificate" {
            self.issuance_count += 1;
        }
        if let Some((id, ca)) = new_ca {
            self.keys.insert(id, ca);
        }
        Ok(reply)
    }
}
fn signing_zone(db: &Connection, zone: &str, user_id: &str) -> Result<(String, u64, u64)> {
    db.query_row(
        "SELECT z.id,z.max_duration,z.next_serial FROM zones z JOIN user_zones g ON g.zone_id=z.id WHERE z.name=?1 AND z.active=1 AND g.user_id=?2",
        params![zone, user_id],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )
    .optional()?
    .ok_or_else(Error::denied)
}
fn changed(n: usize) -> Result<()> {
    if n == 0 {
        Err(Error::new(
            tonic::Code::NotFound,
            "NOT_FOUND",
            "resource not found",
        ))
    } else {
        Ok(())
    }
}
pub fn is_admin(op: &str) -> bool {
    matches!(
        op,
        "CreateZone"
            | "ImportZone"
            | "ListZones"
            | "UpdateZone"
            | "CreateUser"
            | "ListUsers"
            | "UpdateUser"
            | "RemoveUser"
            | "GrantZone"
            | "RevokeZone"
            | "ListUserZones"
            | "CreateAccessToken"
            | "ListAccessTokens"
            | "UpdateAccessToken"
            | "RemoveAccessToken"
            | "ClearTotp"
            | "RotateAdminKey"
    )
}
fn user_id(db: &Connection, name: &str) -> Result<String> {
    auth::name(name)?;
    Ok(db.query_row(
        "SELECT id FROM users WHERE name=?1 AND removed=0",
        [name],
        |r| r.get(0),
    )?)
}
fn zone_id(db: &Connection, name: &str) -> Result<String> {
    auth::name(name)?;
    Ok(db.query_row("SELECT id FROM zones WHERE name=?1", [name], |r| r.get(0))?)
}
struct Actor {
    id: String,
    kind: String,
    user_id: String,
    username: String,
    user_limit: u64,
    token_limit: u64,
    totp: Option<Zeroizing<String>>,
    last_step: i64,
}
fn authenticate(db: &Connection, key: &auth::Key, admin: bool) -> Result<Actor> {
    if admin && key.kind != "ad" || !admin && key.kind != "at" {
        return Err(Error::denied());
    }
    if admin {
        let (id, digest): (String, Vec<u8>) = db
            .query_row(
                "SELECT id,digest FROM admin_credentials WHERE key_id=?1 AND active=1",
                [&key.id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .ok_or_else(Error::auth)?;
        if !auth::equal(&digest, &key.digest) {
            return Err(Error::auth());
        }
        return Ok(Actor {
            id,
            kind: "admin".into(),
            user_id: String::new(),
            username: String::new(),
            user_limit: 0,
            token_limit: 0,
            totp: None,
            last_step: -1,
        });
    }
    let row=db.query_row("SELECT t.id,t.digest,u.id,u.name,u.max_duration,t.max_duration,u.totp_secret,u.last_step FROM access_tokens t JOIN users u ON u.id=t.user_id WHERE t.key_id=?1 AND t.active=1 AND t.removed=0 AND u.active=1 AND u.removed=0",[&key.id],|r|Ok((r.get::<_,Vec<u8>>(1)?,Actor {id:r.get(0)?,kind:"access_token".into(),user_id:r.get(2)?,username:r.get(3)?,user_limit:r.get(4)?,token_limit:r.get(5)?,totp:r.get::<_,Option<String>>(6)?.map(Zeroizing::new),last_step:r.get(7)?}))).optional()?.ok_or_else(Error::auth)?;
    if !auth::equal(&row.0, &key.digest) {
        return Err(Error::auth());
    }
    Ok(row.1)
}
fn check_totp(db: &Connection, actor: &Actor, code: &str, now: u64) -> Result<()> {
    if let Some(secret) = &actor.totp {
        let step = auth::totp_step(secret, code, actor.last_step, now)?;
        db.execute(
            "UPDATE users SET last_step=?1 WHERE id=?2",
            params![step, actor.user_id],
        )?;
    }
    Ok(())
}
fn prune_audit(db: &Connection) -> Result<()> {
    db.execute(
        "DELETE FROM audit_events WHERE rowid <= (SELECT rowid FROM audit_events ORDER BY rowid DESC LIMIT 1 OFFSET 10000)",
        [],
    )?;
    Ok(())
}
fn audit(
    db: &Connection,
    kind: &str,
    actor: &str,
    op: &str,
    result: &str,
    request: &str,
) -> Result<()> {
    db.execute(
        "INSERT INTO audit_events VALUES(?1,?2,?3,?4,?5,?6,?7)",
        params![auth::id(), kind, actor, op, result, request, auth::now()],
    )?;
    prune_audit(db)?;
    Ok(())
}
fn public_key(db: &Connection, zone: &str, id: &str) -> Result<Reply> {
    auth::name(zone)?;
    let (public_key, fingerprint) = db.query_row(
        "SELECT public_key,fingerprint FROM zones WHERE name=?1 AND active=1",
        [zone],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Reply {
        request_id: id.into(),
        public_key,
        fingerprint,
        ..Default::default()
    })
}
fn list(db: &Connection, op: &str, c: &Command) -> Result<Reply> {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    let size = if c.page_size == 0 {
        100
    } else {
        c.page_size.min(100)
    };
    let cursor = if c.page_token.is_empty() {
        String::new()
    } else {
        let raw = URL_SAFE_NO_PAD
            .decode(&c.page_token)
            .map_err(|_| Error::input("invalid page token"))?;
        let raw = String::from_utf8(raw).map_err(|_| Error::input("invalid page token"))?;
        let prefix = format!("{op}:{}:", c.user);
        let id = raw
            .strip_prefix(&prefix)
            .ok_or_else(|| Error::input("page token belongs to another query"))?;
        auth::request_id(id)?;
        id.into()
    };
    let sql = match op {
        "ListZones" => {
            "SELECT id,name,'',max_duration,active,0,fingerprint FROM zones WHERE id>?1 ORDER BY id LIMIT ?2"
        }
        "ListUsers" => {
            "SELECT id,name,'',max_duration,active,totp_secret IS NOT NULL,'' FROM users WHERE removed=0 AND id>?1 ORDER BY id LIMIT ?2"
        }
        "ListUserZones" => include_str!("queries/list_user_zones.sql"),
        "ListAccessTokens" => {
            "SELECT t.id,t.name,u.name,t.max_duration,t.active,0,'' FROM access_tokens t JOIN users u ON u.id=t.user_id WHERE t.removed=0 AND t.id>?1 AND u.name=?3 ORDER BY t.id LIMIT ?2"
        }
        _ => return Err(Error::input("unknown list operation")),
    };
    let mut stmt = db.prepare(sql)?;
    let mut rows = if matches!(op, "ListAccessTokens" | "ListUserZones") {
        user_id(db, &c.user)?;
        stmt.query(params![cursor, size + 1, c.user])?
    } else {
        stmt.query(params![cursor, size + 1])?
    };
    let mut resources = Vec::new();
    while let Some(r) = rows.next()? {
        let mut resource = Resource {
            id: r.get(0)?,
            name: r.get(1)?,
            user: r.get(2)?,
            max_duration: r.get(3)?,
            active: r.get(4)?,
            totp_enrolled: r.get(5)?,
            fingerprint: r.get(6)?,
            ..Default::default()
        };
        if op == "ListUsers" {
            let mut grants=db.prepare("SELECT z.name FROM user_zones g JOIN zones z ON z.id=g.zone_id WHERE g.user_id=?1 ORDER BY z.name")?;
            resource.zones = grants
                .query_map([&resource.id], |r| r.get(0))?
                .collect::<std::result::Result<_, _>>()?;
        }
        resources.push(resource);
    }
    let next = if resources.len() > size as usize {
        resources.pop();
        URL_SAFE_NO_PAD.encode(format!(
            "{op}:{}:{}",
            c.user,
            resources.last().ok_or_else(Error::internal)?.id
        ))
    } else {
        String::new()
    };
    Ok(Reply {
        request_id: c.request_id.clone(),
        resources,
        next_page_token: next,
        ..Default::default()
    })
}
