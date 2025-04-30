use std::{net::IpAddr, str::FromStr, sync::Arc};

use chrono::{DateTime, Utc};
use constant_time_eq::constant_time_eq;
use super::{config::{Config, SignDuration, ValidatedConfig}, ssh_keygen::sign_key, totp::TotpSecret};
use http_app::{BodyExt, Full, HttpServerHandler, body::Incoming, Request, Response, StatusCode, bytes::Bytes};
use ssh_key::{PrivateKey, PublicKey};
use tokio::sync::RwLock;

pub struct WebServer {
    inner: RwLock<Inner>,
}

struct Inner {
    config: Config,
}

impl HttpServerHandler for WebServer {
    type Body = Full<Bytes>;

    async fn handle_request(self: Arc<Self>, source: IpAddr, request: Request<Incoming>) -> Response<Self::Body> {
        tracing::info!(?source, path = %request.uri().path(), "handle request");

        match self.handle(request).await {
            Ok(v) => v,
            Err(WebError(status, message)) => Response::builder()
                .status(status)
                .body(Full::new(format!("{}\n", message).into()))
                .unwrap(),
        }
    }
}

impl WebServer {
    pub fn new(config: ValidatedConfig) -> Arc<Self> {
        Arc::new(WebServer {
            inner: RwLock::new(Inner {
                config: config.into_config(),
            })
        })
    }

    pub async fn update_config(&self, config: ValidatedConfig) {
        let mut lock = self.inner.write().await;
        lock.config = config.into_config();
    }

    async fn handle(&self, request: Request<Incoming>) -> Result<Response<Full<Bytes>>, WebError> {
        let mut parts = request.uri().path().split("/");
        let _ = parts.next();

        match parts.next() {
            Some("pubkey") => {
                let target = parts.next().ok_or(WebError(StatusCode::NOT_FOUND, "/pubkey/<target>"))?;

                let lock = self.inner.read().await;
                let found = lock.config.targets.iter().find(|t| t.name == target).ok_or(WebError(StatusCode::NOT_FOUND, "target not found"))?.clone();
                let ca_pub_path = lock.config.paths.ca_path(&found.name);
                drop(lock);

                let key = load_pubkey(&ca_pub_path).await?;
                Ok(Response::new(Full::new(key.to_openssh().expect("failed to write key").into())))
            }
            Some("sign") => {
                /* parse request */
                let client_s = parts.next().ok_or(WebError(StatusCode::NOT_FOUND, "/sign/<client>/<target>/<user>"))?.to_string();
                let target_s = parts.next().ok_or(WebError(StatusCode::NOT_FOUND, "/sign/<client>/<target>/<user>"))?.to_string();
                let user_s = parts.next().ok_or(WebError(StatusCode::NOT_FOUND, "/sign/<client>/<target>/<user>"))?.to_string();

                let mut totp = None;
                let mut duration = None;

                if let Some(query) = request.uri().query() {
                    for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                        if key.eq_ignore_ascii_case("totp") || key.eq_ignore_ascii_case("t") {
                            totp = Some(value.to_string());
                        }
                        else if key.eq_ignore_ascii_case("duration") || key.eq_ignore_ascii_case("d") {
                            duration = SignDuration::from_param_str(&value.to_ascii_lowercase());
                            if duration.is_none() {
                                return Err(WebError(StatusCode::BAD_REQUEST, "unknown duration parameter options m(inute)/d(day)/h(our)/w(week)"));
                            }
                        }
                    }
                }

                let api_key = parse_api_key(&request)?;

                let lock = self.inner.read().await;
                let client = lock.config.clients.iter().find(|c| c.name == client_s).ok_or(WebError(StatusCode::NOT_FOUND, "unknown client"))?.clone();
                let target = lock.config.targets.iter().find(|t| t.name == target_s).ok_or(WebError(StatusCode::NOT_FOUND, "unknown target"))?.clone();
                let user = lock.config.users.iter().find(|u| u.name == user_s).ok_or(WebError(StatusCode::NOT_FOUND, "unknown user"))?.clone();

                let api_path = lock.config.paths.api_path(&client.name);
                let ca_priv_path = lock.config.paths.ca_priv_path(&target.name);
                let totp_path = lock.config.paths.totp_path(&user.name);

                drop(lock);

                let client_api_key = match tokio::fs::read_to_string(&api_path).await {
                    Ok(key) => key,
                    Err(error) => {
                        tracing::error!(?error, "failed to load api key: {}", api_path);
                        return Err(WebError(StatusCode::INTERNAL_SERVER_ERROR, "failed to load api file"));
                    }
                };

                if !constant_time_eq(client_api_key.trim().as_bytes(), api_key.trim().as_bytes()) {
                    return Err(WebError(StatusCode::UNAUTHORIZED, "invalid api key for client"));
                }

                if !user.allowed_clients.iter().any(|c| c == &client.name) {
                    return Err(WebError(StatusCode::UNAUTHORIZED, "user not allowed to access through client"));
                }

                if !user.allowed_targets.iter().any(|t| t == &target.name) {
                    return Err(WebError(StatusCode::UNAUTHORIZED, "user not allowed to access target"));
                }

                if !user.allow_missing_totp && totp.is_none() {
                    return Err(WebError(StatusCode::UNAUTHORIZED, "totp required"));
                }

                let totp_secret = match tokio::fs::read_to_string(&totp_path).await {
                    Ok(v) => {
                        match TotpSecret::from_str(v.trim()) {
                            Ok(s) => Some(s),
                            Err(error) => {
                                tracing::error!(?error, "failed to load totp secret");
                                return Err(WebError(StatusCode::INTERNAL_SERVER_ERROR, "failed to parse totp secret on server"));
                            }
                        }
                    }
                    Err(error) => {
                        if error.kind() != std::io::ErrorKind::NotFound {
                            tracing::error!(?error, "failed to load totp file: {}", totp_path);
                        }

                        if !user.allow_missing_totp {
                            return Err(WebError(StatusCode::UNAUTHORIZED, "could not load server side secret totp file (maybe missing?)"));
                        }

                        None
                    }
                };

                if let Some(totp_secret) = totp_secret {
                    let Some(code) = totp else {
                        return Err(WebError(StatusCode::UNAUTHORIZED, "request missing totp secret"));
                    };

                    if totp_secret.get_code() != code.trim() {
                        return Err(WebError(StatusCode::UNAUTHORIZED, "invalid totp code"));
                    }
                }

                let to_sign = PublicKey::from_openssh(&load_body_str(request).await?)
                    .map_err(|_| WebError(StatusCode::BAD_REQUEST, "invalid openssh public key in request body"))?;

                /* todo: check totp secret */

                let mut set_duration = target.max_duration.min(client.max_duration).min(user.max_duration);
                set_duration = duration.unwrap_or(set_duration).min(set_duration);

                let priv_key = load_privkey(&ca_priv_path).await?;
                let result = sign_key(&priv_key, &to_sign, &format!("{}@{}", user.name, target.name), &user.name, set_duration).await
                    .map_err(|error| {
                        tracing::error!(?error, "failed to sign key");
                        WebError(StatusCode::INTERNAL_SERVER_ERROR, "failed to sign key")
                    })?;

                let cert = ssh_key::Certificate::from_openssh(&result).map_err(|error| {
                    tracing::error!(?error, "failed to parse certificate");
                    WebError(StatusCode::INTERNAL_SERVER_ERROR, "failed to parse certificate")
                })?;
                
                let expires_at = DateTime::<Utc>::from(cert.valid_before_time());

                Response::builder()
                    .header(http_app::header::EXPIRES, expires_at.to_rfc2822())
                    .body(Full::new(result.into()))
                    .map_err(|error| {
                        tracing::error!(?error, "failed to build response");
                        WebError(StatusCode::INTERNAL_SERVER_ERROR, "failed to build response")
                    })
            }
            path => {
                tracing::warn!(?path, "invalid path");
                Err(WebError(StatusCode::NOT_FOUND, "invalid path"))
            }
        }
    }
}

async fn load_body_str(req: Request<Incoming>) -> Result<String, WebError> {
    let body_bytes = req.into_body().collect().await
        .map_err(|_| WebError(StatusCode::BAD_REQUEST, "failed to read request body"))?
        .to_bytes().to_vec();

    let body_str = String::from_utf8(body_bytes)
        .map_err(|_| WebError(StatusCode::BAD_REQUEST, "invalid request body encoding"))?;

    Ok(body_str)
}

fn parse_api_key<B>(req: &Request<B>) -> Result<String, WebError> {
    let api_key = req.headers().get(http_app::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(WebError(StatusCode::UNAUTHORIZED, "missing AUTHORIZATION header"))?;

    if let Some(key) = api_key.strip_prefix("Api-Key: ") {
        Ok(key.to_string())
    } else {
        Err(WebError(StatusCode::UNAUTHORIZED, "AUTHORIZATION header does start with \"Api-Key: \""))
    }
}

async fn load_pubkey(path: &str) -> Result<PublicKey, WebError> {
    let content = match tokio::fs::read_to_string(&path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound =>
            return Err(WebError(StatusCode::INTERNAL_SERVER_ERROR, "failed to load public key file")),
        Err(error) => {
            tracing::error!(?error, "failed to load pub key");
            return Err(WebError(StatusCode::INTERNAL_SERVER_ERROR, "io error"));
        }
    };

    let Ok(key) = PublicKey::from_openssh(&content) else {
        return Err(WebError(StatusCode::INTERNAL_SERVER_ERROR, "malformed openssh public key"));
    };

    Ok(key)
}

async fn load_privkey(path: &str) -> Result<PrivateKey, WebError> {
    let content = match tokio::fs::read(&path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound =>
            return Err(WebError(StatusCode::INTERNAL_SERVER_ERROR, "failed to load private key file")),
        Err(error) => {
            tracing::error!(?error, "failed to load private key");
            return Err(WebError(StatusCode::INTERNAL_SERVER_ERROR, "io error"));
        }
    };

    let Ok(key) = PrivateKey::from_openssh(&content) else {
        return Err(WebError(StatusCode::INTERNAL_SERVER_ERROR, "malformed openssh private key"));
    };

    Ok(key)
}

pub struct WebError(StatusCode, &'static str);

