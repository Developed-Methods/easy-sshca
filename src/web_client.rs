use chrono::{DateTime, Utc};
use http_app::StatusCode;
use reqwest::Certificate;

use crate::config::SignDuration;

pub struct WebClient {
    base_url: String,
    client: reqwest::Client,
    auth: Option<WebAuth>,
}

pub struct WebAuth {
    pub client_name: String,
    pub api_key: String,
}

impl WebClient {
    pub fn new(cert: Certificate, host: String) -> Self {
        let client = reqwest::Client::builder()
            .tls_built_in_root_certs(false)
            .add_root_certificate(cert)
            .danger_accept_invalid_hostnames(true)
            .https_only(true)
            .build()
            .unwrap();

        WebClient {
            client,
            base_url: format!("https://{}", host),
            auth: None,
        }
    }

    pub fn set_auth(&mut self, auth: WebAuth) {
        self.auth = Some(auth);
    }

    pub async fn pubkey(&self, target: &str) -> Result<String, WebClientError> {
        let resp = self.client.get(format!("{}/pubkey/{}", self.base_url, target))
            .send().await
            .map_err(WebClientError::ReqwestError)?;

        let status = resp.status();
        let text = resp.text().await
            .map_err(WebClientError::ReqwestError)?;

        if !status.is_success() {
            return Err(WebClientError::ResponseError(ErrorResponse {
                status,
                response: text,
            }));
        }

        Ok(text)
    }

    pub async fn sign(&self, sign: SignRequest<'_>) -> Result<SignResponse, WebClientError> {
        let auth = self.auth.as_ref().ok_or(WebClientError::MissingAuth)?;

        let url = if let Some(totp) = sign.totp {
            format!("{}/sign/{}/{}/{}?totp={}&d={}",
                self.base_url,
                auth.client_name,
                sign.target,
                sign.user,
                totp,
                sign.duration.param_str(),
            )
        } else {
            format!("{}/sign/{}/{}/{}?d={}",
                self.base_url,
                auth.client_name,
                sign.target,
                sign.user,
                sign.duration.param_str(),
            )
        };

        let resp = self.client.post(url)
            .header(reqwest::header::AUTHORIZATION, format!("Api-Key: {}", auth.api_key))
            .body(sign.pubkey.to_string())
            .send().await
            .map_err(WebClientError::ReqwestError)?;

        let expires_at = resp.headers()
            .get(reqwest::header::EXPIRES)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| DateTime::parse_from_rfc2822(v).ok())
            .map(|v| v.to_utc());

        let status = resp.status();
        let text = resp.text().await
            .map_err(WebClientError::ReqwestError)?;

        if !status.is_success() {
            return Err(WebClientError::ResponseError(ErrorResponse {
                status,
                response: text,
            }));
        }

        Ok(SignResponse {
            cert: text,
            expires_at,
        })
    }
}

pub struct SignResponse {
    pub cert: String,
    pub expires_at: Option<DateTime<Utc>>,
}

pub struct SignRequest<'a> {
    pub target: &'a str,
    pub user: &'a str,
    pub pubkey: &'a str,
    pub totp: Option<&'a str>,
    pub duration: SignDuration,
}

#[derive(Debug)]
pub enum WebClientError {
    MissingAuth,
    ReqwestError(reqwest::Error),
    ResponseError(ErrorResponse),
}

#[derive(Debug)]
pub struct ErrorResponse {
    pub status: StatusCode,
    pub response: String,
}

