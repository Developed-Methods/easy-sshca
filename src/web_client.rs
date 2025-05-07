use chrono::{DateTime, Utc};
use http_app::StatusCode;
use reqwest::header::HeaderValue;
use tls_friend::tls_setup::TlsSetup;

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
    pub fn new(cert: &[u8], host: String) -> Result<Self, std::io::Error> {
        tls_friend::install_crypto();

        let client_tls = TlsSetup::build_client(cert)?;
        let client_config = client_tls.into_client_config()?;

        let client = reqwest::Client::builder()
            .use_preconfigured_tls(client_config)
            .https_only(true)
            .build()
            .unwrap();

        Ok(WebClient {
            client,
            base_url: format!("https://{}", host),
            auth: None,
        })
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
            .header(reqwest::header::AUTHORIZATION, {
                let mut value = HeaderValue::from_str(&format!("Api-Key: {}", auth.api_key.trim())).unwrap();
                value.set_sensitive(true);
                value
            })
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

