use std::{fmt::{Debug, Display}, str::FromStr, time::{SystemTime, UNIX_EPOCH}};

use base32::Alphabet;
use http_app::hyper::Uri;
use totp_lite::{Sha1, DEFAULT_STEP};

#[derive(PartialEq, Eq)]
pub struct TotpSecret {
    issuer: String,
    secret: Vec<u8>,
}

impl Debug for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "TotpSecret{{issuer: {:?}, secret: \"<secret>\"}}", self.issuer)
    }
}

const ALPHABET: Alphabet = base32::Alphabet::Rfc4648 { padding: false };

impl TotpSecret {
    pub fn new(issuer: String, secret: Vec<u8>) -> Self {
        TotpSecret { issuer, secret }
    }

    pub fn get_code(&self) -> String {
        let seconds: u64 = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        totp_lite::totp_custom::<Sha1>(DEFAULT_STEP, 6, &self.secret, seconds).to_string()
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}

impl Display for TotpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let encoded = base32::encode(ALPHABET, &self.secret);
        write!(f, "otpauth://totp/{}?secret={}&issuer={}&algorithm=sha1&digits=6", self.issuer, encoded, self.issuer)
    }
}

impl FromStr for TotpSecret {
    type Err = TotpSecretParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let uri = Uri::from_str(s).map_err(TotpSecretParseError::FailedToParseUri)?;
        if uri.scheme().map(|v| v.as_str()) != Some("otpauth") {
            return Err(TotpSecretParseError::InvalidScheme);
        }

        if uri.host() != Some("totp") {
            return Err(TotpSecretParseError::NotTotpUri);
        }

        let issuer = uri.path().trim_start_matches("/").to_string();
        let mut secret_slice = None;

        if let Some(query) = uri.query() {
            for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
                if key.eq_ignore_ascii_case("issuer") {
                    if value != issuer {
                        return Err(TotpSecretParseError::UnexpectedIssuerKey(value.to_string()));
                    }
                    continue;
                }

                if key.eq_ignore_ascii_case("secret") {
                    if secret_slice.is_some() {
                        return Err(TotpSecretParseError::DuplicateSecretParam);
                    }
                    secret_slice = Some(value);
                    continue;
                }

                if key.eq_ignore_ascii_case("algorithm")  {
                    if !value.eq_ignore_ascii_case("sha1") {
                        return Err(TotpSecretParseError::UnexpectedIssuerValue(key.to_string(), value.to_string()));
                    }
                    continue;
                }

                if key.eq_ignore_ascii_case("digits") {
                    if !value.eq_ignore_ascii_case("6") {
                        return Err(TotpSecretParseError::UnexpectedIssuerValue(key.to_string(), value.to_string()));
                    }
                    continue;
                }

                return Err(TotpSecretParseError::UnexpectedIssuerKey(key.to_string()));
            }
        }

        let secret_slice = secret_slice.ok_or(TotpSecretParseError::MissingSecret)?;
        let secret = base32::decode(ALPHABET, &secret_slice)
            .ok_or(TotpSecretParseError::InvalidSecretEncoding)?;

        Ok(TotpSecret {
            issuer,
            secret,
        })
    }
}

#[derive(Debug)]
pub enum TotpSecretParseError {
    FailedToParseUri(<Uri as FromStr>::Err),
    InvalidScheme,
    NotTotpUri,
    UnsupportedParam(String),
    UnexpectedIssuerKey(String),
    UnexpectedIssuerValue(String, String),
    DuplicateSecretParam,
    MissingSecret,
    InvalidSecretEncoding,
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::TotpSecret;

    #[test]
    fn totp_secret_parse_test() {
        let s = "otpauth://totp/playit.gg?secret=MZSHGYLKMZVWYZDTMFVGM23MMRZWC2TGNNWGIYLT&issuer=playit.gg";
        let parse = TotpSecret::from_str(s).unwrap();
        assert_eq!(parse.secret, base32::decode(base32::Alphabet::Rfc4648 { padding: false }, "MZSHGYLKMZVWYZDTMFVGM23MMRZWC2TGNNWGIYLT").unwrap());

        let there_and_back = TotpSecret::from_str(&parse.to_string()).unwrap();
        assert_eq!(there_and_back, parse);
    }
}


