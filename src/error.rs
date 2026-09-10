use prost::Message;
use tonic::{Code, Status};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug)]
pub struct Error {
    pub code: Code,
    pub reason: &'static str,
    pub message: String,
}
impl Error {
    pub fn new(code: Code, reason: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            reason,
            message: message.into(),
        }
    }
    pub fn input(message: impl Into<String>) -> Self {
        Self::new(Code::InvalidArgument, "INVALID_INPUT", message)
    }
    pub fn auth() -> Self {
        Self::new(
            Code::Unauthenticated,
            "INVALID_CREDENTIAL",
            "invalid credential",
        )
    }
    pub fn denied() -> Self {
        Self::new(Code::PermissionDenied, "ACCESS_DENIED", "access denied")
    }
    pub fn locked() -> Self {
        Self::new(Code::FailedPrecondition, "LOCKED", "server is locked")
    }
    pub fn internal() -> Self {
        Self::new(Code::Internal, "INTERNAL", "internal operation failed")
    }
    pub fn status(&self, id: &str) -> Status {
        let detail = crate::protocol::ErrorDetail {
            request_id: id.into(),
            reason: self.reason.into(),
            totp_required: self.reason == "TOTP_REQUIRED",
        };
        let mut status =
            Status::with_details(self.code, &self.message, detail.encode_to_vec().into());
        if let Ok(value) = id.parse() {
            status.metadata_mut().insert("x-request-id", value);
        }
        status
    }
}
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for Error {}
impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        match e {
            rusqlite::Error::QueryReturnedNoRows => {
                Self::new(Code::NotFound, "NOT_FOUND", "resource not found")
            }
            rusqlite::Error::SqliteFailure(ref x, _)
                if x.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Self::new(
                    Code::AlreadyExists,
                    "CONFLICT",
                    "resource conflicts with existing state",
                )
            }
            rusqlite::Error::SqliteFailure(ref x, _)
                if x.code == rusqlite::ErrorCode::OperationInterrupted =>
            {
                Self::new(
                    Code::DeadlineExceeded,
                    "TIMEOUT",
                    "database operation exceeded its deadline",
                )
            }
            rusqlite::Error::SqliteFailure(ref x, _)
                if matches!(
                    x.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) =>
            {
                Self::new(Code::Unavailable, "DATABASE_BUSY", "database is busy")
            }
            _ => Self::internal(),
        }
    }
}
impl From<ssh_key::Error> for Error {
    fn from(_: ssh_key::Error) -> Self {
        Self::input("invalid SSH key or certificate")
    }
}
impl From<std::io::Error> for Error {
    fn from(_: std::io::Error) -> Self {
        Self::internal()
    }
}
