use prost::Message;
use tonic::{Code, Status};

pub type Result<T> = std::result::Result<T, Error>;

/// A failure with a stable machine-readable `reason` for clients and audit logs.
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

    pub fn not_found() -> Self {
        Self::new(Code::NotFound, "NOT_FOUND", "resource not found")
    }

    pub fn locked() -> Self {
        Self::failed_precondition("LOCKED", "server is locked")
    }

    pub fn internal() -> Self {
        Self::new(Code::Internal, "INTERNAL", "internal operation failed")
    }

    pub fn failed_precondition(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(Code::FailedPrecondition, reason, message)
    }

    pub fn already_exists(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(Code::AlreadyExists, reason, message)
    }

    pub fn exhausted(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(Code::ResourceExhausted, reason, message)
    }

    pub fn unavailable(reason: &'static str, message: impl Into<String>) -> Self {
        Self::new(Code::Unavailable, reason, message)
    }

    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(Code::DeadlineExceeded, "TIMEOUT", message)
    }

    /// Convert to a gRPC status carrying an `ErrorDetail` payload and the request id.
    pub fn status(&self, request_id: &str) -> Status {
        let detail = crate::protocol::ErrorDetail {
            request_id: request_id.into(),
            reason: self.reason.into(),
            totp_required: self.reason == "TOTP_REQUIRED",
        };
        let mut status =
            Status::with_details(self.code, &self.message, detail.encode_to_vec().into());
        if let Ok(value) = request_id.parse() {
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
    fn from(error: rusqlite::Error) -> Self {
        use rusqlite::ErrorCode::*;
        match error {
            rusqlite::Error::QueryReturnedNoRows => Self::not_found(),
            rusqlite::Error::SqliteFailure(failure, _) => match failure.code {
                ConstraintViolation => {
                    Self::already_exists("CONFLICT", "resource conflicts with existing state")
                }
                OperationInterrupted => Self::timeout("database operation exceeded its deadline"),
                DatabaseBusy | DatabaseLocked => {
                    Self::unavailable("DATABASE_BUSY", "database is busy")
                }
                _ => Self::internal(),
            },
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
