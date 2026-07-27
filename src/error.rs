use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;
use tracing::{error, warn};

pub use crate::models::otp::OtpError;
use crate::ports::crypto::CryptoError;

/// Stable, machine-readable error identifier. Clients branch on these to
/// pick a translated message, so the strings are part of the public API
/// contract — add freely, but rename or remove only as a breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    Internal,
    BadRequest,
    Validation,
    Unauthorized,
    InvalidCredentials,
    Forbidden,
    NotFound,
    Conflict,
    OtpExpired,
    OtpWrongCode,
    OtpAlreadyVerified,
    OtpNotFound,
    OtpMaxAttempts,
    OtpMaxMessages,
    SmsFailed,
}

impl ErrorCode {
    /// Every code, so clients (and the contract test below) can enumerate
    /// the full set that needs a translation.
    pub const ALL: &'static [ErrorCode] = &[
        Self::Internal,
        Self::BadRequest,
        Self::Validation,
        Self::Unauthorized,
        Self::InvalidCredentials,
        Self::Forbidden,
        Self::NotFound,
        Self::Conflict,
        Self::OtpExpired,
        Self::OtpWrongCode,
        Self::OtpAlreadyVerified,
        Self::OtpNotFound,
        Self::OtpMaxAttempts,
        Self::OtpMaxMessages,
        Self::SmsFailed,
    ];

    /// The single source of truth for the wire format: both `Serialize` and
    /// `Display` delegate here so they can never disagree.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Internal => "INTERNAL",
            Self::BadRequest => "BAD_REQUEST",
            Self::Validation => "VALIDATION",
            Self::Unauthorized => "UNAUTHORIZED",
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::Forbidden => "FORBIDDEN",
            Self::NotFound => "NOT_FOUND",
            Self::Conflict => "CONFLICT",
            Self::OtpExpired => "OTP_EXPIRED",
            Self::OtpWrongCode => "OTP_WRONG_CODE",
            Self::OtpAlreadyVerified => "OTP_ALREADY_VERIFIED",
            Self::OtpNotFound => "OTP_NOT_FOUND",
            Self::OtpMaxAttempts => "OTP_MAX_ATTEMPTS",
            Self::OtpMaxMessages => "OTP_MAX_MESSAGES",
            Self::SmsFailed => "SMS_FAILED",
        }
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The JSON body returned for every failed request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApiError {
    pub code: ErrorCode,
    pub message: String,
}

impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("RSA error: {0}")]
    RSA(#[from] rsa::pkcs8::spki::Error),

    #[error("Auth error: {0}")]
    Auth(String),

    #[error("Invalid credentials")]
    InvalidCredentials,

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("Not found")]
    NotFound,

    #[error("Forbidden")]
    Forbidden,

    #[error("OTP error: {0}")]
    Otp(#[from] OtpError),

    #[error("Validation error: {0}")]
    Validation(String),

    /// Escape hatch for one-off errors that don't warrant a named variant.
    /// Prefer a named variant for anything a caller might want to match on.
    #[error("API error: {0} - {1:?}")]
    Api(StatusCode, ApiError),
}

impl ServerError {
    pub fn api(status: StatusCode, code: ErrorCode, message: impl Into<String>) -> Self {
        Self::Api(status, ApiError::new(code, message))
    }

    /// True when the underlying database error is a unique-constraint
    /// violation, letting call sites treat "already exists" as a domain
    /// outcome instead of a server fault.
    pub fn is_unique_violation(&self) -> bool {
        matches!(
            self,
            Self::Database(sqlx::Error::Database(db_err)) if db_err.is_unique_violation()
        )
    }

    /// Maps this error to its wire representation. Internal faults are
    /// logged here and deliberately given opaque messages so that details
    /// never reach the client.
    pub fn to_api_error(self) -> (StatusCode, ApiError) {
        match self {
            Self::Database(err) => {
                error!("Database error: {}", err);
                internal("Database error")
            }
            Self::RSA(err) => {
                error!("RSA error: {}", err);
                internal("Cryptographic error")
            }
            Self::Crypto(err) => {
                error!("Crypto error: {}", err);
                internal("Cryptographic error")
            }
            Self::Auth(msg) => {
                warn!("Auth error: {}", msg);
                (
                    StatusCode::UNAUTHORIZED,
                    ApiError::new(ErrorCode::Unauthorized, msg),
                )
            }
            Self::InvalidCredentials => {
                warn!("Invalid credentials");
                (
                    StatusCode::UNAUTHORIZED,
                    ApiError::new(ErrorCode::InvalidCredentials, "Invalid credentials"),
                )
            }
            Self::NotFound => {
                warn!("Resource not found");
                (
                    StatusCode::NOT_FOUND,
                    ApiError::new(ErrorCode::NotFound, "Not found"),
                )
            }
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                ApiError::new(ErrorCode::Forbidden, "Forbidden"),
            ),
            Self::Validation(msg) => {
                warn!("Validation error: {}", msg);
                (
                    StatusCode::BAD_REQUEST,
                    ApiError::new(ErrorCode::Validation, msg),
                )
            }
            Self::Otp(err) => {
                let (status, body) = err.to_api_error();
                if status.is_server_error() {
                    error!("OTP error: {}", err);
                } else {
                    warn!("OTP error: {}", err);
                }
                (status, body)
            }
            Self::Api(status, body) => {
                if status.is_server_error() {
                    error!("API error: {} - {:?}", status, body);
                } else {
                    warn!("API error: {} - {:?}", status, body);
                }
                (status, body)
            }
        }
    }
}

fn internal(message: &str) -> (StatusCode, ApiError) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        ApiError::new(ErrorCode::Internal, message),
    )
}

impl IntoResponse for ServerError {
    fn into_response(self) -> axum::response::Response {
        let (status, body) = self.to_api_error();
        (status, Json(body)).into_response()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn code_of(err: ServerError) -> (StatusCode, ErrorCode) {
        let (status, body) = err.to_api_error();
        (status, body.code)
    }

    #[test]
    fn domain_errors_map_to_expected_status_and_code() {
        assert_eq!(
            code_of(ServerError::NotFound),
            (StatusCode::NOT_FOUND, ErrorCode::NotFound)
        );
        assert_eq!(
            code_of(ServerError::Forbidden),
            (StatusCode::FORBIDDEN, ErrorCode::Forbidden)
        );
        assert_eq!(
            code_of(ServerError::InvalidCredentials),
            (StatusCode::UNAUTHORIZED, ErrorCode::InvalidCredentials)
        );
        assert_eq!(
            code_of(ServerError::Auth("nope".into())),
            (StatusCode::UNAUTHORIZED, ErrorCode::Unauthorized)
        );
        assert_eq!(
            code_of(ServerError::Validation("bad phone".into())),
            (StatusCode::BAD_REQUEST, ErrorCode::Validation)
        );
    }

    #[test]
    fn validation_message_reaches_the_client() {
        let (_, body) = ServerError::Validation("phone_number is invalid".into()).to_api_error();
        assert_eq!(body.message, "phone_number is invalid");
    }

    #[test]
    fn database_errors_are_opaque_to_the_client() {
        let err = ServerError::Database(sqlx::Error::RowNotFound);
        let (status, body) = err.to_api_error();

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.code, ErrorCode::Internal);
        assert_eq!(body.message, "Database error");
    }

    #[test]
    fn otp_errors_delegate_to_otp_mapping() {
        assert_eq!(
            code_of(ServerError::Otp(OtpError::Expired)),
            (StatusCode::GONE, ErrorCode::OtpExpired)
        );
        assert_eq!(
            code_of(ServerError::Otp(OtpError::WrongCode)),
            (StatusCode::UNAUTHORIZED, ErrorCode::OtpWrongCode)
        );
    }

    #[test]
    fn otp_database_errors_are_opaque_to_the_client() {
        let err = ServerError::Otp(OtpError::Database(sqlx::Error::RowNotFound));
        let (status, body) = err.to_api_error();

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(body.code, ErrorCode::Internal);
        assert_eq!(body.message, "Database error");
    }

    #[test]
    fn api_escape_hatch_preserves_status_code_and_message() {
        let err = ServerError::api(
            StatusCode::BAD_REQUEST,
            ErrorCode::BadRequest,
            "Something went wrong",
        );
        let (status, body) = err.to_api_error();

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body.code, ErrorCode::BadRequest);
        assert_eq!(body.message, "Something went wrong");
    }

    #[test]
    fn error_codes_serialize_as_screaming_snake_case() {
        let body = ApiError::new(ErrorCode::InvalidCredentials, "Invalid credentials");
        let json = serde_json::to_string(&body).unwrap();

        assert_eq!(
            json,
            r#"{"code":"INVALID_CREDENTIALS","message":"Invalid credentials"}"#
        );
    }

    #[test]
    fn display_matches_serialized_form_for_every_code() {
        for code in ErrorCode::ALL {
            let serialized = serde_json::to_string(code).unwrap();
            assert_eq!(
                serialized,
                format!(r#""{}""#, code),
                "Display and Serialize disagree for {:?}",
                code
            );
        }
    }

    /// Frontends key their translations off these strings, so a rename is a
    /// breaking change. Update this list only alongside the clients.
    #[test]
    fn error_code_strings_are_stable() {
        let actual: Vec<&str> = ErrorCode::ALL.iter().map(|c| c.as_str()).collect();

        assert_eq!(
            actual,
            vec![
                "INTERNAL",
                "BAD_REQUEST",
                "VALIDATION",
                "UNAUTHORIZED",
                "INVALID_CREDENTIALS",
                "FORBIDDEN",
                "NOT_FOUND",
                "CONFLICT",
                "OTP_EXPIRED",
                "OTP_WRONG_CODE",
                "OTP_ALREADY_VERIFIED",
                "OTP_NOT_FOUND",
                "OTP_MAX_ATTEMPTS",
                "OTP_MAX_MESSAGES",
                "SMS_FAILED",
            ]
        );
    }

    #[test]
    fn all_contains_every_code_exactly_once() {
        let mut seen = ErrorCode::ALL.to_vec();
        let before = seen.len();
        seen.dedup_by_key(|c| c.as_str());

        assert_eq!(before, seen.len(), "ErrorCode::ALL contains duplicates");
    }

    #[test]
    fn is_unique_violation_is_false_for_other_errors() {
        assert!(!ServerError::Database(sqlx::Error::RowNotFound).is_unique_violation());
        assert!(!ServerError::NotFound.is_unique_violation());
    }
}
