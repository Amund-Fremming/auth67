use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;
use tracing::{error, warn};

use crate::ports::crypto::CryptoError;

/// Domain error codes for frontend translation.
/// Clients match on these to show localized messages.
/// Add freely, but rename/remove only as breaking change.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AppErrorCode {
    OtpExpired,
    OtpWrongCode,
    OtpAlreadyVerified,
    OtpNotFound,
    OtpMaxAttempts,
    OtpMaxMessages,
    SmsFailed,
    EmailFailed,
    InvalidCredentials,
    ValidationFailed,
    PasswordSameAsOld,
}

impl AppErrorCode {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::OtpExpired => "OTP_EXPIRED",
            Self::OtpWrongCode => "OTP_WRONG_CODE",
            Self::OtpAlreadyVerified => "OTP_ALREADY_VERIFIED",
            Self::OtpNotFound => "OTP_NOT_FOUND",
            Self::OtpMaxAttempts => "OTP_MAX_ATTEMPTS",
            Self::OtpMaxMessages => "OTP_MAX_MESSAGES",
            Self::SmsFailed => "SMS_FAILED",
            Self::EmailFailed => "EMAIL_FAILED",
            Self::InvalidCredentials => "INVALID_CREDENTIALS",
            Self::ValidationFailed => "VALIDATION_FAILED",
            Self::PasswordSameAsOld => "PASSWORD_SAME_AS_OLD",
        }
    }

    pub const fn status(&self) -> StatusCode {
        match self {
            Self::OtpExpired => StatusCode::GONE,
            Self::OtpWrongCode | Self::InvalidCredentials => StatusCode::UNAUTHORIZED,
            Self::OtpAlreadyVerified => StatusCode::CONFLICT,
            Self::OtpNotFound => StatusCode::NOT_FOUND,
            Self::OtpMaxAttempts | Self::OtpMaxMessages => StatusCode::TOO_MANY_REQUESTS,
            Self::SmsFailed | Self::EmailFailed => StatusCode::INTERNAL_SERVER_ERROR,
            Self::ValidationFailed | Self::PasswordSameAsOld => StatusCode::BAD_REQUEST,
        }
    }
}

impl std::fmt::Display for AppErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for AppErrorCode {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// JSON body for domain errors - frontend matches on `code`.
#[derive(Debug, Clone, Serialize)]
pub struct AppError {
    pub code: AppErrorCode,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("Internal server error")]
    Internal,

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    #[error("RSA error: {0}")]
    Rsa(#[from] rsa::pkcs8::spki::Error),

    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),

    /// Simple HTTP error - no body, just status code
    #[error("HTTP error: {0} - {1}")]
    Http(StatusCode, String),

    /// Domain error with code for frontend translation
    #[error("App error: {0} - {1}")]
    App(AppErrorCode, String),
}

impl ServerError {
    pub fn is_unique_violation(&self) -> bool {
        matches!(
            self,
            Self::Database(sqlx::Error::Database(db_err)) if db_err.is_unique_violation()
        )
    }
}

impl IntoResponse for ServerError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal => {
                error!("Internal server error");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
                    .into_response()
            }
            Self::Database(err) => {
                error!("Database error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
                    .into_response()
            }
            Self::Rsa(err) => {
                error!("RSA error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
                    .into_response()
            }
            Self::Crypto(err) => {
                error!("Crypto error: {}", err);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Internal server error".to_string(),
                )
                    .into_response()
            }
            Self::Http(status, message) => {
                error!("Http error: {} - {}", status, message);
                (status, message).into_response()
            }
            Self::App(code, message) => {
                warn!("App error: {} - {}", code, message);
                let status_code = code.status();
                let error = AppError { code, message };
                (status_code, Json(error)).into_response()
            }
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn http_error_returns_status_only() {
        let err = ServerError::Http(StatusCode::NOT_FOUND, "Not found".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn app_error_returns_json_body() {
        let err = ServerError::App(AppErrorCode::OtpWrongCode, "Wrong code".to_string());
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn error_codes_serialize_as_screaming_snake_case() {
        let body = AppError {
            code: AppErrorCode::InvalidCredentials,
            message: "Bad password".to_string(),
        };
        let json = serde_json::to_string(&body).unwrap();
        assert_eq!(
            json,
            r#"{"code":"INVALID_CREDENTIALS","message":"Bad password"}"#
        );
    }

    #[test]
    fn is_unique_violation_is_false_for_other_errors() {
        assert!(!ServerError::Database(sqlx::Error::RowNotFound).is_unique_violation());
        assert!(
            !ServerError::Http(StatusCode::NOT_FOUND, "Not found".to_string())
                .is_unique_violation()
        );
    }
}
