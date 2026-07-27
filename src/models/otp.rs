use axum::http::StatusCode;
use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::error::{ApiError, ErrorCode};
use crate::models::auth::ProviderType;

#[derive(Debug, thiserror::Error)]
pub enum OtpError {
    #[error("SMS failed to send")]
    SmsFailed,

    #[error("OTP expired")]
    Expired,

    #[error("OTP already verified")]
    AlreadyVerified,

    #[error("Max attempts exceeded")]
    MaxAttemptsExceeded,

    #[error("Wrong code")]
    WrongCode,

    #[error("OTP not found")]
    NotFound,

    #[error("Max messages per day exceeded")]
    MaxMessagesExceeded,

    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
}

impl OtpError {
    pub fn to_api_error(&self) -> (StatusCode, ApiError) {
        let (status, code) = match self {
            Self::Expired => (StatusCode::GONE, ErrorCode::OtpExpired),
            Self::MaxAttemptsExceeded => (StatusCode::TOO_MANY_REQUESTS, ErrorCode::OtpMaxAttempts),
            Self::MaxMessagesExceeded => (StatusCode::TOO_MANY_REQUESTS, ErrorCode::OtpMaxMessages),
            Self::WrongCode => (StatusCode::UNAUTHORIZED, ErrorCode::OtpWrongCode),
            Self::AlreadyVerified => (StatusCode::CONFLICT, ErrorCode::OtpAlreadyVerified),
            Self::NotFound => (StatusCode::NOT_FOUND, ErrorCode::OtpNotFound),
            Self::SmsFailed => (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::SmsFailed),
            // Internal fault: keep the cause out of the response body
            Self::Database(_) => (StatusCode::INTERNAL_SERVER_ERROR, ErrorCode::Internal),
        };

        let message = match self {
            Self::Database(_) => "Database error".to_string(),
            other => other.to_string(),
        };

        (status, ApiError::new(code, message))
    }
}

#[derive(Debug, Serialize)]
pub struct OtpResponse {
    pub otp_id: Uuid,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct CreateOtpRequest {
    #[validate(custom(function = "validate_phone"))]
    pub phone_number: String,
    pub provider_type: ProviderType,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct VerifyOtpRequest {
    pub otp_id: Uuid,
    #[validate(custom(function = "validate_otp_code"))]
    pub code: String,
}

fn validate_phone(phone: &str) -> Result<(), ValidationError> {
    if !crate::PHONE_REGEX.is_match(phone) {
        return Err(ValidationError::new("invalid_phone"));
    }
    Ok(())
}

fn validate_otp_code(code: &str) -> Result<(), ValidationError> {
    if code.len() != 6 || !code.chars().all(|c| c.is_ascii_digit()) {
        return Err(ValidationError::new("invalid_otp_code"));
    }
    Ok(())
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Otp {
    pub id: Uuid,
    pub identifier: String,
    pub provider_type: ProviderType,
    pub hash: String,
    pub expires_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub failed_attempts: i32,
}

impl Otp {
    pub fn is_verified(&self) -> bool {
        self.verified_at.is_some()
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }

    pub fn is_max_attempts_exceeded(&self, max: i32) -> bool {
        self.failed_attempts >= max
    }

    pub fn generate_code() -> String {
        let code: u32 = rand::thread_rng().gen_range(0..1_000_000);
        format!("{:06}", code)
    }

    pub fn hash_code(code: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        hex::encode(hasher.finalize())
    }
}
