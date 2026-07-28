use chrono::{DateTime, Utc};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::models::auth::ProviderType;
use crate::models::user::validate_identifier;

#[derive(Debug, Serialize)]
pub struct OtpResponse {
    pub otp_id: Uuid,
}

fn validate_otp_request(req: &CreateOtpRequest) -> Result<(), ValidationError> {
    validate_identifier(req.provider_type, &req.identifier)
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_otp_request"))]
pub struct CreateOtpRequest {
    pub identifier: String,
    pub provider_type: ProviderType,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct VerifyOtpRequest {
    pub otp_id: Uuid,
    #[validate(custom(function = "validate_otp_code"))]
    pub code: String,
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
