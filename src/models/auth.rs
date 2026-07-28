use std::fmt;

use axum::http::StatusCode;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ServerError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_in: i64,
    pub refresh_expires_in: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Claims {
    pub iss: String,
    pub sub: String,
    pub aud: Vec<String>,
    pub exp: usize,
    pub iat: usize,
}

impl Claims {
    pub fn user_id(&self) -> Result<Uuid, ServerError> {
        self.sub.parse::<Uuid>().map_err(|_| {
            ServerError::Http(
                StatusCode::FORBIDDEN,
                "Invalid user id in claims".to_string(),
            )
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    #[serde(rename = "use")]
    pub _use: String,
    pub alg: String,
    pub n: String,
    pub e: String,
}

impl Jwk {
    pub fn new(kid: &str, public_key_pem: &str) -> Result<Self, rsa::pkcs8::spki::Error> {
        let public_key = RsaPublicKey::from_public_key_pem(public_key_pem)?;
        Ok(Self {
            kty: "RSA".to_string(),
            _use: "sig".to_string(),
            alg: "RS256".to_string(),
            kid: kid.to_string(),
            n: URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be()),
            e: URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be()),
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Jwks {
    pub keys: [Jwk; 1],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordHistory {
    pub user_id: Uuid,
    pub pwd_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserIdentity {
    pub id: Uuid,
    pub user_id: Uuid,
    pub identifier: String,
    pub provider_type: ProviderType,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize, sqlx::Type)]
#[sqlx(type_name = "provider_type", rename_all = "lowercase")]
#[serde(rename_all = "snake_case")]
pub enum ProviderType {
    Phone,
    Email,
}

impl ProviderType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Phone => "phone",
            Self::Email => "email",
        }
    }
}

impl fmt::Display for ProviderType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[derive(Debug, Clone)]
pub struct LoginCredentials {
    pub user_id: Uuid,
    pub identity_id: Uuid,
    pub password_hash: String,
    pub locked_until: Option<DateTime<Utc>>,
    pub failed_attempts: i32,
}

impl LoginCredentials {
    pub fn is_locked(&self) -> bool {
        self.locked_until
            .map(|until| Utc::now() < until)
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct UserCredential {
    pub id: Uuid,
    pub identity_id: Uuid,
    pub password_hash: String,
    pub failed_attempts: i32,
    pub locked_until: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
pub struct Session {
    pub device_id: Uuid,
    pub user_id: Uuid,
    pub refresh_token_hash: String,
    pub user_agent: Option<String>,
    pub device_name: String,
    pub expires_at: DateTime<Utc>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct SessionDto {
    pub device_id: Uuid,
    pub device_name: String,
    pub user_agent: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RefreshTokenRequest {
    pub device_id: Uuid,
    pub refresh_token: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LogoutRequest {
    pub device_id: Uuid,
}
