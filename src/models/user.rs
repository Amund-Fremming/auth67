use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use validator::{Validate, ValidationError};

use crate::models::auth::ProviderType;

pub fn normalize_phone(phone: &str) -> String {
    let digits: String = phone.chars().filter(|c| c.is_ascii_digit()).collect();
    
    // Strip leading 00 (international prefix)
    let stripped = digits.strip_prefix("00").unwrap_or(&digits);
    
    // Strip common country codes (47 for Norway, etc.)
    // If number is longer than 8 digits and starts with country code, strip it
    if stripped.len() > 8 {
        if let Some(local) = stripped.strip_prefix("47") {
            if local.len() >= 8 {
                return local.to_string();
            }
        }
    }
    
    stripped.to_string()
}

pub const MIN_PASSWORD_LENGTH: usize = 8;
pub const MAX_PASSWORD_LENGTH: usize = 128;

pub fn validate_password(password: &str) -> Result<(), ValidationError> {
    if password.len() < MIN_PASSWORD_LENGTH {
        return Err(ValidationError::new("password_too_short"));
    }
    if password.len() > MAX_PASSWORD_LENGTH {
        return Err(ValidationError::new("password_too_long"));
    }
    if !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(ValidationError::new("password_missing_uppercase"));
    }
    if !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(ValidationError::new("password_missing_digit"));
    }
    Ok(())
}

pub fn validate_identifier(
    provider_type: ProviderType,
    identifier: &str,
) -> Result<(), ValidationError> {
    match provider_type {
        ProviderType::Email => {
            if !crate::EMAIL_REGEX.is_match(identifier) {
                return Err(ValidationError::new("invalid_email"));
            }
        }
        ProviderType::Phone => {
            if !crate::PHONE_REGEX.is_match(identifier) {
                return Err(ValidationError::new("invalid_phone"));
            }
        }
    }
    Ok(())
}

fn validate_login(req: &LoginRequest) -> Result<(), ValidationError> {
    validate_identifier(req.provider_type, &req.identifier)?;
    validate_password(&req.password)
}

fn validate_signup(req: &SignupRequest) -> Result<(), ValidationError> {
    validate_identifier(req.provider_type, &req.identifier)?;
    validate_password(&req.password)
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_login"))]
pub struct LoginRequest {
    pub device_id: Uuid,
    pub device_name: String,
    pub provider_type: ProviderType,
    pub identifier: String,
    pub password: String,
}

impl LoginRequest {
    pub fn normalize(&mut self) {
        if self.provider_type == ProviderType::Phone {
            self.identifier = normalize_phone(&self.identifier);
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Validate)]
#[validate(schema(function = "validate_signup"))]
pub struct SignupRequest {
    pub provider_type: ProviderType,
    pub device_name: String,
    pub identifier: String,
    pub password: String,
    #[validate(regex(path = *crate::NAME_REGEX))]
    pub given_name: String,
    #[validate(regex(path = *crate::NAME_REGEX))]
    pub family_name: String,
}

#[derive(Debug, Serialize, Deserialize, sqlx::FromRow)]
pub struct User {
    pub id: Uuid,
    pub phone_number: Option<String>,
    pub phone_number_verified: bool,
    pub email: Option<String>,
    pub email_verified: bool,
    pub given_name: String,
    pub family_name: String,
    pub avatar_url: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub last_active_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize, Validate)]
pub struct PatchUserRequest {
    #[validate(regex(path = *crate::NAME_REGEX))]
    pub given_name: Option<String>,
    #[validate(regex(path = *crate::NAME_REGEX))]
    pub family_name: Option<String>,
    #[validate(url)]
    pub avatar_url: Option<String>,
}

impl User {
    pub fn new(given_name: &str, family_name: &str) -> Self {
        Self {
            id: Uuid::new_v4(),
            given_name: given_name.to_string(),
            family_name: family_name.to_string(),
            phone_number: None,
            phone_number_verified: false,
            email: None,
            email_verified: false,
            avatar_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_active_at: Utc::now(),
        }
    }
}

impl From<SignupRequest> for User {
    fn from(req: SignupRequest) -> Self {
        let (phone_number, email) = match req.provider_type {
            ProviderType::Phone => (Some(req.identifier), None),
            ProviderType::Email => (None, Some(req.identifier)),
        };

        Self {
            id: Uuid::new_v4(),
            phone_number,
            phone_number_verified: false,
            email,
            email_verified: false,
            given_name: req.given_name,
            family_name: req.family_name,
            avatar_url: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            last_active_at: Utc::now(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_phone_plain_number() {
        assert_eq!(normalize_phone("41387142"), "41387142");
    }

    #[test]
    fn normalize_phone_with_plus_country_code() {
        assert_eq!(normalize_phone("+4741387142"), "41387142");
    }

    #[test]
    fn normalize_phone_with_double_zero_prefix() {
        assert_eq!(normalize_phone("004741387142"), "41387142");
    }

    #[test]
    fn normalize_phone_country_code_no_prefix() {
        assert_eq!(normalize_phone("4741387142"), "41387142");
    }

    #[test]
    fn normalize_phone_with_spaces_and_dashes() {
        assert_eq!(normalize_phone("+47 413 87 142"), "41387142");
        assert_eq!(normalize_phone("413-87-142"), "41387142");
    }

    #[test]
    fn normalize_phone_short_number_unchanged() {
        assert_eq!(normalize_phone("12345678"), "12345678");
    }
}
