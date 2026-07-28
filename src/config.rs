use base64::{Engine, engine::general_purpose::STANDARD};
use config::{Config, ConfigError, Environment, File};
use once_cell::sync::Lazy;
use serde::{Deserialize, Deserializer, de};

fn deserialize_base64_to_pem<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let base64_str = String::deserialize(deserializer)?;
    let bytes = STANDARD
        .decode(&base64_str)
        .map_err(|e| de::Error::custom(format!("invalid base64: {}", e)))?;

    String::from_utf8(bytes).map_err(|e| de::Error::custom(format!("invalid UTF-8 in PEM: {}", e)))
}

#[derive(Debug, Deserialize, Clone)]
pub struct ServerConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct DatabaseConfig {
    pub url: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CommsConfig {
    pub username: String,
    pub password: String,
    pub from_phone: String,
    pub from_email: String,
    pub otp_message_template: String,
    pub otp_email_subject: String,
    pub resend_api_key: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthConfig {
    #[serde(
        deserialize_with = "deserialize_base64_to_pem",
        rename = "private_key_base64"
    )]
    private_key_pem: String,
    #[serde(
        deserialize_with = "deserialize_base64_to_pem",
        rename = "public_key_base64"
    )]
    public_key_pem: String,
    pub audience: String,
    pub issuer: String,
    pub access_token_lifetime_minutes: i64,
    pub refresh_token_lifetime_days: i64,
    pub max_failed_login_attempts: i32,
    #[serde(default = "default_account_lock_hours")]
    pub account_lock_hours: i64,
}

fn default_account_lock_hours() -> i64 {
    24
}

impl AuthConfig {
    pub fn private_key_pem(&self) -> &str {
        &self.private_key_pem
    }

    pub fn public_key_pem(&self) -> &str {
        &self.public_key_pem
    }

    #[cfg(test)]
    pub fn new_for_test(
        access_token_lifetime_minutes: i64,
        refresh_token_lifetime_days: i64,
        max_failed_login_attempts: i32,
        account_lock_hours: i64,
        audience: String,
        issuer: String,
    ) -> Self {
        Self {
            private_key_pem: String::new(),
            public_key_pem: String::new(),
            access_token_lifetime_minutes,
            refresh_token_lifetime_days,
            max_failed_login_attempts,
            account_lock_hours,
            audience,
            issuer,
        }
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct OtpConfig {
    pub ttl_minutes: u8,
    pub max_attempts: u8,
    pub max_messages_per_day: i64,
    pub cleanup_interval_minutes: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CryptoConfig {
    pub secret: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuditConfig {
    pub retention_days: i64,
    pub cleanup_interval_hours: u16,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AdminConfig {
    pub admins: Vec<uuid::Uuid>,
}

impl AdminConfig {
    pub fn is_admin(&self, user_id: &uuid::Uuid) -> bool {
        self.admins.contains(user_id)
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct AppConfig {
    pub server: ServerConfig,
    pub database: DatabaseConfig,
    pub comms: CommsConfig,
    pub auth: AuthConfig,
    pub otp: OtpConfig,
    pub crypto: CryptoConfig,
    pub audit: AuditConfig,
    pub admin: AdminConfig,
}

impl AppConfig {
    pub fn load() -> Result<Self, ConfigError> {
        let env = std::env::var("RUN_ENV").unwrap_or_else(|_| "development".into());

        let config = Config::builder()
            .add_source(File::with_name(&format!("config/{}", env)))
            .add_source(Environment::with_prefix("APP").separator("__"))
            .build()?;

        let app_config: Self = config.try_deserialize()?;

        if env == "production" {
            app_config.validate_production_secrets();
        }

        Ok(app_config)
    }

    fn validate_production_secrets(&self) {
        let mut errors = Vec::new();

        if self.crypto.secret.is_empty() {
            errors.push("crypto.secret is empty");
        }
        if self.crypto.secret == "dev-secret-change-in-production" {
            errors.push("crypto.secret is using development default");
        }
        if self.auth.private_key_pem().is_empty() {
            errors.push("auth.private_key_base64 is empty");
        }
        if self.auth.public_key_pem().is_empty() {
            errors.push("auth.public_key_base64 is empty");
        }
        if self.database.url.is_empty() {
            errors.push("database.url is empty");
        }

        if !errors.is_empty() {
            panic!(
                "FATAL: Production configuration validation failed:\n  - {}",
                errors.join("\n  - ")
            );
        }
    }
}

pub static CONFIG: Lazy<AppConfig> =
    Lazy::new(|| AppConfig::load().expect("Failed to load config"));
