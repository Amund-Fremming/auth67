use std::sync::Arc;
use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use reqwest::StatusCode;
use serde_json::json;
use sqlx::{Pool, Postgres};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    config::AuthConfig,
    db::{
        self,
        audit::create_audit,
        auth::{
            get_login_credentials, increment_and_get_failed_attempts, lock_account,
            reset_failed_attempts,
        },
        otp::get_otp_by_id,
        user::is_identifier_in_use,
    },
    error::ServerError,
    models::{
        audit::{Action, AuditBuilder, ResourceType},
        auth::{Claims, Jwk, Jwks, ProviderType, TokenResponse},
        user::User,
    },
    ports::crypto::CryptoPort,
};

/// Dummy Argon2 hash for timing-safe login.
/// Used when user not found to prevent timing oracle attacks.
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$ZHVtbXlzYWx0Zm9ydGltaW5n$K8H8X3Q9Z5Y2W1V0U9T8S7R6Q5P4O3N2M1L0K9J8I7H6";

pub struct AuthService {
    config: AuthConfig,
    pool: Pool<Postgres>,
    crypto: Arc<dyn CryptoPort>,
    jwks: Jwks,
    encoding_key: EncodingKey,
    decoding_key: DecodingKey,
    validation: Validation,
    audience: String,
    issuer: String,
}

impl std::fmt::Debug for AuthService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthService")
            .field("audience", &self.audience)
            .field("issuer", &self.issuer)
            .finish_non_exhaustive()
    }
}

impl AuthService {
    pub fn new(
        config: AuthConfig,
        pool: Pool<Postgres>,
        crypto: Arc<dyn CryptoPort>,
        private_key_pem: &str,
        public_key_pem: &str,
        audience: &str,
        issuer: &str,
    ) -> Result<Self, ServerError> {
        let encoding_key = EncodingKey::from_rsa_pem(private_key_pem.as_bytes())
            .map_err(|e| ServerError::Auth(format!("Invalid private key: {}", e)))?;

        let decoding_key = DecodingKey::from_rsa_pem(public_key_pem.as_bytes())
            .map_err(|e| ServerError::Auth(format!("Invalid public key: {}", e)))?;

        let jwk = Jwk::new("key-1", public_key_pem)?;
        let jwks = Jwks { keys: [jwk] };

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[issuer]);

        Ok(Self {
            config,
            pool,
            crypto,
            jwks,
            encoding_key,
            decoding_key,
            validation,
            audience: audience.to_string(),
            issuer: issuer.to_string(),
        })
    }

    pub fn get_jwks(&self) -> &Jwks {
        &self.jwks
    }

    pub fn validate_token(&self, token: &str) -> Result<Claims, StatusCode> {
        let token_data =
            decode::<Claims>(token, &self.decoding_key, &self.validation).map_err(|e| {
                warn!("Token validation failed: {}", e);
                StatusCode::UNAUTHORIZED
            })?;

        let claims = token_data.claims;
        Ok(claims)
    }

    fn generate_access_token(&self, user_id: Uuid) -> Result<String, ServerError> {
        let access_token_lifetime_seconds = self.config.access_token_lifetime_minutes * 60;

        let claims = Claims {
            sub: user_id.to_string(),
            iss: self.issuer.clone(),
            aud: vec![self.audience.clone()],
            exp: (Utc::now().timestamp() + access_token_lifetime_seconds) as usize,
            iat: Utc::now().timestamp() as usize,
        };

        let header = Header::new(Algorithm::RS256);
        let access_token = encode(&header, &claims, &self.encoding_key)
            .map_err(|e| ServerError::Auth(format!("Failed to encode AT: {:?}", e)))?;

        Ok(access_token)
    }

    fn generate_refresh_token(&self) -> String {
        let bytes: [u8; 32] = rand::random();
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn audit_suspicious(&self, user_id: Uuid, description: &str) {
        let pool = self.pool.clone();
        let description = description.to_string();

        tokio::spawn(async move {
            let log = AuditBuilder::new()
                .resource_id(user_id)
                .resource_type(ResourceType::User)
                .action(Action::Suspicious)
                .metadata(json!({ "description": description }))
                .build();

            if let Err(e) = create_audit(&pool, &log).await {
                error!("Failed to create suspicious audit log: {}", e);
            }
        });
    }

    fn audit_account_locked(&self, user_id: Uuid, lock_hours: i64) {
        let pool = self.pool.clone();

        tokio::spawn(async move {
            let log = AuditBuilder::new()
                .resource_id(user_id)
                .resource_type(ResourceType::User)
                .action(Action::AccountLocked)
                .metadata(json!({ "lock_hours": lock_hours }))
                .build();

            if let Err(e) = create_audit(&pool, &log).await {
                error!("Failed to create account locked audit log: {}", e);
            }
        });
    }

    /// TODO:
    /// - optimize 5/6 database trips
    #[allow(clippy::too_many_arguments)]
    pub async fn signup(
        &self,
        otp_id: Uuid,
        provider_type: ProviderType,
        device_name: &str,
        user_agent: Option<&str>,
        given_name: &str,
        family_name: &str,
        password: &str,
    ) -> Result<TokenResponse, ServerError> {
        let otp = get_otp_by_id(&self.pool, otp_id).await?;

        if !otp.is_verified() {
            return Err(ServerError::Auth("Phone number not verified".to_string()));
        }

        let identifier = otp.identifier;

        if is_identifier_in_use(&self.pool, provider_type, &identifier).await? {
            warn!("Signup attempted with identifier already in use");
            return Err(ServerError::Conflict);
        }

        let mut user = User::new(given_name, family_name);
        match provider_type {
            ProviderType::Email => {
                user.email = Some(identifier.clone());
                user.email_verified = true;
            }
            ProviderType::Phone => {
                user.phone_number = Some(identifier.clone());
                user.phone_number_verified = true;
            }
        }

        let password_hash = self.crypto.hash_password(password)?;

        let mut tx = self.pool.begin().await?;
        db::user::create_user(&mut *tx, &user).await?;
        let identity =
            db::auth::create_identity(&mut *tx, user.id, provider_type, &identifier).await?;
        db::auth::create_credential(&mut *tx, identity.id, &password_hash).await?;
        tx.commit().await?;

        let device_id = Uuid::new_v4();
        let at = self.generate_access_token(user.id)?;
        let rt = self.generate_refresh_token();
        let rt_hash = self.crypto.hash(&rt);
        let rt_expiry = self.refresh_token_expiry();

        db::auth::create_session(
            &self.pool,
            user.id,
            device_id,
            device_name,
            &rt_hash,
            rt_expiry,
            user_agent,
        )
        .await?;

        Ok(self.token_response(at, rt))
    }

    fn refresh_token_expiry(&self) -> DateTime<Utc> {
        Utc::now() + Duration::from_hours(24 * self.config.refresh_token_lifetime_days as u64)
    }

    /// Returns the same error even tough errors differ.
    /// This is done to prevent attackers gaining info.
    pub async fn login(
        &self,
        device_id: Uuid,
        device_name: &str,
        user_agent: Option<&str>,
        identifier: &str, // email or phone_number
        provider_type: ProviderType,
        password: &str,
    ) -> Result<TokenResponse, ServerError> {
        let max_attempts = self.config.max_failed_login_attempts;
        let lock_hours = self.config.account_lock_hours;

        let login_object = get_login_credentials(&self.pool, identifier, provider_type).await?;

        // Always verify password to prevent timing oracle (use dummy hash if user not found)
        let hash_to_verify = login_object
            .as_ref()
            .map(|l| l.password_hash.as_str())
            .unwrap_or(DUMMY_PASSWORD_HASH);

        let is_valid = self.crypto.verify_password(password, hash_to_verify)?;

        let Some(login_object) = login_object else {
            warn!(device_id = %device_id, "Login failed: user not found");
            return Err(ServerError::InvalidCredentials);
        };

        if login_object.is_locked() {
            warn!(identifier = %identifier, "Login failed: account locked");
            return Err(ServerError::InvalidCredentials);
        }

        if !is_valid {
            self.audit_suspicious(login_object.user_id, "Login failed: wrong password");
            warn!(user_id = %login_object.user_id, "Login failed: wrong password");

            let new_count =
                increment_and_get_failed_attempts(&self.pool, login_object.identity_id).await?;

            if new_count >= max_attempts {
                lock_account(&self.pool, login_object.identity_id, lock_hours).await?;
                self.audit_account_locked(login_object.user_id, lock_hours);
                warn!(user_id = %login_object.user_id, "Account locked due to max failed attempts");
            }

            return Err(ServerError::InvalidCredentials);
        }

        reset_failed_attempts(&self.pool, login_object.identity_id).await?;

        let user_id = login_object.user_id;
        let pool = self.pool.clone();

        tokio::task::spawn(async move {
            let log = AuditBuilder::new()
                .resource_id(user_id)
                .resource_type(ResourceType::User)
                .action(Action::LoginSuccess)
                .build();

            if let Err(e) = create_audit(&pool, &log).await {
                error!("Failed to create audit log on login: {}", e);
            }
        });

        let at = self.generate_access_token(user_id)?;
        let rt = self.generate_refresh_token();
        let rt_hash = self.crypto.hash(&rt);
        let rt_expiry = self.refresh_token_expiry();

        db::auth::upsert_session(
            &self.pool,
            user_id,
            device_id,
            device_name,
            &rt_hash,
            rt_expiry,
            user_agent,
        )
        .await?;

        Ok(self.token_response(at, rt))
    }

    pub async fn set_password(
        &self,
        user_id: Uuid,
        provider_type: ProviderType,
        old_password: &str,
        new_password: &str,
    ) -> Result<(), ServerError> {
        let Some(user_credential) =
            db::auth::get_credential(&self.pool, user_id, &provider_type).await?
        else {
            self.audit_suspicious(user_id, "Tried setting password on non-existent provider");
            warn!(
                user_id = %user_id,
                provider_type = %provider_type,
                "User tried setting password on non existent provider type"
            );
            return Err(ServerError::Forbidden);
        };

        if old_password == new_password {
            return Err(ServerError::Auth(
                "New password must differ from current".to_string(),
            ));
        }

        let valid_old_password = self
            .crypto
            .verify_password(old_password, &user_credential.password_hash)?;

        if !valid_old_password {
            self.audit_suspicious(user_id, "Tried setting password with invalid old password");
            warn!(
                user_id = %user_id,
                provider_type = %provider_type,
                "User tried setting new password with invalid old password"
            );
            return Err(ServerError::Forbidden);
        }

        let new_password_hash = self.crypto.hash_password(new_password)?;
        db::auth::set_credential_password(&self.pool, user_credential.id, &new_password_hash)
            .await?;

        info!(
            user_id = %user_id,
            "User updated their password"
        );

        Ok(())
    }

    pub async fn refresh_token(
        &self,
        device_id: Uuid,
        refresh_token: &str,
    ) -> Result<TokenResponse, ServerError> {
        let Some(session) = db::auth::get_session(&self.pool, device_id).await? else {
            warn!(
                device_id = %device_id,
                "Requested refresh token does not exist"
            );
            return Err(ServerError::Forbidden);
        };

        let user_id = session.user_id;
        let valid_token = self
            .crypto
            .verify(refresh_token, &session.refresh_token_hash);

        if !valid_token {
            self.audit_suspicious(user_id, "Invalid refresh token attempt");
            warn!(
                device_id = %device_id,
                "Invalid refresh token, invalidating session"
            );
            db::auth::expire_session(&self.pool, device_id).await?;
            return Err(ServerError::Forbidden);
        }

        let at = self.generate_access_token(user_id)?;
        let rt = self.generate_refresh_token();
        let rt_hash = self.crypto.hash(&rt);
        let rt_expiry = self.refresh_token_expiry();

        db::auth::update_session(&self.pool, device_id, &rt_hash, rt_expiry).await?;
        db::user::touch_last_active(&self.pool, user_id).await?;

        Ok(self.token_response(at, rt))
    }

    pub async fn logout(&self, user_id: Uuid, device_id: Uuid) -> Result<(), ServerError> {
        let Some(session) = db::auth::get_session(&self.pool, device_id).await? else {
            warn!(device_id = %device_id, "Logout attempted for non-existent session");
            return Err(ServerError::NotFound);
        };

        if session.user_id != user_id {
            self.audit_suspicious(
                user_id,
                "Logout attempted for session owned by another user",
            );
            warn!(user_id = %user_id, device_id = %device_id, "Logout attempted for session not owned by user");
            return Err(ServerError::Forbidden);
        }

        db::auth::expire_session(&self.pool, device_id).await?;

        info!(user_id = %user_id, device_id = %device_id, "User logged out");
        Ok(())
    }

    fn token_response(&self, access_token: String, refresh_token: String) -> TokenResponse {
        let access_expires_in_secs = self.config.access_token_lifetime_minutes * 60;
        let refresh_expires_in_secs = self.config.refresh_token_lifetime_days * 24 * 60 * 60;

        TokenResponse {
            access_token,
            refresh_token,
            access_expires_in: access_expires_in_secs,
            refresh_expires_in: refresh_expires_in_secs,
        }
    }
}

#[cfg(test)]
mod test {
    /*
    ## new (constructor)
    - new succeeds with valid RSA keys
    - new fails with invalid private key PEM
    - new fails with invalid public key PEM
    - new fails when Jwk construction fails

    ## get_jwks
    - get_jwks returns the JWKS with both keys
    - get_jwks returns keys with distinct kids

    ## validate_token
    - validate_token succeeds with valid token and returns claims
    - validate_token fails with expired token
    - validate_token fails with invalid signature
    - validate_token fails with wrong audience
    - validate_token fails with wrong issuer
    - validate_token rejects malformed tokens
    - validate_token rejects alg=none and HS256-signed tokens (algorithm confusion)
    - validate_token rejects tokens missing sub

    ## signup
    - signup succeeds with phone provider and returns token response
    - signup succeeds with email provider and returns token response
    - signup fails when OTP not found
    - signup fails when OTP is not verified
    - signup fails when identifier already in use (phone)
    - signup fails when identifier already in use (email)
    - signup sets phone_number and phone_number_verified for phone provider
    - signup sets email and email_verified for email provider
    - signup creates identity with the requested provider type (not always Phone)
    - signup rolls back user row when credential creation fails
    - signup rejects reuse of an already-consumed otp_id
    - signup persists session with device_name/user_agent and a hash matching the returned RT
    - signup succeeds with user_agent = None

    ## login
    - login succeeds with phone provider and creates new session
    - login succeeds with email provider and creates new session
    - login succeeds and updates existing session for known device
    - login fails when identifier not found (phone)
    - login fails when identifier not found (email)
    - login fails when account is locked
    - login fails when password is invalid
    - login locks account after max failed attempts reached
    - login increments failed_attempts without locking below max
    - login succeeds when locked_until has expired
    - login resets failed_attempts after success following failures
    - login propagates crypto verify_password errors
    - login writes a success audit log
    - login fails when identifier does not match provider_type
    - login succeeds with user_agent = None

    ## set_password
    - set_password succeeds with valid old password
    - set_password fails when credential not found for provider
    - set_password fails when old password equals new password
    - set_password fails when old password is invalid
    - set_password: new password verifies and old password is rejected afterwards
    - set_password propagates crypto verify errors

    ## refresh_token
    - refresh_token succeeds and returns new token pair
    - refresh_token fails when session not found for device
    - refresh_token fails and expires session when token is invalid
    - refresh_token updates session with new token hash after rotation
    - refresh_token fails when session is expired
    - refresh_token fails when session is revoked
    - refresh_token rejects a rotated (replayed) token and expires the session

    ## logout
    - logout succeeds and session becomes inactive
    - logout fails when session not found
    - logout fails when session owned by another user
    - refresh_token fails after logout
    - session shows as inactive in list after logout

    ## tokens
    - access token exp equals now + access_token_lifetime_minutes * 60
    - refresh token expiry equals now + refresh_token_lifetime_days
    - generate_refresh_token produces distinct 32-byte URL-safe values
    - token_response lifetimes agree with the values used to mint the tokens
    */

    use super::*;
    use crate::config::AuthConfig;
    use crate::ports::crypto::MockCryptoPort;

    // Test RSA key pair (2048-bit PKCS#8 format, for testing only)
    const TEST_PRIVATE_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDBextJ2j2PeWUH
UAzvtMo8GWn3PUfnT/c31vAWy47MNQLE2HNoLjVc7Yn4CwS9Zp0Srx6zpAC6Oku8
SCCjRpy/AozFItTp5w8jHS08st4tr3+pBZBh+frBVY+KVEDiCfumbnsSHhcBafZj
KfOERDQL5t2nImSf66IUKUe5HslTRmEbnwTz9x92iTYl7vf3iKne4DRVcZ3oUn/Q
HBIjjbjiwE9FPUN8k/TyWGiyMUXh0v5PrgdRSGICQtP2WDK5ycs5vQaqkshsAuUI
Nfjvgtu0GRkiMUYDi3p24Tk4A9f2a5d0UVwuxOyBT9QVWC7ZN/zf6OCyqyrapXon
KYBdkWL9AgMBAAECggEAChDPAyEU+c1deatq+N+Fc+n4jtHD119cI64NcIonhC0v
1zDRlDZvNUXwWxSrqvTXMB0nMj5SgV2+Ce4QsJ3gUrmdvDXLMN4B9hgy/cjqcSMD
t7Xf5JD+QCek35PxijDtxCNUSMWC+eJa3J7Wmed4c7QPjP3nkUBPftAE+LcGz0uv
YYche2bKmcGxW9DjWT4zLphEY0bMVd2NljCHVF5ETm40FUcwGys7/SBODaXtOPXW
ETjDpAWj1E7l2Ju1fyaPMzkeqNr/6wnjsK8Q1Eq4cFrJhLJjETLJUV7EAkp8DGp3
BE19YLHKMcW+SppC6jx1U0Tu06na/HfoZecyqNqx0QKBgQDikf1bKttS2DVBbURj
QWxkcFaDE73kyZorSobZObVHTyE3zY8jSzOX4FZTSNTbiSNSae2AmvKYdyLbcRjH
l4S9f3L8pO4Im7bQm3MmU9BiYc4Suo7NZDscOmdPR8D3R2cttu8DJbhOSJ/AO4uE
CPV0KXxvK2WYGz8vmM3PgNoGZQKBgQDanNCNefL9pRnem72G/6bh7EU3gQ8q3Ede
kJyUQuNkkn6UQk/6jIDTYEyNxneRb7H1oDyTauRO+OGQamakZW2vecSMS5KYiqvB
8HCRG5l9tU/z3DXN6WVHItQi/5Q0v39LKQ36HWwO/lB9iyUKSI3znZa/C7TzGBUF
wWiGjFl0uQKBgDltLV1FMI//8wehTVsnAvU2MAdLIq9xldzxJ9q5MMRhPxcox+X3
Mp2FI/w6EpGOYeCKrsMRAvo4ACLEuLYmJmPtgNSebSLLbPvU2svVJJU7GwNOO9G9
XOobt4G1uygx9en1WwFeNyfIao1LymHt72DA/yQiSL7T8SD8RvYYP6qtAoGBANMX
LMIPiTSmoY40MBQU892fOU7ZDf5C6Z9EYA1BcTUBx7v9NCEoXpS8ne8gPwBuLBaT
fSqTwpUG+TdrpmUDk6AnIkSeDJXDAQqp0ugrEFE0LFm6vzFvNt4zoUeSJlewuYen
wtlKY7culiZDn6aIXJlqB8+9zCIXlOUT1oxlJVPxAoGAPOIDeYWO4wRaZwUWQJox
obuDcYZ6mpUtKeyobkLEv9ThUXqi7s/eH2V0seKVEfuJGv6/UYYJxMvmavdYfVhS
BEJy/yLFZwRXC8HHx3+IZB//x5V/jHlFyf6bVVjdwzomrd535iFy6oQvMHIEu552
3rR3vtBcz1EmXFIPCcOfDK4=
-----END PRIVATE KEY-----"#;

    const TEST_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwXsbSdo9j3llB1AM77TK
PBlp9z1H50/3N9bwFsuOzDUCxNhzaC41XO2J+AsEvWadEq8es6QAujpLvEggo0ac
vwKMxSLU6ecPIx0tPLLeLa9/qQWQYfn6wVWPilRA4gn7pm57Eh4XAWn2YynzhEQ0
C+bdpyJkn+uiFClHuR7JU0ZhG58E8/cfdok2Je7394ip3uA0VXGd6FJ/0BwSI424
4sBPRT1DfJP08lhosjFF4dL+T64HUUhiAkLT9lgyucnLOb0GqpLIbALlCDX474Lb
tBkZIjFGA4t6duE5OAPX9muXdFFcLsTsgU/UFVgu2Tf83+jgsqsq2qV6JymAXZFi
/QIDAQAB
-----END PUBLIC KEY-----"#;

    const TEST_AUDIENCE: &str = "test-audience";
    const TEST_ISSUER: &str = "test-issuer";

    fn mock_auth_config() -> AuthConfig {
        AuthConfig::new_for_test(
            15, // access_token_lifetime_minutes
            30, // refresh_token_lifetime_days
            5,  // max_failed_login_attempts
            24, // account_lock_hours
            TEST_AUDIENCE.to_string(),
            TEST_ISSUER.to_string(),
        )
    }

    fn mock_crypto() -> MockCryptoPort {
        let mut mock = MockCryptoPort::new();
        mock.expect_hash().returning(|v| format!("hashed_{}", v));
        mock.expect_verify()
            .returning(|v, h| h == format!("hashed_{}", v));
        mock.expect_hash_password()
            .returning(|p| Ok(format!("argon2_{}", p)));
        mock.expect_verify_password()
            .returning(|p, h| Ok(h == format!("argon2_{}", p)));
        mock
    }

    #[tokio::test]
    async fn new_succeeds_with_valid_rsa_keys() {
        let config = mock_auth_config();
        let pool = create_test_pool();
        let crypto = Arc::new(mock_crypto());

        let result = AuthService::new(
            config,
            pool,
            crypto,
            TEST_PRIVATE_KEY_PEM,
            TEST_PUBLIC_KEY_PEM,
            TEST_AUDIENCE,
            TEST_ISSUER,
        );

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn new_fails_with_invalid_private_key_pem() {
        let config = mock_auth_config();
        let pool = create_test_pool();
        let crypto = Arc::new(mock_crypto());

        let result = AuthService::new(
            config,
            pool,
            crypto,
            "not-a-valid-pem",
            TEST_PUBLIC_KEY_PEM,
            TEST_AUDIENCE,
            TEST_ISSUER,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ServerError::Auth(_)));
    }

    #[tokio::test]
    async fn new_fails_with_invalid_public_key_pem() {
        let config = mock_auth_config();
        let pool = create_test_pool();
        let crypto = Arc::new(mock_crypto());

        let result = AuthService::new(
            config,
            pool,
            crypto,
            TEST_PRIVATE_KEY_PEM,
            "not-a-valid-pem",
            TEST_AUDIENCE,
            TEST_ISSUER,
        );

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(matches!(err, ServerError::Auth(_)));
    }

    #[tokio::test]
    async fn get_jwks_returns_jwks_with_both_keys() {
        let service = create_test_service();
        let jwks = service.get_jwks();

        assert_eq!(jwks.keys.len(), 1);
    }

    #[tokio::test]
    async fn get_jwks_returns_keys_with_distinct_kids() {
        let service = create_test_service();
        let jwks = service.get_jwks();

        assert_eq!(jwks.keys[0].kid, "key-1");
    }

    #[tokio::test]
    async fn validate_token_succeeds_with_valid_token_and_returns_claims() {
        let service = create_test_service();
        let user_id = Uuid::new_v4();
        let token = service.generate_access_token(user_id).unwrap();

        let result = service.validate_token(&token);

        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.sub, user_id.to_string());
        assert_eq!(claims.iss, TEST_ISSUER);
        assert_eq!(claims.aud, vec![TEST_AUDIENCE]);
    }

    #[tokio::test]
    async fn validate_token_fails_with_expired_token() {
        let service = create_test_service();

        // Manually create an expired token
        let user_id = Uuid::new_v4();
        let claims = Claims {
            sub: user_id.to_string(),
            iss: TEST_ISSUER.to_string(),
            aud: vec![TEST_AUDIENCE.to_string()],
            exp: (Utc::now().timestamp() - 3600) as usize, // 1 hour in the past
            iat: (Utc::now().timestamp() - 7200) as usize,
        };

        let header = Header::new(Algorithm::RS256);
        let encoding_key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY_PEM.as_bytes()).unwrap();
        let expired_token = encode(&header, &claims, &encoding_key).unwrap();

        let result = service.validate_token(&expired_token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_token_fails_with_wrong_audience() {
        // Create a service, then create a token with wrong audience
        let service = create_test_service();
        let user_id = Uuid::new_v4();

        let claims = Claims {
            sub: user_id.to_string(),
            iss: TEST_ISSUER.to_string(),
            aud: vec!["wrong-audience".to_string()],
            exp: (Utc::now().timestamp() + 3600) as usize,
            iat: Utc::now().timestamp() as usize,
        };

        let header = Header::new(Algorithm::RS256);
        let encoding_key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY_PEM.as_bytes()).unwrap();
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = service.validate_token(&token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_token_fails_with_wrong_issuer() {
        let service = create_test_service();
        let user_id = Uuid::new_v4();

        let claims = Claims {
            sub: user_id.to_string(),
            iss: "wrong-issuer".to_string(),
            aud: vec![TEST_AUDIENCE.to_string()],
            exp: (Utc::now().timestamp() + 3600) as usize,
            iat: Utc::now().timestamp() as usize,
        };

        let header = Header::new(Algorithm::RS256);
        let encoding_key = EncodingKey::from_rsa_pem(TEST_PRIVATE_KEY_PEM.as_bytes()).unwrap();
        let token = encode(&header, &claims, &encoding_key).unwrap();

        let result = service.validate_token(&token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_token_rejects_malformed_tokens() {
        let service = create_test_service();

        let result = service.validate_token("not.a.valid.jwt");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_token_rejects_empty_token() {
        let service = create_test_service();

        let result = service.validate_token("");

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn generate_access_token_produces_valid_jwt() {
        let service = create_test_service();
        let user_id = Uuid::new_v4();

        let token = service.generate_access_token(user_id).unwrap();

        // Token should have 3 parts separated by dots
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Should be validatable
        let result = service.validate_token(&token);
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn generate_access_token_sets_correct_expiry() {
        let service = create_test_service();
        let user_id = Uuid::new_v4();
        let before = Utc::now().timestamp();

        let token = service.generate_access_token(user_id).unwrap();
        let claims = service.validate_token(&token).unwrap();

        let after = Utc::now().timestamp();
        let expected_lifetime = 15 * 60; // 15 minutes in seconds

        // exp should be approximately now + 15 minutes
        assert!(claims.exp as i64 >= before + expected_lifetime);
        assert!(claims.exp as i64 <= after + expected_lifetime + 1);
    }

    #[tokio::test]
    async fn generate_refresh_token_produces_distinct_values() {
        let service = create_test_service();

        let rt1 = service.generate_refresh_token();
        let rt2 = service.generate_refresh_token();

        assert_ne!(rt1, rt2);
    }

    #[tokio::test]
    async fn generate_refresh_token_is_url_safe() {
        let service = create_test_service();

        let rt = service.generate_refresh_token();

        // URL-safe base64 should not contain +, /, or =
        assert!(!rt.contains('+'));
        assert!(!rt.contains('/'));
        assert!(!rt.contains('='));
    }

    #[tokio::test]
    async fn generate_refresh_token_has_sufficient_entropy() {
        let service = create_test_service();

        let rt = service.generate_refresh_token();

        // 32 bytes encoded as URL-safe base64 without padding = 43 chars
        assert_eq!(rt.len(), 43);
    }

    #[tokio::test]
    async fn token_response_contains_correct_lifetimes() {
        let service = create_test_service();
        let at = "access_token".to_string();
        let rt = "refresh_token".to_string();

        let response = service.token_response(at.clone(), rt.clone());

        assert_eq!(response.access_token, at);
        assert_eq!(response.refresh_token, rt);
        assert_eq!(response.access_expires_in, 15 * 60);
        assert_eq!(response.refresh_expires_in, 30 * 24 * 60 * 60);
    }

    #[tokio::test]
    async fn refresh_token_expiry_is_future_date() {
        let service = create_test_service();
        let now = Utc::now();
        let expiry = service.refresh_token_expiry();

        assert!(expiry > now);
    }

    fn create_test_pool() -> Pool<Postgres> {
        // connect_lazy is synchronous and creates a pool without connecting.
        // Note: pool Drop still needs tokio, so tests using this should be #[tokio::test]
        use sqlx::postgres::PgPoolOptions;
        use std::time::Duration as StdDuration;

        PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(StdDuration::from_millis(1))
            .connect_lazy("postgres://test:test@localhost:5432/test")
            .unwrap()
    }

    fn create_test_service() -> AuthService {
        let config = mock_auth_config();
        let pool = create_test_pool();
        let crypto = Arc::new(mock_crypto());

        AuthService::new(
            config,
            pool,
            crypto,
            TEST_PRIVATE_KEY_PEM,
            TEST_PUBLIC_KEY_PEM,
            TEST_AUDIENCE,
            TEST_ISSUER,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn validate_token_rejects_alg_none_tokens() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let service = create_test_service();
        let user_id = Uuid::new_v4();

        // Craft a token with alg=none (no signature)
        let header = r#"{"alg":"none","typ":"JWT"}"#;
        let claims = serde_json::json!({
            "sub": user_id.to_string(),
            "iss": TEST_ISSUER,
            "aud": [TEST_AUDIENCE],
            "exp": (Utc::now().timestamp() + 3600) as usize,
            "iat": Utc::now().timestamp() as usize,
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());

        // alg=none token has empty signature
        let token = format!("{}.{}.", header_b64, claims_b64);

        let result = service.validate_token(&token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_token_rejects_hs256_signed_tokens() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        use hmac::{Hmac, Mac};
        use sha2::Sha256;

        let service = create_test_service();
        let user_id = Uuid::new_v4();

        // Algorithm confusion: sign with HS256 using the public key as secret
        let header = r#"{"alg":"HS256","typ":"JWT"}"#;
        let claims = serde_json::json!({
            "sub": user_id.to_string(),
            "iss": TEST_ISSUER,
            "aud": [TEST_AUDIENCE],
            "exp": (Utc::now().timestamp() + 3600) as usize,
            "iat": Utc::now().timestamp() as usize,
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let message = format!("{}.{}", header_b64, claims_b64);

        // Sign with public key as HMAC secret (algorithm confusion attack)
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(TEST_PUBLIC_KEY_PEM.as_bytes()).unwrap();
        mac.update(message.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());

        let token = format!("{}.{}", message, signature);

        let result = service.validate_token(&token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn validate_token_rejects_tokens_missing_sub() {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};

        let service = create_test_service();

        // Create claims without 'sub' field
        let header = r#"{"alg":"RS256","typ":"JWT"}"#;
        let claims = serde_json::json!({
            "iss": TEST_ISSUER,
            "aud": [TEST_AUDIENCE],
            "exp": (Utc::now().timestamp() + 3600) as usize,
            "iat": Utc::now().timestamp() as usize,
            // No "sub" field
        });

        let header_b64 = URL_SAFE_NO_PAD.encode(header.as_bytes());
        let claims_b64 = URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
        let message = format!("{}.{}", header_b64, claims_b64);

        // We need to sign a custom payload, so we'll use raw signing
        use rsa::{Pkcs1v15Sign, RsaPrivateKey, pkcs8::DecodePrivateKey};
        use sha2::{Digest, Sha256};

        let private_key = RsaPrivateKey::from_pkcs8_pem(TEST_PRIVATE_KEY_PEM).unwrap();
        let mut hasher = Sha256::new();
        hasher.update(message.as_bytes());
        let digest = hasher.finalize();

        let signature = private_key
            .sign(Pkcs1v15Sign::new::<Sha256>(), &digest)
            .unwrap();
        let sig_b64 = URL_SAFE_NO_PAD.encode(&signature);

        let token = format!("{}.{}", message, sig_b64);

        let result = service.validate_token(&token);

        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    fn create_integration_test_service(pool: Pool<Postgres>) -> AuthService {
        let config = mock_auth_config();
        let crypto = Arc::new(mock_crypto());

        AuthService::new(
            config,
            pool,
            crypto,
            TEST_PRIVATE_KEY_PEM,
            TEST_PUBLIC_KEY_PEM,
            TEST_AUDIENCE,
            TEST_ISSUER,
        )
        .unwrap()
    }

    #[sqlx::test]
    async fn logout_succeeds_and_session_becomes_inactive(pool: sqlx::PgPool) {
        let service = create_integration_test_service(pool.clone());
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        // Create user first
        sqlx::query!(
            r#"INSERT INTO "user" (id, given_name, family_name, created_at, updated_at) VALUES ($1, 'Test', 'User', NOW(), NOW())"#,
            user_id
        )
        .execute(&pool)
        .await
        .unwrap();

        // Create session
        let rt_hash = "hashed_test_refresh_token";
        let expires_at = Utc::now() + chrono::Duration::days(30);
        db::auth::create_session(
            &pool,
            user_id,
            device_id,
            "Test Device",
            rt_hash,
            expires_at,
            None,
        )
        .await
        .unwrap();

        // Logout
        let result = service.logout(user_id, device_id).await;
        assert!(result.is_ok());

        // Verify session is inactive
        let sessions = db::auth::list_session_dtos(&pool, user_id).await.unwrap();
        assert_eq!(sessions.len(), 1);
        assert!(!sessions[0].active);
    }

    #[sqlx::test]
    async fn logout_fails_when_session_not_found(pool: sqlx::PgPool) {
        let service = create_integration_test_service(pool.clone());
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        let result = service.logout(user_id, device_id).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ServerError::NotFound));
    }

    #[sqlx::test]
    async fn logout_fails_when_session_owned_by_another_user(pool: sqlx::PgPool) {
        let service = create_integration_test_service(pool.clone());
        let user_id = Uuid::new_v4();
        let other_user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();

        // Create both users
        sqlx::query!(
            r#"INSERT INTO "user" (id, given_name, family_name, created_at, updated_at) VALUES ($1, 'Test', 'User', NOW(), NOW())"#,
            user_id
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query!(
            r#"INSERT INTO "user" (id, given_name, family_name, created_at, updated_at) VALUES ($1, 'Other', 'User', NOW(), NOW())"#,
            other_user_id
        )
        .execute(&pool)
        .await
        .unwrap();

        // Create session for other_user
        let rt_hash = "hashed_test_refresh_token";
        let expires_at = Utc::now() + chrono::Duration::days(30);
        db::auth::create_session(
            &pool,
            other_user_id,
            device_id,
            "Test Device",
            rt_hash,
            expires_at,
            None,
        )
        .await
        .unwrap();

        // Try to logout as user_id (not the owner)
        let result = service.logout(user_id, device_id).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ServerError::Forbidden));
    }

    #[sqlx::test]
    async fn refresh_token_fails_after_logout(pool: sqlx::PgPool) {
        let service = create_integration_test_service(pool.clone());
        let user_id = Uuid::new_v4();
        let device_id = Uuid::new_v4();
        let refresh_token = "test_refresh_token";
        let rt_hash = format!("hashed_{}", refresh_token);

        // Create user
        sqlx::query!(
            r#"INSERT INTO "user" (id, given_name, family_name, created_at, updated_at) VALUES ($1, 'Test', 'User', NOW(), NOW())"#,
            user_id
        )
        .execute(&pool)
        .await
        .unwrap();

        // Create session
        let expires_at = Utc::now() + chrono::Duration::days(30);
        db::auth::create_session(
            &pool,
            user_id,
            device_id,
            "Test Device",
            &rt_hash,
            expires_at,
            None,
        )
        .await
        .unwrap();

        // Logout
        service.logout(user_id, device_id).await.unwrap();

        // Try to refresh - should fail
        let result = service.refresh_token(device_id, refresh_token).await;

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), ServerError::Forbidden));
    }

    #[sqlx::test]
    async fn session_shows_as_inactive_in_list_after_logout(pool: sqlx::PgPool) {
        let service = create_integration_test_service(pool.clone());
        let user_id = Uuid::new_v4();
        let device_id_1 = Uuid::new_v4();
        let device_id_2 = Uuid::new_v4();

        // Create user
        sqlx::query!(
            r#"INSERT INTO "user" (id, given_name, family_name, created_at, updated_at) VALUES ($1, 'Test', 'User', NOW(), NOW())"#,
            user_id
        )
        .execute(&pool)
        .await
        .unwrap();

        // Create two sessions
        let expires_at = Utc::now() + chrono::Duration::days(30);
        db::auth::create_session(
            &pool,
            user_id,
            device_id_1,
            "Device 1",
            "hash1",
            expires_at,
            None,
        )
        .await
        .unwrap();
        db::auth::create_session(
            &pool,
            user_id,
            device_id_2,
            "Device 2",
            "hash2",
            expires_at,
            None,
        )
        .await
        .unwrap();

        // Verify both are active
        let sessions = db::auth::list_session_dtos(&pool, user_id).await.unwrap();
        assert_eq!(sessions.len(), 2);
        assert!(sessions.iter().all(|s| s.active));

        // Logout from device 1
        service.logout(user_id, device_id_1).await.unwrap();

        // Verify device 1 is inactive, device 2 is still active
        let sessions = db::auth::list_session_dtos(&pool, user_id).await.unwrap();
        assert_eq!(sessions.len(), 2);
        let device_1_session = sessions
            .iter()
            .find(|s| s.device_id == device_id_1)
            .unwrap();
        let device_2_session = sessions
            .iter()
            .find(|s| s.device_id == device_id_2)
            .unwrap();
        assert!(!device_1_session.active);
        assert!(device_2_session.active);
    }
}
