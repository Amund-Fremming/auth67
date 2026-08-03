use std::sync::Arc;

use sqlx::{Pool, Postgres};
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::{
    config::{CommsConfig, OtpConfig},
    db,
    error::{AppErrorCode, ServerError},
    models::{
        auth::ProviderType,
        otp::{Otp, OtpResponse},
    },
    ports::{comms::CommsPort, crypto::CryptoPort},
};

pub struct OtpService {
    config: OtpConfig,
    comms_config: CommsConfig,
    pool: Pool<Postgres>,
    comms: Arc<dyn CommsPort>,
    crypto: Arc<dyn CryptoPort>,
}

impl OtpService {
    pub fn new(
        config: OtpConfig,
        comms_config: CommsConfig,
        pool: Pool<Postgres>,
        comms: Arc<dyn CommsPort>,
        crypto: Arc<dyn CryptoPort>,
    ) -> Self {
        Self {
            config,
            comms_config,
            pool,
            comms,
            crypto,
        }
    }

    pub async fn create_and_send(
        &self,
        identifier: &str,
        provider_type: ProviderType,
    ) -> Result<OtpResponse, ServerError> {
        let code = Otp::generate_code();
        let hash = self.crypto.hash(&code);

        let response = db::otp::create_otp(
            &self.pool,
            identifier,
            provider_type,
            &hash,
            self.config.ttl_minutes,
            self.config.max_messages_per_day,
        )
        .await?;

        let message = self
            .comms_config
            .otp_message_template
            .replace("{code}", &code);

        let result = match provider_type {
            ProviderType::Phone => self
                .comms
                .send_sms(&self.comms_config.from_phone, identifier, &message)
                .await
                .map(|_| ()),
            ProviderType::Email => self
                .comms
                .send_email(
                    &self.comms_config.from_email,
                    &[identifier],
                    &self.comms_config.otp_email_subject,
                    Some(&message),
                    None,
                )
                .await
                .map(|_| ()),
        };

        if let Err(e) = result {
            error!(
                otp_id = %response.otp_id,
                error = %e,
                "Failed to send OTP, deleting entry"
            );
            db::otp::delete_otp(&self.pool, response.otp_id).await?;

            let (code, msg) = match provider_type {
                ProviderType::Phone => (AppErrorCode::SmsFailed, "SMS failed to send"),
                ProviderType::Email => (AppErrorCode::EmailFailed, "Email failed to send"),
            };
            return Err(ServerError::App(code, msg.to_string()));
        }

        info!(otp_id = %response.otp_id, "Created OTP entry");

        Ok(response)
    }

    pub async fn verify(&self, otp_id: Uuid, code: &str) -> Result<(), ServerError> {
        let otp = db::otp::get_otp_by_id(&self.pool, otp_id).await?;

        if otp.is_verified() {
            return Err(ServerError::App(
                AppErrorCode::OtpAlreadyVerified,
                "OTP already verified".to_string(),
            ));
        }

        if otp.is_expired() {
            return Err(ServerError::App(
                AppErrorCode::OtpExpired,
                "OTP expired".to_string(),
            ));
        }

        if otp.is_max_attempts_exceeded(self.config.max_attempts as i32) {
            return Err(ServerError::App(
                AppErrorCode::OtpWrongCode,
                "Wrong code".to_string(),
            )); // Hide lock state from attacker
        }

        let valid_code = self.crypto.verify(code, &otp.hash);

        if !valid_code {
            let new_count = db::otp::increment_and_get_failed_attempts(&self.pool, otp_id).await?;

            warn!(
                otp_id = %otp_id,
                failed_attempts = new_count,
                "Invalid code for OTP"
            );

            return Err(ServerError::App(
                AppErrorCode::OtpWrongCode,
                "Wrong code".to_string(),
            ));
        }

        db::otp::mark_verified(&self.pool, otp_id).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::sync::{Arc, Mutex};

    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use uuid::Uuid;

    use crate::{
        config::{CommsConfig, OtpConfig},
        error::AppErrorCode,
        models::{
            auth::ProviderType,
            comms::{SendEmailResponse, SendSmsResponse},
        },
        ports::comms::CommsPort,
    };

    use super::{OtpService, ServerError};

    struct MockCrypto {
        hash_value: String,
        verify_result: bool,
    }

    impl MockCrypto {
        fn new(hash_value: &str, verify_result: bool) -> Self {
            Self {
                hash_value: hash_value.to_string(),
                verify_result,
            }
        }
    }

    impl crate::ports::crypto::CryptoPort for MockCrypto {
        fn hash(&self, _value: &str) -> String {
            self.hash_value.clone()
        }

        fn verify(&self, _value: &str, _expected_hash: &str) -> bool {
            self.verify_result
        }

        fn hash_password(
            &self,
            _password: &str,
        ) -> Result<String, crate::ports::crypto::CryptoError> {
            Ok(self.hash_value.clone())
        }

        fn verify_password(
            &self,
            _password: &str,
            _hash: &str,
        ) -> Result<bool, crate::ports::crypto::CryptoError> {
            Ok(self.verify_result)
        }
    }

    struct MockComms {
        should_fail: bool,
        call_count: Mutex<u32>,
    }

    impl MockComms {
        fn new(should_fail: bool) -> Self {
            Self {
                should_fail,
                call_count: Mutex::new(0),
            }
        }

        fn get_call_count(&self) -> u32 {
            *self.call_count.lock().unwrap()
        }
    }

    #[async_trait]
    impl CommsPort for MockComms {
        async fn send_sms(
            &self,
            _from: &str,
            _to: &str,
            _message: &str,
        ) -> Result<SendSmsResponse, reqwest::Error> {
            *self.call_count.lock().unwrap() += 1;

            if self.should_fail {
                // Create a fake reqwest error by making an invalid request
                let client = reqwest::Client::new();
                let err = client
                    .get("http://[::1]:0/invalid")
                    .send()
                    .await
                    .unwrap_err();
                return Err(err);
            }

            Ok(SendSmsResponse {
                status: "sent".to_string(),
                direction: "outbound".to_string(),
                from: "+1234567890".to_string(),
                created: "2024-01-01T00:00:00Z".to_string(),
                parts: 1,
                to: "+0987654321".to_string(),
                cost: 100,
                message: "Test".to_string(),
                id: "msg_123".to_string(),
            })
        }

        async fn send_email(
            &self,
            _from: &str,
            _to: &[&str],
            _subject: &str,
            _html: Option<&str>,
            _text: Option<&str>,
        ) -> Result<SendEmailResponse, reqwest::Error> {
            unimplemented!()
        }
    }

    fn test_otp_config() -> OtpConfig {
        OtpConfig {
            ttl_minutes: 5,
            max_attempts: 3,
            max_messages_per_day: 10,
            cleanup_interval_minutes: 60,
        }
    }

    fn test_comms_config() -> CommsConfig {
        CommsConfig {
            username: "test".to_string(),
            password: "test".to_string(),
            from_phone: "+1234567890".to_string(),
            from_email: "test@example.com".to_string(),
            otp_message_template: "Your code is {code}".to_string(),
            otp_email_subject: "Your verification code".to_string(),
            resend_api_key: "test_key".to_string(),
        }
    }

    #[sqlx::test]
    async fn create_and_send_success(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let service = OtpService::new(
            test_otp_config(),
            test_comms_config(),
            pool,
            comms.clone(),
            crypto,
        );

        let result = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await;

        assert!(result.is_ok());
        assert_eq!(comms.get_call_count(), 1);
    }

    #[sqlx::test]
    async fn create_and_send_sms_fails_deletes_otp(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(true));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let service = OtpService::new(
            test_otp_config(),
            test_comms_config(),
            pool.clone(),
            comms.clone(),
            crypto,
        );

        let result = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await;

        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::SmsFailed, _))
        ));
        assert_eq!(comms.get_call_count(), 1);

        // Verify no OTP records remain
        let count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM otp")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count.0, 0);
    }

    #[sqlx::test]
    async fn create_and_send_max_messages_exceeded(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let config = OtpConfig {
            max_messages_per_day: 2,
            ..test_otp_config()
        };

        let service = OtpService::new(config, test_comms_config(), pool, comms.clone(), crypto);

        // Send max allowed
        service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();
        service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();

        // Third should fail
        let result = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await;
        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpMaxMessages, _))
        ));
        assert_eq!(comms.get_call_count(), 2);
    }

    #[sqlx::test]
    async fn verify_success(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let service = OtpService::new(test_otp_config(), test_comms_config(), pool, comms, crypto);

        let response = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();
        let result = service.verify(response.otp_id, "123456").await;

        assert!(result.is_ok());
    }

    #[sqlx::test]
    async fn verify_wrong_code_increments_attempts(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", false)); // verify returns false

        let service = OtpService::new(
            test_otp_config(),
            test_comms_config(),
            pool.clone(),
            comms,
            crypto,
        );

        let response = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();

        let result = service.verify(response.otp_id, "wrong").await;
        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpWrongCode, _))
        ));

        // Check failed_attempts incremented
        let otp: (i32,) = sqlx::query_as("SELECT failed_attempts FROM otp WHERE id = $1")
            .bind(response.otp_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(otp.0, 1);
    }

    #[sqlx::test]
    async fn verify_max_attempts_exceeded_returns_wrong_code(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true)); // Would pass if attempts not exceeded

        let config = OtpConfig {
            max_attempts: 3,
            ..test_otp_config()
        };

        let service = OtpService::new(config, test_comms_config(), pool.clone(), comms, crypto);

        let response = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();

        // Set failed_attempts to max
        sqlx::query("UPDATE otp SET failed_attempts = 3 WHERE id = $1")
            .bind(response.otp_id)
            .execute(&pool)
            .await
            .unwrap();

        // Should return WrongCode (hides lock state)
        let result = service.verify(response.otp_id, "123456").await;
        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpWrongCode, _))
        ));
    }

    #[sqlx::test]
    async fn verify_at_max_attempts_minus_one_still_works(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let config = OtpConfig {
            max_attempts: 3,
            ..test_otp_config()
        };

        let service = OtpService::new(config, test_comms_config(), pool.clone(), comms, crypto);

        let response = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();

        // Set failed_attempts to max - 1
        sqlx::query("UPDATE otp SET failed_attempts = 2 WHERE id = $1")
            .bind(response.otp_id)
            .execute(&pool)
            .await
            .unwrap();

        // Should still succeed
        let result = service.verify(response.otp_id, "123456").await;
        assert!(result.is_ok());
    }

    #[sqlx::test]
    async fn verify_expired_otp(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let service = OtpService::new(
            test_otp_config(),
            test_comms_config(),
            pool.clone(),
            comms,
            crypto,
        );

        let response = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();

        // Expire the OTP
        let expired = Utc::now() - Duration::minutes(10);
        sqlx::query("UPDATE otp SET expires_at = $1 WHERE id = $2")
            .bind(expired)
            .bind(response.otp_id)
            .execute(&pool)
            .await
            .unwrap();

        let result = service.verify(response.otp_id, "123456").await;
        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpExpired, _))
        ));
    }

    #[sqlx::test]
    async fn verify_not_found(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let service = OtpService::new(test_otp_config(), test_comms_config(), pool, comms, crypto);

        let fake_id = Uuid::new_v4();
        let result = service.verify(fake_id, "123456").await;

        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpNotFound, _))
        ));
    }

    #[sqlx::test]
    async fn verify_multiple_wrong_attempts_then_lockout(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", false));

        let config = OtpConfig {
            max_attempts: 3,
            ..test_otp_config()
        };

        let service = OtpService::new(config, test_comms_config(), pool.clone(), comms, crypto);

        let response = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();

        // Try wrong code 3 times
        for i in 1..=3 {
            let result = service.verify(response.otp_id, "wrong").await;
            assert!(matches!(
                result,
                Err(ServerError::App(AppErrorCode::OtpWrongCode, _))
            ));

            let otp: (i32,) = sqlx::query_as("SELECT failed_attempts FROM otp WHERE id = $1")
                .bind(response.otp_id)
                .fetch_one(&pool)
                .await
                .unwrap();
            assert_eq!(otp.0, i);
        }

        // 4th attempt should still return WrongCode (locked but hidden)
        let result = service.verify(response.otp_id, "wrong").await;
        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpWrongCode, _))
        ));

        // Failed attempts should NOT increment past max (checked before verify)
        let otp: (i32,) = sqlx::query_as("SELECT failed_attempts FROM otp WHERE id = $1")
            .bind(response.otp_id)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(otp.0, 3); // Should remain at 3
    }

    #[sqlx::test]
    async fn create_and_send_different_phone_numbers_independent(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let config = OtpConfig {
            max_messages_per_day: 1,
            ..test_otp_config()
        };

        let service = OtpService::new(config, test_comms_config(), pool, comms.clone(), crypto);

        // Different phone numbers should have independent limits
        let r1 = service
            .create_and_send("+4799999991", ProviderType::Phone)
            .await;
        let r2 = service
            .create_and_send("+4799999992", ProviderType::Phone)
            .await;
        let r3 = service
            .create_and_send("+4799999993", ProviderType::Phone)
            .await;

        assert!(r1.is_ok());
        assert!(r2.is_ok());
        assert!(r3.is_ok());
        assert_eq!(comms.get_call_count(), 3);
    }

    #[sqlx::test]
    async fn verify_already_verified_otp_is_rejected(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let service = OtpService::new(
            test_otp_config(),
            test_comms_config(),
            pool.clone(),
            comms,
            crypto,
        );

        let response = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();

        // Verify first time
        let result = service.verify(response.otp_id, "123456").await;
        assert!(result.is_ok());

        // Second verification should fail
        let result = service.verify(response.otp_id, "123456").await;
        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpAlreadyVerified, _))
        ));
    }

    #[sqlx::test]
    async fn otp_message_template_substitution(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let comms_config = CommsConfig {
            otp_message_template: "Code: {code} - expires in 5 min".to_string(),
            ..test_comms_config()
        };

        let service = OtpService::new(test_otp_config(), comms_config, pool, comms.clone(), crypto);

        // Just verify it doesn't panic - template substitution happens internally
        let result = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await;
        assert!(result.is_ok());
    }

    #[sqlx::test]
    async fn max_messages_per_day_zero_blocks_all(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let config = OtpConfig {
            max_messages_per_day: 0,
            ..test_otp_config()
        };

        let service = OtpService::new(config, test_comms_config(), pool, comms.clone(), crypto);

        let result = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await;
        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpMaxMessages, _))
        ));
        assert_eq!(comms.get_call_count(), 0); // SMS never sent
    }

    #[sqlx::test]
    async fn max_attempts_zero_locks_immediately(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let config = OtpConfig {
            max_attempts: 0,
            ..test_otp_config()
        };

        let service = OtpService::new(config, test_comms_config(), pool, comms, crypto);

        let response = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();

        // First attempt should fail (max_attempts = 0 means locked immediately)
        let result = service.verify(response.otp_id, "123456").await;
        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpWrongCode, _))
        ));
    }

    #[sqlx::test]
    async fn verify_with_empty_code(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", false)); // Empty won't match

        let service = OtpService::new(test_otp_config(), test_comms_config(), pool, comms, crypto);

        let response = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await
            .unwrap();
        let result = service.verify(response.otp_id, "").await;

        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpWrongCode, _))
        ));
    }

    #[sqlx::test]
    async fn create_multiple_otps_for_same_number_within_limit(pool: sqlx::PgPool) {
        let comms = Arc::new(MockComms::new(false));
        let crypto = Arc::new(MockCrypto::new("hashed_code", true));

        let config = OtpConfig {
            max_messages_per_day: 5,
            ..test_otp_config()
        };

        let service = OtpService::new(config, test_comms_config(), pool, comms.clone(), crypto);

        // Create 5 OTPs (at the limit)
        for _ in 0..5 {
            let result = service
                .create_and_send("+4799999999", ProviderType::Phone)
                .await;
            assert!(result.is_ok());
        }
        assert_eq!(comms.get_call_count(), 5);

        // 6th should fail
        let result = service
            .create_and_send("+4799999999", ProviderType::Phone)
            .await;
        assert!(matches!(
            result,
            Err(ServerError::App(AppErrorCode::OtpMaxMessages, _))
        ));
        assert_eq!(comms.get_call_count(), 5); // No additional SMS sent
    }

    // Unit tests for Otp model methods
    mod otp_model_tests {
        use chrono::{Duration, Utc};
        use uuid::Uuid;

        use crate::models::{auth::ProviderType, otp::Otp};

        fn create_test_otp(expires_in_minutes: i64, failed_attempts: i32) -> Otp {
            Otp {
                id: Uuid::new_v4(),
                identifier: "+4799999999".to_string(),
                provider_type: ProviderType::Phone,
                hash: "test_hash".to_string(),
                expires_at: Utc::now() + Duration::minutes(expires_in_minutes),
                verified_at: None,
                created_at: Utc::now(),
                ip_address: None,
                failed_attempts,
            }
        }

        #[test]
        fn is_expired_returns_false_for_future_expiry() {
            let otp = create_test_otp(10, 0);
            assert!(!otp.is_expired());
        }

        #[test]
        fn is_expired_returns_true_for_past_expiry() {
            let otp = create_test_otp(-10, 0);
            assert!(otp.is_expired());
        }

        #[test]
        fn is_max_attempts_exceeded_boundary() {
            let otp = create_test_otp(10, 3);
            assert!(!otp.is_max_attempts_exceeded(4)); // 3 < 4
            assert!(otp.is_max_attempts_exceeded(3)); // 3 >= 3
            assert!(otp.is_max_attempts_exceeded(2)); // 3 >= 2
        }

        #[test]
        fn is_verified_returns_false_when_none() {
            let otp = create_test_otp(10, 0);
            assert!(!otp.is_verified());
        }

        #[test]
        fn is_verified_returns_true_when_some() {
            let mut otp = create_test_otp(10, 0);
            otp.verified_at = Some(Utc::now());
            assert!(otp.is_verified());
        }

        #[test]
        fn generate_code_returns_six_digit_string() {
            for _ in 0..100 {
                let code = Otp::generate_code();
                assert_eq!(code.len(), 6);
                assert!(code.chars().all(|c| c.is_ascii_digit()));
            }
        }

        #[test]
        fn hash_code_produces_consistent_output() {
            let code = "123456";
            let hash1 = Otp::hash_code(code);
            let hash2 = Otp::hash_code(code);
            assert_eq!(hash1, hash2);
            assert_eq!(hash1.len(), 64); // SHA256 hex = 64 chars
        }

        #[test]
        fn hash_code_produces_different_output_for_different_input() {
            let hash1 = Otp::hash_code("123456");
            let hash2 = Otp::hash_code("654321");
            assert_ne!(hash1, hash2);
        }
    }
}
