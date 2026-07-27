use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString, rand_core::OsRng},
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::ports::crypto::{CryptoError, CryptoPort};

type HmacSha256 = Hmac<Sha256>;

pub struct CryptoAdapter {
    secret: String,
}

impl CryptoAdapter {
    pub fn new(secret: String) -> Self {
        Self { secret }
    }
}

impl CryptoPort for CryptoAdapter {
    fn hash(&self, value: &str) -> String {
        let mut mac =
            HmacSha256::new_from_slice(self.secret.as_bytes()).expect("HMAC can take any size key");
        mac.update(value.as_bytes());
        let result = mac.finalize();
        hex::encode(result.into_bytes())
    }

    fn verify(&self, value: &str, expected_hash: &str) -> bool {
        let hash = self.hash(value);
        hash.as_bytes().ct_eq(expected_hash.as_bytes()).into()
    }

    fn hash_password(&self, password: &str) -> Result<String, CryptoError> {
        let salt = SaltString::generate(&mut OsRng);
        let argon2 = Argon2::default();

        argon2
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| CryptoError::HashFailed(e.to_string()))
    }

    fn verify_password(&self, password: &str, hash: &str) -> Result<bool, CryptoError> {
        let parsed_hash =
            PasswordHash::new(hash).map_err(|e| CryptoError::InvalidHash(e.to_string()))?;

        Ok(Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    fn test_adapter() -> CryptoAdapter {
        CryptoAdapter::new("test-secret".to_string())
    }

    #[test]
    fn verify_uses_constant_time_comparison() {
        let adapter = test_adapter();

        let value = "test-value";
        let correct_hash = adapter.hash(value);
        let wrong_hash = adapter.hash("wrong-value");

        // Correct hash should verify
        assert!(adapter.verify(value, &correct_hash));

        // Wrong hash should not verify
        assert!(!adapter.verify(value, &wrong_hash));

        // Length mismatch should not verify (and not panic)
        assert!(!adapter.verify(value, "short"));
        assert!(!adapter.verify(value, ""));
    }

    #[test]
    fn hash_produces_consistent_results() {
        let adapter = test_adapter();

        let hash1 = adapter.hash("test");
        let hash2 = adapter.hash("test");

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn hash_produces_different_results_for_different_inputs() {
        let adapter = test_adapter();

        let hash1 = adapter.hash("test1");
        let hash2 = adapter.hash("test2");

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn hash_password_produces_valid_argon2_hash() {
        let adapter = test_adapter();

        let hash = adapter.hash_password("password123").unwrap();

        // Argon2 hashes start with $argon2
        assert!(hash.starts_with("$argon2"));
    }

    #[test]
    fn hash_password_produces_unique_salts() {
        let adapter = test_adapter();

        let hash1 = adapter.hash_password("password").unwrap();
        let hash2 = adapter.hash_password("password").unwrap();

        // Same password should produce different hashes due to random salt
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn verify_password_succeeds_for_correct_password() {
        let adapter = test_adapter();

        let hash = adapter.hash_password("correct-password").unwrap();

        assert!(adapter.verify_password("correct-password", &hash).unwrap());
    }

    #[test]
    fn verify_password_fails_for_wrong_password() {
        let adapter = test_adapter();

        let hash = adapter.hash_password("correct-password").unwrap();

        assert!(!adapter.verify_password("wrong-password", &hash).unwrap());
    }

    #[test]
    fn verify_password_returns_error_for_invalid_hash() {
        let adapter = test_adapter();

        let result = adapter.verify_password("password", "not-a-valid-hash");

        assert!(result.is_err());
    }
}
