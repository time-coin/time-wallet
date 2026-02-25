//! PIN authentication module for wallet
//!
//! Provides PIN-based authentication as a faster alternative to full password entry.
//! Useful for quick access while maintaining security.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use zeroize::ZeroizeOnDrop;

#[derive(Error, Debug)]
pub enum PinError {
    #[error("Invalid PIN format")]
    InvalidFormat,

    #[error("PIN too short (minimum {0} digits)")]
    TooShort(usize),

    #[error("PIN too long (maximum {0} digits)")]
    TooLong(usize),

    #[error("PIN must contain only digits")]
    NonNumeric,

    #[error("Incorrect PIN")]
    IncorrectPin,

    #[error("PIN attempts exceeded - account locked")]
    AttemptsExceeded,

    #[error("Hash error")]
    HashError,
}

/// PIN configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinConfig {
    /// Minimum PIN length (default: 4)
    pub min_length: usize,
    /// Maximum PIN length (default: 8)
    pub max_length: usize,
    /// Maximum failed attempts before lockout (default: 3)
    pub max_attempts: u32,
    /// Lockout duration in seconds (default: 300 = 5 minutes)
    pub lockout_duration_secs: u64,
}

impl Default for PinConfig {
    fn default() -> Self {
        Self {
            min_length: 4,
            max_length: 8,
            max_attempts: 3,
            lockout_duration_secs: 300,
        }
    }
}

/// Secure PIN wrapper that zeros memory on drop
#[derive(ZeroizeOnDrop)]
pub struct SecurePin(String);

impl SecurePin {
    /// Create new secure PIN
    pub fn new(pin: String) -> Result<Self, PinError> {
        // Validate PIN format
        if pin.is_empty() {
            return Err(PinError::InvalidFormat);
        }

        if !pin.chars().all(|c| c.is_ascii_digit()) {
            return Err(PinError::NonNumeric);
        }

        Ok(Self(pin))
    }

    /// Create from numeric value
    pub fn from_number(pin: u32) -> Self {
        Self(pin.to_string())
    }

    /// Get PIN as string slice
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Get PIN as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Get length
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// Stored PIN data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredPin {
    /// Argon2 hash of the PIN
    pub hash: String,
    /// Salt used for hashing
    pub salt: String,
    /// Failed attempt counter
    pub failed_attempts: u32,
    /// Timestamp of last failed attempt (for lockout)
    pub last_failed_attempt: Option<u64>,
    /// Configuration
    pub config: PinConfig,
}

/// PIN authentication manager
pub struct PinAuth;

impl PinAuth {
    /// Hash a PIN for storage
    pub fn hash_pin(pin: &SecurePin, config: &PinConfig) -> Result<StoredPin, PinError> {
        // Validate PIN length
        if pin.len() < config.min_length {
            return Err(PinError::TooShort(config.min_length));
        }
        if pin.len() > config.max_length {
            return Err(PinError::TooLong(config.max_length));
        }

        // Generate salt
        let salt = SaltString::generate(&mut rand::thread_rng());

        // Hash PIN with Argon2id
        let argon2 = Argon2::default();
        let hash = argon2
            .hash_password(pin.as_bytes(), &salt)
            .map_err(|_| PinError::HashError)?
            .to_string();

        Ok(StoredPin {
            hash,
            salt: salt.as_str().to_string(),
            failed_attempts: 0,
            last_failed_attempt: None,
            config: config.clone(),
        })
    }

    /// Verify PIN against stored hash
    pub fn verify_pin(pin: &SecurePin, stored: &mut StoredPin) -> Result<(), PinError> {
        // Check if account is locked out
        if let Some(last_failed) = stored.last_failed_attempt {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if stored.failed_attempts >= stored.config.max_attempts {
                let lockout_end = last_failed + stored.config.lockout_duration_secs;
                if now < lockout_end {
                    return Err(PinError::AttemptsExceeded);
                }
                // Lockout expired, reset attempts
                stored.failed_attempts = 0;
                stored.last_failed_attempt = None;
            }
        }

        // Parse stored hash
        let parsed_hash = PasswordHash::new(&stored.hash).map_err(|_| PinError::HashError)?;

        // Verify PIN
        if Argon2::default()
            .verify_password(pin.as_bytes(), &parsed_hash)
            .is_ok()
        {
            // Success - reset failed attempts
            stored.failed_attempts = 0;
            stored.last_failed_attempt = None;
            Ok(())
        } else {
            // Failed attempt
            stored.failed_attempts += 1;
            stored.last_failed_attempt = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );

            if stored.failed_attempts >= stored.config.max_attempts {
                Err(PinError::AttemptsExceeded)
            } else {
                Err(PinError::IncorrectPin)
            }
        }
    }

    /// Generate random PIN
    pub fn generate_random_pin(length: usize) -> SecurePin {
        let mut rng = rand::thread_rng();
        let pin_num = rng.gen_range(10_u32.pow((length - 1) as u32)..10_u32.pow(length as u32));
        SecurePin::from_number(pin_num)
    }

    /// Check if PIN is weak (e.g., 1234, 0000)
    pub fn is_weak_pin(pin: &SecurePin) -> bool {
        let s = pin.as_str();

        // Check for sequential digits
        if s == "0123456789"[..s.len()].to_string() || s == "9876543210"[..s.len()].to_string() {
            return true;
        }

        // Check for repeated digits
        if s.chars().all(|c| c == s.chars().next().unwrap()) {
            return true;
        }

        // Check common weak PINs
        let weak_pins = ["1234", "0000", "1111", "1212", "1004", "2000"];
        weak_pins.contains(&s)
    }

    /// Get remaining attempts before lockout
    pub fn remaining_attempts(stored: &StoredPin) -> u32 {
        stored
            .config
            .max_attempts
            .saturating_sub(stored.failed_attempts)
    }

    /// Get lockout time remaining in seconds
    pub fn lockout_remaining(stored: &StoredPin) -> Option<u64> {
        if stored.failed_attempts < stored.config.max_attempts {
            return None;
        }

        if let Some(last_failed) = stored.last_failed_attempt {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let lockout_end = last_failed + stored.config.lockout_duration_secs;
            if now < lockout_end {
                return Some(lockout_end - now);
            }
        }

        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pin_creation() {
        let pin = SecurePin::new("1234".to_string()).unwrap();
        assert_eq!(pin.len(), 4);
        assert_eq!(pin.as_str(), "1234");
    }

    #[test]
    fn test_pin_validation() {
        assert!(SecurePin::new("".to_string()).is_err());
        assert!(SecurePin::new("abc".to_string()).is_err());
        assert!(SecurePin::new("12a4".to_string()).is_err());
        assert!(SecurePin::new("1234".to_string()).is_ok());
    }

    #[test]
    fn test_pin_hash_and_verify() {
        let config = PinConfig::default();
        let pin = SecurePin::new("5678".to_string()).unwrap();

        let mut stored = PinAuth::hash_pin(&pin, &config).unwrap();
        assert_eq!(stored.failed_attempts, 0);

        // Correct PIN
        assert!(PinAuth::verify_pin(&pin, &mut stored).is_ok());
        assert_eq!(stored.failed_attempts, 0);

        // Wrong PIN
        let wrong_pin = SecurePin::new("0000".to_string()).unwrap();
        assert!(PinAuth::verify_pin(&wrong_pin, &mut stored).is_err());
        assert_eq!(stored.failed_attempts, 1);
    }

    #[test]
    fn test_lockout() {
        let config = PinConfig {
            max_attempts: 3,
            ..Default::default()
        };
        let pin = SecurePin::new("1234".to_string()).unwrap();
        let wrong_pin = SecurePin::new("9999".to_string()).unwrap();

        let mut stored = PinAuth::hash_pin(&pin, &config).unwrap();

        // Three failed attempts
        for _ in 0..3 {
            let _ = PinAuth::verify_pin(&wrong_pin, &mut stored);
        }

        // Should be locked out
        assert_eq!(stored.failed_attempts, 3);
        let result = PinAuth::verify_pin(&pin, &mut stored);
        assert!(matches!(result, Err(PinError::AttemptsExceeded)));
    }

    #[test]
    fn test_weak_pin_detection() {
        assert!(PinAuth::is_weak_pin(
            &SecurePin::new("1234".to_string()).unwrap()
        ));
        assert!(PinAuth::is_weak_pin(
            &SecurePin::new("0000".to_string()).unwrap()
        ));
        assert!(PinAuth::is_weak_pin(
            &SecurePin::new("1111".to_string()).unwrap()
        ));
        assert!(!PinAuth::is_weak_pin(
            &SecurePin::new("5678".to_string()).unwrap()
        ));
    }

    #[test]
    fn test_random_pin_generation() {
        let pin = PinAuth::generate_random_pin(4);
        assert_eq!(pin.len(), 4);
        assert!(pin.as_str().chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn test_remaining_attempts() {
        let config = PinConfig::default();
        let pin = SecurePin::new("1234".to_string()).unwrap();
        let mut stored = PinAuth::hash_pin(&pin, &config).unwrap();

        assert_eq!(PinAuth::remaining_attempts(&stored), 3);

        let wrong_pin = SecurePin::new("0000".to_string()).unwrap();
        let _ = PinAuth::verify_pin(&wrong_pin, &mut stored);
        assert_eq!(PinAuth::remaining_attempts(&stored), 2);
    }

    #[test]
    fn test_pin_length_validation() {
        let config = PinConfig {
            min_length: 4,
            max_length: 6,
            ..Default::default()
        };

        let short_pin = SecurePin::new("123".to_string()).unwrap();
        assert!(PinAuth::hash_pin(&short_pin, &config).is_err());

        let long_pin = SecurePin::new("1234567".to_string()).unwrap();
        assert!(PinAuth::hash_pin(&long_pin, &config).is_err());

        let ok_pin = SecurePin::new("12345".to_string()).unwrap();
        assert!(PinAuth::hash_pin(&ok_pin, &config).is_ok());
    }
}
