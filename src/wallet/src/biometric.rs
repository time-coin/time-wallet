//! Biometric authentication module for wallet
//!
//! Provides platform-agnostic biometric authentication interface.
//! Actual implementation depends on the platform:
//! - iOS: Face ID, Touch ID via LocalAuthentication framework
//! - Android: BiometricPrompt API
//! - Desktop: Platform-specific (Windows Hello, macOS Touch ID, Linux fingerprint)

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum BiometricError {
    #[error("Biometric authentication not available on this device")]
    NotAvailable,

    #[error("Biometric authentication not enrolled")]
    NotEnrolled,

    #[error("Biometric authentication failed")]
    AuthenticationFailed,

    #[error("Biometric authentication was cancelled by user")]
    UserCancelled,

    #[error("Biometric authentication timed out")]
    Timeout,

    #[error("Biometric authentication locked out")]
    Lockout,

    #[error("Platform error: {0}")]
    PlatformError(String),

    #[error("Not implemented on this platform")]
    NotImplemented,
}

/// Biometric authentication types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BiometricType {
    /// Face recognition (Face ID, Face Unlock)
    Face,
    /// Fingerprint (Touch ID, Fingerprint Scanner)
    Fingerprint,
    /// Iris scan
    Iris,
    /// Voice recognition
    Voice,
    /// Multiple types available
    Multiple,
}

/// Biometric capability information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricCapability {
    /// Whether biometric authentication is available
    pub available: bool,
    /// Whether biometrics are enrolled
    pub enrolled: bool,
    /// Type of biometric authentication
    pub biometric_type: Option<BiometricType>,
    /// Hardware support
    pub hardware_present: bool,
}

/// Biometric authentication configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BiometricConfig {
    /// Title shown in authentication prompt
    pub title: String,
    /// Subtitle or description
    pub subtitle: String,
    /// Description text
    pub description: String,
    /// Allow fallback to password/PIN
    pub allow_fallback: bool,
    /// Timeout in seconds
    pub timeout_secs: u64,
}

impl Default for BiometricConfig {
    fn default() -> Self {
        Self {
            title: "Authenticate".to_string(),
            subtitle: "Unlock your TIME Coin wallet".to_string(),
            description: "Use biometric authentication to unlock your wallet".to_string(),
            allow_fallback: true,
            timeout_secs: 30,
        }
    }
}

/// Platform-agnostic biometric authentication interface
pub trait BiometricAuthenticator: Send + Sync {
    /// Check if biometric authentication is available
    fn check_capability(&self) -> Result<BiometricCapability, BiometricError>;

    /// Authenticate using biometrics
    fn authenticate(&self, config: &BiometricConfig) -> Result<(), BiometricError>;

    /// Authenticate asynchronously
    fn authenticate_async(
        &self,
        config: &BiometricConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BiometricError>> + Send>>;
}

/// Mock biometric authenticator for testing and platforms without biometric support
pub struct MockBiometricAuth {
    should_succeed: bool,
}

impl MockBiometricAuth {
    /// Create mock authenticator that succeeds
    pub fn success() -> Self {
        Self {
            should_succeed: true,
        }
    }

    /// Create mock authenticator that fails
    pub fn failure() -> Self {
        Self {
            should_succeed: false,
        }
    }
}

impl BiometricAuthenticator for MockBiometricAuth {
    fn check_capability(&self) -> Result<BiometricCapability, BiometricError> {
        Ok(BiometricCapability {
            available: true,
            enrolled: true,
            biometric_type: Some(BiometricType::Fingerprint),
            hardware_present: true,
        })
    }

    fn authenticate(&self, _config: &BiometricConfig) -> Result<(), BiometricError> {
        if self.should_succeed {
            Ok(())
        } else {
            Err(BiometricError::AuthenticationFailed)
        }
    }

    fn authenticate_async(
        &self,
        config: &BiometricConfig,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), BiometricError>> + Send>>
    {
        let result = self.authenticate(config);
        Box::pin(async move { result })
    }
}

/// Platform-specific biometric implementation selector
pub struct BiometricAuth;

impl BiometricAuth {
    /// Create platform-specific biometric authenticator
    #[cfg(target_os = "ios")]
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Box<dyn BiometricAuthenticator> {
        // iOS implementation would use LocalAuthentication framework
        // For now, return mock
        Box::new(MockBiometricAuth::success())
    }

    #[cfg(target_os = "android")]
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Box<dyn BiometricAuthenticator> {
        // Android implementation would use BiometricPrompt API
        // For now, return mock
        Box::new(MockBiometricAuth::success())
    }

    #[cfg(target_os = "macos")]
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Box<dyn BiometricAuthenticator> {
        // macOS implementation would use Touch ID / LocalAuthentication
        // For now, return mock
        Box::new(MockBiometricAuth::success())
    }

    #[cfg(target_os = "windows")]
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Box<dyn BiometricAuthenticator> {
        // Windows implementation would use Windows Hello
        // For now, return mock
        Box::new(MockBiometricAuth::success())
    }

    #[cfg(not(any(
        target_os = "ios",
        target_os = "android",
        target_os = "macos",
        target_os = "windows"
    )))]
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Box<dyn BiometricAuthenticator> {
        // Fallback for other platforms
        Box::new(MockBiometricAuth::success())
    }

    /// Check if biometric authentication is supported on this platform
    pub fn is_supported() -> bool {
        cfg!(any(
            target_os = "ios",
            target_os = "android",
            target_os = "macos",
            target_os = "windows"
        ))
    }
}

impl Default for BiometricAuth {
    fn default() -> Self {
        Self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_biometric_capability() {
        let auth = MockBiometricAuth::success();
        let capability = auth.check_capability().unwrap();

        assert!(capability.available);
        assert!(capability.enrolled);
        assert_eq!(capability.biometric_type, Some(BiometricType::Fingerprint));
    }

    #[test]
    fn test_mock_auth_success() {
        let auth = MockBiometricAuth::success();
        let config = BiometricConfig::default();

        assert!(auth.authenticate(&config).is_ok());
    }

    #[test]
    fn test_mock_auth_failure() {
        let auth = MockBiometricAuth::failure();
        let config = BiometricConfig::default();

        assert!(auth.authenticate(&config).is_err());
    }

    #[tokio::test]
    async fn test_async_auth() {
        let auth = MockBiometricAuth::success();
        let config = BiometricConfig::default();

        let result = auth.authenticate_async(&config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_biometric_config_default() {
        let config = BiometricConfig::default();
        assert_eq!(config.title, "Authenticate");
        assert!(config.allow_fallback);
        assert_eq!(config.timeout_secs, 30);
    }

    #[test]
    fn test_platform_support() {
        // Should return true on major platforms
        #[cfg(any(
            target_os = "ios",
            target_os = "android",
            target_os = "macos",
            target_os = "windows"
        ))]
        assert!(BiometricAuth::is_supported());

        // Can create authenticator
        let _auth = BiometricAuth::new();
    }
}
