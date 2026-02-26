//! Auto-lock functionality for wallet security
//!
//! Automatically locks the wallet after a period of inactivity to protect
//! against unauthorized access if the user steps away.

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tokio::time::sleep;

/// Wallet lock state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// Wallet is unlocked and ready to use
    Unlocked,
    /// Wallet is locked, requires password to unlock
    Locked,
}

/// Auto-lock configuration
#[derive(Debug, Clone)]
pub struct AutoLockConfig {
    /// Duration of inactivity before auto-locking
    pub timeout: Duration,
    /// Whether auto-lock is enabled
    pub enabled: bool,
}

impl Default for AutoLockConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(300), // 5 minutes default
            enabled: true,
        }
    }
}

impl AutoLockConfig {
    /// Create config with custom timeout
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            timeout,
            enabled: true,
        }
    }

    /// Disable auto-lock
    pub fn disabled() -> Self {
        Self {
            timeout: Duration::from_secs(0),
            enabled: false,
        }
    }
}

/// Type alias for lock callback
type LockCallback = Box<dyn Fn() + Send + Sync>;

/// Auto-lock manager for wallet
pub struct AutoLockManager {
    /// Current lock state
    state: Arc<RwLock<LockState>>,
    /// Last activity timestamp
    last_activity: Arc<RwLock<Instant>>,
    /// Configuration
    config: Arc<RwLock<AutoLockConfig>>,
    /// Callback when wallet locks
    on_lock: Arc<RwLock<Option<LockCallback>>>,
}

impl AutoLockManager {
    /// Create new auto-lock manager
    pub fn new(config: AutoLockConfig) -> Self {
        Self {
            state: Arc::new(RwLock::new(LockState::Unlocked)),
            last_activity: Arc::new(RwLock::new(Instant::now())),
            config: Arc::new(RwLock::new(config)),
            on_lock: Arc::new(RwLock::new(None)),
        }
    }

    /// Get current lock state
    pub async fn is_locked(&self) -> bool {
        *self.state.read().await == LockState::Locked
    }

    /// Get current lock state
    pub async fn lock_state(&self) -> LockState {
        *self.state.read().await
    }

    /// Lock the wallet immediately
    pub async fn lock(&self) {
        let mut state = self.state.write().await;
        *state = LockState::Locked;
        drop(state);

        // Trigger callback
        if let Some(callback) = &*self.on_lock.read().await {
            callback();
        }
    }

    /// Unlock the wallet
    pub async fn unlock(&self) {
        let mut state = self.state.write().await;
        *state = LockState::Unlocked;
        drop(state);

        // Reset activity timer
        self.update_activity().await;
    }

    /// Update last activity timestamp (call on any wallet interaction)
    pub async fn update_activity(&self) {
        let mut last_activity = self.last_activity.write().await;
        *last_activity = Instant::now();
    }

    /// Get time until auto-lock
    pub async fn time_until_lock(&self) -> Option<Duration> {
        let config = self.config.read().await;
        if !config.enabled {
            return None;
        }

        let last_activity = *self.last_activity.read().await;
        let elapsed = last_activity.elapsed();

        if elapsed >= config.timeout {
            Some(Duration::from_secs(0))
        } else {
            Some(config.timeout - elapsed)
        }
    }

    /// Set callback for when wallet locks
    pub async fn set_on_lock<F>(&self, callback: F)
    where
        F: Fn() + Send + Sync + 'static,
    {
        let mut on_lock = self.on_lock.write().await;
        *on_lock = Some(Box::new(callback));
    }

    /// Update configuration
    pub async fn update_config(&self, config: AutoLockConfig) {
        let mut current_config = self.config.write().await;
        *current_config = config;
    }

    /// Get current configuration
    pub async fn get_config(&self) -> AutoLockConfig {
        self.config.read().await.clone()
    }

    /// Start auto-lock monitor task
    ///
    /// This spawns a background task that checks for inactivity and locks
    /// the wallet when the timeout is reached.
    ///
    /// # Arguments
    /// * `check_interval` - How often to check for inactivity (default: 10 seconds)
    pub fn start_monitor_with_interval(
        self: Arc<Self>,
        check_interval: Duration,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                sleep(check_interval).await;

                let config = self.config.read().await.clone();

                // Skip if disabled or already locked
                if !config.enabled || self.is_locked().await {
                    continue;
                }

                // Check if timeout reached
                let last_activity = *self.last_activity.read().await;
                let elapsed = last_activity.elapsed();

                if elapsed >= config.timeout {
                    log::info!(
                        "Auto-locking wallet after {} seconds of inactivity",
                        elapsed.as_secs()
                    );
                    self.lock().await;
                }
            }
        })
    }

    /// Start auto-lock monitor task with default 10-second check interval
    pub fn start_monitor(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        self.start_monitor_with_interval(Duration::from_secs(10))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_auto_lock_manager_creation() {
        let config = AutoLockConfig::default();
        let manager = AutoLockManager::new(config);

        assert!(!manager.is_locked().await);
        assert_eq!(manager.lock_state().await, LockState::Unlocked);
    }

    #[tokio::test]
    async fn test_manual_lock_unlock() {
        let config = AutoLockConfig::default();
        let manager = AutoLockManager::new(config);

        // Initially unlocked
        assert!(!manager.is_locked().await);

        // Lock
        manager.lock().await;
        assert!(manager.is_locked().await);

        // Unlock
        manager.unlock().await;
        assert!(!manager.is_locked().await);
    }

    #[tokio::test]
    async fn test_activity_update() {
        let config = AutoLockConfig::with_timeout(Duration::from_secs(2));
        let manager = AutoLockManager::new(config);

        // Update activity
        manager.update_activity().await;

        // Should have time until lock
        let time_left = manager.time_until_lock().await;
        assert!(time_left.is_some());
        assert!(time_left.unwrap() <= Duration::from_secs(2));
    }

    #[tokio::test]
    async fn test_auto_lock_timeout() {
        let config = AutoLockConfig::with_timeout(Duration::from_millis(200));
        let manager = Arc::new(AutoLockManager::new(config));

        // Start monitor with fast check interval for testing
        let _handle = manager
            .clone()
            .start_monitor_with_interval(Duration::from_millis(50));

        // Wait for auto-lock
        tokio::time::sleep(Duration::from_millis(300)).await;

        // Should be locked
        assert!(manager.is_locked().await);
    }

    #[tokio::test]
    async fn test_activity_prevents_lock() {
        let config = AutoLockConfig::with_timeout(Duration::from_millis(300));
        let manager = Arc::new(AutoLockManager::new(config));

        // Start monitor with fast check interval
        let _handle = manager
            .clone()
            .start_monitor_with_interval(Duration::from_millis(50));

        // Keep updating activity
        for _ in 0..5 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            manager.update_activity().await;
        }

        // Should still be unlocked (activity within timeout)
        assert!(!manager.is_locked().await);
    }

    #[tokio::test]
    async fn test_disabled_auto_lock() {
        let config = AutoLockConfig::disabled();
        let manager = AutoLockManager::new(config);

        // Time until lock should be None (disabled)
        assert!(manager.time_until_lock().await.is_none());
    }

    #[tokio::test]
    async fn test_lock_callback() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let config = AutoLockConfig::default();
        let manager = AutoLockManager::new(config);

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = called.clone();

        manager
            .set_on_lock(move || {
                called_clone.store(true, Ordering::SeqCst);
            })
            .await;

        manager.lock().await;

        assert!(called.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn test_config_update() {
        let config = AutoLockConfig::default();
        let manager = AutoLockManager::new(config);

        // Update config
        let new_config = AutoLockConfig::with_timeout(Duration::from_secs(600));
        manager.update_config(new_config).await;

        let current_config = manager.get_config().await;
        assert_eq!(current_config.timeout, Duration::from_secs(600));
    }
}
