//! Timeout utilities for preventing UI blocking operations

use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct SafeTimeout<T> {
    pub value: Option<T>,
    pub timed_out: bool,
    pub elapsed_ms: u128,
}

impl<T> SafeTimeout<T> {
    pub fn ok_or<E>(self, error: E) -> Result<T, E> {
        self.value.ok_or(error)
    }

    pub fn log_if_slow(&self, operation: &str, threshold_ms: u128) {
        if self.elapsed_ms > threshold_ms {
            log::warn!(
                "⏱️ Slow operation '{}': {}ms (threshold: {}ms)",
                operation,
                self.elapsed_ms,
                threshold_ms
            );
        }
    }
}

/// Execute a future with a timeout
pub async fn safe_timeout<F, T>(timeout_ms: u64, future: F) -> SafeTimeout<T>
where
    F: std::future::Future<Output = T>,
{
    let start = Instant::now();

    match tokio::time::timeout(Duration::from_millis(timeout_ms), future).await {
        Ok(value) => SafeTimeout {
            value: Some(value),
            timed_out: false,
            elapsed_ms: start.elapsed().as_millis(),
        },
        Err(_) => {
            log::error!("⏱️ Operation timeout after {}ms", timeout_ms);
            SafeTimeout {
                value: None,
                timed_out: true,
                elapsed_ms: start.elapsed().as_millis(),
            }
        }
    }
}

/// Standard timeouts for common operations
pub mod timeouts {
    pub const UI_QUICK: u64 = 100; // 100ms - UI updates
    pub const NETWORK_QUICK: u64 = 1000; // 1s - Quick network ops
    pub const NETWORK_NORMAL: u64 = 5000; // 5s - Normal network ops
    pub const NETWORK_SLOW: u64 = 30000; // 30s - Slow operations (sync, etc)
}

/// Debounce timer to prevent excessive operation calls
pub struct DebounceTimer {
    last_fire: Instant,
    interval: Duration,
}

impl DebounceTimer {
    pub fn new(interval_ms: u64) -> Self {
        Self {
            last_fire: Instant::now(),
            interval: Duration::from_millis(interval_ms),
        }
    }

    pub fn should_fire(&mut self) -> bool {
        if self.last_fire.elapsed() >= self.interval {
            self.last_fire = Instant::now();
            true
        } else {
            false
        }
    }

    pub fn reset(&mut self) {
        self.last_fire = Instant::now();
    }

    pub fn time_until_next(&self) -> Duration {
        self.interval.saturating_sub(self.last_fire.elapsed())
    }
}
