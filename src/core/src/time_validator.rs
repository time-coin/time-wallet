//! Time-based blockchain validation for TIME Coin
//!
//! This module ensures nodes operate on correct time and validates blocks
//! based on time constraints to prevent time manipulation attacks.

use chrono::{DateTime, Utc};
use std::error::Error;
use std::fmt;

/// Genesis block timestamp for testnet (December 1, 2025 00:00:00 UTC)
pub const GENESIS_TIMESTAMP: i64 = 1764547200;

/// Block time for testnet (10 minutes)
pub const TESTNET_BLOCK_TIME_SECONDS: i64 = 600; // 10 minutes

/// Block time for mainnet (1 hour) - future use
pub const MAINNET_BLOCK_TIME_SECONDS: i64 = 3600; // 1 hour

/// Maximum allowed time drift (5 minutes)
/// Nodes with time drift exceeding this will be rejected
pub const MAX_TIME_DRIFT_SECONDS: i64 = 300; // 5 minutes

/// Maximum future block tolerance (30 seconds)
/// Blocks with timestamps this far in the future are rejected
pub const MAX_FUTURE_BLOCK_SECONDS: i64 = 30;

/// Minimum time between blocks (to prevent spam)
/// Should be slightly less than block time to allow for small variations
pub const MIN_BLOCK_INTERVAL_SECONDS: i64 = TESTNET_BLOCK_TIME_SECONDS - 60; // 9 minutes

#[derive(Debug, Clone)]
pub enum TimeValidationError {
    /// Node's system clock is too far off from network time
    ClockDrift {
        local_time: i64,
        network_time: i64,
        drift_seconds: i64,
    },
    /// Block timestamp is in the future
    FutureBlock { block_time: i64, current_time: i64 },
    /// Block height exceeds what's possible given elapsed time
    TooManyBlocks { block_height: u64, max_allowed: u64 },
    /// Block height is less than expected (node is behind)
    InsufficientBlocks {
        block_height: u64,
        expected_min: u64,
    },
    /// Block created too quickly after previous block
    BlockTooFast {
        time_since_previous: i64,
        minimum_required: i64,
    },
    /// Invalid genesis timestamp
    InvalidGenesis,
    /// Time calculation error
    CalculationError(String),
}

impl fmt::Display for TimeValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TimeValidationError::ClockDrift {
                local_time,
                network_time,
                drift_seconds,
            } => {
                write!(
                    f,
                    "Clock drift detected: local={}, network={}, drift={}s (max allowed: {}s)",
                    local_time, network_time, drift_seconds, MAX_TIME_DRIFT_SECONDS
                )
            }
            TimeValidationError::FutureBlock {
                block_time,
                current_time,
            } => {
                write!(
                    f,
                    "Block is from the future: block_time={}, current_time={}, diff={}s",
                    block_time,
                    current_time,
                    block_time - current_time
                )
            }
            TimeValidationError::TooManyBlocks {
                block_height,
                max_allowed,
            } => {
                write!(
                    f,
                    "Block height {} exceeds maximum allowed {} based on elapsed time",
                    block_height, max_allowed
                )
            }
            TimeValidationError::InsufficientBlocks {
                block_height,
                expected_min,
            } => {
                write!(
                    f,
                    "Node is behind: current height {} but should be at least {} (catch-up mode required)",
                    block_height, expected_min
                )
            }
            TimeValidationError::BlockTooFast {
                time_since_previous,
                minimum_required,
            } => {
                write!(
                    f,
                    "Block created too quickly: {}s since previous (minimum: {}s)",
                    time_since_previous, minimum_required
                )
            }
            TimeValidationError::InvalidGenesis => {
                write!(f, "Genesis block has invalid timestamp")
            }
            TimeValidationError::CalculationError(msg) => {
                write!(f, "Time calculation error: {}", msg)
            }
        }
    }
}

impl Error for TimeValidationError {}

/// Time validator for TIME Coin blockchain
pub struct TimeValidator {
    /// Genesis timestamp (Unix timestamp)
    genesis_timestamp: i64,
    /// Block time in seconds (testnet: 600, mainnet: 3600)
    block_time_seconds: i64,
    /// Whether this is testnet (affects block time)
    is_testnet: bool,
}

impl TimeValidator {
    /// Create a new time validator for testnet
    pub fn new_testnet() -> Self {
        Self {
            genesis_timestamp: GENESIS_TIMESTAMP,
            block_time_seconds: TESTNET_BLOCK_TIME_SECONDS,
            is_testnet: true,
        }
    }

    /// Create a new time validator for mainnet
    pub fn new_mainnet(genesis_timestamp: i64) -> Self {
        Self {
            genesis_timestamp,
            block_time_seconds: MAINNET_BLOCK_TIME_SECONDS,
            is_testnet: false,
        }
    }

    /// Calculate the expected maximum block height for current time
    ///
    /// Formula: blocks = (current_time - genesis_time) / block_time
    pub fn calculate_expected_height(&self, current_time: i64) -> Result<u64, TimeValidationError> {
        if current_time < self.genesis_timestamp {
            return Err(TimeValidationError::CalculationError(format!(
                "Current time {} is before genesis time {}",
                current_time, self.genesis_timestamp
            )));
        }

        let elapsed_seconds = current_time - self.genesis_timestamp;
        let blocks = elapsed_seconds / self.block_time_seconds;

        Ok(blocks as u64)
    }

    /// Calculate the minimum expected block height (with some tolerance for delays)
    ///
    /// Allows for network delays, consensus time, etc.
    /// Minimum is expected - 2 blocks to allow for reasonable variance
    pub fn calculate_minimum_height(&self, current_time: i64) -> Result<u64, TimeValidationError> {
        let expected = self.calculate_expected_height(current_time)?;

        // Allow up to 2 blocks behind before considering node out of sync
        Ok(expected.saturating_sub(2))
    }

    /// Validate that a block height is reasonable for the current time
    ///
    /// Returns Ok if the block height is within acceptable range
    pub fn validate_block_height(
        &self,
        block_height: u64,
        block_timestamp: i64,
    ) -> Result<(), TimeValidationError> {
        // Calculate max allowed height at this timestamp
        let max_allowed = self.calculate_expected_height(block_timestamp)?;

        // Check if block height exceeds maximum possible
        if block_height > max_allowed {
            return Err(TimeValidationError::TooManyBlocks {
                block_height,
                max_allowed,
            });
        }

        Ok(())
    }

    /// Check if node needs to enter catch-up mode
    ///
    /// Returns true if the local chain is significantly behind where it should be
    pub fn should_catch_up(
        &self,
        local_height: u64,
        current_time: i64,
    ) -> Result<bool, TimeValidationError> {
        let min_expected = self.calculate_minimum_height(current_time)?;

        Ok(local_height < min_expected)
    }

    /// Get catch-up information if node is behind
    pub fn get_catch_up_info(
        &self,
        local_height: u64,
        current_time: i64,
    ) -> Result<CatchUpInfo, TimeValidationError> {
        let expected = self.calculate_expected_height(current_time)?;
        let min_expected = self.calculate_minimum_height(current_time)?;

        let should_catch_up = local_height < min_expected;
        let blocks_behind = expected.saturating_sub(local_height);

        Ok(CatchUpInfo {
            local_height,
            expected_height: expected,
            minimum_height: min_expected,
            blocks_behind,
            should_catch_up,
            estimated_catch_up_time_seconds: blocks_behind * self.block_time_seconds as u64,
        })
    }

    /// Validate block timestamp is not in the future
    pub fn validate_block_timestamp(
        &self,
        block_timestamp: i64,
        current_time: i64,
    ) -> Result<(), TimeValidationError> {
        let time_diff = block_timestamp - current_time;

        if time_diff > MAX_FUTURE_BLOCK_SECONDS {
            return Err(TimeValidationError::FutureBlock {
                block_time: block_timestamp,
                current_time,
            });
        }

        Ok(())
    }

    /// Validate time between consecutive blocks
    pub fn validate_block_interval(
        &self,
        previous_timestamp: i64,
        current_timestamp: i64,
    ) -> Result<(), TimeValidationError> {
        let interval = current_timestamp - previous_timestamp;

        if interval < MIN_BLOCK_INTERVAL_SECONDS {
            return Err(TimeValidationError::BlockTooFast {
                time_since_previous: interval,
                minimum_required: MIN_BLOCK_INTERVAL_SECONDS,
            });
        }

        Ok(())
    }

    /// Check if a peer's claimed height is valid for current time
    ///
    /// Used to detect malicious peers claiming to have future blocks
    pub fn validate_peer_height(
        &self,
        peer_height: u64,
        current_time: i64,
    ) -> Result<(), TimeValidationError> {
        let max_allowed = self.calculate_expected_height(current_time)?;

        // Add 1 block tolerance for network propagation
        if peer_height > max_allowed + 1 {
            return Err(TimeValidationError::TooManyBlocks {
                block_height: peer_height,
                max_allowed,
            });
        }

        Ok(())
    }

    /// Validate system clock against network time
    ///
    /// Returns Ok if system clock is within acceptable drift
    pub fn validate_system_time(
        &self,
        local_time: i64,
        network_time: i64,
    ) -> Result<(), TimeValidationError> {
        let drift = (local_time - network_time).abs();

        if drift > MAX_TIME_DRIFT_SECONDS {
            return Err(TimeValidationError::ClockDrift {
                local_time,
                network_time,
                drift_seconds: drift,
            });
        }

        Ok(())
    }

    /// Get the block time for this validator
    pub fn block_time_seconds(&self) -> i64 {
        self.block_time_seconds
    }

    /// Get the genesis timestamp for this validator
    pub fn genesis_timestamp(&self) -> i64 {
        self.genesis_timestamp
    }

    /// Check if this is testnet
    pub fn is_testnet(&self) -> bool {
        self.is_testnet
    }
}

/// Information about catch-up status
#[derive(Debug, Clone)]
pub struct CatchUpInfo {
    /// Current local block height
    pub local_height: u64,
    /// Expected height based on current time
    pub expected_height: u64,
    /// Minimum acceptable height (with tolerance)
    pub minimum_height: u64,
    /// Number of blocks behind
    pub blocks_behind: u64,
    /// Whether node should enter catch-up mode
    pub should_catch_up: bool,
    /// Estimated time to catch up (seconds)
    pub estimated_catch_up_time_seconds: u64,
}

impl CatchUpInfo {
    /// Get human-readable catch-up status
    pub fn status_message(&self) -> String {
        if !self.should_catch_up {
            return "Node is in sync".to_string();
        }

        let hours = self.estimated_catch_up_time_seconds / 3600;
        let minutes = (self.estimated_catch_up_time_seconds % 3600) / 60;

        format!(
            "Node is {} blocks behind (expected: {}, current: {}). Estimated catch-up time: {}h {}m",
            self.blocks_behind,
            self.expected_height,
            self.local_height,
            hours,
            minutes
        )
    }
}

/// Get current Unix timestamp
pub fn current_timestamp() -> i64 {
    Utc::now().timestamp()
}

/// Convert DateTime to Unix timestamp
pub fn datetime_to_timestamp(dt: DateTime<Utc>) -> i64 {
    dt.timestamp()
}

/// Convert Unix timestamp to DateTime
pub fn timestamp_to_datetime(ts: i64) -> DateTime<Utc> {
    DateTime::from_timestamp(ts, 0).unwrap_or_else(Utc::now)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_expected_height_calculation() {
        let validator = TimeValidator::new_testnet();

        // Test: 1 hour after genesis (6 blocks at 10 min each)
        let one_hour_later = GENESIS_TIMESTAMP + 3600;
        let height = validator.calculate_expected_height(one_hour_later).unwrap();
        assert_eq!(height, 6);

        // Test: 1 day after genesis (144 blocks at 10 min each)
        let one_day_later = GENESIS_TIMESTAMP + 86400;
        let height = validator.calculate_expected_height(one_day_later).unwrap();
        assert_eq!(height, 144);
    }

    #[test]
    fn test_future_block_detection() {
        let validator = TimeValidator::new_testnet();
        let current_time = current_timestamp();
        let future_time = current_time + 300; // 5 minutes in future

        let result = validator.validate_block_timestamp(future_time, current_time);
        assert!(result.is_err());
    }

    #[test]
    fn test_block_interval_validation() {
        let validator = TimeValidator::new_testnet();
        let prev_time = GENESIS_TIMESTAMP;
        let curr_time = prev_time + 300; // Only 5 minutes later

        let result = validator.validate_block_interval(prev_time, curr_time);
        assert!(result.is_err()); // Should fail - too fast
    }

    #[test]
    fn test_catch_up_detection() {
        let validator = TimeValidator::new_testnet();
        let current_time = GENESIS_TIMESTAMP + 86400; // 1 day later

        // Should have ~144 blocks, but only have 50
        let should_catch_up = validator.should_catch_up(50, current_time).unwrap();
        assert!(should_catch_up);

        // At expected height
        let should_catch_up = validator.should_catch_up(144, current_time).unwrap();
        assert!(!should_catch_up);
    }

    #[test]
    fn test_too_many_blocks_detection() {
        let validator = TimeValidator::new_testnet();
        let current_time = GENESIS_TIMESTAMP + 3600; // 1 hour later

        // Should only have ~6 blocks, but claiming 100
        let result = validator.validate_block_height(100, current_time);
        assert!(result.is_err());

        // Valid height
        let result = validator.validate_block_height(6, current_time);
        assert!(result.is_ok());
    }
}
