//! VDF Integration for Block Creation and Validation
//!
//! This module provides helper functions to integrate VDF Proof-of-Time
//! into the block creation and validation pipeline.

use crate::block::{Block, BlockError};
use crate::vdf::{compute_vdf, generate_vdf_input, verify_vdf};
use std::time::Instant;

/// Configuration for VDF computation
#[derive(Debug, Clone)]
pub struct VDFConfig {
    /// Whether VDF is enabled (for gradual rollout)
    pub enabled: bool,
    /// Number of VDF iterations to perform
    pub iterations: u64,
    /// Minimum time (seconds) that must pass between blocks
    pub min_block_time_seconds: u64,
}

impl VDFConfig {
    /// Testnet configuration (10-min blocks, 2-min VDF)
    pub fn testnet() -> Self {
        Self {
            enabled: true,
            iterations: crate::vdf::TESTNET_TOTAL_ITERATIONS,
            min_block_time_seconds: crate::vdf::TESTNET_BLOCK_TIME_SECONDS,
        }
    }

    /// Mainnet configuration (1-hour blocks, 5-min VDF)
    pub fn mainnet() -> Self {
        Self {
            enabled: true,
            iterations: crate::vdf::MAINNET_TOTAL_ITERATIONS,
            min_block_time_seconds: crate::vdf::MAINNET_BLOCK_TIME_SECONDS,
        }
    }

    /// Disabled configuration (for testing or gradual rollout)
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            iterations: 0,
            min_block_time_seconds: 0,
        }
    }
}

impl Default for VDFConfig {
    fn default() -> Self {
        Self::testnet()
    }
}

/// Compute VDF proof for a block and attach it to the header
///
/// This should be called after the block is constructed but before finalization.
/// It computes the VDF proof based on block contents and attaches it to the header.
///
/// # Arguments
/// * `block` - The block to compute VDF for (will be modified in place)
/// * `config` - VDF configuration
///
/// # Returns
/// `Ok(())` if successful, error otherwise
///
/// # Example
/// ```ignore
/// let mut block = create_block(...);
/// let config = VDFConfig::testnet();
/// compute_block_vdf(&mut block, &config).await?;
/// // Block now has VDF proof attached
/// ```
pub async fn compute_block_vdf(block: &mut Block, config: &VDFConfig) -> Result<(), BlockError> {
    if !config.enabled {
        log::debug!("VDF disabled, skipping computation");
        return Ok(());
    }

    let start = Instant::now();

    // Generate VDF input from block data
    let vdf_input = generate_vdf_input(
        block.header.block_number,
        &block.header.previous_hash,
        &block.header.merkle_root,
        block.header.timestamp.timestamp_nanos_opt().unwrap_or(0),
    );

    log::info!(
        "⏱️  Computing Proof-of-Time for block {} ({} iterations, ~{} seconds)...",
        block.header.block_number,
        config.iterations,
        config.iterations / crate::vdf::DEFAULT_ITERATIONS_PER_SECOND
    );

    // Clone values needed in the blocking task
    let iterations = config.iterations;

    // Compute VDF proof (this is the slow, sequential operation)
    let vdf_proof = tokio::task::spawn_blocking(move || compute_vdf(&vdf_input, iterations))
        .await
        .map_err(|e| BlockError::VDFError(format!("Failed to spawn VDF task: {}", e)))?
        .map_err(|e| BlockError::VDFError(e.to_string()))?;

    let elapsed = start.elapsed();

    log::info!(
        "✅ Proof-of-Time computed in {:.2} seconds for block {}",
        elapsed.as_secs_f64(),
        block.header.block_number
    );

    // Attach VDF proof to block header
    block.header.proof_of_time = Some(vdf_proof);

    // Recalculate block hash since header changed
    block.hash = block.calculate_hash();

    Ok(())
}

/// Validate VDF proof in a block
///
/// Verifies that the block contains a valid VDF proof and that sufficient
/// time has passed since the previous block.
///
/// # Arguments
/// * `block` - The block to validate
/// * `previous_block` - The previous block in the chain
/// * `config` - VDF configuration
///
/// # Returns
/// `Ok(true)` if VDF is valid, error otherwise
pub async fn validate_block_vdf(
    block: &Block,
    previous_block: Option<&Block>,
    config: &VDFConfig,
) -> Result<bool, BlockError> {
    // If VDF is disabled, skip validation
    if !config.enabled {
        return Ok(true);
    }

    // Check if block has VDF proof
    let proof = match &block.header.proof_of_time {
        Some(proof) => proof,
        None => {
            // For backwards compatibility, allow blocks without VDF
            // but log a warning
            log::warn!(
                "Block {} missing VDF proof (backwards compatibility mode)",
                block.header.block_number
            );
            return Ok(true);
        }
    };

    // Verify minimum time has passed since previous block
    if let Some(prev) = previous_block {
        let time_diff = block
            .header
            .timestamp
            .signed_duration_since(prev.header.timestamp);

        if time_diff.num_seconds() < config.min_block_time_seconds as i64 {
            log::error!(
                "Block {} created too quickly: {} seconds (minimum: {})",
                block.header.block_number,
                time_diff.num_seconds(),
                config.min_block_time_seconds
            );
            return Err(BlockError::BlockTooFast);
        }
    }

    // Generate expected VDF input
    let vdf_input = generate_vdf_input(
        block.header.block_number,
        &block.header.previous_hash,
        &block.header.merkle_root,
        block.header.timestamp.timestamp_nanos_opt().unwrap_or(0),
    );

    log::debug!(
        "🔍 Verifying Proof-of-Time for block {}...",
        block.header.block_number
    );

    // Verify VDF proof (fast - takes ~1 second)
    let start = Instant::now();
    let vdf_input_clone = vdf_input.clone();
    let proof_clone = proof.clone();

    let is_valid = tokio::task::spawn_blocking(move || verify_vdf(&vdf_input_clone, &proof_clone))
        .await
        .map_err(|e| BlockError::VDFError(format!("Failed to spawn VDF verification: {}", e)))?
        .map_err(|e| BlockError::VDFError(e.to_string()))?;

    let elapsed = start.elapsed();

    if !is_valid {
        log::error!(
            "❌ Block {} has invalid Proof-of-Time!",
            block.header.block_number
        );
        return Err(BlockError::InvalidProofOfTime);
    }

    log::debug!(
        "✅ Block {} VDF valid (verified in {:.3}s, {} iterations)",
        block.header.block_number,
        elapsed.as_secs_f64(),
        proof.iterations
    );

    Ok(true)
}

/// Check if enough time has passed to create a new block
///
/// This helps prevent blocks from being created too quickly.
///
/// # Arguments
/// * `previous_block` - The previous block in the chain
/// * `config` - VDF configuration
///
/// # Returns
/// `Ok(true)` if enough time has passed, `Ok(false)` if should wait longer
pub fn can_create_block(previous_block: &Block, config: &VDFConfig) -> Result<bool, BlockError> {
    if !config.enabled {
        return Ok(true);
    }

    let time_since_prev = chrono::Utc::now().signed_duration_since(previous_block.header.timestamp);

    let can_create = time_since_prev.num_seconds() >= config.min_block_time_seconds as i64;

    if !can_create {
        let wait_time = config.min_block_time_seconds as i64 - time_since_prev.num_seconds();
        log::debug!(
            "Must wait {} more seconds before creating block (minimum {} seconds between blocks)",
            wait_time,
            config.min_block_time_seconds
        );
    }

    Ok(can_create)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::MasternodeCounts;
    use crate::BlockHeader;
    use chrono::Utc;

    fn create_test_block(number: u64, previous_hash: String) -> Block {
        Block {
            header: BlockHeader {
                block_number: number,
                timestamp: Utc::now(),
                previous_hash,
                merkle_root: format!("merkle_{}", number),
                validator_signature: "sig".to_string(),
                validator_address: "addr".to_string(),
                masternode_counts: MasternodeCounts::default(),
                proof_of_time: None,
                checkpoints: vec![],
            },
            transactions: vec![],
            hash: format!("hash_{}", number),
        }
    }

    #[tokio::test]
    async fn test_compute_block_vdf_disabled() {
        let mut block = create_test_block(1, "genesis".to_string());
        let config = VDFConfig::disabled();

        let result = compute_block_vdf(&mut block, &config).await;
        assert!(result.is_ok());
        assert!(block.header.proof_of_time.is_none());
    }

    #[tokio::test]
    async fn test_compute_block_vdf_enabled() {
        let mut block = create_test_block(1, "genesis".to_string());
        let config = VDFConfig {
            enabled: true,
            iterations: 1000, // Small for testing
            min_block_time_seconds: 10,
        };

        let result = compute_block_vdf(&mut block, &config).await;
        assert!(result.is_ok());
        assert!(block.header.proof_of_time.is_some());

        // Verify the proof is valid
        let validation = validate_block_vdf(&block, None, &config).await;
        assert!(validation.is_ok());
        assert!(validation.unwrap());
    }

    #[tokio::test]
    async fn test_validate_block_vdf_missing_proof() {
        let block = create_test_block(1, "genesis".to_string());
        let config = VDFConfig::testnet();

        // Block without VDF proof should pass (backwards compatibility)
        let result = validate_block_vdf(&block, None, &config).await;
        assert!(result.is_ok());
    }

    #[test]
    fn test_can_create_block() {
        let mut prev_block = create_test_block(1, "genesis".to_string());
        prev_block.header.timestamp = Utc::now() - chrono::Duration::minutes(11);

        let config = VDFConfig::testnet(); // 10-minute minimum

        let result = can_create_block(&prev_block, &config);
        assert!(result.is_ok());
        assert!(result.unwrap()); // Should be able to create (11 min > 10 min)
    }

    #[test]
    fn test_cannot_create_block_too_soon() {
        let mut prev_block = create_test_block(1, "genesis".to_string());
        prev_block.header.timestamp = Utc::now() - chrono::Duration::minutes(5);

        let config = VDFConfig::testnet(); // 10-minute minimum

        let result = can_create_block(&prev_block, &config);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Cannot create yet (5 min < 10 min)
    }
}
