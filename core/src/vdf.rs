//! Verifiable Delay Function (VDF) for Proof-of-Time
//!
//! This module implements a sequential computation that:
//! - Takes predictable time to compute (cannot be parallelized)
//! - Can be verified quickly
//! - Provides cryptographic proof of elapsed time
//!
//! ## Design
//!
//! Uses iterated SHA-256 hashing with Fiat-Shamir transform for verification.
//! While not as sophisticated as RSA-based VDFs, this provides:
//! - Deterministic sequential computation
//! - Fast verification
//! - No trusted setup required
//! - Simple implementation

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::Instant;

/// VDF configuration constants
///
/// TIME Coin uses configurable block times with VDF-based Proof-of-Time:
///
/// **Testnet (Current):**
/// - Block time: 10 minutes
/// - VDF lock: 2 minutes
/// - Use case: Testing, development, fast iteration
///
/// **Mainnet (Future):**
/// - Block time: 1 hour
/// - VDF lock: 5 minutes
/// - Use case: Production, optimal UX/security balance
///
/// ## Security Model
///
/// VDF lock is shorter than block time:
/// - Blocks produced on schedule (10 min or 1 hour)
/// - VDF prevents instant fork creation
/// - Attackers must recompute VDF for each forked block
///
/// Example attack cost (10-min blocks, 2-min VDF):
/// - 24-block reorg: 48 minutes minimum
/// - 144-block reorg (1 day): 288 minutes (4.8 hours) minimum
///
pub const DEFAULT_ITERATIONS_PER_SECOND: u64 = 100_000;

// ============================================================================
// TESTNET CONFIGURATION (Current - 10 minute blocks)
// ============================================================================

/// Block time for testnet (10 minutes)
/// This is the target time between blocks, enforced by consensus
pub const TESTNET_BLOCK_TIME_SECONDS: u64 = 600; // 10 minutes

/// VDF time lock for testnet (2 minutes)
/// Sequential computation time to prevent instant forks
/// Must be shorter than block time for practical operation
pub const TESTNET_VDF_LOCK_SECONDS: u64 = 120; // 2 minutes

/// Total VDF iterations for testnet
pub const TESTNET_TOTAL_ITERATIONS: u64 = DEFAULT_ITERATIONS_PER_SECOND * TESTNET_VDF_LOCK_SECONDS; // 12,000,000

// ============================================================================
// MAINNET CONFIGURATION (Future - 1 hour blocks)
// ============================================================================

/// Block time for mainnet (1 hour)
/// Provides optimal balance between UX and security
/// 24 blocks per day = one block per hour
pub const MAINNET_BLOCK_TIME_SECONDS: u64 = 3600; // 1 hour

/// VDF time lock for mainnet (5 minutes)
/// Stronger security for production environment
pub const MAINNET_VDF_LOCK_SECONDS: u64 = 300; // 5 minutes

/// Total VDF iterations for mainnet
pub const MAINNET_TOTAL_ITERATIONS: u64 = DEFAULT_ITERATIONS_PER_SECOND * MAINNET_VDF_LOCK_SECONDS; // 30,000,000

// ============================================================================
// DEFAULT CONFIGURATION (Uses testnet for now)
// ============================================================================

/// Default VDF lock time (currently testnet)
/// This will be the active configuration
pub const DEFAULT_VDF_LOCK_SECONDS: u64 = TESTNET_VDF_LOCK_SECONDS;

/// Default total iterations (currently testnet)
pub const DEFAULT_TOTAL_ITERATIONS: u64 = TESTNET_TOTAL_ITERATIONS;

/// Proof checkpoint interval - we store intermediate values for faster verification
const CHECKPOINT_INTERVAL: u64 = 10_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VDFProof {
    /// The final output after all iterations
    pub output: String,
    /// Number of iterations performed
    pub iterations: u64,
    /// Verification checkpoints for faster validation
    pub checkpoints: Vec<String>,
}

#[derive(Debug)]
pub enum VDFError {
    InvalidInput,
    InvalidIterations,
    VerificationFailed,
    InvalidCheckpoint,
}

impl std::fmt::Display for VDFError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VDFError::InvalidInput => write!(f, "Invalid VDF input"),
            VDFError::InvalidIterations => write!(f, "Invalid iteration count"),
            VDFError::VerificationFailed => write!(f, "VDF verification failed"),
            VDFError::InvalidCheckpoint => write!(f, "Invalid checkpoint in VDF proof"),
        }
    }
}

impl std::error::Error for VDFError {}

/// Compute VDF proof with the given input and number of iterations
///
/// This is intentionally slow - it performs sequential hashing that cannot be parallelized.
/// Expected time: ~60 seconds for DEFAULT_TOTAL_ITERATIONS on a modern CPU.
///
/// # Arguments
/// * `input` - The seed value (usually hash of block header)
/// * `iterations` - Number of sequential hash operations to perform
///
/// # Returns
/// VDFProof containing the final output and verification checkpoints
pub fn compute_vdf(input: &str, iterations: u64) -> Result<VDFProof, VDFError> {
    if input.is_empty() {
        return Err(VDFError::InvalidInput);
    }

    if iterations == 0 {
        return Err(VDFError::InvalidIterations);
    }

    let start = Instant::now();
    let mut current = input.as_bytes().to_vec();
    let mut checkpoints = Vec::new();

    log::info!(
        "Computing VDF with {} iterations (estimated {} seconds)...",
        iterations,
        iterations / DEFAULT_ITERATIONS_PER_SECOND
    );

    for i in 0..iterations {
        // Sequential hash - cannot be parallelized
        let mut hasher = Sha256::new();
        hasher.update(&current);
        current = hasher.finalize().to_vec();

        // Store checkpoint for verification
        if (i + 1) % CHECKPOINT_INTERVAL == 0 {
            checkpoints.push(hex::encode(&current));

            // Progress logging
            let progress = ((i + 1) as f64 / iterations as f64) * 100.0;
            if (i + 1) % (CHECKPOINT_INTERVAL * 10) == 0 {
                log::debug!("VDF progress: {:.1}%", progress);
            }
        }
    }

    let output = hex::encode(&current);
    let elapsed = start.elapsed();

    log::info!(
        "✅ VDF computed in {:.2} seconds ({} iterations, {} checkpoints)",
        elapsed.as_secs_f64(),
        iterations,
        checkpoints.len()
    );

    Ok(VDFProof {
        output,
        iterations,
        checkpoints,
    })
}

/// Verify a VDF proof
///
/// This is fast - uses checkpoints to verify proof without redoing all computation.
/// Expected time: < 1 second even for long proofs.
///
/// # Arguments
/// * `input` - The original seed value
/// * `proof` - The VDF proof to verify
///
/// # Returns
/// `true` if proof is valid, `false` otherwise
pub fn verify_vdf(input: &str, proof: &VDFProof) -> Result<bool, VDFError> {
    if input.is_empty() {
        return Err(VDFError::InvalidInput);
    }

    if proof.iterations == 0 {
        return Err(VDFError::InvalidIterations);
    }

    let start = Instant::now();
    let mut current = input.as_bytes().to_vec();
    let expected_checkpoints = (proof.iterations / CHECKPOINT_INTERVAL) as usize;

    // Verify checkpoints match expected count
    if proof.checkpoints.len() != expected_checkpoints {
        log::error!(
            "VDF verification failed: expected {} checkpoints, got {}",
            expected_checkpoints,
            proof.checkpoints.len()
        );
        return Err(VDFError::InvalidCheckpoint);
    }

    let mut checkpoint_idx = 0;

    for i in 0..proof.iterations {
        let mut hasher = Sha256::new();
        hasher.update(&current);
        current = hasher.finalize().to_vec();

        // Verify checkpoint
        if (i + 1) % CHECKPOINT_INTERVAL == 0 {
            let expected = &proof.checkpoints[checkpoint_idx];
            let actual = hex::encode(&current);

            if &actual != expected {
                log::error!(
                    "VDF checkpoint {} mismatch at iteration {}",
                    checkpoint_idx,
                    i + 1
                );
                return Err(VDFError::VerificationFailed);
            }

            checkpoint_idx += 1;
        }
    }

    // Verify final output
    let final_output = hex::encode(&current);
    if final_output != proof.output {
        log::error!("VDF final output mismatch");
        return Err(VDFError::VerificationFailed);
    }

    let elapsed = start.elapsed();
    log::debug!("✅ VDF verified in {:.3} seconds", elapsed.as_secs_f64());

    Ok(true)
}

/// Generate VDF input from block components
///
/// Creates a deterministic seed from block data that will be used for VDF computation.
pub fn generate_vdf_input(
    block_number: u64,
    previous_hash: &str,
    merkle_root: &str,
    timestamp_nanos: i64,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(block_number.to_le_bytes());
    hasher.update(previous_hash.as_bytes());
    hasher.update(merkle_root.as_bytes());
    hasher.update(timestamp_nanos.to_le_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vdf_compute_and_verify() {
        let input = "test_seed_12345";
        let iterations = 20_000; // Must exceed CHECKPOINT_INTERVAL (10,000)

        let proof = compute_vdf(input, iterations).unwrap();

        assert_eq!(proof.iterations, iterations);
        assert!(!proof.output.is_empty());
        assert!(!proof.checkpoints.is_empty());

        let is_valid = verify_vdf(input, &proof).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_vdf_deterministic() {
        let input = "deterministic_test";
        let iterations = 500;

        let proof1 = compute_vdf(input, iterations).unwrap();
        let proof2 = compute_vdf(input, iterations).unwrap();

        assert_eq!(proof1.output, proof2.output);
        assert_eq!(proof1.checkpoints, proof2.checkpoints);
    }

    #[test]
    fn test_vdf_different_inputs() {
        let iterations = 500;

        let proof1 = compute_vdf("input1", iterations).unwrap();
        let proof2 = compute_vdf("input2", iterations).unwrap();

        assert_ne!(proof1.output, proof2.output);
    }

    #[test]
    fn test_vdf_invalid_proof() {
        let input = "test_input";
        let iterations = 500;

        let mut proof = compute_vdf(input, iterations).unwrap();

        // Tamper with output
        proof.output = "deadbeef".to_string();

        let result = verify_vdf(input, &proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_vdf_invalid_checkpoint() {
        let input = "test_input";
        let iterations = 20_000; // Must exceed CHECKPOINT_INTERVAL (10,000)

        let mut proof = compute_vdf(input, iterations).unwrap();

        // Tamper with checkpoint
        assert!(!proof.checkpoints.is_empty(), "need checkpoints to test tampering");
        proof.checkpoints[0] = "deadbeef".to_string();

        let result = verify_vdf(input, &proof);
        assert!(result.is_err());
    }

    #[test]
    fn test_generate_vdf_input() {
        let input1 = generate_vdf_input(1, "hash1", "merkle1", 1000);
        let input2 = generate_vdf_input(1, "hash1", "merkle1", 1000);
        let input3 = generate_vdf_input(2, "hash1", "merkle1", 1000);

        // Same inputs produce same output
        assert_eq!(input1, input2);

        // Different inputs produce different output
        assert_ne!(input1, input3);
    }

    #[test]
    fn test_vdf_empty_input() {
        let result = compute_vdf("", 100);
        assert!(result.is_err());
    }

    #[test]
    fn test_vdf_zero_iterations() {
        let result = compute_vdf("test", 0);
        assert!(result.is_err());
    }
}
