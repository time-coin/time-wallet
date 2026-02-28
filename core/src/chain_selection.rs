//! Chain selection and fork resolution for TIME Coin
//!
//! This module implements the logic for choosing between competing blockchain forks
//! using Proof-of-Time (VDF) for security.
//!
//! ## Fork Resolution Rules
//!
//! 1. **Find Common Ancestor**: Identify where chains diverged
//! 2. **Validate VDF Proofs**: Verify all blocks in competing chain have valid PoT
//! 3. **Calculate Cumulative Work**: Sum VDF iterations from fork point
//! 4. **Select Best Chain**: Choose chain with most time invested
//! 5. **Tie-Breaker**: If equal work, choose chain with lowest hash

use crate::block::{Block, BlockError};
use crate::vdf::{generate_vdf_input, verify_vdf, DEFAULT_ITERATIONS_PER_SECOND};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainSelection {
    /// Keep the local chain (it's better or equal)
    KeepLocal,
    /// Switch to the peer chain (it has more work)
    SwitchToPeer,
    /// Both chains are equal, no change needed
    Equal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForkInfo {
    /// Block height where chains diverged
    pub fork_height: u64,
    /// Number of blocks in local chain after fork
    pub local_blocks: usize,
    /// Number of blocks in peer chain after fork
    pub peer_blocks: usize,
    /// Cumulative VDF time in local chain (seconds)
    pub local_work: u64,
    /// Cumulative VDF time in peer chain (seconds)
    pub peer_work: u64,
    /// Whether peer chain has valid VDF proofs
    pub peer_chain_valid: bool,
}

#[derive(Debug)]
pub enum ChainError {
    InvalidVDFProof(String),
    InvalidBlock(BlockError),
    NoCommonAncestor,
    EmptyChain,
}

impl std::fmt::Display for ChainError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            ChainError::InvalidVDFProof(msg) => write!(f, "Invalid VDF proof: {}", msg),
            ChainError::InvalidBlock(e) => write!(f, "Invalid block: {}", e),
            ChainError::NoCommonAncestor => write!(f, "No common ancestor found"),
            ChainError::EmptyChain => write!(f, "Cannot process empty chain"),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<BlockError> for ChainError {
    fn from(err: BlockError) -> Self {
        ChainError::InvalidBlock(err)
    }
}

/// Find the fork point between two chains
///
/// Returns the index of the last common block (the common ancestor).
/// If chains have no common blocks, returns 0.
///
/// # Arguments
/// * `chain_a` - First chain to compare
/// * `chain_b` - Second chain to compare
///
/// # Returns
/// Index of the last common block
pub fn find_fork_point(chain_a: &[Block], chain_b: &[Block]) -> usize {
    if chain_a.is_empty() || chain_b.is_empty() {
        return 0;
    }

    let max_common = chain_a.len().min(chain_b.len());

    // Start from genesis and walk forward until chains diverge
    for i in 0..max_common {
        if chain_a[i].hash != chain_b[i].hash {
            // Found divergence point, return previous block as common ancestor
            if i == 0 {
                return 0; // Chains diverge at genesis (shouldn't happen)
            }
            return i - 1;
        }
    }

    // All compared blocks match, fork is at the end of shorter chain
    max_common - 1
}

/// Calculate cumulative VDF work (time invested) for a chain segment
///
/// Sums up all VDF iterations in the given blocks and converts to seconds.
///
/// # Arguments
/// * `blocks` - Chain segment to analyze
///
/// # Returns
/// Total time invested in seconds
pub fn calculate_cumulative_work(blocks: &[Block]) -> u64 {
    blocks
        .iter()
        .filter_map(|block| block.header.proof_of_time.as_ref())
        .map(|proof| proof.iterations / DEFAULT_ITERATIONS_PER_SECOND)
        .sum()
}

/// Validate VDF proofs for a chain segment
///
/// Verifies that each block has a valid Proof-of-Time VDF proof.
/// This is fast (~1ms per block) because VDF verification is efficient.
///
/// # Arguments
/// * `blocks` - Chain segment to validate (must include previous block for first block)
///
/// # Returns
/// `Ok(true)` if all proofs are valid, error otherwise
pub fn validate_chain_vdf_proofs(blocks: &[Block]) -> Result<bool, ChainError> {
    if blocks.is_empty() {
        return Err(ChainError::EmptyChain);
    }

    // Validate each block's VDF proof
    for i in 1..blocks.len() {
        let block = &blocks[i];
        let prev_block = &blocks[i - 1];

        if let Some(proof) = &block.header.proof_of_time {
            // Generate expected VDF input
            let vdf_input = generate_vdf_input(
                block.header.block_number,
                &prev_block.hash,
                &block.header.merkle_root,
                block.header.timestamp.timestamp_nanos_opt().unwrap_or(0),
            );

            // Verify proof
            match verify_vdf(&vdf_input, proof) {
                Ok(true) => {
                    log::debug!(
                        "✅ Block {} VDF valid ({} iterations)",
                        block.header.block_number,
                        proof.iterations
                    );
                }
                Ok(false) => {
                    log::error!(
                        "❌ Block {} VDF verification returned false",
                        block.header.block_number
                    );
                    return Err(ChainError::InvalidVDFProof(format!(
                        "Block {} VDF verification failed",
                        block.header.block_number
                    )));
                }
                Err(e) => {
                    log::error!(
                        "❌ Block {} VDF verification error: {}",
                        block.header.block_number,
                        e
                    );
                    return Err(ChainError::InvalidVDFProof(format!(
                        "Block {}: {}",
                        block.header.block_number, e
                    )));
                }
            }
        } else {
            log::warn!(
                "⚠️ Block {} missing VDF proof (backwards compatibility)",
                block.header.block_number
            );
            // For backwards compatibility, allow blocks without VDF
            // but they count as zero work
        }
    }

    Ok(true)
}

/// Select the best chain between local and peer chains
///
/// This is the main fork resolution algorithm. It:
/// 1. Finds where chains diverged
/// 2. Validates VDF proofs on peer chain
/// 3. Compares cumulative work
/// 4. Returns which chain should be used
///
/// # Arguments
/// * `local_chain` - The current local blockchain
/// * `peer_chain` - A competing chain from a peer
///
/// # Returns
/// Decision on which chain to use, along with fork information
pub fn select_best_chain(
    local_chain: &[Block],
    peer_chain: &[Block],
) -> Result<(ChainSelection, ForkInfo), ChainError> {
    if local_chain.is_empty() {
        return Err(ChainError::EmptyChain);
    }

    if peer_chain.is_empty() {
        return Err(ChainError::EmptyChain);
    }

    // Step 1: Find where chains diverged
    let fork_point = find_fork_point(local_chain, peer_chain);

    log::info!("🔀 Fork detected at block {}", fork_point);
    log::info!(
        "   Local chain: {} blocks total, {} after fork",
        local_chain.len(),
        local_chain.len() - fork_point - 1
    );
    log::info!(
        "   Peer chain:  {} blocks total, {} after fork",
        peer_chain.len(),
        peer_chain.len() - fork_point - 1
    );

    // Step 2: Validate VDF proofs on peer chain from fork point
    let peer_fork_segment = &peer_chain[fork_point..];

    log::info!("🔍 Validating {} peer blocks...", peer_fork_segment.len());

    let peer_chain_valid = match validate_chain_vdf_proofs(peer_fork_segment) {
        Ok(_) => {
            log::info!("✅ Peer chain VDF proofs are valid");
            true
        }
        Err(e) => {
            log::error!("❌ Peer chain has invalid VDF proofs: {}", e);
            false
        }
    };

    // If peer chain is invalid, keep local chain
    if !peer_chain_valid {
        let fork_info = ForkInfo {
            fork_height: fork_point as u64,
            local_blocks: local_chain.len() - fork_point - 1,
            peer_blocks: peer_chain.len() - fork_point - 1,
            local_work: 0,
            peer_work: 0,
            peer_chain_valid: false,
        };

        log::info!("📌 Keeping local chain (peer chain invalid)");
        return Ok((ChainSelection::KeepLocal, fork_info));
    }

    // Step 3: Calculate cumulative work for both chains from fork point
    let local_fork_segment = &local_chain[fork_point + 1..];
    let peer_fork_segment_after = &peer_chain[fork_point + 1..];

    let local_work = calculate_cumulative_work(local_fork_segment);
    let peer_work = calculate_cumulative_work(peer_fork_segment_after);

    log::info!("⚖️  Comparing cumulative work:");
    log::info!(
        "   Local: {} seconds ({} blocks)",
        local_work,
        local_fork_segment.len()
    );
    log::info!(
        "   Peer:  {} seconds ({} blocks)",
        peer_work,
        peer_fork_segment_after.len()
    );

    let fork_info = ForkInfo {
        fork_height: fork_point as u64,
        local_blocks: local_fork_segment.len(),
        peer_blocks: peer_fork_segment_after.len(),
        local_work,
        peer_work,
        peer_chain_valid: true,
    };

    // Step 4: Select chain with most cumulative work
    let selection = if peer_work > local_work {
        log::info!(
            "🔄 Switching to peer chain (+{} seconds more work)",
            peer_work - local_work
        );
        ChainSelection::SwitchToPeer
    } else if local_work > peer_work {
        log::info!(
            "📌 Keeping local chain (+{} seconds more work)",
            local_work - peer_work
        );
        ChainSelection::KeepLocal
    } else {
        // Tie-breaker: choose chain with lowest hash (deterministic)
        let local_tip_hash = &local_chain.last().unwrap().hash;
        let peer_tip_hash = &peer_chain.last().unwrap().hash;

        if peer_tip_hash < local_tip_hash {
            log::info!("🔄 Switching to peer chain (tie-breaker: lower hash)");
            ChainSelection::SwitchToPeer
        } else if local_tip_hash < peer_tip_hash {
            log::info!("📌 Keeping local chain (tie-breaker: lower hash)");
            ChainSelection::KeepLocal
        } else {
            log::info!("⚖️  Chains are identical");
            ChainSelection::Equal
        }
    };

    Ok((selection, fork_info))
}

/// Check if a reorg (chain reorganization) is safe
///
/// Determines if switching from local chain to peer chain would cause
/// an unacceptably deep reorganization.
///
/// # Arguments
/// * `fork_info` - Information about the fork
/// * `max_reorg_depth` - Maximum number of blocks to allow reorg
///
/// # Returns
/// `true` if reorg is within safe limits
pub fn is_reorg_safe(fork_info: &ForkInfo, max_reorg_depth: usize) -> bool {
    fork_info.local_blocks <= max_reorg_depth
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::block::{BlockHeader, MasternodeCounts};
    use crate::vdf::compute_vdf;
    use chrono::Utc;

    fn create_test_block(number: u64, previous_hash: String, with_vdf: bool) -> Block {
        let proof = if with_vdf {
            Some(compute_vdf(&format!("test_input_{}", number), 1000).unwrap())
        } else {
            None
        };

        let mut block = Block {
            header: BlockHeader {
                block_number: number,
                timestamp: Utc::now(),
                previous_hash,
                merkle_root: format!("merkle_{}", number),
                validator_signature: "sig".to_string(),
                validator_address: "addr".to_string(),
                masternode_counts: MasternodeCounts::default(),
                proof_of_time: proof,
                checkpoints: vec![],
            },
            transactions: vec![],
            hash: format!("hash_{}", number),
        };

        block.hash = format!("hash_{}_{}", number, block.header.merkle_root);
        block
    }

    #[test]
    fn test_find_fork_point_no_fork() {
        let chain_a = vec![
            create_test_block(0, "genesis".to_string(), false),
            create_test_block(1, "hash_0".to_string(), false),
            create_test_block(2, "hash_1".to_string(), false),
        ];

        let chain_b = chain_a.clone();

        let fork_point = find_fork_point(&chain_a, &chain_b);
        assert_eq!(fork_point, 2); // Last block is common
    }

    #[test]
    fn test_find_fork_point_with_fork() {
        let chain_a = vec![
            create_test_block(0, "genesis".to_string(), false),
            create_test_block(1, "hash_0".to_string(), false),
            create_test_block(2, "hash_1_a".to_string(), false),
        ];

        let mut chain_b = vec![
            chain_a[0].clone(),
            chain_a[1].clone(),
            create_test_block(2, "hash_1_b".to_string(), false),
        ];
        chain_b[2].hash = "different_hash".to_string();

        let fork_point = find_fork_point(&chain_a, &chain_b);
        assert_eq!(fork_point, 1); // Fork at block 2, so block 1 is common ancestor
    }

    #[test]
    fn test_calculate_cumulative_work() {
        let blocks = vec![
            create_test_block(0, "genesis".to_string(), true),
            create_test_block(1, "hash_0".to_string(), true),
            create_test_block(2, "hash_1".to_string(), true),
        ];

        let work = calculate_cumulative_work(&blocks);
        // Each block has 1000 iterations, so 3000 total
        // At 100,000 iterations/second, that's 0.03 seconds (rounds to 0)
        let _ = work; // verify it computed without panic
    }

    #[test]
    fn test_calculate_cumulative_work_no_vdf() {
        let blocks = vec![
            create_test_block(0, "genesis".to_string(), false),
            create_test_block(1, "hash_0".to_string(), false),
        ];

        let work = calculate_cumulative_work(&blocks);
        assert_eq!(work, 0); // No VDF proofs = no work
    }

    #[test]
    fn test_is_reorg_safe() {
        let fork_info = ForkInfo {
            fork_height: 100,
            local_blocks: 5,
            peer_blocks: 7,
            local_work: 300,
            peer_work: 420,
            peer_chain_valid: true,
        };

        assert!(is_reorg_safe(&fork_info, 10));
        assert!(is_reorg_safe(&fork_info, 5));
        assert!(!is_reorg_safe(&fork_info, 4));
    }
}
