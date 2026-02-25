//! Block finalization logic for TIME Coin

use crate::block::Block;
use crate::state::{BlockchainState, StateError};

use serde::{Deserialize, Serialize};

/// Finalizer handles block finalization after BFT consensus
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finalizer {
    /// Blocks awaiting finalization
    pending_blocks: Vec<Block>,
    /// Last finalized block height
    last_finalized_height: u64,
}

impl Finalizer {
    pub fn new() -> Self {
        Self {
            pending_blocks: Vec::new(),
            last_finalized_height: 0,
        }
    }

    /// Add a block pending finalization
    pub fn add_pending_block(&mut self, block: Block) {
        self.pending_blocks.push(block);
    }

    /// Finalize a block (after BFT consensus reached)
    pub fn finalize_block(
        &mut self,
        block_hash: &str,
        state: &mut BlockchainState,
    ) -> Result<(), StateError> {
        // Find the block in pending
        let block_index = self
            .pending_blocks
            .iter()
            .position(|b| b.hash == block_hash)
            .ok_or(StateError::BlockNotFound)?;

        let block = self.pending_blocks.remove(block_index);

        // Add to blockchain state
        state.add_block(block.clone())?;

        // Update last finalized height
        self.last_finalized_height = block.header.block_number;

        Ok(())
    }

    /// Get pending blocks
    pub fn pending_blocks(&self) -> &[Block] {
        &self.pending_blocks
    }

    /// Get last finalized height
    pub fn last_finalized_height(&self) -> u64 {
        self.last_finalized_height
    }

    /// Clear old pending blocks
    pub fn clear_old_pending(&mut self, max_height: u64) {
        self.pending_blocks
            .retain(|b| b.header.block_number >= max_height);
    }
}

impl Default for Finalizer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::TxOutput;

    #[test]
    fn test_finalizer_creation() {
        let finalizer = Finalizer::new();
        assert_eq!(finalizer.last_finalized_height(), 0);
        assert_eq!(finalizer.pending_blocks().len(), 0);
    }

    #[test]
    fn test_add_pending_block() {
        let mut finalizer = Finalizer::new();
        let outputs = vec![TxOutput::new(100_000_000_000, "test".to_string())];
        let counts = crate::block::MasternodeCounts {
            free: 0,
            bronze: 0,
            silver: 0,
            gold: 0,
        };
        let block = Block::new(
            1,
            "prev".to_string(),
            "validator".to_string(),
            outputs,
            &counts,
        );

        finalizer.add_pending_block(block);
        assert_eq!(finalizer.pending_blocks().len(), 1);
    }
}
