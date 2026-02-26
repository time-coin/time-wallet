//! 24-hour checkpoint system

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Checkpoint {
    pub block_number: u64,
    pub block_hash: String,
    pub timestamp: u64,
    pub state_root: String,
}

impl Checkpoint {
    pub fn new(block_number: u64, block_hash: String, state_root: String) -> Self {
        Self {
            block_number,
            block_hash,
            timestamp: current_timestamp(),
            state_root,
        }
    }

    pub fn is_checkpoint_block(block_number: u64) -> bool {
        // Checkpoint every 24 hours (17,280 blocks at 5 seconds)
        block_number.is_multiple_of(17_280)
    }
}

fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_checkpoint_detection() {
        assert!(Checkpoint::is_checkpoint_block(17_280));
        assert!(Checkpoint::is_checkpoint_block(34_560));
        assert!(!Checkpoint::is_checkpoint_block(1));
        assert!(!Checkpoint::is_checkpoint_block(100));
    }
}
