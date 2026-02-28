//! Block structures and functionality for TIME Coin

use crate::transaction::{Transaction, TransactionError, TxOutput};
use crate::utxo_set::UTXOSet;
use crate::vdf::VDFProof;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone)]
pub enum BlockError {
    InvalidHash,
    InvalidMerkleRoot,
    InvalidTimestamp,
    InvalidBlockNumber,
    InvalidCoinbase,
    InvalidTransactions,
    TransactionError(TransactionError),
    NoTransactions,
    InvalidVDFInput,
    InvalidProofOfTime,
    BlockTooFast,
    VDFError(String),
}

impl std::fmt::Display for BlockError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            BlockError::InvalidHash => write!(f, "Invalid block hash"),
            BlockError::InvalidMerkleRoot => write!(f, "Invalid merkle root"),
            BlockError::InvalidTimestamp => write!(f, "Invalid timestamp"),
            BlockError::InvalidBlockNumber => write!(f, "Invalid block number"),
            BlockError::InvalidCoinbase => write!(f, "Invalid coinbase transaction"),
            BlockError::InvalidTransactions => write!(f, "Invalid transactions"),
            BlockError::TransactionError(e) => write!(f, "Transaction error: {}", e),
            BlockError::NoTransactions => write!(f, "Block has no transactions"),
            BlockError::InvalidVDFInput => write!(f, "Invalid VDF input"),
            BlockError::InvalidProofOfTime => write!(f, "Invalid Proof-of-Time"),
            BlockError::BlockTooFast => write!(f, "Block created too quickly"),
            BlockError::VDFError(e) => write!(f, "VDF error: {}", e),
        }
    }
}

impl std::error::Error for BlockError {}

impl From<TransactionError> for BlockError {
    fn from(err: TransactionError) -> Self {
        BlockError::TransactionError(err)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height/number
    pub block_number: u64,
    /// Timestamp when block was created
    pub timestamp: DateTime<Utc>,
    /// Hash of the previous block
    pub previous_hash: String,
    /// Merkle root of all transactions
    pub merkle_root: String,
    /// Validator/masternode signature
    pub validator_signature: String,
    /// Validator address
    pub validator_address: String,
    /// Masternode counts at time of block creation (for reward validation)
    /// Optional for backwards compatibility with blocks created before this field was added
    #[serde(default)]
    pub masternode_counts: MasternodeCounts,
    /// Proof-of-Time VDF proof (optional for backwards compatibility)
    #[serde(default)]
    pub proof_of_time: Option<VDFProof>,
    /// Checkpoints (finality markers) - optional, primarily for genesis
    #[serde(default)]
    pub checkpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block header
    pub header: BlockHeader,
    /// All transactions in the block (first one must be coinbase)
    pub transactions: Vec<Transaction>,
    /// Block hash
    pub hash: String,
}

/// Masternode tier definitions
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MasternodeTier {
    Free,
    Bronze,
    Silver,
    Gold,
}

impl MasternodeTier {
    /// Get the collateral requirement for this tier
    pub fn collateral_requirement(&self) -> u64 {
        const TIME_UNIT: u64 = 100_000_000;
        match self {
            MasternodeTier::Free => 0,
            MasternodeTier::Bronze => 1_000 * TIME_UNIT,
            MasternodeTier::Silver => 10_000 * TIME_UNIT,
            MasternodeTier::Gold => 100_000 * TIME_UNIT,
        }
    }

    /// Get the reward weight multiplier for this tier
    /// Check if this tier can vote in governance
    pub fn can_vote(&self) -> bool {
        match self {
            MasternodeTier::Free => false, // Free tier cannot vote
            _ => true,                     // All paid tiers can vote
        }
    }

    pub fn weight(&self) -> u64 {
        match self {
            MasternodeTier::Free => 1,
            MasternodeTier::Bronze => 10,  // 10x Free tier
            MasternodeTier::Silver => 100, // 10x Bronze tier
            MasternodeTier::Gold => 1000,  // 10x Silver tier
        }
    }

    /// Get voting power for governance (separate from reward weights)
    pub fn voting_power(&self) -> u64 {
        match self {
            MasternodeTier::Free => 0, // Cannot vote
            MasternodeTier::Bronze => 1,
            MasternodeTier::Silver => 10,
            MasternodeTier::Gold => 100,
        }
    }
}

/// Masternode count breakdown by tier
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MasternodeCounts {
    pub free: u64,
    pub bronze: u64,
    pub silver: u64,
    pub gold: u64,
}

impl MasternodeCounts {
    pub fn total(&self) -> u64 {
        self.free + self.bronze + self.silver + self.gold
    }

    pub fn total_weight(&self) -> u64 {
        (self.free * MasternodeTier::Free.weight())
            + (self.bronze * MasternodeTier::Bronze.weight())
            + (self.silver * MasternodeTier::Silver.weight())
            + (self.gold * MasternodeTier::Gold.weight())
    }
}

impl Block {
    /// Create a new block with a coinbase transaction
    pub fn new(
        block_number: u64,
        previous_hash: String,
        validator_address: String,
        coinbase_outputs: Vec<TxOutput>,
        masternode_counts: &MasternodeCounts,
    ) -> Self {
        // Create coinbase transaction (no inputs, generates new coins)
        let coinbase = Transaction {
            txid: format!("coinbase_{}", block_number),
            version: 1,
            inputs: vec![], // Coinbase has no inputs
            outputs: coinbase_outputs,
            lock_time: 0,
            timestamp: Utc::now().timestamp(),
        };

        let mut block = Block {
            header: BlockHeader {
                block_number,
                timestamp: Utc::now(),
                previous_hash,
                merkle_root: String::new(),
                validator_signature: String::new(),
                validator_address,
                masternode_counts: masternode_counts.clone(),
                proof_of_time: None,
                checkpoints: Vec::new(),
            },
            transactions: vec![coinbase],
            hash: String::new(),
        };

        // Calculate merkle root and hash
        block.header.merkle_root = block.calculate_merkle_root();
        block.hash = block.calculate_hash();

        block
    }

    /// Add a transaction to the block
    pub fn add_transaction(&mut self, tx: Transaction) -> Result<(), BlockError> {
        // Validate transaction structure
        tx.validate_structure()?;

        self.transactions.push(tx);
        self.header.merkle_root = self.calculate_merkle_root();
        self.hash = self.calculate_hash();

        Ok(())
    }

    /// Calculate the block hash (double SHA3-256)
    pub fn calculate_hash(&self) -> String {
        let mut hasher = Sha3_256::new();

        // Hash header data
        hasher.update(self.header.block_number.to_le_bytes());
        hasher.update(self.header.timestamp.to_rfc3339().as_bytes());
        hasher.update(self.header.previous_hash.as_bytes());
        hasher.update(self.header.merkle_root.as_bytes());
        hasher.update(self.header.validator_address.as_bytes());

        let hash1 = hasher.finalize();
        let hash2 = Sha3_256::digest(hash1);

        hex::encode(hash2)
    }

    /// Calculate merkle root of all transactions
    pub fn calculate_merkle_root(&self) -> String {
        if self.transactions.is_empty() {
            return "0".repeat(64);
        }

        let mut hashes: Vec<String> = self.transactions.iter().map(|tx| tx.txid.clone()).collect();

        // Build merkle tree
        while hashes.len() > 1 {
            let mut next_level = Vec::new();

            for i in (0..hashes.len()).step_by(2) {
                let left = &hashes[i];
                let right = if i + 1 < hashes.len() {
                    &hashes[i + 1]
                } else {
                    left // Duplicate if odd number
                };

                let combined = format!("{}{}", left, right);
                let hash = Sha3_256::digest(combined.as_bytes());
                next_level.push(hex::encode(hash));
            }

            hashes = next_level;
        }

        hashes[0].clone()
    }

    /// Get the coinbase transaction
    pub fn coinbase(&self) -> Option<&Transaction> {
        self.transactions.first()
    }

    /// Get all transactions except coinbase
    pub fn regular_transactions(&self) -> &[Transaction] {
        if self.transactions.len() > 1 {
            &self.transactions[1..]
        } else {
            &[]
        }
    }

    /// Validate block structure (not including transaction validation against UTXO)
    pub fn validate_structure(&self) -> Result<(), BlockError> {
        // Must have at least one transaction (coinbase)
        if self.transactions.is_empty() {
            return Err(BlockError::NoTransactions);
        }

        // First transaction must be coinbase
        if !self.transactions[0].is_coinbase() {
            return Err(BlockError::InvalidCoinbase);
        }

        // Only first transaction can be coinbase (treasury grants can appear anywhere)
        for tx in &self.transactions[1..] {
            if tx.is_coinbase() {
                return Err(BlockError::InvalidCoinbase);
            }
        }

        // Verify merkle root
        let calculated_merkle = self.calculate_merkle_root();
        if calculated_merkle != self.header.merkle_root {
            return Err(BlockError::InvalidMerkleRoot);
        }

        // Verify block hash
        let calculated_hash = self.calculate_hash();
        // Skip hash validation for genesis block
        if self.header.block_number == 0 {
            return Ok(());
        }
        if calculated_hash != self.hash {
            return Err(BlockError::InvalidHash);
        }

        // Validate all transaction structures
        for tx in &self.transactions {
            tx.validate_structure()?;
        }

        Ok(())
    }

    /// Validate block timestamp (SECURITY: prevents timestamp manipulation)
    ///
    /// Ensures:
    /// 1. Block timestamp is not too far in the future (prevents time-based attacks)
    /// 2. Block timestamp is monotonically increasing (must be > previous block)
    /// 3. Block timestamp is reasonable (not too far in the past) - UNLESS syncing historical chain
    ///
    /// # Arguments
    /// * `prev_block_timestamp` - Timestamp of previous block (for monotonic check)
    /// * `allow_historical` - If true, skip "too old" check (for syncing years-old chains)
    pub fn validate_timestamp(
        &self,
        prev_block_timestamp: Option<i64>,
        allow_historical: bool,
    ) -> Result<(), BlockError> {
        use crate::constants::{MAX_FUTURE_DRIFT_SECS, MAX_PAST_DRIFT_SECS};

        let now = Utc::now().timestamp();
        let block_time = self.header.timestamp.timestamp();

        // Check not too far in future (prevents miners creating future blocks)
        // ALWAYS enforce this - never accept future blocks
        if block_time > now + MAX_FUTURE_DRIFT_SECS {
            return Err(BlockError::InvalidTimestamp);
        }

        // Check not too far in past (prevents old blocks being accepted)
        // SKIP this check when syncing historical blockchain (allow_historical=true)
        if !allow_historical && block_time < now - MAX_PAST_DRIFT_SECS {
            return Err(BlockError::InvalidTimestamp);
        }

        // Check monotonic increase (blocks must have increasing timestamps)
        if let Some(prev_time) = prev_block_timestamp {
            if block_time <= prev_time {
                return Err(BlockError::InvalidTimestamp);
            }
        }

        Ok(())
    }

    /// Validate block against UTXO set and apply it
    /// Uses masternode counts stored in block header for reward validation
    pub fn validate_and_apply(&self, utxo_set: &mut UTXOSet) -> Result<(), BlockError> {
        // First validate structure
        self.validate_structure()?;

        // Use masternode counts from block header (stored when block was created)
        let masternode_counts = self.header.masternode_counts.clone();

        // For old blocks without masternode_counts (all zeros), skip strict validation
        // These are blocks created before the masternode_counts field was added
        let is_legacy_block = masternode_counts.free == 0
            && masternode_counts.bronze == 0
            && masternode_counts.silver == 0
            && masternode_counts.gold == 0;

        if is_legacy_block {
            eprintln!(
                "   ℹ️  Block {} is a legacy block (no masternode counts), using lenient validation",
                self.header.block_number
            );
            // For legacy blocks, we'll validate that coinbase exists and has reasonable structure
            // but won't validate the exact reward amounts
            let coinbase = self.coinbase().ok_or(BlockError::InvalidCoinbase)?;

            // Just verify coinbase has outputs
            if coinbase.outputs.is_empty() {
                return Err(BlockError::InvalidCoinbase);
            }

            // Apply transactions to UTXO set
            for tx in &self.transactions {
                utxo_set.apply_transaction(tx)?;
            }

            return Ok(());
        }

        // Calculate expected rewards including treasury allocation
        let base_masternode_reward = calculate_total_masternode_reward(&masternode_counts);

        // Validate coinbase reward
        let coinbase = self.coinbase().ok_or(BlockError::InvalidCoinbase)?;
        let coinbase_total: u64 = coinbase.outputs.iter().map(|o| o.amount).sum();

        // Calculate total fees from regular transactions (excluding treasury grants)
        let mut total_fees = 0u64;
        for tx in self.regular_transactions() {
            if !tx.is_treasury_grant() {
                let fee = tx.fee(utxo_set.utxos())?;
                total_fees += fee;
            }
        }

        // Total rewards = base masternode rewards + transaction fees
        // Coinbase should contain 100% of this (90% to masternodes + 10% to treasury)
        let total_rewards = base_masternode_reward + total_fees;
        let max_coinbase = total_rewards;

        if coinbase_total > max_coinbase {
            eprintln!(
                "❌ Coinbase validation failed for block {}: total {} exceeds max {}",
                self.header.block_number, coinbase_total, max_coinbase
            );
            eprintln!(
                "   Base reward: {}, Fees: {}",
                base_masternode_reward, total_fees
            );
            eprintln!(
                "   Masternode counts from block: free={}, bronze={}, silver={}, gold={}",
                masternode_counts.free,
                masternode_counts.bronze,
                masternode_counts.silver,
                masternode_counts.gold
            );
            return Err(BlockError::InvalidCoinbase);
        }

        // Verify treasury allocation is present and correct (10% of total)
        let expected_treasury = calculate_treasury_allocation(total_rewards);
        let treasury_output = coinbase.outputs.iter().find(|o| o.address == "TREASURY");

        if let Some(treasury_out) = treasury_output {
            if treasury_out.amount != expected_treasury {
                eprintln!(
                    "❌ Treasury allocation mismatch for block {}: got {}, expected {}",
                    self.header.block_number, treasury_out.amount, expected_treasury
                );
                eprintln!("   Total rewards: {}", total_rewards);
                return Err(BlockError::InvalidCoinbase);
            }
        } else if expected_treasury > 0 {
            eprintln!(
                "❌ Missing treasury output for block {} (expected {})",
                self.header.block_number, expected_treasury
            );
            // Treasury output must be present if there are rewards
            return Err(BlockError::InvalidCoinbase);
        }

        // Apply coinbase first
        utxo_set.apply_transaction(coinbase)?;

        // Validate and apply all regular transactions (including treasury grants)
        for tx in self.regular_transactions() {
            utxo_set.apply_transaction(tx)?;
        }

        Ok(())
    }

    /// Get total transaction fees in the block
    pub fn total_fees(&self, utxo_set: &UTXOSet) -> Result<u64, BlockError> {
        let mut total = 0u64;
        for tx in self.regular_transactions() {
            // Skip treasury grants as they don't have fees
            if !tx.is_treasury_grant() {
                let fee = tx.fee(utxo_set.utxos())?;
                total += fee;
            }
        }
        Ok(total)
    }

    /// Sign the block (for masternode validators)
    pub fn sign(&mut self, signature: String) {
        self.header.validator_signature = signature;
        // Note: Signature is not included in hash calculation
    }

    /// Get block size in bytes (approximate)
    pub fn size(&self) -> usize {
        serde_json::to_string(self).map(|s| s.len()).unwrap_or(0)
    }

    /// Get transaction count
    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

/// Treasury percentage of total block rewards and fees (10%)
pub const TREASURY_PERCENTAGE: u64 = 10;

/// Calculate treasury allocation from total rewards (block rewards + fees)
/// Returns 10% of the total amount
pub fn calculate_treasury_allocation(total_rewards: u64) -> u64 {
    (total_rewards * TREASURY_PERCENTAGE) / 100
}

/// Calculate total masternode reward pool using logarithmic scaling
/// Formula: BASE * ln(1 + total_masternodes / SCALE)
pub fn calculate_total_masternode_reward(counts: &MasternodeCounts) -> u64 {
    const TIME_UNIT: u64 = 100_000_000;
    const BASE_REWARD: f64 = 2000.0; // 95 TIME base
    const SCALE_FACTOR: f64 = 50.0; // Controls growth speed

    let total_nodes = counts.total() as f64;

    if total_nodes == 0.0 {
        return 0;
    }

    // Logarithmic scaling: BASE * ln(1 + count / SCALE)
    let multiplier = (1.0 + (total_nodes / SCALE_FACTOR)).ln();
    let reward = BASE_REWARD * multiplier * (TIME_UNIT as f64);

    reward as u64
}

/// Calculate reward for a specific masternode tier
pub fn calculate_tier_reward(tier: MasternodeTier, counts: &MasternodeCounts) -> u64 {
    let total_pool = calculate_total_masternode_reward(counts);
    let total_weight = counts.total_weight();

    if total_weight == 0 {
        return 0;
    }

    // Reward per weight unit
    let per_weight = total_pool / total_weight;

    // Multiply by tier weight
    per_weight * tier.weight()
}

/// Calculate total block reward including treasury allocation
/// Total rewards are split: 90% to masternodes, 10% to treasury
pub fn calculate_total_block_reward(
    masternode_counts: &MasternodeCounts,
    transaction_fees: u64,
) -> u64 {
    let masternodes = calculate_total_masternode_reward(masternode_counts);
    masternodes + transaction_fees
}

/// Calculate masternode share after treasury allocation (90% of total)
pub fn calculate_masternode_share(total_rewards: u64) -> u64 {
    total_rewards - calculate_treasury_allocation(total_rewards)
}

/// Distribute masternode rewards to all active masternodes
/// Returns a vector of TxOutput for the coinbase transaction
pub fn distribute_masternode_rewards(
    active_masternodes: &[(String, MasternodeTier)],
    counts: &MasternodeCounts,
) -> Vec<crate::transaction::TxOutput> {
    let mut outputs = Vec::new();

    // Calculate total pool
    let total_pool = calculate_total_masternode_reward(counts);
    let total_weight = counts.total_weight();

    if total_weight == 0 || active_masternodes.is_empty() {
        return outputs;
    }

    // Calculate reward per weight unit
    let per_weight = total_pool / total_weight;

    // Distribute to each masternode based on their tier weight
    for (address, tier) in active_masternodes {
        let reward = per_weight * tier.weight();
        if reward > 0 {
            outputs.push(crate::transaction::TxOutput::new(reward, address.clone()));
        }
    }

    outputs
}

/// Create a complete coinbase transaction with all block rewards
/// Splits rewards: 90% to masternodes, 10% to treasury
/// Uses block_timestamp to ensure deterministic transaction across all nodes
pub fn create_coinbase_transaction(
    block_number: u64,
    active_masternodes: &[(String, MasternodeTier)],
    counts: &MasternodeCounts,
    transaction_fees: u64,
    block_timestamp: i64, // Use block timestamp for determinism
) -> crate::transaction::Transaction {
    let mut outputs = Vec::new();

    // Calculate total rewards (masternode rewards + transaction fees)
    let base_masternode_rewards = calculate_total_masternode_reward(counts);
    let total_rewards = base_masternode_rewards + transaction_fees;

    // CRITICAL FIX: If no rewards at all, create minimum treasury output
    // This prevents empty coinbase transactions which fail validation
    if total_rewards == 0 {
        const MIN_TREASURY_OUTPUT: u64 = 1; // 1 satoshi minimum
        outputs.push(crate::transaction::TxOutput::new(
            MIN_TREASURY_OUTPUT,
            "TREASURY".to_string(),
        ));

        eprintln!(
            "⚠️  Block {} has no masternodes/fees - created minimal coinbase (1 satoshi to treasury)",
            block_number
        );

        return crate::transaction::Transaction {
            txid: format!("coinbase_{}", block_number),
            version: 1,
            inputs: vec![],
            outputs,
            lock_time: 0,
            timestamp: block_timestamp,
        };
    }

    // Calculate treasury allocation (10% of total rewards)
    let treasury_amount = calculate_treasury_allocation(total_rewards);

    // Calculate actual masternode share (90% of total rewards)
    let masternode_total = calculate_masternode_share(total_rewards);

    // CRITICAL FIX: Always add treasury output if we have rewards
    // This ensures coinbase is never empty even if masternode distribution fails
    if treasury_amount > 0 {
        outputs.push(crate::transaction::TxOutput::new(
            treasury_amount,
            "TREASURY".to_string(), // Special marker address for protocol-managed treasury
        ));
    }

    // Distribute masternode share proportionally based on tier weights
    let mut masternode_list: Vec<(String, MasternodeTier)> = active_masternodes.to_vec();
    masternode_list.sort_by(|a, b| a.0.cmp(&b.0)); // Sort by wallet address for determinism

    if !masternode_list.is_empty() && masternode_total > 0 {
        let total_weight = counts.total_weight();
        if total_weight > 0 {
            let per_weight = masternode_total / total_weight;

            // Distribute to each masternode based on their tier weight
            for (address, tier) in &masternode_list {
                let reward = per_weight * tier.weight();
                if reward > 0 {
                    outputs.push(crate::transaction::TxOutput::new(reward, address.clone()));
                }
            }
        } else {
            // CRITICAL FIX: No weight (all Free tier) but have rewards
            // Send entire masternode share to treasury
            eprintln!(
                "⚠️  Block {} has {} Free tier masternodes - sending full reward to treasury",
                block_number,
                masternode_list.len()
            );

            if let Some(treasury_output) = outputs.iter_mut().find(|o| o.address == "TREASURY") {
                treasury_output.amount = treasury_output.amount.saturating_add(masternode_total);
            } else {
                outputs.push(crate::transaction::TxOutput::new(
                    masternode_total,
                    "TREASURY".to_string(),
                ));
            }
        }
    } else if masternode_total > 0 {
        // CRITICAL FIX: No masternodes but have masternode rewards
        // Send entire masternode share to treasury
        eprintln!(
            "⚠️  Block {} has no masternodes - sending {} satoshis to treasury",
            block_number, masternode_total
        );

        if let Some(treasury_output) = outputs.iter_mut().find(|o| o.address == "TREASURY") {
            treasury_output.amount = treasury_output.amount.saturating_add(masternode_total);
        } else {
            outputs.push(crate::transaction::TxOutput::new(
                masternode_total,
                "TREASURY".to_string(),
            ));
        }
    }

    // FINAL SAFETY CHECK: Ensure we always have at least one output
    if outputs.is_empty() {
        panic!(
            "CRITICAL: Coinbase transaction would have 0 outputs! \
             block={}, masternodes={}, counts={:?}, fees={}",
            block_number,
            masternode_list.len(),
            counts,
            transaction_fees
        );
    }

    // Create coinbase transaction with DETERMINISTIC timestamp
    crate::transaction::Transaction {
        txid: format!("coinbase_{}", block_number), // This will be recalculated
        version: 1,
        inputs: vec![],
        outputs,
        lock_time: 0,
        timestamp: block_timestamp, // Use block timestamp for determinism!
    }
}

/// Create a deterministic reward-only block (no mempool transactions)
/// Uses a normalized timestamp (block_number * 86400) to ensure all nodes create identical blocks
/// This function is specifically designed for empty mempool scenarios to achieve instant consensus
pub fn create_reward_only_block(
    block_number: u64,
    previous_hash: String,
    validator_address: String,
    active_masternodes: &[(String, MasternodeTier)],
    counts: &MasternodeCounts,
) -> Block {
    // Use normalized timestamp based on block number (seconds since genesis)
    // This ensures ALL nodes create the exact same timestamp
    let normalized_timestamp = (block_number * 86400) as i64;

    // Sort masternodes by address for complete determinism
    let mut sorted_masternodes = active_masternodes.to_vec();
    sorted_masternodes.sort_by(|a, b| a.0.cmp(&b.0));

    // Create deterministic coinbase transaction (no treasury address needed)
    let coinbase_tx = create_coinbase_transaction(
        block_number,
        &sorted_masternodes,
        counts,
        0, // No transaction fees in reward-only block
        normalized_timestamp,
    );

    // Create normalized datetime from timestamp
    let datetime =
        chrono::DateTime::from_timestamp(normalized_timestamp, 0).unwrap_or_else(Utc::now);

    // Create block with deterministic values
    let mut block = Block {
        header: BlockHeader {
            block_number,
            timestamp: datetime,
            previous_hash,
            merkle_root: String::new(),
            validator_signature: String::new(),
            validator_address,
            masternode_counts: counts.clone(),
            proof_of_time: None,
            checkpoints: Vec::new(),
        },
        transactions: vec![coinbase_tx],
        hash: String::new(),
    };

    // Calculate merkle root and hash
    block.header.merkle_root = block.calculate_merkle_root();
    block.hash = block.calculate_hash();

    block
}

/// Create a treasury grant transaction for approved proposals
/// This transaction spends from the treasury state to a recipient address
pub fn create_treasury_grant_transaction(
    proposal_id: String,
    recipient: String,
    amount: u64,
    block_number: u64,
    timestamp: i64,
) -> crate::transaction::Transaction {
    // Treasury grant transaction has no inputs (like coinbase)
    // but is marked with a special txid format to identify it as a treasury grant
    crate::transaction::Transaction {
        txid: format!("treasury_grant_{}_{}", proposal_id, block_number),
        version: 1,
        inputs: vec![], // No inputs - funds come from protocol-managed treasury state
        outputs: vec![crate::transaction::TxOutput::new(amount, recipient)],
        lock_time: 0,
        timestamp,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_masternode_tier_collateral() {
        assert_eq!(MasternodeTier::Free.collateral_requirement(), 0);
        assert_eq!(
            MasternodeTier::Bronze.collateral_requirement(),
            1_000 * 100_000_000
        );
        assert_eq!(
            MasternodeTier::Silver.collateral_requirement(),
            10_000 * 100_000_000
        );
        assert_eq!(
            MasternodeTier::Gold.collateral_requirement(),
            100_000 * 100_000_000
        );
    }

    #[test]
    fn test_masternode_tier_weights() {
        // Reward weights scale by 10x per tier
        assert_eq!(MasternodeTier::Free.weight(), 1);
        assert_eq!(MasternodeTier::Bronze.weight(), 10);
        assert_eq!(MasternodeTier::Silver.weight(), 100);
        assert_eq!(MasternodeTier::Gold.weight(), 1000);
    }

    #[test]
    fn test_masternode_voting_power() {
        // Voting power is separate from reward weights
        assert_eq!(MasternodeTier::Free.voting_power(), 0);
        assert_eq!(MasternodeTier::Bronze.voting_power(), 1);
        assert_eq!(MasternodeTier::Silver.voting_power(), 10);
        assert_eq!(MasternodeTier::Gold.voting_power(), 100);
    }

    #[test]
    fn test_treasury_percentage() {
        // Treasury should be 10% of total rewards
        assert_eq!(TREASURY_PERCENTAGE, 10);

        // Test allocation calculation
        let total_rewards = 1000 * 100_000_000; // 1000 TIME
        let treasury_allocation = calculate_treasury_allocation(total_rewards);
        assert_eq!(treasury_allocation, 100 * 100_000_000); // 100 TIME (10%)

        let masternode_share = calculate_masternode_share(total_rewards);
        assert_eq!(masternode_share, 900 * 100_000_000); // 900 TIME (90%)

        // Verify they sum to total
        assert_eq!(treasury_allocation + masternode_share, total_rewards);
    }

    #[test]
    fn test_logarithmic_scaling() {
        let counts1 = MasternodeCounts {
            free: 100,
            bronze: 0,
            silver: 0,
            gold: 0,
        };
        let counts2 = MasternodeCounts {
            free: 500,
            bronze: 0,
            silver: 0,
            gold: 0,
        };
        let counts3 = MasternodeCounts {
            free: 1000,
            bronze: 0,
            silver: 0,
            gold: 0,
        };

        let reward1 = calculate_total_masternode_reward(&counts1);
        let reward2 = calculate_total_masternode_reward(&counts2);
        let reward3 = calculate_total_masternode_reward(&counts3);

        // Rewards should increase but with diminishing returns
        assert!(reward2 > reward1);
        assert!(reward3 > reward2);
        assert!(reward2 - reward1 > reward3 - reward2); // Diminishing returns
    }

    #[test]
    fn test_tier_reward_distribution() {
        let counts = MasternodeCounts {
            free: 100,
            bronze: 50,
            silver: 20,
            gold: 10,
        };

        let free_reward = calculate_tier_reward(MasternodeTier::Free, &counts);
        let bronze_reward = calculate_tier_reward(MasternodeTier::Bronze, &counts);
        let silver_reward = calculate_tier_reward(MasternodeTier::Silver, &counts);
        let gold_reward = calculate_tier_reward(MasternodeTier::Gold, &counts);

        // Higher tiers should get proportionally more
        assert!(bronze_reward > free_reward);
        assert!(silver_reward > bronze_reward);
        assert!(gold_reward > silver_reward);

        // Check proportions match weights (10x per tier)
        assert_eq!(bronze_reward / free_reward, 10); // 10x weight
        assert_eq!(silver_reward / free_reward, 100); // 100x weight
        assert_eq!(gold_reward / free_reward, 1000); // 1000x weight
    }

    #[test]
    fn test_block_creation() {
        let outputs = vec![TxOutput::new(
            10_000_000_000,
            "validator_address".to_string(),
        )];
        let counts = MasternodeCounts {
            free: 0,
            bronze: 0,
            silver: 0,
            gold: 0,
        };
        let block = Block::new(
            1,
            "previous_hash".to_string(),
            "validator".to_string(),
            outputs,
            &counts,
        );

        assert_eq!(block.header.block_number, 1);
        assert_eq!(block.transactions.len(), 1);
        assert!(block.transactions[0].is_coinbase());
        assert!(!block.hash.is_empty());
    }
    #[test]
    fn test_tier_economics() {
        use super::*;
        const TIME_UNIT: u64 = 100_000_000;

        // Test different network scenarios
        let scenarios = vec![
            (
                "Early network",
                MasternodeCounts {
                    free: 50,
                    bronze: 10,
                    silver: 3,
                    gold: 1,
                },
            ),
            (
                "Growing network",
                MasternodeCounts {
                    free: 200,
                    bronze: 50,
                    silver: 20,
                    gold: 10,
                },
            ),
            (
                "Mature network",
                MasternodeCounts {
                    free: 1000,
                    bronze: 200,
                    silver: 50,
                    gold: 20,
                },
            ),
        ];

        for (name, counts) in scenarios {
            println!("\n{}: {} total nodes", name, counts.total());
            println!(
                "Total pool: {} TIME",
                calculate_total_masternode_reward(&counts) / TIME_UNIT
            );

            let free_reward = calculate_tier_reward(MasternodeTier::Free, &counts);
            let bronze_reward = calculate_tier_reward(MasternodeTier::Bronze, &counts);
            let silver_reward = calculate_tier_reward(MasternodeTier::Silver, &counts);
            let gold_reward = calculate_tier_reward(MasternodeTier::Gold, &counts);

            println!(
                "  Free:   {:.2} TIME/day",
                free_reward as f64 / TIME_UNIT as f64
            );
            println!(
                "  Bronze: {:.2} TIME/day (APY: {}%)",
                bronze_reward as f64 / TIME_UNIT as f64,
                (bronze_reward * 365 / TIME_UNIT / 1000)
            );
            println!(
                "  Silver: {:.2} TIME/day (APY: {}%)",
                silver_reward as f64 / TIME_UNIT as f64,
                (silver_reward * 365 / TIME_UNIT / 10000)
            );
            println!(
                "  Gold:   {:.2} TIME/day (APY: {}%)",
                gold_reward as f64 / TIME_UNIT as f64,
                (gold_reward * 365 / TIME_UNIT / 100000)
            );
        }
    }
    #[test]
    fn test_distribute_masternode_rewards() {
        let masternodes = vec![
            ("addr1".to_string(), MasternodeTier::Free),
            ("addr2".to_string(), MasternodeTier::Free),
            ("addr3".to_string(), MasternodeTier::Bronze),
            ("addr4".to_string(), MasternodeTier::Silver),
            ("addr5".to_string(), MasternodeTier::Gold),
        ];

        let counts = MasternodeCounts {
            free: 2,
            bronze: 1,
            silver: 1,
            gold: 1,
        };

        let outputs = distribute_masternode_rewards(&masternodes, &counts);

        // Should have 5 outputs (one per masternode)
        assert_eq!(outputs.len(), 5);

        // Calculate expected values with 10x scaling weights
        let total_pool = calculate_total_masternode_reward(&counts);
        let total_weight = counts.total_weight(); // 2*1 + 1*10 + 1*100 + 1*1000 = 1,112
        let per_weight = total_pool / total_weight;

        // Verify each tier gets correct reward (10x per tier)
        assert_eq!(outputs[0].amount, per_weight); // Free
        assert_eq!(outputs[1].amount, per_weight); // Free
        assert_eq!(outputs[2].amount, per_weight * 10); // Bronze
        assert_eq!(outputs[3].amount, per_weight * 100); // Silver
        assert_eq!(outputs[4].amount, per_weight * 1000); // Gold
    }

    #[test]
    fn test_create_coinbase_transaction() {
        let masternodes = vec![
            ("masternode1".to_string(), MasternodeTier::Bronze),
            ("masternode2".to_string(), MasternodeTier::Silver),
        ];

        let counts = MasternodeCounts {
            free: 0,
            bronze: 1,
            silver: 1,
            gold: 0,
        };

        let block_timestamp = 1700000000; // Fixed timestamp for testing
        let transaction_fees = 50_000_000; // 0.5 TIME in fees
        let tx = create_coinbase_transaction(
            100,
            &masternodes,
            &counts,
            transaction_fees,
            block_timestamp,
        );

        // Verify it's a coinbase
        assert!(tx.is_coinbase());

        // Calculate expected values
        let base_rewards = calculate_total_masternode_reward(&counts);
        let total_rewards = base_rewards + transaction_fees;
        let expected_treasury = calculate_treasury_allocation(total_rewards);
        let expected_masternode_share = calculate_masternode_share(total_rewards);

        // Should have: 1 treasury output + 2 masternode outputs = 3 outputs
        assert_eq!(tx.outputs.len(), 3);

        // First output should be treasury marker
        assert_eq!(tx.outputs[0].address, "TREASURY");
        assert_eq!(tx.outputs[0].amount, expected_treasury);

        // Remaining outputs are for masternodes (10x scaling weights)
        let total_weight = counts.total_weight(); // 1*10 + 1*100 = 110
        let per_weight = expected_masternode_share / total_weight;

        // Masternodes sorted by address: masternode1, masternode2
        assert_eq!(tx.outputs[1].address, "masternode1");
        assert_eq!(tx.outputs[1].amount, per_weight * 10); // Bronze weight

        assert_eq!(tx.outputs[2].address, "masternode2");
        assert_eq!(tx.outputs[2].amount, per_weight * 100); // Silver weight

        // Verify total adds up (within rounding tolerance)
        let total: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        assert!(total <= total_rewards);
        assert!(total_rewards - total < 100); // Small rounding loss acceptable
    }

    #[test]
    fn test_create_treasury_grant_transaction() {
        let proposal_id = "prop-001".to_string();
        let recipient = "time1recipient_address".to_string();
        let amount = 10_000 * 100_000_000; // 10,000 TIME
        let block_number = 12345;
        let timestamp = 1700000000;

        let tx = create_treasury_grant_transaction(
            proposal_id.clone(),
            recipient.clone(),
            amount,
            block_number,
            timestamp,
        );

        // Verify it's a treasury grant (no inputs but not a coinbase)
        assert!(tx.is_treasury_grant());
        assert!(!tx.is_coinbase());
        assert_eq!(tx.inputs.len(), 0);

        // Verify txid format
        assert_eq!(
            tx.txid,
            format!("treasury_grant_{}_{}", proposal_id, block_number)
        );

        // Verify single output to recipient
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.outputs[0].address, recipient);
        assert_eq!(tx.outputs[0].amount, amount);

        // Verify timestamp
        assert_eq!(tx.timestamp, timestamp);
    }

    #[test]
    fn test_reward_scaling_with_growth() {
        // Test that rewards scale logarithmically
        let scenarios = vec![
            (
                10,
                MasternodeCounts {
                    free: 10,
                    bronze: 0,
                    silver: 0,
                    gold: 0,
                },
            ),
            (
                100,
                MasternodeCounts {
                    free: 100,
                    bronze: 0,
                    silver: 0,
                    gold: 0,
                },
            ),
            (
                1000,
                MasternodeCounts {
                    free: 1000,
                    bronze: 0,
                    silver: 0,
                    gold: 0,
                },
            ),
        ];

        for (count, counts) in &scenarios {
            let total = calculate_total_masternode_reward(counts);
            println!("{} masternodes: {} TIME total", count, total / 100_000_000);
        }

        // Verify logarithmic growth (not linear)
        let pool_10 = calculate_total_masternode_reward(&scenarios[0].1);
        let pool_100 = calculate_total_masternode_reward(&scenarios[1].1);
        let pool_1000 = calculate_total_masternode_reward(&scenarios[2].1);

        // 10x increase in nodes should NOT be 10x increase in rewards
        assert!(pool_100 < pool_10 * 10);
        assert!(pool_1000 < pool_100 * 10);
    }

    #[test]
    fn test_create_reward_only_block_deterministic() {
        // Test that create_reward_only_block produces identical blocks
        let block_number = 100;
        let previous_hash = "test_prev_hash".to_string();
        let validator_address = "validator1".to_string();

        let active_masternodes = vec![
            ("wallet_a".to_string(), MasternodeTier::Bronze),
            ("wallet_b".to_string(), MasternodeTier::Gold),
            ("wallet_c".to_string(), MasternodeTier::Silver),
        ];

        let counts = MasternodeCounts {
            free: 10,
            bronze: 5,
            silver: 3,
            gold: 2,
        };

        // Create block twice with same inputs
        let block1 = create_reward_only_block(
            block_number,
            previous_hash.clone(),
            validator_address.clone(),
            &active_masternodes,
            &counts,
        );

        let block2 = create_reward_only_block(
            block_number,
            previous_hash.clone(),
            validator_address.clone(),
            &active_masternodes,
            &counts,
        );

        // Blocks should be identical
        assert_eq!(block1.hash, block2.hash);
        assert_eq!(block1.header.merkle_root, block2.header.merkle_root);
        assert_eq!(block1.header.timestamp, block2.header.timestamp);
        assert_eq!(block1.transactions.len(), 1); // Only coinbase
        assert!(block1.transactions[0].is_coinbase());

        // Verify normalized timestamp
        let expected_timestamp = (block_number * 86400) as i64;
        assert_eq!(block1.transactions[0].timestamp, expected_timestamp);
    }

    #[test]
    fn test_reward_only_block_different_order() {
        // Test that masternode order doesn't affect the final block
        let block_number = 100;
        let previous_hash = "test_prev_hash".to_string();
        let validator_address = "validator1".to_string();

        // Same masternodes in different order
        let masternodes1 = vec![
            ("wallet_a".to_string(), MasternodeTier::Bronze),
            ("wallet_b".to_string(), MasternodeTier::Gold),
            ("wallet_c".to_string(), MasternodeTier::Silver),
        ];

        let masternodes2 = vec![
            ("wallet_c".to_string(), MasternodeTier::Silver),
            ("wallet_a".to_string(), MasternodeTier::Bronze),
            ("wallet_b".to_string(), MasternodeTier::Gold),
        ];

        let counts = MasternodeCounts {
            free: 10,
            bronze: 5,
            silver: 3,
            gold: 2,
        };

        let block1 = create_reward_only_block(
            block_number,
            previous_hash.clone(),
            validator_address.clone(),
            &masternodes1,
            &counts,
        );

        let block2 = create_reward_only_block(
            block_number,
            previous_hash.clone(),
            validator_address.clone(),
            &masternodes2,
            &counts,
        );

        // Blocks should be identical despite different input order
        assert_eq!(block1.hash, block2.hash);
        assert_eq!(block1.header.merkle_root, block2.header.merkle_root);
    }

    #[test]
    fn test_coinbase_with_treasury_split() {
        // Test that coinbase properly splits rewards: 90% masternodes, 10% treasury
        let masternodes = vec![
            ("addr1".to_string(), MasternodeTier::Bronze),
            ("addr2".to_string(), MasternodeTier::Bronze),
        ];

        let counts = MasternodeCounts {
            free: 0,
            bronze: 2,
            silver: 0,
            gold: 0,
        };

        let transaction_fees = 100_000_000; // 1 TIME in fees
        let block_timestamp = 1700000000;

        let tx = create_coinbase_transaction(
            200,
            &masternodes,
            &counts,
            transaction_fees,
            block_timestamp,
        );

        // Calculate expected allocations
        let base_rewards = calculate_total_masternode_reward(&counts);
        let total_rewards = base_rewards + transaction_fees;
        let treasury_amount = calculate_treasury_allocation(total_rewards);
        let masternode_amount = calculate_masternode_share(total_rewards);

        // Verify treasury allocation is 10%
        assert_eq!(treasury_amount, total_rewards / 10);

        // Verify masternode share is 90%
        assert_eq!(masternode_amount, (total_rewards * 9) / 10);

        // Verify coinbase outputs
        assert_eq!(tx.outputs[0].address, "TREASURY");
        assert_eq!(tx.outputs[0].amount, treasury_amount);

        // Sum masternode outputs
        let masternode_total: u64 = tx.outputs[1..].iter().map(|o| o.amount).sum();

        // Due to integer division when distributing to masternodes,
        // the actual total may be slightly less than the share (rounding loss)
        assert!(masternode_total <= masternode_amount);
        assert!(masternode_amount - masternode_total < 100); // Loss should be minimal

        // Verify total distributed is close to total rewards (within rounding tolerance)
        let all_outputs: u64 = tx.outputs.iter().map(|o| o.amount).sum();
        assert!(all_outputs <= total_rewards);
        assert!(total_rewards - all_outputs < 100); // Small rounding loss acceptable
    }

    #[test]
    fn test_genesis_block_hash() {
        use crate::transaction::TxOutput;

        // Create the exact genesis block as specified
        let timestamp = 1760227200i64;
        let datetime = chrono::DateTime::from_timestamp(timestamp, 0).expect("Valid timestamp");

        let amount = 11653781624u64;

        let coinbase = crate::transaction::Transaction {
            txid: "coinbase_0".to_string(),
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput::new(amount, "genesis".to_string())],
            lock_time: 0,
            timestamp,
        };

        let mut block = Block {
            header: BlockHeader {
                block_number: 0,
                timestamp: datetime,
                previous_hash: "0000000000000000000000000000000000000000000000000000000000000000"
                    .to_string(),
                merkle_root: String::new(),
                validator_signature: "genesis".to_string(),
                validator_address: "genesis".to_string(),
                masternode_counts: MasternodeCounts {
                    free: 0,
                    bronze: 0,
                    silver: 0,
                    gold: 0,
                },
                proof_of_time: None,
                checkpoints: vec![],
            },
            transactions: vec![coinbase],
            hash: String::new(),
        };

        // Calculate merkle root and hash
        block.header.merkle_root = block.calculate_merkle_root();
        block.hash = block.calculate_hash();

        println!("\n=== Genesis Block ===");
        println!("Block Number: {}", block.header.block_number);
        println!("Timestamp: {}", block.header.timestamp);
        println!("Previous Hash: {}", block.header.previous_hash);
        println!("Merkle Root: {}", block.header.merkle_root);
        println!("Validator: {}", block.header.validator_address);
        println!("Hash: {}", block.hash);
        println!("=====================\n");

        // Verify structure
        assert_eq!(block.header.block_number, 0);
        assert_eq!(block.transactions.len(), 1);
        assert!(block.transactions[0].is_coinbase());
    }

    #[test]
    fn test_coinbase_zero_masternodes() {
        // CRITICAL: Test that coinbase works with NO masternodes
        let masternodes = vec![];
        let counts = MasternodeCounts::default(); // All zeros

        let tx = create_coinbase_transaction(100, &masternodes, &counts, 0, 1234567890);

        // Should have at least 1 output
        assert!(!tx.outputs.is_empty(), "Coinbase must have outputs");

        // Should be treasury output
        assert_eq!(tx.outputs[0].address, "TREASURY");
        assert!(tx.outputs[0].amount > 0, "Treasury output must be > 0");

        // Should be minimal (1 satoshi)
        assert_eq!(tx.outputs[0].amount, 1);
    }

    #[test]
    fn test_coinbase_only_free_tier() {
        // Test that coinbase works with only Free tier masternodes
        let masternodes = vec![
            ("addr1".to_string(), MasternodeTier::Free),
            ("addr2".to_string(), MasternodeTier::Free),
        ];
        let counts = MasternodeCounts {
            free: 2,
            bronze: 0,
            silver: 0,
            gold: 0,
        };

        let tx = create_coinbase_transaction(100, &masternodes, &counts, 0, 1234567890);

        // Should have treasury output + masternode outputs
        assert!(!tx.outputs.is_empty());
        assert!(tx.outputs.iter().any(|o| o.address == "TREASURY"));

        // Free tier has weight 1, so masternodes should receive rewards
        let total_rewards = calculate_total_masternode_reward(&counts);
        assert!(total_rewards > 0);

        let treasury_total: u64 = tx
            .outputs
            .iter()
            .filter(|o| o.address == "TREASURY")
            .map(|o| o.amount)
            .sum();

        // Treasury gets 10% of total rewards
        assert_eq!(treasury_total, calculate_treasury_allocation(total_rewards));

        // Each Free masternode should get a share of the remaining 90%
        let masternode_outputs: Vec<_> = tx
            .outputs
            .iter()
            .filter(|o| o.address != "TREASURY")
            .collect();
        assert_eq!(masternode_outputs.len(), 2);
    }

    #[test]
    fn test_coinbase_no_masternodes_with_fees() {
        // Test that fees are properly allocated when no masternodes exist
        let masternodes = vec![];
        let counts = MasternodeCounts::default();
        let fees = 100_000_000; // 1 TIME in fees

        let tx = create_coinbase_transaction(100, &masternodes, &counts, fees, 1234567890);

        // Should have treasury output with full fees (10% of fees as treasury, 90% also to treasury since no masternodes)
        assert!(!tx.outputs.is_empty());
        assert_eq!(tx.outputs[0].address, "TREASURY");

        // Treasury should get 100% of fees (10% normal + 90% from unused masternode share)
        assert_eq!(tx.outputs[0].amount, fees);
    }

    #[test]
    fn test_coinbase_normal_operation_regression() {
        // Regression test: Ensure normal operation still works correctly
        let masternodes = vec![
            ("addr1".to_string(), MasternodeTier::Bronze),
            ("addr2".to_string(), MasternodeTier::Silver),
        ];
        let counts = MasternodeCounts {
            free: 0,
            bronze: 1,
            silver: 1,
            gold: 0,
        };

        let tx = create_coinbase_transaction(100, &masternodes, &counts, 50_000_000, 1234567890);

        // Should have treasury + 2 masternode outputs = 3 total
        assert_eq!(tx.outputs.len(), 3);

        // All outputs must have amount > 0
        for output in &tx.outputs {
            assert!(output.amount > 0, "Output amount must be > 0");
        }

        // First should be treasury
        assert_eq!(tx.outputs[0].address, "TREASURY");
    }
}
