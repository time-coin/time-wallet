//! UTXO-based transaction model for TIME Coin

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fmt;

#[derive(Debug, Clone)]
pub enum TransactionError {
    InvalidAmount,
    InvalidSignature,
    InvalidInput,
    InsufficientFunds,
    DuplicateInput,
    InvalidOutputIndex,
    SerializationError,
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TransactionError::InvalidAmount => write!(f, "Invalid transaction amount"),
            TransactionError::InvalidSignature => write!(f, "Invalid signature"),
            TransactionError::InvalidInput => write!(f, "Invalid transaction input"),
            TransactionError::InsufficientFunds => write!(f, "Insufficient funds"),
            TransactionError::DuplicateInput => write!(f, "Duplicate input detected"),
            TransactionError::InvalidOutputIndex => write!(f, "Invalid output index"),
            TransactionError::SerializationError => write!(f, "Serialization error"),
        }
    }
}

impl std::error::Error for TransactionError {}

/// Reference to a previous transaction output (UTXO)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutPoint {
    /// Transaction ID being spent
    pub txid: String,
    /// Output index in the transaction
    pub vout: u32,
}

impl OutPoint {
    pub fn new(txid: String, vout: u32) -> Self {
        Self { txid, vout }
    }
}

/// Transaction input spending a UTXO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    /// Reference to the UTXO being spent
    pub previous_output: OutPoint,
    /// Public key of the spender
    pub public_key: Vec<u8>,
    /// Signature proving ownership
    pub signature: Vec<u8>,
    /// Sequence number (for future use with timelocks)
    pub sequence: u32,
}

impl TxInput {
    pub fn new(txid: String, vout: u32, public_key: Vec<u8>, signature: Vec<u8>) -> Self {
        Self {
            previous_output: OutPoint::new(txid, vout),
            public_key,
            signature,
            sequence: 0xFFFFFFFF, // Default: no timelock
        }
    }
}

/// Transaction output creating a new UTXO
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    /// Amount in the smallest unit (satoshi equivalent)
    pub amount: u64,
    /// Address that can spend this output
    pub address: String,
}

impl TxOutput {
    pub fn new(amount: u64, address: String) -> Self {
        Self { amount, address }
    }
}

/// Complete UTXO-based transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Transaction ID (hash of the transaction)
    pub txid: String,
    /// Transaction version
    pub version: u32,
    /// Input UTXOs being spent
    pub inputs: Vec<TxInput>,
    /// Output UTXOs being created
    pub outputs: Vec<TxOutput>,
    /// Lock time (block height or timestamp)
    pub lock_time: u32,
    /// Transaction timestamp
    pub timestamp: i64,
}

impl Transaction {
    /// Create a new transaction
    pub fn new(inputs: Vec<TxInput>, outputs: Vec<TxOutput>) -> Self {
        let mut tx = Self {
            txid: String::new(),
            version: 1,
            inputs,
            outputs,
            lock_time: 0,
            timestamp: chrono::Utc::now().timestamp(),
        };

        tx.txid = tx.calculate_txid();
        tx
    }

    /// Create a treasury grant transaction for an approved proposal
    /// Treasury grants have no inputs (protocol-controlled) and a special txid format
    pub fn create_treasury_grant(
        proposal_id: String,
        recipient: String,
        amount: u64,
        block_number: u64,
        timestamp: i64,
    ) -> Self {
        let output = TxOutput::new(amount, recipient);

        Self {
            txid: format!("treasury_grant_{}_{}", proposal_id, block_number),
            version: 1,
            inputs: vec![], // No inputs - protocol controlled
            outputs: vec![output],
            lock_time: 0,
            timestamp,
        }
    }

    /// Calculate the transaction ID (double SHA3-256 hash)
    pub fn calculate_txid(&self) -> String {
        let data = self.serialize_for_signing();
        let hash1 = Sha3_256::digest(&data);
        let hash2 = Sha3_256::digest(hash1);
        hex::encode(hash2)
    }

    /// Serialize transaction data for signing (excludes signatures)
    pub fn serialize_for_signing(&self) -> Vec<u8> {
        let mut data = Vec::new();

        // Version
        data.extend_from_slice(&self.version.to_le_bytes());

        // Inputs (without signatures)
        data.extend_from_slice(&(self.inputs.len() as u32).to_le_bytes());
        for input in &self.inputs {
            data.extend_from_slice(input.previous_output.txid.as_bytes());
            data.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            data.extend_from_slice(&input.public_key);
            data.extend_from_slice(&input.sequence.to_le_bytes());
        }

        // Outputs
        data.extend_from_slice(&(self.outputs.len() as u32).to_le_bytes());
        for output in &self.outputs {
            data.extend_from_slice(&output.amount.to_le_bytes());
            data.extend_from_slice(output.address.as_bytes());
        }

        // Lock time and timestamp
        data.extend_from_slice(&self.lock_time.to_le_bytes());
        data.extend_from_slice(&self.timestamp.to_le_bytes());

        data
    }

    /// Get total input amount (requires UTXO lookup)
    pub fn total_input(
        &self,
        utxo_set: &std::collections::HashMap<OutPoint, TxOutput>,
    ) -> Result<u64, TransactionError> {
        let mut total = 0u64;
        for input in &self.inputs {
            let utxo = utxo_set
                .get(&input.previous_output)
                .ok_or(TransactionError::InvalidInput)?;
            total = total
                .checked_add(utxo.amount)
                .ok_or(TransactionError::InvalidAmount)?;
        }
        Ok(total)
    }

    /// Get total output amount
    pub fn total_output(&self) -> Result<u64, TransactionError> {
        let mut total = 0u64;
        for output in &self.outputs {
            total = total
                .checked_add(output.amount)
                .ok_or(TransactionError::InvalidAmount)?;
        }
        Ok(total)
    }

    /// Calculate transaction fee
    pub fn fee(
        &self,
        utxo_set: &std::collections::HashMap<OutPoint, TxOutput>,
    ) -> Result<u64, TransactionError> {
        let input_total = self.total_input(utxo_set)?;
        let output_total = self.total_output()?;

        input_total
            .checked_sub(output_total)
            .ok_or(TransactionError::InsufficientFunds)
    }

    /// Basic validation (structure checks)
    pub fn validate_structure(&self) -> Result<(), TransactionError> {
        // Must have at least one input and output
        // Coinbase and treasury grant transactions have no inputs
        if self.inputs.is_empty() && !self.is_coinbase() && !self.is_treasury_grant() {
            return Err(TransactionError::InvalidInput);
        }
        if self.outputs.is_empty() {
            return Err(TransactionError::InvalidAmount);
        }

        // Check for duplicate inputs
        let mut seen = std::collections::HashSet::new();
        for input in &self.inputs {
            if !seen.insert(&input.previous_output) {
                return Err(TransactionError::DuplicateInput);
            }
        }

        // All outputs must have positive amounts
        for output in &self.outputs {
            if output.amount == 0 {
                return Err(TransactionError::InvalidAmount);
            }
        }

        Ok(())
    }

    /// Verify all input signatures (CRITICAL SECURITY CHECK)
    ///
    /// Verifies that:
    /// 1. Each input's public key derives to the UTXO's address
    /// 2. Each input's signature is valid for the transaction data
    ///
    /// Coinbase and treasury grant transactions have no signatures to verify.
    pub fn verify_signatures(
        &self,
        utxo_set: &std::collections::HashMap<OutPoint, TxOutput>,
    ) -> Result<(), TransactionError> {
        // Coinbase and treasury grants have no signatures to verify
        if self.is_coinbase() || self.is_treasury_grant() {
            return Ok(());
        }

        let message = self.serialize_for_signing();

        for input in &self.inputs {
            // Get the UTXO being spent
            let utxo = utxo_set
                .get(&input.previous_output)
                .ok_or(TransactionError::InvalidInput)?;

            // Derive address from public key
            let pub_key_hex = hex::encode(&input.public_key);

            // Verify the UTXO address matches the public key's derived address
            // This ensures the spender owns the UTXO
            if !pub_key_hex.is_empty() {
                let derived_address = format!(
                    "TIME1{}",
                    &pub_key_hex[..std::cmp::min(40, pub_key_hex.len())]
                );
                if derived_address != utxo.address {
                    return Err(TransactionError::InvalidSignature);
                }
            }

            // Verify the Ed25519 signature
            // This cryptographically proves the spender has the private key
            if input.signature.len() == 64 {
                // Convert to arrays for ed25519_dalek
                let pub_key_bytes: Result<[u8; 32], _> = input.public_key.as_slice().try_into();
                let sig_bytes: Result<[u8; 64], _> = input.signature.as_slice().try_into();

                match (pub_key_bytes, sig_bytes) {
                    (Ok(pk), Ok(sig)) => {
                        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

                        let verifying_key = VerifyingKey::from_bytes(&pk)
                            .map_err(|_| TransactionError::InvalidSignature)?;
                        let signature = Signature::from_bytes(&sig);

                        verifying_key
                            .verify(&message, &signature)
                            .map_err(|_| TransactionError::InvalidSignature)?;
                    }
                    _ => return Err(TransactionError::InvalidSignature),
                }
            } else {
                return Err(TransactionError::InvalidSignature);
            }
        }

        Ok(())
    }

    /// Check if this is a coinbase transaction (no inputs, generates new coins)
    /// Note: Treasury grants also have no inputs but are identified differently
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty() && !self.is_treasury_grant()
    }

    /// Check if this is a treasury grant transaction (protocol-controlled distribution)
    /// Treasury grants have no inputs and txid starts with "treasury_grant_"
    pub fn is_treasury_grant(&self) -> bool {
        self.inputs.is_empty() && self.txid.starts_with("treasury_grant_")
    }

    /// Extract proposal ID from treasury grant transaction
    /// Returns None if this is not a treasury grant
    pub fn treasury_grant_proposal_id(&self) -> Option<String> {
        if !self.is_treasury_grant() {
            return None;
        }
        // Treasury grant txid format: "treasury_grant_{proposal_id}_{block_number}"
        let parts: Vec<&str> = self.txid.split('_').collect();
        if parts.len() >= 3 && parts[0] == "treasury" && parts[1] == "grant" {
            Some(parts[2].to_string())
        } else {
            None
        }
    }
}

/// Special transaction types for TIME Coin
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SpecialTransaction {
    /// Coinbase transaction (block reward)
    Coinbase {
        block_height: u64,
        outputs: Vec<TxOutput>,
    },
    /// Masternode registration
    MasternodeRegistration {
        collateral_tx: Transaction,
        masternode_address: String,
        operator_pubkey: Vec<u8>,
        voting_address: String,
    },
    /// Governance proposal
    GovernanceProposal {
        proposal_hash: String,
        payment_amount: u64,
        payment_address: String,
    },
}

impl SpecialTransaction {
    /// Convert special transaction to regular transaction
    pub fn to_transaction(&self) -> Transaction {
        match self {
            SpecialTransaction::Coinbase {
                block_height,
                outputs,
            } => {
                Transaction {
                    txid: format!("coinbase_{}", block_height),
                    version: 1,
                    inputs: vec![], // Coinbase has no inputs
                    outputs: outputs.clone(),
                    lock_time: 0,
                    timestamp: chrono::Utc::now().timestamp(),
                }
            }
            SpecialTransaction::MasternodeRegistration { collateral_tx, .. } => {
                collateral_tx.clone()
            }
            SpecialTransaction::GovernanceProposal {
                proposal_hash: _,
                payment_amount,
                payment_address,
            } => {
                Transaction::new(
                    vec![], // Will be filled by treasury
                    vec![TxOutput::new(*payment_amount, payment_address.clone())],
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_transaction_creation() {
        let input = TxInput::new("prev_tx_id".to_string(), 0, vec![1, 2, 3], vec![4, 5, 6]);
        let output = TxOutput::new(1000, "recipient_address".to_string());

        let tx = Transaction::new(vec![input], vec![output]);

        assert!(!tx.txid.is_empty());
        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
    }

    #[test]
    fn test_outpoint_equality() {
        let op1 = OutPoint::new("txid".to_string(), 0);
        let op2 = OutPoint::new("txid".to_string(), 0);
        let op3 = OutPoint::new("txid".to_string(), 1);

        assert_eq!(op1, op2);
        assert_ne!(op1, op3);
    }

    #[test]
    fn test_treasury_grant_identification() {
        // Regular transaction should not be identified as treasury grant
        let regular_tx = Transaction::new(
            vec![TxInput::new("prev".to_string(), 0, vec![], vec![])],
            vec![TxOutput::new(1000, "addr".to_string())],
        );
        assert!(!regular_tx.is_treasury_grant());
        assert!(regular_tx.treasury_grant_proposal_id().is_none());

        // Treasury grant should be identified correctly
        let grant = Transaction::create_treasury_grant(
            "proposal-xyz".to_string(),
            "recipient".to_string(),
            5000,
            100,
            1234567890,
        );
        assert!(grant.is_treasury_grant());
        assert!(!grant.is_coinbase());
        assert_eq!(
            grant.treasury_grant_proposal_id(),
            Some("proposal-xyz".to_string())
        );
    }

    #[test]
    fn test_treasury_grant_structure() {
        let grant = Transaction::create_treasury_grant(
            "prop-123".to_string(),
            "dev_team".to_string(),
            10_000_000,
            50,
            1700000000,
        );

        // Should have no inputs (protocol-controlled)
        assert_eq!(grant.inputs.len(), 0);

        // Should have exactly one output
        assert_eq!(grant.outputs.len(), 1);
        assert_eq!(grant.outputs[0].amount, 10_000_000);
        assert_eq!(grant.outputs[0].address, "dev_team");

        // Should have correct timestamp
        assert_eq!(grant.timestamp, 1700000000);

        // txid should follow the format
        assert_eq!(grant.txid, "treasury_grant_prop-123_50");
    }

    #[test]
    fn test_coinbase_vs_treasury_grant() {
        // Coinbase transaction (empty inputs, generic txid)
        let coinbase = Transaction {
            txid: "coinbase_123".to_string(),
            version: 1,
            inputs: vec![],
            outputs: vec![TxOutput::new(1000, "miner".to_string())],
            lock_time: 0,
            timestamp: 1234567890,
        };

        assert!(coinbase.is_coinbase());
        assert!(!coinbase.is_treasury_grant());
        assert!(coinbase.treasury_grant_proposal_id().is_none());

        // Treasury grant (empty inputs, special txid)
        let grant = Transaction::create_treasury_grant(
            "prop-1".to_string(),
            "recipient".to_string(),
            5000,
            10,
            1234567890,
        );

        assert!(!grant.is_coinbase()); // Not a coinbase
        assert!(grant.is_treasury_grant());
        assert_eq!(
            grant.treasury_grant_proposal_id(),
            Some("prop-1".to_string())
        );
    }
}
