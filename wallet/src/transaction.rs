use crate::address::Address;
use crate::keypair::Keypair;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TransactionError {
    #[error("Invalid transaction input")]
    InvalidInput,

    #[error("Invalid transaction output")]
    InvalidOutput,

    #[error("Invalid signature")]
    InvalidSignature,

    #[error("Invalid amount (must be > 0)")]
    InvalidAmount,

    #[error("Serialization error")]
    SerializationError,
}

/// Transaction input
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxInput {
    /// Previous transaction hash
    pub prev_tx: [u8; 32],
    /// Output index in previous transaction
    pub prev_index: u32,
    /// Signature (empty before signing)
    pub signature: Vec<u8>,
    /// Public key of sender
    pub public_key: Vec<u8>,
}

impl TxInput {
    pub fn new(prev_tx: [u8; 32], prev_index: u32) -> Self {
        Self {
            prev_tx,
            prev_index,
            signature: Vec::new(),
            public_key: Vec::new(),
        }
    }
}

/// Transaction output
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxOutput {
    /// Amount in smallest unit
    pub amount: u64,
    /// Recipient address
    pub address: String,
}

impl TxOutput {
    pub fn new(amount: u64, address: Address) -> Self {
        Self {
            amount,
            address: address.to_string(),
        }
    }
}

/// Transaction
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    /// Transaction version
    pub version: u32,
    /// Transaction inputs
    pub inputs: Vec<TxInput>,
    /// Transaction outputs
    pub outputs: Vec<TxOutput>,
    /// Lock time (0 = not locked)
    pub lock_time: u32,
    /// Nonce for transaction uniqueness
    pub nonce: u64,
    /// Timestamp
    pub timestamp: u64,
}

impl Transaction {
    /// Create a new transaction
    pub fn new() -> Self {
        Self {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            nonce: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    /// Add an input to the transaction
    pub fn add_input(&mut self, input: TxInput) {
        self.inputs.push(input);
    }

    /// Add an output to the transaction
    pub fn add_output(&mut self, output: TxOutput) -> Result<(), TransactionError> {
        if output.amount == 0 {
            return Err(TransactionError::InvalidAmount);
        }
        self.outputs.push(output);
        Ok(())
    }

    /// Set nonce
    pub fn set_nonce(&mut self, nonce: u64) {
        self.nonce = nonce;
    }

    /// Calculate transaction hash
    pub fn hash(&self) -> [u8; 32] {
        let serialized = bincode::serialize(self).expect("Failed to serialize transaction");
        let hash = Sha256::digest(&serialized);
        hash.into()
    }

    /// Get transaction hash as hex string (TXID)
    pub fn txid(&self) -> String {
        hex::encode(self.hash())
    }

    /// Get the hash for signing (without signatures and public keys)
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut tx_copy = self.clone();
        for input in &mut tx_copy.inputs {
            input.signature.clear();
            input.public_key.clear();
        }
        tx_copy.hash()
    }

    /// Sign the transaction with a keypair
    pub fn sign(&mut self, keypair: &Keypair, input_index: usize) -> Result<(), TransactionError> {
        if input_index >= self.inputs.len() {
            return Err(TransactionError::InvalidInput);
        }

        let signing_hash = self.signing_hash();
        let signature = keypair.sign(&signing_hash);
        let public_key = keypair.public_key_bytes().to_vec();

        self.inputs[input_index].signature = signature;
        self.inputs[input_index].public_key = public_key;

        Ok(())
    }

    /// Sign all inputs with the same keypair
    pub fn sign_all(&mut self, keypair: &Keypair) -> Result<(), TransactionError> {
        for i in 0..self.inputs.len() {
            self.sign(keypair, i)?;
        }
        Ok(())
    }

    /// Verify a single input signature
    pub fn verify_input(&self, input_index: usize) -> Result<(), TransactionError> {
        if input_index >= self.inputs.len() {
            return Err(TransactionError::InvalidInput);
        }

        let input = &self.inputs[input_index];
        if input.signature.is_empty() || input.public_key.is_empty() {
            return Err(TransactionError::InvalidSignature);
        }

        let signing_hash = self.signing_hash();

        Keypair::verify_with_public_key(&input.public_key, &signing_hash, &input.signature)
            .map_err(|_| TransactionError::InvalidSignature)
    }

    /// Verify all input signatures
    pub fn verify_all(&self) -> Result<(), TransactionError> {
        for i in 0..self.inputs.len() {
            self.verify_input(i)?;
        }
        Ok(())
    }

    /// Get total input count
    pub fn total_input_count(&self) -> usize {
        self.inputs.len()
    }

    /// Get total output amount
    pub fn total_output(&self) -> u64 {
        self.outputs.iter().map(|o| o.amount).sum()
    }

    /// Check if transaction is coinbase (no inputs)
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Serialize to bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>, TransactionError> {
        bincode::serialize(self).map_err(|_| TransactionError::SerializationError)
    }

    /// Deserialize from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, TransactionError> {
        bincode::deserialize(bytes).map_err(|_| TransactionError::SerializationError)
    }
}

impl Default for Transaction {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::NetworkType;

    #[test]
    fn test_transaction_creation() {
        let tx = Transaction::new();
        assert_eq!(tx.version, 1);
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
    }

    #[test]
    fn test_add_input_output() {
        let mut tx = Transaction::new();

        let input = TxInput::new([1u8; 32], 0);
        tx.add_input(input);

        let keypair = Keypair::generate().expect("Failed to generate keypair");
        let public_key = keypair.public_key_bytes();
        let address = Address::from_public_key(&public_key, NetworkType::Mainnet)
            .expect("Failed to generate address");
        let output = TxOutput::new(1000, address);
        tx.add_output(output).unwrap();

        assert_eq!(tx.inputs.len(), 1);
        assert_eq!(tx.outputs.len(), 1);
        assert_eq!(tx.total_output(), 1000);
    }

    #[test]
    fn test_transaction_hash() {
        let mut tx = Transaction::new();
        tx.add_input(TxInput::new([1u8; 32], 0));

        let hash1 = tx.hash();
        let hash2 = tx.hash();

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, [0u8; 32]);
    }

    #[test]
    fn test_sign_and_verify() {
        let keypair = Keypair::generate().expect("Failed to generate keypair");
        let public_key = keypair.public_key_bytes();
        let address = Address::from_public_key(&public_key, NetworkType::Mainnet)
            .expect("Failed to generate address");

        let mut tx = Transaction::new();
        tx.add_input(TxInput::new([1u8; 32], 0));

        let output = TxOutput::new(1000, address);
        tx.add_output(output).unwrap();

        tx.sign_all(&keypair).unwrap();
        assert!(tx.verify_all().is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let keypair1 = Keypair::generate().expect("Failed to generate keypair");
        let keypair2 = Keypair::generate().expect("Failed to generate keypair");
        let public_key = keypair1.public_key_bytes();
        let address = Address::from_public_key(&public_key, NetworkType::Mainnet)
            .expect("Failed to generate address");

        let mut tx = Transaction::new();
        tx.add_input(TxInput::new([1u8; 32], 0));

        let output = TxOutput::new(1000, address);
        tx.add_output(output).unwrap();

        tx.sign_all(&keypair1).unwrap();

        tx.inputs[0].signature = keypair2.sign(&tx.signing_hash());

        assert!(tx.verify_all().is_err());
    }

    #[test]
    fn test_coinbase_detection() {
        let tx = Transaction::new();
        assert!(tx.is_coinbase());

        let mut tx2 = Transaction::new();
        tx2.add_input(TxInput::new([1u8; 32], 0));
        assert!(!tx2.is_coinbase());
    }
}
