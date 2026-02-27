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

/// Outpoint referencing a previous transaction output (matches masternode OutPoint)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct OutPoint {
    pub txid: [u8; 32],
    pub vout: u32,
}

/// Transaction input (matches masternode TxInput)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxInput {
    pub previous_output: OutPoint,
    /// script_sig format: [32-byte Ed25519 pubkey || 64-byte signature]
    pub script_sig: Vec<u8>,
    pub sequence: u32,
}

impl TxInput {
    pub fn new(prev_tx: [u8; 32], prev_index: u32) -> Self {
        Self {
            previous_output: OutPoint {
                txid: prev_tx,
                vout: prev_index,
            },
            script_sig: Vec::new(),
            sequence: 0xFFFFFFFF,
        }
    }
}

/// Transaction output (matches masternode TxOutput)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxOutput {
    pub value: u64,
    /// script_pubkey stores the address string as bytes
    pub script_pubkey: Vec<u8>,
}

impl TxOutput {
    pub fn new(amount: u64, address: Address) -> Self {
        Self {
            value: amount,
            script_pubkey: address.to_string().as_bytes().to_vec(),
        }
    }

    /// Get the address from script_pubkey
    pub fn address_string(&self) -> String {
        String::from_utf8_lossy(&self.script_pubkey).to_string()
    }
}

/// Transaction (matches masternode Transaction)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
    pub timestamp: i64,
}

impl Transaction {
    /// Create a new transaction
    pub fn new() -> Self {
        Self {
            version: 1,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64,
        }
    }

    /// Add an input to the transaction
    pub fn add_input(&mut self, input: TxInput) {
        self.inputs.push(input);
    }

    /// Add an output to the transaction
    pub fn add_output(&mut self, output: TxOutput) -> Result<(), TransactionError> {
        if output.value == 0 {
            return Err(TransactionError::InvalidAmount);
        }
        self.outputs.push(output);
        Ok(())
    }

    /// Calculate transaction hash (JSON-based, matches masternode txid())
    pub fn hash(&self) -> [u8; 32] {
        let json = serde_json::to_string(self).expect("JSON serialization should succeed");
        Sha256::digest(json.as_bytes()).into()
    }

    /// Get transaction hash as hex string (TXID)
    pub fn txid(&self) -> String {
        hex::encode(self.hash())
    }

    /// Create signature message for a specific input (matches masternode)
    fn create_signature_message(&self, input_idx: usize) -> Vec<u8> {
        let mut signing_tx = self.clone();
        for input in &mut signing_tx.inputs {
            input.script_sig = vec![];
        }
        let tx_hash = signing_tx.hash();

        let mut message = Vec::new();
        message.extend_from_slice(&tx_hash);
        message.extend_from_slice(&(input_idx as u32).to_le_bytes());
        let outputs_bytes = bincode::serialize(&self.outputs).expect("Failed to serialize outputs");
        let outputs_hash: [u8; 32] = Sha256::digest(&outputs_bytes).into();
        message.extend_from_slice(&outputs_hash);
        message
    }

    /// Sign the transaction with a keypair (produces masternode-compatible script_sig)
    pub fn sign(&mut self, keypair: &Keypair, input_index: usize) -> Result<(), TransactionError> {
        if input_index >= self.inputs.len() {
            return Err(TransactionError::InvalidInput);
        }

        let message = self.create_signature_message(input_index);
        let signature = keypair.sign(&message);
        let pubkey_bytes = keypair.public_key_bytes();

        // script_sig = [32-byte pubkey || 64-byte signature]
        let mut script_sig = Vec::with_capacity(96);
        script_sig.extend_from_slice(&pubkey_bytes);
        script_sig.extend_from_slice(&signature);
        self.inputs[input_index].script_sig = script_sig;

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
        if input.script_sig.len() != 96 {
            return Err(TransactionError::InvalidSignature);
        }

        let pubkey_bytes = &input.script_sig[..32];
        let signature = &input.script_sig[32..96];

        let message = self.create_signature_message(input_index);

        Keypair::verify_with_public_key(pubkey_bytes, &message, signature)
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
        self.outputs.iter().map(|o| o.value).sum()
    }

    /// Check if transaction is coinbase (no inputs)
    pub fn is_coinbase(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Serialize to bytes (bincode, matches masternode)
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
        let _keypair2 = Keypair::generate().expect("Failed to generate keypair");
        let public_key = keypair1.public_key_bytes();
        let address = Address::from_public_key(&public_key, NetworkType::Mainnet)
            .expect("Failed to generate address");

        let mut tx = Transaction::new();
        tx.add_input(TxInput::new([1u8; 32], 0));

        let output = TxOutput::new(1000, address);
        tx.add_output(output).unwrap();

        tx.sign_all(&keypair1).unwrap();

        // Corrupt the signature by flipping a byte
        tx.inputs[0].script_sig[50] ^= 0xFF;

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
