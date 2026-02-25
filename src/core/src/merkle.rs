//! Merkle Tree for UTXO State Verification
//!
//! Provides cryptographic verification of state snapshots through merkle trees.
//! Used to verify that a received state snapshot is valid without downloading
//! the entire blockchain.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleTree {
    /// Root hash of the tree
    pub root: String,
    /// Leaf hashes (one per UTXO)
    pub leaves: Vec<String>,
    /// Internal nodes (for proof generation)
    nodes: Vec<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MerkleProof {
    /// Path from leaf to root
    pub path: Vec<String>,
    /// Indices indicating left/right at each level
    pub indices: Vec<bool>,
}

impl MerkleTree {
    /// Create merkle tree from UTXO set
    pub fn from_utxo_set(utxos: &crate::utxo_set::UTXOSet) -> Self {
        let mut leaves = Vec::new();

        // Create leaf for each UTXO
        for (outpoint, output) in utxos.iter() {
            let leaf_data = format!(
                "{}:{}:{}:{}",
                outpoint.txid, outpoint.vout, output.address, output.amount
            );
            let hash = Self::hash(&leaf_data);
            leaves.push(hash);
        }

        // Sort leaves for deterministic tree
        leaves.sort();

        // Handle empty UTXO set
        if leaves.is_empty() {
            return Self {
                root: Self::hash("empty"),
                leaves: vec![],
                nodes: vec![],
            };
        }

        // Build tree bottom-up
        let mut nodes = vec![leaves.clone()];
        let mut current_level = leaves.clone();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();

            for chunk in current_level.chunks(2) {
                let combined = if chunk.len() == 2 {
                    format!("{}{}", chunk[0], chunk[1])
                } else {
                    // Duplicate last element if odd number
                    format!("{}{}", chunk[0], chunk[0])
                };
                next_level.push(Self::hash(&combined));
            }

            nodes.push(next_level.clone());
            current_level = next_level;
        }

        let root = current_level[0].clone();

        Self {
            root,
            leaves: leaves.clone(),
            nodes,
        }
    }

    /// Create merkle tree from serialized UTXO data
    pub fn from_snapshot_data(data: &[u8]) -> Result<Self, String> {
        // Decompress if needed
        let decompressed = Self::decompress_if_needed(data)?;

        // Deserialize UTXO set
        let utxos: crate::utxo_set::UTXOSet = bincode::deserialize(&decompressed)
            .map_err(|e| format!("Failed to deserialize UTXO set: {}", e))?;

        Ok(Self::from_utxo_set(&utxos))
    }

    /// Verify that the root hash matches
    pub fn verify_root(&self, expected_root: &str) -> bool {
        self.root == expected_root
    }

    /// Generate merkle proof for a specific leaf
    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaves.len() {
            return None;
        }

        let mut path = Vec::new();
        let mut indices = Vec::new();
        let mut current_index = leaf_index;

        for level in &self.nodes[..self.nodes.len() - 1] {
            let sibling_index = if current_index.is_multiple_of(2) {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < level.len() {
                path.push(level[sibling_index].clone());
                indices.push(current_index.is_multiple_of(2));
            } else {
                // Duplicate if no sibling
                path.push(level[current_index].clone());
                indices.push(true);
            }

            current_index /= 2;
        }

        Some(MerkleProof { path, indices })
    }

    /// Verify a merkle proof
    pub fn verify_proof(&self, leaf: &str, proof: &MerkleProof) -> bool {
        let mut current_hash = Self::hash(leaf);

        for (sibling, is_left) in proof.path.iter().zip(&proof.indices) {
            let combined = if *is_left {
                format!("{}{}", current_hash, sibling)
            } else {
                format!("{}{}", sibling, current_hash)
            };
            current_hash = Self::hash(&combined);
        }

        current_hash == self.root
    }

    /// Calculate SHA256 hash
    fn hash(data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Decompress data if compressed
    fn decompress_if_needed(data: &[u8]) -> Result<Vec<u8>, String> {
        use flate2::read::GzDecoder;
        use std::io::Read;

        // Try to decompress
        let mut decoder = GzDecoder::new(data);
        let mut decompressed = Vec::new();

        match decoder.read_to_end(&mut decompressed) {
            Ok(_) => Ok(decompressed),
            Err(_) => {
                // Not compressed, return as-is
                Ok(data.to_vec())
            }
        }
    }

    /// Get number of leaves
    pub fn leaf_count(&self) -> usize {
        self.leaves.len()
    }

    /// Get tree height
    pub fn height(&self) -> usize {
        self.nodes.len()
    }
}

/// Quick merkle root calculation without building full tree
pub fn calculate_utxo_merkle_root(utxos: &crate::utxo_set::UTXOSet) -> String {
    let tree = MerkleTree::from_utxo_set(utxos);
    tree.root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::{OutPoint, TxOutput};
    use crate::utxo_set::UTXOSet;

    #[test]
    fn test_empty_utxo_set() {
        let utxos = UTXOSet::new();
        let tree = MerkleTree::from_utxo_set(&utxos);

        assert_eq!(tree.leaf_count(), 0);
        assert!(!tree.root.is_empty());
    }

    #[test]
    fn test_single_utxo() {
        let mut utxos = UTXOSet::new();
        let outpoint = OutPoint {
            txid: "test_tx".to_string(),
            vout: 0,
        };
        let output = TxOutput {
            amount: 1000,
            address: "test_address".to_string(),
        };
        utxos.add_utxo(outpoint, output);

        let tree = MerkleTree::from_utxo_set(&utxos);

        assert_eq!(tree.leaf_count(), 1);
        assert!(!tree.root.is_empty());
    }

    #[test]
    fn test_multiple_utxos() {
        let mut utxos = UTXOSet::new();

        for i in 0..10 {
            let outpoint = OutPoint {
                txid: format!("tx_{}", i),
                vout: 0,
            };
            let output = TxOutput {
                amount: 1000 * (i + 1),
                address: format!("address_{}", i),
            };
            utxos.add_utxo(outpoint, output);
        }

        let tree = MerkleTree::from_utxo_set(&utxos);

        assert_eq!(tree.leaf_count(), 10);
        assert!(tree.height() > 1);
    }

    #[test]
    fn test_merkle_proof_generation_and_verification() {
        let mut utxos = UTXOSet::new();

        for i in 0..5 {
            let outpoint = OutPoint {
                txid: format!("tx_{}", i),
                vout: 0,
            };
            let output = TxOutput {
                amount: 1000,
                address: format!("address_{}", i),
            };
            utxos.add_utxo(outpoint, output);
        }

        let tree = MerkleTree::from_utxo_set(&utxos);

        // Generate proof for first leaf
        let proof = tree.generate_proof(0).unwrap();

        // Verify proof
        let leaf = &tree.leaves[0];
        assert!(tree.verify_proof(leaf, &proof));
    }

    #[test]
    fn test_deterministic_root() {
        let mut utxos1 = UTXOSet::new();
        let mut utxos2 = UTXOSet::new();

        // Add same UTXOs in different order
        for i in 0..5 {
            let outpoint = OutPoint {
                txid: format!("tx_{}", i),
                vout: 0,
            };
            let output = TxOutput {
                amount: 1000,
                address: format!("address_{}", i),
            };
            utxos1.add_utxo(outpoint.clone(), output.clone());
        }

        for i in (0..5).rev() {
            let outpoint = OutPoint {
                txid: format!("tx_{}", i),
                vout: 0,
            };
            let output = TxOutput {
                amount: 1000,
                address: format!("address_{}", i),
            };
            utxos2.add_utxo(outpoint, output);
        }

        let tree1 = MerkleTree::from_utxo_set(&utxos1);
        let tree2 = MerkleTree::from_utxo_set(&utxos2);

        // Should have same root despite different insertion order
        assert_eq!(tree1.root, tree2.root);
    }

    #[test]
    fn test_calculate_utxo_merkle_root() {
        let mut utxos = UTXOSet::new();

        let outpoint = OutPoint {
            txid: "test".to_string(),
            vout: 0,
        };
        let output = TxOutput {
            amount: 1000,
            address: "test_addr".to_string(),
        };
        utxos.add_utxo(outpoint, output);

        let root = calculate_utxo_merkle_root(&utxos);
        let tree = MerkleTree::from_utxo_set(&utxos);

        assert_eq!(root, tree.root);
    }
}
