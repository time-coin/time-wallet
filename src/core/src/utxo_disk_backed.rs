//! Disk-backed UTXO Set for scalability
//!
//! This module provides a UTXO set that stores data on disk using Sled,
//! with an LRU cache for frequently accessed UTXOs. This prevents memory
//! exhaustion when the UTXO set grows very large.

use crate::transaction::{OutPoint, TxOutput};
use lru::LruCache;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

const UTXO_CACHE_SIZE: usize = 10_000; // Keep 10K most recent UTXOs in memory

/// Disk-backed UTXO set with LRU cache
pub struct DiskBackedUTXOSet {
    /// Sled database for persistent storage
    db: sled::Db,
    /// LRU cache for hot UTXOs (most frequently accessed)
    cache: Arc<RwLock<LruCache<String, TxOutput>>>,
    /// Total supply (cached in memory for performance)
    total_supply: Arc<RwLock<u64>>,
}

impl DiskBackedUTXOSet {
    /// Create new disk-backed UTXO set
    pub fn new(db_path: &str) -> Result<Self, String> {
        let db = sled::open(db_path).map_err(|e| format!("Failed to open UTXO DB: {}", e))?;

        // Initialize total supply from metadata
        let total_supply = if let Ok(Some(data)) = db.get(b"meta:total_supply") {
            bincode::deserialize(&data).unwrap_or(0)
        } else {
            0
        };

        Ok(Self {
            db,
            cache: Arc::new(RwLock::new(LruCache::new(
                NonZeroUsize::new(UTXO_CACHE_SIZE).unwrap(),
            ))),
            total_supply: Arc::new(RwLock::new(total_supply)),
        })
    }

    /// Get a UTXO (checks cache first, then disk)
    pub fn get(&self, outpoint: &OutPoint) -> Option<TxOutput> {
        let key = Self::make_key(outpoint);

        // Check cache first
        {
            let mut cache = self.cache.write().unwrap();
            if let Some(output) = cache.get(&key) {
                return Some(output.clone());
            }
        }

        // Not in cache, check disk
        if let Ok(Some(data)) = self.db.get(key.as_bytes()) {
            if let Ok(output) = bincode::deserialize::<TxOutput>(&data) {
                // Add to cache for future access
                self.cache.write().unwrap().put(key, output.clone());
                return Some(output);
            }
        }

        None
    }

    /// Check if a UTXO exists
    pub fn contains(&self, outpoint: &OutPoint) -> bool {
        self.get(outpoint).is_some()
    }

    /// Add a new UTXO
    pub fn add_utxo(&mut self, outpoint: OutPoint, output: TxOutput) -> Result<(), String> {
        let key = Self::make_key(&outpoint);

        // Serialize and store on disk
        let data =
            bincode::serialize(&output).map_err(|e| format!("Failed to serialize UTXO: {}", e))?;

        self.db
            .insert(key.as_bytes(), data)
            .map_err(|e| format!("Failed to store UTXO: {}", e))?;

        // Update cache
        self.cache.write().unwrap().put(key, output.clone());

        // Update total supply
        *self.total_supply.write().unwrap() += output.amount;
        self.save_total_supply()?;

        Ok(())
    }

    /// Remove a spent UTXO
    pub fn remove_utxo(&mut self, outpoint: &OutPoint) -> Result<Option<TxOutput>, String> {
        let key = Self::make_key(outpoint);

        // Get the UTXO to return it and update supply
        let output = self.get(outpoint);

        // Remove from disk
        self.db
            .remove(key.as_bytes())
            .map_err(|e| format!("Failed to remove UTXO: {}", e))?;

        // Remove from cache
        self.cache.write().unwrap().pop(&key);

        // Update total supply
        if let Some(ref output) = output {
            *self.total_supply.write().unwrap() -= output.amount;
            self.save_total_supply()?;
        }

        Ok(output)
    }

    /// Get total supply
    pub fn total_supply(&self) -> u64 {
        *self.total_supply.read().unwrap()
    }

    /// Get all UTXOs for an address (expensive operation, scans disk)
    pub fn get_utxos_by_address(&self, address: &str) -> Vec<(OutPoint, TxOutput)> {
        let mut result = Vec::new();

        // Scan all UTXOs (this is expensive!)
        for (key, value) in self.db.iter().flatten() {
            if let Ok(key_str) = String::from_utf8(key.to_vec()) {
                if key_str.starts_with("utxo:") {
                    if let Ok(output) = bincode::deserialize::<TxOutput>(&value) {
                        if output.address == address {
                            // Parse outpoint from key
                            if let Some(outpoint) = Self::parse_key(&key_str) {
                                result.push((outpoint, output));
                            }
                        }
                    }
                }
            }
        }

        result
    }

    /// Get balance for an address (scans disk)
    pub fn get_balance(&self, address: &str) -> u64 {
        self.get_utxos_by_address(address)
            .iter()
            .map(|(_, output)| output.amount)
            .sum()
    }

    /// Count total UTXOs (scans disk)
    pub fn count(&self) -> usize {
        self.db
            .iter()
            .filter(|item| {
                if let Ok((key, _)) = item {
                    if let Ok(key_str) = String::from_utf8(key.to_vec()) {
                        return key_str.starts_with("utxo:");
                    }
                }
                false
            })
            .count()
    }

    /// Flush to disk
    pub fn flush(&self) -> Result<(), String> {
        self.db
            .flush()
            .map_err(|e| format!("Failed to flush UTXO DB: {}", e))?;
        Ok(())
    }

    /// Make a key for an outpoint
    fn make_key(outpoint: &OutPoint) -> String {
        format!("utxo:{}:{}", outpoint.txid, outpoint.vout)
    }

    /// Parse outpoint from key
    fn parse_key(key: &str) -> Option<OutPoint> {
        let parts: Vec<&str> = key.strip_prefix("utxo:")?.split(':').collect();
        if parts.len() == 2 {
            Some(OutPoint {
                txid: parts[0].to_string(),
                vout: parts[1].parse().ok()?,
            })
        } else {
            None
        }
    }

    /// Save total supply to disk
    fn save_total_supply(&self) -> Result<(), String> {
        let supply = *self.total_supply.read().unwrap();
        let data = bincode::serialize(&supply)
            .map_err(|e| format!("Failed to serialize supply: {}", e))?;

        self.db
            .insert(b"meta:total_supply", data)
            .map_err(|e| format!("Failed to save supply: {}", e))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::TxOutput;

    #[test]
    fn test_disk_backed_utxo_set() {
        let temp_dir = tempfile::tempdir().unwrap();
        let db_path = temp_dir.path().join("utxo_test");
        let mut utxo_set = DiskBackedUTXOSet::new(db_path.to_str().unwrap()).unwrap();

        // Add UTXO
        let outpoint = OutPoint {
            txid: "test_tx".to_string(),
            vout: 0,
        };
        let output = TxOutput::new(1000, "addr1".to_string());

        utxo_set.add_utxo(outpoint.clone(), output.clone()).unwrap();

        // Verify it exists
        assert!(utxo_set.contains(&outpoint));
        assert_eq!(utxo_set.get(&outpoint).unwrap().amount, 1000);
        assert_eq!(utxo_set.total_supply(), 1000);

        // Remove UTXO
        utxo_set.remove_utxo(&outpoint).unwrap();
        assert!(!utxo_set.contains(&outpoint));
        assert_eq!(utxo_set.total_supply(), 0);
    }
}
