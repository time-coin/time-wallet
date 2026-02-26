use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// Address metadata for contact information
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AddressMetadata {
    pub label: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub is_default: bool,
}

#[derive(Debug, Error)]
pub enum MetadataDbError {
    #[error("Database error: {0}")]
    DbError(#[from] sled::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] bincode::Error),
}

/// Metadata database for wallet contact information and labels
pub struct MetadataDb {
    db: sled::Db,
}

impl MetadataDb {
    /// Open or create a metadata database at the given path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, MetadataDbError> {
        let db = sled::open(path)?;
        Ok(Self { db })
    }

    /// Save address metadata
    pub fn save_metadata(
        &self,
        address: &str,
        metadata: &AddressMetadata,
    ) -> Result<(), MetadataDbError> {
        let key = address.as_bytes();
        let value = bincode::serialize(metadata)?;
        self.db.insert(key, value)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get address metadata
    pub fn get_metadata(&self, address: &str) -> Result<Option<AddressMetadata>, MetadataDbError> {
        let key = address.as_bytes();
        if let Some(value) = self.db.get(key)? {
            let metadata: AddressMetadata = bincode::deserialize(&value)?;
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }

    /// Get all address metadata entries
    pub fn get_all_metadata(&self) -> Result<Vec<(String, AddressMetadata)>, MetadataDbError> {
        let mut result = Vec::new();

        for item in self.db.iter() {
            let (key, value) = item?;
            let address = String::from_utf8_lossy(&key).to_string();
            let metadata: AddressMetadata = bincode::deserialize(&value)?;
            result.push((address, metadata));
        }

        Ok(result)
    }

    /// Remove address metadata
    pub fn remove_metadata(&self, address: &str) -> Result<(), MetadataDbError> {
        let key = address.as_bytes();
        self.db.remove(key)?;
        self.db.flush()?;
        Ok(())
    }

    /// Get the default address
    pub fn get_default_address(&self) -> Result<Option<String>, MetadataDbError> {
        for item in self.db.iter() {
            let (key, value) = item?;
            let metadata: AddressMetadata = bincode::deserialize(&value)?;
            if metadata.is_default {
                let address = String::from_utf8_lossy(&key).to_string();
                return Ok(Some(address));
            }
        }
        Ok(None)
    }

    /// Set an address as default (and unset all others)
    pub fn set_default_address(&self, address: &str) -> Result<(), MetadataDbError> {
        // First, unset all defaults
        for item in self.db.iter() {
            let (key, value) = item?;
            let mut metadata: AddressMetadata = bincode::deserialize(&value)?;
            if metadata.is_default {
                metadata.is_default = false;
                let updated_value = bincode::serialize(&metadata)?;
                self.db.insert(key, updated_value)?;
            }
        }

        // Then set the new default
        if let Some(mut metadata) = self.get_metadata(address)? {
            metadata.is_default = true;
            self.save_metadata(address, &metadata)?;
        }

        self.db.flush()?;
        Ok(())
    }

    /// Clear all metadata (keep addresses intact in wallet)
    pub fn clear_all_metadata(&self) -> Result<(), MetadataDbError> {
        self.db.clear()?;
        self.db.flush()?;
        Ok(())
    }
}
