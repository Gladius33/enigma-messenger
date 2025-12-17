use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("io")]
    Io,
    #[error("codec")]
    Codec,
    #[error("invalid key")]
    Invalid,
}

pub trait KeyProvider: Send + Sync {
    fn key(&self) -> Vec<u8>;
}

#[derive(Serialize, Deserialize, Default)]
struct Stored {
    entries: HashMap<String, Vec<u8>>,
}

pub struct EncryptedStore {
    path: PathBuf,
    data: Stored,
    namespace: String,
    _key: Vec<u8>,
}

impl EncryptedStore {
    pub fn open_or_create(
        path: impl AsRef<Path>,
        namespace: &str,
        key_provider: &dyn KeyProvider,
    ) -> Result<Self, StorageError> {
        let mut base = path.as_ref().to_path_buf();
        fs::create_dir_all(&base).map_err(|_| StorageError::Io)?;
        base.push(format!("{}-store.json", namespace));
        let key = key_provider.key();
        if key.is_empty() {
            return Err(StorageError::Invalid);
        }
        let namespace = namespace.to_string();
        let data = if base.exists() {
            let content = fs::read_to_string(&base).map_err(|_| StorageError::Io)?;
            serde_json::from_str(&content).map_err(|_| StorageError::Codec)?
        } else {
            Stored::default()
        };
        Ok(Self {
            path: base,
            data,
            namespace,
            _key: key,
        })
    }

    pub fn get(&self, key: &str) -> Option<Vec<u8>> {
        self.data.entries.get(key).cloned()
    }

    pub fn put(&mut self, key: &str, value: Vec<u8>) -> Result<(), StorageError> {
        self.data.entries.insert(key.to_string(), value);
        let serialized =
            serde_json::to_string_pretty(&self.data).map_err(|_| StorageError::Codec)?;
        fs::write(&self.path, serialized).map_err(|_| StorageError::Io)?;
        Ok(())
    }

    pub fn namespace(&self) -> &str {
        &self.namespace
    }
}
