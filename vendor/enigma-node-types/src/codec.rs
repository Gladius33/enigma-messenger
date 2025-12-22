use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::error::{EnigmaNodeTypesError, Result};

pub fn to_json_string<T: Serialize>(v: &T) -> Result<String> {
    serde_json::to_string(v).map_err(|_| EnigmaNodeTypesError::JsonError)
}

pub fn from_json_str<T: DeserializeOwned>(s: &str) -> Result<T> {
    serde_json::from_str(s).map_err(|_| EnigmaNodeTypesError::JsonError)
}
