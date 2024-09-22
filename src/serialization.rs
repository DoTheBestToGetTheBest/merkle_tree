use alloy_primitives::hex::{decode, encode};
use alloy_primitives::TxHash;
use alloy_primitives::B256;
use serde::{self, Deserialize, Deserializer, Serializer};

pub mod b256_hex {
    use super::*;

    pub fn serialize<S>(bytes: &B256, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = encode(bytes);
        serializer.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<B256, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid length for B256"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(B256::from_slice(&array))
    }
}

pub mod txhash_hex {
    use super::*;

    pub fn serialize<S>(tx_hash: &TxHash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = encode(tx_hash);
        serializer.serialize_str(&hex_str)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<TxHash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = decode(&s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("Invalid length for TxHash"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(TxHash::from_slice(&array))
    }
}
