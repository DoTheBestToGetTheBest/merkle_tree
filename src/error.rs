use thiserror::Error;

#[derive(Error, Debug)]
pub enum MerkleTreeError {
    #[error("Cannot build a Merkle Tree with no data")]
    EmptyData,

    #[error("Serialization/Deserialization error: {0}")]
    SerdeError(#[from] serde_json::Error),

    #[error("Hex decoding error: {0}")]
    HexDecodeError(#[from] alloy_primitives::hex::FromHexError),

    #[error("Hashing error: {0}")]
    HashError(String),

    #[error("Invalid proof: {0}")]
    InvalidProof(String),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
}
