use crate::error::MerkleTreeError;

use alloy_primitives::B256;
use alloy_signer::k256::sha2::Digest;
use alloy_signer::k256::sha2::Sha256;
use serde::{Deserialize, Serialize};

/// Represents a single step in the Merkle Proof.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub enum ProofStep {
    #[serde(
        serialize_with = "crate::serialization::b256_hex::serialize",
        deserialize_with = "crate::serialization::b256_hex::deserialize"
    )]
    Left(B256), // Sibling hash is on the left
    #[serde(
        serialize_with = "crate::serialization::b256_hex::serialize",
        deserialize_with = "crate::serialization::b256_hex::deserialize"
    )]
    Right(B256), // Sibling hash is on the right
}

/// Represents a Merkle Proof for a specific leaf.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct MerkleProof {
    #[serde(
        serialize_with = "crate::serialization::b256_hex::serialize",
        deserialize_with = "crate::serialization::b256_hex::deserialize"
    )]
    pub leaf_hash: B256,
    pub proof_steps: Vec<ProofStep>,
}

impl MerkleProof {
    /// Verifies the Merkle Proof against a given root hash.
    pub fn verify(&self, root_hash: &B256) -> Result<bool, MerkleTreeError> {
        let mut computed_hash = self.leaf_hash;

        for step in &self.proof_steps {
            let combined = match step {
                ProofStep::Left(sibling_hash) => {
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&sibling_hash.0);
                    combined.extend_from_slice(&computed_hash.0);
                    combined
                }
                ProofStep::Right(sibling_hash) => {
                    let mut combined = Vec::new();
                    combined.extend_from_slice(&computed_hash.0);
                    combined.extend_from_slice(&sibling_hash.0);
                    combined
                }
            };

            let digest = Sha256::digest(&combined);
            computed_hash = B256::from_slice(&digest);
        }

        Ok(&computed_hash == root_hash)
    }
}
