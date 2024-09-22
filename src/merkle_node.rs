use crate::error::MerkleTreeError;
use alloy_primitives::hex::{decode, encode};

use alloy_primitives::B256;

use serde::de::Error as SerdeError;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::io::Read;

/// Represents a node in the Merkle Tree.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct MerkleNode {
    /// The hash of this node as a B256.
    pub hash: B256,

    /// Left child node. `None` if this is a leaf node.
    pub left: Option<Box<MerkleNode>>,

    /// Right child node. `None` if this is a leaf node.
    pub right: Option<Box<MerkleNode>>,
}

impl MerkleNode {
    /// Creates a new leaf node from data.
    pub fn new_leaf(data: &[u8]) -> Result<Self, MerkleTreeError> {
        let hash = alloy_primitives::keccak256(data);
        Ok(MerkleNode {
            hash,
            left: None,
            right: None,
        })
    }

    /// Creates a new internal node from left and right children.
    pub fn new_internal(left: MerkleNode, right: MerkleNode) -> Result<Self, MerkleTreeError> {
        let mut combined = Vec::new();
        combined.extend(left.hash.bytes());
        combined.extend(right.hash.bytes());

        let data: Vec<_> = combined.into_iter().map(|e| e.unwrap()).collect();
        let hash = alloy_primitives::keccak256(&data);
        Ok(MerkleNode {
            hash,
            left: Some(Box::new(left)),
            right: Some(Box::new(right)),
        })
    }
}

// Custom Serialize and Deserialize implementations

impl Serialize for MerkleNode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // Serialize hash as hex string
        let mut state = serializer.serialize_struct("MerkleNode", 3)?;
        state.serialize_field("hash", &encode(self.hash))?;
        state.serialize_field("left", &self.left)?;
        state.serialize_field("right", &self.right)?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for MerkleNode {
    fn deserialize<D>(deserializer: D) -> Result<MerkleNode, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct MerkleNodeHelper {
            hash: String,
            left: Option<Box<MerkleNode>>,
            right: Option<Box<MerkleNode>>,
        }

        let helper = MerkleNodeHelper::deserialize(deserializer)?;
        let hash_bytes = decode(&helper.hash).map_err(D::Error::custom)?;
        let hash = B256::from_slice(&hash_bytes);
        Ok(MerkleNode {
            hash,
            left: helper.left,
            right: helper.right,
        })
    }
}

impl fmt::Display for MerkleNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn fmt_node(node: &MerkleNode, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
            for _ in 0..depth {
                write!(f, "  ")?;
            }
            writeln!(f, "- {}", encode(node.hash))?;
            if let Some(left) = &node.left {
                fmt_node(left, f, depth + 1)?;
            }
            if let Some(right) = &node.right {
                fmt_node(right, f, depth + 1)?;
            }
            Ok(())
        }

        fmt_node(self, f, 0)
    }
}
