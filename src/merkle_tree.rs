// src/merkle_tree.rs

use crate::error::MerkleTreeError;
use crate::merkle_node::MerkleNode;
use crate::proof::{MerkleProof, ProofStep};
use alloy_primitives::hex::encode;
use alloy_primitives::keccak256;
use alloy_primitives::B256;
use log::{debug, info};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Represents the Merkle Tree.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MerkleTree {
    /// The root node of the tree.
    pub root: MerkleNode,

    /// Map from leaf hashes to their corresponding data.
    #[serde(skip)]
    pub leaves: HashMap<B256, Vec<u8>>,
}

impl MerkleTree {
    /// Builds a new Merkle Tree from a list of data items.
    pub fn new(data: &[Vec<u8>]) -> Result<Self, MerkleTreeError> {
        if data.is_empty() {
            return Err(MerkleTreeError::EmptyData);
        }

        // Initialize logging
        let _ = env_logger::builder().is_test(true).try_init();

        info!("Building Merkle Tree with {} leaves.", data.len());

        // Create leaf nodes
        let mut leaf_nodes: Vec<MerkleNode> = Vec::new();
        let mut leaves_map: HashMap<B256, Vec<u8>> = HashMap::new();

        for datum in data {
            let leaf = MerkleNode::new_leaf(datum)?;
            leaves_map.insert(leaf.hash.clone(), datum.clone());
            leaf_nodes.push(leaf);
        }

        // Build the tree
        let root = Self::build_tree_recursive(leaf_nodes)?;

        Ok(MerkleTree {
            root,
            leaves: leaves_map,
        })
    }

    /// Recursively builds the Merkle Tree from a list of nodes.
    fn build_tree_recursive(mut nodes: Vec<MerkleNode>) -> Result<MerkleNode, MerkleTreeError> {
        debug!("Building tree level with {} nodes.", nodes.len());

        if nodes.len() == 1 {
            return Ok(nodes.pop().unwrap());
        }

        let mut next_level = Vec::new();

        for i in (0..nodes.len()).step_by(2) {
            if i + 1 < nodes.len() {
                let left = nodes[i].clone();
                let right = nodes[i + 1].clone();
                let parent = MerkleNode::new_internal(left, right)?;
                next_level.push(parent);
            } else {
                // Odd node, promote to next level
                next_level.push(nodes[i].clone());
                info!(
                    "Promoting node with hash {} to next level due to odd count.",
                    encode(nodes[i].hash)
                );
            }
        }

        Self::build_tree_recursive(next_level)
    }

    /// Returns the root hash of the Merkle Tree.
    pub fn root_hash(&self) -> &B256 {
        &self.root.hash
    }

    /// Serializes the Merkle Tree to a JSON string.
    pub fn to_json(&self) -> Result<String, MerkleTreeError> {
        serde_json::to_string_pretty(&self).map_err(MerkleTreeError::SerdeError)
    }

    /// Deserializes the Merkle Tree from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, MerkleTreeError> {
        serde_json::from_str(json_str).map_err(MerkleTreeError::SerdeError)
    }

    /// Verifies the integrity of the Merkle Tree.
    pub fn verify(&self) -> bool {
        Self::verify_node(&self.root)
    }

    /// Recursively verifies the hash of each node.
    fn verify_node(node: &MerkleNode) -> bool {
        if node.left.is_none() && node.right.is_none() {
            // Leaf node: hash should already be correct
            true
        } else if let (Some(left), Some(right)) = (&node.left, &node.right) {
            // Internal node: recompute hash and compare
            let mut combined = Vec::new();
            combined.extend(left.hash);
            combined.extend(right.hash);
            let expected_hash = keccak256(&combined);
            if node.hash != expected_hash {
                return false;
            }
            // Recursively verify children
            Self::verify_node(left) && Self::verify_node(right)
        } else {
            // Invalid node state
            false
        }
    }

    /// Generates a Merkle Proof for the given data.
    pub fn generate_proof(&self, data: &[u8]) -> Result<MerkleProof, MerkleTreeError> {
        let leaf_hash = keccak256(data);

        if !self.leaves.contains_key(&leaf_hash) {
            return Err(MerkleTreeError::InvalidProof(
                "Data not found in the tree".to_string(),
            ));
        }

        let mut proof_steps = Vec::new();
        self.build_proof(&self.root, &leaf_hash, &mut proof_steps)?;

        Ok(MerkleProof {
            leaf_hash,
            proof_steps,
        })
    }

    /// Recursively builds the proof steps.
    fn build_proof(
        &self,
        node: &MerkleNode,
        target_hash: &B256,
        proof_steps: &mut Vec<ProofStep>,
    ) -> Result<bool, MerkleTreeError> {
        if &node.hash == target_hash {
            return Ok(true);
        }

        if let (Some(left), Some(right)) = (&node.left, &node.right) {
            // Search left subtree
            if self.build_proof(left, target_hash, proof_steps)? {
                proof_steps.push(ProofStep::Right(right.hash.clone()));
                return Ok(true);
            }

            // Search right subtree
            if self.build_proof(right, target_hash, proof_steps)? {
                proof_steps.push(ProofStep::Left(left.hash.clone()));
                return Ok(true);
            }
        }

        Ok(false)
    }

    /// Traverses the tree in-order and applies a function to each node.
    pub fn traverse_in_order<Fn>(&self, mut func: Fn)
    where
        Fn: FnMut(&MerkleNode),
    {
        self.traverse_in_order_recursive(&self.root, &mut func);
    }

    fn traverse_in_order_recursive<Fn>(&self, node: &MerkleNode, func: &mut Fn)
    where
        Fn: FnMut(&MerkleNode),
    {
        if let Some(left) = &node.left {
            self.traverse_in_order_recursive(left, func);
        }

        func(node);

        if let Some(right) = &node.right {
            self.traverse_in_order_recursive(right, func);
        }
    }
}

impl fmt::Display for MerkleTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.root.fmt(f)
    }
}
