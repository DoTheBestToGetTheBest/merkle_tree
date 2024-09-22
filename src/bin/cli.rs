// src/bin/cli.rs

use alloy_primitives::hex::{decode, encode};
use alloy_primitives::{TxHash, B256};
use clap::{Parser, Subcommand};
use merkle_tree::{MerkleProof, MerkleTree, MerkleTreeError};
use serde::ser::Error;

use std::fs;
use std::path::PathBuf;
/// Simple program to manage a Merkle Tree
#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Sets the level of verbosity
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Build a Merkle Tree from a file containing transaction hashes
    Build {
        /// Input file containing transaction hashes (one per line, hex encoded)
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// Output file to save the Merkle Tree JSON
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Generate a Merkle Proof for a specific transaction hash
    Proof {
        /// Input file containing transaction hashes (one per line, hex encoded)
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,

        /// The transaction hash to generate proof for (hex encoded)
        #[arg(short, long, value_name = "TX_HASH")]
        tx_hash: String,

        /// Output file to save the Merkle Proof JSON
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Verify a Merkle Proof against a given Merkle Root
    Verify {
        /// Merkle Root hash (hex encoded)
        #[arg(short, long, value_name = "ROOT_HASH")]
        root_hash: String,

        /// Input file containing the Merkle Proof JSON
        #[arg(short, long, value_name = "FILE")]
        proof: PathBuf,
    },
}

fn main() -> Result<(), MerkleTreeError> {
    let cli = Cli::parse();

    // Initialize logging
    match cli.verbose {
        0 => {}
        1 => env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Info)
            .init(),
        2 => env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Debug)
            .init(),
        _ => env_logger::Builder::from_default_env()
            .filter_level(log::LevelFilter::Trace)
            .init(),
    }

    match &cli.command {
        Commands::Build { input, output } => {
            // Read transaction hashes from input file
            let content = fs::read_to_string(input)?;
            let tx_hashes: Result<Vec<TxHash>, _> = content
                .lines()
                .map(|line| {
                    let bytes = decode(line.trim())
                        .map_err(|e| serde_json::Error::custom(e.to_string()))?;
                    if bytes.len() != 32 {
                        return Err(serde_json::Error::custom("Invalid TxHash length"));
                    }
                    let mut array = [0u8; 32];
                    array.copy_from_slice(&bytes);
                    Ok(TxHash::from_slice(&array))
                })
                .collect();

            let tx_hashes = tx_hashes?;

            // Build the Merkle Tree
            let merkle_tree = MerkleTree::new(&convert_fixed_bytes_to_vec_u8(&tx_hashes))?;

            // Serialize to JSON
            let json = merkle_tree.to_json()?;

            // Write to output file
            fs::write(output, json)?;

            println!(
                "Merkle Tree built successfully. Root Hash: {}",
                encode(merkle_tree.root_hash())
            );
        }
        Commands::Proof {
            input,
            tx_hash,
            output,
        } => {
            // Read transaction hashes from input file
            let content = fs::read_to_string(input)?;
            let tx_hashes: Result<Vec<TxHash>, _> = content
                .lines()
                .map(|line| {
                    let bytes = decode(line.trim())
                        .map_err(|e| serde_json::Error::custom(e.to_string()))?;
                    if bytes.len() != 32 {
                        return Err(serde_json::Error::custom("Invalid TxHash length"));
                    }
                    let mut array = [0u8; 32];
                    array.copy_from_slice(&bytes);
                    Ok(TxHash::from_slice(&array))
                })
                .collect();

            let tx_hashes = tx_hashes?;

            // Build the Merkle Tree
            let merkle_tree = MerkleTree::new(&convert_fixed_bytes_to_vec_u8(&tx_hashes))?;

            // Parse the target TxHash
            let target_bytes =
                decode(tx_hash.trim()).map_err(|e| serde_json::Error::custom(e.to_string()))?;
            if target_bytes.len() != 32 {
                return Err(MerkleTreeError::InvalidProof(
                    "Invalid TxHash length".to_string(),
                ));
            }
            let mut target_array = [0u8; 32];
            target_array.copy_from_slice(&target_bytes);
            let target_hash = TxHash::from_slice(&target_array);

            // Generate Merkle Proof
            let proof = merkle_tree.generate_proof(&target_hash.as_slice())?;

            // Serialize proof to JSON
            let proof_json = serde_json::to_string_pretty(&proof)?;

            // Write to output file
            fs::write(output, proof_json)?;

            println!("Merkle Proof generated successfully.");
        }
        Commands::Verify { root_hash, proof } => {
            // Parse the Merkle Root
            let root_bytes =
                decode(root_hash.trim()).map_err(|e| serde_json::Error::custom(e.to_string()))?;
            if root_bytes.len() != 32 {
                return Err(MerkleTreeError::InvalidProof(
                    "Invalid Merkle Root length".to_string(),
                ));
            }
            let mut root_array = [0u8; 32];
            root_array.copy_from_slice(&root_bytes);
            let root_hash = B256::from_slice(&root_array);

            // Read and deserialize the Merkle Proof
            let proof_content = fs::read_to_string(proof)?;
            let merkle_proof: MerkleProof = serde_json::from_str(&proof_content)?;

            // Verify the proof
            let is_valid = merkle_proof.verify(&root_hash)?;

            if is_valid {
                println!("Merkle Proof is valid.");
            } else {
                println!("Merkle Proof is INVALID.");
            }
        }
    }

    Ok(())
}

fn convert_fixed_bytes_to_vec_u8(input: &Vec<B256>) -> Vec<Vec<u8>> {
    input
        .iter()
        .map(|fixed_bytes| fixed_bytes.to_vec())
        .collect()
}
