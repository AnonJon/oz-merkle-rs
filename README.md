# OZ Merkle-rs

## Introduction

OZ Merkle-rs is a lightweight, efficient Merkle tree implementation written in Rust, designed to seamlessly integrate with OpenZeppelin contracts for proof verification.

## Features

- **Lightweight Design**: Optimized for minimal memory footprint and maximum performance.
- **Seamless Integration**: Works out of the box with OpenZeppelin contracts, making it easy to incorporate into your blockchain projects.
- **Rust Implementation**: Leverages Rust's safety and concurrency features to ensure secure and efficient operation.
- **Keccak256**: Supports Keccak256 hashing.

## Getting Started

### Prerequisites

- Rust (latest stable version recommended)
- Cargo (Rust's package manager)

### Installation

Add `oz_merkle_rs` to your `Cargo.toml` file:

```toml
[dependencies]
oz_merkle_rs = "0.1.0"
```

## Basic Usage

```rust
use oz_merkle_rs::MerkleTree;
use std::str::FromStr;

fn main() {
    let data = vec![
    (Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        U256::from_dec_str("1840233889215604334017").unwrap()),
    (Address::from_str("0x00393d62f17b07e64f7cdcdf9bdc2fd925b20bba").unwrap(),
        U256::from_dec_str("7840233889215604334017").unwrap()),
    ];

    // Create a new Merkle tree from the data
    let merkle_tree = MerkleTree::new(data);
}

```

## Examples

```rust
let data = vec![
    (Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
        U256::from_dec_str("1840233889215604334017").unwrap()),
    (Address::from_str("0x00393d62f17b07e64f7cdcdf9bdc2fd925b20bba").unwrap(),
        U256::from_dec_str("7840233889215604334017").unwrap()),
    ];
        let tree = MerkleTree::new(data);
        let node = MerkleTree::hash_node(0, data[0]);
        let proof = tree.get_proof(node).unwrap();
        let result = tree.verify_proof(node, proof, tree.get_root().unwrap());
```

## License

OZ Merkle-rs is open source and available under the MIT License.
