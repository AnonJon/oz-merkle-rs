use ethers::core::utils::keccak256;
use ethers::types::{Address, H256, U256};

pub struct MerkleTree {
    elements: Vec<H256>,
    layers: Vec<Vec<H256>>,
    leaves: usize,
}

impl MerkleTree {
    /// Constructs a new Merkle tree from the given data.
    ///
    /// This function creates a new Merkle tree from the provided data,
    /// where each element in the data is hashed and stored in the tree.
    ///
    /// # Arguments
    ///
    /// * `data` - A vector containing tuples of addresses and amounts to be stored in the Merkle tree.
    ///
    /// # Returns
    ///
    /// A new instance of `MerkleTree` containing the constructed Merkle tree.
    ///
    /// # Example
    ///
    /// ```rust
    /// use oz_merkle_rs::MerkleTree;
    /// use ethers::types::{Address, U256};
    /// use std::str::FromStr;
    ///
    /// // Create some sample data
    /// let data = vec![
    ///     (Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
    ///         U256::from_dec_str("1840233889215604334017").unwrap()),
    ///     (Address::from_str("0x00393d62f17b07e64f7cdcdf9bdc2fd925b20bba").unwrap(),
    ///         U256::from_dec_str("7840233889215604334017").unwrap()),
    /// ];
    ///
    /// // Create a new Merkle tree from the data
    /// let merkle_tree = MerkleTree::new(data);
    ///
    pub fn new(data: Vec<(Address, U256)>) -> Self {
        let mut elements: Vec<H256> = data
            .iter()
            .enumerate()
            .map(|(index, x)| Self::hash_node(index, *x))
            .collect();
        // sort and deduplicate to get the correct order of elements
        elements.sort();
        elements.dedup();
        let leaves = elements.len();
        let mut layers = vec![elements.clone()];

        while layers.last().unwrap().len() > 1 {
            layers.push(Self::next_layer(layers.last().unwrap()));
        }

        MerkleTree {
            elements,
            layers,
            leaves,
        }
    }

    /// Retrieves the root hash of the Merkle tree.
    ///
    /// This function returns the root hash of the Merkle tree, if it exists.
    ///
    /// # Returns
    ///
    /// An `Option` containing either the root hash if the Merkle tree is not empty,
    /// or `None` if the Merkle tree is empty.
    pub fn get_root(&self) -> Option<H256> {
        self.layers
            .last()
            .and_then(|last_layer| last_layer.first().cloned())
    }

    /// Retrieves the Merkle proof for a given element.
    ///
    /// This function takes an element and returns the Merkle proof for that element,
    /// if it exists in the Merkle tree.
    ///
    /// # Arguments
    ///
    /// * `element` - The hash of the element for which the proof is to be retrieved.
    ///
    /// # Returns
    ///
    /// An `Option` containing either the Merkle proof as a vector of hashes if the element is found,
    /// or `None` if the element is not present in the Merkle tree.
    pub fn get_proof(&self, element: H256) -> Option<Vec<H256>> {
        let mut index = self.elements.iter().position(|&e| e == element)?;
        let mut proof = Vec::new();

        for layer in &self.layers[..self.layers.len() - 1] {
            let pair_index = if index % 2 == 0 { index + 1 } else { index - 1 };
            if pair_index < layer.len() {
                proof.push(layer[pair_index]);
            }
            index /= 2; // move up to the next layer.
        }

        Some(proof)
    }

    /// Verifies a proof for a given element in a Merkle tree.
    ///
    /// This function takes an element, a proof (list of hashes), and the root hash of the Merkle tree,
    /// and verifies if the element is part of the Merkle tree with the given proof.
    ///
    /// # Arguments
    ///
    /// * `element` - The hash of the element to be verified.
    /// * `proof` - A vector containing the hashes forming the Merkle proof.
    /// * `root` - The root hash of the Merkle tree.
    ///
    /// # Returns
    ///
    /// `true` if the proof is valid for the given element and root hash,
    pub fn verify_proof(&self, element: H256, proof: Vec<H256>, root: H256) -> bool {
        let mut computed_hash = element;

        for proof_element in proof.into_iter() {
            computed_hash = if computed_hash < proof_element {
                Self::hash_pair(&computed_hash, &proof_element)
            } else {
                Self::hash_pair(&proof_element, &computed_hash)
            };
        }

        computed_hash == root
    }

    /// Returns the number of leaves in the Merkle tree.
    ///
    /// This function returns the total number of leaves (i.e., elements) in the Merkle tree.
    ///
    /// # Returns
    ///
    /// The number of leaves (elements) in the Merkle tree.
    ///
    pub fn leaves_length(&self) -> usize {
        self.leaves
    }

    /// Computes the hash of a leaf node in a Merkle tree.
    ///
    /// This function takes the index and leaf data (address and amount) as input,
    /// concatenates them together, and computes the hash of the resulting byte array.
    /// The hash is returned as a `H256` value.
    ///
    /// # Arguments
    ///
    /// * `index` - The index of the leaf node in the Merkle tree.
    /// * `leaf_data` - A tuple containing the address (`Address`) and amount (`U256`) of the leaf node.
    ///
    /// # Returns
    ///
    /// A `H256` value representing the hash of the leaf node.
    pub fn hash_node(index: usize, leaf_data: (Address, U256)) -> H256 {
        let (account, amount) = leaf_data;
        let mut bytes = Vec::new();

        let mut index_bytes = [0u8; 32];
        U256::from(index).to_big_endian(&mut index_bytes);
        bytes.extend_from_slice(&index_bytes);

        bytes.extend_from_slice(account.as_bytes());

        let mut amount_bytes = [0u8; 32];
        amount.to_big_endian(&mut amount_bytes);
        bytes.extend_from_slice(&amount_bytes);

        H256::from(keccak256(bytes))
    }

    fn next_layer(elements: &[H256]) -> Vec<H256> {
        elements
            .chunks(2)
            .map(|chunk| {
                if chunk.len() == 2 {
                    Self::hash_pair(&chunk[0], &chunk[1])
                } else {
                    // if there are odd layers we hash the last element with itself
                    *chunk.first().unwrap()
                }
            })
            .collect()
    }

    fn hash_pair(a: &H256, b: &H256) -> H256 {
        let mut pairs = [a, b];
        // Ensure lexicographical order
        pairs.sort();
        let concatenated = [pairs[0].as_bytes(), pairs[1].as_bytes()].concat();
        H256::from(keccak256(&concatenated))
    }
}

#[cfg(test)]

mod test {
    use super::*;
    use std::str::FromStr;

    fn setup_tree() -> MerkleTree {
        let data = vec![
            (
                Address::from_str("0x00393d62f17b07e64f7cdcdf9bdc2fd925b20bba").unwrap(),
                U256::from_dec_str("1840233889215604334017").unwrap(),
            ),
            (
                Address::from_str("0x008EF27b8d0B9f8c1FAdcb624ef5FebE4f11fa9f").unwrap(),
                U256::from_dec_str("73750290420694562195").unwrap(),
            ),
        ];
        MerkleTree::new(data)
    }

    #[test]
    fn merkle_tree_creation() {
        let tree = setup_tree();
        assert!(
            !tree.get_root().expect("no root found").is_zero(),
            "The root hash should not be zero"
        );
    }

    #[test]
    fn merkle_tree_root_hash_correctness() {
        let tree = setup_tree();
        let expected_root_hash =
            "0x1b999c65d923a6c4e70c9a4419c9f7d2a303d4599c165fbd9fbca60d457211c6";

        assert_eq!(
            format!("{:?}", tree.get_root().unwrap()),
            expected_root_hash,
            "The calculated root hash should match the expected value"
        );
    }

    #[test]
    fn get_proof_for_valid_index() {
        let data = (
            Address::from_str("0x00393d62f17b07e64f7cdcdf9bdc2fd925b20bba").unwrap(),
            U256::from_dec_str("1840233889215604334017").unwrap(),
        );
        let tree = setup_tree();
        let proof = tree.get_proof(MerkleTree::hash_node(0, data)).unwrap();

        assert!(
            !proof.is_empty(),
            "Expected non-empty proof for a valid leaf"
        );
    }

    #[test]
    fn get_proof_for_invalid_index() {
        let data = (
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap(),
            U256::from_dec_str("1840233889215604334017").unwrap(),
        );
        let tree = setup_tree();
        let proof_result = tree.get_proof(MerkleTree::hash_node(0, data));

        assert!(
            proof_result.is_none(),
            "Expected error when requesting proof for an invalid index"
        );
    }

    #[test]
    fn verify_valid_proof() {
        let data = (
            Address::from_str("0x00393d62f17b07e64f7cdcdf9bdc2fd925b20bba").unwrap(),
            U256::from_dec_str("1840233889215604334017").unwrap(),
        );
        let tree = setup_tree();
        let node = MerkleTree::hash_node(0, data);
        let proof = tree.get_proof(node).unwrap();
        let result = tree.verify_proof(node, proof, tree.get_root().unwrap());

        assert!(
            result,
            "Proof should be valid and verification should succeed"
        );
    }
}
