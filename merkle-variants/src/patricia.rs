//! Merkle Patricia trie implementation.
//!
//! [`MerklePatriciaTrie`] models Ethereum's nibble-addressed Merkle Patricia
//! Trie shape. The implementation includes nibble-path utilities, RLP/HP
//! encoding, Ethereum-style node references, root hashing, and basic
//! key-value mutation.

use std::{collections::HashMap, marker::PhantomData};

use merkle_core::{error::MerkleError, traits::HashFunction};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

const EMPTY_RLP: u8 = 0x80;
const SHORT_STRING_OFFSET: u8 = 0x80;
const SHORT_LIST_OFFSET: u8 = 0xC0;
const LONG_STRING_OFFSET: u8 = 0xB7;
const LONG_LIST_OFFSET: u8 = 0xF7;

/// A sequence of 4-bit nibbles extracted from a byte key.
///
/// Each stored nibble is guaranteed to be in the range `0x0..=0xF` when
/// constructed through [`Self::from_key`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NibblePath {
    nibbles: Vec<u8>,
}

impl NibblePath {
    /// Converts a byte key into a high-nibble-first path.
    ///
    /// Every input byte contributes two nibbles. For example, `b"key"` has
    /// three bytes and therefore produces six nibbles.
    #[must_use]
    pub fn from_key(key: &[u8]) -> Self {
        let mut nibbles = Vec::with_capacity(key.len() * 2);
        for byte in key {
            nibbles.push(byte >> 4);
            nibbles.push(byte & 0x0F);
        }

        Self { nibbles }
    }

    fn from_nibbles(nibbles: Vec<u8>) -> Result<Self, MerkleError> {
        if let Some(invalid) = nibbles.iter().find(|nibble| **nibble > 0x0F) {
            return Err(MerkleError::RlpError(format!(
                "invalid nibble value {invalid:#x}"
            )));
        }

        Ok(Self { nibbles })
    }

    fn prefix(&self, len: usize) -> Self {
        Self {
            nibbles: self.nibbles[..len].to_vec(),
        }
    }

    /// Returns the number of nibbles in this path.
    #[must_use]
    pub fn len(&self) -> usize {
        self.nibbles.len()
    }

    /// Returns `true` when this path contains no nibbles.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nibbles.is_empty()
    }

    /// Returns the nibble at `idx`.
    ///
    /// # Panics
    ///
    /// Panics when `idx` is outside this path.
    #[must_use]
    pub fn get(&self, idx: usize) -> u8 {
        self.nibbles[idx]
    }

    /// Returns a path beginning at nibble `start`.
    ///
    /// # Panics
    ///
    /// Panics when `start` is greater than [`Self::len`].
    #[must_use]
    pub fn slice(&self, start: usize) -> Self {
        Self {
            nibbles: self.nibbles[start..].to_vec(),
        }
    }

    /// Returns the shared prefix length with `other`, measured in nibbles.
    #[must_use]
    pub fn common_prefix_len(&self, other: &Self) -> usize {
        self.nibbles
            .iter()
            .zip(&other.nibbles)
            .take_while(|(left, right)| left == right)
            .count()
    }
}

/// Hex-prefix encodes an MPT nibble path.
///
/// Leaf paths use prefix nibble `0x2` for even paths and `0x3` for odd paths.
/// Extension paths use `0x0` for even paths and `0x1` for odd paths.
#[must_use]
pub fn hp_encode(path: &NibblePath, is_leaf: bool) -> Vec<u8> {
    let odd = path.len() % 2 == 1;
    let mut prefixed = Vec::with_capacity(path.len() + 2);
    let prefix = match (is_leaf, odd) {
        (false, false) => 0x0,
        (false, true) => 0x1,
        (true, false) => 0x2,
        (true, true) => 0x3,
    };

    prefixed.push(prefix);
    if odd {
        prefixed.extend_from_slice(&path.nibbles);
    } else {
        prefixed.push(0);
        prefixed.extend_from_slice(&path.nibbles);
    }

    nibbles_to_bytes(&prefixed)
}

/// Decodes a hex-prefix encoded MPT path.
///
/// Returns the decoded path and whether the path belongs to a leaf. Malformed
/// input returns an empty extension path instead of panicking; callers that
/// need strict validation should use [`rlp_decode`].
#[must_use]
pub fn hp_decode(bytes: &[u8]) -> (NibblePath, bool) {
    hp_decode_checked(bytes).unwrap_or_default()
}

/// RLP-encodes an MPT node.
#[must_use]
pub fn rlp_encode<D: AsRef<[u8]>>(node: &MptNode<D>) -> Vec<u8> {
    match node {
        MptNode::Empty | MptNode::__DigestMarker(_) => vec![EMPTY_RLP],
        MptNode::Leaf { key_suffix, value } => rlp_encode_list(&[
            rlp_encode_bytes(&hp_encode(key_suffix, true)),
            rlp_encode_bytes(value),
        ]),
        MptNode::Extension {
            shared_prefix,
            child,
        } => rlp_encode_list(&[
            rlp_encode_bytes(&hp_encode(shared_prefix, false)),
            rlp_encode(child),
        ]),
        MptNode::Branch { children, value } => {
            let mut items = Vec::with_capacity(17);
            items.extend(children.iter().map(rlp_encode_node_ref));
            items.push(
                value
                    .as_deref()
                    .map_or_else(|| vec![EMPTY_RLP], rlp_encode_bytes),
            );

            rlp_encode_list(&items)
        }
    }
}

/// Decodes an RLP-encoded MPT node.
///
/// # Errors
///
/// Returns [`MerkleError::RlpError`] when the input is malformed or does not
/// describe one of the supported MPT node shapes.
pub fn rlp_decode<D>(bytes: &[u8]) -> Result<MptNode<D>, MerkleError>
where
    D: TryFrom<Vec<u8>>,
{
    let (item, consumed) = parse_rlp_item(bytes)?;
    if consumed != bytes.len() {
        return Err(MerkleError::RlpError(
            "trailing bytes after RLP item".to_string(),
        ));
    }

    decode_node_item(&item)
}

/// A lazily materialized reference to an MPT node.
///
/// Ethereum embeds small node RLP directly in the parent and stores only the
/// hash for larger nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeRef<D> {
    /// Hash of a large node's RLP encoding.
    Hash(D),
    /// Raw RLP encoding of a small node.
    Inline(Vec<u8>),
}

/// A Merkle Patricia Trie witness for one key.
///
/// The proof nodes are RLP-encoded MPT nodes ordered from root to the terminal
/// node reached by the key path. `value = None` represents a non-membership
/// proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MptProof<D> {
    /// Raw key bytes this proof is for.
    pub key: Vec<u8>,
    /// Stored value for membership proofs, or `None` for non-membership.
    pub value: Option<Vec<u8>>,
    /// RLP-encoded witness nodes, ordered root first.
    pub proof_nodes: Vec<Vec<u8>>,
    #[serde(skip)]
    _marker: PhantomData<D>,
}

impl<D> MptProof<D> {
    /// Creates a proof from its key, optional value, and RLP witness nodes.
    #[must_use]
    pub fn new(key: Vec<u8>, value: Option<Vec<u8>>, proof_nodes: Vec<Vec<u8>>) -> Self {
        Self {
            key,
            value,
            proof_nodes,
            _marker: PhantomData,
        }
    }

    /// Returns `true` when this proof contains a concrete value.
    #[must_use]
    pub const fn is_membership(&self) -> bool {
        self.value.is_some()
    }

    /// Returns `true` when this proof proves absence for the key.
    #[must_use]
    pub const fn is_non_membership(&self) -> bool {
        self.value.is_none()
    }
}

/// Returns the Ethereum-style node reference for `node`.
///
/// Nodes whose RLP encoding is at least 32 bytes are represented by
/// `H(RLP(node))`; smaller nodes are represented by their raw RLP bytes.
#[must_use]
pub fn hash_node<H>(node: &MptNode<H::Digest>) -> NodeRef<H::Digest>
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    let rlp = rlp_encode(node);
    if rlp.len() >= 32 {
        NodeRef::Hash(hash_mpt_bytes::<H>(&rlp))
    } else {
        NodeRef::Inline(rlp)
    }
}

/// Computes a full root hash for an MPT root node.
///
/// Unlike child references, the root is always returned as a digest, even when
/// the root node's RLP encoding is short enough to be inlined by a parent.
#[must_use]
pub fn compute_root_hash<H>(root: &MptNode<H::Digest>) -> H::Digest
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    hash_mpt_bytes::<H>(&rlp_encode(root))
}

/// A Merkle Patricia Trie node.
///
/// The public variants mirror Ethereum's four logical MPT node types: empty,
/// leaf, extension, and branch. The hidden marker variant exists only to make
/// the digest type parameter available before later issues add node hashing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MptNode<D> {
    /// Empty slot with no data at this path.
    Empty,

    /// Leaf node storing the remaining key suffix and value bytes.
    Leaf {
        /// Remaining nibble path after the branch point.
        key_suffix: NibblePath,
        /// Value stored at the complete key.
        value: Vec<u8>,
    },

    /// Extension node compressing a shared nibble prefix.
    Extension {
        /// Shared prefix consumed before following `child`.
        shared_prefix: NibblePath,
        /// Next trie node after the compressed prefix.
        child: Box<MptNode<D>>,
    },

    /// Branch node with one child slot per nibble plus an optional value.
    Branch {
        /// Children indexed by nibble `0x0..=0xF`.
        children: Box<[NodeRef<D>; 16]>,
        /// Value stored exactly at this branch path, if any.
        value: Option<Vec<u8>>,
    },

    #[doc(hidden)]
    __DigestMarker(PhantomData<D>),
}

impl<D> MptNode<D> {
    #[cfg(test)]
    fn empty_children() -> Box<[NodeRef<D>; 16]> {
        Box::new(std::array::from_fn(|_| NodeRef::Inline(vec![EMPTY_RLP])))
    }

    #[cfg(test)]
    fn height(&self) -> usize {
        match self {
            Self::Empty | Self::__DigestMarker(_) => 0,
            Self::Leaf { .. } => 1,
            Self::Extension { child, .. } => 1 + child.height(),
            Self::Branch { .. } => 1,
        }
    }
}

/// Ethereum-style Merkle Patricia Trie over nibble-addressed keys.
///
/// The trie starts empty. Later Phase 4 work will add mutation, RLP
/// serialization, and root hashing.
pub struct MerklePatriciaTrie<H: HashFunction> {
    root: MptNode<H::Digest>,
    root_hash: Option<H::Digest>,
    node_count: usize,
    entries: HashMap<Vec<u8>, Vec<u8>>,
    nodes: HashMap<Vec<u8>, MptNode<H::Digest>>,
    _marker: PhantomData<H>,
}

impl<H> MerklePatriciaTrie<H>
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    /// Creates an empty Merkle Patricia Trie.
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: MptNode::Empty,
            root_hash: None,
            node_count: 0,
            entries: HashMap::new(),
            nodes: HashMap::new(),
            _marker: PhantomData,
        }
    }

    /// Inserts or updates `value` at `key`.
    ///
    /// Keys are converted to nibble paths before the trie is rebuilt into its
    /// compressed Patricia shape.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::EmptyLeafData`] when `value` is empty.
    pub fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<(), MerkleError> {
        if value.is_empty() {
            return Err(MerkleError::EmptyLeafData);
        }

        self.entries.insert(key.to_vec(), value.to_vec());
        self.rebuild();

        Ok(())
    }

    /// Removes the value stored at `key`.
    ///
    /// Removal rebuilds the compressed Patricia shape from the remaining
    /// entries. That canonical rebuild collapses branch and extension nodes
    /// that no longer need to exist after the target leaf is deleted.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::UnsupportedOperation`] when `key` is not present.
    pub fn remove(&mut self, key: &[u8]) -> Result<(), MerkleError> {
        Self::remove_at(&mut self.entries, key)?;
        self.collapse();

        Ok(())
    }

    /// Returns the value stored at `key`, if present.
    #[must_use]
    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        let path = NibblePath::from_key(key);
        self.get_at(&self.root, &path).map(Vec::as_slice)
    }

    /// Generates an MPT witness for `key`.
    ///
    /// The returned proof contains RLP-encoded nodes from the root to the
    /// terminal node reached by the key path. Missing keys produce a
    /// non-membership proof with `value = None`.
    ///
    /// # Errors
    ///
    /// Returns [`MerkleError::EmptyTree`] when the trie is empty.
    pub fn generate_proof(&self, key: &[u8]) -> Result<MptProof<H::Digest>, MerkleError> {
        if self.is_empty() {
            return Err(MerkleError::EmptyTree);
        }

        let path = NibblePath::from_key(key);
        let mut proof_nodes = Vec::new();
        let value = self.collect_proof_nodes(&self.root, &path, &mut proof_nodes);

        Ok(MptProof::new(key.to_vec(), value, proof_nodes))
    }

    /// Verifies an MPT proof against a trusted root hash.
    ///
    /// Membership proofs require the final node to contain `proof.value`.
    /// Non-membership proofs require the path to terminate at an empty child,
    /// a missing branch value, or a divergent leaf/extension.
    #[must_use]
    pub fn verify_proof(expected_root: &H::Digest, proof: &MptProof<H::Digest>) -> bool
    where
        H::Digest: TryFrom<Vec<u8>>,
    {
        let Some(root_node) = proof.proof_nodes.first() else {
            return false;
        };
        if hash_mpt_bytes::<H>(root_node) != *expected_root {
            return false;
        }

        let key_path = NibblePath::from_key(&proof.key);
        Self::verify_proof_at(&key_path, &proof.value, &proof.proof_nodes, 0)
    }

    /// Returns the current root digest, or `None` for an empty trie.
    #[must_use]
    pub fn root(&self) -> Option<&H::Digest> {
        self.root_hash.as_ref()
    }

    /// Returns `true` when the trie contains no materialized nodes.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Returns the number of materialized trie nodes.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.node_count
    }

    /// Returns the longest node path from the root to any leaf.
    #[must_use]
    pub fn height(&self) -> usize {
        self.height_at(&self.root)
    }

    fn rebuild(&mut self) {
        self.nodes.clear();

        let entries = self
            .entries
            .iter()
            .map(|(key, value)| (NibblePath::from_key(key), value.clone()))
            .collect::<Vec<_>>();

        self.root = Self::build_subtree(&entries, &mut self.nodes);
        self.node_count = Self::count_nodes(&self.root, &self.nodes);
        self.root_hash = if self.entries.is_empty() {
            None
        } else {
            Some(compute_root_hash::<H>(&self.root))
        };
    }

    fn remove_at(entries: &mut HashMap<Vec<u8>, Vec<u8>>, key: &[u8]) -> Result<(), MerkleError> {
        entries
            .remove(key)
            .map(|_| ())
            .ok_or(MerkleError::UnsupportedOperation(
                "remove missing Patricia key",
            ))
    }

    fn collapse(&mut self) {
        self.rebuild();
    }

    fn build_subtree(
        entries: &[(NibblePath, Vec<u8>)],
        nodes: &mut HashMap<Vec<u8>, MptNode<H::Digest>>,
    ) -> MptNode<H::Digest> {
        match entries {
            [] => MptNode::Empty,
            [(path, value)] => MptNode::Leaf {
                key_suffix: path.clone(),
                value: value.clone(),
            },
            _ => {
                let shared_prefix_len = Self::shared_prefix_len(entries);
                if shared_prefix_len > 0 {
                    let shared_prefix = entries[0].0.prefix(shared_prefix_len);
                    let stripped = entries
                        .iter()
                        .map(|(path, value)| (path.slice(shared_prefix_len), value.clone()))
                        .collect::<Vec<_>>();
                    let child = Self::build_subtree(&stripped, nodes);

                    return MptNode::Extension {
                        shared_prefix,
                        child: Box::new(child),
                    };
                }

                let mut children =
                    Box::new(std::array::from_fn(|_| NodeRef::Inline(vec![EMPTY_RLP])));
                let mut branch_value = None;
                for nibble in 0_u8..=0x0F {
                    let child_entries = entries
                        .iter()
                        .filter_map(|(path, value)| {
                            if path.is_empty() {
                                return None;
                            }
                            (path.get(0) == nibble).then(|| (path.slice(1), value.clone()))
                        })
                        .collect::<Vec<_>>();

                    if !child_entries.is_empty() {
                        let child = Self::build_subtree(&child_entries, nodes);
                        children[usize::from(nibble)] = Self::store_node_ref(child, nodes);
                    }
                }

                for (path, value) in entries {
                    if path.is_empty() {
                        branch_value = Some(value.clone());
                        break;
                    }
                }

                MptNode::Branch {
                    children,
                    value: branch_value,
                }
            }
        }
    }

    fn shared_prefix_len(entries: &[(NibblePath, Vec<u8>)]) -> usize {
        let Some((first, _)) = entries.first() else {
            return 0;
        };

        entries
            .iter()
            .skip(1)
            .fold(first.len(), |prefix_len, (path, _)| {
                prefix_len.min(first.common_prefix_len(path))
            })
    }

    fn store_node_ref(
        node: MptNode<H::Digest>,
        nodes: &mut HashMap<Vec<u8>, MptNode<H::Digest>>,
    ) -> NodeRef<H::Digest> {
        let node_ref = hash_node::<H>(&node);
        nodes.insert(Self::node_ref_key(&node_ref), node);
        node_ref
    }

    fn node_ref_key(node_ref: &NodeRef<H::Digest>) -> Vec<u8> {
        match node_ref {
            NodeRef::Hash(hash) => hash.as_ref().to_vec(),
            NodeRef::Inline(rlp) => rlp.clone(),
        }
    }

    fn resolve_node_ref(&self, node_ref: &NodeRef<H::Digest>) -> Option<&MptNode<H::Digest>> {
        self.nodes.get(&Self::node_ref_key(node_ref))
    }

    fn collect_proof_nodes(
        &self,
        node: &MptNode<H::Digest>,
        path: &NibblePath,
        proof_nodes: &mut Vec<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        proof_nodes.push(rlp_encode(node));

        match node {
            MptNode::Empty | MptNode::__DigestMarker(_) => None,
            MptNode::Leaf { key_suffix, value } => (key_suffix == path).then(|| value.clone()),
            MptNode::Extension {
                shared_prefix,
                child,
            } => {
                if path.common_prefix_len(shared_prefix) == shared_prefix.len() {
                    self.collect_proof_nodes(child, &path.slice(shared_prefix.len()), proof_nodes)
                } else {
                    None
                }
            }
            MptNode::Branch { children, value } => {
                if path.is_empty() {
                    return value.clone();
                }

                let child_ref = &children[usize::from(path.get(0))];
                self.resolve_node_ref(child_ref)
                    .and_then(|child| self.collect_proof_nodes(child, &path.slice(1), proof_nodes))
            }
        }
    }

    fn verify_proof_at(
        path: &NibblePath,
        proof_value: &Option<Vec<u8>>,
        proof_nodes: &[Vec<u8>],
        index: usize,
    ) -> bool
    where
        H::Digest: TryFrom<Vec<u8>>,
    {
        let Some(encoded_node) = proof_nodes.get(index) else {
            return false;
        };
        let Ok(node) = rlp_decode::<H::Digest>(encoded_node) else {
            return false;
        };

        match node {
            MptNode::Empty | MptNode::__DigestMarker(_) => {
                proof_value.is_none() && index + 1 == proof_nodes.len()
            }
            MptNode::Leaf { key_suffix, value } => {
                if key_suffix == *path {
                    proof_value.as_ref() == Some(&value) && index + 1 == proof_nodes.len()
                } else {
                    proof_value.is_none() && index + 1 == proof_nodes.len()
                }
            }
            MptNode::Extension {
                shared_prefix,
                child,
            } => {
                if path.common_prefix_len(&shared_prefix) != shared_prefix.len() {
                    return proof_value.is_none() && index + 1 == proof_nodes.len();
                }

                let Some(next_node) = proof_nodes.get(index + 1) else {
                    return false;
                };
                if next_node != &rlp_encode(&child) {
                    return false;
                }

                Self::verify_proof_at(
                    &path.slice(shared_prefix.len()),
                    proof_value,
                    proof_nodes,
                    index + 1,
                )
            }
            MptNode::Branch { children, value } => {
                if path.is_empty() {
                    return proof_value.as_ref() == value.as_ref()
                        && index + 1 == proof_nodes.len();
                }

                let child_ref = &children[usize::from(path.get(0))];
                if matches!(child_ref, NodeRef::Inline(rlp) if is_rlp_empty(rlp)) {
                    return proof_value.is_none() && index + 1 == proof_nodes.len();
                }

                let Some(next_node) = proof_nodes.get(index + 1) else {
                    return false;
                };
                if !Self::node_ref_matches(child_ref, next_node) {
                    return false;
                }

                Self::verify_proof_at(&path.slice(1), proof_value, proof_nodes, index + 1)
            }
        }
    }

    fn node_ref_matches(node_ref: &NodeRef<H::Digest>, encoded_node: &[u8]) -> bool {
        match node_ref {
            NodeRef::Hash(hash) => hash_mpt_bytes::<H>(encoded_node) == *hash,
            NodeRef::Inline(rlp) => rlp == encoded_node,
        }
    }

    fn get_at<'a>(
        &'a self,
        node: &'a MptNode<H::Digest>,
        path: &NibblePath,
    ) -> Option<&'a Vec<u8>> {
        match node {
            MptNode::Empty | MptNode::__DigestMarker(_) => None,
            MptNode::Leaf { key_suffix, value } => (key_suffix == path).then_some(value),
            MptNode::Extension {
                shared_prefix,
                child,
            } => {
                if path.common_prefix_len(shared_prefix) == shared_prefix.len() {
                    self.get_at(child, &path.slice(shared_prefix.len()))
                } else {
                    None
                }
            }
            MptNode::Branch { children, value } => {
                if path.is_empty() {
                    return value.as_ref();
                }

                let child_ref = &children[usize::from(path.get(0))];
                let child = self.resolve_node_ref(child_ref)?;
                self.get_at(child, &path.slice(1))
            }
        }
    }

    fn count_nodes(
        node: &MptNode<H::Digest>,
        nodes: &HashMap<Vec<u8>, MptNode<H::Digest>>,
    ) -> usize {
        match node {
            MptNode::Empty | MptNode::__DigestMarker(_) => 0,
            MptNode::Leaf { .. } => 1,
            MptNode::Extension { child, .. } => 1 + Self::count_nodes(child, nodes),
            MptNode::Branch { children, .. } => {
                1 + children
                    .iter()
                    .filter_map(|child_ref| nodes.get(&Self::node_ref_key(child_ref)))
                    .map(|child| Self::count_nodes(child, nodes))
                    .sum::<usize>()
            }
        }
    }

    fn height_at(&self, node: &MptNode<H::Digest>) -> usize {
        match node {
            MptNode::Empty | MptNode::__DigestMarker(_) => 0,
            MptNode::Leaf { .. } => 1,
            MptNode::Extension { child, .. } => 1 + self.height_at(child),
            MptNode::Branch { children, .. } => {
                1 + children
                    .iter()
                    .filter_map(|child_ref| self.resolve_node_ref(child_ref))
                    .map(|child| self.height_at(child))
                    .max()
                    .unwrap_or(0)
            }
        }
    }
}

impl<H> Default for MerklePatriciaTrie<H>
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<Vec<u8>>),
}

fn nibbles_to_bytes(nibbles: &[u8]) -> Vec<u8> {
    nibbles
        .chunks(2)
        .map(|chunk| {
            let high = chunk[0] << 4;
            let low = chunk.get(1).copied().unwrap_or(0);
            high | low
        })
        .collect()
}

fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0F])
        .collect()
}

fn hp_decode_checked(bytes: &[u8]) -> Result<(NibblePath, bool), MerkleError> {
    let mut nibbles = bytes_to_nibbles(bytes);
    let Some(prefix) = nibbles.first().copied() else {
        return Err(MerkleError::RlpError("empty hex-prefix path".to_string()));
    };

    let (is_leaf, odd) = match prefix {
        0x0 => (false, false),
        0x1 => (false, true),
        0x2 => (true, false),
        0x3 => (true, true),
        _ => {
            return Err(MerkleError::RlpError(format!(
                "invalid hex-prefix nibble {prefix:#x}"
            )));
        }
    };

    let path_nibbles = if odd {
        nibbles.split_off(1)
    } else {
        if nibbles.get(1).copied() != Some(0) {
            return Err(MerkleError::RlpError(
                "even hex-prefix path must include zero padding nibble".to_string(),
            ));
        }
        nibbles.split_off(2)
    };

    Ok((NibblePath::from_nibbles(path_nibbles)?, is_leaf))
}

fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.to_vec();
    }

    if bytes.len() <= 55 {
        let mut encoded = Vec::with_capacity(bytes.len() + 1);
        encoded.push(SHORT_STRING_OFFSET + u8::try_from(bytes.len()).expect("length <= 55"));
        encoded.extend_from_slice(bytes);
        return encoded;
    }

    let length_bytes = usize_to_be_bytes(bytes.len());
    let mut encoded = Vec::with_capacity(1 + length_bytes.len() + bytes.len());
    encoded.push(LONG_STRING_OFFSET + u8::try_from(length_bytes.len()).expect("usize is short"));
    encoded.extend_from_slice(&length_bytes);
    encoded.extend_from_slice(bytes);
    encoded
}

fn rlp_encode_list(items: &[Vec<u8>]) -> Vec<u8> {
    let payload_len = items.iter().map(Vec::len).sum::<usize>();
    let mut payload = Vec::with_capacity(payload_len);
    for item in items {
        payload.extend_from_slice(item);
    }

    if payload.len() <= 55 {
        let mut encoded = Vec::with_capacity(payload.len() + 1);
        encoded.push(SHORT_LIST_OFFSET + u8::try_from(payload.len()).expect("length <= 55"));
        encoded.extend_from_slice(&payload);
        return encoded;
    }

    let length_bytes = usize_to_be_bytes(payload.len());
    let mut encoded = Vec::with_capacity(1 + length_bytes.len() + payload.len());
    encoded.push(LONG_LIST_OFFSET + u8::try_from(length_bytes.len()).expect("usize is short"));
    encoded.extend_from_slice(&length_bytes);
    encoded.extend_from_slice(&payload);
    encoded
}

fn rlp_encode_node_ref<D: AsRef<[u8]>>(node_ref: &NodeRef<D>) -> Vec<u8> {
    match node_ref {
        NodeRef::Hash(hash) => rlp_encode_bytes(hash.as_ref()),
        NodeRef::Inline(rlp) => rlp.clone(),
    }
}

fn hash_mpt_bytes<H>(bytes: &[u8]) -> H::Digest
where
    H: HashFunction,
    H::Digest: From<[u8; 32]>,
{
    if H::algorithm_name() == "Keccak-256" && H::digest_size() == 32 {
        return raw_keccak256(bytes).into();
    }

    H::hash(bytes)
}

fn raw_keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0_u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(bytes);
    hasher.finalize(&mut out);
    out
}

fn usize_to_be_bytes(value: usize) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    bytes
        .iter()
        .skip_while(|byte| **byte == 0)
        .copied()
        .collect()
}

fn parse_rlp_item(bytes: &[u8]) -> Result<(RlpItem, usize), MerkleError> {
    let Some(&prefix) = bytes.first() else {
        return Err(MerkleError::RlpError("empty RLP input".to_string()));
    };

    match prefix {
        0x00..=0x7F => Ok((RlpItem::Bytes(vec![prefix]), 1)),
        0x80..=0xB7 => {
            let len = usize::from(prefix - SHORT_STRING_OFFSET);
            let payload = read_payload(bytes, 1, len)?;
            Ok((RlpItem::Bytes(payload.to_vec()), 1 + len))
        }
        0xB8..=0xBF => {
            let len_of_len = usize::from(prefix - LONG_STRING_OFFSET);
            let (len, offset) = read_long_length(bytes, len_of_len)?;
            let payload = read_payload(bytes, offset, len)?;
            Ok((RlpItem::Bytes(payload.to_vec()), offset + len))
        }
        0xC0..=0xF7 => {
            let len = usize::from(prefix - SHORT_LIST_OFFSET);
            let payload = read_payload(bytes, 1, len)?;
            Ok((RlpItem::List(parse_rlp_list_payload(payload)?), 1 + len))
        }
        0xF8..=0xFF => {
            let len_of_len = usize::from(prefix - LONG_LIST_OFFSET);
            let (len, offset) = read_long_length(bytes, len_of_len)?;
            let payload = read_payload(bytes, offset, len)?;
            Ok((
                RlpItem::List(parse_rlp_list_payload(payload)?),
                offset + len,
            ))
        }
    }
}

fn read_payload(bytes: &[u8], offset: usize, len: usize) -> Result<&[u8], MerkleError> {
    bytes
        .get(offset..offset + len)
        .ok_or_else(|| MerkleError::RlpError("RLP payload length exceeds input".to_string()))
}

fn read_long_length(bytes: &[u8], len_of_len: usize) -> Result<(usize, usize), MerkleError> {
    if len_of_len == 0 {
        return Err(MerkleError::RlpError(
            "RLP long length must not be empty".to_string(),
        ));
    }

    let length_bytes = read_payload(bytes, 1, len_of_len)?;
    if length_bytes.first().copied() == Some(0) {
        return Err(MerkleError::RlpError(
            "RLP length has leading zero".to_string(),
        ));
    }

    let mut len = 0_usize;
    for byte in length_bytes {
        len = len
            .checked_mul(256)
            .and_then(|value| value.checked_add(usize::from(*byte)))
            .ok_or_else(|| MerkleError::RlpError("RLP length overflows usize".to_string()))?;
    }

    Ok((len, 1 + len_of_len))
}

fn parse_rlp_list_payload(payload: &[u8]) -> Result<Vec<Vec<u8>>, MerkleError> {
    let mut items = Vec::new();
    let mut cursor = 0_usize;

    while cursor < payload.len() {
        let (_, consumed) = parse_rlp_item(&payload[cursor..])?;
        items.push(payload[cursor..cursor + consumed].to_vec());
        cursor += consumed;
    }

    Ok(items)
}

fn decode_node_item<D>(item: &RlpItem) -> Result<MptNode<D>, MerkleError>
where
    D: TryFrom<Vec<u8>>,
{
    match item {
        RlpItem::Bytes(bytes) if bytes.is_empty() => Ok(MptNode::Empty),
        RlpItem::Bytes(_) => Err(MerkleError::RlpError(
            "top-level MPT node cannot be a non-empty byte string".to_string(),
        )),
        RlpItem::List(items) if items.len() == 2 => decode_leaf_or_extension(items),
        RlpItem::List(items) if items.len() == 17 => decode_branch(items),
        RlpItem::List(items) => Err(MerkleError::RlpError(format!(
            "invalid MPT list length {}; expected 2 or 17",
            items.len()
        ))),
    }
}

fn decode_leaf_or_extension<D>(items: &[Vec<u8>]) -> Result<MptNode<D>, MerkleError>
where
    D: TryFrom<Vec<u8>>,
{
    let encoded_path = decode_rlp_bytes(&items[0])?;
    let (path, is_leaf) = hp_decode_checked(&encoded_path)?;

    if is_leaf {
        return Ok(MptNode::Leaf {
            key_suffix: path,
            value: decode_rlp_bytes(&items[1])?,
        });
    }

    Ok(MptNode::Extension {
        shared_prefix: path,
        child: Box::new(rlp_decode(&items[1])?),
    })
}

fn decode_branch<D>(items: &[Vec<u8>]) -> Result<MptNode<D>, MerkleError>
where
    D: TryFrom<Vec<u8>>,
{
    let mut children = Vec::with_capacity(16);
    for item in &items[..16] {
        if is_rlp_empty(item) {
            children.push(NodeRef::Inline(vec![EMPTY_RLP]));
        } else if let Ok(hash) = decode_rlp_hash(item) {
            children.push(NodeRef::Hash(hash));
        } else {
            children.push(NodeRef::Inline(item.clone()));
        }
    }
    let children = children.try_into().map_err(|_| {
        MerkleError::RlpError("branch node must contain exactly 16 children".to_string())
    })?;
    let value = decode_rlp_bytes(&items[16])?;
    let value = if value.is_empty() { None } else { Some(value) };

    Ok(MptNode::Branch {
        children: Box::new(children),
        value,
    })
}

fn decode_rlp_hash<D>(bytes: &[u8]) -> Result<D, MerkleError>
where
    D: TryFrom<Vec<u8>>,
{
    let value = decode_rlp_bytes(bytes)?;
    if value.len() != 32 {
        return Err(MerkleError::RlpError(
            "branch child hash must be 32 bytes".to_string(),
        ));
    }

    D::try_from(value).map_err(|_| {
        MerkleError::RlpError("failed to convert branch child hash digest".to_string())
    })
}

fn decode_rlp_bytes(bytes: &[u8]) -> Result<Vec<u8>, MerkleError> {
    let (item, consumed) = parse_rlp_item(bytes)?;
    if consumed != bytes.len() {
        return Err(MerkleError::RlpError(
            "trailing bytes after RLP byte string".to_string(),
        ));
    }

    match item {
        RlpItem::Bytes(value) => Ok(value),
        RlpItem::List(_) => Err(MerkleError::RlpError(
            "expected RLP byte string, found list".to_string(),
        )),
    }
}

fn is_rlp_empty(bytes: &[u8]) -> bool {
    bytes == [EMPTY_RLP]
}

#[cfg(test)]
mod tests {
    use merkle_core::error::MerkleError;
    use merkle_core::traits::Serializable;
    use merkleforge_hash::{Blake3, Keccak256};

    use super::{
        MerklePatriciaTrie, MptNode, MptProof, NibblePath, NodeRef, compute_root_hash,
        hash_mpt_bytes, hash_node, hp_decode, hp_encode, rlp_decode, rlp_encode,
    };

    #[test]
    fn new_trie_is_empty() {
        let tree = MerklePatriciaTrie::<Keccak256>::new();

        assert!(tree.is_empty());
        assert_eq!(tree.root(), None);
        assert_eq!(tree.node_count(), 0);
        assert_eq!(tree.height(), 0);
    }

    #[test]
    fn nibble_path_from_key_splits_each_byte() {
        let path = NibblePath::from_key(b"key");

        assert_eq!(path.len(), 6);
        assert_eq!(path.get(0), 0x6);
        assert_eq!(path.get(1), 0xB);
        assert_eq!(path.get(2), 0x6);
        assert_eq!(path.get(3), 0x5);
        assert_eq!(path.get(4), 0x7);
        assert_eq!(path.get(5), 0x9);
    }

    #[test]
    fn nibble_path_slice_keeps_suffix() {
        let path = NibblePath::from_key(&[0xAB, 0xCD]);
        let suffix = path.slice(2);

        assert_eq!(suffix.len(), 2);
        assert_eq!(suffix.get(0), 0xC);
        assert_eq!(suffix.get(1), 0xD);
    }

    #[test]
    fn nibble_path_common_prefix_len_counts_matching_nibbles() {
        let first = NibblePath::from_key(&[0xAB, 0xCD]);
        let second = NibblePath::from_key(&[0xAB, 0xEF]);

        assert_eq!(first.common_prefix_len(&second), 2);
    }

    #[test]
    fn all_four_node_variants_compile() {
        let leaf = MptNode::<[u8; 32]>::Leaf {
            key_suffix: NibblePath::from_key(b"leaf"),
            value: b"value".to_vec(),
        };
        let extension = MptNode::<[u8; 32]>::Extension {
            shared_prefix: NibblePath::from_key(b"shared"),
            child: Box::new(MptNode::Empty),
        };
        let branch = MptNode::<[u8; 32]>::Branch {
            children: MptNode::empty_children(),
            value: Some(b"branch value".to_vec()),
        };

        assert!(matches!(MptNode::<[u8; 32]>::Empty, MptNode::Empty));
        assert!(matches!(leaf, MptNode::Leaf { .. }));
        assert!(matches!(extension, MptNode::Extension { .. }));
        assert!(matches!(branch, MptNode::Branch { .. }));
    }

    #[test]
    fn node_height_tracks_longest_path_to_leaf() {
        let node = MptNode::<[u8; 32]>::Extension {
            shared_prefix: NibblePath::from_key(&[0xA0]),
            child: Box::new(MptNode::Leaf {
                key_suffix: NibblePath::from_key(&[0xBC]),
                value: b"value".to_vec(),
            }),
        };

        assert_eq!(node.height(), 2);
    }

    #[test]
    fn rlp_encoding_of_empty_node_is_empty_string() {
        let encoded = rlp_encode(&MptNode::<[u8; 32]>::Empty);

        assert_eq!(encoded, vec![0x80]);
        assert_eq!(rlp_decode::<[u8; 32]>(&encoded).unwrap(), MptNode::Empty);
    }

    #[test]
    fn hp_encode_marks_even_and_odd_leaf_paths() {
        let even_path = NibblePath::from_key(&[0xAB]);
        let odd_path = even_path.slice(1);

        let even_encoded = hp_encode(&even_path, true);
        let odd_encoded = hp_encode(&odd_path, true);

        assert_eq!(even_encoded[0] >> 4, 0x2);
        assert_eq!(odd_encoded[0] >> 4, 0x3);
        assert_eq!(hp_decode(&even_encoded), (even_path, true));
        assert_eq!(hp_decode(&odd_encoded), (odd_path, true));
    }

    #[test]
    fn rlp_round_trips_leaf_node() {
        let node = MptNode::<[u8; 32]>::Leaf {
            key_suffix: NibblePath::from_key(b"leaf"),
            value: b"value".to_vec(),
        };

        assert_eq!(rlp_decode(&rlp_encode(&node)).unwrap(), node);
    }

    #[test]
    fn rlp_round_trips_extension_node() {
        let node = MptNode::<[u8; 32]>::Extension {
            shared_prefix: NibblePath::from_key(&[0xAB]),
            child: Box::new(MptNode::Leaf {
                key_suffix: NibblePath::from_key(&[0xCD]),
                value: b"value".to_vec(),
            }),
        };

        assert_eq!(rlp_decode(&rlp_encode(&node)).unwrap(), node);
    }

    #[test]
    fn rlp_round_trips_branch_node() {
        let mut children = MptNode::<[u8; 32]>::empty_children();
        let child = MptNode::<[u8; 32]>::Leaf {
            key_suffix: NibblePath::from_key(&[0xBC]),
            value: b"child".to_vec(),
        };
        children[10] = NodeRef::Inline(rlp_encode(&child));
        let node = MptNode::<[u8; 32]>::Branch {
            children,
            value: Some(b"branch".to_vec()),
        };

        assert_eq!(rlp_decode(&rlp_encode(&node)).unwrap(), node);
    }

    #[test]
    fn malformed_rlp_returns_rlp_error() {
        let result = rlp_decode::<[u8; 32]>(&[0xC1, 0x80]);

        assert!(matches!(result, Err(MerkleError::RlpError(_))));
    }

    #[test]
    fn malformed_hp_prefix_inside_rlp_returns_rlp_error() {
        let malformed_leaf = super::rlp_encode_list(&[
            super::rlp_encode_bytes(&[0x40]),
            super::rlp_encode_bytes(b"value"),
        ]);
        let result = rlp_decode::<[u8; 32]>(&malformed_leaf);

        assert!(matches!(result, Err(MerkleError::RlpError(_))));
    }

    #[test]
    fn empty_trie_root_matches_ethereum_known_hash() {
        let root = compute_root_hash::<Keccak256>(&MptNode::Empty);
        let expected = [
            0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0,
            0xf8, 0x6e, 0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5,
            0xe3, 0x63, 0xb4, 0x21,
        ];

        assert_eq!(root, expected);
    }

    #[test]
    fn hash_node_inlines_small_rlp_nodes() {
        let node = MptNode::<[u8; 32]>::Leaf {
            key_suffix: NibblePath::from_key(&[0x01]),
            value: b"x".to_vec(),
        };
        let rlp = rlp_encode(&node);

        assert!(rlp.len() < 32);
        assert_eq!(hash_node::<Keccak256>(&node), NodeRef::Inline(rlp));
    }

    #[test]
    fn hash_node_hashes_large_rlp_nodes() {
        let node = MptNode::<[u8; 32]>::Leaf {
            key_suffix: NibblePath::from_key(b"large"),
            value: vec![0xAB; 64],
        };

        assert!(rlp_encode(&node).len() >= 32);
        assert!(matches!(hash_node::<Keccak256>(&node), NodeRef::Hash(_)));
    }

    #[test]
    fn root_hash_computation_is_deterministic() {
        let node = MptNode::<[u8; 32]>::Leaf {
            key_suffix: NibblePath::from_key(b"deterministic"),
            value: b"value".to_vec(),
        };

        assert_eq!(
            compute_root_hash::<Blake3>(&node),
            compute_root_hash::<Blake3>(&node)
        );
    }

    #[test]
    fn insert_then_get_returns_value() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();

        assert_eq!(tree.get(b"key"), Some(&b"value"[..]));
        assert!(!tree.is_empty());
        assert!(tree.root().is_some());
    }

    #[test]
    fn get_missing_key_returns_none() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();
        tree.insert(b"key", b"value").unwrap();

        assert_eq!(tree.get(b"missing"), None);
    }

    #[test]
    fn shared_prefix_keys_are_retrievable_independently() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();
        tree.insert(b"keyboard", b"instrument").unwrap();

        assert_eq!(tree.get(b"key"), Some(&b"value"[..]));
        assert_eq!(tree.get(b"keyboard"), Some(&b"instrument"[..]));
    }

    #[test]
    fn one_hundred_inserted_pairs_are_retrievable() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        for index in 0_u8..100 {
            let key = [b'k', index];
            let value = [b'v', index];
            tree.insert(&key, &value).unwrap();
        }

        for index in 0_u8..100 {
            let key = [b'k', index];
            let value = [b'v', index];
            assert_eq!(tree.get(&key), Some(&value[..]));
        }
    }

    #[test]
    fn inserting_same_key_updates_value() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();
        tree.insert(b"key", b"updated").unwrap();

        assert_eq!(tree.get(b"key"), Some(&b"updated"[..]));
    }

    #[test]
    fn insert_rejects_empty_value_without_mutating() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        assert_eq!(tree.insert(b"key", b""), Err(MerkleError::EmptyLeafData));
        assert!(tree.is_empty());
        assert_eq!(tree.get(b"key"), None);
    }

    #[test]
    fn root_hash_changes_on_distinct_inserts() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"first", b"value-1").unwrap();
        let first_root = *tree.root().unwrap();
        tree.insert(b"second", b"value-2").unwrap();
        let second_root = *tree.root().unwrap();

        assert_ne!(first_root, second_root);
    }

    #[test]
    fn remove_deletes_existing_key() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();
        tree.remove(b"key").unwrap();

        assert_eq!(tree.get(b"key"), None);
        assert!(tree.is_empty());
        assert_eq!(tree.root(), None);
    }

    #[test]
    fn remove_missing_key_returns_error_without_mutating() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();
        tree.insert(b"key", b"value").unwrap();
        let root_before = *tree.root().unwrap();

        let result = tree.remove(b"missing");

        assert_eq!(
            result,
            Err(MerkleError::UnsupportedOperation(
                "remove missing Patricia key"
            ))
        );
        assert_eq!(tree.get(b"key"), Some(&b"value"[..]));
        assert_eq!(tree.root(), Some(&root_before));
    }

    #[test]
    fn removing_all_keys_returns_to_empty_trie() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"alpha", b"one").unwrap();
        tree.insert(b"beta", b"two").unwrap();
        tree.remove(b"alpha").unwrap();
        tree.remove(b"beta").unwrap();

        assert!(tree.is_empty());
        assert_eq!(tree.root(), None);
        assert_eq!(tree.node_count(), 0);
        assert_eq!(tree.height(), 0);
    }

    #[test]
    fn remove_collapses_to_canonical_remaining_subtree() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();
        let mut singleton = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();
        tree.insert(b"keyboard", b"instrument").unwrap();
        tree.remove(b"keyboard").unwrap();
        singleton.insert(b"key", b"value").unwrap();

        assert_eq!(tree.get(b"keyboard"), None);
        assert_eq!(tree.get(b"key"), Some(&b"value"[..]));
        assert_eq!(tree.root(), singleton.root());
        assert_eq!(tree.node_count(), singleton.node_count());
        assert_eq!(tree.height(), singleton.height());
    }

    #[test]
    fn membership_proof_for_inserted_key_verifies() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();
        tree.insert(b"keyboard", b"instrument").unwrap();
        let proof = tree.generate_proof(b"keyboard").unwrap();

        assert!(proof.is_membership());
        assert_eq!(proof.value, Some(b"instrument".to_vec()));
        assert!(MerklePatriciaTrie::<Keccak256>::verify_proof(
            tree.root().unwrap(),
            &proof
        ));
    }

    #[test]
    fn proof_root_node_hashes_to_trusted_root() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();
        let proof = tree.generate_proof(b"key").unwrap();

        assert_eq!(
            hash_mpt_bytes::<Keccak256>(&proof.proof_nodes[0]),
            *tree.root().unwrap()
        );
    }

    #[test]
    fn stale_proof_fails_after_key_is_removed() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();
        tree.insert(b"keyboard", b"instrument").unwrap();
        let proof = tree.generate_proof(b"key").unwrap();
        tree.remove(b"key").unwrap();

        assert!(!MerklePatriciaTrie::<Keccak256>::verify_proof(
            tree.root().unwrap(),
            &proof
        ));
    }

    #[test]
    fn non_membership_proof_for_absent_key_verifies() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();
        let proof = tree.generate_proof(b"missing").unwrap();

        assert!(proof.is_non_membership());
        assert_eq!(proof.value, None);
        assert!(MerklePatriciaTrie::<Keccak256>::verify_proof(
            tree.root().unwrap(),
            &proof
        ));
    }

    #[test]
    fn tampered_mpt_proof_fails_verification() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();
        let mut proof = tree.generate_proof(b"key").unwrap();
        proof.value = Some(b"tampered".to_vec());

        assert!(!MerklePatriciaTrie::<Keccak256>::verify_proof(
            tree.root().unwrap(),
            &proof
        ));
    }

    #[test]
    fn mpt_proof_round_trips_through_serializable() {
        let mut tree = MerklePatriciaTrie::<Keccak256>::new();

        tree.insert(b"key", b"value").unwrap();
        tree.insert(b"keyboard", b"instrument").unwrap();
        let proof = tree.generate_proof(b"key").unwrap();
        let encoded = proof.to_bytes().unwrap();
        let decoded = MptProof::<[u8; 32]>::from_bytes(&encoded).unwrap();

        assert_eq!(decoded, proof);
        assert!(MerklePatriciaTrie::<Keccak256>::verify_proof(
            tree.root().unwrap(),
            &decoded
        ));
    }
}
