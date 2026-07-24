//! Merkle Patricia trie implementation.
//!
//! [`MerklePatriciaTrie`] models Ethereum's nibble-addressed Merkle Patricia
//! Trie shape. This module currently defines the core node structure,
//! nibble-path utilities, and empty-trie metadata. Mutation, RLP encoding, and
//! root hashing are added in later Phase 4 issues.

use std::marker::PhantomData;

use merkle_core::{error::MerkleError, traits::HashFunction};

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
pub fn rlp_encode<D>(node: &MptNode<D>) -> Vec<u8> {
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
            items.extend(children.iter().map(|child| rlp_encode(child)));
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
pub fn rlp_decode<D>(bytes: &[u8]) -> Result<MptNode<D>, MerkleError> {
    let (item, consumed) = parse_rlp_item(bytes)?;
    if consumed != bytes.len() {
        return Err(MerkleError::RlpError(
            "trailing bytes after RLP item".to_string(),
        ));
    }

    decode_node_item(&item)
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
        children: [Box<MptNode<D>>; 16],
        /// Value stored exactly at this branch path, if any.
        value: Option<Vec<u8>>,
    },

    #[doc(hidden)]
    __DigestMarker(PhantomData<D>),
}

impl<D> MptNode<D> {
    #[cfg(test)]
    fn empty_children() -> [Box<Self>; 16] {
        std::array::from_fn(|_| Box::new(Self::Empty))
    }

    fn height(&self) -> usize {
        match self {
            Self::Empty | Self::__DigestMarker(_) => 0,
            Self::Leaf { .. } => 1,
            Self::Extension { child, .. } => 1 + child.height(),
            Self::Branch { children, .. } => {
                1 + children
                    .iter()
                    .map(|child| child.height())
                    .max()
                    .unwrap_or(0)
            }
        }
    }
}

/// Ethereum-style Merkle Patricia Trie over nibble-addressed keys.
///
/// The trie starts empty. Later Phase 4 work will add mutation, RLP
/// serialization, and root hashing.
pub struct MerklePatriciaTrie<H: HashFunction> {
    root: MptNode<H::Digest>,
    node_count: usize,
    _marker: PhantomData<H>,
}

impl<H: HashFunction> MerklePatriciaTrie<H> {
    /// Creates an empty Merkle Patricia Trie.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            root: MptNode::Empty,
            node_count: 0,
            _marker: PhantomData,
        }
    }

    /// Returns the current root digest, or `None` for an empty trie.
    ///
    /// Root hashing is introduced in a later Phase 4 issue, so the current
    /// structural skeleton reports no digest.
    #[must_use]
    pub const fn root(&self) -> Option<&H::Digest> {
        None
    }

    /// Returns `true` when the trie contains no materialized nodes.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.node_count == 0
    }

    /// Returns the number of materialized trie nodes.
    #[must_use]
    pub const fn node_count(&self) -> usize {
        self.node_count
    }

    /// Returns the longest node path from the root to any leaf.
    #[must_use]
    pub fn height(&self) -> usize {
        self.root.height()
    }
}

impl<H: HashFunction> Default for MerklePatriciaTrie<H> {
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

fn decode_node_item<D>(item: &RlpItem) -> Result<MptNode<D>, MerkleError> {
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

fn decode_leaf_or_extension<D>(items: &[Vec<u8>]) -> Result<MptNode<D>, MerkleError> {
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

fn decode_branch<D>(items: &[Vec<u8>]) -> Result<MptNode<D>, MerkleError> {
    let mut children = Vec::with_capacity(16);
    for item in &items[..16] {
        if is_rlp_empty(item) {
            children.push(Box::new(MptNode::Empty));
        } else {
            children.push(Box::new(rlp_decode(item)?));
        }
    }
    let children = children.try_into().map_err(|_| {
        MerkleError::RlpError("branch node must contain exactly 16 children".to_string())
    })?;
    let value = decode_rlp_bytes(&items[16])?;
    let value = if value.is_empty() { None } else { Some(value) };

    Ok(MptNode::Branch { children, value })
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
    use merkleforge_hash::Keccak256;

    use super::{
        MerklePatriciaTrie, MptNode, NibblePath, hp_decode, hp_encode, rlp_decode, rlp_encode,
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
        *children[10] = MptNode::Leaf {
            key_suffix: NibblePath::from_key(&[0xBC]),
            value: b"child".to_vec(),
        };
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
}
