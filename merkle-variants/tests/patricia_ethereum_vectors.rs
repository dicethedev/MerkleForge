use std::collections::BTreeMap;

use merkle_variants::MerklePatriciaTrie;
use merkle_variants::patricia::{MptNode, compute_root_hash};
use merkleforge_hash::Keccak256;
use serde_json::Value;

type Root = [u8; 32];
type OrderedOperation = (Vec<u8>, Option<Vec<u8>>);
type OrderedCase = (String, Vec<OrderedOperation>, Root);
type AnyOrderEntry = (Vec<u8>, Vec<u8>);
type AnyOrderCase = (String, Vec<AnyOrderEntry>, Root);

const EMPTY_TRIE_ROOT: [u8; 32] = [
    0x56, 0xe8, 0x1f, 0x17, 0x1b, 0xcc, 0x55, 0xa6, 0xff, 0x83, 0x45, 0xe6, 0x92, 0xc0, 0xf8, 0x6e,
    0x5b, 0x48, 0xe0, 0x1b, 0x99, 0x6c, 0xad, 0xc0, 0x01, 0x62, 0x2f, 0xb5, 0xe3, 0x63, 0xb4, 0x21,
];

#[test]
fn empty_trie_root_matches_ethereum_vector() {
    assert_eq!(
        compute_root_hash::<Keccak256>(&MptNode::Empty),
        EMPTY_TRIE_ROOT
    );
}

#[test]
fn official_trietest_vectors_match_ethereum_roots() {
    let cases = parse_ordered_cases(include_str!("fixtures/ethereum_trie/trietest.json"));

    for (name, operations, expected_root) in cases {
        let mut trie = MerklePatriciaTrie::<Keccak256>::new();
        for (key, value) in operations {
            apply_operation(&mut trie, &key, value.as_deref());
        }

        assert_eq!(root_or_empty(&trie), expected_root, "case {name}");
    }
}

#[test]
fn official_trieanyorder_vectors_match_ethereum_roots() {
    let cases = parse_any_order_cases(include_str!("fixtures/ethereum_trie/trieanyorder.json"));

    for (name, entries, expected_root) in cases {
        let mut insertion_order = MerklePatriciaTrie::<Keccak256>::new();
        for (key, value) in &entries {
            insertion_order.insert(key, value).unwrap();
        }

        let mut reverse_order = MerklePatriciaTrie::<Keccak256>::new();
        for (key, value) in entries.iter().rev() {
            reverse_order.insert(key, value).unwrap();
        }

        assert_eq!(
            root_or_empty(&insertion_order),
            expected_root,
            "case {name}"
        );
        assert_eq!(
            root_or_empty(&reverse_order),
            expected_root,
            "case {name} reversed"
        );
    }
}

fn parse_ordered_cases(json: &str) -> Vec<OrderedCase> {
    let value = serde_json::from_str::<Value>(json).expect("valid trietest.json");
    value
        .as_object()
        .expect("top-level object")
        .iter()
        .map(|(name, case)| {
            let operations = case["in"]
                .as_array()
                .expect("ordered operation list")
                .iter()
                .map(|operation| {
                    let operation = operation.as_array().expect("operation tuple");
                    let key = decode_test_bytes(operation[0].as_str().expect("key string"));
                    let value = match &operation[1] {
                        Value::Null => None,
                        Value::String(value) => Some(decode_test_bytes(value)),
                        _ => panic!("invalid operation value"),
                    };

                    (key, value)
                })
                .collect::<Vec<_>>();

            (name.clone(), operations, decode_root(case))
        })
        .collect()
}

fn parse_any_order_cases(json: &str) -> Vec<AnyOrderCase> {
    let value = serde_json::from_str::<Value>(json).expect("valid trieanyorder.json");
    value
        .as_object()
        .expect("top-level object")
        .iter()
        .map(|(name, case)| {
            let entries = case["in"]
                .as_object()
                .expect("key-value map")
                .iter()
                .map(|(key, value)| {
                    (
                        decode_test_bytes(key),
                        decode_test_bytes(value.as_str().expect("value string")),
                    )
                })
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect::<Vec<_>>();

            (name.clone(), entries, decode_root(case))
        })
        .collect()
}

fn apply_operation(trie: &mut MerklePatriciaTrie<Keccak256>, key: &[u8], value: Option<&[u8]>) {
    match value {
        Some([]) | None => {
            let _ = trie.remove(key);
        }
        Some(value) => trie.insert(key, value).unwrap(),
    }
}

fn root_or_empty(trie: &MerklePatriciaTrie<Keccak256>) -> [u8; 32] {
    trie.root()
        .copied()
        .unwrap_or_else(|| compute_root_hash::<Keccak256>(&MptNode::Empty))
}

fn decode_root(case: &Value) -> [u8; 32] {
    let root = case["root"]
        .as_str()
        .expect("root hex")
        .strip_prefix("0x")
        .expect("root has hex prefix");
    let bytes = decode_hex(root);
    bytes.try_into().expect("root is 32 bytes")
}

fn decode_test_bytes(value: &str) -> Vec<u8> {
    value
        .strip_prefix("0x")
        .map_or_else(|| value.as_bytes().to_vec(), decode_hex)
}

fn decode_hex(value: &str) -> Vec<u8> {
    assert!(
        value.len().is_multiple_of(2),
        "hex string must have even length"
    );

    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let high = hex_value(pair[0]);
            let low = hex_value(pair[1]);
            high << 4 | low
        })
        .collect()
}

fn hex_value(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        b'A'..=b'F' => byte - b'A' + 10,
        _ => panic!("invalid hex byte {byte:#x}"),
    }
}
