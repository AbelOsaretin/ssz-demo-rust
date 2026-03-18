use super::*;

#[test]
fn test_serialize_uint8() {
    assert_eq!(serialize(&SszValue::Uint8(0x12)), vec![0x12]);
}

#[test]
fn test_serialize_uint16_little_endian() {
    assert_eq!(serialize(&SszValue::Uint16(0x0100)), vec![0x00, 0x01]);
}

#[test]
fn test_serialize_bool() {
    assert_eq!(serialize(&SszValue::Bool(true)), vec![0x01]);
    assert_eq!(serialize(&SszValue::Bool(false)), vec![0x00]);
}

#[test]
fn test_serialize_null() {
    assert_eq!(serialize(&SszValue::Null), vec![]);
}

#[test]
fn test_serialize_fixed_vector() {
    let v = SszValue::Vector(vec![
        SszValue::Uint8(1),
        SszValue::Uint8(2),
        SszValue::Uint8(3),
    ]);
    assert_eq!(serialize(&v), vec![1, 2, 3]);
}

#[test]
fn test_serialize_container_fixed() {
    let c = SszValue::Container(vec![
        ("a".to_string(), SszValue::Uint16(1)),
        ("b".to_string(), SszValue::Uint16(2)),
    ]);
    assert_eq!(serialize(&c), vec![1, 0, 2, 0]);
}

#[test]
fn test_serialize_container_with_list() {
    // container { x: uint32(0x12345678), y: list([uint8(0xAB)]) }
    // Fixed section = 4 bytes for x + 4 bytes offset for y = 8 bytes
    // Offset for y = 8 (it starts right after the fixed section)
    // Variable section = [0xAB]
    let c = SszValue::Container(vec![
        ("x".to_string(), SszValue::Uint32(0x12345678)),
        ("y".to_string(), SszValue::List(vec![SszValue::Uint8(0xAB)])),
    ]);
    let expected = vec![0x78, 0x56, 0x34, 0x12, 0x08, 0x00, 0x00, 0x00, 0xAB];
    assert_eq!(serialize(&c), expected);
}

#[test]
fn test_serialize_union() {
    let u = SszValue::Union {
        type_index: 1,
        value: Box::new(SszValue::Uint32(42)),
    };
    assert_eq!(serialize(&u), vec![1, 0, 0, 0, 42, 0, 0, 0]);
}

#[test]
fn test_is_variable_size_basics() {
    assert!(!is_variable_size(&SszValue::Uint64(0)));
    assert!(!is_variable_size(&SszValue::Bool(true)));
    assert!(is_variable_size(&SszValue::List(vec![])));
    assert!(is_variable_size(&SszValue::Union {
        type_index: 0,
        value: Box::new(SszValue::Null)
    }));
}

#[test]
fn test_is_variable_size_container() {
    let c = SszValue::Container(vec![("a".to_string(), SszValue::List(vec![]))]);
    assert!(is_variable_size(&c));
    let c2 = SszValue::Container(vec![("a".to_string(), SszValue::Uint64(1))]);
    assert!(!is_variable_size(&c2));
}

#[test]
fn test_hash_tree_root_bool_false() {
    // pack(false) = [0x00, ...zeros] → one zero chunk → merkleize returns it as-is
    assert_eq!(hash_tree_root(&SszValue::Bool(false)), [0u8; 32]);
}

#[test]
fn test_hash_tree_root_bool_true() {
    let mut expected = [0u8; 32];
    expected[0] = 0x01;
    assert_eq!(hash_tree_root(&SszValue::Bool(true)), expected);
}

#[test]
fn test_mix_in_length_changes_root() {
    let base = [1u8; 32];
    assert_ne!(mix_in_length(base, 0), mix_in_length(base, 1));
}

#[test]
fn test_signing_root() {
    let c = SszValue::Container(vec![
        ("data".to_string(), SszValue::Uint64(999)),
        ("signature".to_string(), SszValue::Uint64(0xDEADBEEF)),
    ]);
    let expected = hash_tree_root(&SszValue::Container(vec![(
        "data".to_string(),
        SszValue::Uint64(999),
    )]));
    assert_eq!(signing_root(&c), expected);
}

#[test]
fn test_hash_tree_root_list_vs_vector_differs() {
    // A list and vector with same elements should have different roots
    // because lists mix in length
    let elements = vec![SszValue::Uint64(1), SszValue::Uint64(2)];
    let list_root = hash_tree_root(&SszValue::List(elements.clone()));
    let vec_root = hash_tree_root(&SszValue::Vector(elements));
    assert_ne!(list_root, vec_root);
}
