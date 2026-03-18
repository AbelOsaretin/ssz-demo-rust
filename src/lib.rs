use sha2::{Digest, Sha256};

// ---- Constants from the spec --------------------------------
const BYTES_PER_CHUNK: usize = 32;
const BYTES_PER_LENGTH_OFFSET: usize = 4;
const BITS_PER_BYTE: usize = 8;

#[derive(Debug, Clone, PartialEq)]
pub enum SszValue {
    // Basic types
    Uint8(u8),
    Uint16(u16),
    Uint32(u32),
    Uint64(u64),
    Uint128(u128),
    // u256 is not natively in Rust, so we store 32 raw bytes (little-endian)
    Uint256([u8; 32]),
    Bool(bool),
    // "null" is the empty container
    Null,

    // Composite types
    Vector(Vec<SszValue>),
    List(Vec<SszValue>),
    Container(Vec<(String, SszValue)>),
    Union {
        type_index: u32,
        value: Box<SszValue>,
    },
}

// ---- Helper: is this value variable-size? -------------------
pub fn is_variable_size(val: &SszValue) -> bool {
    match val {
        SszValue::Uint8(_)
        | SszValue::Uint16(_)
        | SszValue::Uint32(_)
        | SszValue::Uint64(_)
        | SszValue::Uint128(_)
        | SszValue::Uint256(_)
        | SszValue::Bool(_)
        | SszValue::Null => false,
        SszValue::List(_) => true,
        SszValue::Union { .. } => true,
        SszValue::Vector(elements) => elements.iter().any(is_variable_size),
        SszValue::Container(fields) => fields.iter().any(|(_, v)| is_variable_size(v)),
    }
}

// ---- Serialization ------------------------------------------
pub fn serialize(val: &SszValue) -> Vec<u8> {
    match val {
        SszValue::Uint8(n) => n.to_le_bytes().to_vec(),
        SszValue::Uint16(n) => n.to_le_bytes().to_vec(),
        SszValue::Uint32(n) => n.to_le_bytes().to_vec(),
        SszValue::Uint64(n) => n.to_le_bytes().to_vec(),
        SszValue::Uint128(n) => n.to_le_bytes().to_vec(),
        SszValue::Uint256(bytes) => bytes.to_vec(),
        SszValue::Bool(b) => vec![if *b { 0x01 } else { 0x00 }],
        SszValue::Null => vec![],
        SszValue::Vector(elements) | SszValue::List(elements) => serialize_sequence(elements),
        SszValue::Container(fields) => {
            let values: Vec<SszValue> = fields.iter().map(|(_, v)| v.clone()).collect();
            serialize_sequence(&values)
        }
        SszValue::Union { type_index, value } => {
            let mut result = type_index.to_le_bytes().to_vec();
            result.extend(serialize(value));
            result
        }
    }
}

fn serialize_sequence(elements: &[SszValue]) -> Vec<u8> {
    // For each element: serialize if fixed-size, or mark as None (placeholder for offset)
    let fixed_parts: Vec<Option<Vec<u8>>> = elements
        .iter()
        .map(|e| {
            if !is_variable_size(e) {
                Some(serialize(e))
            } else {
                None
            }
        })
        .collect();

    let variable_parts: Vec<Vec<u8>> = elements
        .iter()
        .map(|e| {
            if is_variable_size(e) {
                serialize(e)
            } else {
                vec![]
            }
        })
        .collect();

    // Total size of the fixed section (offsets count as BYTES_PER_LENGTH_OFFSET each)
    let total_fixed: usize = fixed_parts
        .iter()
        .map(|p| p.as_ref().map_or(BYTES_PER_LENGTH_OFFSET, |b| b.len()))
        .sum();

    let total_variable: usize = variable_parts.iter().map(|p| p.len()).sum();

    let max_size: u64 = 1u64 << (BYTES_PER_LENGTH_OFFSET * BITS_PER_BYTE);
    assert!(
        (total_fixed + total_variable) as u64 <= max_size,
        "SSZ object too large"
    );

    // Compute where each variable-size element starts in the final output
    let mut offset_cursor = total_fixed;
    let variable_offsets: Vec<Vec<u8>> = elements
        .iter()
        .enumerate()
        .map(|(i, _)| {
            if is_variable_size(&elements[i]) {
                let offset_bytes = (offset_cursor as u32).to_le_bytes().to_vec();
                offset_cursor += variable_parts[i].len();
                offset_bytes
            } else {
                vec![]
            }
        })
        .collect();

    // Build final fixed section (real bytes + offset placeholders interleaved)
    let final_fixed: Vec<u8> = fixed_parts
        .iter()
        .enumerate()
        .flat_map(|(i, part)| match part {
            Some(bytes) => bytes.clone(),
            None => variable_offsets[i].clone(),
        })
        .collect();

    let final_variable: Vec<u8> = variable_parts.into_iter().flatten().collect();
    [final_fixed, final_variable].concat()
}

// ---- Merkleization ------------------------------------------

fn hash_two_chunks(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

// Serialize a value and split into 32-byte chunks (zero-padded)
fn pack(val: &SszValue) -> Vec<[u8; 32]> {
    let bytes = serialize(val);
    if bytes.is_empty() {
        return vec![[0u8; 32]];
    }
    bytes
        .chunks(BYTES_PER_CHUNK)
        .map(|chunk| {
            let mut padded = [0u8; 32];
            padded[..chunk.len()].copy_from_slice(chunk);
            padded
        })
        .collect()
}

// Build a Merkle tree from chunks, padding to next power-of-two
fn merkleize(mut chunks: Vec<[u8; 32]>) -> [u8; 32] {
    if chunks.is_empty() {
        return [0u8; 32];
    }
    let next_pow2 = chunks.len().next_power_of_two();
    chunks.resize(next_pow2, [0u8; 32]);

    while chunks.len() > 1 {
        chunks = chunks
            .chunks(2)
            .map(|pair| hash_two_chunks(&pair[0], &pair[1]))
            .collect();
    }
    chunks[0]
}

fn mix_in_length(root: [u8; 32], length: usize) -> [u8; 32] {
    let mut length_bytes = [0u8; 32];
    length_bytes[..8].copy_from_slice(&(length as u64).to_le_bytes());
    let mut hasher = Sha256::new();
    hasher.update(root);
    hasher.update(length_bytes);
    hasher.finalize().into()
}

fn mix_in_type(root: [u8; 32], type_index: u32) -> [u8; 32] {
    let mut type_bytes = [0u8; 32];
    type_bytes[..4].copy_from_slice(&type_index.to_le_bytes());
    let mut hasher = Sha256::new();
    hasher.update(root);
    hasher.update(type_bytes);
    hasher.finalize().into()
}

fn is_basic(val: &SszValue) -> bool {
    matches!(
        val,
        SszValue::Uint8(_)
            | SszValue::Uint16(_)
            | SszValue::Uint32(_)
            | SszValue::Uint64(_)
            | SszValue::Uint128(_)
            | SszValue::Uint256(_)
            | SszValue::Bool(_)
            | SszValue::Null
    )
}

fn pack_elements(elements: &[SszValue]) -> Vec<[u8; 32]> {
    let mut all_bytes = Vec::new();
    for e in elements {
        all_bytes.extend(serialize(e));
    }
    if all_bytes.is_empty() {
        return vec![[0u8; 32]];
    }
    all_bytes
        .chunks(BYTES_PER_CHUNK)
        .map(|c| {
            let mut padded = [0u8; 32];
            padded[..c.len()].copy_from_slice(c);
            padded
        })
        .collect()
}

pub fn hash_tree_root(val: &SszValue) -> [u8; 32] {
    match val {
        // Basic types: pack into 32-byte chunks, then merkleize
        SszValue::Uint8(_)
        | SszValue::Uint16(_)
        | SszValue::Uint32(_)
        | SszValue::Uint64(_)
        | SszValue::Uint128(_)
        | SszValue::Uint256(_)
        | SszValue::Bool(_)
        | SszValue::Null => merkleize(pack(val)),

        // Vector: check if elements are all basic or all composite
        SszValue::Vector(elements) => {
            if elements.iter().all(is_basic) {
                // Pack all element bytes together, then merkleize
                merkleize(pack_elements(elements))
            } else {
                // Hash each composite element, then merkleize the hashes
                let hashes: Vec<[u8; 32]> = elements.iter().map(hash_tree_root).collect();
                merkleize(hashes)
            }
        }

        // List: same as vector but mix in the length at the end
        SszValue::List(elements) => {
            let root = if elements.iter().all(is_basic) {
                merkleize(pack_elements(elements))
            } else {
                let hashes: Vec<[u8; 32]> = elements.iter().map(hash_tree_root).collect();
                let chunks = if hashes.is_empty() {
                    vec![[0u8; 32]]
                } else {
                    hashes
                };
                merkleize(chunks)
            };
            mix_in_length(root, elements.len())
        }

        // Container: hash each field value, then merkleize the hashes
        SszValue::Container(fields) => {
            let hashes: Vec<[u8; 32]> = fields.iter().map(|(_, v)| hash_tree_root(v)).collect();
            merkleize(hashes)
        }

        // Union: merkleize the inner value, then mix in the type index
        SszValue::Union { type_index, value } => {
            let root = hash_tree_root(value);
            mix_in_type(root, *type_index)
        }
    }
}

// ---- Signing root (self-signed containers) ------------------
pub fn signing_root(container: &SszValue) -> [u8; 32] {
    match container {
        SszValue::Container(fields) => {
            let truncated = fields[..fields.len() - 1].to_vec();
            hash_tree_root(&SszValue::Container(truncated))
        }
        _ => panic!("signing_root only works on containers"),
    }
}

#[cfg(test)]
mod tests;

// ---- Main: demonstration ------------------------------------
fn main() {
    println!("=== SimpleSerialize (SSZ) Demo ===\n");

    // Serialization examples
    println!("-- Serialization --");
    println!(
        "uint64(12345678)   = {:?}",
        serialize(&SszValue::Uint64(12345678))
    );
    println!(
        "bool(true)         = {:?}",
        serialize(&SszValue::Bool(true))
    );
    println!(
        "bool(false)        = {:?}",
        serialize(&SszValue::Bool(false))
    );
    println!("null               = {:?}", serialize(&SszValue::Null));

    let block_header = SszValue::Container(vec![
        ("slot".to_string(), SszValue::Uint64(42)),
        ("proposer_index".to_string(), SszValue::Uint64(7)),
    ]);
    println!(
        "container{{slot:42, proposer_index:7}} = {:?}",
        serialize(&block_header)
    );

    let validator = SszValue::Container(vec![
        ("index".to_string(), SszValue::Uint64(1)),
        (
            "balances".to_string(),
            SszValue::List(vec![
                SszValue::Uint64(32_000_000_000),
                SszValue::Uint64(31_000_000_000),
            ]),
        ),
    ]);
    println!("container with list = {:?}", serialize(&validator));

    let union_val = SszValue::Union {
        type_index: 1,
        value: Box::new(SszValue::Uint64(999)),
    };
    println!("union(1, uint64(999)) = {:?}", serialize(&union_val));

    // Merkleization examples
    println!("\n-- Merkleization (hash_tree_root) --");
    println!(
        "hash_tree_root(bool(true))   = {}",
        hex(&hash_tree_root(&SszValue::Bool(true)))
    );
    println!(
        "hash_tree_root(uint64(0))    = {}",
        hex(&hash_tree_root(&SszValue::Uint64(0)))
    );
    println!(
        "hash_tree_root(uint64(1))    = {}",
        hex(&hash_tree_root(&SszValue::Uint64(1)))
    );

    let list_val = SszValue::List(vec![
        SszValue::Uint64(1),
        SszValue::Uint64(2),
        SszValue::Uint64(3),
    ]);
    println!(
        "hash_tree_root(list[1,2,3])  = {}",
        hex(&hash_tree_root(&list_val))
    );
    println!(
        "hash_tree_root(block_header) = {}",
        hex(&hash_tree_root(&block_header))
    );

    // Self-signed container
    println!("\n-- Signing Root --");
    let signed_block = SszValue::Container(vec![
        ("slot".to_string(), SszValue::Uint64(100)),
        ("proposer_index".to_string(), SszValue::Uint64(5)),
        ("signature".to_string(), SszValue::Uint64(0xABCDEF)), // stand-in for BLS sig
    ]);
    println!(
        "signing_root(signed_block) = {}",
        hex(&signing_root(&signed_block))
    );
    println!("(excludes the signature field — this is what the validator signs)");
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}
