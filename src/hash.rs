//! Hash utilities for Git objects with selectable algorithms (SHA-1 and SHA-256).
//! Hash kind is stored thread-locally; set once at startup to match your repository format.
//! Defaults to SHA-1.

use std::{cell::RefCell, fmt::Display, hash::Hash, io, str::FromStr};

use colored::Colorize;
use sha1::Digest;

use crate::internal::object::types::ObjectType;

/// Supported hash algorithms for object IDs (selector only, no data attached).
/// Used to configure which hash algorithm to use globally (thread-local).
/// Defaults to SHA-1.
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Default,
    serde::Deserialize,
    serde::Serialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
pub enum HashKind {
    #[default]
    Sha1,
    Sha256,
}
impl HashKind {
    /// Byte length of the hash output.
    pub const fn size(&self) -> usize {
        match self {
            HashKind::Sha1 => 20,
            HashKind::Sha256 => 32,
            // Add more hash kinds here as needed
        }
    }
    /// Hex string length of the hash output.
    pub const fn hex_len(&self) -> usize {
        match self {
            HashKind::Sha1 => 40,
            HashKind::Sha256 => 64,
        }
    }
    /// Lowercase name of the hash algorithm.
    pub const fn as_str(&self) -> &'static str {
        match self {
            HashKind::Sha1 => "sha1",
            HashKind::Sha256 => "sha256",
        }
    }
}
impl std::fmt::Display for HashKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
impl std::str::FromStr for HashKind {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "sha1" => Ok(HashKind::Sha1),
            "sha256" => Ok(HashKind::Sha256),
            _ => Err("Invalid hash kind".to_string()),
        }
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    serde::Deserialize,
    serde::Serialize,
    rkyv::Archive,
    rkyv::Serialize,
    rkyv::Deserialize,
)]
/// Concrete object ID value carrying the bytes for the selected algorithm (SHA-1 or SHA-256).
/// Used for Git object hashes.
/// Supports conversion to/from hex strings, byte slices, and stream reading.
pub enum ObjectHash {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
}
impl Default for ObjectHash {
    fn default() -> Self {
        ObjectHash::Sha1([0u8; 20])
    }
}
impl Display for ObjectHash {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.as_ref()))
    }
}
impl AsRef<[u8]> for ObjectHash {
    fn as_ref(&self) -> &[u8] {
        match self {
            ObjectHash::Sha1(bytes) => bytes.as_slice(),
            ObjectHash::Sha256(bytes) => bytes.as_slice(),
        }
    }
}
/// Parse hex (40 for SHA1, 64 for SHA-256) into `ObjectHash`.
impl FromStr for ObjectHash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.len() {
            40 => {
                let mut h = [0u8; 20];
                let bytes = hex::decode(s).map_err(|e| e.to_string())?;
                h.copy_from_slice(bytes.as_slice());
                Ok(ObjectHash::Sha1(h))
            }
            64 => {
                let mut h = [0u8; 32];
                let bytes = hex::decode(s).map_err(|e| e.to_string())?;
                h.copy_from_slice(bytes.as_slice());
                Ok(ObjectHash::Sha256(h))
            }
            _ => Err("Invalid hash length".to_string()),
        }
    }
}

impl ObjectHash {
    /// Zero-filled hex string for a given hash kind.
    pub fn zero_str(kind: HashKind) -> String {
        match kind {
            HashKind::Sha1 => "0000000000000000000000000000000000000000".to_string(),
            HashKind::Sha256 => {
                "0000000000000000000000000000000000000000000000000000000000000000".to_string()
            }
        }
    }

    /// Return the hash kind for this value.
    pub fn kind(&self) -> HashKind {
        match self {
            ObjectHash::Sha1(_) => HashKind::Sha1,
            ObjectHash::Sha256(_) => HashKind::Sha256,
        }
    }
    /// Return the hash size in bytes.
    pub fn size(&self) -> usize {
        self.kind().size()
    }

    /// Compute hash of data using current thread-local `HashKind`.
    pub fn new(data: &[u8]) -> ObjectHash {
        match get_hash_kind() {
            HashKind::Sha1 => {
                let h = sha1::Sha1::digest(data);
                let mut bytes = [0u8; 20];
                bytes.copy_from_slice(h.as_ref());
                ObjectHash::Sha1(bytes)
            }
            HashKind::Sha256 => {
                let h = sha2::Sha256::digest(data);
                let mut bytes = [0u8; 32];
                bytes.copy_from_slice(h.as_ref());
                ObjectHash::Sha256(bytes)
            }
        }
    }
    /// Create ObjectHash from object type and data
    pub fn from_type_and_data(object_type: ObjectType, data: &[u8]) -> ObjectHash {
        let mut d: Vec<u8> = Vec::new();
        d.extend(object_type.to_data().unwrap());
        d.push(b' ');
        d.extend(data.len().to_string().as_bytes());
        d.push(b'\x00');
        d.extend(data);
        ObjectHash::new(&d)
    }
    /// Create `ObjectHash` from raw bytes matching the current hash size.
    pub fn from_bytes(bytes: &[u8]) -> Result<ObjectHash, String> {
        let expected_len = get_hash_kind().size();
        if bytes.len() != expected_len {
            return Err(format!(
                "Invalid byte length: got {}, expected {}",
                bytes.len(),
                expected_len
            ));
        }

        match get_hash_kind() {
            HashKind::Sha1 => {
                let mut h = [0u8; 20];
                h.copy_from_slice(bytes);
                Ok(ObjectHash::Sha1(h))
            }
            HashKind::Sha256 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(bytes);
                Ok(ObjectHash::Sha256(h))
            }
        }
    }
    /// Create `ObjectHash` from raw bytes, inferring the hash kind from the
    /// byte length (20 → SHA-1, 32 → SHA-256).
    ///
    /// Unlike [`ObjectHash::from_bytes`], this does not consult the
    /// thread-local [`HashKind`], so it is safe on threads where
    /// [`set_hash_kind`] was never called. The pack encoder finalizes its
    /// running checksum on whichever async worker thread happens to run the
    /// task; the checksum bytes already carry the correct length, while the
    /// worker's thread-local may still hold the default SHA-1 kind — the
    /// mismatch used to panic with "Invalid byte length: got 32, expected 20".
    pub fn from_bytes_infer_kind(bytes: &[u8]) -> Result<ObjectHash, String> {
        match bytes.len() {
            20 => {
                let mut h = [0u8; 20];
                h.copy_from_slice(bytes);
                Ok(ObjectHash::Sha1(h))
            }
            32 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(bytes);
                Ok(ObjectHash::Sha256(h))
            }
            other => Err(format!(
                "Invalid byte length: got {other}, expected 20 (SHA-1) or 32 (SHA-256)"
            )),
        }
    }
    /// Read hash bytes from a stream according to current hash size.
    pub fn from_stream(data: &mut impl io::Read) -> io::Result<ObjectHash> {
        match get_hash_kind() {
            HashKind::Sha1 => {
                let mut h = [0u8; 20];
                data.read_exact(&mut h)?;
                Ok(ObjectHash::Sha1(h))
            }
            HashKind::Sha256 => {
                let mut h = [0u8; 32];
                data.read_exact(&mut h)?;
                Ok(ObjectHash::Sha256(h))
            }
        }
    }

    /// Format hash as colored string (for terminal display).
    pub fn to_color_str(self) -> String {
        self.to_string().red().bold().to_string()
    }

    /// Return raw bytes of the hash.
    pub fn to_data(self) -> Vec<u8> {
        self.as_ref().to_vec()
    }

    /// Faster string conversion than `Display`.
    pub fn _to_string(&self) -> String {
        hex::encode(self.as_ref())
    }

    /// Get mutable access to inner byte slice.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        match self {
            ObjectHash::Sha1(bytes) => bytes.as_mut_slice(),
            ObjectHash::Sha256(bytes) => bytes.as_mut_slice(),
        }
    }
}

thread_local! {
    /// Thread-local variable to store the current hash kind.
    /// This allows different threads to work with different hash algorithms concurrently
    /// without interfering with each other.
    static CURRENT_HASH_KIND: RefCell<HashKind> = RefCell::new(HashKind::default());
}
/// Set the thread-local hash kind (configure once at startup to match repo format).
pub fn set_hash_kind(kind: HashKind) {
    CURRENT_HASH_KIND.with(|h| {
        *h.borrow_mut() = kind;
    });
}

/// Retrieves the hash kind for the current thread.
pub fn get_hash_kind() -> HashKind {
    CURRENT_HASH_KIND.with(|h| *h.borrow())
}
/// A guard to reset the hash kind after the test
pub struct HashKindGuard {
    prev: HashKind,
}
/// Implementation of the `Drop` trait for the `HashKindGuard` struct.
impl Drop for HashKindGuard {
    fn drop(&mut self) {
        set_hash_kind(self.prev);
    }
}
/// Sets the hash kind for the current thread and returns a guard to reset it later.
pub fn set_hash_kind_for_test(kind: HashKind) -> HashKindGuard {
    let prev = get_hash_kind();
    set_hash_kind(kind);
    HashKindGuard { prev }
}
#[cfg(test)]
mod tests {

    use std::{
        io::{BufReader, Read, Seek, SeekFrom},
        str::FromStr,
    };

    use crate::{
        hash::{HashKind, ObjectHash, set_hash_kind_for_test},
        internal::pack::test_pack_download::download_pack_file,
    };

    /// Hashing "Hello, world!" with SHA1 should match known value.
    #[test]
    fn test_sha1_new() {
        // Set hash kind to SHA1 for this test
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        // Example input
        let data = "Hello, world!".as_bytes();

        // Generate SHA1 hash from the input data
        let sha1 = ObjectHash::new(data);

        // Known SHA1 hash for "Hello, world!"
        let expected_sha1_hash = "943a702d06f34599aee1f8da8ef9f7296031d699";

        assert_eq!(sha1.to_string(), expected_sha1_hash);
    }

    /// Hashing "Hello, world!" with SHA256 should match known value.
    #[test]
    fn test_sha256_new() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let data = "Hello, world!".as_bytes();
        let sha256 = ObjectHash::new(data);
        let expected_sha256_hash =
            "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";
        assert_eq!(sha256.to_string(), expected_sha256_hash);
    }

    /// Read pack trailer for SHA1 pack should yield SHA1 hash.
    #[test]
    fn test_signature_without_delta() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let (source, _dl_guard) = download_pack_file("small-sha1.pack");

        let f = std::fs::File::open(source).unwrap();
        let mut buffered = BufReader::new(f);

        buffered.seek(SeekFrom::End(-20)).unwrap();
        let mut buffer = vec![0; 20];
        buffered.read_exact(&mut buffer).unwrap();
        let signature = ObjectHash::from_bytes(buffer.as_ref()).unwrap();
        assert_eq!(signature.kind(), HashKind::Sha1);
    }

    /// Read pack trailer for SHA256 pack should yield SHA256 hash.
    #[test]
    fn test_signature_without_delta_sha256() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let (source, _dl_guard) = download_pack_file("small-sha256.pack");

        let f = std::fs::File::open(source).unwrap();
        let mut buffered = BufReader::new(f);

        buffered.seek(SeekFrom::End(-32)).unwrap();
        let mut buffer = vec![0; 32];
        buffered.read_exact(&mut buffer).unwrap();
        let signature = ObjectHash::from_bytes(buffer.as_ref()).unwrap();
        assert_eq!(signature.kind(), HashKind::Sha256);
    }

    /// Construct SHA1 from raw bytes.
    #[test]
    fn test_sha1_from_bytes() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let sha1 = ObjectHash::from_bytes(&[
            0x8a, 0xb6, 0x86, 0xea, 0xfe, 0xb1, 0xf4, 0x47, 0x02, 0x73, 0x8c, 0x8b, 0x0f, 0x24,
            0xf2, 0x56, 0x7c, 0x36, 0xda, 0x6d,
        ])
        .unwrap();

        assert_eq!(sha1.to_string(), "8ab686eafeb1f44702738c8b0f24f2567c36da6d");
    }

    /// Construct SHA256 from raw bytes.
    #[test]
    fn test_sha256_from_bytes() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        // Pre-calculated SHA256 hash for "abc"
        let sha256 = ObjectHash::from_bytes(&[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ])
        .unwrap();

        assert_eq!(
            sha256.to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Read hash from stream for SHA1.
    #[test]
    fn test_from_stream() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let source = [
            0x8a, 0xb6, 0x86, 0xea, 0xfe, 0xb1, 0xf4, 0x47, 0x02, 0x73, 0x8c, 0x8b, 0x0f, 0x24,
            0xf2, 0x56, 0x7c, 0x36, 0xda, 0x6d,
        ];
        let mut reader = std::io::Cursor::new(source);
        let sha1 = ObjectHash::from_stream(&mut reader).unwrap();
        assert_eq!(sha1.to_string(), "8ab686eafeb1f44702738c8b0f24f2567c36da6d");
    }

    /// Read hash from stream for SHA256.
    #[test]
    fn test_sha256_from_stream() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let source = [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad,
        ];
        let mut reader = std::io::Cursor::new(source);
        let sha256 = ObjectHash::from_stream(&mut reader).unwrap();
        assert_eq!(
            sha256.to_string(),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    /// Parse SHA1 from hex string.
    #[test]
    fn test_sha1_from_str() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let hash_str = "8ab686eafeb1f44702738c8b0f24f2567c36da6d";

        match ObjectHash::from_str(hash_str) {
            Ok(hash) => {
                assert_eq!(hash.to_string(), "8ab686eafeb1f44702738c8b0f24f2567c36da6d");
            }
            Err(e) => println!("Error: {e}"),
        }
    }

    /// Parse SHA256 from hex string.
    #[test]
    fn test_sha256_from_str() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let hash_str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

        match ObjectHash::from_str(hash_str) {
            Ok(hash) => {
                assert_eq!(
                    hash.to_string(),
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                );
            }
            Err(e) => println!("Error: {e}"),
        }
    }

    /// SHA1 to_string should round-trip.
    #[test]
    fn test_sha1_to_string() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let hash_str = "8ab686eafeb1f44702738c8b0f24f2567c36da6d";

        match ObjectHash::from_str(hash_str) {
            Ok(hash) => {
                assert_eq!(hash.to_string(), "8ab686eafeb1f44702738c8b0f24f2567c36da6d");
            }
            Err(e) => println!("Error: {e}"),
        }
    }

    /// SHA256 to_string should round-trip.
    #[test]
    fn test_sha256_to_string() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let hash_str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        match ObjectHash::from_str(hash_str) {
            Ok(hash) => {
                assert_eq!(
                    hash.to_string(),
                    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                );
            }
            Err(e) => println!("Error: {e}"),
        }
    }

    /// SHA1 to_data should produce expected bytes.
    #[test]
    fn test_sha1_to_data() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let hash_str = "8ab686eafeb1f44702738c8b0f24f2567c36da6d";

        match ObjectHash::from_str(hash_str) {
            Ok(hash) => {
                assert_eq!(
                    hash.to_data(),
                    vec![
                        0x8a, 0xb6, 0x86, 0xea, 0xfe, 0xb1, 0xf4, 0x47, 0x02, 0x73, 0x8c, 0x8b,
                        0x0f, 0x24, 0xf2, 0x56, 0x7c, 0x36, 0xda, 0x6d
                    ]
                );
            }
            Err(e) => println!("Error: {e}"),
        }
    }

    /// SHA256 to_data should produce expected bytes.
    #[test]
    fn test_sha256_to_data() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let hash_str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
        match ObjectHash::from_str(hash_str) {
            Ok(hash) => {
                assert_eq!(
                    hash.to_data(),
                    vec![
                        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde,
                        0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad,
                    ]
                );
            }
            Err(e) => println!("Error: {e}"),
        }
    }
}
