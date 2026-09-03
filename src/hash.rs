//! Hash utilities for Git objects with selectable algorithms (SHA-1, SHA-256 and
//! BLAKE3-256).
//!
//! # Algorithms
//!
//! * `Sha1` (20 bytes / 40 hex) and `Sha256` (32 bytes / 64 hex) follow the
//!   standard Git object formats.
//! * `Blake3` (32 bytes / 64 hex) is a **git-internal / Libra extension**: a
//!   repository created with it is a separate object namespace that standard
//!   Git does not understand. Because SHA-256 and BLAKE3 IDs have the same
//!   width, a 64-hex or 32-byte value can only be interpreted inside a known
//!   repository [`HashKind`] context (see the explicit-kind API below) or when
//!   it carries its algorithm tag (`blake3:HEX`); nothing in this module guesses
//!   BLAKE3 from a length.
//! * BLAKE3 here is the *repository object ID* algorithm only. It does not
//!   change [`crate::internal::object::integrity::IntegrityHash`] (always
//!   SHA-256) or any application-level digest (Buck manifests, policy digests,
//!   HMACs).
//!
//! # Thread-local default versus explicit `HashKind`
//!
//! Two families of API live here:
//!
//! * **Thread-local compatibility wrappers** — [`ObjectHash::new`],
//!   [`ObjectHash::from_type_and_data`], [`ObjectHash::from_bytes`],
//!   [`ObjectHash::from_stream`] and [`crate::utils::HashAlgorithm::new`] read the
//!   thread-local [`HashKind`] set by [`set_hash_kind`]. They exist for the
//!   established single-repository workflow: configure the kind once at startup
//!   on the thread that does the work, then call the parameterless API.
//! * **Explicit-kind API** — [`ObjectHash::new_for_kind`],
//!   [`ObjectHash::from_type_and_data_for_kind`], [`ObjectHash::from_hex_for_kind`],
//!   [`ObjectHash::from_bytes_for_kind`], [`ObjectHash::from_stream_for_kind`],
//!   [`ObjectHash::zero_for_kind`] and
//!   [`crate::utils::HashAlgorithm::new_for_kind`] take the repository
//!   [`HashKind`] as a parameter and never consult the thread-local. New code
//!   that runs on worker threads, async tasks, streams, caches, object loaders or
//!   protocol callbacks — anywhere the current thread may belong to another
//!   repository — must use this family and pass the kind of the repository it
//!   is operating on.
//!
//! Raw hex IDs (`Display`, [`FromStr`]) stay Git-like: no algorithm prefix. The
//! legacy [`FromStr`] implementation infers SHA-1 for 40 hex characters and
//! SHA-256 for 64 hex characters purely from the length; it does not consult
//! the thread-local kind and must not be used where the repository format is
//! known. When an ID has to travel across repositories, APIs, logs or indexes
//! together with its algorithm, use the tagged representation
//! (`sha1:HEX` / `sha256:HEX` / `blake3:HEX`) via
//! [`ObjectHash::to_tagged_string`] and [`ObjectHash::from_tagged_str`].
//!
//! Every explicit-kind parser fails closed: a length, hex or kind mismatch is
//! reported through [`HashError`] (carrying the operation, the expected/actual
//! lengths and — whenever it can be determined — the requested kind) and never
//! silently falls back to another algorithm.
//!
//! Hash kind is stored thread-locally; set once at startup to match your repository format.
//! Defaults to SHA-1.

use std::{cell::RefCell, fmt::Display, hash::Hash, io, str::FromStr};

use colored::Colorize;

use crate::{internal::object::types::ObjectType, utils::HashAlgorithm};

/// Errors produced by the explicit-kind [`ObjectHash`] constructors and parsers.
///
/// Every variant records the operation that failed and the expected/actual
/// lengths involved; the requested [`HashKind`] is recorded on every variant
/// where it can be determined ([`HashError::UnknownKind`] is precisely the case
/// where the tag did not resolve to one). None of these paths fall back to
/// another algorithm.
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum HashError {
    /// The raw byte slice, hex string or stream does not have the length required by `kind`.
    #[error("{operation}: invalid {kind} hash length: expected {expected}, got {actual}")]
    InvalidLength {
        /// Name of the API that rejected the input.
        operation: &'static str,
        /// Requested hash kind.
        kind: HashKind,
        /// Expected length (bytes for byte/stream input, characters for hex input).
        expected: usize,
        /// Actual length of the input (bytes actually read for stream input).
        actual: usize,
    },
    /// The hex string has the right length but contains characters outside `[0-9a-fA-F]`.
    #[error(
        "{operation}: invalid {kind} hex string (expected {expected} hex chars, got {actual}): {source}"
    )]
    InvalidHex {
        /// Name of the API that rejected the input.
        operation: &'static str,
        /// Requested hash kind.
        kind: HashKind,
        /// Expected hex length for `kind`.
        expected: usize,
        /// Actual length of the input.
        actual: usize,
        /// Underlying hex decoding error.
        source: hex::FromHexError,
    },
    /// An [`ObjectHash`] of a different algorithm was supplied where `expected` was required.
    #[error(
        "{operation}: hash kind mismatch: expected {expected} ({expected_len} bytes), got {actual} ({actual_len} bytes)"
    )]
    KindMismatch {
        /// Name of the API that rejected the input.
        operation: &'static str,
        /// Kind required by the caller / repository.
        expected: HashKind,
        /// Kind actually carried by the value.
        actual: HashKind,
        /// Byte length of `expected`.
        expected_len: usize,
        /// Byte length of `actual`.
        actual_len: usize,
    },
    /// A tagged ID has a missing or unknown `<kind>:` prefix.
    ///
    /// No [`HashKind`] can be attached because the tag is exactly what failed to
    /// resolve; the accepted tag set and the lengths that were seen are carried
    /// instead so the caller can still diagnose the input.
    #[error(
        "{operation}: unknown hash kind tag {tag:?} (accepted: {expected_tags}; tag length {actual}, expected one of {expected_tag_lens}; id part {hex_len} hex chars)"
    )]
    UnknownKind {
        /// Name of the API that rejected the input.
        operation: &'static str,
        /// The offending tag (or the whole input when no `:` separator exists).
        tag: String,
        /// Accepted tags.
        expected_tags: &'static str,
        /// Accepted tag lengths (characters).
        expected_tag_lens: &'static str,
        /// Length of the offending tag (characters).
        actual: usize,
        /// Length of the hex part after the separator (0 when no separator exists).
        hex_len: usize,
    },
    /// `object_type` has no loose-object header (delta types) and therefore no canonical object ID.
    #[error(
        "{operation}: {kind} object hash requested for {object_type}, which has no loose-object header (expected a {expected}-byte digest, produced {actual}; payload {payload_len} bytes)"
    )]
    UnsupportedObjectType {
        /// Name of the API that rejected the input.
        operation: &'static str,
        /// Requested hash kind.
        kind: HashKind,
        /// The object type without a header.
        object_type: ObjectType,
        /// Digest length `kind` would have produced.
        expected: usize,
        /// Digest bytes actually produced (always 0: nothing is hashed).
        actual: usize,
        /// Length of the payload that was offered.
        payload_len: usize,
    },
    /// The underlying reader failed while reading a `kind`-sized ID.
    #[error("{operation}: I/O error after {actual} of {expected} {kind} bytes: {message}")]
    Io {
        /// Name of the API that rejected the input.
        operation: &'static str,
        /// Requested hash kind.
        kind: HashKind,
        /// Bytes required.
        expected: usize,
        /// Bytes read before the error.
        actual: usize,
        /// [`io::ErrorKind`] of the underlying error.
        error_kind: io::ErrorKind,
        /// Display text of the underlying error.
        message: String,
    },
}

impl From<HashError> for io::Error {
    /// Map a [`HashError`] onto the closest [`io::ErrorKind`]: short streams become
    /// `UnexpectedEof` (matching `Read::read_exact`), transport errors keep their
    /// original kind and every other diagnostic is `InvalidData`.
    fn from(err: HashError) -> Self {
        let kind = match &err {
            HashError::InvalidLength {
                operation: "from_stream_for_kind",
                ..
            } => io::ErrorKind::UnexpectedEof,
            HashError::Io { error_kind, .. } => *error_kind,
            _ => io::ErrorKind::InvalidData,
        };
        io::Error::new(kind, err)
    }
}

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
    /// BLAKE3-256 repository object IDs (git-internal / Libra extension; not a
    /// standard Git object format).
    Blake3,
}
impl HashKind {
    /// Accepted lowercase tags for [`HashKind::from_str`] / tagged IDs, for diagnostics.
    pub const ACCEPTED_TAGS: &'static str = "sha1|sha256|blake3";
    /// Character lengths of [`HashKind::ACCEPTED_TAGS`], for diagnostics.
    pub const ACCEPTED_TAG_LENS: &'static str = "4|6";

    /// Byte length of the hash output.
    pub const fn size(&self) -> usize {
        match self {
            HashKind::Sha1 => 20,
            HashKind::Sha256 => 32,
            HashKind::Blake3 => 32,
        }
    }
    /// Hex string length of the hash output.
    pub const fn hex_len(&self) -> usize {
        self.size() * 2
    }
    /// Lowercase name of the hash algorithm (also the wire / tag spelling).
    pub const fn as_str(&self) -> &'static str {
        match self {
            HashKind::Sha1 => "sha1",
            HashKind::Sha256 => "sha256",
            HashKind::Blake3 => "blake3",
        }
    }
    /// Whether this kind is a standard Git object format (SHA-1, SHA-256) or a
    /// git-internal / Libra extension (BLAKE3).
    pub const fn is_git_standard(&self) -> bool {
        match self {
            HashKind::Sha1 | HashKind::Sha256 => true,
            HashKind::Blake3 => false,
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
            "blake3" => Ok(HashKind::Blake3),
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
/// Concrete object ID value carrying the bytes for the selected algorithm
/// (SHA-1, SHA-256 or BLAKE3-256).
/// Used for Git object hashes.
/// Supports conversion to/from hex strings, byte slices, and stream reading.
///
/// `Sha256` and `Blake3` carry the same 32 bytes and print as the same 64-hex
/// width; they are distinct variants and never compare equal, so the algorithm
/// is always preserved as metadata.
pub enum ObjectHash {
    Sha1([u8; 20]),
    Sha256([u8; 32]),
    /// BLAKE3-256 repository object ID (git-internal / Libra extension).
    Blake3([u8; 32]),
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
            ObjectHash::Blake3(bytes) => bytes.as_slice(),
        }
    }
}
/// Parse hex (40 for SHA1, 64 for SHA-256) into `ObjectHash`.
///
/// **Legacy, length-inferring parser.** The algorithm is chosen from the hex
/// length alone (40 → SHA-1, 64 → SHA-256); the thread-local [`HashKind`] is
/// *not* consulted and **BLAKE3 is never produced** (a BLAKE3 ID has the same
/// 64-hex width and would be mislabelled as SHA-256). Any other length is
/// rejected. When the repository format is known, prefer
/// [`ObjectHash::from_hex_for_kind`]; when the ID travels with its algorithm,
/// prefer [`ObjectHash::from_tagged_str`].
impl FromStr for ObjectHash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Error surface intentionally unchanged from the pre-refactor parser:
        // `hex::FromHexError`'s own message for bad hex, "Invalid hash length" otherwise.
        let kind = match s.len() {
            40 => HashKind::Sha1,
            64 => HashKind::Sha256,
            _ => return Err("Invalid hash length".to_string()),
        };
        let bytes = hex::decode(s).map_err(|e| e.to_string())?;
        ObjectHash::from_bytes_for_kind(kind, &bytes).map_err(|e| e.to_string())
    }
}

impl ObjectHash {
    /// Zero-filled ID (all bytes `0x00`) for a given hash kind.
    pub fn zero_for_kind(kind: HashKind) -> ObjectHash {
        match kind {
            HashKind::Sha1 => ObjectHash::Sha1([0u8; 20]),
            HashKind::Sha256 => ObjectHash::Sha256([0u8; 32]),
            HashKind::Blake3 => ObjectHash::Blake3([0u8; 32]),
        }
    }

    /// Zero-filled hex string for a given hash kind.
    pub fn zero_str(kind: HashKind) -> String {
        Self::zero_for_kind(kind).to_string()
    }

    /// Return the hash kind for this value.
    pub fn kind(&self) -> HashKind {
        match self {
            ObjectHash::Sha1(_) => HashKind::Sha1,
            ObjectHash::Sha256(_) => HashKind::Sha256,
            ObjectHash::Blake3(_) => HashKind::Blake3,
        }
    }
    /// Return the hash size in bytes.
    pub fn size(&self) -> usize {
        self.kind().size()
    }

    /// Fail closed unless this value carries `expected`.
    ///
    /// Use this at repository boundaries (pack trailers, ref-delta bases,
    /// index entries, protocol IDs) to reject an ID of the wrong algorithm
    /// instead of accepting a same-length value of another kind.
    pub fn ensure_kind(&self, expected: HashKind) -> Result<(), HashError> {
        let actual = self.kind();
        if actual == expected {
            Ok(())
        } else {
            Err(HashError::KindMismatch {
                operation: "ensure_kind",
                expected,
                actual,
                expected_len: expected.size(),
                actual_len: actual.size(),
            })
        }
    }

    /// Compute the digest of `data` with an explicit `kind`.
    ///
    /// Streams `data` through [`HashAlgorithm::new_for_kind`]; no copy of the
    /// input is made. Does not consult the thread-local [`HashKind`].
    pub fn new_for_kind(kind: HashKind, data: &[u8]) -> ObjectHash {
        let mut hasher = HashAlgorithm::new_for_kind(kind);
        hasher.update(data);
        hasher.finalize_object_hash()
    }

    /// Compute hash of data using current thread-local `HashKind`.
    ///
    /// Compatibility wrapper around [`ObjectHash::new_for_kind`].
    pub fn new(data: &[u8]) -> ObjectHash {
        Self::new_for_kind(get_hash_kind(), data)
    }

    /// Compute the canonical Git object ID `hash("<type> <size>\0" + data)` with an
    /// explicit `kind`.
    ///
    /// The header and payload are streamed into the hasher, so `data` is never
    /// copied (only the decimal size string is formatted). Does not consult the
    /// thread-local [`HashKind`]. Delta object types have no loose-object header
    /// and are rejected with [`HashError::UnsupportedObjectType`] instead of
    /// panicking.
    pub fn from_type_and_data_for_kind(
        kind: HashKind,
        object_type: ObjectType,
        data: &[u8],
    ) -> Result<ObjectHash, HashError> {
        let type_bytes = object_type
            .to_bytes()
            .ok_or(HashError::UnsupportedObjectType {
                operation: "from_type_and_data_for_kind",
                kind,
                object_type,
                expected: kind.size(),
                actual: 0,
                payload_len: data.len(),
            })?;
        let mut hasher = HashAlgorithm::new_for_kind(kind);
        hasher.update(type_bytes);
        hasher.update(b" ");
        hasher.update(data.len().to_string().as_bytes());
        hasher.update(b"\x00");
        hasher.update(data);
        Ok(hasher.finalize_object_hash())
    }

    /// Create ObjectHash from object type and data using the thread-local `HashKind`.
    ///
    /// Legacy entry point; the header assembly below is the pre-refactor code
    /// (including its behaviour for delta types, which have no loose-object
    /// header and were never valid input here). Only the digest step was
    /// redirected to [`ObjectHash::new_for_kind`]. New code should call
    /// [`ObjectHash::from_type_and_data_for_kind`], which is fallible and
    /// streams the header instead of copying the payload.
    pub fn from_type_and_data(object_type: ObjectType, data: &[u8]) -> ObjectHash {
        let mut d: Vec<u8> = Vec::new();
        d.extend(object_type.to_data().unwrap());
        d.push(b' ');
        d.extend(data.len().to_string().as_bytes());
        d.push(b'\x00');
        d.extend(data);
        Self::new_for_kind(get_hash_kind(), &d)
    }

    /// Create an `ObjectHash` of an explicit `kind` from raw digest bytes.
    ///
    /// Fails closed with [`HashError::InvalidLength`] when `bytes.len()` is not
    /// `kind.size()`; it never re-interprets the bytes as another algorithm.
    pub fn from_bytes_for_kind(kind: HashKind, bytes: &[u8]) -> Result<ObjectHash, HashError> {
        let expected = kind.size();
        if bytes.len() != expected {
            return Err(HashError::InvalidLength {
                operation: "from_bytes_for_kind",
                kind,
                expected,
                actual: bytes.len(),
            });
        }
        Ok(match kind {
            HashKind::Sha1 => {
                let mut h = [0u8; 20];
                h.copy_from_slice(bytes);
                ObjectHash::Sha1(h)
            }
            HashKind::Sha256 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(bytes);
                ObjectHash::Sha256(h)
            }
            HashKind::Blake3 => {
                let mut h = [0u8; 32];
                h.copy_from_slice(bytes);
                ObjectHash::Blake3(h)
            }
        })
    }

    /// Create `ObjectHash` from raw bytes matching the current hash size.
    ///
    /// Compatibility wrapper around [`ObjectHash::from_bytes_for_kind`] using the
    /// thread-local [`HashKind`].
    pub fn from_bytes(bytes: &[u8]) -> Result<ObjectHash, String> {
        // Error string intentionally unchanged from the pre-refactor implementation.
        Self::from_bytes_for_kind(get_hash_kind(), bytes).map_err(|e| match e {
            HashError::InvalidLength {
                expected, actual, ..
            } => format!("Invalid byte length: got {actual}, expected {expected}"),
            other => other.to_string(),
        })
    }

    /// Parse a raw (untagged) hex string as an ID of an explicit `kind`.
    ///
    /// The string must be exactly `kind.hex_len()` characters of hex; a
    /// 64-character string is only accepted as the requested 32-byte kind and is
    /// never guessed from its length. Fails closed with [`HashError`].
    pub fn from_hex_for_kind(kind: HashKind, hex_str: &str) -> Result<ObjectHash, HashError> {
        let expected = kind.hex_len();
        if hex_str.len() != expected {
            return Err(HashError::InvalidLength {
                operation: "from_hex_for_kind",
                kind,
                expected,
                actual: hex_str.len(),
            });
        }
        let bytes = hex::decode(hex_str).map_err(|source| HashError::InvalidHex {
            operation: "from_hex_for_kind",
            kind,
            expected,
            actual: hex_str.len(),
            source,
        })?;
        Self::from_bytes_for_kind(kind, &bytes)
    }

    /// Format as a tagged ID `<kind>:<hex>` (for example `sha256:ab12…`).
    ///
    /// Use this representation wherever an ID leaves its repository context
    /// (APIs, indexes, logs). It must not be written into pack, tree/commit
    /// payloads or pkt-lines, which carry raw hex only.
    pub fn to_tagged_string(&self) -> String {
        format!("{}:{}", self.kind(), self)
    }

    /// Parse a tagged ID `<kind>:<hex>` produced by [`ObjectHash::to_tagged_string`].
    ///
    /// The tag selects the algorithm; the hex part must match that algorithm's
    /// length. Unknown tags, missing separators and length/hex errors fail
    /// closed with [`HashError`].
    pub fn from_tagged_str(tagged: &str) -> Result<ObjectHash, HashError> {
        let (tag, hex_str) = tagged
            .split_once(':')
            .ok_or_else(|| HashError::UnknownKind {
                operation: "from_tagged_str",
                tag: tagged.to_string(),
                expected_tags: HashKind::ACCEPTED_TAGS,
                expected_tag_lens: HashKind::ACCEPTED_TAG_LENS,
                actual: tagged.len(),
                hex_len: 0,
            })?;
        let kind = tag
            .parse::<HashKind>()
            .map_err(|_| HashError::UnknownKind {
                operation: "from_tagged_str",
                tag: tag.to_string(),
                expected_tags: HashKind::ACCEPTED_TAGS,
                expected_tag_lens: HashKind::ACCEPTED_TAG_LENS,
                actual: tag.len(),
                hex_len: hex_str.len(),
            })?;
        Self::from_hex_for_kind(kind, hex_str)
    }

    /// Create `ObjectHash` from raw bytes, inferring the hash kind from the
    /// byte length (20 → SHA-1, 32 → SHA-256).
    ///
    /// **Legacy contract (frozen):** 20 bytes are always SHA-1 and 32 bytes are
    /// always SHA-256 — **never BLAKE3**, even though BLAKE3 digests are also
    /// 32 bytes. This helper predates the explicit-kind API and will be
    /// marked `#[deprecated]` once the remaining internal callers have moved to
    /// [`ObjectHash::from_bytes_for_kind`] / [`HashAlgorithm::finalize_object_hash`].
    /// It must not be used on any *new* repository, pack or protocol path,
    /// because a 32-byte digest of another algorithm would be silently
    /// mislabelled as SHA-256. The two remaining pack-encode callers
    /// (`encode/mod.rs`, `encode/parallel.rs`) are migrated to
    /// [`HashAlgorithm::finalize_object_hash`] in B3-05, after which the
    /// attribute is added.
    ///
    /// Unlike [`ObjectHash::from_bytes`], this does not consult the
    /// thread-local [`HashKind`], so it is safe on threads where
    /// [`set_hash_kind`] was never called. The pack encoder finalizes its
    /// running checksum on whichever async worker thread happens to run the
    /// task; the checksum bytes already carry the correct length, while the
    /// worker's thread-local may still hold the default SHA-1 kind — the
    /// mismatch used to panic with "Invalid byte length: got 32, expected 20".
    #[deprecated(
        since = "0.9.0",
        note = "infers SHA-256 from a 32-byte length and can never represent BLAKE3; use \
                ObjectHash::from_bytes_for_kind or HashAlgorithm::finalize_object_hash"
    )]
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

    /// Read exactly `kind.size()` bytes from `data` as an ID of an explicit `kind`.
    ///
    /// Does not consult the thread-local [`HashKind`]. A short stream fails
    /// closed with [`HashError::InvalidLength`] carrying the bytes actually
    /// read; other reader failures surface as [`HashError::Io`].
    pub fn from_stream_for_kind(
        kind: HashKind,
        data: &mut impl io::Read,
    ) -> Result<ObjectHash, HashError> {
        const OP: &str = "from_stream_for_kind";
        let expected = kind.size();
        let mut buf = [0u8; 32];
        let mut filled = 0usize;
        while filled < expected {
            match data.read(&mut buf[filled..expected]) {
                Ok(0) => break,
                Ok(n) => filled += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e) => {
                    return Err(HashError::Io {
                        operation: OP,
                        kind,
                        expected,
                        actual: filled,
                        error_kind: e.kind(),
                        message: e.to_string(),
                    });
                }
            }
        }
        if filled != expected {
            return Err(HashError::InvalidLength {
                operation: OP,
                kind,
                expected,
                actual: filled,
            });
        }
        Self::from_bytes_for_kind(kind, &buf[..expected])
    }

    /// Read hash bytes from a stream according to current hash size.
    ///
    /// Legacy entry point using the thread-local [`HashKind`]. The error
    /// surface is unchanged from the pre-refactor implementation: the
    /// [`io::Error`] returned by `Read::read_exact` (a short stream is
    /// `UnexpectedEof`). Only the byte-to-variant step goes through
    /// [`ObjectHash::from_bytes_for_kind`]. New code should call
    /// [`ObjectHash::from_stream_for_kind`].
    pub fn from_stream(data: &mut impl io::Read) -> io::Result<ObjectHash> {
        let kind = get_hash_kind();
        let mut buf = [0u8; 32];
        let want = &mut buf[..kind.size()];
        data.read_exact(want)?;
        Self::from_bytes_for_kind(kind, want).map_err(io::Error::from)
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
            ObjectHash::Blake3(bytes) => bytes.as_mut_slice(),
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
        hash::{HashError, HashKind, ObjectHash, set_hash_kind_for_test},
        internal::{object::types::ObjectType, pack::test_pack_download::download_pack_file},
        utils::HashAlgorithm,
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
    const HELLO_SHA1: &str = "943a702d06f34599aee1f8da8ef9f7296031d699";
    const HELLO_SHA256: &str = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";

    /// Explicit-kind constructors must ignore the thread-local kind and agree with the
    /// thread-local wrappers when the kinds coincide.
    #[test]
    fn object_hash_for_kind_ignores_thread_local() {
        let data = b"Hello, world!";
        for (kind, other, expected) in [
            (HashKind::Sha1, HashKind::Sha256, HELLO_SHA1),
            (HashKind::Sha256, HashKind::Sha1, HELLO_SHA256),
        ] {
            // Deliberately configure the *other* kind on this thread.
            let _guard = set_hash_kind_for_test(other);

            let digest = ObjectHash::new_for_kind(kind, data);
            assert_eq!(digest.kind(), kind);
            assert_eq!(digest.to_string(), expected);
            assert_eq!(digest.size(), kind.size());
            assert_eq!(digest.to_string().len(), kind.hex_len());

            // Raw hex / bytes / stream round-trips under the explicit kind.
            let from_hex = ObjectHash::from_hex_for_kind(kind, expected).unwrap();
            assert_eq!(from_hex, digest);
            let from_bytes = ObjectHash::from_bytes_for_kind(kind, digest.as_ref()).unwrap();
            assert_eq!(from_bytes, digest);
            let mut cursor = std::io::Cursor::new(digest.to_data());
            let from_stream = ObjectHash::from_stream_for_kind(kind, &mut cursor).unwrap();
            assert_eq!(from_stream, digest);

            // Canonical Git object hash with header must match the thread-local path
            // once the thread-local is switched to the same kind.
            let explicit =
                ObjectHash::from_type_and_data_for_kind(kind, ObjectType::Blob, data).unwrap();
            assert_eq!(explicit.kind(), kind);
            {
                let _same = set_hash_kind_for_test(kind);
                assert_eq!(
                    ObjectHash::from_type_and_data(ObjectType::Blob, data),
                    explicit
                );
                assert_eq!(ObjectHash::new(data), digest);
                assert_eq!(ObjectHash::from_bytes(digest.as_ref()).unwrap(), digest);
            }

            // Zero IDs.
            let zero = ObjectHash::zero_for_kind(kind);
            assert_eq!(zero.kind(), kind);
            assert!(zero.as_ref().iter().all(|b| *b == 0));
            assert_eq!(zero.to_string(), ObjectHash::zero_str(kind));
            assert_eq!(ObjectHash::zero_str(kind).len(), kind.hex_len());
        }
        assert_eq!(
            ObjectHash::default(),
            ObjectHash::zero_for_kind(HashKind::Sha1)
        );
    }

    /// Length, hex and kind mismatches fail closed with diagnostic errors and never
    /// fall back to the other algorithm.
    #[test]
    fn object_hash_for_kind_errors_fail_closed() {
        // 64 hex chars requested as SHA-1: length error carrying kind + lengths.
        let err = ObjectHash::from_hex_for_kind(HashKind::Sha1, HELLO_SHA256).unwrap_err();
        assert_eq!(
            err,
            HashError::InvalidLength {
                operation: "from_hex_for_kind",
                kind: HashKind::Sha1,
                expected: 40,
                actual: 64,
            }
        );
        let msg = err.to_string();
        assert!(
            msg.contains("sha1") && msg.contains("40") && msg.contains("64"),
            "{msg}"
        );

        // 40 hex chars requested as SHA-256: no silent SHA-1 fallback.
        let err = ObjectHash::from_hex_for_kind(HashKind::Sha256, HELLO_SHA1).unwrap_err();
        assert!(matches!(
            err,
            HashError::InvalidLength {
                kind: HashKind::Sha256,
                expected: 64,
                actual: 40,
                ..
            }
        ));

        // Non-hex input of the right length.
        let bad = "zz".repeat(20);
        let err = ObjectHash::from_hex_for_kind(HashKind::Sha1, &bad).unwrap_err();
        assert!(matches!(
            err,
            HashError::InvalidHex {
                kind: HashKind::Sha1,
                expected: 40,
                actual: 40,
                ..
            }
        ));
        let msg = err.to_string();
        assert!(msg.contains("sha1") && msg.contains("40"), "{msg}");

        // Delta types have no loose-object header: explicit API fails closed.
        let err =
            ObjectHash::from_type_and_data_for_kind(HashKind::Sha1, ObjectType::OffsetDelta, b"x")
                .unwrap_err();
        assert_eq!(
            err,
            HashError::UnsupportedObjectType {
                operation: "from_type_and_data_for_kind",
                kind: HashKind::Sha1,
                object_type: ObjectType::OffsetDelta,
                expected: 20,
                actual: 0,
                payload_len: 1,
            }
        );

        // Raw bytes of the wrong width.
        let err = ObjectHash::from_bytes_for_kind(HashKind::Sha256, &[0u8; 20]).unwrap_err();
        assert!(matches!(
            err,
            HashError::InvalidLength {
                operation: "from_bytes_for_kind",
                kind: HashKind::Sha256,
                expected: 32,
                actual: 20,
            }
        ));
        // The thread-local wrapper keeps its legacy error string verbatim.
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let msg = ObjectHash::from_bytes(&[0u8; 20]).unwrap_err();
        assert_eq!(msg, "Invalid byte length: got 20, expected 32");

        // Reader failures surface as `HashError::Io` with the bytes read so far;
        // `Interrupted` is retried transparently.
        struct FlakyReader {
            chunks: Vec<std::io::Result<&'static [u8]>>,
        }
        impl std::io::Read for FlakyReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                match self.chunks.remove(0) {
                    Ok(bytes) => {
                        buf[..bytes.len()].copy_from_slice(bytes);
                        Ok(bytes.len())
                    }
                    Err(e) => Err(e),
                }
            }
        }
        let mut broken = FlakyReader {
            chunks: vec![
                Ok(&[0u8; 8][..]),
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "retry",
                )),
                Ok(&[0u8; 4][..]),
                Err(std::io::Error::other("disk gone")),
            ],
        };
        let err = ObjectHash::from_stream_for_kind(HashKind::Sha1, &mut broken).unwrap_err();
        assert_eq!(
            err,
            HashError::Io {
                operation: "from_stream_for_kind",
                kind: HashKind::Sha1,
                expected: 20,
                actual: 12,
                error_kind: std::io::ErrorKind::Other,
                message: "disk gone".to_string(),
            }
        );
        assert_eq!(std::io::Error::from(err).kind(), std::io::ErrorKind::Other);
        let mut healed = FlakyReader {
            chunks: vec![
                Ok(&[0xab; 8][..]),
                Err(std::io::Error::new(
                    std::io::ErrorKind::Interrupted,
                    "retry",
                )),
                Ok(&[0xab; 12][..]),
            ],
        };
        assert_eq!(
            ObjectHash::from_stream_for_kind(HashKind::Sha1, &mut healed).unwrap(),
            ObjectHash::Sha1([0xab; 20])
        );

        // Short stream.
        let mut short = std::io::Cursor::new(vec![0u8; 10]);
        let err = ObjectHash::from_stream_for_kind(HashKind::Sha1, &mut short).unwrap_err();
        assert_eq!(
            err,
            HashError::InvalidLength {
                operation: "from_stream_for_kind",
                kind: HashKind::Sha1,
                expected: 20,
                actual: 10,
            }
        );
        assert_eq!(
            std::io::Error::from(err).kind(),
            std::io::ErrorKind::UnexpectedEof
        );
        let mut short = std::io::Cursor::new(vec![0u8; 10]);
        let err = ObjectHash::from_stream(&mut short).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);

        // Kind mismatch guard.
        let sha256 = ObjectHash::from_hex_for_kind(HashKind::Sha256, HELLO_SHA256).unwrap();
        assert_eq!(sha256.ensure_kind(HashKind::Sha256), Ok(()));
        assert_eq!(
            sha256.ensure_kind(HashKind::Sha1),
            Err(HashError::KindMismatch {
                operation: "ensure_kind",
                expected: HashKind::Sha1,
                actual: HashKind::Sha256,
                expected_len: 20,
                actual_len: 32,
            })
        );
    }

    /// Tagged IDs carry the algorithm explicitly and round-trip for every kind.
    #[test]
    fn object_hash_for_kind_tagged_round_trip() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let sha1 = ObjectHash::from_hex_for_kind(HashKind::Sha1, HELLO_SHA1).unwrap();
        let sha256 = ObjectHash::from_hex_for_kind(HashKind::Sha256, HELLO_SHA256).unwrap();

        assert_eq!(sha1.to_tagged_string(), format!("sha1:{HELLO_SHA1}"));
        assert_eq!(sha256.to_tagged_string(), format!("sha256:{HELLO_SHA256}"));
        assert_eq!(
            ObjectHash::from_tagged_str(&sha1.to_tagged_string()).unwrap(),
            sha1
        );
        assert_eq!(
            ObjectHash::from_tagged_str(&sha256.to_tagged_string()).unwrap(),
            sha256
        );

        // Raw Display is unchanged by the tagged API.
        assert_eq!(sha1.to_string(), HELLO_SHA1);
        assert_eq!(sha256.to_string(), HELLO_SHA256);

        // Unknown / missing tags and tag-length mismatches fail closed.
        assert!(matches!(
            ObjectHash::from_tagged_str(&format!("md5:{HELLO_SHA1}")).unwrap_err(),
            HashError::UnknownKind { tag, expected_tags: "sha1|sha256|blake3", actual: 3, hex_len: 40, .. } if tag == "md5"
        ));
        assert!(matches!(
            ObjectHash::from_tagged_str(HELLO_SHA1).unwrap_err(),
            HashError::UnknownKind { .. }
        ));
        assert!(matches!(
            ObjectHash::from_tagged_str(&format!("sha1:{HELLO_SHA256}")).unwrap_err(),
            HashError::InvalidLength {
                kind: HashKind::Sha1,
                expected: 40,
                actual: 64,
                ..
            }
        ));
    }

    /// The legacy length-inferring parsers keep their frozen contract regardless of the
    /// thread-local kind: 40 hex / 20 bytes → SHA-1, 64 hex / 32 bytes → SHA-256.
    #[test]
    #[allow(deprecated)]
    fn object_hash_for_kind_legacy_parsers_unchanged() {
        for other in [HashKind::Sha1, HashKind::Sha256] {
            let _guard = set_hash_kind_for_test(other);
            assert_eq!(
                ObjectHash::from_str(HELLO_SHA1).unwrap().kind(),
                HashKind::Sha1
            );
            assert_eq!(
                ObjectHash::from_str(HELLO_SHA256).unwrap().kind(),
                HashKind::Sha256
            );
            assert_eq!(
                ObjectHash::from_str("abc").unwrap_err(),
                "Invalid hash length".to_string()
            );
            assert!(ObjectHash::from_str(&"zz".repeat(20)).is_err());
            assert_eq!(
                ObjectHash::from_bytes_infer_kind(&[0u8; 20])
                    .unwrap()
                    .kind(),
                HashKind::Sha1
            );
            assert_eq!(
                ObjectHash::from_bytes_infer_kind(&[0u8; 32])
                    .unwrap()
                    .kind(),
                HashKind::Sha256
            );
            assert!(ObjectHash::from_bytes_infer_kind(&[0u8; 16]).is_err());
        }
    }

    /// Official BLAKE3 test vectors (BLAKE3-team/BLAKE3 `test_vectors.json`, first 32 output
    /// bytes): input byte `i` is `i % 251`.
    const BLAKE3_VECTORS: &[(usize, &str)] = &[
        (
            0,
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
        ),
        (
            1,
            "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
        ),
        (
            2,
            "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63",
        ),
        (
            3,
            "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
        ),
        (
            4,
            "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32",
        ),
        (
            5,
            "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2",
        ),
        (
            6,
            "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844",
        ),
        (
            7,
            "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe",
        ),
        (
            8,
            "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb",
        ),
        (
            63,
            "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b",
        ),
        (
            64,
            "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98",
        ),
        (
            65,
            "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee",
        ),
        (
            127,
            "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d",
        ),
        (
            128,
            "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef",
        ),
        (
            129,
            "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12",
        ),
        (
            1023,
            "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11",
        ),
        (
            1024,
            "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
        ),
        (
            1025,
            "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
        ),
        (
            2048,
            "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
        ),
        (
            3072,
            "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
        ),
        (
            4096,
            "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
        ),
        (
            8192,
            "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
        ),
        (
            31744,
            "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47",
        ),
        (
            102400,
            "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085",
        ),
    ];

    /// BLAKE3 digests match the official vectors through every entry point (one-shot,
    /// chunked streaming, `Write` sink) and the Git canonical header path is consistent.
    #[test]
    fn blake3_known_vectors() {
        // Run under a SHA-1 thread-local to prove the explicit kind is what matters.
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        for &(len, expected) in BLAKE3_VECTORS {
            let input: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();

            let one_shot = ObjectHash::new_for_kind(HashKind::Blake3, &input);
            assert_eq!(one_shot.kind(), HashKind::Blake3);
            assert_eq!(one_shot.to_string(), expected, "len {len}");
            assert_eq!(one_shot.size(), 32);

            // Chunked streaming through HashAlgorithm must agree.
            let mut hasher = HashAlgorithm::new_for_kind(HashKind::Blake3);
            assert_eq!(hasher.kind(), HashKind::Blake3);
            for chunk in input.chunks(97) {
                hasher.update(chunk);
            }
            assert_eq!(hasher.finalize_object_hash(), one_shot, "len {len}");

            let mut sink = HashAlgorithm::new_for_kind(HashKind::Blake3);
            std::io::Write::write_all(&mut sink, &input).unwrap();
            assert_eq!(hex::encode(sink.finalize()), expected, "len {len}");
        }

        // Git canonical header: hash("blob <size>\0" + data) via the crate directly.
        let data = b"Hello, world!";
        let object_id =
            ObjectHash::from_type_and_data_for_kind(HashKind::Blake3, ObjectType::Blob, data)
                .unwrap();
        let mut reference = blake3::Hasher::new();
        reference.update(b"blob 13\x00");
        reference.update(data);
        assert_eq!(
            object_id,
            ObjectHash::Blake3(*reference.finalize().as_bytes())
        );
        assert_eq!(object_id.to_string().len(), 64);
        // Same payload, same width, different algorithm: never equal to SHA-256.
        let sha256_id =
            ObjectHash::from_type_and_data_for_kind(HashKind::Sha256, ObjectType::Blob, data)
                .unwrap();
        assert_eq!(sha256_id.size(), object_id.size());
        assert_ne!(sha256_id, object_id);
        assert_ne!(sha256_id.as_ref(), object_id.as_ref());
        {
            let _b3 = set_hash_kind_for_test(HashKind::Blake3);
            assert_eq!(
                ObjectHash::from_type_and_data(ObjectType::Blob, data),
                object_id
            );
            assert_eq!(
                ObjectHash::new(data),
                ObjectHash::new_for_kind(HashKind::Blake3, data)
            );
            assert_eq!(HashAlgorithm::new().kind(), HashKind::Blake3);
        }
    }

    /// BLAKE3 IDs are only produced under an explicit kind or a `blake3:` tag; a 64-hex /
    /// 32-byte value is never guessed to be BLAKE3, and SHA-256/BLAKE3 never alias.
    #[test]
    #[allow(deprecated)]
    fn blake3_context_and_tagged_id() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let digest = ObjectHash::new_for_kind(HashKind::Blake3, b"payload");
        let hex_str = digest.to_string();
        assert_eq!(hex_str.len(), 64);
        assert_eq!(HashKind::Blake3.size(), 32);
        assert_eq!(HashKind::Blake3.hex_len(), 64);
        assert_eq!(HashKind::Blake3.as_str(), "blake3");
        assert_eq!(HashKind::Blake3.to_string(), "blake3");
        assert_eq!("blake3".parse::<HashKind>().unwrap(), HashKind::Blake3);
        assert!(!HashKind::Blake3.is_git_standard());
        assert!(HashKind::Sha1.is_git_standard() && HashKind::Sha256.is_git_standard());

        // Explicit-kind parsers.
        assert_eq!(
            ObjectHash::from_hex_for_kind(HashKind::Blake3, &hex_str).unwrap(),
            digest
        );
        assert_eq!(
            ObjectHash::from_bytes_for_kind(HashKind::Blake3, digest.as_ref()).unwrap(),
            digest
        );
        let mut cursor = std::io::Cursor::new(digest.to_data());
        assert_eq!(
            ObjectHash::from_stream_for_kind(HashKind::Blake3, &mut cursor).unwrap(),
            digest
        );
        let zero = ObjectHash::zero_for_kind(HashKind::Blake3);
        assert_eq!(zero, ObjectHash::Blake3([0u8; 32]));
        assert_eq!(ObjectHash::zero_str(HashKind::Blake3), "0".repeat(64));
        assert_ne!(zero, ObjectHash::zero_for_kind(HashKind::Sha256));

        // Same hex under the SHA-256 kind is a *different* value (distinct variant).
        let as_sha256 = ObjectHash::from_hex_for_kind(HashKind::Sha256, &hex_str).unwrap();
        assert_ne!(as_sha256, digest);
        assert_eq!(as_sha256.as_ref(), digest.as_ref());
        assert_eq!(as_sha256.kind(), HashKind::Sha256);
        assert_eq!(
            digest.ensure_kind(HashKind::Sha256),
            Err(HashError::KindMismatch {
                operation: "ensure_kind",
                expected: HashKind::Sha256,
                actual: HashKind::Blake3,
                expected_len: 32,
                actual_len: 32,
            })
        );
        assert!(
            as_sha256
                .ensure_kind(HashKind::Blake3)
                .unwrap_err()
                .to_string()
                .contains("blake3")
        );

        // Tagged representation distinguishes the two 64-hex kinds.
        assert_eq!(digest.to_tagged_string(), format!("blake3:{hex_str}"));
        assert_eq!(as_sha256.to_tagged_string(), format!("sha256:{hex_str}"));
        assert_eq!(
            ObjectHash::from_tagged_str(&format!("blake3:{hex_str}")).unwrap(),
            digest
        );
        assert_eq!(
            ObjectHash::from_tagged_str(&format!("sha256:{hex_str}")).unwrap(),
            as_sha256
        );
        assert!(matches!(
            ObjectHash::from_tagged_str(&format!("blake3:{HELLO_SHA1}")).unwrap_err(),
            HashError::InvalidLength {
                kind: HashKind::Blake3,
                expected: 64,
                actual: 40,
                ..
            }
        ));
        assert!(matches!(
            ObjectHash::from_tagged_str(&format!("blake2:{hex_str}")).unwrap_err(),
            HashError::UnknownKind {
                expected_tags: "sha1|sha256|blake3",
                ..
            }
        ));

        // Legacy inference never yields BLAKE3, regardless of the thread-local kind.
        for other in [HashKind::Sha1, HashKind::Sha256, HashKind::Blake3] {
            let _tl = set_hash_kind_for_test(other);
            assert_eq!(ObjectHash::from_str(&hex_str).unwrap(), as_sha256);
            assert_eq!(
                ObjectHash::from_str(&hex_str).unwrap().kind(),
                HashKind::Sha256
            );
            assert_eq!(
                ObjectHash::from_bytes_infer_kind(digest.as_ref())
                    .unwrap()
                    .kind(),
                HashKind::Sha256
            );
        }
        // Thread-local BLAKE3 drives the compatibility wrappers.
        {
            let _tl = set_hash_kind_for_test(HashKind::Blake3);
            assert_eq!(ObjectHash::from_bytes(digest.as_ref()).unwrap(), digest);
            let mut cursor = std::io::Cursor::new(digest.to_data());
            assert_eq!(ObjectHash::from_stream(&mut cursor).unwrap(), digest);
            assert_eq!(
                ObjectHash::from_bytes(&[0u8; 20]).unwrap_err(),
                "Invalid byte length: got 20, expected 32"
            );
        }

        // serde: new variants round-trip and old SHA payloads still deserialize.
        let json = serde_json::to_string(&digest).unwrap();
        assert!(json.starts_with("{\"Blake3\":["), "{json}");
        assert_eq!(serde_json::from_str::<ObjectHash>(&json).unwrap(), digest);
        assert_eq!(
            serde_json::to_string(&HashKind::Blake3).unwrap(),
            "\"Blake3\""
        );
        assert_eq!(
            serde_json::from_str::<HashKind>("\"Blake3\"").unwrap(),
            HashKind::Blake3
        );
        let sha1 = ObjectHash::from_hex_for_kind(HashKind::Sha1, HELLO_SHA1).unwrap();
        let legacy_json = format!(
            "{{\"Sha1\":{}}}",
            serde_json::to_string(&sha1.to_data()).unwrap()
        );
        assert_eq!(
            serde_json::from_str::<ObjectHash>(&legacy_json).unwrap(),
            sha1
        );
        let legacy_json = format!(
            "{{\"Sha256\":{}}}",
            serde_json::to_string(&as_sha256.to_data()).unwrap()
        );
        assert_eq!(
            serde_json::from_str::<ObjectHash>(&legacy_json).unwrap(),
            as_sha256
        );
        assert_eq!(
            serde_json::from_str::<HashKind>("\"Sha256\"").unwrap(),
            HashKind::Sha256
        );

        // Blake3 zero ID round-trips through serde and rkyv like any other value.
        let zero_json = serde_json::to_string(&zero).unwrap();
        assert_eq!(
            serde_json::from_str::<ObjectHash>(&zero_json).unwrap(),
            zero
        );
        let zero_rkyv = rkyv::to_bytes::<rkyv::rancor::Error>(&zero).unwrap();
        assert_eq!(
            rkyv::from_bytes::<ObjectHash, rkyv::rancor::Error>(&zero_rkyv).unwrap(),
            zero
        );

        // rkyv: archived round-trip for every kind.
        for value in [sha1, as_sha256, digest, zero] {
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&value).unwrap();
            let back = rkyv::from_bytes::<ObjectHash, rkyv::rancor::Error>(&bytes).unwrap();
            assert_eq!(back, value);
        }
        for kind in [HashKind::Sha1, HashKind::Sha256, HashKind::Blake3] {
            let bytes = rkyv::to_bytes::<rkyv::rancor::Error>(&kind).unwrap();
            assert_eq!(
                rkyv::from_bytes::<HashKind, rkyv::rancor::Error>(&bytes).unwrap(),
                kind
            );
        }
    }

    /// The AI IntegrityHash stays SHA-256 no matter which repository kind is active.
    #[test]
    fn blake3_does_not_change_integrity_hash() {
        use crate::internal::object::integrity::IntegrityHash;
        let content = b"integrity payload";
        let expected = {
            let _sha = set_hash_kind_for_test(HashKind::Sha256);
            IntegrityHash::compute(content)
        };
        for kind in [HashKind::Sha1, HashKind::Sha256, HashKind::Blake3] {
            let _tl = set_hash_kind_for_test(kind);
            let got = IntegrityHash::compute(content);
            assert_eq!(got, expected);
            assert_eq!(got.to_hex().len(), 64);
            assert_eq!(
                got.as_bytes(),
                ObjectHash::new_for_kind(HashKind::Sha256, content).as_ref()
            );
            assert_ne!(
                got.as_bytes(),
                ObjectHash::new_for_kind(HashKind::Blake3, content).as_ref()
            );
        }
    }

    /// Archives written by the pre-BLAKE3 crate (captured from the 0.8.7 baseline build)
    /// still deserialize, and the new build emits byte-identical archives for SHA values:
    /// the Blake3 variant is appended, so existing discriminants and layouts are unchanged.
    #[test]
    fn blake3_legacy_archives_still_deserialize() {
        // rkyv bytes produced by git-internal 0.8.7 (before HashKind::Blake3 existed).
        const LEGACY_RKYV_SHA1: &str =
            "001111111111111111111111111111111111111111000000000000000000000000";
        const LEGACY_RKYV_SHA256: &str =
            "012222222222222222222222222222222222222222222222222222222222222222";
        const LEGACY_RKYV_KIND_SHA1: &str = "00";
        const LEGACY_RKYV_KIND_SHA256: &str = "01";
        const LEGACY_JSON_SHA1: &str =
            "{\"Sha1\":[17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17]}";

        let sha1 = ObjectHash::Sha1([0x11; 20]);
        let sha256 = ObjectHash::Sha256([0x22; 32]);
        let decode = |hex_bytes: &str| hex::decode(hex_bytes).unwrap();

        assert_eq!(
            rkyv::from_bytes::<ObjectHash, rkyv::rancor::Error>(&decode(LEGACY_RKYV_SHA1)).unwrap(),
            sha1
        );
        assert_eq!(
            rkyv::from_bytes::<ObjectHash, rkyv::rancor::Error>(&decode(LEGACY_RKYV_SHA256))
                .unwrap(),
            sha256
        );
        assert_eq!(
            rkyv::from_bytes::<HashKind, rkyv::rancor::Error>(&decode(LEGACY_RKYV_KIND_SHA1))
                .unwrap(),
            HashKind::Sha1
        );
        assert_eq!(
            rkyv::from_bytes::<HashKind, rkyv::rancor::Error>(&decode(LEGACY_RKYV_KIND_SHA256))
                .unwrap(),
            HashKind::Sha256
        );
        // Layout stability: the new crate writes the same bytes the old one did.
        assert_eq!(
            hex::encode(rkyv::to_bytes::<rkyv::rancor::Error>(&sha1).unwrap()),
            LEGACY_RKYV_SHA1
        );
        assert_eq!(
            hex::encode(rkyv::to_bytes::<rkyv::rancor::Error>(&sha256).unwrap()),
            LEGACY_RKYV_SHA256
        );
        assert_eq!(
            hex::encode(rkyv::to_bytes::<rkyv::rancor::Error>(&HashKind::Sha256).unwrap()),
            LEGACY_RKYV_KIND_SHA256
        );
        assert_eq!(
            serde_json::from_str::<ObjectHash>(LEGACY_JSON_SHA1).unwrap(),
            sha1
        );
        assert_eq!(serde_json::to_string(&sha1).unwrap(), LEGACY_JSON_SHA1);
        assert_eq!(
            serde_json::from_str::<HashKind>("\"Sha256\"").unwrap(),
            HashKind::Sha256
        );
    }
}
