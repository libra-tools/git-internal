//! Shared I/O utilities for Git-internal including buffered readers, the streaming hash
//! abstraction over SHA-1 / SHA-256 / BLAKE3-256, and helpers for reading pack/file bytes while
//! tracking stream progress.

use std::{
    io,
    io::{BufRead, Read},
};

use sha1::{Digest, Sha1};

use crate::hash::{HashError, HashKind, ObjectHash, get_hash_kind};
/// Read exactly `len` bytes from the given reader.
pub fn read_bytes(file: &mut impl Read, len: usize) -> io::Result<Vec<u8>> {
    let mut buf = vec![0; len];
    file.read_exact(&mut buf)?;
    Ok(buf)
}

/// Read an object hash of an explicit `kind` from the given reader.
///
/// Does not consult the thread-local [`HashKind`]; a short or failing read
/// surfaces as [`HashError`] with the expected/actual byte counts.
pub fn read_sha_for_kind(kind: HashKind, file: &mut impl Read) -> Result<ObjectHash, HashError> {
    ObjectHash::from_stream_for_kind(kind, file)
}

/// Read an object hash from the given reader using the thread-local [`HashKind`].
///
/// Legacy entry point; delegates to [`ObjectHash::from_stream`], whose
/// `read_exact`-based error surface is unchanged.
pub fn read_sha(file: &mut impl Read) -> io::Result<ObjectHash> {
    ObjectHash::from_stream(file)
}

/// A lightweight wrapper that counts bytes read from the underlying reader.
/// replace deflate.intotal() in decompress_data
pub struct CountingReader<R> {
    pub inner: R,
    pub bytes_read: u64,
}

impl<R> CountingReader<R> {
    /// Creates a new `CountingReader` wrapping the given reader.
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            bytes_read: 0,
        }
    }
}

impl<R: Read> Read for CountingReader<R> {
    /// Reads data into the provided buffer, updating the byte count.
    /// Returns the number of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        self.bytes_read += n as u64;
        Ok(n)
    }
}

impl<R: BufRead> BufRead for CountingReader<R> {
    /// Fills the internal buffer and returns a slice to it.
    /// Updates the byte count.
    /// Returns the number of bytes read.
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf()
    }

    /// Consumes `amt` bytes from the internal buffer, updating the byte count.
    /// Returns the number of bytes consumed.
    fn consume(&mut self, amt: usize) {
        self.bytes_read += amt as u64;
        self.inner.consume(amt);
    }
}
/// A streaming hasher abstraction over the supported [`HashKind`]s.
///
/// This is the crate's digest factory (GC-02): callers obtain a hasher through
/// [`HashAlgorithm::new_for_kind`] (explicit repository kind) or
/// [`HashAlgorithm::new`] (thread-local compatibility default) instead of
/// matching on the algorithm themselves. The remaining direct SHA dispatch in
/// `internal/pack/utils.rs` and `internal/pack/wrapper.rs` is migrated onto
/// this type in B3-03. It implements `std::io::Write` so it can be used as a
/// sink while streaming.
#[derive(Clone)]
pub enum HashAlgorithm {
    Sha1(Sha1),
    Sha256(sha2::Sha256),
    /// BLAKE3-256 (git-internal / Libra extension; 32-byte output). Boxed because the
    /// BLAKE3 hasher state is much larger than the SHA states.
    Blake3(Box<blake3::Hasher>),
}
impl HashAlgorithm {
    /// Create a new streaming hasher for an explicit `kind`.
    ///
    /// Does not consult the thread-local [`HashKind`]; use this on worker
    /// threads, async tasks and any code that may serve a repository other
    /// than the one configured on the current thread.
    pub fn new_for_kind(kind: HashKind) -> Self {
        match kind {
            HashKind::Sha1 => HashAlgorithm::Sha1(Sha1::new()),
            HashKind::Sha256 => HashAlgorithm::Sha256(sha2::Sha256::new()),
            HashKind::Blake3 => HashAlgorithm::Blake3(Box::new(blake3::Hasher::new())),
        }
    }
    /// Create a new hash algorithm instance based on the current thread-local hash kind.
    ///
    /// Compatibility wrapper around [`HashAlgorithm::new_for_kind`].
    pub fn new() -> Self {
        Self::new_for_kind(get_hash_kind())
    }
    /// The [`HashKind`] this hasher produces.
    pub fn kind(&self) -> HashKind {
        match self {
            HashAlgorithm::Sha1(_) => HashKind::Sha1,
            HashAlgorithm::Sha256(_) => HashKind::Sha256,
            HashAlgorithm::Blake3(_) => HashKind::Blake3,
        }
    }
    /// Update hash with data
    pub fn update(&mut self, data: &[u8]) {
        match self {
            HashAlgorithm::Sha1(hasher) => hasher.update(data),
            HashAlgorithm::Sha256(hasher) => hasher.update(data),
            HashAlgorithm::Blake3(hasher) => {
                hasher.update(data);
            }
        }
    }
    /// Finalize and get the raw digest bytes.
    pub fn finalize(self) -> Vec<u8> {
        match self {
            HashAlgorithm::Sha1(hasher) => hasher.finalize().to_vec(),
            HashAlgorithm::Sha256(hasher) => hasher.finalize().to_vec(),
            HashAlgorithm::Blake3(hasher) => hasher.finalize().as_bytes().to_vec(),
        }
    }
    /// Finalize into an [`ObjectHash`] of the hasher's own kind.
    ///
    /// The kind is taken from the hasher itself, so this is correct on any
    /// thread and is the preferred replacement for
    /// `ObjectHash::from_bytes(&hasher.finalize())` and for the deprecated
    /// length-inferring `ObjectHash::from_bytes_infer_kind` helper.
    pub fn finalize_object_hash(self) -> ObjectHash {
        match self {
            HashAlgorithm::Sha1(hasher) => ObjectHash::Sha1(hasher.finalize().into()),
            HashAlgorithm::Sha256(hasher) => ObjectHash::Sha256(hasher.finalize().into()),
            HashAlgorithm::Blake3(hasher) => ObjectHash::Blake3(*hasher.finalize().as_bytes()),
        }
    }
}
impl std::io::Write for HashAlgorithm {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;
    use crate::hash::set_hash_kind_for_test;

    const HELLO_SHA1: &str = "943a702d06f34599aee1f8da8ef9f7296031d699";
    const HELLO_SHA256: &str = "315f5bdb76d078c43b8ac0064e4a0164612b1fce77c869345bfc94c75894edd3";

    /// `HashAlgorithm::new_for_kind` produces the requested algorithm regardless of the
    /// thread-local kind, and `finalize_object_hash` tags the result with that kind.
    #[test]
    fn hash_algorithm_for_kind_ignores_thread_local() {
        let data = b"Hello, world!";
        for (kind, other, expected) in [
            (HashKind::Sha1, HashKind::Sha256, HELLO_SHA1),
            (HashKind::Sha256, HashKind::Sha1, HELLO_SHA256),
        ] {
            let _guard = set_hash_kind_for_test(other);

            let mut hasher = HashAlgorithm::new_for_kind(kind);
            assert_eq!(hasher.kind(), kind);
            // Stream in two chunks to exercise incremental update.
            hasher.update(&data[..5]);
            hasher.update(&data[5..]);
            let raw = hasher.clone().finalize();
            assert_eq!(raw.len(), kind.size());
            assert_eq!(hex::encode(&raw), expected);

            let object_hash = hasher.finalize_object_hash();
            assert_eq!(object_hash.kind(), kind);
            assert_eq!(object_hash.to_string(), expected);
            assert_eq!(object_hash, ObjectHash::new_for_kind(kind, data));

            // `std::io::Write` sink path yields the same digest.
            let mut sink = HashAlgorithm::new_for_kind(kind);
            std::io::Write::write_all(&mut sink, data).unwrap();
            assert_eq!(sink.finalize_object_hash(), object_hash);

            // Explicit stream reader of the digest bytes.
            let mut cursor = Cursor::new(object_hash.to_data());
            assert_eq!(read_sha_for_kind(kind, &mut cursor).unwrap(), object_hash);
        }
    }

    /// The parameterless constructors follow the thread-local kind (compatibility wrappers).
    #[test]
    fn hash_algorithm_for_kind_thread_local_wrappers() {
        for kind in [HashKind::Sha1, HashKind::Sha256, HashKind::Blake3] {
            let _guard = set_hash_kind_for_test(kind);
            assert_eq!(HashAlgorithm::new().kind(), kind);
            assert_eq!(HashAlgorithm::default().kind(), kind);
            let digest = ObjectHash::new(b"x");
            let mut cursor = Cursor::new(digest.to_data());
            assert_eq!(read_sha(&mut cursor).unwrap(), digest);
        }
    }
}
