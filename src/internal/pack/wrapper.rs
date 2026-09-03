//! Reader wrapper that tracks how many bytes of a pack have been consumed while keeping a running
//! SHA-1/SHA-256 hash for trailer verification.

use std::io::{self, BufRead, Read};

use crate::{
    hash::{HashKind, ObjectHash, get_hash_kind},
    utils::HashAlgorithm,
};
/// [`Wrapper`] is a wrapper around a reader that also computes the SHA1/ SHA256 hash of the data read.
///
/// It is designed to work with any reader that implements `BufRead`.
///
/// Fields:
/// * `inner`: The inner reader.
/// * `hash`: The optional hash state. `None` means only bytes read are counted.
/// * `bytes_read`: The number of bytes consumed from the wrapped reader.
///
pub struct Wrapper<R> {
    inner: R,
    hash: Option<HashAlgorithm>,
    bytes_read: usize,
}

impl<R> Wrapper<R>
where
    R: BufRead,
{
    /// Constructs a new [`Wrapper`] with hash tracking enabled for an explicit
    /// repository `kind`.
    ///
    /// Does not consult the thread-local [`HashKind`]; use this on worker
    /// threads and async tasks that may serve another repository.
    pub fn new_with_kind(inner: R, kind: HashKind) -> Self {
        Self {
            inner,
            hash: Some(HashAlgorithm::new_for_kind(kind)),
            bytes_read: 0,
        }
    }

    /// Constructs a new [`Wrapper`] with hash tracking enabled.
    ///
    /// Compatibility wrapper around [`Wrapper::new_with_kind`] using the
    /// thread-local [`HashKind`].
    ///
    /// # Parameters
    /// * `inner`: The reader to wrap.
    pub fn new(inner: R) -> Self {
        Self::new_with_kind(inner, get_hash_kind())
    }

    /// The [`HashKind`] of the running hash, or `None` when hash tracking is disabled.
    pub fn hash_kind(&self) -> Option<HashKind> {
        self.hash.as_ref().map(HashAlgorithm::kind)
    }

    /// Constructs a wrapper that only tracks bytes read, skipping the running hash.
    pub fn new_without_hash(inner: R) -> Self {
        Self {
            inner,
            hash: None,
            bytes_read: 0,
        }
    }

    /// Returns the number of bytes read so far.
    pub fn bytes_read(&self) -> usize {
        self.bytes_read
    }

    /// Returns the final SHA1/ SHA256 hash of the data read so far.
    ///
    /// This is a clone of the internal hash state finalized into a SHA1/ SHA256 hash.
    pub fn final_hash(&self) -> ObjectHash {
        self.hash
            .clone()
            .expect("Wrapper::final_hash called while hash tracking is disabled")
            .finalize_object_hash()
    }
}

impl<R> BufRead for Wrapper<R>
where
    R: BufRead,
{
    /// Provides access to the internal buffer of the wrapped reader without consuming it.
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        self.inner.fill_buf() // Delegate to the inner reader
    }

    /// Consumes data from the buffer and updates the hash when tracking is enabled.
    ///
    /// # Parameters
    /// * `amt`: The amount of data to consume from the buffer.
    fn consume(&mut self, amt: usize) {
        let buffer = self.inner.fill_buf().expect("Failed to fill buffer");
        if let Some(hash) = &mut self.hash {
            hash.update(&buffer[..amt]); // Update the running hash with the data being consumed
        }
        self.inner.consume(amt); // Consume the data from the inner reader
        self.bytes_read += amt;
    }
}

impl<R> Read for Wrapper<R>
where
    R: BufRead,
{
    /// Reads data into the provided buffer and updates the hash when tracking is enabled.
    /// <br> [Read::read_exact] calls it internally.
    ///
    /// # Parameters
    /// * `buf`: The buffer to read data into.
    ///
    /// # Returns
    /// Returns the number of bytes read.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let o = self.inner.read(buf)?; // Read data into the buffer
        if let Some(hash) = &mut self.hash {
            hash.update(&buf[..o]); // Update the running hash with the data being read
        }
        self.bytes_read += o;
        Ok(o) // Return the number of bytes read
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, BufRead, BufReader, Cursor, Read};

    use crate::{
        hash::{HashKind, ObjectHash, set_hash_kind_for_test},
        internal::pack::wrapper::Wrapper,
    };

    /// Helper function to test wrapper read functionality for different hash kinds.
    fn wrapper_read(kind: HashKind) {
        let _guard = set_hash_kind_for_test(kind);
        let data = b"Hello, world!"; // Sample data
        let cursor = Cursor::new(data.as_ref());
        let buf_reader = BufReader::new(cursor);
        let mut wrapper = Wrapper::new(buf_reader);

        let mut buffer = vec![0; data.len()];
        wrapper.read_exact(&mut buffer).unwrap();

        assert_eq!(buffer, data);
    }

    /// Verify Wrapper correctly reads data for both SHA-1 and SHA-256 hash modes.
    #[test]
    fn test_wrapper_read() {
        wrapper_read(HashKind::Sha1);
        wrapper_read(HashKind::Sha256);
    }

    /// Helper function to test wrapper hash functionality for different hash kinds.
    fn wrapper_hash_with_kind(kind: HashKind) -> io::Result<()> {
        let _guard = set_hash_kind_for_test(kind);
        let data = b"Hello, world!";
        let cursor = Cursor::new(data.as_ref());
        let buf_reader = BufReader::new(cursor);
        let mut wrapper = Wrapper::new(buf_reader);

        let mut buffer = vec![0; data.len()];
        wrapper.read_exact(&mut buffer)?;

        let hash_result = wrapper.final_hash();
        // Explicit-kind digest of the same bytes; no exhaustive `HashKind` match here so a
        // future variant does not break this fixture.
        let expected_hash = ObjectHash::new_for_kind(kind, data);

        assert_eq!(hash_result, expected_hash);
        assert_eq!(wrapper.hash_kind(), Some(kind));
        Ok(())
    }

    /// `new_with_kind` hashes for the explicit kind regardless of the thread-local kind,
    /// through both `read` and `consume` paths.
    #[test]
    fn test_wrapper_new_with_kind_ignores_thread_local() -> io::Result<()> {
        for (kind, other) in [
            (HashKind::Sha1, HashKind::Sha256),
            (HashKind::Sha256, HashKind::Sha1),
        ] {
            let _guard = set_hash_kind_for_test(other);
            let data = b"Hello, world!";
            let expected = ObjectHash::new_for_kind(kind, data);

            let mut wrapper =
                Wrapper::new_with_kind(BufReader::new(Cursor::new(data.as_ref())), kind);
            let mut buffer = vec![0; data.len()];
            wrapper.read_exact(&mut buffer)?;
            assert_eq!(wrapper.hash_kind(), Some(kind));
            assert_eq!(wrapper.final_hash(), expected);
            assert_eq!(wrapper.bytes_read(), data.len());

            let mut wrapper =
                Wrapper::new_with_kind(BufReader::new(Cursor::new(data.as_ref())), kind);
            let n = wrapper.fill_buf()?.len();
            wrapper.consume(n);
            assert_eq!(wrapper.final_hash(), expected);

            assert_eq!(
                Wrapper::new(BufReader::new(Cursor::new(data.as_ref()))).hash_kind(),
                Some(other)
            );
            assert_eq!(
                Wrapper::new_without_hash(BufReader::new(Cursor::new(data.as_ref()))).hash_kind(),
                None
            );
        }
        Ok(())
    }
    #[test]
    fn test_wrapper_hash() -> io::Result<()> {
        wrapper_hash_with_kind(HashKind::Sha1)?;
        wrapper_hash_with_kind(HashKind::Sha256)?;
        Ok(())
    }
}
