//! Buffered inflate reader that decodes Git's zlib-compressed objects while simultaneously tracking
//! SHA digests for integrity verification.

use std::{io, io::BufRead};

use flate2::{Decompress, FlushDecompress, Status};

use crate::{
    errors::GitError,
    hash::{HashError, HashKind, get_hash_kind},
    internal::object::types::ObjectType,
    utils::HashAlgorithm,
};

/// ReadBoxed is to unzip information from a  DEFLATE stream,
/// which hash [`BufRead`] trait.
/// For a continuous stream of DEFLATE information, the structure
/// does not read too many bytes to affect subsequent information
/// reads
pub struct ReadBoxed<R> {
    /// The reader from which bytes should be decompressed.
    pub inner: R,
    /// The decompressor doing all the work.
    pub decompressor: Box<Decompress>,
    /// the [`count_hash`] decide whether to calculate the hash value in the [`read`] method
    count_hash: bool,
    /// The current hash state for the decompressed data.
    /// It is updated as data is read from the stream.
    pub hash: HashAlgorithm,
}
impl<R> ReadBoxed<R>
where
    R: BufRead,
{
    /// Seed `hash` with the loose-object header `<type> <size>\0` and build the reader.
    fn with_header(inner: R, mut hash: HashAlgorithm, type_bytes: &[u8], size: usize) -> Self {
        hash.update(type_bytes);
        hash.update(b" ");
        hash.update(size.to_string().as_bytes());
        hash.update(b"\0");
        ReadBoxed {
            inner,
            hash,
            count_hash: true,
            decompressor: Box::new(Decompress::new(true)),
        }
    }

    /// New a ReadBoxed for a common (non-delta) object whose ID must be computed
    /// with an explicit repository `kind`.
    ///
    /// Does not consult the thread-local [`HashKind`]. Delta object types have no
    /// loose-object header and are rejected with
    /// [`HashError::UnsupportedObjectType`] (carrying the operation, `kind`,
    /// the expected digest width and the offered payload size) wrapped in
    /// [`GitError::InvalidHashValue`].
    pub fn new_with_kind(
        inner: R,
        obj_type: ObjectType,
        size: usize,
        kind: HashKind,
    ) -> Result<Self, GitError> {
        let type_bytes = obj_type
            .to_bytes()
            .ok_or(HashError::UnsupportedObjectType {
                operation: "ReadBoxed::new_with_kind",
                kind,
                object_type: obj_type,
                expected: kind.size(),
                actual: 0,
                payload_len: size,
            })?;
        Ok(Self::with_header(
            inner,
            HashAlgorithm::new_for_kind(kind),
            type_bytes,
            size,
        ))
    }

    /// New a ReadBoxed for zlib read, the Output ReadBoxed is for the Common Object,
    /// but not for the Delta Object,if that ,see new_for_delta method below.
    ///
    /// Legacy entry point using the thread-local [`HashKind`]; keeps its
    /// pre-existing panicking contract for delta types. Prefer
    /// [`ReadBoxed::new_with_kind`].
    pub fn new(inner: R, obj_type: ObjectType, size: usize) -> Self {
        // Initialize the hash with the object header.
        let hash = HashAlgorithm::new();
        let type_bytes = obj_type
            .to_bytes()
            .expect("ReadBoxed::new called with a delta type");
        Self::with_header(inner, hash, type_bytes, size)
    }

    /// New a ReadBoxed for a delta object with an explicit repository `kind`.
    /// Delta payloads are not hashed, so the hasher is only carried for API symmetry.
    pub fn new_for_delta_with_kind(inner: R, kind: HashKind) -> Self {
        ReadBoxed {
            inner,
            hash: HashAlgorithm::new_for_kind(kind),
            count_hash: false,
            decompressor: Box::new(Decompress::new(true)),
        }
    }

    /// New a ReadBoxed for zlib read, the Output ReadBoxed is for the Delta Object,
    /// which does not need to calculate the hash value.
    ///
    /// Compatibility wrapper around [`ReadBoxed::new_for_delta_with_kind`] using
    /// the thread-local [`HashKind`].
    pub fn new_for_delta(inner: R) -> Self {
        Self::new_for_delta_with_kind(inner, get_hash_kind())
    }

    /// The [`HashKind`] this reader's hasher produces.
    pub fn hash_kind(&self) -> HashKind {
        self.hash.kind()
    }
}
impl<R> io::Read for ReadBoxed<R>
where
    R: BufRead,
{
    fn read(&mut self, into: &mut [u8]) -> io::Result<usize> {
        let o = read(&mut self.inner, &mut self.decompressor, into)?;
        //update the hash value
        if self.count_hash {
            self.hash.update(&into[..o]);
        }
        Ok(o)
    }
}

/// Read bytes from `rd` and decompress them using `state` into a pre-allocated fitting buffer `dst`, returning the amount of bytes written.
fn read(rd: &mut impl BufRead, state: &mut Decompress, mut dst: &mut [u8]) -> io::Result<usize> {
    let mut total_written = 0;
    loop {
        let (written, consumed, ret, eof);
        {
            let input = rd.fill_buf()?;
            eof = input.is_empty();
            let before_out = state.total_out();
            let before_in = state.total_in();
            let flush = if eof {
                FlushDecompress::Finish
            } else {
                FlushDecompress::None
            };
            ret = state.decompress(input, dst, flush);
            written = (state.total_out() - before_out) as usize;
            total_written += written;
            dst = &mut dst[written..];
            consumed = (state.total_in() - before_in) as usize;
        }
        rd.consume(consumed);

        match ret {
            // The stream has officially ended, nothing more to do here.
            Ok(Status::StreamEnd) => return Ok(total_written),
            // Either input our output are depleted even though the stream is not depleted yet.
            Ok(Status::Ok | Status::BufError) if eof || dst.is_empty() => return Ok(total_written),
            // Some progress was made in both the input and the output, it must continue to reach the end.
            Ok(Status::Ok | Status::BufError) if consumed != 0 || written != 0 => continue,
            // A strange state, where zlib makes no progress but isn't done either. Call it out.
            Ok(Status::Ok | Status::BufError) => unreachable!("Definitely a bug somewhere"),
            Err(..) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "corrupt deflate stream",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use flate2::{Compression, write::ZlibEncoder};
    use sha1::{Digest, Sha1};

    use super::*;
    use crate::hash::{HashKind, ObjectHash, set_hash_kind_for_test};

    /// Helper to build zlib-compressed bytes from input data.
    fn zlib_compress(data: &[u8]) -> Vec<u8> {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    /// ReadBoxed::new should inflate data and accumulate SHA-1 over the object header + body.
    #[test]
    fn inflate_object_counts_hash() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let body = b"hello\n";
        let compressed = zlib_compress(body);
        let cursor = io::Cursor::new(compressed);

        let mut reader = ReadBoxed::new(cursor, ObjectType::Blob, body.len());
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, body);

        // Expected hash: header "blob <len>\\0" + body
        let mut expected = Sha1::new();
        expected.update(ObjectType::Blob.to_bytes().unwrap());
        expected.update(b" ");
        expected.update(body.len().to_string());
        expected.update(b"\0");
        expected.update(body);
        assert_eq!(reader.hash.finalize(), expected.finalize().to_vec());
    }

    /// ReadBoxed::new_for_delta should inflate data without touching the hash accumulator.
    #[test]
    fn inflate_delta_skips_hash() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let body = b"delta bytes";
        let compressed = zlib_compress(body);
        let cursor = io::Cursor::new(compressed);

        let mut reader = ReadBoxed::new_for_delta(cursor);
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, body);

        // Hash should remain the initial zero-state (Sha1 of empty string)
        let empty_hash = Sha1::new().finalize();
        assert_eq!(reader.hash.finalize(), empty_hash.to_vec());
    }

    /// Corrupt deflate stream should surface as InvalidInput.
    #[test]
    fn corrupt_stream_returns_error() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let data = b"not a valid zlib stream";
        let mut reader = ReadBoxed::new(io::Cursor::new(data), ObjectType::Blob, data.len());
        let mut out = [0u8; 16];
        let err = reader.read(&mut out).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    /// With SHA-256 configured, hash accumulation should match SHA-256 object ID.
    #[test]
    fn inflate_object_counts_hash_sha256() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let body = b"content";
        let compressed = zlib_compress(body);
        let cursor = io::Cursor::new(compressed);

        let mut reader = ReadBoxed::new(cursor, ObjectType::Blob, body.len());
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, body);

        // Reader uses repository hash kind (SHA-256) internally.
        let reader_hash = reader.hash.finalize();
        let expected = ObjectHash::from_type_and_data(ObjectType::Blob, body);

        assert_eq!(reader_hash.len(), 32);
        assert_eq!(expected.as_ref().len(), 32);
        assert_eq!(reader_hash.as_slice(), expected.as_ref());
    }

    /// `new_with_kind` hashes with the explicit kind regardless of the thread-local kind.
    #[test]
    fn inflate_object_new_with_kind_ignores_thread_local() {
        for (kind, other) in [
            (HashKind::Sha1, HashKind::Sha256),
            (HashKind::Sha256, HashKind::Sha1),
        ] {
            let _guard = set_hash_kind_for_test(other);
            let body = b"content";
            let compressed = zlib_compress(body);

            let mut reader = ReadBoxed::new_with_kind(
                io::Cursor::new(&compressed),
                ObjectType::Blob,
                body.len(),
                kind,
            )
            .unwrap();
            assert_eq!(reader.hash_kind(), kind);
            let mut out = Vec::new();
            reader.read_to_end(&mut out).unwrap();
            assert_eq!(out, body);

            let expected =
                ObjectHash::from_type_and_data_for_kind(kind, ObjectType::Blob, body).unwrap();
            assert_eq!(reader.hash.finalize_object_hash(), expected);

            // Legacy constructors follow the thread-local kind.
            assert_eq!(
                ReadBoxed::new(io::Cursor::new(&compressed), ObjectType::Blob, body.len())
                    .hash_kind(),
                other
            );
            assert_eq!(
                ReadBoxed::new_for_delta(io::Cursor::new(&compressed)).hash_kind(),
                other
            );
            assert_eq!(
                ReadBoxed::new_for_delta_with_kind(io::Cursor::new(&compressed), kind).hash_kind(),
                kind
            );
        }
    }
}
