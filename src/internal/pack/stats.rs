use std::{
    collections::{HashMap, HashSet},
    fmt,
    fs::File,
    io::{BufRead, BufReader, ErrorKind, Read},
    path::Path,
};

use flate2::bufread::ZlibDecoder;

use crate::{
    errors::GitError,
    hash::{HashKind, ObjectHash, get_hash_kind},
    internal::pack::{Pack, pack_index, utils, wrapper::Wrapper},
    utils::CountingReader,
};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct PackStats {
    /// Repository hash kind the pack (trailer, ref-delta bases, idx) was verified with.
    pub hash_kind: HashKind,
    pub total: usize,
    pub commits: usize,
    pub trees: usize,
    pub blobs: usize,
    pub tags: usize,
    pub deltas: usize,
}

struct PackScan {
    stats: PackStats,
    /// `(offset, name)` of every base (non-delta) object, streamed through the `kind` hasher.
    base_objects: Vec<(usize, ObjectHash)>,
    ref_delta_bases: HashSet<ObjectHash>,
    /// Start offset of every object in the pack (base and delta).
    object_offsets: HashSet<usize>,
    pack_hash: ObjectHash,
}

struct PackIndexEntries {
    names: HashSet<ObjectHash>,
    /// Name recorded by the idx at each pack offset (offsets are unique).
    by_offset: HashMap<u64, ObjectHash>,
    pack_hash: ObjectHash,
}

impl fmt::Display for PackStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PackStats {{ total: {}, commits: {}, trees: {}, blobs: {}, tags: {}, deltas: {} }}",
            self.total, self.commits, self.trees, self.blobs, self.tags, self.deltas
        )
    }
}

impl PackStats {
    /// Empty statistics tagged with an explicit repository `hash_kind`.
    pub fn new_with_hash_kind(hash_kind: HashKind) -> Self {
        PackStats {
            hash_kind,
            ..Default::default()
        }
    }

    /// Repository hash kind these statistics were computed for.
    pub fn hash_kind(&self) -> HashKind {
        self.hash_kind
    }

    /// Analyze a pack using the thread-local [`HashKind`]; compatibility wrapper around
    /// [`PackStats::analyze_with_hash_kind`].
    pub fn analyze<P: AsRef<Path>>(pack_path: P) -> Result<PackStats, GitError> {
        Self::analyze_with_hash_kind(get_hash_kind(), pack_path)
    }

    /// Analyze a pack of an explicit repository `kind`: the pack trailer, every ref-delta
    /// base ID and the accompanying idx (object names, pack checksum, idx checksum) are
    /// parsed and verified with that kind and never inferred from their length.
    pub fn analyze_with_hash_kind<P: AsRef<Path>>(
        kind: HashKind,
        pack_path: P,
    ) -> Result<PackStats, GitError> {
        let pack_path = pack_path.as_ref();
        if !pack_path.exists() {
            return Err(GitError::InvalidPackFile(format!(
                "Pack file not found: {}",
                pack_path.display()
            )));
        }

        let f = File::open(pack_path)
            .map_err(|e| GitError::InvalidPackFile(format!("Failed to open pack file: {e}")))?;
        let scan = Self::scan(BufReader::new(f), kind)?;
        let index = Self::read_pack_index_hashes(pack_path, kind)?;
        if index.is_none() && !scan.ref_delta_bases.is_empty() {
            return Err(GitError::InvalidPackFile(
                "Pack index is required to verify ref-delta bases".to_string(),
            ));
        }
        // An existing idx is verified against the pack even when there are no ref-deltas:
        // object count, copied pack checksum, every base object's streamed content hash and
        // every ref-delta base must all agree (fail-closed). This is a single-pass statistics
        // scan that inflates and hashes every base payload but does not resolve delta chains, so the idx names of *delta* objects are
        // outside its verification scope (their idx offsets must still be object boundaries);
        // `Pack::decode_file_full_without_callback` (or any decode that resolves deltas)
        // verifies those names by rebuilding each delta.
        if let Some(index) = index {
            if index.names.len() != scan.stats.total {
                return Err(GitError::InvalidPackFile(format!(
                    "Pack index lists {} objects but the pack contains {}",
                    index.names.len(),
                    scan.stats.total
                )));
            }
            if index.pack_hash != scan.pack_hash {
                return Err(GitError::InvalidPackFile(format!(
                    "Pack index hash {} does not match pack trailer hash {}",
                    index.pack_hash, scan.pack_hash
                )));
            }
            // Every idx entry must point at an object boundary of this pack.
            if let Some((offset, name)) = index.by_offset.iter().find(|(offset, _)| {
                !usize::try_from(**offset).is_ok_and(|offset| scan.object_offsets.contains(&offset))
            }) {
                return Err(GitError::InvalidPackFile(format!(
                    "Pack index entry {name} points at offset {offset}, which is not an object boundary of the pack"
                )));
            }
            // Every base object must be named by the idx *at its own offset*: a set-level
            // comparison would accept an idx whose names are merely permuted across offsets.
            for (offset, hash) in &scan.base_objects {
                match index.by_offset.get(&(*offset as u64)) {
                    Some(name) if name == hash => {}
                    Some(name) => {
                        return Err(GitError::InvalidPackFile(format!(
                            "Pack object {hash} ({kind}) at offset {offset} is not named by the pack index at that offset (index names {name})"
                        )));
                    }
                    None => {
                        return Err(GitError::InvalidPackFile(format!(
                            "Pack object {hash} ({kind}) at offset {offset} is not named by the pack index (no index entry at that offset)"
                        )));
                    }
                }
            }
            if let Some(base_hash) = scan
                .ref_delta_bases
                .iter()
                .find(|base_hash| !index.names.contains(*base_hash))
            {
                return Err(GitError::InvalidPackFile(format!(
                    "Ref-delta base {base_hash} is not present in the pack index"
                )));
            }
        }

        Ok(scan.stats)
    }

    pub fn validate_header<P: AsRef<Path>>(pack_path: P) -> Result<u32, GitError> {
        let pack_path = pack_path.as_ref();
        if !pack_path.exists() {
            return Err(GitError::InvalidPackFile(format!(
                "Pack file not found: {}",
                pack_path.display()
            )));
        }

        let f = File::open(pack_path)
            .map_err(|e| GitError::InvalidPackFile(format!("Failed to open pack file: {e}")))?;
        let mut reader = BufReader::new(f);

        let (count, _) = Pack::check_header(&mut reader)?;
        Ok(count)
    }

    fn scan(reader: impl BufRead, kind: HashKind) -> Result<PackScan, GitError> {
        let mut reader = Wrapper::new_with_kind(reader, kind);
        let (object_num, header_data) = Pack::check_header(&mut reader)?;
        let mut stats = PackStats {
            hash_kind: kind,
            total: object_num as usize,
            ..Default::default()
        };
        let first_object_offset = header_data.len();
        let mut offset = first_object_offset;
        let mut object_starts = HashSet::new();
        let mut ref_delta_bases = HashSet::new();
        let mut base_objects = Vec::new();

        for _ in 0..object_num {
            let object_start = offset;
            let (type_bits, size) = utils::read_type_and_varint_size(&mut reader, &mut offset)
                .map_err(|e| {
                    GitError::InvalidPackFile(format!("Read error at offset {offset}: {e}"))
                })?;

            stats.count_type_bits(type_bits, offset)?;

            match type_bits {
                1..=4 => {
                    // Stream the base object through the hasher (no payload retained) so its
                    // name can be checked against the idx.
                    let obj_type =
                        crate::internal::object::types::ObjectType::from_pack_type_u8(type_bits)?;
                    let (hash, consumed) =
                        Pack::hash_compressed_object(&mut reader, obj_type, size, kind)?;
                    add_to_offset(&mut offset, consumed)?;
                    base_objects.push((object_start, hash));
                }
                5 | 6 => {
                    let (delta_offset, consumed) = utils::read_offset_encoding(&mut reader)
                        .map_err(|e| {
                            GitError::InvalidPackFile(format!(
                                "Read offset encoding error at offset {offset}: {e}"
                            ))
                        })?;
                    let delta_offset = usize::try_from(delta_offset).map_err(|_| {
                        GitError::InvalidPackFile(format!(
                            "Offset delta at {object_start} exceeds platform limits"
                        ))
                    })?;
                    let base_offset = object_start.checked_sub(delta_offset).ok_or_else(|| {
                        GitError::InvalidPackFile(format!(
                            "Offset delta at {object_start} points before pack data"
                        ))
                    })?;
                    if delta_offset == 0
                        || base_offset < first_object_offset
                        || !object_starts.contains(&base_offset)
                    {
                        return Err(GitError::InvalidPackFile(format!(
                            "Offset delta at {object_start} does not reference an earlier object"
                        )));
                    }
                    add_to_offset(&mut offset, consumed)?;
                    drain_zlib(&mut reader, &mut offset, size)?;
                }
                7 => {
                    let base_hash =
                        ObjectHash::from_stream_for_kind(kind, &mut reader).map_err(|e| {
                            GitError::InvalidPackFile(format!(
                                "Read hash error at offset {offset}: {e}"
                            ))
                        })?;
                    add_to_offset(&mut offset, base_hash.size())?;
                    ref_delta_bases.insert(base_hash);
                    drain_zlib(&mut reader, &mut offset, size)?;
                }
                _ => unreachable!(),
            }
            object_starts.insert(object_start);
        }

        let computed_hash = reader.final_hash();
        let trailer = ObjectHash::from_stream_for_kind(kind, &mut reader).map_err(|e| {
            GitError::InvalidPackFile(format!("Failed to read trailer hash: {e:?}"))
        })?;
        if computed_hash != trailer {
            return Err(GitError::InvalidPackFile(format!(
                "Pack trailer mismatch: computed {computed_hash}, stored {trailer}"
            )));
        }
        if !utils::is_eof(&mut reader) {
            return Err(GitError::InvalidPackFile(
                "Pack has trailing data after trailer".to_string(),
            ));
        }

        Ok(PackScan {
            stats,
            base_objects,
            ref_delta_bases,
            object_offsets: object_starts,
            pack_hash: trailer,
        })
    }

    fn read_pack_index_hashes(
        pack_path: &Path,
        kind: HashKind,
    ) -> Result<Option<PackIndexEntries>, GitError> {
        let idx_path = pack_path.with_extension("idx");
        // `symlink_metadata`: a dangling `.idx` symlink counts as present (and then fails to
        // open) instead of being mistaken for a missing idx; only NotFound means "no idx".
        match std::fs::symlink_metadata(&idx_path) {
            Ok(_) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => {
                return Err(GitError::InvalidPackFile(format!(
                    "Pack index {} exists but cannot be read: {e}",
                    idx_path.display()
                )));
            }
        }
        let idx_file = File::open(&idx_path).map_err(|e| {
            GitError::InvalidPackFile(format!(
                "Pack index {} exists but cannot be read: {e}",
                idx_path.display()
            ))
        })?;
        let idx_len = idx_file
            .metadata()
            .map_err(|e| GitError::InvalidPackFile(format!("Read pack index metadata error: {e}")))?
            .len();
        // Streamed, size-bounded parse (no whole-file buffer).
        let parsed = pack_index::parse_idx_v2_from(BufReader::new(idx_file), kind, idx_len)?;
        let mut names = HashSet::with_capacity(parsed.entries.len());
        let mut by_offset = HashMap::with_capacity(parsed.entries.len());
        for entry in parsed.entries {
            names.insert(entry.hash);
            if by_offset.insert(entry.offset, entry.hash).is_some() {
                return Err(GitError::InvalidPackFile(format!(
                    "Pack index lists offset {} more than once",
                    entry.offset
                )));
            }
        }
        Ok(Some(PackIndexEntries {
            names,
            by_offset,
            pack_hash: parsed.pack_hash,
        }))
    }

    fn count_type_bits(&mut self, type_bits: u8, offset: usize) -> Result<(), GitError> {
        match type_bits {
            1 => {
                self.commits += 1;
            }
            2 => {
                self.trees += 1;
            }
            3 => {
                self.blobs += 1;
            }
            4 => {
                self.tags += 1;
            }
            5..=7 => {
                self.deltas += 1;
            }
            _ => {
                return Err(GitError::InvalidObjectType(format!(
                    "Unknown pack type bits: {type_bits} at offset {offset}"
                )));
            }
        }
        Ok(())
    }
}

fn drain_zlib(
    reader: &mut impl BufRead,
    offset: &mut usize,
    expected_size: usize,
) -> Result<(), GitError> {
    let mut counting_reader = CountingReader::new(reader);
    let mut deflate = ZlibDecoder::new(&mut counting_reader);
    let mut remaining = expected_size;
    let mut scratch = [0; 8192];

    while remaining > 0 {
        let chunk_len = remaining.min(scratch.len());
        let bytes = deflate
            .read(&mut scratch[..chunk_len])
            .map_err(|e| GitError::InvalidPackFile(format!("Decompression error: {e}")))?;
        if bytes == 0 {
            return Err(GitError::InvalidPackFile(format!(
                "The object size is smaller than the expected size {expected_size}"
            )));
        }
        remaining -= bytes;
    }

    let mut extra = [0; 1];
    let extra_bytes = deflate
        .read(&mut extra)
        .map_err(|e| GitError::InvalidPackFile(format!("Decompression error: {e}")))?;
    if extra_bytes != 0 {
        return Err(GitError::InvalidPackFile(format!(
            "The object size exceeds the expected size {expected_size}"
        )));
    }

    let consumed = usize::try_from(counting_reader.bytes_read).map_err(|_| {
        GitError::InvalidPackFile("Compressed object size exceeds platform limits".to_string())
    })?;
    add_to_offset(offset, consumed)
}

fn add_to_offset(offset: &mut usize, consumed: usize) -> Result<(), GitError> {
    *offset = offset
        .checked_add(consumed)
        .ok_or_else(|| GitError::InvalidPackFile("Pack offset overflow".to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::{
        hash::{HashKind, set_hash_kind_for_test},
        internal::pack::test_pack_download::download_pack_file,
        utils::HashAlgorithm,
    };

    #[test]
    fn test_analyze_small_pack_sha1() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let (pack_path, _dl_guard) = download_pack_file("small-sha1.pack");
        let stats = PackStats::analyze(pack_path).expect("Failed to analyze");

        assert!(stats.total > 0);
        assert_eq!(
            stats.total,
            stats.commits + stats.trees + stats.blobs + stats.tags + stats.deltas
        );
    }

    #[test]
    fn test_analyze_small_pack_sha256() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let (pack_path, _dl_guard) = download_pack_file("small-sha256.pack");
        let stats = PackStats::analyze(pack_path).expect("Failed to analyze");

        assert!(stats.total > 0);
        assert_eq!(
            stats.total,
            stats.commits + stats.trees + stats.blobs + stats.tags + stats.deltas
        );
    }

    #[test]
    fn test_analyze_delta_pack_sha1() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let (pack_path, _dl_guard) = download_pack_file("ref-delta-sha1.pack");
        let stats = PackStats::analyze(pack_path).expect("Failed to analyze");

        assert!(stats.total > 0);

        assert_eq!(
            stats.total,
            stats.commits + stats.trees + stats.blobs + stats.tags + stats.deltas
        );
    }

    #[test]
    fn test_analyze_delta_pack_sha256() {
        let _guard = set_hash_kind_for_test(HashKind::Sha256);
        let (pack_path, _dl_guard) = download_pack_file("ref-delta-sha256.pack");
        let stats = PackStats::analyze(pack_path).expect("Failed to analyze");

        assert!(stats.total > 0);
        assert_eq!(
            stats.total,
            stats.commits + stats.trees + stats.blobs + stats.tags + stats.deltas
        );
    }

    #[test]
    fn test_nonexistent_file() {
        let result = PackStats::analyze("tests/data/packs/nonexistent.pack");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_pack_file() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let mut temp = NamedTempFile::new().expect("create temp file");
        temp.write_all(b"XXXX").expect("write temp file");
        temp.flush().expect("flush temp file");

        let result = PackStats::analyze(temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_rejects_trailing_data() {
        use std::{fs, io::Write};

        use tempfile::NamedTempFile;

        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let (pack_path, _dl_guard) = download_pack_file("small-sha1.pack");
        let mut bytes = fs::read(pack_path).expect("read pack fixture");
        bytes.push(0);

        let mut temp = NamedTempFile::new().expect("create temp file");
        temp.write_all(&bytes).expect("write temp file");
        temp.flush().expect("flush temp file");

        let result = PackStats::analyze(temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_huge_object_count_does_not_preallocate() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PACK");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&u32::MAX.to_be_bytes());

        let mut temp = NamedTempFile::new().expect("create temp file");
        temp.write_all(&bytes).expect("write temp file");
        temp.flush().expect("flush temp file");

        let result = PackStats::analyze(temp.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_analyze_ref_delta_requires_index() {
        use std::io::Write;

        use flate2::{Compression, write::ZlibEncoder};
        use tempfile::NamedTempFile;

        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let mut deflate = ZlibEncoder::new(Vec::new(), Compression::default());
        deflate.write_all(&[]).expect("write zlib payload");
        let compressed_delta = deflate.finish().expect("finish zlib payload");

        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PACK");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&1u32.to_be_bytes());
        write_pack_object_header(&mut bytes, 7, 0);
        bytes.extend(std::iter::repeat_n(0, get_hash_kind().size()));
        bytes.extend_from_slice(&compressed_delta);
        append_pack_trailer(&mut bytes);

        let mut temp = NamedTempFile::new().expect("create temp file");
        temp.write_all(&bytes).expect("write temp file");
        temp.flush().expect("flush temp file");

        let result = PackStats::analyze(temp.path());
        assert!(format!("{result:?}").contains("Pack index is required"));
    }

    #[test]
    fn test_validate_header() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let (pack_path, _dl_guard) = download_pack_file("small-sha1.pack");
        let result = PackStats::validate_header(pack_path);
        assert!(result.is_ok());
        assert!(result.unwrap() > 0);
    }

    #[test]
    fn test_validate_header_nonexistent() {
        let result = PackStats::validate_header("tests/data/packs/nonexistent.pack");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_header_invalid_file() {
        use std::io::Write;

        use tempfile::NamedTempFile;

        let mut temp = NamedTempFile::new().expect("create temp file");
        temp.write_all(b"XX").expect("write temp file");
        temp.flush().expect("flush temp file");

        let result = PackStats::validate_header(temp.path());
        assert!(result.is_err());
    }

    fn write_pack_object_header(out: &mut Vec<u8>, type_bits: u8, mut size: usize) {
        let mut byte = ((type_bits & 0x07) << 4) | (size as u8 & 0x0f);
        size >>= 4;
        if size != 0 {
            byte |= 0x80;
        }
        out.push(byte);

        while size != 0 {
            let mut next = (size as u8) & 0x7f;
            size >>= 7;
            if size != 0 {
                next |= 0x80;
            }
            out.push(next);
        }
    }

    fn append_pack_trailer(bytes: &mut Vec<u8>) {
        append_pack_trailer_for_kind(bytes, get_hash_kind());
    }

    fn append_pack_trailer_for_kind(bytes: &mut Vec<u8>, kind: HashKind) {
        let mut hash = HashAlgorithm::new_for_kind(kind);
        hash.update(bytes);
        let trailer = hash.finalize_object_hash();
        bytes.extend_from_slice(trailer.as_ref());
    }

    fn append_zlib(out: &mut Vec<u8>, data: &[u8]) {
        use std::io::Write;
        let mut deflate =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        deflate.write_all(data).expect("zlib payload");
        out.extend_from_slice(&deflate.finish().expect("finish zlib payload"));
    }

    /// Minimal idx v2 writer for one BLAKE3 pack (used to exercise ref-delta validation).
    fn write_idx_v2_for_kind(
        pack_path: &Path,
        objects: &[(ObjectHash, u32)],
        kind: HashKind,
        version: u32,
    ) {
        let mut objects: Vec<(ObjectHash, u32)> = objects.to_vec();
        objects.sort_by(|a, b| a.0.as_ref().cmp(b.0.as_ref()));
        let mut idx = Vec::new();
        idx.extend_from_slice(&0xff74_4f63u32.to_be_bytes());
        idx.extend_from_slice(&version.to_be_bytes());
        for fanout_idx in 0..256 {
            let count = objects
                .iter()
                .filter(|(h, _)| h.as_ref()[0] as usize <= fanout_idx)
                .count() as u32;
            idx.extend_from_slice(&count.to_be_bytes());
        }
        for (h, _) in &objects {
            idx.extend_from_slice(h.as_ref());
        }
        for _ in &objects {
            idx.extend_from_slice(&0u32.to_be_bytes());
        }
        for (_, off) in &objects {
            idx.extend_from_slice(&off.to_be_bytes());
        }
        let pack = std::fs::read(pack_path).unwrap();
        idx.extend_from_slice(&pack[pack.len() - kind.size()..]);
        let mut hasher = HashAlgorithm::new_for_kind(kind);
        hasher.update(&idx);
        let idx_hash = hasher.finalize_object_hash();
        idx.extend_from_slice(idx_hash.as_ref());
        std::fs::write(pack_path.with_extension("idx"), idx).unwrap();
    }

    /// `PackStats::analyze_with_hash_kind(Blake3)` verifies a BLAKE3 trailer, resolves 32-byte
    /// BLAKE3 ref-delta bases through a BLAKE3 idx v2, rejects the same pack under SHA-256 and
    /// rejects an idx whose version is not 2 — all with a SHA-1 thread-local kind.
    #[test]
    fn blake3_pack_stats() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let kind = HashKind::Blake3;
        let dir = tempfile::tempdir().unwrap();

        // Two plain blobs.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PACK");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        write_pack_object_header(&mut bytes, 3, 5);
        append_zlib(&mut bytes, b"hello");
        let world_offset = bytes.len() as u32;
        write_pack_object_header(&mut bytes, 3, 5);
        append_zlib(&mut bytes, b"world");
        append_pack_trailer_for_kind(&mut bytes, kind);
        let plain = dir.path().join("plain.pack");
        std::fs::write(&plain, &bytes).unwrap();

        let stats = PackStats::analyze_with_hash_kind(kind, &plain).expect("blake3 stats");
        assert_eq!(stats.hash_kind(), HashKind::Blake3);
        assert_eq!(PackStats::new_with_hash_kind(kind).hash_kind(), kind);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.blobs, 2);
        assert_eq!(stats.deltas, 0);
        // Legacy `analyze` follows the thread-local (SHA-1) kind and cannot verify the trailer.
        assert!(PackStats::analyze(&plain).is_err());
        // An idx next to a plain pack is verified too: a checksum-valid idx naming an object
        // wrongly is rejected, the correct one is accepted.
        let hello = utils::calculate_object_hash_for_kind(
            kind,
            crate::internal::object::types::ObjectType::Blob,
            b"hello",
        )
        .unwrap();
        let world = utils::calculate_object_hash_for_kind(
            kind,
            crate::internal::object::types::ObjectType::Blob,
            b"world",
        )
        .unwrap();
        let bogus = ObjectHash::new_for_kind(kind, b"bogus");
        write_idx_v2_for_kind(&plain, &[(hello, 12), (bogus, world_offset)], kind, 2);
        let err = PackStats::analyze_with_hash_kind(kind, &plain).unwrap_err();
        assert!(
            err.to_string().contains("is not named by the pack index"),
            "{err}"
        );
        write_idx_v2_for_kind(&plain, &[(hello, 12), (world, world_offset)], kind, 2);
        assert_eq!(
            PackStats::analyze_with_hash_kind(kind, &plain)
                .unwrap()
                .blobs,
            2
        );
        // Swapping the offsets of two correctly named objects is caught: names are verified
        // at their own offsets, not as a set.
        write_idx_v2_for_kind(&plain, &[(hello, world_offset), (world, 12)], kind, 2);
        let err = PackStats::analyze_with_hash_kind(kind, &plain).unwrap_err();
        assert!(err.to_string().contains("index names"), "{err}");
        // An idx entry that does not point at an object boundary is rejected.
        write_idx_v2_for_kind(&plain, &[(hello, 12), (world, 13)], kind, 2);
        let err = PackStats::analyze_with_hash_kind(kind, &plain).unwrap_err();
        assert!(err.to_string().contains("not an object boundary"), "{err}");
        // A dangling `.idx` symlink is an error, never a fallback to the no-idx path.
        #[cfg(unix)]
        {
            let idx_path = plain.with_extension("idx");
            std::fs::remove_file(&idx_path).unwrap();
            std::os::unix::fs::symlink(dir.path().join("missing.idx"), &idx_path).unwrap();
            let err = PackStats::analyze_with_hash_kind(kind, &plain).unwrap_err();
            assert!(err.to_string().contains("cannot be read"), "{err}");
            std::fs::remove_file(&idx_path).unwrap();
        }
        write_idx_v2_for_kind(&plain, &[(hello, 12), (world, world_offset)], kind, 2);
        assert_eq!(
            PackStats::analyze_with_hash_kind(kind, &plain)
                .unwrap()
                .blobs,
            2
        );
        let err = PackStats::analyze_with_hash_kind(HashKind::Sha256, &plain).unwrap_err();
        assert!(err.to_string().contains("Pack trailer mismatch"), "{err}");

        // Base blob + ref delta whose base ID is a 32-byte BLAKE3 hash.
        let base_hash = utils::calculate_object_hash_for_kind(
            kind,
            crate::internal::object::types::ObjectType::Blob,
            b"hello",
        )
        .unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"PACK");
        bytes.extend_from_slice(&2u32.to_be_bytes());
        bytes.extend_from_slice(&2u32.to_be_bytes());
        let base_offset = bytes.len() as u32;
        write_pack_object_header(&mut bytes, 3, 5);
        append_zlib(&mut bytes, b"hello");
        let delta_offset = bytes.len() as u32;
        let delta_hash = utils::calculate_object_hash_for_kind(
            kind,
            crate::internal::object::types::ObjectType::Blob,
            b"HELLO",
        )
        .unwrap();
        write_pack_object_header(&mut bytes, 7, 8);
        bytes.extend_from_slice(base_hash.as_ref());
        append_zlib(
            &mut bytes,
            [b"\x05\x05\x05".as_ref(), b"HELLO"].concat().as_slice(),
        );
        append_pack_trailer_for_kind(&mut bytes, kind);
        let delta = dir.path().join("delta.pack");
        std::fs::write(&delta, &bytes).unwrap();

        // Without an idx the ref-delta base cannot be verified.
        assert!(
            PackStats::analyze_with_hash_kind(kind, &delta)
                .unwrap_err()
                .to_string()
                .contains("Pack index is required")
        );
        // Write the idx with the crate's own `IdxBuilder` (BLAKE3 names + checksums) so the
        // writer and this reader are verified against each other end-to-end.
        {
            use crate::internal::pack::pack_index::{IdxBuilder, IndexEntry};
            let pack_hash =
                ObjectHash::from_bytes_for_kind(kind, &bytes[bytes.len() - 32..]).unwrap();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            let idx_bytes = rt.block_on(async {
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Vec<u8>>(4096);
                let mut builder = IdxBuilder::new(2, tx, pack_hash);
                assert_eq!(builder.hash_kind(), kind);
                builder
                    .write_idx(vec![
                        IndexEntry {
                            hash: base_hash,
                            crc32: 0,
                            offset: base_offset as u64,
                        },
                        IndexEntry {
                            hash: delta_hash,
                            crc32: 0,
                            offset: delta_offset as u64,
                        },
                    ])
                    .await
                    .unwrap();
                let mut out = Vec::new();
                while let Some(chunk) = rx.recv().await {
                    out.extend_from_slice(&chunk);
                }
                out
            });
            std::fs::write(delta.with_extension("idx"), idx_bytes).unwrap();
        }
        let stats =
            PackStats::analyze_with_hash_kind(kind, &delta).expect("blake3 ref-delta stats");
        assert_eq!(stats.hash_kind(), kind);
        assert_eq!(stats.total, 2);
        assert_eq!(stats.blobs, 1);
        assert_eq!(stats.deltas, 1);
        // An idx that lists fewer objects than the pack is rejected.
        write_idx_v2_for_kind(&delta, &[(base_hash, base_offset)], kind, 2);
        let err = PackStats::analyze_with_hash_kind(kind, &delta).unwrap_err();
        assert!(
            err.to_string()
                .contains("lists 1 objects but the pack contains 2"),
            "{err}"
        );
        // An idx of any other version is rejected for BLAKE3.
        write_idx_v2_for_kind(
            &delta,
            &[(base_hash, base_offset), (delta_hash, delta_offset)],
            kind,
            1,
        );
        let err = PackStats::analyze_with_hash_kind(kind, &delta).unwrap_err();
        assert!(
            err.to_string().contains("Only pack index v2") && err.to_string().contains("blake3"),
            "{err}"
        );
    }
}
