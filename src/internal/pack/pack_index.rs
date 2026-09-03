//! Builder for Git pack index (.idx) files that streams fanout tables, CRCs, offsets, and trailer
//! hashes through an async channel.

use tokio::sync::mpsc;

pub use crate::internal::pack::index_entry::IndexEntry;
use crate::{
    errors::GitError,
    hash::{HashKind, ObjectHash},
    utils::HashAlgorithm,
};

/// Magic bytes of a pack index (`\xfftOc`).
pub const IDX_MAGIC: u32 = 0xff74_4f63;
/// The only pack index version this crate reads or writes.
pub const IDX_VERSION_V2: u32 = 2;
/// Upper bound on the entry capacity reserved up front from an idx's declared object count.
const IDX_PREALLOC_CAP: usize = 1 << 16;

/// Reject anything but a v2 pack index header (fail-closed for every hash kind, and the
/// only layout that can carry 32-byte SHA-256 / BLAKE3 object names).
pub fn validate_idx_v2_header(
    magic: u32,
    version: u32,
    kind: HashKind,
    context: &str,
) -> Result<(), GitError> {
    if magic != IDX_MAGIC {
        return Err(GitError::InvalidPackFile(format!(
            "Invalid pack index magic {magic:#010x} for {context} ({kind} repository)"
        )));
    }
    if version != IDX_VERSION_V2 {
        return Err(GitError::InvalidPackFile(format!(
            "Only pack index v2 is supported for {context}: got version {version} (this crate reads and writes v2 only; {kind} repository, {}-byte object names)",
            kind.size()
        )));
    }
    Ok(())
}

/// A parsed pack index (v2) with every object name verified for `kind` and both
/// checksums checked.
#[derive(Debug, Clone)]
pub struct IdxV2 {
    /// Entries in on-disk (object-name) order; `offset` already merges the 8-byte table and
    /// `crc32` is the CRC recorded for the object's compressed pack bytes (verified by the
    /// decoder when it tracks CRCs).
    pub entries: Vec<IndexEntry>,
    /// The pack checksum copied into the idx trailer.
    pub pack_hash: ObjectHash,
    /// The idx file checksum (verified).
    pub idx_hash: ObjectHash,
}

/// Reader wrapper that feeds everything it reads into a `kind` hasher (for the idx checksum).
struct IdxHashingReader<R> {
    inner: R,
    hasher: HashAlgorithm,
}

impl<R: std::io::Read> IdxHashingReader<R> {
    fn read_exact_hashed(&mut self, buf: &mut [u8]) -> Result<(), GitError> {
        self.inner
            .read_exact(buf)
            .map_err(|e| GitError::InvalidPackFile(format!("Read index error: {e}")))?;
        self.hasher.update(buf);
        Ok(())
    }
    fn read_u32_hashed(&mut self) -> Result<u32, GitError> {
        let mut buf = [0u8; 4];
        self.read_exact_hashed(&mut buf)?;
        Ok(u32::from_be_bytes(buf))
    }
}

/// Parse and fully verify an in-memory pack index v2 for an explicit repository `kind`
/// (see [`parse_idx_v2_from`]).
pub fn parse_idx_v2(bytes: &[u8], kind: HashKind) -> Result<IdxV2, GitError> {
    parse_idx_v2_from(std::io::Cursor::new(bytes), kind, bytes.len() as u64)
}

/// Parse and fully verify a pack index v2 **streamed** from `reader` for an explicit
/// repository `kind`; `total_len` is the index length in bytes (file metadata), used to
/// validate the object count *before* anything is allocated.
///
/// Verified, in order: magic/version; fanout monotonic and `fanout[255] == object count`;
/// the declared size fits in `total_len` (so a hostile fanout cannot drive an allocation);
/// every object name has `kind` width, names are strictly ascending and the per-first-byte
/// counts match the fanout table exactly; the CRC table is read (its values are checked by
/// the decoder against the pack bytes); 4-byte offsets merged with the 8-byte large-offset
/// table (every referenced slot must exist); the copied pack checksum; the idx checksum
/// over everything before it; and no trailing bytes. Any inconsistency fails closed and the
/// kind is never inferred from the name width.
pub fn parse_idx_v2_from<R: std::io::Read>(
    reader: R,
    kind: HashKind,
    total_len: u64,
) -> Result<IdxV2, GitError> {
    let hs = kind.size();
    let mut reader = IdxHashingReader {
        inner: reader,
        hasher: HashAlgorithm::new_for_kind(kind),
    };
    let magic = reader.read_u32_hashed()?;
    let version = reader.read_u32_hashed()?;
    validate_idx_v2_header(magic, version, kind, "index parsing")?;

    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = reader.read_u32_hashed()?;
        if i > 0 && fanout[i] < fanout[i - 1] {
            return Err(GitError::InvalidPackFile(format!(
                "Pack index fanout is not monotonic at entry {i}"
            )));
        }
    }
    let object_num = fanout[255] as usize;
    // Size sanity check before any allocation: names + crc + offsets + two checksums.
    let fixed = 8u64 + 256 * 4 + 2 * hs as u64;
    let per_object = (hs + 4 + 4) as u64;
    let declared = fixed + per_object * object_num as u64;
    if declared > total_len {
        return Err(GitError::InvalidPackFile(format!(
            "Pack index declares {object_num} objects ({declared} bytes) but is only {total_len} bytes long"
        )));
    }

    // Never pre-allocate by the untrusted declared count alone: the length check above only
    // bounds it by the file size, and a sparse or hostile file can be arbitrarily long. The
    // vector grows as entries are actually read and validated (strictly ascending names), so
    // a garbage table fails at its first bad entry instead of reserving gigabytes up front.
    let mut entries: Vec<IndexEntry> = Vec::with_capacity(object_num.min(IDX_PREALLOC_CAP));
    let mut per_first_byte = [0u32; 256];
    let mut name = vec![0u8; hs];
    for i in 0..object_num {
        reader.read_exact_hashed(&mut name)?;
        let hash = ObjectHash::from_bytes_for_kind(kind, &name)
            .map_err(|e| GitError::InvalidPackFile(format!("Pack index object name {i}: {e}")))?;
        if let Some(prev) = entries.last()
            && prev.hash.as_ref() >= name.as_slice()
        {
            return Err(GitError::InvalidPackFile(format!(
                "Pack index object names are not strictly ascending at entry {i}"
            )));
        }
        per_first_byte[name[0] as usize] += 1;
        entries.push(IndexEntry {
            hash,
            crc32: 0,
            offset: 0,
        });
    }
    let mut running = 0u32;
    for (byte, count) in per_first_byte.iter().enumerate() {
        running += count;
        if fanout[byte] != running {
            return Err(GitError::InvalidPackFile(format!(
                "Pack index fanout[{byte:#04x}] is {} but {running} object names start at or below it",
                fanout[byte]
            )));
        }
    }
    for entry in entries.iter_mut() {
        entry.crc32 = reader.read_u32_hashed()?;
    }
    let mut large_slots = Vec::new();
    for (i, entry) in entries.iter_mut().enumerate() {
        let raw_offset = reader.read_u32_hashed()?;
        if raw_offset & 0x8000_0000 == 0 {
            entry.offset = u64::from(raw_offset);
        } else {
            large_slots.push((i, (raw_offset & 0x7fff_ffff) as usize));
        }
    }
    let large_count = large_slots
        .iter()
        .map(|&(_, slot)| slot + 1)
        .max()
        .unwrap_or(0);
    if large_count > large_slots.len() {
        return Err(GitError::InvalidPackFile(format!(
            "Pack index references large-offset slot {} but only {} objects use the large table",
            large_count - 1,
            large_slots.len()
        )));
    }
    if declared + (large_count as u64) * 8 > total_len {
        return Err(GitError::InvalidPackFile(
            "Pack index is truncated before its large-offset table".to_string(),
        ));
    }
    let mut large_offsets = Vec::with_capacity(large_count);
    for _ in 0..large_count {
        let mut buf = [0u8; 8];
        reader.read_exact_hashed(&mut buf)?;
        large_offsets.push(u64::from_be_bytes(buf));
    }
    for (i, slot) in large_slots {
        entries[i].offset = large_offsets[slot];
    }
    // Offsets must be unique: two names at one pack offset cannot both be right. Bounded by
    // the (already size-checked) entry count.
    let mut seen_offsets = std::collections::HashSet::with_capacity(entries.len());
    for entry in &entries {
        if !seen_offsets.insert(entry.offset) {
            return Err(GitError::InvalidPackFile(format!(
                "Pack index lists offset {} more than once",
                entry.offset
            )));
        }
    }

    let mut pack_hash_buf = vec![0u8; hs];
    reader.read_exact_hashed(&mut pack_hash_buf)?;
    let pack_hash = ObjectHash::from_bytes_for_kind(kind, &pack_hash_buf)
        .map_err(|e| GitError::InvalidPackFile(format!("Pack index pack checksum: {e}")))?;
    let computed = reader.hasher.clone().finalize_object_hash();
    let mut idx_hash_buf = vec![0u8; hs];
    reader
        .inner
        .read_exact(&mut idx_hash_buf)
        .map_err(|e| GitError::InvalidPackFile(format!("Read index error: {e}")))?;
    let idx_hash = ObjectHash::from_bytes_for_kind(kind, &idx_hash_buf)
        .map_err(|e| GitError::InvalidPackFile(format!("Pack index checksum: {e}")))?;
    if computed != idx_hash {
        return Err(GitError::InvalidPackFile(format!(
            "Pack index checksum {idx_hash} does not match calculated checksum {computed} ({kind})"
        )));
    }
    let mut trailing = [0u8; 1];
    let extra = reader
        .inner
        .read(&mut trailing)
        .map_err(|e| GitError::InvalidPackFile(format!("Read index error: {e}")))?;
    if extra != 0 {
        return Err(GitError::InvalidPackFile(
            "Pack index has trailing data after checksum".to_string(),
        ));
    }
    Ok(IdxV2 {
        entries,
        pack_hash,
        idx_hash,
    })
}

/// Builder for Git pack index (.idx) files that streams data through an async channel.
/// # Arguments
/// * `object_number` - Total number of objects in the pack file.
/// * `sender` - Async channel sender to stream idx data.
/// * `pack_hash` - Hash of the corresponding pack file (used in the idx trailer).
/// * `inner_hash` - Hash algorithm instance to compute the idx file hash.
pub struct IdxBuilder {
    sender: Option<mpsc::Sender<Vec<u8>>>,
    inner_hash: HashAlgorithm, //  idx trailer
    object_number: usize,
    pack_hash: ObjectHash,
}

impl IdxBuilder {
    /// Create a new IdxBuilder.
    ///
    /// The idx checksum and the object-name width follow `pack_hash.kind()` — the
    /// repository kind of the pack being indexed — never the thread-local kind.
    pub fn new(object_number: usize, sender: mpsc::Sender<Vec<u8>>, pack_hash: ObjectHash) -> Self {
        Self {
            sender: Some(sender),
            inner_hash: HashAlgorithm::new_for_kind(pack_hash.kind()),
            object_number,
            pack_hash,
        }
    }

    /// Hash kind of the pack being indexed (drives the object-name width and idx checksum).
    pub fn hash_kind(&self) -> HashKind {
        self.pack_hash.kind()
    }

    /// Drop the sender to close the channel.
    pub fn drop_sender(&mut self) {
        self.sender.take(); // Take the sender out, dropping it
    }

    /// Send data through the channel and update the inner hash.
    async fn send_data(&mut self, data: Vec<u8>) -> Result<(), GitError> {
        if let Some(sender) = &self.sender {
            self.inner_hash.update(&data);
            sender.send(data).await.map_err(|e| {
                GitError::IOError(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("Failed to send idx data: {e}"),
                ))
            })?;
        }
        Ok(())
    }

    /// Send data through the channel without updating the inner hash.
    async fn send_data_without_update_hash(&mut self, data: Vec<u8>) -> Result<(), GitError> {
        if let Some(sender) = &self.sender {
            sender.send(data).await.map_err(|e| {
                GitError::IOError(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    format!("Failed to send idx data: {e}"),
                ))
            })?;
        }
        Ok(())
    }

    /// send u32 value (big-endian)
    async fn send_u32(&mut self, v: u32) -> Result<(), GitError> {
        self.send_data(v.to_be_bytes().to_vec()).await
    }

    /// send u64 value (big-endian)
    async fn send_u64(&mut self, v: u64) -> Result<(), GitError> {
        self.send_data(v.to_be_bytes().to_vec()).await
    }

    /// Write the idx v2 header (Git pack index format, used for both SHA1 and SHA256).
    /// The 4-byte pack index signature: \377t0c, followed by 4-byte version number: 2.
    async fn write_header(&mut self) -> Result<(), GitError> {
        // .idx v2 header (used for both SHA1 and SHA256)
        // magic: FF 74 4F 63, version: 2
        let header: [u8; 8] = [0xFF, 0x74, 0x4F, 0x63, 0, 0, 0, 2];
        self.send_data(header.to_vec()).await
    }

    /// Write the fanout table for the index.
    async fn write_fanout(&mut self, entries: &mut [IndexEntry]) -> Result<(), GitError> {
        entries.sort_by_key(|entry| entry.hash);
        let mut fanout = [0u32; 256];
        for entry in entries.iter() {
            fanout[entry.hash.to_data()[0] as usize] += 1;
        }

        // Calculate cumulative counts
        for i in 1..fanout.len() {
            fanout[i] += fanout[i - 1];
        }

        // Send all 256 cumulative counts
        for &count in fanout.iter() {
            self.send_u32(count).await?;
        }

        Ok(())
    }

    /// Write the object names (hashes) to the index.
    async fn write_names(&mut self, entries: &Vec<IndexEntry>) -> Result<(), GitError> {
        for e in entries {
            self.send_data(e.hash.to_data().clone()).await?;
        }

        Ok(())
    }

    /// Write the CRC32 checksums for each object in the index.
    async fn write_crc32(&mut self, entries: &Vec<IndexEntry>) -> Result<(), GitError> {
        for e in entries {
            self.send_u32(e.crc32).await?;
        }

        Ok(())
    }

    /// Write the offsets for each object in the index, handling large offsets.
    async fn write_offsets(&mut self, entries: &Vec<IndexEntry>) -> Result<(), GitError> {
        let mut large = vec![];
        for e in entries {
            if e.offset <= 0x7FFF_FFFF {
                // normal 31-bit offset
                self.send_u32(e.offset as u32).await?;
            } else {
                // MSB=1 => large offset reference , a label for large offset
                let marker = 0x8000_0000 | large.len() as u32;
                self.send_u32(marker).await?;
                large.push(e.offset);
            }
        }
        for v in large {
            self.send_u64(v).await?;
        }
        Ok(())
    }

    /// Write the idx trailer containing the pack hash and idx file hash.
    ///
    /// Per the Git idx v2 layout the idx checksum covers *everything* before it, including
    /// the copied pack checksum; the crate's readers (`Pack` and `PackStats`) verify it that
    /// way, so the pack hash is fed to the running hash too.
    async fn write_trailer(&mut self) -> Result<(), GitError> {
        // pack hash (part of the idx checksum input)
        self.send_data(self.pack_hash.to_data()).await?;

        let idx_hash = self.inner_hash.clone().finalize();
        // idx file hash (not hashed itself)
        self.send_data_without_update_hash(idx_hash).await?;
        Ok(())
    }

    /// Write the complete idx file by sending header, fanout, names, CRCs, offsets, and trailer.
    pub async fn write_idx(&mut self, mut entries: Vec<IndexEntry>) -> Result<(), GitError> {
        // check entries length
        if entries.len() != self.object_number {
            return Err(GitError::ConversionError(format!(
                "entries length {} != object_number {}",
                entries.len(),
                self.object_number
            )));
        }
        // every object name must belong to the pack's kind (one repository kind per idx)
        let kind = self.hash_kind();
        for entry in &entries {
            entry.hash.ensure_kind(kind)?;
        }

        // write header
        self.write_header().await?;
        self.write_fanout(&mut entries).await?;
        self.write_names(&entries).await?;
        self.write_crc32(&entries).await?;
        self.write_offsets(&entries).await?;
        self.write_trailer().await?;
        self.drop_sender();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use tokio::sync::mpsc;

    use crate::{
        errors::GitError,
        hash::ObjectHash,
        internal::pack::{index_entry::IndexEntry, pack_index::IdxBuilder},
    };

    /// construct fake sha1 hash
    fn fake_sha1(n: u8) -> ObjectHash {
        ObjectHash::Sha1([n; 20])
    }

    /// construct entries (hashes from 1, 2, 3… for fanout testing)
    fn build_entries_sha1(n: usize) -> Vec<IndexEntry> {
        (0..n)
            .map(|i| IndexEntry {
                hash: fake_sha1(i as u8),
                crc32: 0x12345678 + i as u32,
                offset: 0x10 + (i as u64) * 3,
            })
            .collect()
    }

    /// Test basic idx building for SHA1 pack index.
    #[tokio::test]
    async fn test_idx_builder_sha1_basic() -> Result<(), GitError> {
        // mock channel catcher
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);

        let object_number = 3;
        let pack_hash = fake_sha1(0xAA);

        let mut builder = IdxBuilder::new(object_number, tx, pack_hash);

        let entries = build_entries_sha1(object_number);

        // execute idx write
        builder.write_idx(entries).await?;

        // collect all written byte chunks
        let mut out: Vec<u8> = Vec::new();
        while let Some(chunk) = rx.recv().await {
            out.extend_from_slice(&chunk);
        }

        // ------- assert header -------
        // .idx v2 magic: FF 74 4F 63 00000002
        assert_eq!(&out[0..8], &[0xFF, 0x74, 0x4F, 0x63, 0, 0, 0, 2]);

        // ------- fanout -------
        // fanout has 256 * 4 bytes, starting from offset 8
        let fanout_start = 8;
        let fanout_end = fanout_start + 256 * 4;
        let fanout_bytes = &out[fanout_start..fanout_end];

        // Because the first byte of the hash is 0,1,2, fanout[0]=1 fanout[1]=2 fanout[2]=3, the rest=3
        let mut fanout = [0u32; 256];
        fanout[0] = 1;
        fanout[1] = 2;
        fanout[2] = 3;
        for item in fanout.iter_mut().skip(3) {
            *item = 3;
        }

        for (i, val) in fanout.iter().enumerate() {
            let idx = i * 4;
            let v = u32::from_be_bytes([
                fanout_bytes[idx],
                fanout_bytes[idx + 1],
                fanout_bytes[idx + 2],
                fanout_bytes[idx + 3],
            ]);
            assert_eq!(v, *val, "fanout mismatch at index {i}");
        }

        // ------- names -------
        let names_start = fanout_end;
        let names_end = names_start + object_number * 20; // sha1 = 20 bytes
        let names_bytes = &out[names_start..names_end];

        for i in 0..object_number {
            let name = &names_bytes[i * 20..i * 20 + 20];
            assert!(name.iter().all(|b| *b == i as u8));
        }

        // ------- crc32 -------
        let crc_start = names_end;
        let crc_end = crc_start + object_number * 4;
        let crc_bytes = &out[crc_start..crc_end];

        for i in 0..object_number {
            let expected = 0x12345678 + i as u32;
            let actual = u32::from_be_bytes([
                crc_bytes[4 * i],
                crc_bytes[4 * i + 1],
                crc_bytes[4 * i + 2],
                crc_bytes[4 * i + 3],
            ]);
            assert_eq!(expected, actual);
        }

        // ------- offsets -------
        let offset_start = crc_end;
        let offset_end = offset_start + object_number * 4;
        let offsets_bytes = &out[offset_start..offset_end];

        for i in 0..object_number {
            let expected = 0x10 + (i as u64) * 3;
            let actual = u32::from_be_bytes([
                offsets_bytes[i * 4],
                offsets_bytes[i * 4 + 1],
                offsets_bytes[i * 4 + 2],
                offsets_bytes[i * 4 + 3],
            ]);
            assert_eq!(expected as u32, actual);
        }

        // ------- pack hash -------
        let trailer_pack_hash_start = offset_end;
        let trailer_pack_hash_end = trailer_pack_hash_start + 20;
        let pack_hash_bytes = &out[trailer_pack_hash_start..trailer_pack_hash_end];
        assert!(pack_hash_bytes.iter().all(|b| *b == 0xAA));

        // ------- idx hash (cannot be exactly the same as git, but should have a value) -------
        let idx_hash = &out[trailer_pack_hash_end..trailer_pack_hash_end + 20];
        assert_eq!(idx_hash.len(), 20);

        Ok(())
    }

    /// BLAKE3 idx v2: 32-byte object names, BLAKE3 pack checksum and BLAKE3 idx checksum are
    /// written from the pack hash's kind (thread-local is SHA-1), and any idx version other
    /// than 2 is rejected for every kind.
    #[tokio::test]
    async fn blake3_idx_v2() -> Result<(), GitError> {
        use super::{IDX_MAGIC, IDX_VERSION_V2, validate_idx_v2_header};
        use crate::{
            hash::{HashKind, set_hash_kind_for_test},
            utils::HashAlgorithm,
        };

        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let fake_blake3 = |n: u8| ObjectHash::Blake3([n; 32]);
        let object_number = 4;
        let pack_hash = fake_blake3(0xAA);
        // The last entry sits past the 31-bit offset limit, so it needs the 8-byte offset table.
        let large_offset: u64 = 0x1_2345_6789;
        let entries: Vec<IndexEntry> = (0..object_number)
            .map(|i| IndexEntry {
                hash: fake_blake3(i as u8),
                crc32: 0x1234_5678 + i as u32,
                offset: if i == object_number - 1 {
                    large_offset
                } else {
                    0x10 + (i as u64) * 3
                },
            })
            .collect();

        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);
        let mut builder = IdxBuilder::new(object_number, tx, pack_hash);
        assert_eq!(builder.hash_kind(), HashKind::Blake3);
        builder.write_idx(entries).await?;
        let mut out: Vec<u8> = Vec::new();
        while let Some(chunk) = rx.recv().await {
            out.extend_from_slice(&chunk);
        }

        // header + fanout + 4 * (32-byte name + crc + offset) + one 8-byte large offset
        // + pack hash + idx hash
        assert_eq!(
            out.len(),
            8 + 256 * 4 + object_number * (32 + 4 + 4) + 8 + 32 + 32
        );
        assert_eq!(&out[0..8], &[0xFF, 0x74, 0x4F, 0x63, 0, 0, 0, 2]);
        let names_start = 8 + 256 * 4;
        for i in 0..object_number {
            let name = &out[names_start + i * 32..names_start + (i + 1) * 32];
            assert_eq!(name, &[i as u8; 32]);
            assert_eq!(
                ObjectHash::from_bytes_for_kind(HashKind::Blake3, name).unwrap(),
                fake_blake3(i as u8)
            );
        }
        // Offsets: three small 4-byte offsets, then the MSB-marked slot 0 for the large one,
        // then the 8-byte large-offset table.
        let offsets_start = names_start + object_number * 32 + object_number * 4;
        let last_slot = &out[offsets_start + 3 * 4..offsets_start + 4 * 4];
        assert_eq!(
            u32::from_be_bytes(last_slot.try_into().unwrap()),
            0x8000_0000
        );
        let large_table = &out[offsets_start + 4 * 4..offsets_start + 4 * 4 + 8];
        assert_eq!(
            u64::from_be_bytes(large_table.try_into().unwrap()),
            large_offset
        );
        let trailer_start = out.len() - 64;
        assert_eq!(&out[trailer_start..trailer_start + 32], pack_hash.as_ref());
        let mut idx_hasher = HashAlgorithm::new_for_kind(HashKind::Blake3);
        idx_hasher.update(&out[..trailer_start + 32]);
        let expected_idx_hash = idx_hasher.finalize_object_hash();
        assert_eq!(expected_idx_hash.kind(), HashKind::Blake3);
        assert_eq!(&out[trailer_start + 32..], expected_idx_hash.as_ref());
        // Not the SHA-256 checksum of the same bytes.
        assert_ne!(
            &out[trailer_start + 32..],
            ObjectHash::new_for_kind(HashKind::Sha256, &out[..trailer_start + 32]).as_ref()
        );

        // idx version != 2 is rejected (fail-closed) for BLAKE3 and for the SHA kinds alike.
        assert!(
            validate_idx_v2_header(IDX_MAGIC, IDX_VERSION_V2, HashKind::Blake3, "test").is_ok()
        );
        for version in [1u32, 3] {
            let err =
                validate_idx_v2_header(IDX_MAGIC, version, HashKind::Blake3, "test").unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("Only pack index v2")
                    && msg.contains("blake3")
                    && msg.contains("32-byte"),
                "{msg}"
            );
            assert!(validate_idx_v2_header(IDX_MAGIC, version, HashKind::Sha1, "test").is_err());
            assert!(validate_idx_v2_header(IDX_MAGIC, version, HashKind::Sha256, "test").is_err());
        }
        let err = validate_idx_v2_header(0x1234_5678, IDX_VERSION_V2, HashKind::Blake3, "test")
            .unwrap_err();
        assert!(err.to_string().contains("magic"), "{err}");

        // Read the idx back through the crate's own reader: names, CRCs, the merged 8-byte
        // offset and both checksums round-trip for BLAKE3; a SHA-256 read fails closed.
        let parsed = super::parse_idx_v2(&out, HashKind::Blake3).unwrap();
        assert_eq!(parsed.entries.len(), object_number);
        for (i, entry) in parsed.entries.iter().enumerate() {
            assert_eq!(entry.hash, fake_blake3(i as u8));
            assert_eq!(entry.crc32, 0x1234_5678 + i as u32);
        }
        assert_eq!(parsed.entries[object_number - 1].offset, large_offset);
        assert_eq!(parsed.entries[0].offset, 0x10);
        assert_eq!(parsed.pack_hash, pack_hash);
        // Two entries at one pack offset are rejected by the shared reader even when the idx
        // checksum verifies.
        let mut dup = out.clone();
        let slot1 = offsets_start + 4;
        dup[slot1..slot1 + 4].copy_from_slice(&0x10u32.to_be_bytes());
        let mut reseal = HashAlgorithm::new_for_kind(HashKind::Blake3);
        reseal.update(&dup[..trailer_start + 32]);
        let reseal = reseal.finalize_object_hash();
        dup[trailer_start + 32..].copy_from_slice(reseal.as_ref());
        let err = super::parse_idx_v2(&dup, HashKind::Blake3).unwrap_err();
        assert!(err.to_string().contains("more than once"), "{err}");

        // A hostile fanout[255] = u32::MAX on a file that claims to be long enough (sparse
        // file: zeros forever) is rejected at the second (non-ascending) name without
        // reserving the declared capacity.
        let mut hostile = Vec::new();
        hostile.extend_from_slice(&IDX_MAGIC.to_be_bytes());
        hostile.extend_from_slice(&IDX_VERSION_V2.to_be_bytes());
        for _ in 0..255 {
            hostile.extend_from_slice(&0u32.to_be_bytes());
        }
        hostile.extend_from_slice(&u32::MAX.to_be_bytes());
        let sparse = std::io::Read::chain(std::io::Cursor::new(hostile), std::io::repeat(0u8));
        let err = super::parse_idx_v2_from(sparse, HashKind::Blake3, u64::MAX).unwrap_err();
        assert!(err.to_string().contains("not strictly ascending"), "{err}");
        assert_eq!(parsed.idx_hash, expected_idx_hash);
        let err = super::parse_idx_v2(&out, HashKind::Sha256).unwrap_err();
        assert!(err.to_string().contains("checksum"), "{err}");
        let mut corrupted = out.clone();
        corrupted[names_start + 3] ^= 0x01;
        assert!(super::parse_idx_v2(&corrupted, HashKind::Blake3).is_err());
        assert!(super::parse_idx_v2(&out[..out.len() - 1], HashKind::Blake3).is_err());
        // A hostile fanout (u32::MAX objects) is rejected by the size check before any
        // allocation, and an inconsistent (non-covering) fanout is rejected too.
        let mut hostile = out.clone();
        hostile[8 + 255 * 4..8 + 256 * 4].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = super::parse_idx_v2(&hostile, HashKind::Blake3).unwrap_err();
        assert!(err.to_string().contains("declares"), "{err}");
        let mut skewed = out.clone();
        skewed[8..12].copy_from_slice(&0u32.to_be_bytes()); // fanout[0] must be 1
        let err = super::parse_idx_v2(&skewed, HashKind::Blake3).unwrap_err();
        assert!(err.to_string().contains("fanout"), "{err}");

        // A same-width SHA-256 object name cannot be written into a BLAKE3 idx.
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(64);
        let mut builder = IdxBuilder::new(1, tx, pack_hash);
        let err = builder
            .write_idx(vec![IndexEntry {
                hash: ObjectHash::Sha256([7; 32]),
                crc32: 0,
                offset: 12,
            }])
            .await
            .unwrap_err();
        assert!(matches!(err, GitError::InvalidHashValue(_)), "{err:?}");
        Ok(())
    }

    /// SHA-256 idx regression: 32-byte names and SHA-256 checksums from `pack_hash.kind()`.
    #[tokio::test]
    async fn test_idx_builder_sha256_basic() -> Result<(), GitError> {
        use crate::{
            hash::{HashKind, set_hash_kind_for_test},
            utils::HashAlgorithm,
        };
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let fake = |n: u8| ObjectHash::Sha256([n; 32]);
        let object_number = 3;
        let pack_hash = fake(0xBB);
        let entries: Vec<IndexEntry> = (0..object_number)
            .map(|i| IndexEntry {
                hash: fake(i as u8),
                crc32: i as u32,
                offset: 0x20 + (i as u64) * 5,
            })
            .collect();
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(4096);
        let mut builder = IdxBuilder::new(object_number, tx, pack_hash);
        assert_eq!(builder.hash_kind(), HashKind::Sha256);
        builder.write_idx(entries).await?;
        let mut out = Vec::new();
        while let Some(chunk) = rx.recv().await {
            out.extend_from_slice(&chunk);
        }
        assert_eq!(
            out.len(),
            8 + 256 * 4 + object_number * (32 + 4 + 4) + 32 + 32
        );
        assert_eq!(&out[0..8], &[0xFF, 0x74, 0x4F, 0x63, 0, 0, 0, 2]);
        let names_start = 8 + 256 * 4;
        for i in 0..object_number {
            assert_eq!(
                &out[names_start + i * 32..names_start + (i + 1) * 32],
                &[i as u8; 32]
            );
        }
        let trailer_start = out.len() - 64;
        assert_eq!(&out[trailer_start..trailer_start + 32], pack_hash.as_ref());
        let mut hasher = HashAlgorithm::new_for_kind(HashKind::Sha256);
        hasher.update(&out[..trailer_start + 32]);
        assert_eq!(
            &out[trailer_start + 32..],
            hasher.finalize_object_hash().as_ref()
        );
        let parsed = super::parse_idx_v2(&out, HashKind::Sha256).unwrap();
        assert_eq!(parsed.entries.len(), object_number);
        assert_eq!(parsed.entries[1].offset, 0x25);
        assert_eq!(parsed.pack_hash, pack_hash);
        assert!(super::parse_idx_v2(&out, HashKind::Blake3).is_err());
        Ok(())
    }
}
