//! Integration tests that decode fixture packs, rebuild their `.idx` files, and assert offsets match
//! the originals for both SHA-1 and SHA-256 object formats.

use std::{
    collections::HashMap,
    convert::TryInto,
    fs,
    io::BufReader,
    sync::{Arc, Mutex},
};

mod common;

use common::download_pack_file;
use git_internal::{
    errors::GitError,
    hash::{HashKind, ObjectHash, set_hash_kind_for_test},
    internal::{
        metadata::{EntryMeta, MetaAttached},
        pack::{
            Pack,
            entry::Entry,
            pack_index::{IdxBuilder, IndexEntry},
        },
    },
};
use tokio::sync::mpsc;

fn parse_idx_offsets(idx_bytes: &[u8], kind: HashKind) -> HashMap<Vec<u8>, u64> {
    assert!(idx_bytes.len() >= 8, "idx too short");
    assert_eq!(&idx_bytes[0..4], &[0xFF, 0x74, 0x4F, 0x63], "idx magic");
    let version = u32::from_be_bytes(idx_bytes[4..8].try_into().unwrap());

    assert_eq!(version, 2, "idx version must be 2 per pack-format spec");
    let mut cursor = 8usize;

    // Fanout
    let mut fanout = [0u32; 256];
    for i in 0..256 {
        fanout[i] = u32::from_be_bytes(
            idx_bytes[cursor + i * 4..cursor + i * 4 + 4]
                .try_into()
                .unwrap(),
        );
    }
    cursor += 256 * 4;

    let object_count = fanout[255] as usize;

    let hash_len = kind.size();
    let names_end = cursor + object_count * hash_len;
    let names = &idx_bytes[cursor..names_end];
    cursor = names_end;

    // Skip CRCs
    cursor += object_count * 4;

    // Offsets table
    let offsets_end = cursor + object_count * 4;
    let offsets_bytes = &idx_bytes[cursor..offsets_end];
    cursor = offsets_end;

    let large_count = offsets_bytes
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|raw| u32::from_be_bytes(**raw) & 0x8000_0000 != 0)
        .count();

    let mut large_offsets = Vec::with_capacity(large_count);
    for _ in 0..large_count {
        let v = u64::from_be_bytes(idx_bytes[cursor..cursor + 8].try_into().unwrap());
        large_offsets.push(v);
        cursor += 8;
    }

    let mut map = HashMap::new();
    for (i, raw) in offsets_bytes.as_chunks::<4>().0.iter().enumerate() {
        let raw = u32::from_be_bytes(*raw);
        let offset = if raw & 0x8000_0000 == 0 {
            raw as u64
        } else {
            let idx = (raw & 0x7FFF_FFFF) as usize;
            large_offsets[idx]
        };
        let hash = names[i * hash_len..(i + 1) * hash_len].to_vec();
        map.insert(hash, offset);
    }
    map
}

type DecodePackResult = Result<(Vec<MetaAttached<Entry, EntryMeta>>, ObjectHash, usize), GitError>;

fn decode_pack(filename: &str) -> DecodePackResult {
    let (pack_path, _dl_guard) = download_pack_file(filename);
    let file = fs::File::open(pack_path)?;
    let mut reader = BufReader::new(file);
    let mut pack = Pack::new(Some(2), Some(64 * 1024 * 1024), None, true);

    let entries = Arc::new(Mutex::new(Vec::new()));
    let entries_for_cb = entries.clone();
    pack.decode(
        &mut reader,
        move |entry| {
            if let Ok(mut guard) = entries_for_cb.lock() {
                guard.push(entry);
            }
        },
        None::<fn(ObjectHash)>,
    )?;
    let pack_hash = pack.signature;
    let count = pack.number;
    let entries = Arc::try_unwrap(entries).unwrap().into_inner().unwrap();
    Ok((entries, pack_hash, count))
}

async fn roundtrip(filename: &str, kind: HashKind) -> Result<(), GitError> {
    let _guard = set_hash_kind_for_test(kind);
    let (metas, pack_hash, count) = decode_pack(filename)?;
    assert_eq!(metas.len(), count, "decoded entries count mismatch");

    let mut idx_entries = Vec::with_capacity(metas.len());
    for m in &metas {
        idx_entries.push(IndexEntry::try_from(m)?);
    }

    let (tx, mut rx) = mpsc::channel::<Vec<u8>>(1024);
    let mut builder = IdxBuilder::new(idx_entries.len(), tx, pack_hash);
    builder.write_idx(idx_entries).await?;

    let mut idx_bytes = Vec::new();
    while let Some(chunk) = rx.recv().await {
        idx_bytes.extend_from_slice(&chunk);
    }

    let offsets_map = parse_idx_offsets(&idx_bytes, kind);
    for meta in metas {
        let hash = meta.inner.hash.to_data();
        let expected = meta.meta.pack_offset.expect("missing pack offset") as u64;
        let actual = *offsets_map
            .get(&hash)
            .unwrap_or_else(|| panic!("hash missing in idx: {}", meta.inner.hash));
        assert_eq!(actual, expected, "offset mismatch for {}", meta.inner.hash);
    }
    Ok(())
}

#[tokio::test]
async fn idx_offsets_match_sha1_small() -> Result<(), GitError> {
    roundtrip("small-sha1.pack", HashKind::Sha1).await
}

#[tokio::test]
async fn idx_offsets_match_sha1_delta() -> Result<(), GitError> {
    roundtrip("ref-delta-sha1.pack", HashKind::Sha1).await
}

#[tokio::test]
async fn idx_offsets_match_sha256_small() -> Result<(), GitError> {
    roundtrip("small-sha256.pack", HashKind::Sha256).await
}

#[tokio::test]
async fn idx_offsets_match_sha256_delta() -> Result<(), GitError> {
    roundtrip("ref-delta-sha256.pack", HashKind::Sha256).await
}
