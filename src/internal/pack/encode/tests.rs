use std::{io::Cursor, path::PathBuf, sync::Arc, time::Instant};

use tempfile::tempdir;
use tokio::sync::Mutex;

use super::{
    header::encode_offset,
    sort::{magic_sort, multi_point_similar},
    *,
};
use crate::{
    hash::{HashKind, ObjectHash, set_hash_kind_for_test},
    internal::{
        object::{
            blob::Blob,
            commit::Commit,
            tree::{Tree, TreeItem, TreeItemMode},
            types::ObjectType,
        },
        pack::{
            Pack,
            test_pack_download::{PackFileGuard, download_pack_file},
            tests::init_logger,
            utils::read_offset_encoding,
        },
    },
    time_it,
};

/// Check if the given data is a valid pack file format by attempting to decode it.
fn check_format(data: &Vec<u8>) {
    // Use a smaller cap on 32-bit targets to avoid usize overflow.
    let max_pack_size_u64 = if cfg!(target_pointer_width = "64") {
        6u64 * 1024 * 1024 * 1024
    } else {
        2u64 * 1024 * 1024 * 1024
    };
    let max_pack_size = usize::try_from(max_pack_size_u64).unwrap_or_else(|_| {
        panic!(
            "internal assertion failed: pack size cap {} does not fit in usize on this \
             target; this should be unreachable given the target_pointer_width configuration",
            max_pack_size_u64
        )
    });
    let mut p = Pack::new(
        None,
        Some(max_pack_size), // 6GB on 64-bit, 2GB on 32-bit
        Some(PathBuf::from("/tmp/.cache_temp")),
        true,
    );
    let mut reader = Cursor::new(data);
    tracing::debug!("start check format");
    p.decode(&mut reader, |_| {}, None::<fn(ObjectHash)>)
        .expect("pack file format error");
}

async fn get_entries_for_test() -> (Arc<Mutex<Vec<Entry>>>, PackFileGuard) {
    let (source, dl_guard) = download_pack_file("encode-test-sha1.pack");

    let mut p = Pack::new(None, None, Some(PathBuf::from("/tmp/.cache_temp")), true);

    let f = std::fs::File::open(&source).unwrap();
    tracing::info!("pack file size: {}", f.metadata().unwrap().len());
    let mut reader = std::io::BufReader::new(f);
    let entries = Arc::new(Mutex::new(Vec::new()));
    let entries_clone = entries.clone();
    p.decode(
        &mut reader,
        move |entry| {
            let mut entries = entries_clone.blocking_lock();
            entries.push(entry.inner);
        },
        None::<fn(ObjectHash)>,
    )
    .unwrap();
    assert_eq!(p.number, entries.lock().await.len());
    tracing::info!("total entries: {}", p.number);
    drop(p);

    (entries, dl_guard)
}
async fn get_entries_for_test_sha256() -> (Arc<Mutex<Vec<Entry>>>, PackFileGuard) {
    let (source, dl_guard) = download_pack_file("encode-test-sha256.pack");

    let mut p = Pack::new(None, None, Some(PathBuf::from("/tmp/.cache_temp")), true);

    let f = std::fs::File::open(&source).unwrap();
    tracing::info!("pack file size: {}", f.metadata().unwrap().len());
    let mut reader = std::io::BufReader::new(f);
    let entries = Arc::new(Mutex::new(Vec::new()));
    let entries_clone = entries.clone();
    p.decode(
        &mut reader,
        move |entry| {
            let mut entries = entries_clone.blocking_lock();
            entries.push(entry.inner);
        },
        None::<fn(ObjectHash)>,
    )
    .unwrap();
    assert_eq!(p.number, entries.lock().await.len());
    tracing::info!("total entries: {}", p.number);
    drop(p);

    (entries, dl_guard)
}

#[tokio::test]
async fn test_pack_encoder() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    async fn encode_once(window_size: usize) -> Vec<u8> {
        let (tx, mut rx) = mpsc::channel(100);
        let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(1);

        // make some different objects, or decode will fail
        let str_vec = vec!["hello, word", "hello, world.", "!", "123141251251"];
        let encoder = PackEncoder::new(str_vec.len(), window_size, tx);
        encoder.encode_async(entry_rx).await.unwrap();

        for str in str_vec {
            let blob = Blob::from_content(str);
            let entry: Entry = blob.into();
            entry_tx
                .send(MetaAttached {
                    inner: entry,
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        // assert!(encoder.get_hash().is_some());
        let mut result = Vec::new();
        while let Some(chunk) = rx.recv().await {
            result.extend(chunk);
        }
        result
    }

    // without delta
    let pack_without_delta = encode_once(0).await;
    let pack_without_delta_size = pack_without_delta.len();
    check_format(&pack_without_delta);

    // with delta
    let pack_with_delta = encode_once(4).await;
    assert!(pack_with_delta.len() <= pack_without_delta_size);
    check_format(&pack_with_delta);
}

#[test]
fn test_try_as_offset_delta_keeps_one_result_per_input() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    let entries: Vec<Entry> = [
        "alpha content",
        "beta content",
        "gamma content",
        "delta content",
    ]
    .into_iter()
    .map(|content| Blob::from_content(content).into())
    .collect();
    let expected_hashes: Vec<ObjectHash> = entries.iter().map(|entry| entry.hash).collect();

    let results = PackEncoder::try_as_offset_delta(entries, 0, false, false, false)
        .expect("offset delta encoding should succeed");

    assert_eq!(results.len(), expected_hashes.len());
    for ((encoded, idx_entry), expected_hash) in results.iter().zip(expected_hashes) {
        assert!(!encoded.is_empty(), "encoded object should not be empty");
        assert_eq!(idx_entry.hash, expected_hash);
    }
}

#[test]
fn test_try_as_offset_delta_accepts_empty_bucket() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    let entries = Vec::new();

    let results = PackEncoder::try_as_offset_delta(entries, 0, false, false, false)
        .expect("empty bucket should encode successfully");

    assert!(results.is_empty());
}

#[tokio::test]
async fn test_delta_window_encode_after_copy_optimization_roundtrips() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    let shared_prefix = "shared-prefix-".repeat(16);
    let contents = vec![
        format!("{shared_prefix}alpha-tail"),
        format!("{shared_prefix}beta-tail"),
        format!("{shared_prefix}gamma-tail"),
        format!("{shared_prefix}delta-tail"),
    ];
    let (tx, mut rx) = mpsc::channel(16);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(16);
    let encoder = PackEncoder::new(contents.len(), 4, tx);
    encoder.encode_async(entry_rx).await.unwrap();

    for content in contents {
        let entry: Entry = Blob::from_content(&content).into();
        entry_tx
            .send(MetaAttached {
                inner: entry,
                meta: EntryMeta::new(),
            })
            .await
            .unwrap();
    }
    drop(entry_tx);

    let mut result = Vec::new();
    while let Some(chunk) = rx.recv().await {
        result.extend(chunk);
    }

    check_format(&result);
}

#[tokio::test]
async fn test_parallel_encode_after_owned_write_roundtrips() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    let contents = vec![
        "parallel alpha",
        "parallel beta",
        "parallel gamma",
        "parallel delta",
    ];
    let (tx, mut rx) = mpsc::channel(16);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(16);
    let encoder = PackEncoder::new(contents.len(), 0, tx);
    encoder.encode_async(entry_rx).await.unwrap();

    for content in contents {
        let entry: Entry = Blob::from_content(content).into();
        entry_tx
            .send(MetaAttached {
                inner: entry,
                meta: EntryMeta::new(),
            })
            .await
            .unwrap();
    }
    drop(entry_tx);

    let mut result = Vec::new();
    while let Some(chunk) = rx.recv().await {
        result.extend(chunk);
    }

    check_format(&result);
}

#[tokio::test]
async fn test_pack_encoder_sha256() {
    let _guard = set_hash_kind_for_test(HashKind::Sha256);

    async fn encode_once(window_size: usize) -> Vec<u8> {
        let (tx, mut rx) = mpsc::channel(100);
        let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(1);

        let str_vec = vec!["hello, word", "hello, world.", "!", "123141251251"];
        let encoder = PackEncoder::new(str_vec.len(), window_size, tx);
        encoder.encode_async(entry_rx).await.unwrap();

        for s in str_vec {
            let blob = Blob::from_content(s);
            let entry: Entry = blob.into();
            entry_tx
                .send(MetaAttached {
                    inner: entry,
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);

        let mut result = Vec::new();
        while let Some(chunk) = rx.recv().await {
            result.extend(chunk);
        }
        result
    }

    // without delta
    let pack_without_delta = encode_once(0).await;
    let pack_without_delta_size = pack_without_delta.len();
    check_format(&pack_without_delta);

    // with delta
    let pack_with_delta = encode_once(4).await;
    assert!(pack_with_delta.len() <= pack_without_delta_size);
    check_format(&pack_with_delta);
}

#[tokio::test]
async fn test_pack_encoder_rejects_unencodable_ai_type_parallel() {
    let (tx, _rx) = mpsc::channel(8);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(1);
    let mut encoder = PackEncoder::new(1, 0, tx);

    let mut entry: Entry = Blob::from_content("ai").into();
    entry.obj_type = ObjectType::Task;
    entry_tx
        .send(MetaAttached {
            inner: entry,
            meta: EntryMeta::new(),
        })
        .await
        .expect("send entry");
    drop(entry_tx);

    let err = encoder
        .encode(entry_rx)
        .await
        .expect_err("must reject AI pack type");
    assert!(matches!(err, GitError::PackEncodeError(_)));
}

#[tokio::test]
async fn test_pack_encoder_rejects_unencodable_ai_type_delta_window() {
    let (tx, _rx) = mpsc::channel(8);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(1);
    let mut encoder = PackEncoder::new(1, 10, tx);

    let mut entry: Entry = Blob::from_content("ai").into();
    entry.obj_type = ObjectType::Task;
    entry_tx
        .send(MetaAttached {
            inner: entry,
            meta: EntryMeta::new(),
        })
        .await
        .expect("send entry");
    drop(entry_tx);

    let err = encoder
        .encode(entry_rx)
        .await
        .expect_err("must reject AI pack type");
    assert!(matches!(err, GitError::PackEncodeError(_)));
}

#[tokio::test]
async fn test_pack_encoder_parallel_large_file() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    init_logger();

    let start = Instant::now();
    let (entries, _dl_guard) = get_entries_for_test().await;
    let entries_number = entries.lock().await.len();

    let total_original_size: usize = entries
        .lock()
        .await
        .iter()
        .map(|entry| entry.data.len())
        .sum();

    // encode entries with parallel
    let (tx, mut rx) = mpsc::channel(1_000_000);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(1_000_000);

    let mut encoder = PackEncoder::new(entries_number, 0, tx);
    tokio::spawn(async move {
        time_it!("test parallel encode", {
            encoder.parallel_encode(entry_rx).await.unwrap();
        });
    });

    // spawn a task to send entries
    tokio::spawn(async move {
        let entries = entries.lock().await;
        for entry in entries.iter() {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        tracing::info!("all entries sent");
    });

    let mut result = Vec::new();
    while let Some(chunk) = rx.recv().await {
        result.extend(chunk);
    }

    let pack_size = result.len();
    let compression_rate = if total_original_size > 0 {
        1.0 - (pack_size as f64 / total_original_size as f64)
    } else {
        0.0
    };

    let duration = start.elapsed();
    tracing::info!("test executed in: {:.2?}", duration);
    tracing::info!("new pack file size: {}", result.len());
    tracing::info!("compression rate: {:.2}%", compression_rate * 100.0);
    // check format
    check_format(&result);
}
#[tokio::test]
async fn test_pack_encoder_parallel_large_file_sha256() {
    let _guard = set_hash_kind_for_test(HashKind::Sha256);
    init_logger();

    let start = Instant::now();
    // use sha256 pack file for testing
    let (entries, _dl_guard) = get_entries_for_test_sha256().await;
    let entries_number = entries.lock().await.len();

    let total_original_size: usize = entries
        .lock()
        .await
        .iter()
        .map(|entry| entry.data.len())
        .sum();

    let (tx, mut rx) = mpsc::channel(1_000_000);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(1_000_000);

    let mut encoder = PackEncoder::new(entries_number, 0, tx);
    tokio::spawn(async move {
        time_it!("test parallel encode sha256", {
            encoder.parallel_encode(entry_rx).await.unwrap();
        });
    });

    tokio::spawn(async move {
        let entries = entries.lock().await;
        for entry in entries.iter() {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        tracing::info!("all entries sent");
    });

    let mut result = Vec::new();
    while let Some(chunk) = rx.recv().await {
        result.extend(chunk);
    }

    let pack_size = result.len();
    let compression_rate = if total_original_size > 0 {
        1.0 - (pack_size as f64 / total_original_size as f64)
    } else {
        0.0
    };

    let duration = start.elapsed();
    tracing::info!("sha256 test executed in: {:.2?}", duration);
    tracing::info!("new pack file size: {}", result.len());
    tracing::info!("compression rate: {:.2}%", compression_rate * 100.0);
    check_format(&result);
}

#[tokio::test]
async fn test_pack_encoder_large_file() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    init_logger();
    let (entries, _dl_guard) = get_entries_for_test().await;
    let entries_number = entries.lock().await.len();

    let total_original_size: usize = entries
        .lock()
        .await
        .iter()
        .map(|entry| entry.data.len())
        .sum();

    let start = Instant::now();
    // encode entries
    let (tx, mut rx) = mpsc::channel(100_000);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(100_000);

    let mut encoder = PackEncoder::new(entries_number, 0, tx);
    tokio::spawn(async move {
        time_it!("test encode no parallel", {
            encoder.encode(entry_rx).await.unwrap();
        });
    });

    // spawn a task to send entries
    tokio::spawn(async move {
        let entries = entries.lock().await;
        for entry in entries.iter() {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        tracing::info!("all entries sent");
    });

    let mut result = Vec::new();
    while let Some(chunk) = rx.recv().await {
        result.extend(chunk);
    }

    let pack_size = result.len();
    let compression_rate = if total_original_size > 0 {
        1.0 - (pack_size as f64 / total_original_size as f64)
    } else {
        0.0
    };

    let duration = start.elapsed();
    tracing::info!("test executed in: {:.2?}", duration);
    tracing::info!("new pack file size: {}", pack_size);
    tracing::info!("original total size: {}", total_original_size);
    tracing::info!("compression rate: {:.2}%", compression_rate * 100.0);
    tracing::info!(
        "space saved: {} bytes",
        total_original_size.saturating_sub(pack_size)
    );
}
#[tokio::test]
async fn test_pack_encoder_large_file_sha256() {
    let _guard = set_hash_kind_for_test(HashKind::Sha256);
    init_logger();
    let (entries, _dl_guard) = get_entries_for_test_sha256().await;
    let entries_number = entries.lock().await.len();

    let total_original_size: usize = entries
        .lock()
        .await
        .iter()
        .map(|entry| entry.data.len())
        .sum();

    let start = Instant::now();
    // encode entries
    let (tx, mut rx) = mpsc::channel(100_000);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(100_000);

    let mut encoder = PackEncoder::new(entries_number, 0, tx);
    tokio::spawn(async move {
        time_it!("test encode no parallel sha256", {
            encoder.encode(entry_rx).await.unwrap();
        });
    });

    // spawn a task to send entries
    tokio::spawn(async move {
        let entries = entries.lock().await;
        for entry in entries.iter() {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        tracing::info!("all entries sent");
    });

    let mut result = Vec::new();
    while let Some(chunk) = rx.recv().await {
        result.extend(chunk);
    }

    let pack_size = result.len();
    let compression_rate = if total_original_size > 0 {
        1.0 - (pack_size as f64 / total_original_size as f64)
    } else {
        0.0
    };

    let duration = start.elapsed();
    tracing::info!("test executed in: {:.2?}", duration);
    tracing::info!("new pack file size: {}", pack_size);
    tracing::info!("original total size: {}", total_original_size);
    tracing::info!("compression rate: {:.2}%", compression_rate * 100.0);
    tracing::info!(
        "space saved: {} bytes",
        total_original_size.saturating_sub(pack_size)
    );
}

#[tokio::test]
async fn test_pack_encoder_with_zstdelta() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    init_logger();
    let (entries, _dl_guard) = get_entries_for_test().await;
    let entries_number = entries.lock().await.len();

    let total_original_size: usize = entries
        .lock()
        .await
        .iter()
        .map(|entry| entry.data.len())
        .sum();

    let start = Instant::now();
    let (tx, mut rx) = mpsc::channel(100_000);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(100_000);

    let encoder = PackEncoder::new(entries_number, 10, tx);
    encoder.encode_async_with_zstdelta(entry_rx).await.unwrap();

    // spawn a task to send entries
    tokio::spawn(async move {
        let entries = entries.lock().await;
        for entry in entries.iter() {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        tracing::info!("all entries sent");
    });

    let mut result = Vec::new();
    while let Some(chunk) = rx.recv().await {
        result.extend(chunk);
    }

    let pack_size = result.len();
    let compression_rate = if total_original_size > 0 {
        1.0 - (pack_size as f64 / total_original_size as f64)
    } else {
        0.0
    };

    let duration = start.elapsed();
    tracing::info!("test executed in: {:.2?}", duration);
    tracing::info!("new pack file size: {}", pack_size);
    tracing::info!("original total size: {}", total_original_size);
    tracing::info!("compression rate: {:.2}%", compression_rate * 100.0);
    tracing::info!(
        "space saved: {} bytes",
        total_original_size.saturating_sub(pack_size)
    );

    // check format
    check_format(&result);
}
#[tokio::test]
async fn test_pack_encoder_with_zstdelta_sha256() {
    let _guard = set_hash_kind_for_test(HashKind::Sha256);
    init_logger();
    let (entries, _dl_guard) = get_entries_for_test_sha256().await;
    let entries_number = entries.lock().await.len();

    let total_original_size: usize = entries
        .lock()
        .await
        .iter()
        .map(|entry| entry.data.len())
        .sum();

    let start = Instant::now();
    let (tx, mut rx) = mpsc::channel(100_000);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(100_000);

    let encoder = PackEncoder::new(entries_number, 10, tx);
    encoder.encode_async_with_zstdelta(entry_rx).await.unwrap();

    // spawn a task to send entries
    tokio::spawn(async move {
        let entries = entries.lock().await;
        for entry in entries.iter() {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        tracing::info!("all entries sent");
    });

    let mut result = Vec::new();
    while let Some(chunk) = rx.recv().await {
        result.extend(chunk);
    }

    let pack_size = result.len();
    let compression_rate = if total_original_size > 0 {
        1.0 - (pack_size as f64 / total_original_size as f64)
    } else {
        0.0
    };

    let duration = start.elapsed();
    tracing::info!("test executed in: {:.2?}", duration);
    tracing::info!("new pack file size: {}", pack_size);
    tracing::info!("original total size: {}", total_original_size);
    tracing::info!("compression rate: {:.2}%", compression_rate * 100.0);
    tracing::info!(
        "space saved: {} bytes",
        total_original_size.saturating_sub(pack_size)
    );

    // check format
    check_format(&result);
}

#[test]
fn test_encode_offset() {
    // let value = 11013;
    let value = 16389;

    let data = encode_offset(value);
    println!("{data:?}");
    let mut reader = Cursor::new(data);
    let (result, _) = read_offset_encoding(&mut reader).unwrap();
    println!("result: {result}");
    assert_eq!(result, value as u64);
}

#[tokio::test]
async fn test_pack_encoder_large_file_with_delta() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    init_logger();
    let (entries, _dl_guard) = get_entries_for_test().await;
    let entries_number = entries.lock().await.len();

    let total_original_size: usize = entries
        .lock()
        .await
        .iter()
        .map(|entry| entry.data.len())
        .sum();

    let (tx, mut rx) = mpsc::channel(100_000);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(100_000);

    let encoder = PackEncoder::new(entries_number, 10, tx);

    let start = Instant::now();
    encoder.encode_async(entry_rx).await.unwrap();

    // spawn a task to send entries
    tokio::spawn(async move {
        let entries = entries.lock().await;
        for entry in entries.iter() {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        tracing::info!("all entries sent");
    });

    let mut result = Vec::new();
    while let Some(chunk) = rx.recv().await {
        result.extend(chunk);
    }

    let pack_size = result.len();
    let compression_rate = if total_original_size > 0 {
        1.0 - (pack_size as f64 / total_original_size as f64)
    } else {
        0.0
    };

    let duration = start.elapsed();
    tracing::info!("test executed in: {:.2?}", duration);
    tracing::info!("new pack file size: {}", pack_size);
    tracing::info!("original total size: {}", total_original_size);
    tracing::info!("compression rate: {:.2}%", compression_rate * 100.0);
    tracing::info!(
        "space saved: {} bytes",
        total_original_size.saturating_sub(pack_size)
    );

    // check format
    check_format(&result);
}
#[tokio::test]
async fn test_pack_encoder_large_file_with_delta_sha256() {
    let _guard = set_hash_kind_for_test(HashKind::Sha256);
    init_logger();
    let (entries, _dl_guard) = get_entries_for_test_sha256().await;
    let entries_number = entries.lock().await.len();

    let total_original_size: usize = entries
        .lock()
        .await
        .iter()
        .map(|entry| entry.data.len())
        .sum();

    let (tx, mut rx) = mpsc::channel(100_000);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(100_000);

    let encoder = PackEncoder::new(entries_number, 10, tx);

    let start = Instant::now();
    encoder.encode_async(entry_rx).await.unwrap();

    // spawn a task to send entries
    tokio::spawn(async move {
        let entries = entries.lock().await;
        for entry in entries.iter() {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        tracing::info!("all entries sent");
    });

    let mut result = Vec::new();
    while let Some(chunk) = rx.recv().await {
        result.extend(chunk);
    }

    let pack_size = result.len();
    let compression_rate = if total_original_size > 0 {
        1.0 - (pack_size as f64 / total_original_size as f64)
    } else {
        0.0
    };

    let duration = start.elapsed();
    tracing::info!("test executed in: {:.2?}", duration);
    tracing::info!("new pack file size: {}", pack_size);
    tracing::info!("original total size: {}", total_original_size);
    tracing::info!("compression rate: {:.2}%", compression_rate * 100.0);
    tracing::info!(
        "space saved: {} bytes",
        total_original_size.saturating_sub(pack_size)
    );

    // check format
    check_format(&result);
}

#[tokio::test]
async fn test_pack_encoder_output_to_files() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    init_logger();
    let (entries, _dl_guard) = get_entries_for_test().await;
    let entries_number = entries.lock().await.len();

    let total_original_size: usize = entries
        .lock()
        .await
        .iter()
        .map(|entry| entry.data.len())
        .sum();

    let start = Instant::now();

    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(100_000);
    let dir = tempdir().unwrap();
    let path = dir.path();

    // spawn a task to send entries
    tokio::spawn(async move {
        let entries = entries.lock().await;
        for entry in entries.iter() {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        tracing::info!("all entries sent");
    });

    encode_and_output_to_files(entry_rx, entries_number, path.to_path_buf(), 0)
        .await
        .unwrap();

    let mut pack_file = None;
    let mut idx_file = None;
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let file_name = entry.file_name();
        tracing::info!("file name: {:?}", file_name);
        let file_name = file_name.to_string_lossy();
        if file_name.ends_with(".pack") {
            pack_file = Some(entry.path());
        } else if file_name.ends_with(".idx") {
            idx_file = Some(entry.path());
        }
    }
    let pack_file = pack_file.expect("pack file not generated");
    let idx_file = idx_file.expect("idx file not generated");
    assert!(
        pack_file.metadata().unwrap().len() > 0,
        "pack file is empty"
    );
    assert!(idx_file.metadata().unwrap().len() > 0, "idx file is empty");

    // The generated pair must be accepted by this crate's own idx-backed decoder: object
    // names, CRCs over the encoded entries, offsets and both checksums are all verified.
    let mut pack = Pack::new(
        Some(2),
        Some(64 * 1024 * 1024),
        Some(path.join("decode-tmp")),
        true,
    );
    pack.decode_file_full_without_callback(&pack_file, None::<fn(ObjectHash)>)
        .unwrap();
    assert_eq!(pack.number, entries_number);

    let duration = start.elapsed();
    tracing::info!("test executed in: {:.2?}", duration);
    tracing::info!("original total size: {}", total_original_size);
}

#[tokio::test]
async fn test_pack_encoder_output_to_files_with_delta() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    init_logger();
    let (entries, _dl_guard) = get_entries_for_test().await;
    let entries_number = entries.lock().await.len();

    let total_original_size: usize = entries
        .lock()
        .await
        .iter()
        .map(|entry| entry.data.len())
        .sum();

    let start = Instant::now();

    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(100_000);
    let dir = tempdir().unwrap();
    let path = dir.path();

    // spawn a task to send entries
    tokio::spawn(async move {
        let entries = entries.lock().await;
        for entry in entries.iter() {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        tracing::info!("all entries sent");
    });

    encode_and_output_to_files(entry_rx, entries_number, path.to_path_buf(), 10)
        .await
        .unwrap();

    let mut pack_file = None;
    let mut idx_file = None;
    for entry in std::fs::read_dir(path).unwrap() {
        let entry = entry.unwrap();
        let file_name = entry.file_name();
        tracing::info!("file name: {:?}", file_name);
        let file_name = file_name.to_string_lossy();
        if file_name.ends_with(".pack") {
            pack_file = Some(entry.path());
        } else if file_name.ends_with(".idx") {
            idx_file = Some(entry.path());
        }
    }
    let pack_file = pack_file.expect("pack file not generated");
    let idx_file = idx_file.expect("idx file not generated");
    assert!(
        pack_file.metadata().unwrap().len() > 0,
        "pack file is empty"
    );
    assert!(idx_file.metadata().unwrap().len() > 0, "idx file is empty");

    // The generated pair must be accepted by this crate's own idx-backed decoder: object
    // names, CRCs over the encoded entries, offsets and both checksums are all verified.
    let mut pack = Pack::new(
        Some(2),
        Some(64 * 1024 * 1024),
        Some(path.join("decode-tmp")),
        true,
    );
    pack.decode_file_full_without_callback(&pack_file, None::<fn(ObjectHash)>)
        .unwrap();
    assert_eq!(pack.number, entries_number);

    let duration = start.elapsed();
    tracing::info!("test executed in: {:.2?}", duration);
    tracing::info!("original total size: {}", total_original_size);
}

// ── Sort / similarity tests ────────────────────────────────────────────

fn sort_entry(path: Option<&str>, size: usize) -> MetaAttached<Entry, EntryMeta> {
    let content = "x".repeat(size);
    let mut entry: Entry = crate::internal::object::blob::Blob::from_content(&content).into();
    entry.data = vec![0u8; size];
    MetaAttached {
        inner: entry,
        meta: EntryMeta {
            file_path: path.map(|s| s.to_string()),
            ..Default::default()
        },
    }
}

#[test]
fn test_magic_sort_path_ordering() {
    // Different parent directories: "dir_a" < "dir_b"
    let a = sort_entry(Some("dir_a/file.rs"), 100);
    let b = sort_entry(Some("dir_b/file.rs"), 200);
    assert!(matches!(magic_sort(&a, &b), std::cmp::Ordering::Less));

    // Same parent, different name hashes → non-Equal
    let a = sort_entry(Some("shared/alpha.rs"), 100);
    let b = sort_entry(Some("shared/beta.rs"), 200);
    assert_ne!(magic_sort(&a, &b), std::cmp::Ordering::Equal);

    // Same path → size tiebreaker (larger first)
    let a = sort_entry(Some("same/path.rs"), 100);
    let b = sort_entry(Some("same/path.rs"), 200);
    assert_eq!(magic_sort(&a, &b), std::cmp::Ordering::Greater);

    // Only first has path
    let a = sort_entry(Some("path.rs"), 100);
    let b = sort_entry(None, 200);
    assert_eq!(magic_sort(&a, &b), std::cmp::Ordering::Less);

    // Only second has path
    let a = sort_entry(None, 100);
    let b = sort_entry(Some("path.rs"), 200);
    assert_eq!(magic_sort(&a, &b), std::cmp::Ordering::Greater);

    // No path on either — size ordering
    let a = sort_entry(None, 50);
    let b = sort_entry(None, 100);
    assert_eq!(magic_sort(&a, &b), std::cmp::Ordering::Greater);

    // No path, equal size — pointer tiebreaker
    let a = sort_entry(None, 100);
    let b = sort_entry(None, 100);
    assert_ne!(magic_sort(&a, &b), std::cmp::Ordering::Equal);
}

#[test]
fn test_multi_point_similar_head_match() {
    // First 128 bytes identical, tails differ.
    let mut a = vec![0u8; 200];
    a[128..].fill(1);
    let mut b = vec![0u8; 200];
    b[128..].fill(2);
    assert!(multi_point_similar(&a, &b));
}

#[test]
fn test_multi_point_similar_tail_match() {
    // Bytes 72..200 (tail of 128) identical; bytes 0..72 differ (so head check fails).
    let mut a = vec![0u8; 200];
    let mut b = vec![0u8; 200];
    a[..72].fill(1);
    b[..72].fill(2);
    assert!(multi_point_similar(&a, &b));
}

#[test]
fn test_multi_point_similar_no_match() {
    let a = vec![1u8; 256];
    let b = vec![2u8; 256];
    assert!(!multi_point_similar(&a, &b));
}

#[test]
fn test_multi_point_similar_too_small() {
    assert!(!multi_point_similar(&[1u8, 2, 3], &[4u8, 5, 6]));
}

/// Regression: the pack trailer must be built from the checksum's own length,
/// not from the thread-local `HashKind`. The encoder is constructed under
/// SHA-256 and then driven on a fresh thread whose thread-local still holds
/// the default SHA-1 kind — the previous `ObjectHash::from_bytes` call
/// panicked there ("Invalid byte length: got 32, expected 20"), which
/// surfaced as flaky SHA-256 pack failures in async runtimes that migrate
/// tasks across worker threads.
#[test]
fn test_parallel_encode_trailer_ignores_thread_local_kind() {
    use crate::hash::get_hash_kind;

    let _guard = set_hash_kind_for_test(HashKind::Sha256);

    let entries: Vec<Entry> = (0..8)
        .map(|i| Entry::from(Blob::from_content(&format!("thread-local-kind-{i}"))))
        .collect();
    let (tx, mut rx) = mpsc::channel(16);
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(16);
    let mut encoder = PackEncoder::new(entries.len(), 0, tx);

    std::thread::spawn(move || {
        // A fresh thread never saw `set_hash_kind`, so it holds the default
        // SHA-1 kind — the exact condition that used to panic on finalize.
        assert_eq!(get_hash_kind(), HashKind::Sha1);
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build current-thread runtime");
        rt.block_on(async move {
            for entry in entries {
                entry_tx
                    .send(MetaAttached {
                        inner: entry,
                        meta: EntryMeta::new(),
                    })
                    .await
                    .expect("send entry");
            }
            drop(entry_tx);

            encoder
                .parallel_encode(entry_rx)
                .await
                .expect("parallel encode must succeed off the origin thread");

            let mut pack = Vec::new();
            while let Some(chunk) = rx.recv().await {
                pack.extend(chunk);
            }
            let trailer = encoder
                .get_hash()
                .expect("final hash must be recorded after encode");
            assert!(
                matches!(trailer, ObjectHash::Sha256(_)),
                "trailer must stay SHA-256 regardless of the worker thread's kind"
            );
            assert_eq!(
                &pack[pack.len() - 32..],
                trailer.to_data().as_slice(),
                "pack trailer bytes must be the 32-byte SHA-256 checksum"
            );
        });
    })
    .join()
    .expect("encoder thread must not panic");
}

/// BLAKE3 in-memory encode/decode round-trip (no-delta and delta windows): the trailer, the
/// decoded object IDs and the pack signature are all `ObjectHash::Blake3`, computed from the
/// explicit encoder/decoder kind while the thread-local kind is SHA-1. A SHA-256 decoder
/// rejects the same bytes (fail-closed, same width).
#[tokio::test]
async fn blake3_round_trip() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    let contents: Vec<String> = (0..12)
        .map(|i| format!("blake3 round trip payload {i} {}", "x".repeat(i * 7)))
        .collect();
    let blobs: Vec<Blob> = contents
        .iter()
        .map(|c| Blob::from_content_with_kind(HashKind::Blake3, c).unwrap())
        .collect();
    // A tree over the blobs and a commit pointing at it, so all three object types round-trip.
    let tree = Tree::from_tree_items_with_kind(
        HashKind::Blake3,
        blobs
            .iter()
            .enumerate()
            .map(|(i, b)| TreeItem::new(TreeItemMode::Blob, b.id, format!("file-{i}.txt")))
            .collect(),
    )
    .unwrap();
    let commit =
        Commit::from_tree_id_with_kind(HashKind::Blake3, tree.id, vec![], "blake3 pack").unwrap();
    let mut entries: Vec<Entry> = blobs.iter().map(|b| Entry::from(b.clone())).collect();
    entries.push(Entry::from(tree.clone()));
    entries.push(Entry::from(commit.clone()));
    let expected_ids: std::collections::HashSet<ObjectHash> =
        entries.iter().map(|e| e.hash).collect();
    assert_eq!(expected_ids.len(), blobs.len() + 2);
    assert!(expected_ids.iter().all(|id| id.kind() == HashKind::Blake3));

    for window in [0usize, 4] {
        let (tx, mut rx) = mpsc::channel(64);
        let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(64);
        let mut encoder =
            PackEncoder::new_with_hash_kind(HashKind::Blake3, entries.len(), window, tx);
        assert_eq!(encoder.hash_kind(), HashKind::Blake3);
        for entry in &entries {
            entry_tx
                .send(MetaAttached {
                    inner: entry.clone(),
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
        drop(entry_tx);
        encoder.encode(entry_rx).await.expect("blake3 encode");
        let mut pack = Vec::new();
        while let Some(chunk) = rx.recv().await {
            pack.extend(chunk);
        }
        let trailer = encoder.get_hash().expect("final hash");
        assert_eq!(trailer.kind(), HashKind::Blake3, "window {window}");
        assert_eq!(&pack[pack.len() - 32..], trailer.to_data().as_slice());
        assert_eq!(
            trailer,
            ObjectHash::new_for_kind(HashKind::Blake3, &pack[..pack.len() - 32])
        );

        // Decode with an explicit BLAKE3 pack (thread-local still SHA-1).
        let decoded = Arc::new(std::sync::Mutex::new(Vec::new()));
        let sink = decoded.clone();
        let tmp = tempdir().unwrap();
        let mut p = Pack::new_with_hash_kind(
            HashKind::Blake3,
            Some(2),
            Some(64 * 1024 * 1024),
            Some(tmp.path().to_path_buf()),
            true,
        );
        assert_eq!(p.hash_kind, HashKind::Blake3);
        p.decode(
            &mut Cursor::new(&pack),
            move |entry| sink.lock().unwrap().push(entry.inner.hash),
            None::<fn(ObjectHash)>,
        )
        .expect("blake3 decode");
        assert_eq!(p.signature, trailer);
        let decoded: std::collections::HashSet<ObjectHash> =
            decoded.lock().unwrap().iter().copied().collect();
        assert_eq!(decoded, expected_ids, "window {window}");
        assert!(decoded.contains(&tree.id) && decoded.contains(&commit.id));

        // Same bytes, SHA-256 decoder: the trailer no longer matches (fail-closed).
        let tmp2 = tempdir().unwrap();
        let mut wrong = Pack::new_with_hash_kind(
            HashKind::Sha256,
            Some(1),
            Some(64 * 1024 * 1024),
            Some(tmp2.path().to_path_buf()),
            true,
        );
        let err = wrong
            .decode(&mut Cursor::new(&pack), |_| {}, None::<fn(ObjectHash)>)
            .unwrap_err();
        assert!(
            err.to_string().contains("does not match the trailer hash"),
            "window {window}: {err}"
        );
    }

    // File output: the BLAKE3 pack/idx pair written by
    // `encode_and_output_to_files_with_hash_kind` is accepted by the idx-backed decoder and by
    // `PackStats` (names, CRCs over the encoded entries, offsets, both checksums), and is
    // still refused under SHA-256.
    let out = tempdir().unwrap();
    let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(64);
    let to_send = entries.clone();
    tokio::spawn(async move {
        for entry in to_send {
            entry_tx
                .send(MetaAttached {
                    inner: entry,
                    meta: EntryMeta::new(),
                })
                .await
                .unwrap();
        }
    });
    super::output::encode_and_output_to_files_with_hash_kind(
        HashKind::Blake3,
        entry_rx,
        entries.len(),
        out.path().to_path_buf(),
        4,
    )
    .await
    .expect("blake3 files");
    let pack_file = std::fs::read_dir(out.path())
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| p.extension().is_some_and(|ext| ext == "pack"))
        .expect("pack file");
    assert!(pack_file.with_extension("idx").is_file());
    let mut p = Pack::new_with_hash_kind(
        HashKind::Blake3,
        Some(1),
        Some(64 * 1024 * 1024),
        Some(out.path().join("tmp")),
        true,
    );
    p.decode_file_full_without_callback(&pack_file, None::<fn(ObjectHash)>)
        .expect("blake3 idx-backed decode");
    assert_eq!(p.number, entries.len());
    assert_eq!(p.signature.kind(), HashKind::Blake3);
    let stats = crate::internal::pack::stats::PackStats::analyze_with_hash_kind(
        HashKind::Blake3,
        &pack_file,
    )
    .expect("blake3 stats over generated idx");
    assert_eq!(stats.total, entries.len());
    let mut wrong = Pack::new_with_hash_kind(
        HashKind::Sha256,
        Some(1),
        None,
        Some(out.path().join("tmp2")),
        true,
    );
    assert!(
        wrong
            .decode_file_full_without_callback(&pack_file, None::<fn(ObjectHash)>)
            .is_err()
    );
}

/// A BLAKE3 encoder refuses an entry whose ID belongs to another kind (same width or not), on
/// both the delta-window and the parallel no-delta paths.
#[tokio::test]
async fn blake3_round_trip_rejects_cross_kind_entries() {
    let _guard = set_hash_kind_for_test(HashKind::Sha1);
    for (window, foreign) in [
        (0usize, HashKind::Sha256),
        (4, HashKind::Sha1),
        (0, HashKind::Sha1),
    ] {
        let blob = Blob::from_content_with_kind(foreign, "foreign").unwrap();
        let (tx, _rx) = mpsc::channel(8);
        let (entry_tx, entry_rx) = mpsc::channel::<MetaAttached<Entry, EntryMeta>>(8);
        let mut encoder = PackEncoder::new_with_hash_kind(HashKind::Blake3, 1, window, tx);
        entry_tx
            .send(MetaAttached {
                inner: Entry::from(blob),
                meta: EntryMeta::new(),
            })
            .await
            .unwrap();
        drop(entry_tx);
        let err = if window == 0 {
            encoder.parallel_encode(entry_rx).await.unwrap_err()
        } else {
            encoder.encode(entry_rx).await.unwrap_err()
        };
        let msg = err.to_string();
        assert!(
            msg.contains("cannot be encoded into a blake3 pack"),
            "{msg}"
        );
        assert!(msg.contains(foreign.as_str()), "{msg}");
    }
}
