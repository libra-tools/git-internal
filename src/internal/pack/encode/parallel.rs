//! Parallel (non-delta) pack encoding path.
//!
//! When `window_size == 0`, entries are independently zlib-compressed in parallel via Rayon.
//! Input is read in bounded batches to balance memory usage and parallelism.
//!
//! This path is not compatible with delta compression — use the delta path in
//! [`super::inner_encode`] for windowed encoding.

use rayon::prelude::*;
use tokio::sync::mpsc;

use super::header::{encode_header, encode_one_object};
use crate::{
    errors::GitError,
    hash::ObjectHash,
    internal::{
        metadata::{EntryMeta, MetaAttached},
        pack::{entry::Entry, index_entry::IndexEntry},
    },
    time_it,
};

impl super::PackEncoder {
    /// Encode independent objects in parallel without delta compression.
    ///
    /// Input is read in bounded batches, and Rayon performs each object's header construction and
    /// zlib compression concurrently. Rayon collection preserves input order, after which chunks
    /// are written serially so pack offsets and the running checksum remain correct.
    ///
    /// This path is valid only when `window_size == 0`.
    pub async fn parallel_encode(
        &mut self,
        mut entry_rx: mpsc::Receiver<MetaAttached<Entry, EntryMeta>>,
    ) -> Result<(), GitError> {
        if self.window_size != 0 {
            return Err(GitError::PackEncodeError(
                "parallel encode only works when window_size == 0".to_string(),
            ));
        }

        // As in the delta path, the trailer checksum covers the header and all entries.
        let head = encode_header(self.object_number);
        self.inner_hash.update(&head);
        self.send_data(head).await;

        // Reusing the same encoder would corrupt its running offset and checksum state.
        if self.start_encoding {
            return Err(GitError::PackEncodeError(
                "encoding operation is already in progress".to_string(),
            ));
        }

        let mut idx_entries = Vec::with_capacity(self.object_number);
        // Batching bounds temporary memory while giving Rayon enough work to distribute.
        let batch_size = usize::max(1000, entry_rx.max_capacity() / 10); // Temporary heuristic.
        tracing::info!("encode with batch size: {}", batch_size);
        loop {
            let mut batch_entries = Vec::with_capacity(batch_size);
            time_it!("parallel encode: receive batch", {
                for _ in 0..batch_size {
                    match entry_rx.recv().await {
                        Some(entry) => {
                            if entry.inner.obj_type.is_ai_object() {
                                return Err(GitError::PackEncodeError(format!(
                                    "AI object type `{}` cannot be encoded in a pack file",
                                    entry.inner.obj_type
                                )));
                            }
                            batch_entries.push(entry.inner);
                            self.process_index += 1;
                        }
                        None => break,
                    }
                }
            });

            if batch_entries.is_empty() {
                break;
            }

            // Indexed parallel collection retains batch order even though compression finishes on
            // different Rayon workers.
            let batch_result: Vec<Result<(Vec<u8>, IndexEntry), GitError>> =
                time_it!("parallel encode: encode batch", {
                    batch_entries
                        .par_iter()
                        .map(|entry| {
                            encode_one_object(entry, None)
                                .map(|encoded| (encoded, IndexEntry::new(entry, 0)))
                        })
                        .collect()
                });

            time_it!("parallel encode: write batch", {
                for obj_data in batch_result {
                    let (encoded_bytes, mut idx_entry) = obj_data?;
                    idx_entry.offset = self.inner_offset as u64;
                    self.write_owned_and_update(encoded_bytes).await;
                    idx_entries.push(idx_entry);
                }
            });
        }

        tracing::debug!("parallel encode idx entries: {:?}", idx_entries.len());
        if self.process_index != self.object_number {
            panic!(
                "not all objects are encoded, process:{}, total:{}",
                self.process_index, self.object_number
            );
        }

        // Append the checksum trailer only after every encoded entry has updated the running hash.
        // Infer the kind from the checksum length: this task may run on an async worker
        // thread whose thread-local `HashKind` was never set, so `ObjectHash::from_bytes`
        // could disagree with the hasher chosen at encoder construction.
        let hash_result = self.inner_hash.clone().finalize();
        self.final_hash = Some(
            ObjectHash::from_bytes_infer_kind(&hash_result).map_err(GitError::PackEncodeError)?,
        );
        self.send_data(hash_result).await;
        self.drop_sender();

        self.idx_entries = Some(idx_entries);
        Ok(())
    }
}
