//! Transport-agnostic pack generator that reuses repository storage traits to walk commits, expand
//! trees/blobs, and either stream packs to clients or unpack uploads for server-side ingestion.

use std::{
    collections::{HashSet, VecDeque},
    io::Cursor,
};

use bytes::Bytes;
use tokio::{self, sync::mpsc};
use tokio_stream::wrappers::ReceiverStream;

use super::{core::RepositoryAccess, types::ProtocolError};
use crate::{
    hash::{HashKind, ObjectHash},
    internal::{
        metadata::{EntryMeta, MetaAttached},
        object::{ObjectTrait, blob::Blob, commit::Commit, tree::Tree, types::ObjectType},
        pack::{Pack, encode::PackEncoder, entry::Entry},
    },
};

/// Pack generation service for Git protocol operations
///
/// This handles the core Git pack generation logic internally within git-internal,
/// using the RepositoryAccess trait only for data access. Pack trailers, object IDs and
/// decoding are bound to the repository's `object_hash_kind()` (SHA-1, SHA-256, or the
/// BLAKE3 extension); nothing is inferred from ID widths.
pub struct PackGenerator<'a, R>
where
    R: RepositoryAccess,
{
    repo_access: &'a R,
    /// Object format every pack produced or consumed by this generator is bound to. Captured
    /// once (at construction, on the caller's thread) and never re-read across `.await`s.
    hash_kind: HashKind,
}

impl<'a, R> PackGenerator<'a, R>
where
    R: RepositoryAccess,
{
    /// Create a generator bound to `repo_access.object_hash_kind()` as observed right now.
    pub fn new(repo_access: &'a R) -> Self {
        Self::new_with_hash_kind(repo_access, repo_access.object_hash_kind())
    }

    /// Create a generator bound to an explicit, already validated `hash_kind` (what
    /// `SmartProtocol` passes after its consistency check).
    pub fn new_with_hash_kind(repo_access: &'a R, hash_kind: HashKind) -> Self {
        Self {
            repo_access,
            hash_kind,
        }
    }

    /// The object format this generator is bound to.
    pub fn hash_kind(&self) -> HashKind {
        self.hash_kind
    }

    /// Generate a full pack containing all requested objects.
    ///
    /// Object collection (and its kind checks) happens before this returns; the pack bytes
    /// are produced on a background task and delivered as `Ok` chunks, and any failure of
    /// that task is delivered as a final `Err` item (fail-closed, never a silent EOF).
    pub async fn generate_full_pack(
        &self,
        want: Vec<String>,
    ) -> Result<ReceiverStream<Result<Vec<u8>, ProtocolError>>, ProtocolError> {
        // The pack is bound to the kind captured at construction, never to a re-read of
        // `object_hash_kind()` after an `.await`.
        let kind = self.hash_kind;

        // Collect all objects needed for the wanted commits
        let all_objects = self.collect_all_objects(kind, want).await?;

        Ok(Self::spawn_pack_stream(kind, all_objects))
    }

    /// Produce the pack for `objects` on a background task, forwarding a producer failure
    /// into the stream as an `Err` item.
    fn spawn_pack_stream(
        kind: HashKind,
        objects: (Vec<Commit>, Vec<Tree>, Vec<Blob>),
    ) -> ReceiverStream<Result<Vec<u8>, ProtocolError>> {
        let (tx, rx) = mpsc::channel(1024);
        tokio::spawn(async move {
            if let Err(e) = Self::generate_pack_stream(kind, objects, tx.clone()).await {
                tracing::error!("Failed to generate pack stream: {}", e);
                // A dropped receiver is not an error for the producer.
                let _ = tx.send(Err(e)).await;
            }
        });
        ReceiverStream::new(rx)
    }

    /// Generate an incremental pack containing only objects not in 'have' (see
    /// [`PackGenerator::generate_full_pack`] for the stream's error contract).
    pub async fn generate_incremental_pack(
        &self,
        want: Vec<String>,
        have: Vec<String>,
    ) -> Result<ReceiverStream<Result<Vec<u8>, ProtocolError>>, ProtocolError> {
        let kind = self.hash_kind;

        // Collect objects for wanted commits
        let wanted_objects = self.collect_all_objects(kind, want).await?;

        // Collect objects for have commits (to exclude)
        let have_objects = self.collect_all_objects(kind, have).await?;

        // Filter out objects that are already in 'have'
        let incremental_objects = Self::filter_objects(wanted_objects, have_objects);

        Ok(Self::spawn_pack_stream(kind, incremental_objects))
    }

    /// Unpack incoming pack stream and extract objects.
    ///
    /// The pack is decoded against the generator's bound object format: object IDs, ref-delta
    /// bases and the trailer checksum are computed and verified with that kind, so a pack of
    /// another format (for example a BLAKE3 pack pushed to a SHA-256 repository) fails closed.
    pub async fn unpack_stream(
        &self,
        pack_data: Bytes,
    ) -> Result<(Vec<Commit>, Vec<Tree>, Vec<Blob>), ProtocolError> {
        use std::sync::{Arc, Mutex};

        let commits = Arc::new(Mutex::new(Vec::new()));
        let trees = Arc::new(Mutex::new(Vec::new()));
        let blobs = Arc::new(Mutex::new(Vec::new()));

        let commits_clone = commits.clone();
        let trees_clone = trees.clone();
        let blobs_clone = blobs.clone();

        // Create a Pack instance for decoding, bound to the generator's object format
        let mut pack = Pack::new_with_hash_kind(self.hash_kind, None, None, None, true);
        let mut cursor = Cursor::new(pack_data.to_vec());

        // Decode the pack and collect entries
        pack.decode(
            &mut cursor,
            move |entry: MetaAttached<Entry, EntryMeta>| match entry.inner.obj_type {
                ObjectType::Commit => {
                    if let Ok(commit) = Commit::from_bytes(&entry.inner.data, entry.inner.hash) {
                        commits_clone.lock().unwrap().push(commit);
                    } else {
                        tracing::warn!("Failed to parse commit from pack entry");
                    }
                }
                ObjectType::Tree => {
                    if let Ok(tree) = Tree::from_bytes(&entry.inner.data, entry.inner.hash) {
                        trees_clone.lock().unwrap().push(tree);
                    } else {
                        tracing::warn!("Failed to parse tree from pack entry");
                    }
                }
                ObjectType::Blob => {
                    if let Ok(blob) = Blob::from_bytes(&entry.inner.data, entry.inner.hash) {
                        blobs_clone.lock().unwrap().push(blob);
                    } else {
                        tracing::warn!("Failed to parse blob from pack entry");
                    }
                }
                _ => {
                    tracing::warn!("Unknown object type in pack: {:?}", entry.inner.obj_type);
                }
            },
            None::<fn(ObjectHash)>,
        )
        .map_err(|e| ProtocolError::invalid_request(&format!("Failed to decode pack: {e}")))?;

        // Extract the results
        let commits_result = Arc::try_unwrap(commits).unwrap().into_inner().unwrap();
        let trees_result = Arc::try_unwrap(trees).unwrap().into_inner().unwrap();
        let blobs_result = Arc::try_unwrap(blobs).unwrap().into_inner().unwrap();

        Ok((commits_result, trees_result, blobs_result))
    }

    /// Collect all objects reachable from the given commit hashes.
    ///
    /// Every object handed back by the repository must carry an ID of `kind` (the kind
    /// captured before the first `.await`): a `RepositoryAccess` whose default accessors
    /// follow a drifting thread-local kind fails closed here instead of feeding foreign IDs
    /// into the pack.
    async fn collect_all_objects(
        &self,
        kind: HashKind,
        commit_hashes: Vec<String>,
    ) -> Result<(Vec<Commit>, Vec<Tree>, Vec<Blob>), ProtocolError> {
        let mut commits = Vec::new();
        let mut trees = Vec::new();
        let mut blobs = Vec::new();

        let mut visited_commits = HashSet::new();
        let mut visited_trees = HashSet::new();
        let mut visited_blobs = HashSet::new();

        let mut commit_queue = VecDeque::from(commit_hashes);

        // BFS traversal of commit graph
        while let Some(commit_hash) = commit_queue.pop_front() {
            if visited_commits.contains(&commit_hash) {
                continue;
            }
            visited_commits.insert(commit_hash.clone());

            // Get commit object
            let commit = self
                .repo_access
                .get_commit(&commit_hash)
                .await
                .map_err(|e| {
                    ProtocolError::repository_error(format!(
                        "Failed to get commit {commit_hash}: {e}"
                    ))
                })?;
            Self::ensure_object_kind(kind, "commit", commit.id)?;
            // Embedded references are validated before they are turned into raw strings: a
            // same-width ID of another namespace must never be re-interpreted as `kind`.
            Self::ensure_object_kind(kind, "commit tree reference", commit.tree_id)?;

            // Add parent commits to queue
            for parent in &commit.parent_commit_ids {
                Self::ensure_object_kind(kind, "commit parent reference", *parent)?;
                let parent_str = parent.to_string();
                if !visited_commits.contains(&parent_str) {
                    commit_queue.push_back(parent_str);
                }
            }

            // Collect tree objects
            Box::pin(self.collect_tree_objects(
                kind,
                &commit.tree_id.to_string(),
                &mut trees,
                &mut blobs,
                &mut visited_trees,
                &mut visited_blobs,
            ))
            .await?;

            commits.push(commit);
        }

        Ok((commits, trees, blobs))
    }

    /// Reject an object whose ID belongs to another format than the repository's `kind`.
    fn ensure_object_kind(kind: HashKind, what: &str, id: ObjectHash) -> Result<(), ProtocolError> {
        id.ensure_kind(kind).map_err(|e| {
            ProtocolError::repository_error(format!(
                "Repository returned {what} {} of another object format: {e}",
                id.to_tagged_string()
            ))
        })
    }

    /// Recursively collect tree and blob objects
    async fn collect_tree_objects(
        &self,
        kind: HashKind,
        tree_hash: &str,
        trees: &mut Vec<Tree>,
        blobs: &mut Vec<Blob>,
        visited_trees: &mut HashSet<String>,
        visited_blobs: &mut HashSet<String>,
    ) -> Result<(), ProtocolError> {
        if visited_trees.contains(tree_hash) {
            return Ok(());
        }
        visited_trees.insert(tree_hash.to_string());

        let tree = self.repo_access.get_tree(tree_hash).await.map_err(|e| {
            ProtocolError::repository_error(format!("Failed to get tree {tree_hash}: {e}"))
        })?;
        Self::ensure_object_kind(kind, "tree", tree.id)?;

        for entry in &tree.tree_items {
            Self::ensure_object_kind(kind, "tree entry reference", entry.id)?;
            let entry_hash = entry.id.to_string();
            match entry.mode {
                crate::internal::object::tree::TreeItemMode::Tree => {
                    Box::pin(self.collect_tree_objects(
                        kind,
                        &entry_hash,
                        trees,
                        blobs,
                        visited_trees,
                        visited_blobs,
                    ))
                    .await?;
                }
                crate::internal::object::tree::TreeItemMode::Blob
                | crate::internal::object::tree::TreeItemMode::BlobExecutable
                    if !visited_blobs.contains(&entry_hash) =>
                {
                    visited_blobs.insert(entry_hash.clone());
                    let blob = self.repo_access.get_blob(&entry_hash).await.map_err(|e| {
                        ProtocolError::repository_error(format!(
                            "Failed to get blob {entry_hash}: {e}"
                        ))
                    })?;
                    Self::ensure_object_kind(kind, "blob", blob.id)?;
                    blobs.push(blob);
                }
                _ => {}
            }
        }

        trees.push(tree);
        Ok(())
    }

    /// Filter objects to exclude those already in 'have'
    fn filter_objects(
        wanted: (Vec<Commit>, Vec<Tree>, Vec<Blob>),
        have: (Vec<Commit>, Vec<Tree>, Vec<Blob>),
    ) -> (Vec<Commit>, Vec<Tree>, Vec<Blob>) {
        let (wanted_commits, wanted_trees, wanted_blobs) = wanted;
        let (have_commits, have_trees, have_blobs) = have;

        // Create hash sets for efficient lookup
        let have_commit_hashes: HashSet<String> =
            have_commits.iter().map(|c| c.id.to_string()).collect();
        let have_tree_hashes: HashSet<String> =
            have_trees.iter().map(|t| t.id.to_string()).collect();
        let have_blob_hashes: HashSet<String> =
            have_blobs.iter().map(|b| b.id.to_string()).collect();

        // Filter out objects that are in 'have'
        let filtered_commits: Vec<Commit> = wanted_commits
            .into_iter()
            .filter(|c| !have_commit_hashes.contains(&c.id.to_string()))
            .collect();

        let filtered_trees: Vec<Tree> = wanted_trees
            .into_iter()
            .filter(|t| !have_tree_hashes.contains(&t.id.to_string()))
            .collect();

        let filtered_blobs: Vec<Blob> = wanted_blobs
            .into_iter()
            .filter(|b| !have_blob_hashes.contains(&b.id.to_string()))
            .collect();

        (filtered_commits, filtered_trees, filtered_blobs)
    }

    /// Generate pack stream from objects, hashing the trailer with the repository `kind`;
    /// the encoder refuses entries whose IDs belong to another kind.
    async fn generate_pack_stream(
        kind: HashKind,
        objects: (Vec<Commit>, Vec<Tree>, Vec<Blob>),
        tx: mpsc::Sender<Result<Vec<u8>, ProtocolError>>,
    ) -> Result<(), ProtocolError> {
        let (commits, trees, blobs) = objects;

        // Convert objects to entries
        let mut entries = Vec::new();

        for commit in commits {
            entries.push(Entry::from(commit));
        }

        for tree in trees {
            entries.push(Entry::from(tree));
        }

        for blob in blobs {
            entries.push(Entry::from(blob));
        }

        // Fail closed before a single PACK byte is emitted: every entry must carry an ID of
        // the repository kind (the encoder checks this too, but only after the header).
        for entry in &entries {
            entry.hash.ensure_kind(kind).map_err(|e| {
                ProtocolError::Pack(format!(
                    "Pack entry {} does not belong to the repository object format: {e}",
                    entry.hash.to_tagged_string()
                ))
            })?;
        }

        // Nothing to send (every wanted object is already on the `have` side): emit a valid
        // empty pack — header with zero objects plus the trailer of the repository kind —
        // instead of driving the encoder, which requires at least one object.
        if entries.is_empty() {
            let mut header = Vec::with_capacity(12 + kind.size());
            header.extend_from_slice(b"PACK");
            header.extend_from_slice(&2u32.to_be_bytes());
            header.extend_from_slice(&0u32.to_be_bytes());
            let trailer = ObjectHash::new_for_kind(kind, &header);
            header.extend_from_slice(trailer.as_ref());
            // A dropped receiver is not an error for the producer.
            let _ = tx.send(Ok(header)).await;
            return Ok(());
        }

        // Create PackEncoder and encode entries
        let (pack_tx, mut pack_rx) = mpsc::channel(1024);
        let (entry_tx, entry_rx) = mpsc::channel(1024);
        let mut encoder = PackEncoder::new_with_hash_kind(kind, entries.len(), 10, pack_tx); // window_size = 10

        // Spawn encoding task; its result is surfaced below instead of being logged and lost.
        let encode_task = tokio::spawn(async move { encoder.encode(entry_rx).await });

        // Send entries to encoder
        tokio::spawn(async move {
            for entry in entries {
                if entry_tx
                    .send(MetaAttached {
                        inner: entry,
                        meta: EntryMeta::new(),
                    })
                    .await
                    .is_err()
                {
                    break; // Receiver dropped
                }
            }
            // Drop sender to signal end of entries
        });

        // Forward pack data to output channel
        let mut consumer_gone = false;
        while let Some(chunk) = pack_rx.recv().await {
            if tx.send(Ok(chunk)).await.is_err() {
                consumer_gone = true; // Receiver dropped
                break;
            }
        }
        if consumer_gone {
            // Nobody is listening: drop our end of the encoder channel so the encoder's next
            // send fails immediately instead of blocking on a full channel forever, then let
            // the task wind down. There is no one left to report to.
            drop(pack_rx);
            let _ = encode_task.await;
            return Ok(());
        }

        // An encoder failure is an error of this call, never a "successful" partial stream.
        match encode_task.await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => Err(ProtocolError::Pack(format!("Failed to encode pack: {e}"))),
            Err(e) => Err(ProtocolError::Pack(format!(
                "Pack encoder task failed: {e}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use async_trait::async_trait;
    use bytes::Bytes;

    use super::*;
    use crate::{
        hash::{HashKind, set_hash_kind_for_test},
        internal::object::{
            blob::Blob,
            commit::Commit,
            signature::{Signature, SignatureType},
            tree::{Tree, TreeItem, TreeItemMode},
        },
        utils::HashAlgorithm,
    };
    /// Dummy repository access for testing
    #[derive(Clone)]
    struct DummyRepoAccess;

    #[async_trait]
    impl RepositoryAccess for DummyRepoAccess {
        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            Ok(vec![])
        }
        async fn has_object(&self, _object_hash: &str) -> Result<bool, ProtocolError> {
            Ok(false)
        }
        async fn get_object(&self, _object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
            Err(ProtocolError::repository_error(
                "not implemented".to_string(),
            ))
        }
        async fn store_pack_data(&self, _pack_data: &[u8]) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn update_reference(
            &self,
            _ref_name: &str,
            _old_hash: Option<&str>,
            _new_hash: &str,
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn get_objects_for_pack(
            &self,
            _wants: &[String],
            _haves: &[String],
        ) -> Result<Vec<String>, ProtocolError> {
            Ok(vec![])
        }
        async fn has_default_branch(&self) -> Result<bool, ProtocolError> {
            Ok(false)
        }
        async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    /// Encode and decode a pack, asserting that all object IDs survive the roundtrip.
    async fn run_pack_roundtrip(kind: HashKind) {
        let _guard = set_hash_kind_for_test(kind);
        let blob1 = Blob::from_content("hello");
        let blob2 = Blob::from_content("world");

        let item1 = TreeItem::new(TreeItemMode::Blob, blob1.id, "hello.txt".to_string());
        let item2 = TreeItem::new(TreeItemMode::Blob, blob2.id, "world.txt".to_string());
        let tree = Tree::from_tree_items(vec![item1, item2]).unwrap();

        let author = Signature::new(
            SignatureType::Author,
            "tester".to_string(),
            "tester@example.com".to_string(),
        );
        let committer = Signature::new(
            SignatureType::Committer,
            "tester".to_string(),
            "tester@example.com".to_string(),
        );
        let commit = Commit::new(author, committer, tree.id, vec![], "init commit");

        let (tx, mut rx) = mpsc::channel::<Result<Vec<u8>, ProtocolError>>(64);
        PackGenerator::<DummyRepoAccess>::generate_pack_stream(
            kind,
            (
                vec![commit.clone()],
                vec![tree.clone()],
                vec![blob1.clone(), blob2.clone()],
            ),
            tx,
        )
        .await
        .unwrap();

        let mut pack_bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = rx.recv().await {
            pack_bytes.extend_from_slice(&chunk.unwrap());
        }

        let dummy = DummyRepoAccess;
        let generator = PackGenerator::new(&dummy);
        let (decoded_commits, decoded_trees, decoded_blobs) = generator
            .unpack_stream(Bytes::from(pack_bytes))
            .await
            .unwrap();

        assert_eq!(decoded_commits.len(), 1);
        assert_eq!(decoded_trees.len(), 1);
        assert_eq!(decoded_blobs.len(), 2);

        assert_eq!(decoded_commits[0].id, commit.id);
        assert_eq!(decoded_trees[0].id, tree.id);

        let mut orig_blob_ids = vec![blob1.id.to_string(), blob2.id.to_string()];
        orig_blob_ids.sort_unstable();
        let mut decoded_blob_ids = decoded_blobs
            .iter()
            .map(|b| b.id.to_string())
            .collect::<Vec<_>>();
        decoded_blob_ids.sort_unstable();
        assert_eq!(orig_blob_ids, decoded_blob_ids);
    }

    /// Pack encode/decode roundtrip using SHA-1 and SHA-256
    #[tokio::test]
    async fn test_pack_roundtrip_encode_decode() {
        run_pack_roundtrip(HashKind::Sha1).await;
        run_pack_roundtrip(HashKind::Sha256).await;
    }

    /// Repository access that reports a fixed object format.
    #[derive(Clone)]
    struct KindRepoAccess(HashKind);

    #[async_trait]
    impl RepositoryAccess for KindRepoAccess {
        fn object_hash_kind(&self) -> HashKind {
            self.0
        }
        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            Ok(vec![])
        }
        async fn has_object(&self, _object_hash: &str) -> Result<bool, ProtocolError> {
            Ok(false)
        }
        async fn get_object(&self, _object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
            Err(ProtocolError::ObjectNotFound("dummy".to_string()))
        }
        async fn store_pack_data(&self, _pack_data: &[u8]) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn update_reference(
            &self,
            _ref_name: &str,
            _old_hash: Option<&str>,
            _new_hash: &str,
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn get_objects_for_pack(
            &self,
            _wants: &[String],
            _haves: &[String],
        ) -> Result<Vec<String>, ProtocolError> {
            Ok(vec![])
        }
        async fn has_default_branch(&self) -> Result<bool, ProtocolError> {
            Ok(false)
        }
        async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }

    /// BLAKE3 repository: the protocol pack path consumes explicit-kind `ObjectHash`es —
    /// generation and unpacking follow `object_hash_kind()` (thread-local kind is SHA-1), the
    /// trailer is a BLAKE3 checksum, a SHA-256 repository rejects the same bytes (same ID
    /// width, different kind: nothing is inferred from the width), and cross-kind entries
    /// never produce a decodable BLAKE3 pack.
    #[tokio::test]
    async fn blake3_round_trip() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let kind = HashKind::Blake3;
        let blob1 = Blob::from_content_with_kind(kind, "hello").unwrap();
        let blob2 = Blob::from_content_with_kind(kind, "world").unwrap();
        let item1 = TreeItem::new(TreeItemMode::Blob, blob1.id, "hello.txt".to_string());
        let item2 = TreeItem::new(TreeItemMode::Blob, blob2.id, "world.txt".to_string());
        let tree = Tree::from_tree_items_with_kind(kind, vec![item1, item2]).unwrap();
        let author = Signature::new(
            SignatureType::Author,
            "tester".to_string(),
            "tester@example.com".to_string(),
        );
        let committer = Signature::new(
            SignatureType::Committer,
            "tester".to_string(),
            "tester@example.com".to_string(),
        );
        let commit =
            Commit::new_with_kind(kind, author, committer, tree.id, vec![], "init commit").unwrap();
        assert_eq!(commit.id.kind(), HashKind::Blake3);

        let (tx, mut rx) = mpsc::channel::<Result<Vec<u8>, ProtocolError>>(64);
        PackGenerator::<KindRepoAccess>::generate_pack_stream(
            kind,
            (
                vec![commit.clone()],
                vec![tree.clone()],
                vec![blob1.clone(), blob2.clone()],
            ),
            tx,
        )
        .await
        .unwrap();
        let mut pack_bytes: Vec<u8> = Vec::new();
        while let Some(chunk) = rx.recv().await {
            pack_bytes.extend_from_slice(&chunk.unwrap());
        }

        // Trailer: 32-byte BLAKE3 checksum of the payload (not SHA-256).
        let (payload, trailer) = pack_bytes.split_at(pack_bytes.len() - kind.size());
        let mut hasher = HashAlgorithm::new_for_kind(kind);
        hasher.update(payload);
        let expected = hasher.finalize_object_hash();
        assert_eq!(
            ObjectHash::from_bytes_for_kind(kind, trailer).unwrap(),
            expected
        );
        let mut sha256 = HashAlgorithm::new_for_kind(HashKind::Sha256);
        sha256.update(payload);
        assert_ne!(sha256.finalize_object_hash().as_ref(), trailer);

        let repo = KindRepoAccess(kind);
        let (commits, trees, blobs) = PackGenerator::new(&repo)
            .unpack_stream(Bytes::from(pack_bytes.clone()))
            .await
            .unwrap();
        assert_eq!(commits.len(), 1);
        assert_eq!(trees.len(), 1);
        assert_eq!(blobs.len(), 2);
        assert_eq!(commits[0].id, commit.id);
        assert_eq!(trees[0].id, tree.id);
        let mut blob_ids = blobs.iter().map(|b| b.id).collect::<Vec<_>>();
        blob_ids.sort_unstable_by_key(|id| id.to_string());
        let mut expected_ids = vec![blob1.id, blob2.id];
        expected_ids.sort_unstable_by_key(|id| id.to_string());
        assert_eq!(blob_ids, expected_ids);
        for id in commits
            .iter()
            .map(|c| c.id)
            .chain(trees.iter().map(|t| t.id))
            .chain(blob_ids)
        {
            assert_eq!(id.kind(), HashKind::Blake3);
        }

        // Same bytes offered to a SHA-256 repository: rejected, never re-interpreted.
        let sha256_repo = KindRepoAccess(HashKind::Sha256);
        assert!(
            PackGenerator::new(&sha256_repo)
                .unpack_stream(Bytes::from(pack_bytes))
                .await
                .is_err()
        );

        // A SHA-1 entry cannot be packed as BLAKE3: refused before a single byte is emitted.
        let sha1_blob = Blob::from_content("hello");
        assert_eq!(sha1_blob.id.kind(), HashKind::Sha1);
        let (tx, mut rx) = mpsc::channel::<Result<Vec<u8>, ProtocolError>>(64);
        let err = PackGenerator::<KindRepoAccess>::generate_pack_stream(
            kind,
            (vec![], vec![], vec![sha1_blob.clone()]),
            tx,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, ProtocolError::Pack(_)), "{err:?}");
        assert!(err.to_string().contains("sha1:"), "{err}");
        assert!(rx.recv().await.is_none(), "no pack bytes may be emitted");

        // Through the background producer the same failure is delivered as the stream's only
        // item, an `Err` (never a silent EOF / truncated pack).
        let mut stream = PackGenerator::<KindRepoAccess>::spawn_pack_stream(
            kind,
            (vec![], vec![], vec![sha1_blob]),
        );
        let first = futures::StreamExt::next(&mut stream)
            .await
            .expect("an item");
        let err = first.expect_err("producer failure must surface as Err");
        assert!(matches!(err, ProtocolError::Pack(_)), "{err:?}");
        assert!(futures::StreamExt::next(&mut stream).await.is_none());

        // A repository that reports BLAKE3 but hands back objects of another format (kind
        // drift behind the default accessors) is refused during collection.
        let drift = DriftRepo {
            commit: Commit::from_tree_id_with_kind(
                HashKind::Sha1,
                Tree::from_tree_items_with_kind(
                    HashKind::Sha1,
                    vec![TreeItem::new(
                        TreeItemMode::Blob,
                        Blob::from_content("d").id,
                        "d".to_string(),
                    )],
                )
                .unwrap()
                .id,
                vec![],
                "drift",
            )
            .unwrap(),
        };
        let err = PackGenerator::new(&drift)
            .collect_all_objects(HashKind::Blake3, vec![drift.commit.id.to_string()])
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("another object format")
                && err.to_string().contains("expected blake3"),
            "{err}"
        );
        // The generator's kind is captured at construction (`new` observes the repository
        // once; `new_with_hash_kind` takes the validated kind) and is what every pack uses.
        assert_eq!(PackGenerator::new(&drift).hash_kind(), HashKind::Blake3);
        assert_eq!(
            PackGenerator::new_with_hash_kind(&repo, HashKind::Blake3).hash_kind(),
            HashKind::Blake3
        );

        // A BLAKE3 commit whose *embedded* parent reference is a same-width SHA-256 ID is
        // refused before the reference is turned into a raw string (never re-interpreted).
        let mut poisoned = commit.clone();
        poisoned.parent_commit_ids.push(ObjectHash::new_for_kind(
            HashKind::Sha256,
            b"foreign parent",
        ));
        let err = PackGenerator::new(&DriftRepo { commit: poisoned })
            .collect_all_objects(HashKind::Blake3, vec![commit.id.to_string()])
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("commit parent reference")
                && err.to_string().contains("expected blake3")
                && err.to_string().contains("got sha256"),
            "{err}"
        );

        // A consumer that drops the stream must not hang the producer.
        let (tx, rx) = mpsc::channel::<Result<Vec<u8>, ProtocolError>>(1);
        drop(rx);
        let big: Vec<Blob> = (0..64)
            .map(|i| {
                Blob::from_content_with_kind(kind, &format!("chunk {i} {}", "y".repeat(4096)))
                    .unwrap()
            })
            .collect();
        tokio::time::timeout(
            std::time::Duration::from_secs(30),
            PackGenerator::<KindRepoAccess>::generate_pack_stream(kind, (vec![], vec![], big), tx),
        )
        .await
        .expect("producer must finish when the consumer is gone")
        .unwrap();
    }

    /// Reports BLAKE3 but returns a SHA-1 commit from `get_commit`.
    #[derive(Clone)]
    struct DriftRepo {
        commit: Commit,
    }

    #[async_trait]
    impl RepositoryAccess for DriftRepo {
        fn object_hash_kind(&self) -> HashKind {
            HashKind::Blake3
        }
        async fn get_repository_refs(&self) -> Result<Vec<(String, String)>, ProtocolError> {
            Ok(vec![])
        }
        async fn has_object(&self, _object_hash: &str) -> Result<bool, ProtocolError> {
            Ok(true)
        }
        async fn get_object(&self, _object_hash: &str) -> Result<Vec<u8>, ProtocolError> {
            Err(ProtocolError::ObjectNotFound("drift".to_string()))
        }
        async fn get_commit(&self, _commit_hash: &str) -> Result<Commit, ProtocolError> {
            Ok(self.commit.clone())
        }
        async fn store_pack_data(&self, _pack_data: &[u8]) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn update_reference(
            &self,
            _ref_name: &str,
            _old_hash: Option<&str>,
            _new_hash: &str,
        ) -> Result<(), ProtocolError> {
            Ok(())
        }
        async fn get_objects_for_pack(
            &self,
            _wants: &[String],
            _haves: &[String],
        ) -> Result<Vec<String>, ProtocolError> {
            Ok(vec![])
        }
        async fn has_default_branch(&self) -> Result<bool, ProtocolError> {
            Ok(false)
        }
        async fn post_receive_hook(&self) -> Result<(), ProtocolError> {
            Ok(())
        }
    }
}
