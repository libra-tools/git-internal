//! Object model definitions for Git blobs, trees, commits, tags, and
//! AI workflow objects.
//!
//! This module is the storage-layer contract for `git-internal`.
//! Git-native objects (`Blob`, `Tree`, `Commit`, `Tag`) model repository
//! content, while the AI objects model immutable workflow history that
//! Libra orchestrates on top.
//!
//! # How Libra should use this module
//!
//! Libra should treat every AI object here as an immutable record:
//!
//! - construct the object in memory,
//! - populate optional fields before persistence,
//! - persist it once,
//! - derive current state later from object history plus Libra
//!   projections.
//!
//! Libra should not store scheduler state, selected heads, active UI
//! focus, or query caches in these objects. Those belong to Libra's own
//! runtime and index layer.
//!
//! AI workflow objects are split into three layers:
//!
//! - **Snapshot objects** in `git-internal` answer "what was the stored
//!   fact at this revision?"
//! - **Event objects** in `git-internal` answer "what happened later?"
//! - **Libra projections** answer "what is the system's current view?"
//!
//! # Relationship Design Standard
//!
//! Relationship fields follow a simple storage rule:
//!
//! - Store the canonical ownership edge on the child object when the
//!   relationship is a historical fact.
//! - Low-frequency, strongly aggregated relationships that benefit
//!   from fast parent-to-children traversal may additionally keep a
//!   reverse convenience link.
//! - High-frequency, high-cardinality, event-stream relationships
//!   should remain single-directional to avoid turning parent objects
//!   into rewrite hotspots.
//!
//! # Three-Layer Design
//!
//! ```text
//! +------------------------------------------------------------------+
//! | Libra projection / runtime                                       |
//! |------------------------------------------------------------------|
//! | thread heads / selected_plan_id / active_run / scheduler state   |
//! | live context window / UI focus / query indexes                   |
//! +--------------------------------+---------------------------------+
//!                                  |
//!                                  v
//! +------------------------------------------------------------------+
//! | git-internal event objects                                        |
//! |------------------------------------------------------------------|
//! | IntentEvent / TaskEvent / RunEvent / PlanStepEvent / RunUsage    |
//! | ToolInvocation / Evidence / Decision / ContextFrame              |
//! +--------------------------------+---------------------------------+
//!                                  |
//!                                  v
//! +------------------------------------------------------------------+
//! | git-internal snapshot objects                                     |
//! |------------------------------------------------------------------|
//! | Intent / Plan / Task / Run / PatchSet / ContextSnapshot          |
//! | Provenance                                                       |
//! +------------------------------------------------------------------+
//! ```
//!
//! # Main Object Relationships
//!
//! ```text
//! Snapshot layer
//! ==============
//!
//! Intent --parents----------------------------> Intent
//! Intent --analysis_context_frames-----------> ContextFrame
//! Plan   --intent-----------------------------> Intent
//! Plan   --context_frames---------------------> ContextFrame
//! Plan   --parents----------------------------> Plan
//! Task   --intent?----------------------------> Intent
//! Task   --parent?----------------------------> Task
//! Task   --origin_step_id?-------------------> PlanStep.step_id
//! Run    --task-------------------------------> Task
//! Run    --plan?------------------------------> Plan
//! Run    --snapshot?--------------------------> ContextSnapshot
//! PatchSet   --run----------------------------> Run
//! Provenance --run_id-------------------------> Run
//!
//! Event layer
//! ===========
//!
//! IntentEvent   --intent_id-------------------> Intent
//! IntentEvent   --next_intent_id?-------------> Intent
//! ContextFrame  --intent_id?------------------> Intent
//! TaskEvent     --task_id---------------------> Task
//! RunEvent      --run_id----------------------> Run
//! RunUsage      --run_id----------------------> Run
//! PlanStepEvent --plan_id + step_id + run_id-> Plan / Run / PlanStep
//! ToolInvocation--run_id----------------------> Run
//! Evidence      --run_id / patchset_id?-------> Run / PatchSet
//! Decision      --run_id / chosen_patchset_id?> Run / PatchSet
//! ContextFrame  --run_id? / plan_id? / step_id?> Run / Plan / PlanStep
//! ```
//!
//! # Libra read / write pattern
//!
//! A typical Libra call flow looks like this:
//!
//! 1. write snapshot objects when a new immutable revision is defined
//!    (`Intent`, `Plan`, `Task`, `Run`, `PatchSet`, `ContextSnapshot`,
//!    `Provenance`);
//! 2. append event objects as execution progresses
//!    (`IntentEvent`, `TaskEvent`, `RunEvent`, `PlanStepEvent`,
//!    `RunUsage`, `ToolInvocation`, `Evidence`, `Decision`,
//!    `ContextFrame`);
//! 3. rebuild current state in Libra from those immutable objects plus
//!    its own `Thread`, `Scheduler`, `UI`, and `Query Index`
//!    projections.
//!
//! ## Object Relationship Summary
//!
//! | From | Field | To | Cardinality |
//! |------|-------|----|-------------|
//! | Intent | `parents` | Intent | 0..N |
//! | Intent | `analysis_context_frames` | ContextFrame | 0..N |
//! | Plan | `intent` | Intent | 1 canonical |
//! | Plan | `parents` | Plan | 0..N |
//! | Plan | `context_frames` | ContextFrame | 0..N |
//! | Task | `parent` | Task | 0..1 |
//! | Task | `intent` | Intent | 0..1 |
//! | Task | `origin_step_id` | PlanStep.step_id | 0..1 |
//! | Task | `dependencies` | Task | 0..N |
//! | Run | `task` | Task | 1 |
//! | Run | `plan` | Plan | 0..1 |
//! | Run | `snapshot` | ContextSnapshot | 0..1 |
//! | PatchSet | `run` | Run | 1 |
//! | Provenance | `run_id` | Run | 1 |
//! | IntentEvent | `intent_id` | Intent | 1 |
//! | IntentEvent | `next_intent_id` | Intent | 0..1 recommended follow-up |
//! | ContextFrame | `intent_id` | Intent | 0..1 |
//! | TaskEvent | `task_id` | Task | 1 |
//! | RunEvent | `run_id` | Run | 1 |
//! | RunUsage | `run_id` | Run | 1 |
//! | PlanStepEvent | `plan_id` | Plan | 1 |
//! | PlanStepEvent | `step_id` | PlanStep.step_id | 1 |
//! | PlanStepEvent | `run_id` | Run | 1 |
//! | ToolInvocation | `run_id` | Run | 1 |
//! | Evidence | `run_id` | Run | 1 |
//! | Evidence | `patchset_id` | PatchSet | 0..1 |
//! | Decision | `run_id` | Run | 1 |
//! | Decision | `chosen_patchset_id` | PatchSet | 0..1 |
//! | ContextFrame | `run_id` | Run | 0..1 |
//! | ContextFrame | `plan_id` | Plan | 0..1 |
//! | ContextFrame | `step_id` | PlanStep.step_id | 0..1 |
//!
pub mod blob;
pub mod commit;
pub mod context;
pub mod context_frame;
pub mod decision;
pub mod evidence;
pub mod integrity;
pub mod intent;
pub mod intent_event;
pub mod note;
pub mod patchset;
pub mod plan;
pub mod plan_step_event;
pub mod provenance;
pub mod run;
pub mod run_event;
pub mod run_usage;
pub mod signature;
pub mod tag;
pub mod task;
pub mod task_event;
pub mod tool;
pub mod tree;
pub mod types;
pub mod utils;

use std::{
    fmt::Display,
    io::{BufRead, Read},
};

use crate::{
    errors::GitError,
    hash::{HashError, HashKind, ObjectHash, get_hash_kind},
    internal::{object::types::ObjectType, zlib::stream::inflate::ReadBoxed},
};

/// **The Object Trait**
/// Defines the common interface for all Git object types, including blobs, trees, commits, and tags.
///
/// # Repository hash context
///
/// Object IDs depend on the repository's [`HashKind`]. Every implementor
/// (standard Git objects and AI objects alike) gets two explicit-kind entry
/// points for free from the default methods:
///
/// * [`ObjectTrait::from_buf_read_with_kind`] — load an object from a
///   [`ReadBoxed`] created for that kind and fail closed if the reader's hasher
///   belongs to another kind;
/// * [`ObjectTrait::object_hash_for_kind`] — compute the canonical object ID
///   for an explicit kind.
///
/// The parameterless [`ObjectTrait::from_buf_read`] and
/// [`ObjectTrait::object_hash`] keep the thread-local behaviour for the
/// established single-repository workflow (GC-06); code that may run on a
/// thread configured for another repository must pass the kind explicitly.
pub trait ObjectTrait: Send + Sync + Display {
    /// Creates a new object from a byte slice.
    fn from_bytes(data: &[u8], hash: ObjectHash) -> Result<Self, GitError>
    where
        Self: Sized;

    /// Generate a new Object from a `ReadBoxed<BufRead>` whose hasher was created
    /// for `kind` (see [`ReadBoxed::new_with_kind`]).
    ///
    /// `size` is only a capacity hint for the content buffer. The object ID is
    /// finalized from the reader's own hasher; if that hasher belongs to a
    /// different [`HashKind`] than `kind`, the call fails closed with a
    /// [`HashError::KindMismatch`] wrapped in [`GitError::InvalidHashValue`]
    /// instead of mislabelling the digest.
    fn from_buf_read_with_kind<R: BufRead>(
        read: &mut ReadBoxed<R>,
        size: usize,
        kind: HashKind,
    ) -> Result<Self, GitError>
    where
        Self: Sized,
    {
        let mut content: Vec<u8> = Vec::with_capacity(size);
        read.read_to_end(&mut content)?;
        let hasher = read.hash.clone();
        let actual = hasher.kind();
        if actual != kind {
            return Err(HashError::KindMismatch {
                operation: "from_buf_read_with_kind",
                expected: kind,
                actual,
                expected_len: kind.size(),
                actual_len: actual.size(),
            }
            .into());
        }
        let hash = hasher.finalize_object_hash();
        Self::from_bytes(&content, hash)
    }

    /// Generate a new Object from a `ReadBoxed<BufRead>`.
    /// the input size,is only for new a vec with directive space allocation
    /// the input data stream and output object should be plain base object .
    ///
    /// Compatibility wrapper around [`ObjectTrait::from_buf_read_with_kind`]
    /// using the thread-local [`HashKind`]. It keeps the pre-existing contract
    /// of this signature: any failure (I/O, parse, or a reader whose hasher
    /// does not match the thread-local kind — formerly an "Invalid byte
    /// length" panic) is a panic. New code should call the explicit-kind
    /// variant and handle the error.
    fn from_buf_read<R: BufRead>(read: &mut ReadBoxed<R>, size: usize) -> Self
    where
        Self: Sized,
    {
        Self::from_buf_read_with_kind(read, size, get_hash_kind()).unwrap()
    }

    /// Returns the type of the object.
    fn get_type(&self) -> ObjectType;

    fn get_size(&self) -> usize;

    fn to_data(&self) -> Result<Vec<u8>, GitError>;

    /// Canonical object ID of this object for an explicit repository `kind`.
    ///
    /// Does not consult the thread-local [`HashKind`].
    fn object_hash_for_kind(&self, kind: HashKind) -> Result<ObjectHash, GitError> {
        let data = self.to_data()?;
        Ok(ObjectHash::from_type_and_data_for_kind(
            kind,
            self.get_type(),
            &data,
        )?)
    }

    /// Canonical object ID of this object using the thread-local [`HashKind`].
    ///
    /// Compatibility wrapper around [`ObjectTrait::object_hash_for_kind`].
    fn object_hash(&self) -> Result<ObjectHash, GitError> {
        self.object_hash_for_kind(get_hash_kind())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write};

    use flate2::{Compression, write::ZlibEncoder};

    use super::*;
    use crate::{
        hash::set_hash_kind_for_test,
        internal::object::{
            blob::Blob,
            commit::Commit,
            note::Note,
            provenance::Provenance,
            signature::{Signature, SignatureType},
            tag::Tag,
            tree::{Tree, TreeItem, TreeItemMode},
            types::{ActorKind, ActorRef},
        },
    };

    /// (kind under test, "other" thread-local kind). The SHA-256/BLAKE3 pairs share the
    /// same 32-byte width, so they prove the kind is carried as metadata, not inferred.
    const KINDS: [(HashKind, HashKind); 4] = [
        (HashKind::Sha1, HashKind::Sha256),
        (HashKind::Sha256, HashKind::Sha1),
        (HashKind::Blake3, HashKind::Sha256),
        (HashKind::Sha256, HashKind::Blake3),
    ];
    const HELLO: &[u8] = b"Hello, world!";
    const HELLO_BLOB_SHA1: &str = "5dd01c177f5d7d1be5346a5bc18a569a7410c2ef";
    const HELLO_BLOB_SHA256: &str =
        "178b5fbed164aee269fee7323badf7269cca0eed0875717b0d2d4f9819164c3f";

    fn zlib(data: &[u8]) -> Vec<u8> {
        let mut enc = ZlibEncoder::new(Vec::new(), Compression::default());
        enc.write_all(data).unwrap();
        enc.finish().unwrap()
    }

    fn signature(role: SignatureType) -> Signature {
        Signature::new(role, "tester".to_string(), "tester@example.com".to_string())
    }

    /// `object_hash_for_kind` and `from_buf_read_with_kind` follow the explicit kind for
    /// standard and AI objects alike, regardless of the thread-local kind.
    #[test]
    fn object_hash_context_explicit_kind_ignores_thread_local() {
        for (kind, other) in KINDS {
            let _guard = set_hash_kind_for_test(other);

            // Standard object: explicit kind wins, thread-local wrapper follows `other`.
            let blob = Blob::from_content_bytes_with_kind(kind, HELLO.to_vec()).unwrap();
            assert_eq!(blob.id.kind(), kind);
            assert_eq!(blob.object_hash_for_kind(kind).unwrap(), blob.id);
            let via_thread_local = blob.object_hash().unwrap();
            assert_eq!(via_thread_local.kind(), other);
            assert_ne!(via_thread_local, blob.id);

            // AI object: default trait method is kind-aware too.
            let actor = ActorRef::new(ActorKind::Agent, "agent-1").unwrap();
            let provenance =
                Provenance::new(actor, uuid::Uuid::now_v7(), "provider", "model").unwrap();
            assert_eq!(provenance.object_hash_for_kind(kind).unwrap().kind(), kind);
            assert_eq!(
                provenance.object_hash_for_kind(other).unwrap().kind(),
                other
            );
            assert_eq!(provenance.object_hash().unwrap().kind(), other);

            // Loader: reader created for `kind` yields the same ID as the constructor.
            let compressed = zlib(HELLO);
            let mut reader = ReadBoxed::new_with_kind(
                io::Cursor::new(&compressed),
                ObjectType::Blob,
                HELLO.len(),
                kind,
            )
            .unwrap();
            let loaded = Blob::from_buf_read_with_kind(&mut reader, HELLO.len(), kind).unwrap();
            assert_eq!(loaded.id, blob.id);
            assert_eq!(loaded.data, HELLO);

            // Loader: a tree with `kind`-width entries loads under the other thread-local kind
            // (entry slicing follows the loaded hash's kind, not the thread-local one).
            let tree = Tree::from_tree_items_with_kind(
                kind,
                vec![TreeItem::new(
                    TreeItemMode::Blob,
                    blob.id,
                    "hello.txt".to_string(),
                )],
            )
            .unwrap();
            let tree_bytes = tree.to_data().unwrap();
            let mut reader = ReadBoxed::new_with_kind(
                io::Cursor::new(zlib(&tree_bytes)),
                ObjectType::Tree,
                tree_bytes.len(),
                kind,
            )
            .unwrap();
            let loaded_tree =
                Tree::from_buf_read_with_kind(&mut reader, tree_bytes.len(), kind).unwrap();
            assert_eq!(loaded_tree.id, tree.id);
            assert_eq!(loaded_tree.tree_items, tree.tree_items);
            assert_eq!(loaded_tree.tree_items[0].id.kind(), kind);

            // Loader: asking for a different kind than the reader's hasher fails closed.
            let mut reader = ReadBoxed::new_with_kind(
                io::Cursor::new(&compressed),
                ObjectType::Blob,
                HELLO.len(),
                kind,
            )
            .unwrap();
            let err = Blob::from_buf_read_with_kind(&mut reader, HELLO.len(), other).unwrap_err();
            match err {
                GitError::InvalidHashValue(msg) => {
                    assert!(msg.contains("from_buf_read_with_kind"), "{msg}");
                    assert!(
                        msg.contains(kind.as_str()) && msg.contains(other.as_str()),
                        "{msg}"
                    );
                }
                other_err => panic!("unexpected error: {other_err:?}"),
            }
        }
    }

    /// Delta object types have no loose-object header: the explicit loader fails closed
    /// with the full diagnostic (operation, kind, expected/actual lengths).
    #[test]
    fn object_hash_context_rejects_delta_reader() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let err = ReadBoxed::new_with_kind(
            io::Cursor::new(Vec::new()),
            ObjectType::OffsetDelta,
            7,
            HashKind::Sha256,
        )
        .err()
        .expect("delta type must be rejected");
        match err {
            GitError::InvalidHashValue(msg) => {
                assert!(msg.contains("ReadBoxed::new_with_kind"), "{msg}");
                assert!(
                    msg.contains("sha256") && msg.contains("OffsetDelta"),
                    "{msg}"
                );
                assert!(
                    msg.contains("32") && msg.contains("payload 7 bytes"),
                    "{msg}"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    /// Blob IDs for an explicit kind match the known SHA-1/SHA-256 vectors.
    #[test]
    fn blob_hash_for_kind_known_vectors() {
        for (kind, other, expected) in [
            (HashKind::Sha1, HashKind::Sha256, HELLO_BLOB_SHA1),
            (HashKind::Sha256, HashKind::Sha1, HELLO_BLOB_SHA256),
        ] {
            let _guard = set_hash_kind_for_test(other);
            let from_bytes = Blob::from_content_bytes_with_kind(kind, HELLO.to_vec()).unwrap();
            let from_str = Blob::from_content_with_kind(kind, "Hello, world!").unwrap();
            assert_eq!(from_bytes.id.to_string(), expected);
            assert_eq!(from_str.id, from_bytes.id);
            assert_eq!(from_bytes.id.kind(), kind);
            {
                let _same = set_hash_kind_for_test(kind);
                assert_eq!(Blob::from_content_bytes(HELLO.to_vec()).id, from_bytes.id);
            }
        }
    }

    /// Derived-ID constructors (tree, commit, tag, note) compute IDs for the explicit kind
    /// and agree with `ObjectHash::from_type_and_data_for_kind`.
    #[test]
    fn derived_id_for_kind_matches_explicit_hash() {
        for (kind, other) in KINDS {
            let _guard = set_hash_kind_for_test(other);

            let blob = Blob::from_content_bytes_with_kind(kind, HELLO.to_vec()).unwrap();
            let item = TreeItem::new(TreeItemMode::Blob, blob.id, "hello.txt".to_string());
            let mut tree = Tree::from_tree_items_with_kind(kind, vec![item]).unwrap();
            assert_eq!(tree.id.kind(), kind);
            assert_eq!(
                tree.id,
                ObjectHash::from_type_and_data_for_kind(
                    kind,
                    ObjectType::Tree,
                    &tree.to_data().unwrap()
                )
                .unwrap()
            );
            let before = tree.id;
            tree.tree_items.push(TreeItem::new(
                TreeItemMode::Blob,
                blob.id,
                "again.txt".to_string(),
            ));
            tree.rehash_with_kind(kind).unwrap();
            assert_ne!(tree.id, before);
            assert_eq!(tree.id.kind(), kind);
            assert_eq!(tree.object_hash_for_kind(kind).unwrap(), tree.id);

            let commit = Commit::new_with_kind(
                kind,
                signature(SignatureType::Author),
                signature(SignatureType::Committer),
                tree.id,
                vec![],
                "initial",
            )
            .unwrap();
            assert_eq!(commit.id.kind(), kind);
            assert_eq!(commit.object_hash_for_kind(kind).unwrap(), commit.id);
            let child =
                Commit::from_tree_id_with_kind(kind, tree.id, vec![commit.id], "child").unwrap();
            assert_eq!(child.id.kind(), kind);
            assert_eq!(child.parent_commit_ids, vec![commit.id]);
            assert_eq!(child.object_hash_for_kind(kind).unwrap(), child.id);

            let tag = Tag::new_with_kind(
                kind,
                commit.id,
                ObjectType::Commit,
                "v1".to_string(),
                signature(SignatureType::Tagger),
                "release".to_string(),
            )
            .unwrap();
            assert_eq!(tag.id.kind(), kind);
            assert_eq!(tag.object_hash_for_kind(kind).unwrap(), tag.id);

            let note = Note::new_with_kind(kind, commit.id, "note body".to_string()).unwrap();
            assert_eq!(note.id.kind(), kind);
            assert_eq!(note.target_object_id, commit.id);
            assert_eq!(note.object_hash_for_kind(kind).unwrap(), note.id);
            let placeholder = Note::from_content_with_kind(kind, "note body").unwrap();
            assert_eq!(placeholder.id, note.id);
            assert_eq!(
                placeholder.target_object_id,
                ObjectHash::zero_for_kind(kind)
            );
            assert_eq!(placeholder.target_object_id.kind(), kind);
        }
    }

    /// Cross-kind references are rejected instead of being silently embedded — including the
    /// same-width SHA-256/BLAKE3 pair.
    #[test]
    fn derived_id_for_kind_rejects_cross_kind_references() {
        for (own, foreign) in [
            (HashKind::Sha1, HashKind::Sha256),
            (HashKind::Sha256, HashKind::Blake3),
            (HashKind::Blake3, HashKind::Sha256),
        ] {
            reject_cross_kind_references(own, foreign);
        }
    }

    fn reject_cross_kind_references(own: HashKind, foreign: HashKind) {
        let _guard = set_hash_kind_for_test(own);
        let sha1_blob = Blob::from_content_bytes_with_kind(own, HELLO.to_vec()).unwrap();
        let sha256_blob = Blob::from_content_bytes_with_kind(foreign, HELLO.to_vec()).unwrap();
        assert_eq!(sha1_blob.id.kind(), own);
        assert_eq!(sha256_blob.id.kind(), foreign);

        let is_kind_mismatch = |err: GitError| match err {
            GitError::InvalidHashValue(msg) => msg.contains("hash kind mismatch"),
            _ => false,
        };

        let item = TreeItem::new(TreeItemMode::Blob, sha256_blob.id, "x".to_string());
        assert!(is_kind_mismatch(
            Tree::from_tree_items_with_kind(own, vec![item]).unwrap_err()
        ));
        let mut tree = Tree::from_tree_items_with_kind(
            own,
            vec![TreeItem::new(
                TreeItemMode::Blob,
                sha1_blob.id,
                "x".to_string(),
            )],
        )
        .unwrap();
        tree.tree_items[0].id = sha256_blob.id;
        assert!(is_kind_mismatch(tree.rehash_with_kind(own).unwrap_err()));

        assert!(is_kind_mismatch(
            Commit::from_tree_id_with_kind(own, sha256_blob.id, vec![], "m").unwrap_err()
        ));
        assert!(is_kind_mismatch(
            Commit::from_tree_id_with_kind(own, sha1_blob.id, vec![sha256_blob.id], "m")
                .unwrap_err()
        ));
        assert!(is_kind_mismatch(
            Tag::new_with_kind(
                own,
                sha256_blob.id,
                ObjectType::Blob,
                "t".to_string(),
                signature(SignatureType::Tagger),
                "m".to_string(),
            )
            .unwrap_err()
        ));
        assert!(is_kind_mismatch(
            Note::new_with_kind(own, sha256_blob.id, "n".to_string()).unwrap_err()
        ));
    }

    /// Commit/Tag/Note reference parsing follows the loaded object's own hash kind
    /// (40 or 64 hex) regardless of the thread-local kind.
    #[test]
    fn reference_parse_context_follows_hash_kind() {
        for (kind, other) in KINDS {
            let _guard = set_hash_kind_for_test(other);

            let blob = Blob::from_content_bytes_with_kind(kind, HELLO.to_vec()).unwrap();
            let tree = Tree::from_tree_items_with_kind(
                kind,
                vec![TreeItem::new(
                    TreeItemMode::Blob,
                    blob.id,
                    "hello.txt".to_string(),
                )],
            )
            .unwrap();
            let root = Commit::from_tree_id_with_kind(kind, tree.id, vec![], "root").unwrap();
            let child = Commit::new_with_kind(
                kind,
                signature(SignatureType::Author),
                signature(SignatureType::Committer),
                tree.id,
                vec![root.id, root.id],
                "child\n\nbody",
            )
            .unwrap();

            let parsed = Commit::from_bytes(&child.to_data().unwrap(), child.id).unwrap();
            assert_eq!(parsed.tree_id, tree.id);
            assert_eq!(parsed.tree_id.kind(), kind);
            assert_eq!(parsed.parent_commit_ids, vec![root.id, root.id]);
            assert!(parsed.parent_commit_ids.iter().all(|p| p.kind() == kind));
            assert_eq!(parsed.message, "child\n\nbody");
            assert_eq!(parsed.to_data().unwrap(), child.to_data().unwrap());

            let tag = Tag::new_with_kind(
                kind,
                child.id,
                ObjectType::Commit,
                "v1".to_string(),
                signature(SignatureType::Tagger),
                "release".to_string(),
            )
            .unwrap();
            let parsed = Tag::from_bytes(&tag.to_data().unwrap(), tag.id).unwrap();
            assert_eq!(parsed.object_hash, child.id);
            assert_eq!(parsed.object_hash.kind(), kind);

            let note = Note::new_with_kind(kind, child.id, "annotation".to_string()).unwrap();
            let parsed = Note::from_bytes(&note.to_data().unwrap(), note.id).unwrap();
            assert_eq!(parsed.target_object_id, ObjectHash::zero_for_kind(kind));
            assert_eq!(parsed.target_object_id.kind(), kind);
            assert_eq!(parsed.content, "annotation");
        }
    }

    /// References of the wrong width, non-hex references and truncated bodies fail closed
    /// (no silent SHA-1 fallback, no panic).
    #[test]
    fn reference_parse_context_rejects_cross_kind_and_malformed() {
        let _guard = set_hash_kind_for_test(HashKind::Sha1);
        let sha1_id = ObjectHash::new_for_kind(HashKind::Sha1, b"x");
        let sha256_id = ObjectHash::new_for_kind(HashKind::Sha256, b"x");
        let author = signature(SignatureType::Author).to_data().unwrap();
        let committer = signature(SignatureType::Committer).to_data().unwrap();
        let body = |tree: &str, parent: Option<&str>| {
            let mut v = format!("tree {tree}\n").into_bytes();
            if let Some(p) = parent {
                v.extend(format!("parent {p}\n").into_bytes());
            }
            v.extend(&author);
            v.push(b'\n');
            v.extend(&committer);
            v.extend(b"\nmsg");
            v
        };
        let hash_msg = |err: GitError| match err {
            GitError::InvalidHashValue(msg) => msg,
            other => panic!("expected InvalidHashValue, got {other:?}"),
        };

        // 40-hex tree inside a SHA-256 commit: not guessed as SHA-1.
        let msg =
            hash_msg(Commit::from_bytes(&body(&sha1_id.to_string(), None), sha256_id).unwrap_err());
        assert!(msg.contains("tree") && msg.contains("sha256"), "{msg}");
        assert!(
            msg.contains("expected 64") && msg.contains("got 40"),
            "{msg}"
        );

        // 64-hex parent inside a SHA-1 commit: not guessed as SHA-256.
        let msg = hash_msg(
            Commit::from_bytes(
                &body(&sha1_id.to_string(), Some(&sha256_id.to_string())),
                sha1_id,
            )
            .unwrap_err(),
        );
        assert!(
            msg.contains("parent") && msg.contains("expected 40") && msg.contains("got 64"),
            "{msg}"
        );

        // Non-hex tree of the right length.
        let msg = hash_msg(Commit::from_bytes(&body(&"zz".repeat(20), None), sha1_id).unwrap_err());
        assert!(msg.contains("tree") && msg.contains("hex"), "{msg}");

        // Truncated / structurally broken bodies: errors, never panics.
        assert!(matches!(
            Commit::from_bytes(b"tree abc", sha1_id),
            Err(GitError::InvalidCommitObject)
        ));
        assert!(matches!(
            Commit::from_bytes(format!("tree {sha1_id}\n").as_bytes(), sha1_id),
            Err(GitError::InvalidCommitObject)
        ));
        assert!(matches!(
            Commit::from_bytes(format!("blob {sha1_id}\n").as_bytes(), sha1_id),
            Err(GitError::InvalidCommitObject)
        ));
        let mut no_committer = format!("tree {sha1_id}\n").into_bytes();
        no_committer.extend(&author);
        assert!(matches!(
            Commit::from_bytes(&no_committer, sha1_id),
            Err(GitError::InvalidCommitObject)
        ));

        // Malformed author/committer lines: signature parsing fails closed (no panic).
        for bad_sig in [
            "author",
            "author name-without-email 1 +0000",
            "author name <mail 1 +0000",
            "author name <mail>",
            "author name <mail> notanumber +0000",
            "author name <mail> 1",
            "author name <mail> 1 ",
            "author name <mail>1 +0000",
            "author name <mail>x1 +0000",
            "author name <mail> 1 +08 00",
            "author name<mail> 1 +0000",
            "author name <mail> 1 garbage",
            "author name <mail> 1 0800",
            "author name <mail> 1 +12345",
            "author name <mail> 1 +0a00",
            "committer name <mail> 1 +0000",
            "xauthor name <mail> 1 +0000",
            "encoding utf-8",
        ] {
            let mut body = format!("tree {sha1_id}\n{bad_sig}\n").into_bytes();
            body.extend(&committer);
            body.extend(b"\nmsg");
            match Commit::from_bytes(&body, sha1_id) {
                Err(GitError::InvalidSignatureType(_)) | Err(GitError::InvalidCommitObject) => {}
                Err(GitError::ConversionError(_)) => {}
                other => panic!("expected a parse error for {bad_sig:?}, got {other:?}"),
            }
        }
        // Edge cases that must parse: empty name, and a body whose author line is preceded
        // by parents only.
        let mut empty_name = format!("tree {sha1_id}\nauthor <mail> 1 +0000\n").into_bytes();
        empty_name.extend(&committer);
        empty_name.extend(b"\nmsg");
        let parsed = Commit::from_bytes(&empty_name, sha1_id).unwrap();
        assert_eq!(parsed.author.name, "");
        assert_eq!(parsed.author.email, "mail");
        assert_eq!(parsed.author.timestamp, 1);
        assert_eq!(parsed.author.timezone, "+0000");
        let mut negative_tz = format!("tree {sha1_id}\nauthor a b <m> 7 -0530\n").into_bytes();
        negative_tz.extend(&committer);
        negative_tz.extend(b"\nmsg");
        let parsed = Commit::from_bytes(&negative_tz, sha1_id).unwrap();
        assert_eq!(parsed.author.name, "a b");
        assert_eq!(parsed.author.timezone, "-0530");
        // `committer` line must follow `author` directly.
        let mut two_authors = format!("tree {sha1_id}\n").into_bytes();
        two_authors.extend(&author);
        two_authors.push(b'\n');
        two_authors.extend(&author);
        two_authors.extend(b"\nmsg");
        assert!(matches!(
            Commit::from_bytes(&two_authors, sha1_id),
            Err(GitError::InvalidCommitObject)
        ));
        let mut non_utf8 = format!("tree {sha1_id}\nauthor ").into_bytes();
        non_utf8.extend_from_slice(&[0xff, 0xfe]);
        non_utf8.extend(b" <m> 1 +0000\n");
        non_utf8.extend(&committer);
        non_utf8.extend(b"\nmsg");
        assert!(matches!(
            Commit::from_bytes(&non_utf8, sha1_id),
            Err(GitError::InvalidSignatureType(_))
        ));

        // Tag object reference of the wrong width for the tag's kind.
        let tag_body = format!(
            "object {sha1_id}\ntype commit\ntag v1\n{}\n\nmsg",
            String::from_utf8(signature(SignatureType::Tagger).to_data().unwrap()).unwrap()
        );
        match Tag::from_bytes(tag_body.as_bytes(), sha256_id) {
            Err(GitError::InvalidTagObject(msg)) => {
                assert!(
                    msg.contains("sha256") && msg.contains("expected 64"),
                    "{msg}"
                )
            }
            other => panic!("expected InvalidTagObject, got {other:?}"),
        }
        // Non-UTF-8 object id: diagnostic carries kind and expected/actual lengths.
        let mut raw_tag = b"object ".to_vec();
        raw_tag.extend_from_slice(&[0xffu8; 40]);
        raw_tag.extend(b"\ntype commit\ntag v1\n");
        match Tag::from_bytes(&raw_tag, sha1_id) {
            Err(GitError::InvalidTagObject(msg)) => {
                assert!(
                    msg.contains("sha1")
                        && msg.contains("expected 40")
                        && msg.contains("got 40 bytes"),
                    "{msg}"
                )
            }
            other => panic!("expected InvalidTagObject, got {other:?}"),
        }
    }
}
