//! Error types for the Git-Internal crate.
//!
//! This module defines a unified error enumeration used across object parsing,
//! pack encoding/decoding, index handling, caching, and streaming. It integrates
//! with `thiserror` to provide rich `Display` implementations and error source
//! chaining where applicable.
//!
//! Notes:
//! - Each variant carries contextual details via its message payload.
//! - Variants cover parse/validation, I/O, encoding/decoding, network/auth,
//!   and custom errors.

use thiserror::Error;

#[derive(Error, Debug)]
/// Unified error enumeration for the Git-Internal library.
///
/// - Used across object parsing, pack encode/decode, index, caching and streams.
/// - Implements `std::error::Error` via `thiserror`.
pub enum GitError {
    /// Invalid or unsupported git object type name.
    #[error("The `{0}` is not a valid git object type.")]
    InvalidObjectType(String),

    /// Malformed or unsupported blob object encoding.
    #[error("The `{0}` is not a valid git blob object.")]
    InvalidBlobObject(String),

    /// Malformed tree object.
    #[error("Not a valid git tree object.")]
    InvalidTreeObject,

    /// Invalid tree entry (mode/name/hash).
    #[error("The `{0}` is not a valid git tree item.")]
    InvalidTreeItem(String),

    /// Tree contains no entries.
    #[error("`{0}`.")]
    EmptyTreeItems(String),

    /// Invalid commit signature type.
    #[error("The `{0}` is not a valid git commit signature.")]
    InvalidSignatureType(String),

    /// Malformed commit object.
    #[error("Not a valid git commit object.")]
    InvalidCommitObject,

    /// Commit parse or validation failed.
    #[error("Invalid Commit: {0}")]
    InvalidCommit(String),

    /// Malformed tag object.
    #[error("Not a valid git tag object: {0}")]
    InvalidTagObject(String),

    /// Malformed note object.
    #[error("Not a valid git note object: {0}")]
    InvalidNoteObject(String),

    /// Malformed context snapshot object.
    #[error("Not a valid agent context snapshot object: {0}")]
    InvalidContextSnapshotObject(String),

    /// Malformed decision object.
    #[error("Not a valid agent decision object: {0}")]
    InvalidDecisionObject(String),

    /// Malformed evidence object.
    #[error("Not a valid agent evidence object: {0}")]
    InvalidEvidenceObject(String),

    /// Malformed patch set object.
    #[error("Not a valid agent patch set object: {0}")]
    InvalidPatchSetObject(String),

    /// Malformed plan object.
    #[error("Not a valid agent plan object: {0}")]
    InvalidPlanObject(String),

    /// Malformed provenance object.
    #[error("Not a valid agent provenance object: {0}")]
    InvalidProvenanceObject(String),

    /// Malformed run object.
    #[error("Not a valid agent run object: {0}")]
    InvalidRunObject(String),

    /// Malformed task object.
    #[error("Not a valid agent task object: {0}")]
    InvalidTaskObject(String),

    /// Malformed intent object.
    #[error("Not a valid agent intent object: {0}")]
    InvalidIntentObject(String),

    /// Malformed tool invocation object.
    #[error("Not a valid agent tool invocation object: {0}")]
    InvalidToolInvocationObject(String),

    /// Malformed context frame object.
    #[error("Not a valid agent context frame object: {0}")]
    InvalidContextFrameObject(String),

    /// Malformed or unsupported index (.idx) file.
    #[error("The `{0}` is not a valid idx file.")]
    InvalidIdxFile(String),

    /// Malformed or unsupported pack file.
    #[error("The `{0}` is not a valid pack file.")]
    InvalidPackFile(String),

    /// Invalid pack header magic or version.
    #[error("The `{0}` is not a valid pack header.")]
    InvalidPackHeader(String),

    /// Malformed or unsupported git index file.
    #[error("The `{0}` is not a valid index file.")]
    InvalidIndexFile(String),

    /// Invalid git index header.
    #[error("The `{0}` is not a valid index header.")]
    InvalidIndexHeader(String),

    /// Invalid CLI or function argument.
    #[error("Argument parse failed: {0}")]
    InvalidArgument(String),

    /// I/O error from underlying reader or writer.
    #[error("IO Error: {0}")]
    IOError(#[from] std::io::Error),

    /// Invalid SHA1/SHA256 hash formatting or value.
    #[error("The {0} is not a valid Hash value ")]
    InvalidHashValue(String),

    /// Delta object reconstruction error.
    #[error("Delta Object Error Info:{0}")]
    DeltaObjectError(String),

    /// Object not fully populated for packing.
    #[error("The object to be packed is incomplete ,{0}")]
    UnCompletedPackObject(String),

    /// Invalid decoded object info.
    #[error("Error decode in the Object ,info:{0}")]
    InvalidObjectInfo(String),

    /// Hash not found in current file context.
    #[error("Cannot find Hash value: {0} from current file")]
    NotFoundHashValue(String),

    /// Failed to encode object to bytes.
    #[error("Can't encode the object which id [{0}] to bytes")]
    EncodeObjectError(String),

    /// Text encoding or UTF-8 conversion error.
    #[error("UTF-8 conversion error: {0}")]
    ConversionError(String),

    /// Invalid path when locating parent tree.
    #[error("Can't find parent tree by path: {0}")]
    InvalidPathError(String),

    /// Failed to encode pack entries.
    #[error("Can't encode entries to pack: {0}")]
    PackEncodeError(String),

    /// Object missing from caches or storage.
    #[error("Can't find specific object: {0}")]
    ObjectNotFound(String),

    /// Repository not found.
    #[error("Repository not found")]
    RepoNotFound,

    /// Unauthorized access.
    #[error("UnAuthorized: {0}")]
    UnAuthorized(String),

    /// Network communication error.
    #[error("Network Error: {0}")]
    NetworkError(String),

    /// Generic custom error for miscellaneous failures.
    #[error("{0}")]
    CustomError(String),
}

impl From<crate::hash::HashError> for GitError {
    /// Explicit-kind hash failures (length / hex / kind mismatch, unsupported
    /// object type, short stream) surface as [`GitError::InvalidHashValue`],
    /// keeping the full diagnostic text of the [`crate::hash::HashError`].
    fn from(err: crate::hash::HashError) -> Self {
        GitError::InvalidHashValue(err.to_string())
    }
}
