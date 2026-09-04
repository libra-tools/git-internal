# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.9.0] - 2026-09-04

BLAKE3-256 object IDs as a git-internal / Libra extension, with an explicit-kind
API and fully cross-verified pack/idx/protocol integrity. This is a `0.x`
**breaking minor** (ADR-GI-B3-06): see the migration note below.

### Added

- `HashKind::Blake3` (`as_str() == "blake3"`, `is_git_standard() == false`),
  `ObjectHash::Blake3` and `HashAlgorithm::Blake3` (32-byte / 64-hex digests).
  BLAKE3 is a separate object namespace that is never inferred from an ID's
  width: the explicit-kind API and `blake3:HEX` tags name it directly, and the
  thread-local constructors (`ObjectHash::new`, `from_bytes`, …) produce it
  only when `set_hash_kind(HashKind::Blake3)` is in effect; `from_str` never
  does (see the migration note).
- Explicit-kind ("context") API that never reads the thread-local kind:
  `ObjectHash::{from_hex_for_kind, from_bytes_for_kind, from_stream_for_kind,
  new_for_kind, from_type_and_data_for_kind, zero_for_kind, ensure_kind,
  to_tagged_string, from_tagged_str}`, `HashAlgorithm::new_for_kind`,
  `HashError` (every variant names the failing operation and carries its own
  expected/actual diagnostics; `UnknownKind` reports the accepted tags),
  `From<HashError>` for `GitError` and `io::Error`.
- Object model: `Blob::from_content_with_kind`, `Tree::from_tree_items_with_kind`
  / `rehash_with_kind`, `TreeItem::from_bytes_with_kind`, `Commit::new_with_kind` /
  `from_tree_id_with_kind`, `Tag::new_with_kind`, `Note::new_with_kind` /
  `from_content_with_kind`, `ObjectTrait::from_buf_read_with_kind`;
  `Tree`/`Commit`/`Tag`/`Note` parsers derive the reference width from the
  object's own ID kind.
- Pack / idx / index: `Pack::new_with_hash_kind`, `PackEncoder::new_with_hash_kind`
  / `new_with_idx_and_hash_kind`, `encode_and_output_to_files_with_hash_kind`,
  `PackStats::analyze_with_hash_kind`, `pack_index::parse_idx_v2_from`,
  `Index::{from_file,to_file,load,save,refresh}_with_hash_kind`; cache spill
  paths are namespaced by kind.
- Smart protocol: `RepositoryAccess::object_hash_kind()` (default: thread-local),
  `object-format=blake3` advertisement/negotiation for BLAKE3 repositories,
  `SmartProtocol::ensure_hash_kind_consistency`, `PackGenerator::new_with_hash_kind`.
- Documentation: `docs/development/blake3-integration.md` (downstream handoff),
  compatibility matrix in `docs/ARCHITECTURE.md`, protocol contract in
  `docs/git-protocol-guide.md` §9.7.

### Changed

- Pack decoding cross-verifies every object against an existing `.idx` (name via
  streamed content hash, CRC over the encoded entry, real start offset), always
  rebuilds delta payloads, hashes the payload inline in the single decode pass,
  and treats a present-but-invalid `.idx` (including a dangling symlink) as an
  error instead of silently falling back to a scan.
- The shared idx v2 reader validates fanout, strictly ascending names, unique
  offsets, large-offset slots and both checksums, and bounds its preallocation.
- Smart protocol negotiation is fail-closed: an unknown, non-canonical or
  mismatching `object-format` is a `ProtocolError::InvalidRequest`; want/have,
  receive-pack command IDs and advertised refs must be raw lowercase hex of the
  wire kind; the repository/local/wire kind invariant is re-checked at every
  await and side-effect boundary.
- Pack streams returned by `SmartProtocol::git_upload_pack` and
  `PackGenerator::generate_{full,incremental}_pack` carry
  `Result<Vec<u8>, ProtocolError>` items so producer failures are reported
  instead of surfacing as a truncated pack; an empty incremental pack is a valid
  zero-object pack.
- `parse_capabilities`, `parse_ref_command` and `parse_receive_pack_commands`
  return `Result`.
- `Index::to_file_with_hash_kind` validates all entries before creating or
  truncating the destination; `refresh_with_hash_kind` rejects cross-kind entries.
- Test suite: the diff-versus-git tests compare by patch equivalence (applying
  the diff reproduces the new file) instead of textual edit-script identity,
  which differed from git 2.55 on ambiguous brace lines.

### Fixed

- `IdxBuilder` excluded the pack checksum from the idx checksum (readers, per
  Git, include it).
- idx CRC32 values produced by the encoder were computed over decompressed
  content instead of the encoded pack entry, so this crate's own `.idx` files
  failed its own CRC verification.
- Decoding a thin or malformed pack whose delta base never appears returns an
  error instead of panicking.
- `Signature` formatted negative half-hour time zones incorrectly.

### Known limitations

- The unified-diff writer does not emit `\ No newline at end of file` markers,
  so a change touching only a file's terminal newline is not representable
  (tracked as FIX-05 in the development plan).

### Deprecated

- `ObjectHash::from_bytes_infer_kind` (width inference can never distinguish
  SHA-256 from BLAKE3).

### Migration note (ADR-GI-B3-06)

- `HashKind`, `ObjectHash` and `HashAlgorithm` gained a `Blake3` variant and are
  not `#[non_exhaustive]`: exhaustive `match` expressions in downstream crates
  will fail to compile until a `Blake3` arm is added.
- `ObjectHash::from_str` infers the algorithm from the hex width and therefore
  returns `Sha256` for a BLAKE3 64-hex ID (`from_bytes_infer_kind` does the
  same for a raw 32-byte BLAKE3 digest); parse IDs
  with `from_hex_for_kind(repository_kind, …)` at every boundary that may serve
  more than one repository. Where a boundary accepts tagged IDs, follow
  `from_tagged_str` with `ensure_kind(repository_kind)`: the tag names the ID's
  own algorithm, not the repository's, so a cross-kind tagged ID must be
  rejected rather than parsed successfully. The thread-local constructors
  (`ObjectHash::new`/`from_bytes`/`from_stream`/`from_type_and_data`,
  `Blob::from_content`, …) keep working for single-repository flows.
- Implement `RepositoryAccess::object_hash_kind()` for repositories whose
  format is known; the smart protocol binds to it at construction.
- Consumers of the upload-pack stream must handle `Err` items.
- The AI `IntegrityHash` remains SHA-256 regardless of the repository kind.

## [0.8.6] - 2026-08-01

### Changed

- Removed unused direct dependencies `sea-orm`, `natord`, and `ring`.
- Package version bumped to `0.8.6`.

## [0.8.5] - 2026-07-31

### Changed

- Dependency upgrades (`bstr`, `futures`, `path-absolutize`, `uuid`, `tokio`,
  and related lockfile updates).

### Fixed

- Delta decoder returns errors for malformed streams instead of panicking;
  pack rebuild path propagates delta rebuild failures.

## [0.8.4] - 2026-07-25

### Fixed

- Pack encoding no longer panics with `Invalid byte length: got 32, expected 20`
  when finalizing a SHA-256 pack trailer on a thread whose thread-local
  `HashKind` was never set. `PackEncoder` finalizes its running checksum on
  whichever async worker thread happens to run the task; the previous
  `ObjectHash::from_bytes` call re-read the thread-local kind at finalize
  time and could disagree with the hasher chosen at encoder construction,
  which surfaced as flaky SHA-256 pack failures (affecting, for example,
  `libra bundle create` on SHA-256 repositories). Both the delta path
  (`encode/mod.rs`) and the non-delta parallel path (`encode/parallel.rs`)
  now infer the hash kind from the checksum byte length via the new
  `ObjectHash::from_bytes_infer_kind`, and propagate a `GitError` instead of
  unwrapping.

### Added

- `ObjectHash::from_bytes_infer_kind` — constructs an `ObjectHash` from raw
  bytes by inferring the hash kind from the byte length (20 → SHA-1,
  32 → SHA-256) instead of consulting the thread-local `HashKind`.
- Regression test
  `internal::pack::encode::tests::test_parallel_encode_trailer_ignores_thread_local_kind`,
  which drives a SHA-256 encoder on a fresh thread holding the default SHA-1
  thread-local kind.

### Changed

- Package `repository` metadata now points to
  <https://github.com/libra-tools/git-internal>.
- Resolved pre-existing clippy `-D warnings` debt so the lint gate passes
  again: `match` → `?` in `delta::decode`, and `iter()` → `values()` map
  iteration in `internal::index` (no behavior change).

## [0.8.3] - 2026-07-24

- Previous release; changes predate this changelog.
