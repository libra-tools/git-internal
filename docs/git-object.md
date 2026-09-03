# Git Object Reference

This document summarizes the object formats supported by git-internal, how IDs are hashed, and how they map to canonical Git formats, based on the implementations in `internal/object`.

## Common Format and Hashing

- Storage format: `<type> <size>\0<raw-bytes>`, where `type` is `blob/tree/commit/tag` and `size` is the raw data length (decimal string).
- Hashing: `ObjectHash::from_type_and_data_for_kind(HashKind, ObjectType, data)` produces an ID for an explicit repository hash kind (SHA-1, SHA-256, or BLAKE3-256) and fails closed (`HashError`) for delta types; `ObjectHash::from_type_and_data(ObjectType, data)` is the thread-local wrapper (switch via `set_hash_kind` / `set_hash_kind_for_test`).
- Hash kinds and compatibility: `HashKind::Sha1` (20 bytes / 40 hex) and `HashKind::Sha256` (32 bytes / 64 hex) are the standard Git object formats. `HashKind::Blake3` (32 bytes / 64 hex, `as_str() == "blake3"`, `is_git_standard() == false`) is a git-internal / Libra **extension**: a BLAKE3 repository is a separate object namespace, existing SHA-1/SHA-256 repositories are never converted in place, and unmodified standard Git cannot read or exchange BLAKE3 objects. Because SHA-256 and BLAKE3 IDs share the same width, a raw 64-hex / 32-byte value is only meaningful inside a known repository kind: use `from_hex_for_kind` / `from_bytes_for_kind` / `from_stream_for_kind`, or the tagged form `sha1:HEX` / `sha256:HEX` / `blake3:HEX` (`to_tagged_string` / `from_tagged_str`) when an ID leaves its repository (APIs, indexes, logs). The legacy `ObjectHash::from_str` (40 → SHA-1, 64 → SHA-256) and `from_bytes_infer_kind` (20 → SHA-1, 32 → SHA-256) never produce BLAKE3. `ObjectHash::Sha256` and `ObjectHash::Blake3` with identical bytes are distinct values (`ensure_kind` rejects the other kind). BLAKE3 only changes the repository object ID: the AI `IntegrityHash` stays SHA-256 under every repository kind, and application-level digests are untouched.
- Repository hash context: the thread-local kind is only a compatibility default for the single-repository workflow. Code that may run on a worker thread, async task, cache or protocol callback belonging to another repository must use the explicit-kind API: `ObjectTrait::object_hash_for_kind(kind)`, `ObjectTrait::from_buf_read_with_kind(reader, size, kind)` (with `ReadBoxed::new_with_kind`), and the `*_with_kind` constructors listed per object below. The `*_with_kind` constructors, `ReadBoxed::new_with_kind` and `object_hash_for_kind` return `Result<_, GitError>` and never panic, and they reject references whose `ObjectHash` belongs to another kind (`GitError::InvalidHashValue` with a `hash kind mismatch` message). `from_buf_read_with_kind` finalizes the ID without panicking and then delegates to the type's `from_bytes`: `Tree::from_bytes` slices entry IDs with the width of the hash it is given (`hash.kind()`) and fails closed on malformed entries, so trees load correctly for any repository kind on any thread; `Commit::from_bytes` and `Tag::from_bytes` parse their `tree`/`parent`/`object` references as IDs of `hash.kind()` (a 64-hex reference is never guessed to be SHA-256 by length) and return errors — never panic — on wrong-width, non-hex, non-UTF-8 or truncated references and on malformed `author`/`committer`/`tagger` signature lines (`Signature::from_data` is fail-closed). `Commit::from_bytes` additionally rejects any header line other than `parent`/`author`/`committer` in its header block, while `Tag::from_bytes` keeps its legacy tolerance of ignoring unknown header lines (it only errors on missing required fields); the commit message bytes after the `committer` line are still taken as-is (legacy behaviour). `Note::from_bytes` fills its placeholder target with `ObjectHash::zero_for_kind(hash.kind())`.
- Types: `ObjectType` offers `to_string`/`to_u8`/`from_u8`/`from_string`, covering base objects (Commit/Tree/Blob/Tag) and delta objects (OffsetDelta/HashDelta/OffsetZstdDelta—extension).
- Serialization: Each object’s `to_data` returns `<type><size>\0<body>`; `ObjectHash::to_string()` emits hex, `to_data()` returns raw bytes.

## Blob

- Location: `object/blob.rs`.
- Meaning: File content snapshot, no path/permission (those live in Tree).
- Structure: `Blob { id: ObjectHash, data: Vec<u8> }`.
- Build: `Blob::from_content` / `from_content_bytes` auto-compute the hash with the thread-local kind; `from_content_with_kind(kind, ..)` / `from_content_bytes_with_kind(kind, ..)` take the repository kind explicitly; `from_bytes(data, hash)` parses with a known hash.
- Serialize: `to_data()` returns raw content (header is implied when hashing with `ObjectHash::from_type_and_data`).

## Tree and TreeItem

- Location: `object/tree.rs`.
- TreeItem format: `"<mode> <name>\0<id-bytes>"`; modes include `100644`/`100755`/`120000`/`160000`/`40000` (gitlink).
- Structure: `TreeItem { mode: TreeItemMode, id: ObjectHash, name: String }`; `Tree { id, tree_items: Vec<TreeItem> }`.
- Build: `Tree::from_tree_items(items)` computes the tree hash with the thread-local kind; `from_tree_items_with_kind(kind, items)` / `rehash_with_kind(kind)` take the repository kind explicitly and require every entry ID to belong to that kind; `rehash` recomputes after modifications with the thread-local kind.
- Parse: `Tree::from_bytes(data, hash)` splits IDs using the width of `hash.kind()` (20/32 bytes) via `TreeItem::from_bytes_with_kind(bytes, kind)`, which fails closed on malformed entries; the legacy `TreeItem::from_bytes(bytes)` uses the thread-local kind. TreeItem parsing has a GBK fallback for non-UTF-8 names.

## Commit

- Location: `object/commit.rs`.
- Field order: `tree <tree-id>`, zero or more `parent <parent-id>`, `author <signature>`, `committer <signature>`, blank line, then message (may include signatures).
- Structure: `Commit { id, tree_id, parent_commit_ids, author, committer, message }`.
- Build: `Commit::new` (explicit signatures) or `from_tree_id` (convenience with current-time signatures); both use `ObjectHash::from_type_and_data` (thread-local kind) to derive the ID. `Commit::new_with_kind(kind, ..)` / `from_tree_id_with_kind(kind, ..)` derive the ID for an explicit kind and require `tree_id` and every parent ID to belong to it.
- Parse: `from_bytes(data, hash)` splits lines, parses `tree`/`parent` references with `ObjectHash::from_hex_for_kind(hash.kind(), ..)` (wrong width / non-hex → `GitError::InvalidHashValue` with the `HashError` diagnostic; structural errors → `GitError::InvalidCommitObject`), and uses `Signature::from_data` for author/committer.
- Helper: `format_message` skips PGP signature blocks or returns the first non-empty line.

## Tag (Annotated)

- Location: `object/tag.rs`.
- Format:  
  `object <object-hash>`  
  `type <object-type>`  
  `tag <tag-name>`  
  `tagger <name> <email> <timestamp> <tz>`  
  `<message>` (after a blank line)
- Structure: `Tag { id, object_hash, object_type, tag_name, tagger, message }`.
- Build: `Tag::new(object_hash, object_type, tag_name, tagger, message)`; hash is computed from serialized content with the thread-local kind. `Tag::new_with_kind(kind, ..)` derives the ID for an explicit kind and requires `object_hash` to belong to it.
- Parse: `from_bytes(data, hash)` validates UTF-8, parses the `object` reference with `ObjectHash::from_hex_for_kind(hash.kind(), ..)` (wrong width / non-UTF-8 → `GitError::InvalidTagObject` carrying kind and expected/actual lengths), errors on missing required fields, and ignores unknown header lines (legacy tolerance); `to_data` emits the format above.

## Note

- Location: `object/note.rs`.
- Meaning: An annotation attached to an object; internally treated as a Blob (`get_type` returns Blob), and hashed using Blob rules.
- Build/Parse: `Note::from_content(content)` builds a note for a placeholder target (legacy: SHA-1 zero ID); `Note::new(target_object_id, content)` associates it to a specific object. `Note::new_with_kind(kind, target, content)` / `from_content_with_kind(kind, content)` derive the ID for an explicit kind, require the target to belong to it, and use `ObjectHash::zero_for_kind(kind)` as the placeholder. Use `from_bytes(data, hash)` to parse existing data; its placeholder target is `ObjectHash::zero_for_kind(hash.kind())`.

## Signature

- Location: `object/signature.rs`.
- Layout: `<role> <name> <email> <timestamp> <tz>`, where `role` is `author`/`committer`/`tagger` (`SignatureType`).
- Functions: `Signature::from_data` parses a byte sequence and fails closed (`GitError::InvalidSignatureType`) on a missing role/`<`/`>`/space separator, non-UTF-8 text, a non-numeric timestamp or a timezone that is not canonical `[+-]HHMM` (an empty name is allowed); `to_data` serializes; `new` creates a signature with a given role/name/email from the current local time and formats the timezone with `format_timezone` (canonical `[+-]HHMM`, e.g. `-0230`).

## Helpers and Common Types

- Location: `object/utils.rs`.
- Contents: Currently minimal; most shared I/O/hash helpers live in top-level `utils.rs`.

## Pack/Protocol Integration

- Loading from a zlib stream: `ReadBoxed::new_with_kind(reader, obj_type, size, kind)` seeds the hasher for the repository kind (`ReadBoxed::new` uses the thread-local kind); `ObjectTrait::from_buf_read_with_kind` then finalizes the ID from that hasher and fails closed if the requested kind differs from the reader's.
- Pack/idx hash context: `Pack::new_with_hash_kind`, `PackEncoder::new_with_hash_kind` / `new_with_idx_and_hash_kind`, `encode_and_output_to_files_with_hash_kind`, `PackStats::analyze_with_hash_kind`, `Pack::decode_pack_object_with_kind` and `Index::{from_file,to_file,load,save,refresh}_with_hash_kind` take the repository `HashKind` explicitly; the parameterless forms are thread-local compatibility wrappers (`encode_and_output_to_files` captures the thread-local kind on the calling thread before the future is polled). `IdxBuilder` derives its kind from the pack hash. Object IDs, ref-delta base IDs, the pack trailer, idx object names and both idx checksums all use that kind; the pack cache spills objects to `<layout>/<2 hex>/<kind>-<hex>` files so same-width SHA-256 and BLAKE3 IDs never alias.
- BLAKE3 packs (git-internal/Libra extension, not readable by standard Git): 32-byte object IDs and ref-delta bases, a BLAKE3 pack trailer and a BLAKE3 idx checksum, always in idx **v2** (the only version this crate reads or writes; `validate_idx_v2_header` fails closed on any other version for every kind). A BLAKE3 pack is byte-compatible in layout with a SHA-256 pack, so the kind must come from the caller — a SHA-256 decoder rejects a BLAKE3 trailer (hash mismatch) rather than misreading it. `ObjectHash::from_bytes_infer_kind` is deprecated and unused by the pack/index/protocol paths.
- Pack decode yields `Entry` with `obj_type`, `hash`, `data`; these can be parsed by the object modules above.
- Pack encode expects `ObjectHash` plus raw data; `PackEncoder` uses `ObjectType` to craft headers and validate hashes.
- Protocol (upload-pack/receive-pack) cares about object ID/type consistency; content parsing is left to the caller or higher layers as needed.
