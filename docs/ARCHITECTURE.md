# Git-Internal Architecture Overview

This doc summarizes the overall design of git-internal: module relationships, key data flows, and concurrency patterns so readers can see how pack/object processing and protocol layers fit together.

## Modules & Call Graph (data-flow view)

```
protocol/* (smart/http/ssh)
        ⇅ pkt-line & pack encode/decode
internal/pack (encode/decode/waitlist/cache/idx)
        ⇅ consumes/produces Entry+Meta
        ⇅ internal/object/index/metadata      (object parse, index IO, metadata)
        ⇅ delta / zstdelta / diff             (delta/compression/line diff)

hash.rs / utils.rs / errors.rs  (shared infra for all arrows above)
```

- Core context: `internal/pack` is the hub, decoding/encoding packs, managing cache/waitlist/idx, and exchanging data with both protocol (upstream) and object/index/metadata + delta/diff (side dependencies).
- Protocol entry: `protocol/*` drives info-refs/upload-pack/receive-pack, calling into `Pack`/`PackEncoder` and receiving decoded entries back; uses app-provided `RepositoryAccess` / `AuthenticationService` for storage/auth.
- Data model: `internal/object` / `internal/index` / `internal/metadata` parse/serialize objects, handle index IO, attach path/offset/CRC metadata; interact bidirectionally with pack (feed objects, receive decoded ones).
- Algorithm support: `delta` / `zstdelta` / `diff` serve pack compression/rebuild and can be consumed independently; pack calls them to build/apply deltas, and they rely on common infra.
- Infrastructure: `hash.rs`, `utils.rs`, `errors.rs` are shared by all modules (hash choice/IDs, IO/hash helpers, unified errors), configured once and reused across flows.

## Core Data Flows

### Pack Decode (offline/streaming)

```
Entry points: decode(reader: impl BufRead) / decode_stream(stream: Stream<Bytes>, mpsc_sender)

Input: pack (BufRead / Stream<Bytes>)
  ├─ Wrap reader (Wrapper + CrcCountingReader) to track bytes and CRC
  ├─ Read/validate PACK header (magic/version/object count)
  ├─ Loop over object count:
  │     - Read object type + varint size
  │     - Inflate zlib body, record raw input bytes and crc32
  │     - Delta objects: extract base offset/hash and target size
  │     - Base objects: insert into caches, trigger waitlist processing
  │     - Delta: rebuild if base is cached, otherwise queue in waitlist
  ├─ Emit each completed object via callback as MetaAttached<Entry, EntryMeta>
  └─ After reading pack, record Pack.signature (trailer checksum)
```

- Concurrency: `ThreadPool` handles decode/rebuild; queue length and `mem_limit` apply backpressure and are configured via the pack-decode configuration (see engine/pack config docs / `PackDecodeConfig` for fields and defaults); `Waitlist` matches base/delta; `Caches` manage memory+disk and track offset/CRC metadata.

### Pack Encode & idx Generation

```
Entry points: encode_and_output_to_files; PackEncoder::encode / encode_idx_file

entries (Entry+Meta) ──▶ PackEncoder
  ├─ window_size==0: parallel straight write
  ├─ window_size>0: Rabin delta by default; Myers/Patience when Rabin is disabled
  ├─ Optional explicit path: zstdelta within the delta window
  ├─ Build object header (type+size); offset-delta writes offset encoding
  ├─ zlib-compress body
  ├─ Async write pack chunks via channel (tokio task)
  ├─ Accumulate idx entry (offset / crc32 / hash), build idx
  └─ Compute pack hash, rename to pack-<hash>.pack /.idx
```

- Entrypoints: `encode_and_output_to_files` is the only file-output API and wires pack/idx writers plus the final rename; `PackEncoder::encode` produces pack data; `encode_idx_file` builds idx.
- Delta strategy: `window_size` controls whether/how big the window is; `window_size==0` uses the non-delta parallel path.
- Algorithm selection: the default Cargo feature set enables only `diff_rabin`, so non-zero windows use Rabin fingerprint matching. Builds without `diff_rabin` fall back to Myers when `diff_mydrs` is enabled, otherwise Patience. zstdelta remains available through its explicit `PackEncoder` API.
- Concurrency & IO: pack/idx writes are decoupled via channel + tokio writers to avoid blocking encode.
- Output: temp files are renamed by final pack hash; idx includes fanout/CRC/offset (supports large offsets).
- Configuration: `Pack::new` sets thread count, `mem_limit`, temp dir, and `clean_tmp` (cleanup temp on drop).

### Smart Protocol & Transport

```
Client ─pkt-line─▶ SmartProtocol
  ├─ info-refs: advertise refs + capabilities (incl. object-format)
  ├─ upload-pack: parse want/have/done, fetch objects via RepositoryAccess, PackGenerator builds pack stream
  ├─ receive-pack: parse commands/pack, decode and hand to RepositoryAccess for storage
  └─ HTTP/SSH adapters: path/query parsing and auth delegation only
```

- Dual hash: `wire_hash_kind` for on-wire format, `local_hash_kind` follows current thread setting; `RepositoryAccess::object_hash_kind()` (default: the thread-local kind, overridable by the storage backend) is the repository's own format and is what the default `get_blob`/`get_commit`/`get_tree` accessors parse incoming hash strings against (`ObjectHash::from_hex_for_kind`, fail-closed on a width/kind mismatch).
- The `object-format` capability is emitted from `HashKind::as_str()` and parsed with the single `HashKind` parser (exact lowercase match); unknown values are logged and ignored; `object-format=blake3` is currently treated the same way and `git_info_refs` refuses to advertise a non-standard wire kind (`InvalidRequest`), so BLAKE3 cannot be negotiated until B3-06 replaces this guard with the explicit BLAKE3 negotiation contract and fail-closed mismatch handling.
- Capabilities: see `protocol/types.rs::Capability` (side-band, ofs-delta, report-status, etc.).
- More details: `docs/GIT_PROTOCOL_GUIDE.md`.

## Typical Git Operations

- **clone/fetch (upload-pack)**
  1) info/refs: `protocol/http|ssh` parses request → `SmartProtocol` advertises refs + capabilities (incl. object-format).
  2) want/have pkt-line: `SmartProtocol::git_upload_pack` parses, delegates to `RepositoryAccess::get_objects_for_pack` / `get_object`.
  3) `PackGenerator` walks commit→tree→blob graph, builds `Entry` list, hands to `PackEncoder` for pack/idx stream.
  4) Pack streamed back (optionally side-band).
  5) Client can decode via `Pack::decode`, receiving objects/metadata.

- **push (receive-pack)**
  1) info/refs as above for capability negotiation.
  2) Commands + pack: `SmartProtocol::git_receive_pack` validates, decodes pack (reusing `Pack::decode`), categorizes Commit/Tree/Blob.
  3) `RepositoryAccess::handle_pack_objects`/`store_pack_data` persist objects, update refs.
  4) Return report-status/report-status-v2.

- **Local diff/tooling**
  - `Diff::diff` produces unified diff for object contents.
  - `internal/index` reads/writes working tree index; `ObjectHash::from_type_and_data` is Git-compatible for external tooling.

## Concurrency & Caching

- **ThreadPool**: used during pack decode for inflate and delta rebuild to avoid single-thread bottlenecks.
- **Tokio**: streaming decode (`decode_stream`) and async file writes (`encode_and_output_to_files`).
- **Cache layer**: `Caches` combines LRU memory + disk spill; 80% of the `mem_limit` is used for object cache; `cache_objs_mem` tracks object heap usage.
- **Waitlist**: delta objects hang until base arrives, then are replayed.

## Hashing & Compatibility

- Default SHA-1; switch to SHA-256 or BLAKE3-256 via `set_hash_kind` (usually configured once upstream for the whole flow).
- Compatibility matrix: `Sha1` and `Sha256` are the standard Git object formats (loose objects, packs, idx, protocol interoperate with Git). `Blake3` is a git-internal / Libra extension and a separate object namespace — same 32-byte / 64-hex width as SHA-256 but a distinct `HashKind`/`ObjectHash` variant; no in-place conversion of existing repositories, no interoperability with unmodified Git, and no length-based inference (`from_str` / `from_bytes_infer_kind` never yield BLAKE3; use the explicit-kind API or `blake3:HEX` tags).
- Repository `ObjectHash` versus AI `IntegrityHash`: `ObjectHash` follows the repository `HashKind` (SHA-1 / SHA-256 / BLAKE3); the AI objects' `IntegrityHash` (`internal/object/integrity.rs`) is always SHA-256 regardless of the repository kind, and application-level digests (manifests, policies, HMACs) do not change with it.
- `ObjectHash::from_type_and_data` matches Git object header format `<type> <size>\0<data>`, used for pack/idx/signatures; `ObjectHash::from_type_and_data_for_kind` / `internal::pack::utils::calculate_object_hash_for_kind` are the explicit-kind, fail-closed variants.
- Algorithm dispatch is centralised (GC-02): the `HashAlgorithm` methods in `utils.rs` (`new_for_kind`, `kind`, `update`, `finalize`, `finalize_object_hash`) and the `HashKind`/`ObjectHash` methods in `hash.rs` are the only places that match on the algorithm. Pack object hashing (`calculate_object_hash`), the pack stream `Wrapper` (`Wrapper::new_with_kind`) and the smart-protocol `object-format` capability delegate to them instead of keeping per-algorithm tables, so adding a hash kind touches `hash.rs`/`utils.rs` only.
- Thread-local `HashKind` is a compatibility default for the single-repository workflow; worker threads, async tasks, caches and protocol callbacks that may serve another repository use the explicit-kind API.
- For tests, use `set_hash_kind_for_test` to temporarily switch hash algorithm; test isolation avoids cross-thread interference.

## References

- README: quick start & performance tips.
- docs/GIT_PROTOCOL_GUIDE.md: protocol details and layering.
- docs/GIT_OBJECTS.md: Git objects overview.
- tests/data/: committed `index/` and `objects/` fixtures; the pack fixtures under `tests/data/packs/` (`*.pack`/`*.idx`) are not committed — they are downloaded on demand by `download_pack_file` (`src/internal/pack/test_pack_download.rs`), so the full test suite needs network access (see the plan's GC-14).
