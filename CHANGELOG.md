# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
