# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-10

### Changed

- Renamed the package and repository from `@megablacklabel/opfspack` to
  `@megablacklabel/nartik`. The pack extension (`.nartik`), magic (`NRTK`),
  and existing public API names are unchanged.
- AAD and key-derivation labels moved to the `ligrol-*` / `nartik-*` prefixes
  (test vectors and fixtures regenerated).
- The WASM crate is now `nartik-wasm` and the generated module is
  `nartik_wasm`.

### Added

- Pack format v3: per-account random pack root key (PRK), HKDF-derived pack
  keys, and AES-256-GCM entries. v2 packs are rejected on read.
- Key bundle parsing and PRK unwrapping (Google `sub` wrap and passphrase wrap).
- Sealed backup envelopes with a shared label and byte helpers.
- Partial-read pack source support (`PackReader.fromSource`,
  `PackReader.fromOPFS`, `packSourceFromBlob`, `packSourceFromBytes`).
- Checksum and byte-comparison helpers for large-entry tests.

### Fixed

- Reuse the derived pack key when the same `ArrayBuffer` PRK is passed
  repeatedly. Keys are now memoized by the backing buffer and byte range
  instead of the `Uint8Array` view identity, so SHA-256/HKDF/importKey no
  longer run again for every entry.

## [0.1.0] - 2026-05-23

### Added

- Initial release of `@megablacklabel/opfspack` (now `@megablacklabel/nartik`)
- PackBuilder: binary pack creation with optional Deflate/LZ4 compression
- PackReader: O(1) random access via index table
- PackManager: orchestration layer with pluggable PackStorage backends
- OPFSPackStorage: Origin Private File System persistence
- MemoryPackStorage: in-memory storage for tests
- SQLitePackStorage: metadata index via wa-sqlite
- Identity binding: AES-GCM encryption keyed to Google OAuth `sub`
- Arrow IPC + SharedArrayBuffer zero-copy Worker communication
- LRU cache with prefetch for sequential read optimization
- WASM bridge for LZ4 decompression and SIMD CRC-32
