# @megablacklabel/nartik

Browser-native pack file system for OPFS (Origin Private File System). Inspired by Unity Asset Bundle architecture.

## Overview

`nartik` groups related files into a single binary package, solving common OPFS issues:

- **Many small files** → One pack file
- **No atomicity** → Atomic pack operations
- **Hard to backup** → Single file transfer
- **Inefficient random access** → O(1) entry lookup
- **Storage fragmentation** → Single large allocation

## Quick Start

```typescript
import { PackManager, MemoryPackStorage } from '@megablacklabel/nartik'

const manager = new PackManager(new MemoryPackStorage())

// Create pack
const imageData = new Uint8Array([/* ... */])
await manager.createPack('book-123', [
  { path: 'cover.webp', data: imageData, mimeType: 'image/webp' },
])

// Read pack
const page = await manager.readFile('book-123', 'cover.webp')
```

## Installation

This package is published to **GitHub Packages**.

Add the following to your `.npmrc` before installing:

```
@megablacklabel:registry=https://npm.pkg.github.com
```

Install via Bun (requires GitHub Packages registry config):

```bash
bun add @megablacklabel/nartik
```

This package was previously published as `@megablacklabel/opfspack`. The pack
format and public API names are unchanged; only the package name and repository
moved.

## Architecture

```
┌─────────────────┬──────────────────┬─────────────────┐
│     HEADER      │      BODY        │  INDEX TABLE    │
│   (64 bytes)    │  (variable size) │  (variable size)│
├─────────────────┴──────────────────┴─────────────────┤
│                                                      │
│  Header: magic (NRTK), version, flags,               │
│          indexOffset, indexSize, entryCount          │
│                                                      │
│  Body: Raw/compressed entry data back-to-back        │
│                                                      │
│  Index: Array of { path, offset, size, flags, iv }   │
│         + CRC-32 checksum                            │
└──────────────────────────────────────────────────────┘
```

## Features

### Random Access
Read any entry in O(1) via index table.

### Optional Compression
- Deflate (JS: fflate)
- LZ4 (Rust/WASM)

### Optional Encryption (v3)
Packs are encrypted per account with `AES-256-GCM`, keyed by
`pack_key = HKDF-SHA256(PRK, pack_id)` where `PRK` is the account's random
**pack root key** (spec: `docs/spec/10-pack-keys.md` in the desktop app repo).

The PRK never appears in a pack. It is stored wrapped — in the OS keyring on
desktop and in Drive's `ligrol-keys.json` — and unlocked with the Google
`sub` wrap (`deriveSubWrapKek` → `unwrapPackRoot`) or a passphrase:

```typescript
const bundle = parseKeyBundle(await fetchKeysFile())
const prk = await unlockPackRoot(bundle, { sub: googleProfile.sub })

// write
await manager.createPack('book-123', files, { packRootKey: prk })

// read
const page = await reader.readEntry('pages/page_0001.webp', {
  packRootKey: prk,
  packId: 'book-123',
})
```

Encrypted entries without a key throw `PackKeyRequiredError` (the ciphertext is
never returned as plaintext). `sub` alone cannot decrypt a pack — v2's
`deriveMasterKey`-based scheme is gone and v2 packs are rejected on read
(`PackVersionError`); re-import them.

### Arrow IPC + SAB Worker Communication
Zero-copy transfer between Worker and Main Thread via SharedArrayBuffer.

### SQLite Pack Index
Fast metadata queries without parsing pack files:

```typescript
import { SQLitePackStorage } from '@megablacklabel/nartik'

const indexDb = new SQLitePackStorage()
await indexDb.init()

// O(1) SQL query instead of OPFS directory scan
const packs = await indexDb.list()
const entries = await indexDb.getPackEntries('book-123')
```

### LRU Cache + Prefetch
PackReader includes 50MB LRU cache:

```typescript
const reader = PackReader.fromBuffer(buffer)

// Prefetch adjacent pages
await reader.prefetch([
  'pages/page_002.webp',
  'pages/page_003.webp',
])

// Cached read
const page = await reader.readEntry('pages/page_002.webp') // <50ms
```

## API Reference

### PackBuilder

```typescript
class PackBuilder {
  constructor(options?: {
    compress?: boolean
    packRootKey?: Uint8Array | ArrayBuffer  // PRK: 渡すと全エントリを暗号化
    packId?: string                          // PRK とセットで必須
  })

  addEntry(path: string, data: Uint8Array, mimeType: string): void
  async build(): Promise<ArrayBuffer>
}
```

### PackReader

```typescript
class PackReader {
  static fromBuffer(buffer: ArrayBuffer | Uint8Array): PackReader
  static async fromSource(source: PackSource): Promise<PackReader>
  static async fromOPFS(handle: FileSystemFileHandle): Promise<PackReader>

  get metadata(): PackMetadata
  hasEntry(path: string): boolean
  getEntryInfo(path: string): PackEntryInfo | undefined
  async readEntry(path: string, options?: ReadOptions): Promise<ArrayBuffer>
  async readEntryRange(path: string, start: number, end: number, options?: ReadOptions): Promise<ArrayBuffer>
  async prefetch(paths: string[]): Promise<void>
  listEntries(): PackEntryInfo[]
}
```

### PackSource（部分読み）

`fromSource` / `fromOPFS` は pack 全体をメモリに載せない。開くときに読むのは
**ヘッダ（先頭 64 バイト）と index だけ**で、エントリ本体は要求されたときにその範囲だけを
`PackSource` 越しに読む（2 GiB / 10 GiB 級の pack を想定）。`readEntryRange` も、
平文・非圧縮のエントリなら要求された範囲だけを読む。

```typescript
interface PackSource {
  /** ソース全体のバイト数。 */
  readonly size: number
  /** `offset` から最大 `length` バイトを読む（EOF では短くてよい）。 */
  read(offset: number, length: number): Promise<Uint8Array>
}
```

`packSourceFromBytes(bytes)` / `packSourceFromBlob(blob)` を使うか、Range 対応の HTTP
レスポンスなどに合わせて自前で実装する。

### PackManager

```typescript
class PackManager {
  constructor(storage: PackStorage)

  async createPack(packId: string, files: PackFile[], options?: PackOptions): Promise<void>
  async openPack(packId: string): Promise<PackReader>
  async deletePack(packId: string): Promise<void>
  async listPacks(): Promise<PackListEntry[]>
  async readFile(packId: string, entryPath: string): Promise<ArrayBuffer>
}
```

## Binary Format

| Field | Size | Description |
|-------|------|-------------|
| Magic | 4 bytes | `NRTK` (0x4E52544B) |
| Version | 4 bytes | Format version (3) |
| Flags | 4 bytes | Global pack flags |
| Reserved | 4 bytes | Padding |
| Index Offset | 8 bytes | Byte offset to index table |
| Index Size | 8 bytes | Byte size of index table |
| Entry Count | 4 bytes | Number of entries |
| Reserved | 4 bytes | Padding |
| Created At | 8 bytes | Unix timestamp (ms) |
| Reserved | 12 bytes | Padding |
| Checksum | 4 bytes | CRC-32 of header bytes 0-59 |

**Index Entry:**
- Path length (2 bytes)
- Path (variable)
- MIME type length (2 bytes)
- MIME type (variable)
- Offset (8 bytes)
- Size (8 bytes)
- Compressed size (8 bytes)
- Flags (4 bytes)
- IV (12 bytes, AES-GCM nonce)
- Padding to 8-byte alignment

## Development

```bash
# Build WASM
bun run wasm:build

# Build package
bun run build

# Type check
bun run typecheck

# Run tests
bun run test:run
```

## License

MIT
