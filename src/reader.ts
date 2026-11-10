import {
  HEADER_SIZE,
  FORMAT_VERSION,
  LITTLE_ENDIAN,
  ENTRY_FLAGS_KNOWN_MASK,
  EntryFlags,
  PackFlags,
  deserializeHeader,
  deserializeIndexEntry,
  calcIndexEntrySize,
  validateMagic,
  type PackHeader,
  type PackIndexEntry,
} from './format.js'

import {
  derivePackKey,
  importPackKey,
  decryptEntry,
} from './auth/identity-key.js'

import { inflate } from 'fflate'
import type { PackEntryInfo, PackMetadata, ReadOptions } from './types.js'
import {
  PackVersionError,
  PackCorruptedError,
  PackKeyRequiredError,
} from './errors.js'
import { LRUCache } from './cache.js'
import { packSourceFromBlob, packSourceFromBytes, type PackSource } from './source.js'

const DEFAULT_CACHE_SIZE = 50 * 1024 * 1024

const EMPTY_BYTES = new Uint8Array(0)

const CRC32_TABLE = (() => {
  const table = new Uint32Array(256)
  for (let i = 0; i < 256; i++) {
    let c = i
    for (let j = 0; j < 8; j++) {
      c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1
    }
    table[i] = c
  }
  return table
})()

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff
  for (let i = 0; i < bytes.length; i++) {
    crc = CRC32_TABLE[(crc ^ bytes[i]!) & 0xff]! ^ (crc >>> 8)
  }
  return (crc ^ 0xffffffff) >>> 0
}

function inflateAsync(data: Uint8Array): Promise<ArrayBuffer> {
  return new Promise((resolve, reject) => {
    inflate(data, (err, result) => {
      if (err) {
        reject(new Error(`Decompression failed: ${err.message}`))
      } else {
        const buf = new ArrayBuffer(result.byteLength)
        new Uint8Array(buf).set(result)
        resolve(buf)
      }
    })
  })
}

const enc = new TextEncoder()

/**
 * 解決済みの pack 鍵と、その鍵素材の指紋（`cacheTag`）。
 * 指紋はエントリキャッシュを鍵ごとに分けるためだけに使う。
 */
interface ResolvedPackKey {
  packKey: CryptoKey
  cacheTag: string
}

/** `Uint8Array` を `ArrayBuffer` として渡す（コピーが要るときだけコピーする）。 */
function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  if (bytes.byteOffset === 0 && bytes.byteLength === bytes.buffer.byteLength) {
    return bytes.buffer as ArrayBuffer
  }
  return bytes.slice().buffer as ArrayBuffer
}

/**
 * `offset` から `length` バイトを読む。
 *
 * ソースが短い読みを返したら継ぎ足し、EOF に当たったらそこで取れた分だけを返す
 * （要求長に満たない場合は呼び出し側が CRC や GCM の検証で弾く）。
 */
async function readFully(
  source: PackSource,
  offset: number,
  length: number,
): Promise<Uint8Array> {
  if (length <= 0) return EMPTY_BYTES

  const first = await source.read(offset, length)
  if (first.byteLength >= length) {
    return first.byteLength === length ? first : first.subarray(0, length)
  }
  if (first.byteLength === 0) return first

  const out = new Uint8Array(length)
  out.set(first, 0)

  let filled = first.byteLength
  while (filled < length) {
    const chunk = await source.read(offset + filled, length - filled)
    if (chunk.byteLength === 0) break
    const take = Math.min(chunk.byteLength, length - filled)
    out.set(chunk.subarray(0, take), filled)
    filled += take
  }

  return filled === length ? out : out.subarray(0, filled)
}

/** pack 先頭の `HEADER_SIZE` バイトを検証して header を返す（v3 のみ）。 */
function parseHeader(bytes: Uint8Array): PackHeader {
  if (bytes.byteLength < HEADER_SIZE) {
    throw new PackCorruptedError('Buffer too small for header')
  }
  if (!validateMagic(bytes)) {
    throw new PackCorruptedError('Invalid magic number: expected NRTK')
  }
  try {
    const header = deserializeHeader(toArrayBuffer(bytes.subarray(0, HEADER_SIZE)))
    if (header.version !== FORMAT_VERSION) {
      throw new PackVersionError(
        `Unsupported pack version: ${header.version} ` +
          `(only v${FORMAT_VERSION} is supported — re-import the book)`,
      )
    }
    return header
  } catch (e) {
    if (e instanceof PackVersionError) throw e
    throw new PackCorruptedError(
      e instanceof Error ? e.message : 'Header validation failed'
    )
  }
}

export class PackReader {
  private source: PackSource
  private header: PackHeader
  /**
   * `fromBuffer` のときだけ設定される元のバイト列。
   *
   * メモリ上の pack は index を同期で読める（既存の同期メソッドのため）ので、
   * その経路だけここを使う。`fromSource` / `fromOPFS` は生成時に index を読む。
   */
  private memory: Uint8Array | null
  private indexMap: Map<string, PackIndexEntry> | null = null
  private indexEntries: PackIndexEntry[] | null = null
  private closed = false
  private cache: LRUCache
  private packKeyMemo: {
    packId: string
    packRootKey: Uint8Array
    resolved: Promise<ResolvedPackKey>
  } | null = null

  private constructor(
    source: PackSource,
    header: PackHeader,
    memory: Uint8Array | null,
    cacheSize = DEFAULT_CACHE_SIZE,
  ) {
    this.source = source
    this.header = header
    this.memory = memory
    this.cache = new LRUCache(cacheSize)
  }

  static fromBuffer(buffer: ArrayBuffer | Uint8Array): PackReader {
    const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer)
    return new PackReader(
      packSourceFromBytes(bytes),
      parseHeader(bytes),
      bytes,
      DEFAULT_CACHE_SIZE,
    )
  }

  /**
   * 任意の `PackSource` から reader を作る。
   *
   * header と index はここで 1 回だけ読み、以降の同期メソッド
   * （`hasEntry` / `getEntryInfo` / `listEntries`）が使えるようにする。
   * エントリ本体は要求されたときに、そのエントリの範囲だけを読む。
   */
  static async fromSource(source: PackSource): Promise<PackReader> {
    const headerBytes = await readFully(source, 0, Math.min(HEADER_SIZE, source.size))
    const reader = new PackReader(source, parseHeader(headerBytes), null)
    await reader.loadIndexFromSource()
    return reader
  }

  /**
   * OPFS の `FileSystemFileHandle` から reader を作る。
   *
   * `file.arrayBuffer()` は呼ばず、`slice()` で必要な範囲だけ読む
   * （大きな pack でも開くときに全体をメモリへ載せない）。
   */
  static async fromOPFS(fileHandle: FileSystemFileHandle): Promise<PackReader> {
    const file = await fileHandle.getFile()
    return PackReader.fromSource(packSourceFromBlob(file))
  }

  get metadata(): PackMetadata {
    this.ensureOpen()
    return {
      version: this.header.version,
      flags: this.header.flags,
      entryCount: this.header.entryCount,
      createdAt: new Date(Number(this.header.createdAt)),
      indexOffset: this.header.indexOffset,
      indexSize: this.header.indexSize,
    }
  }

  hasEntry(path: string): boolean {
    this.ensureOpen()
    this.parseIndexIfNeeded()
    return this.indexMap!.has(path)
  }

  getEntryInfo(path: string): PackEntryInfo | undefined {
    this.ensureOpen()
    this.parseIndexIfNeeded()
    const entry = this.indexMap!.get(path)
    if (!entry) return undefined
    return {
      path: entry.path,
      mimeType: entry.mimeType,
      size: Number(entry.size),
      compressedSize: Number(entry.compressedSize),
      flags: entry.flags,
      offset: entry.offset,
      iv: entry.iv,
    }
  }

  private validateBigInt(value: bigint, name: string): number {
    if (value < 0) {
      throw new PackCorruptedError(`${name} is negative`)
    }
    if (value > Number.MAX_SAFE_INTEGER) {
      throw new PackCorruptedError(`${name} exceeds safe integer range`)
    }
    return Number(value)
  }

  async readEntry(path: string, options?: ReadOptions): Promise<ArrayBuffer> {
    this.ensureOpen()
    this.parseIndexIfNeeded()

    const entry = this.indexMap!.get(path)
    if (!entry) {
      throw new Error(`Entry not found: ${path}`)
    }

    const encrypted = (entry.flags & EntryFlags.Encrypted) !== 0
    // キャッシュ鍵には「暗号化の有無」だけでなく**どの鍵で復号したか**まで入れる。
    // これが無いと、鍵なし・別鍵の読み出しが、以前の鍵で復号した平文を
    // キャッシュから受け取ってしまう（fail-closed 違反）。鍵はキャッシュを
    // 参照する前に解決する。
    const resolvedKey = encrypted ? await this.resolvePackKey(options) : undefined
    if (encrypted && !resolvedKey) {
      throw new PackKeyRequiredError(path)
    }

    const cacheKey = `${this.header.createdAt}-${path}-${
      resolvedKey ? resolvedKey.cacheTag : 'plain'
    }`
    const cached = this.cache.get(cacheKey)
    if (cached) {
      return cached
    }

    const start = this.validateBigInt(entry.offset, 'entry.offset')
    const size = this.validateBigInt(entry.compressedSize, 'entry.compressedSize')
    if (start + size > this.source.size) {
      throw new PackCorruptedError('Entry extends beyond buffer')
    }

    // 読むのは**このエントリの範囲だけ**（pack 全体も index でもない）。
    let data = toArrayBuffer(await readFully(this.source, start, size))

    if (encrypted && resolvedKey) {
      try {
        data = await decryptEntry(data, entry.iv, resolvedKey.packKey)
      } catch {
        // 鍵違い・改変（AES-GCM のタグ検証失敗）
        throw new PackCorruptedError(`decryption failed: ${path}`)
      }
    }

    if (entry.flags & EntryFlags.Compressed) {
      data = await inflateAsync(new Uint8Array(data))
    }

    this.cache.set(cacheKey, data)
    return data
  }

  /**
   * `ReadOptions` からこの pack の復号鍵を用意する。
   *
   * v3 は `pack_key = HKDF(PRK, pack_id)` なので `packRootKey` と `packId` の
   * 両方が要る（v2 の `sub` からは導出できない）。pack ごとに 1 回だけ導出して
   * 覚えるが、同じ `packId` でも PRK の実体が別なら導出し直す。
   *
   * 戻り値の `cacheTag` は**鍵素材の指紋**（`SHA-256(packId ‖ PRK)`）。エントリ
   * キャッシュを鍵ごとに分けるために使い、鍵素材そのものは保持しない。
   */
  private async resolvePackKey(options?: ReadOptions): Promise<ResolvedPackKey | undefined> {
    const packRootKey = options?.packRootKey
    const packId = options?.packId
    if (!packRootKey || !packId) {
      return undefined
    }
    const prk =
      packRootKey instanceof Uint8Array ? packRootKey : new Uint8Array(packRootKey)
    const memo = this.packKeyMemo
    if (memo && memo.packId === packId && memo.packRootKey === prk) {
      return memo.resolved
    }
    const resolved = (async (): Promise<ResolvedPackKey> => {
      // 鍵素材の指紋 = `SHA-256(packId ‖ 0x00 ‖ PRK)`。エントリキャッシュを
      // 鍵ごとに分けるためだけに使い、鍵素材そのものは残さない。
      const packIdBytes = enc.encode(packId)
      const tagInput = new Uint8Array(packIdBytes.byteLength + 1 + prk.byteLength)
      tagInput.set(packIdBytes, 0)
      tagInput.set(prk, packIdBytes.byteLength + 1)
      const digest = await crypto.subtle.digest('SHA-256', tagInput as BufferSource)
      const cacheTag = Array.from(new Uint8Array(digest))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('')
      const packKey = await importPackKey(await derivePackKey(prk, packId))
      return { packKey, cacheTag }
    })()
    this.packKeyMemo = { packId, packRootKey: prk, resolved }
    return resolved
  }

  /**
   * エントリの一部だけを返す。
   *
   * 平文・非圧縮のエントリは**要求された範囲だけ**をソースから読む（pack 全体も
   * エントリ全体も読まない）。暗号化エントリは AES-GCM が全体でしか認証できない
   * ため、圧縮エントリは先頭から伸長が要るため、そのエントリの範囲だけを
   * 復号・伸長してからスライスする。
   */
  async readEntryRange(
    path: string,
    start: number,
    end: number,
    options?: ReadOptions
  ): Promise<ArrayBuffer> {
    this.ensureOpen()
    this.parseIndexIfNeeded()
    const entry = this.indexMap!.get(path)
    if (!entry) {
      throw new Error(`Entry not found: ${path}`)
    }
    if (start < 0 || end > Number(entry.size) || start >= end) {
      throw new Error('Invalid range')
    }

    if ((entry.flags & (EntryFlags.Encrypted | EntryFlags.Compressed)) === 0) {
      const offset = this.validateBigInt(entry.offset, 'entry.offset')
      const size = this.validateBigInt(entry.compressedSize, 'entry.compressedSize')
      if (offset + size > this.source.size) {
        throw new PackCorruptedError('Entry extends beyond buffer')
      }
      return toArrayBuffer(await readFully(this.source, offset + start, end - start))
    }

    const fullData = await this.readEntry(path, options)
    return fullData.slice(start, end)
  }

  listEntries(): PackEntryInfo[] {
    this.ensureOpen()
    this.parseIndexIfNeeded()
    return this.indexEntries!.map((entry) => ({
      path: entry.path,
      mimeType: entry.mimeType,
      size: Number(entry.size),
      compressedSize: Number(entry.compressedSize),
      flags: entry.flags,
      offset: entry.offset,
      iv: entry.iv,
    }))
  }

  close(): void {
    this.closed = true
    this.memory = null
    this.indexMap = null
    this.indexEntries = null
    this.packKeyMemo = null
    this.cache.clear()
  }

  private ensureOpen(): void {
    if (this.closed) {
      throw new Error('PackReader is closed')
    }
  }

  /** header が指す index の位置を検証して返す（`limit` はソース全体の長さ）。 */
  private indexBounds(limit: number): { indexOffset: number; indexSize: number } {
    const indexOffset = this.validateBigInt(this.header.indexOffset, 'header.indexOffset')
    const indexSize = this.validateBigInt(this.header.indexSize, 'header.indexSize')

    if (indexOffset + indexSize > limit) {
      throw new PackCorruptedError('Index extends beyond buffer')
    }

    return { indexOffset, indexSize }
  }

  /** `fromSource` / `fromOPFS` 用: index を 1 回だけ読んで検証する。 */
  private async loadIndexFromSource(): Promise<void> {
    const { indexOffset, indexSize } = this.indexBounds(this.source.size)
    const bytes = await readFully(this.source, indexOffset, indexSize)
    if (bytes.byteLength < indexSize) {
      throw new PackCorruptedError('Index extends beyond buffer')
    }
    this.applyIndex(bytes)
  }

  private parseIndexIfNeeded(): void {
    if (this.indexMap !== null) return

    const memory = this.memory
    if (!memory) {
      // fromSource / fromOPFS は生成時に index を読み終えている（ここへは来ない）
      throw new Error('Pack index is not loaded')
    }

    const { indexOffset, indexSize } = this.indexBounds(memory.byteLength)
    this.applyIndex(memory.subarray(indexOffset, indexOffset + indexSize))
  }

  /** index 領域（末尾 4 バイトの CRC を含む）を検証し、エントリ表を組み立てる。 */
  private applyIndex(indexBytes: Uint8Array): void {
    if (indexBytes.byteLength < 4) {
      throw new PackCorruptedError('Index too small for CRC')
    }

    const storedCrc = new DataView(
      indexBytes.buffer,
      indexBytes.byteOffset + indexBytes.byteLength - 4,
      4,
    ).getUint32(0, LITTLE_ENDIAN)
    const entriesData = indexBytes.subarray(0, indexBytes.byteLength - 4)
    const computedCrc = crc32(entriesData)

    if (storedCrc !== computedCrc) {
      throw new PackCorruptedError(
        `Index CRC mismatch: stored=${storedCrc}, computed=${computedCrc}`
      )
    }

    const indexMap = new Map<string, PackIndexEntry>()
    const indexEntries: PackIndexEntry[] = []
    let pos = 0

    for (let i = 0; i < this.header.entryCount; i++) {
      if (pos >= entriesData.byteLength) {
        throw new PackCorruptedError(
          `Index truncated: expected ${this.header.entryCount} entries`
        )
      }
      try {
        const entry = deserializeIndexEntry(entriesData.subarray(pos))
        indexMap.set(entry.path, entry)
        indexEntries.push(entry)
        pos += calcIndexEntrySize(entry.path, entry.mimeType)
      } catch {
        throw new PackCorruptedError('Invalid index entry at offset ' + pos)
      }
    }

    // v3 で `IDENTITY_BOUND`（v2 の識別束縛）が立っていれば、その pack は
    // v3 として壊れている（鍵スケジュールは header version で選ぶ — 仕様 §6）。
    // 併せて header の `ENCRYPTED` と各エントリの暗号化の一致も見る
    // （builder は鍵を渡されたとき全エントリを暗号化するので、混在は破損）。
    const headerEncrypted = (this.header.flags & PackFlags.Encrypted) !== 0
    for (const entry of indexEntries) {
      if (entry.flags & ~ENTRY_FLAGS_KNOWN_MASK) {
        throw new PackCorruptedError(
          `unknown entry flags 0x${entry.flags.toString(16)}: ${entry.path}`
        )
      }
      const entryEncrypted = (entry.flags & EntryFlags.Encrypted) !== 0
      if (headerEncrypted && !entryEncrypted) {
        throw new PackCorruptedError('encrypted pack contains a plaintext entry')
      }
      if (!headerEncrypted && entryEncrypted) {
        throw new PackCorruptedError(
          'pack contains encrypted entries without the ENCRYPTED flag'
        )
      }
    }

    this.indexMap = indexMap
    this.indexEntries = indexEntries
  }

  async prefetch(entryPaths: string[]): Promise<void> {
    await Promise.all(
      entryPaths.map((path) =>
        this.readEntry(path).catch(() => {})
      )
    )
  }

  getCacheStats(): { size: number; count: number } {
    return { size: this.cache.size, count: this.cache.count }
  }
}
