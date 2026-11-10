import { describe, it, expect } from 'vitest'
import {
  MAGIC_NUMBER,
  HEADER_SIZE,
  FORMAT_VERSION,
  LITTLE_ENDIAN,
  PackFlags,
  serializeHeader,
  serializeIndexEntry,
  calcIndexEntrySize,
  crc32,
} from '../format.js'
import { PackBuilder } from '../builder.js'
import { PackReader } from '../reader.js'
import { packSourceFromBlob, packSourceFromBytes, type PackSource } from '../source.js'
import {
  PackCorruptedError,
  PackVersionError,
  PackKeyRequiredError,
} from '../errors.js'

interface ReadRange {
  offset: number
  length: number
}

interface ReadRegion {
  offset: number
  data: Uint8Array
}

/**
 * `read()` の範囲を記録するメモリ上のソース。
 *
 * `limit` を超える 1 回の読み出しは「pack 全体を読もうとした」とみなして失敗させる
 * （2 GiB/10 GiB 級の pack を扱えることがこのテストの主題なので、実確保で落とす）。
 */
class RecordingSource implements PackSource {
  readonly reads: ReadRange[] = []

  constructor(
    private readonly bytes: Uint8Array,
    private readonly limit: number = Number.MAX_SAFE_INTEGER,
  ) {}

  get size(): number {
    return this.bytes.byteLength
  }

  async read(offset: number, length: number): Promise<Uint8Array> {
    if (length > this.limit) {
      throw new Error(
        `source read of ${length} bytes exceeds the ${this.limit} byte limit of this test`,
      )
    }
    this.reads.push({ offset, length })
    if (offset >= this.bytes.byteLength) return new Uint8Array(0)
    return this.bytes.subarray(offset, Math.min(offset + length, this.bytes.byteLength))
  }

  get bytesRead(): number {
    return this.reads.reduce((sum, range) => sum + range.length, 0)
  }
}

/**
 * 実体を持たない巨大 pack を装うソース。宣言した `size`（2 GiB 等）に対して、
 * `regions` に登録した領域だけを合成して返し、残りは 0 埋めする。
 */
class SparseSource implements PackSource {
  readonly reads: ReadRange[] = []

  constructor(
    readonly size: number,
    private readonly regions: ReadRegion[],
    private readonly limit: number,
  ) {}

  async read(offset: number, length: number): Promise<Uint8Array> {
    if (length > this.limit) {
      throw new Error(
        `source read of ${length} bytes exceeds the ${this.limit} byte limit of this test`,
      )
    }
    this.reads.push({ offset, length })
    const end = Math.min(offset + length, this.size)
    const out = new Uint8Array(Math.max(0, end - offset))
    for (const region of this.regions) {
      const from = Math.max(offset, region.offset)
      const to = Math.min(end, region.offset + region.data.byteLength)
      if (to > from) {
        out.set(
          region.data.subarray(from - region.offset, to - region.offset),
          from - offset,
        )
      }
    }
    return out
  }

  get bytesRead(): number {
    return this.reads.reduce((sum, range) => sum + range.length, 0)
  }
}

interface LayoutEntry {
  path: string
  mimeType: string
  data: Uint8Array
  offset: number
  flags?: number
  uncompressedSize?: number
}

/**
 * header / index / entry の**置き場だけ**を組み立てる（間の領域は呼び出し側が合成する）。
 * `PackBuilder` と同じ並び（entry → index → CRC）で、offset を呼び出し側が決められる。
 */
function layoutPack(
  entries: LayoutEntry[],
  headerFlags: number = PackFlags.None,
): { regions: ReadRegion[]; indexOffset: number; indexSize: number } {
  let indexSize = 4
  for (const entry of entries) {
    indexSize += calcIndexEntrySize(entry.path, entry.mimeType)
  }

  const lastEnd = entries.reduce(
    (max, entry) => Math.max(max, entry.offset + entry.data.byteLength),
    HEADER_SIZE,
  )
  const indexOffset = Math.ceil(lastEnd / 8) * 8

  const indexBytes = new Uint8Array(indexSize)
  let pos = 0
  for (const entry of entries) {
    const record = new Uint8Array(
      serializeIndexEntry({
        path: entry.path,
        mimeType: entry.mimeType,
        offset: BigInt(entry.offset),
        size: BigInt(entry.uncompressedSize ?? entry.data.byteLength),
        compressedSize: BigInt(entry.data.byteLength),
        flags: entry.flags ?? 0,
        iv: new Uint8Array(12),
      }),
    )
    indexBytes.set(record, pos)
    pos += record.byteLength
  }
  new DataView(indexBytes.buffer).setUint32(
    indexSize - 4,
    crc32(indexBytes.subarray(0, indexSize - 4)),
    LITTLE_ENDIAN,
  )

  const headerBytes = new Uint8Array(
    serializeHeader({
      magic: MAGIC_NUMBER,
      version: FORMAT_VERSION,
      flags: headerFlags,
      reserved: 0,
      indexOffset: BigInt(indexOffset),
      indexSize: BigInt(indexSize),
      entryCount: entries.length,
      createdAt: BigInt(1700000000000),
      checksum: 0,
    }),
  )

  return {
    regions: [
      { offset: 0, data: headerBytes },
      ...entries.map((entry) => ({ offset: entry.offset, data: entry.data })),
      { offset: indexOffset, data: indexBytes },
    ],
    indexOffset,
    indexSize,
  }
}

async function buildTestPack(): Promise<{ pack: ArrayBuffer; big: Uint8Array }> {
  const big = new Uint8Array(4 * 1024 * 1024)
  crypto.getRandomValues(big.subarray(0, 65536))
  const builder = new PackBuilder()
  builder.addEntry('pages/big.bin', big, 'application/octet-stream')
  builder.addEntry('meta.json', new TextEncoder().encode('{"title":"partial"}'), 'application/json')
  return { pack: await builder.build(), big }
}

function indexBounds(pack: ArrayBuffer): { indexOffset: number; indexSize: number } {
  const view = new DataView(pack)
  return {
    indexOffset: Number(view.getBigUint64(16, LITTLE_ENDIAN)),
    indexSize: Number(view.getBigUint64(24, LITTLE_ENDIAN)),
  }
}

describe('PackSource 実装', () => {
  it('packSourceFromBytes は size を報告し、EOF では短く返す', async () => {
    const source = packSourceFromBytes(new Uint8Array([1, 2, 3, 4]))
    expect(source.size).toBe(4)
    expect(Array.from(await source.read(1, 2))).toEqual([2, 3])
    expect(Array.from(await source.read(2, 10))).toEqual([3, 4])
    expect(await source.read(9, 4)).toHaveLength(0)
  })

  it('packSourceFromBlob は slice() で範囲読みする', async () => {
    const source = packSourceFromBlob(new Blob([new Uint8Array([1, 2, 3, 4])]))
    expect(source.size).toBe(4)
    expect(Array.from(await source.read(2, 1))).toEqual([3])
  })
})

describe('PackReader.fromSource の部分読み', () => {
  it('開くときに読むのはヘッダと index だけ', async () => {
    const { pack } = await buildTestPack()
    const source = new RecordingSource(new Uint8Array(pack))
    const { indexOffset, indexSize } = indexBounds(pack)

    const reader = await PackReader.fromSource(source)

    expect(source.reads).toEqual([
      { offset: 0, length: HEADER_SIZE },
      { offset: indexOffset, length: indexSize },
    ])
    // index は 1 回だけ読んでキャッシュする（同期メソッドが何度呼ばれても増えない）
    expect(reader.metadata.version).toBe(FORMAT_VERSION)
    expect(reader.hasEntry('meta.json')).toBe(true)
    expect(reader.listEntries()).toHaveLength(2)
    expect(reader.getEntryInfo('meta.json')?.mimeType).toBe('application/json')
    expect(source.reads).toHaveLength(2)
  })

  it('readEntry はそのエントリの範囲だけを読む', async () => {
    const { pack } = await buildTestPack()
    const source = new RecordingSource(new Uint8Array(pack))
    const reader = await PackReader.fromSource(source)
    const info = reader.getEntryInfo('meta.json')!
    const afterOpen = source.bytesRead

    const data = await reader.readEntry('meta.json')

    expect(new TextDecoder().decode(data)).toBe('{"title":"partial"}')
    expect(source.reads.slice(2)).toEqual([
      { offset: Number(info.offset), length: info.compressedSize },
    ])
    // 4 MiB の pack から 1 エントリ読む量は桁違いに少ない
    expect(source.bytesRead - afterOpen).toBe(info.compressedSize)
    expect(source.bytesRead).toBeLessThan(pack.byteLength / 100)
    // 巨大エントリの領域には一切触れない
    const big = reader.getEntryInfo('pages/big.bin')!
    const bigStart = Number(big.offset)
    const bigEnd = bigStart + big.compressedSize
    expect(source.reads.every((r) => r.offset + r.length <= bigStart || r.offset >= bigEnd)).toBe(true)
  })

  it('readEntryRange は要求した範囲だけを読む（非圧縮・平文）', async () => {
    const { pack } = await buildTestPack()
    const source = new RecordingSource(new Uint8Array(pack))
    const reader = await PackReader.fromSource(source)
    const info = reader.getEntryInfo('meta.json')!

    const data = await reader.readEntryRange('meta.json', 2, 7)

    expect(new TextDecoder().decode(data)).toBe('title')
    expect(source.reads.slice(2)).toEqual([
      { offset: Number(info.offset) + 2, length: 5 },
    ])
  })

  it('readEntryRange は巨大エントリの一部だけを読む', async () => {
    const { pack, big } = await buildTestPack()
    const source = new RecordingSource(new Uint8Array(pack))
    const reader = await PackReader.fromSource(source)
    const info = reader.getEntryInfo('pages/big.bin')!

    const data = await reader.readEntryRange('pages/big.bin', 10, 26)

    expect(new Uint8Array(data)).toEqual(big.subarray(10, 26))
    expect(source.reads.slice(2)).toEqual([
      { offset: Number(info.offset) + 10, length: 16 },
    ])
  })

  it('2 GiB を報告するソースでも pack 全体を確保せずに読める', async () => {
    const ENTRY_OFFSET = 1_536 * 1024 * 1024
    const text = new TextEncoder().encode('sparse entry payload')
    const { regions, indexOffset, indexSize } = layoutPack([
      { path: 'far.txt', mimeType: 'text/plain', data: text, offset: ENTRY_OFFSET },
    ])
    const TOTAL_SIZE = 2 * 1024 * 1024 * 1024
    const source = new SparseSource(TOTAL_SIZE, regions, 1024 * 1024)

    const reader = await PackReader.fromSource(source)

    expect(reader.metadata.entryCount).toBe(1)
    expect(reader.hasEntry('far.txt')).toBe(true)
    expect(reader.listEntries().map((entry) => entry.path)).toEqual(['far.txt'])

    const data = await reader.readEntry('far.txt')
    expect(new TextDecoder().decode(data)).toBe('sparse entry payload')

    const range = await reader.readEntryRange('far.txt', 7, 12)
    expect(new TextDecoder().decode(range)).toBe('entry')

    expect(source.reads).toEqual([
      { offset: 0, length: HEADER_SIZE },
      { offset: indexOffset, length: indexSize },
      { offset: ENTRY_OFFSET, length: text.byteLength },
      { offset: ENTRY_OFFSET + 7, length: 5 },
    ])
    expect(source.bytesRead).toBeLessThan(4096)
  })
})

describe('PackReader.fromOPFS の部分読み', () => {
  /** OPFS の `File` を模したオブジェクト。全体読み（`arrayBuffer()`）を数える。 */
  class MockFile {
    readonly reads: ReadRange[] = []
    wholeFileReads = 0

    constructor(private readonly bytes: Uint8Array) {}

    get size(): number {
      return this.bytes.byteLength
    }

    async arrayBuffer(): Promise<ArrayBuffer> {
      this.wholeFileReads += 1
      return this.bytes.slice().buffer as ArrayBuffer
    }

    slice(start = 0, end: number = this.bytes.byteLength) {
      this.reads.push({ offset: start, length: Math.max(0, end - start) })
      return {
        size: Math.max(0, end - start),
        arrayBuffer: async () => this.bytes.slice(start, end).buffer as ArrayBuffer,
      }
    }
  }

  it('arrayBuffer() を呼ばずに slice() で必要な範囲だけ読む', async () => {
    const { pack } = await buildTestPack()
    const file = new MockFile(new Uint8Array(pack))
    const handle = {
      kind: 'file',
      name: 'mock.nartik',
      getFile: async () => file,
    } as unknown as FileSystemFileHandle
    const { indexOffset, indexSize } = indexBounds(pack)

    const reader = await PackReader.fromOPFS(handle)
    const info = reader.getEntryInfo('meta.json')!
    const data = await reader.readEntry('meta.json')

    expect(new TextDecoder().decode(data)).toBe('{"title":"partial"}')
    expect(file.wholeFileReads).toBe(0)
    expect(file.reads).toEqual([
      { offset: 0, length: HEADER_SIZE },
      { offset: indexOffset, length: indexSize },
      { offset: Number(info.offset), length: info.compressedSize },
    ])
  })
})

describe('PackReader.fromSource の検証', () => {
  it('ヘッダに満たないソースを拒否する', async () => {
    await expect(
      PackReader.fromSource(packSourceFromBytes(new Uint8Array(HEADER_SIZE - 1))),
    ).rejects.toThrow(PackCorruptedError)
  })

  it('v2 の pack を拒否する', async () => {
    const bytes = new Uint8Array(
      serializeHeader({
        magic: MAGIC_NUMBER,
        version: 2,
        flags: PackFlags.None,
        reserved: 0,
        indexOffset: BigInt(HEADER_SIZE),
        indexSize: BigInt(4),
        entryCount: 0,
        createdAt: BigInt(0),
        checksum: 0,
      }),
    )
    await expect(PackReader.fromSource(packSourceFromBytes(bytes))).rejects.toThrow(
      PackVersionError,
    )
  })

  it('index の CRC 不一致を拒否する', async () => {
    const { pack } = await buildTestPack()
    const { indexOffset } = indexBounds(pack)
    const bytes = new Uint8Array(pack)
    bytes[indexOffset + 3] ^= 0xff

    await expect(PackReader.fromSource(packSourceFromBytes(bytes))).rejects.toThrow(
      PackCorruptedError,
    )
  })

  it('index がソースの範囲外なら拒否する', async () => {
    const { pack } = await buildTestPack()
    const { indexOffset } = indexBounds(pack)
    const truncated = new Uint8Array(pack.slice(0, indexOffset + 4))

    await expect(PackReader.fromSource(packSourceFromBytes(truncated))).rejects.toThrow(
      'Index extends beyond buffer',
    )
  })

  it('暗号化 pack を鍵なしで拒否し、正しい鍵でだけ復号する', async () => {
    const PRK = Uint8Array.from({ length: 32 }, (_, index) => index)
    const builder = new PackBuilder({ packRootKey: PRK, packId: 'pack-source' })
    builder.addEntry('secret.txt', new TextEncoder().encode('Secret source'), 'text/plain')
    const pack = await builder.build()
    const source = new RecordingSource(new Uint8Array(pack))
    const reader = await PackReader.fromSource(source)

    await expect(reader.readEntry('secret.txt')).rejects.toThrow(PackKeyRequiredError)

    const data = await reader.readEntry('secret.txt', {
      packRootKey: PRK,
      packId: 'pack-source',
    })
    expect(new TextDecoder().decode(data)).toBe('Secret source')

    await expect(
      reader.readEntry('secret.txt', {
        packRootKey: Uint8Array.from({ length: 32 }, (_, index) => 255 - index),
        packId: 'pack-source',
      }),
    ).rejects.toThrow(PackCorruptedError)

    // 触るのは暗号文の範囲だけ（鍵なしの読み出しはソースに触れる前に落ちる）
    const info = reader.getEntryInfo('secret.txt')!
    expect(source.reads.slice(2)).toEqual([
      { offset: Number(info.offset), length: info.compressedSize },
      { offset: Number(info.offset), length: info.compressedSize },
    ])
  })
})

describe('PackReader.fromBuffer（ビュー）', () => {
  it('ArrayBuffer の一部を指すビューでも読める（byteOffset を保つ）', async () => {
    const { pack } = await buildTestPack()
    const padded = new Uint8Array(pack.byteLength + 16)
    padded.set(new Uint8Array(pack), 8)
    const view = padded.subarray(8, 8 + pack.byteLength)

    const reader = PackReader.fromBuffer(view)

    expect(reader.metadata.version).toBe(FORMAT_VERSION)
    expect(reader.listEntries().map((entry) => entry.path)).toEqual([
      'meta.json',
      'pages/big.bin',
    ])
    expect(new TextDecoder().decode(await reader.readEntry('meta.json'))).toBe(
      '{"title":"partial"}',
    )
  })
})
