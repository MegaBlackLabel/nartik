/**
 * pack の読み出し元。
 *
 * `PackReader` はこの抽象越しに読むので、pack 全体をメモリに載せずに
 * 「ヘッダ → index → 必要なエントリ」だけを読める（2 GiB / 10 GiB 級の pack を想定）。
 * Range 対応の HTTP レスポンスや OPFS の `File` なども、この形に合わせれば
 * reader から直接使える。
 */
export interface PackSource {
  /** ソース全体のバイト数。 */
  readonly size: number

  /**
   * `offset` から最大 `length` バイトを読む。
   *
   * EOF に達した場合は要求より短い配列を返してよい（読み出し側が継ぎ足す）。
   * 返す配列は、要求範囲の外を触らないこと。
   */
  read(offset: number, length: number): Promise<Uint8Array>
}

/**
 * メモリ上のバイト列をそのまま読むソース（`fromBuffer` 用）。
 *
 * `read` はビューを返すのでコピーしない。`PackReader.readEntry` が
 * 返り値を必要に応じてコピーする。
 */
export function packSourceFromBytes(bytes: Uint8Array): PackSource {
  return {
    size: bytes.byteLength,
    async read(offset, length) {
      if (offset >= bytes.byteLength) return new Uint8Array(0)
      return bytes.subarray(offset, Math.min(offset + length, bytes.byteLength))
    },
  }
}

/**
 * `Blob` / `File` を `slice()` で部分読みするソース（`fromOPFS` 用）。
 *
 * `file.arrayBuffer()` は呼ばないので、pack 全体をメモリに載せない。
 */
export function packSourceFromBlob(blob: Blob): PackSource {
  return {
    size: blob.size,
    async read(offset, length) {
      if (length <= 0) return new Uint8Array(0)
      return new Uint8Array(await blob.slice(offset, offset + length).arrayBuffer())
    },
  }
}
