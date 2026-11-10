/**
 * 大きなバイト列の比較。
 *
 * vitest の `toEqual` は 1MB の `Uint8Array` で実測 約4 秒かかる（同じデータを扱う
 * `PackBuilder.build()` は 3.4ms、`PackReader.readEntry()` は 1.8ms）。テストの目的は
 * 「バイト列がそのまま往復すること」なので、長さと先頭の不一致位置を見る比較に置き換える。
 * 失敗時は `length: ... != ...` か `byte[offset]: actual != expected` が出る。
 */
import { expect } from 'vitest'

export function expectBytesEqual(actual: Uint8Array, expected: Uint8Array): void {
  const length = Math.min(actual.byteLength, expected.byteLength)
  let index = 0
  while (index < length && actual[index] === expected[index]) index++

  const mismatch =
    actual.byteLength !== expected.byteLength
      ? `length: ${actual.byteLength} != ${expected.byteLength}`
      : index < length
        ? `byte[${index}]: ${actual[index]} != ${expected[index]}`
        : null

  expect(mismatch).toBeNull()
}
