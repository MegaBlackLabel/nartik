import { describe, it, expect } from 'vitest'
import { expectBytesEqual } from './byte-compare'

describe('expectBytesEqual', () => {
  it('passes for identical byte arrays', () => {
    expect(() =>
      expectBytesEqual(new Uint8Array([1, 2, 3]), new Uint8Array([1, 2, 3])),
    ).not.toThrow()
    expect(() => expectBytesEqual(new Uint8Array(0), new Uint8Array(0))).not.toThrow()
  })

  it('fails when the lengths differ', () => {
    expect(() => expectBytesEqual(new Uint8Array([1, 2]), new Uint8Array([1, 2, 3]))).toThrow(
      /length/,
    )
  })

  it('fails with the offset of the first differing byte', () => {
    const actual = new Uint8Array([1, 2, 3, 4])
    const expected = new Uint8Array([1, 2, 9, 4])

    expect(() => expectBytesEqual(actual, expected)).toThrow(/byte\[2\]/)
  })

  it('scans the whole array (a difference in the last byte is reported)', () => {
    const actual = new Uint8Array(1024 * 1024)
    const expected = new Uint8Array(1024 * 1024)
    expected[expected.byteLength - 1] = 1

    expect(() => expectBytesEqual(actual, expected)).toThrow(/byte\[1048575\]/)
  })
})
