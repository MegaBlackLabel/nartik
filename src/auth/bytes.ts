/**
 * 仕様で定めた wire 表現のコーデック（`docs/spec/10-pack-keys.md` §3.2 / §11.3）。
 *
 * base64 は**標準アルファベット + padding**（base64url は使わない）、hex は
 * 32 バイト固定の小文字表現。Rust 版（`crates/nartik/src/keys.rs` の
 * `BASE64` / `hex_encode` / `hex_decode_32`）と同じ規則。
 */

/** 標準アルファベット + padding の base64 だけをデコードする（base64url は使わない）。 */
export function decodeBase64(value: string): Uint8Array | null {
  if (value.length % 4 !== 0 || !/^[A-Za-z0-9+/]*={0,2}$/.test(value)) {
    return null
  }
  try {
    const binary = atob(value)
    const bytes = new Uint8Array(binary.length)
    for (let index = 0; index < binary.length; index++) {
      bytes[index] = binary.charCodeAt(index)
    }
    return bytes
  } catch {
    return null
  }
}

/** 標準アルファベット + padding の base64 にエンコードする。 */
export function encodeBase64(bytes: Uint8Array): string {
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

/** 32 バイトの小文字 hex（`content_hmac` の表現）。 */
export function hexFromBytes(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * hex 64 文字を 32 バイトに戻す（大文字も許す。書き出しは常に小文字）。
 * 長さ・文字種が違えば `null`。
 */
export function hex32FromString(value: string): Uint8Array | null {
  if (value.length !== 64 || !/^[0-9a-fA-F]{64}$/.test(value)) {
    return null
  }
  const bytes = new Uint8Array(32)
  for (let index = 0; index < bytes.length; index++) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16)
  }
  return bytes
}
