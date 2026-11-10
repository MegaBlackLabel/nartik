/**
 * §11 バックアップの暗号化（`ligrol-backup.json` v3 の封筒）の仕様適合テスト。
 *
 * 期待値は `docs/spec/10-pack-keys.md` §11.6 のテストベクタそのもの
 * （アプリ側の `crates/nartik/tests/backup_envelope.rs` が同じ値を固定している）。
 * **Rust 版と TS 版のバイト一致の正**なので、値を書き換えるときは仕様書と
 * 実装を同時に直すこと。
 */

import { describe, it, expect } from 'vitest'
import {
  BACKUP_ALG,
  BACKUP_FORMAT_VERSION,
  BACKUP_KDF,
  backupAad,
  deriveBackupKey,
  openBackupEnvelope,
  parseBackupEnvelope,
  sealBackupEnvelope,
  serializeBackupEnvelope,
  type BackupEnvelope,
} from '../auth/backup-envelope.js'
import { deriveOwnerId } from '../auth/identity-key.js'
import { PackCorruptedError, PackKeyError } from '../errors.js'

const VECTOR_SUB = 'test-sub'
const VECTOR_OWNER_ID = '27b44245034c0ede5be981b0d5d07ab78ce95311defd60ce9d9e8fe2bc25ab7d'
const VECTOR_CIPHER_KEY_HEX = '1bf68ba47f38341eb05bdc83a1c7e8d4a4625d3f45100618bdbc584cf46e3d96'
const VECTOR_HASH_KEY_HEX = 'ec18f9e823762350c0d149e259a51db53303b9302674bd9f90954a2ed88864c7'
const VECTOR_NONCE_HEX = '0b0a09080706050403020100'
const VECTOR_PLAINTEXT = '{"format_version":3,"tables":{}}'
const VECTOR_CIPHERTEXT_HEX =
  '445576399467ff7398a654eec82cf5cbbd50c2f8ca853da6690a5b958aed8c69' +
  'ef68849f6bcc5afbc5a64f19b801d27c'
const VECTOR_CONTENT_HMAC_HEX = '01dd31a61fa0bff7ce79dde91e1e9ba878821efd0966b19d390ddda9cf226e0c'

function bytesFromHex(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2)
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16)
  }
  return out
}

function hexFromBytes(value: Uint8Array): string {
  return Array.from(value)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

function base64FromBytes(value: Uint8Array): string {
  let binary = ''
  for (const byte of value) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary)
}

/**
 * **Rust 版が実際に書き出したバイト列**（`crates/nartik` を `cargo run` で叩いて
 * 取り出した `BackupEnvelope::to_json()` の出力そのもの。入力はこのファイルの
 * ベクタと同じ: PRK = `00 01 … 1f` / `nonce = 0b 0a … 00` / 平文 = `VECTOR_PLAINTEXT` /
 * `owner_id = deriveOwnerId("test-sub")`）。
 *
 * TS 版が①このバイト列を読める ②同じバイト列を書き出せる、の両方をここで固定する。
 */
const RUST_ENVELOPE_JSON =
  '{"format_version":3,' +
  `"owner_id":"${VECTOR_OWNER_ID}",` +
  '"encryption":{"alg":"aes-256-gcm","kdf":"hkdf-sha256",' +
  '"nonce":"CwoJCAcGBQQDAgEA",' +
  '"ciphertext":"RFV2OZRn/3OYplTuyCz1y71QwvjKhT2maQpblYrtjGnvaISfa8xa+8WmTxm4AdJ8"},' +
  `"content_hmac":"${VECTOR_CONTENT_HMAC_HEX}"}`

/** §11.6 のベクタで使う PRK（`00 01 … 1f`）。 */
function vectorPackRootKey(): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => index)
}

async function unwrap<T>(promise: Promise<T>): Promise<Error> {
  try {
    await promise
  } catch (error) {
    return error as Error
  }
  throw new Error('expected the promise to reject')
}

describe('deriveBackupKey', () => {
  it('derives the two backup keys of the spec vector', async () => {
    const { cipherKey, hashKey } = await deriveBackupKey(vectorPackRootKey())

    expect(hexFromBytes(cipherKey)).toBe(VECTOR_CIPHER_KEY_HEX)
    expect(hexFromBytes(hashKey)).toBe(VECTOR_HASH_KEY_HEX)
  })

  it('rejects a pack root key that is not 32 bytes', async () => {
    const error = await unwrap(deriveBackupKey(new Uint8Array(16)))

    expect(error).toBeInstanceOf(PackKeyError)
  })
})

describe('backupAad', () => {
  it('matches the spec vector AAD', async () => {
    const ownerId = await deriveOwnerId(VECTOR_SUB)

    expect(ownerId).toBe(VECTOR_OWNER_ID)
    expect(new TextDecoder().decode(backupAad(ownerId))).toBe(
      `ligrol-backup:3:${VECTOR_OWNER_ID}`,
    )
  })
})

describe('sealBackupEnvelope', () => {
  it('produces the ciphertext and content_hmac of the spec vector', async () => {
    const envelope = await sealBackupEnvelope(
      VECTOR_PLAINTEXT,
      vectorPackRootKey(),
      VECTOR_OWNER_ID,
      bytesFromHex(VECTOR_NONCE_HEX),
    )

    expect(envelope.formatVersion).toBe(BACKUP_FORMAT_VERSION)
    expect(envelope.alg).toBe(BACKUP_ALG)
    expect(envelope.kdf).toBe(BACKUP_KDF)
    expect(hexFromBytes(envelope.nonce)).toBe(VECTOR_NONCE_HEX)
    expect(hexFromBytes(envelope.ciphertext)).toBe(VECTOR_CIPHERTEXT_HEX)
    expect(hexFromBytes(envelope.contentHmac)).toBe(VECTOR_CONTENT_HMAC_HEX)
  })

  it('keeps the content_hmac and changes the ciphertext when sealing twice', async () => {
    const first = await sealBackupEnvelope(VECTOR_PLAINTEXT, vectorPackRootKey(), VECTOR_OWNER_ID)
    const second = await sealBackupEnvelope(VECTOR_PLAINTEXT, vectorPackRootKey(), VECTOR_OWNER_ID)

    // nonce は乱数（仕様 §11.3）— 毎回変わるが、平文の HMAC は内容だけで決まる。
    expect(hexFromBytes(second.nonce)).not.toBe(hexFromBytes(first.nonce))
    expect(hexFromBytes(second.ciphertext)).not.toBe(hexFromBytes(first.ciphertext))
    expect(hexFromBytes(second.contentHmac)).toBe(hexFromBytes(first.contentHmac))
  })
})

describe('serializeBackupEnvelope', () => {
  it('writes the wire form of the spec vector', async () => {
    const envelope = await sealBackupEnvelope(
      VECTOR_PLAINTEXT,
      vectorPackRootKey(),
      VECTOR_OWNER_ID,
      bytesFromHex(VECTOR_NONCE_HEX),
    )

    expect(serializeBackupEnvelope(envelope)).toBe(
      '{"format_version":3,' +
        `"owner_id":"${VECTOR_OWNER_ID}",` +
        `"encryption":{"alg":"${BACKUP_ALG}","kdf":"${BACKUP_KDF}",` +
        `"nonce":"${base64FromBytes(bytesFromHex(VECTOR_NONCE_HEX))}",` +
        `"ciphertext":"${base64FromBytes(bytesFromHex(VECTOR_CIPHERTEXT_HEX))}"},` +
        `"content_hmac":"${VECTOR_CONTENT_HMAC_HEX}"}`,
    )
  })

  it('round-trips through parseBackupEnvelope', async () => {
    const envelope = await sealBackupEnvelope(
      VECTOR_PLAINTEXT,
      vectorPackRootKey(),
      VECTOR_OWNER_ID,
      bytesFromHex(VECTOR_NONCE_HEX),
    )

    const parsed = parseBackupEnvelope(serializeBackupEnvelope(envelope))

    expect(parsed.formatVersion).toBe(envelope.formatVersion)
    expect(parsed.ownerId).toBe(envelope.ownerId)
    expect(hexFromBytes(parsed.nonce)).toBe(hexFromBytes(envelope.nonce))
    expect(hexFromBytes(parsed.ciphertext)).toBe(hexFromBytes(envelope.ciphertext))
    expect(hexFromBytes(parsed.contentHmac)).toBe(hexFromBytes(envelope.contentHmac))
  })
})

describe('openBackupEnvelope', () => {
  it('reads and rewrites the exact bytes the Rust implementation writes', async () => {
    const envelope = parseBackupEnvelope(RUST_ENVELOPE_JSON)

    // ① Rust が作った封筒を読める
    await expect(openBackupEnvelope(envelope, vectorPackRootKey())).resolves.toBe(VECTOR_PLAINTEXT)
    // ② 同じバイト列を書き戻せる（JSON のキー順・base64・hex まで一致）
    expect(serializeBackupEnvelope(envelope)).toBe(RUST_ENVELOPE_JSON)
  })

  it('opens a sealed envelope with the owner_id recorded in it', async () => {
    const envelope = await sealBackupEnvelope(
      VECTOR_PLAINTEXT,
      vectorPackRootKey(),
      VECTOR_OWNER_ID,
      bytesFromHex(VECTOR_NONCE_HEX),
    )

    await expect(openBackupEnvelope(envelope, vectorPackRootKey())).resolves.toBe(VECTOR_PLAINTEXT)
  })

  it('rejects another pack root key, another owner_id and a tampered envelope', async () => {
    const envelope = await sealBackupEnvelope(
      VECTOR_PLAINTEXT,
      vectorPackRootKey(),
      VECTOR_OWNER_ID,
      bytesFromHex(VECTOR_NONCE_HEX),
    )

    const otherKey = new Uint8Array(32).fill(9)
    expect(await unwrap(openBackupEnvelope(envelope, otherKey))).toBeInstanceOf(PackCorruptedError)

    // AAD は封筒の `owner_id` ではなく呼び出し側が確認した所有者（仕様 §11.3）。
    expect(await unwrap(openBackupEnvelope(envelope, vectorPackRootKey(), 'other'))).toBeInstanceOf(
      PackCorruptedError,
    )

    const tamperedCiphertext: BackupEnvelope = {
      ...envelope,
      ciphertext: Uint8Array.from(envelope.ciphertext, (byte, index) =>
        index === 0 ? byte ^ 0xff : byte,
      ),
    }
    expect(await unwrap(openBackupEnvelope(tamperedCiphertext, vectorPackRootKey()))).toBeInstanceOf(
      PackCorruptedError,
    )

    // 平文と封筒の組が食い違う改変（仕様 §11.3）。
    const tamperedHmac: BackupEnvelope = {
      ...envelope,
      contentHmac: new Uint8Array(32).fill(7),
    }
    expect(await unwrap(openBackupEnvelope(tamperedHmac, vectorPackRootKey()))).toBeInstanceOf(
      PackCorruptedError,
    )
  })
})

describe('parseBackupEnvelope', () => {
  async function wire(overrides: Record<string, unknown> = {}): Promise<string> {
    const base = JSON.parse(
      serializeBackupEnvelope(
        await sealBackupEnvelope(
          VECTOR_PLAINTEXT,
          vectorPackRootKey(),
          VECTOR_OWNER_ID,
          bytesFromHex(VECTOR_NONCE_HEX),
        ),
      ),
    ) as Record<string, unknown>
    return JSON.stringify({ ...base, ...overrides })
  }

  it('rejects an unsupported format_version', async () => {
    const envelopeJson = await wire({ format_version: 4 })

    expect(() => parseBackupEnvelope('{"format_version":2}')).toThrow(PackCorruptedError)
    expect(() => parseBackupEnvelope(envelopeJson)).toThrow(PackCorruptedError)
  })

  it('rejects unknown alg / kdf / nonce / ciphertext / content_hmac', async () => {
    const envelope = JSON.parse(await wire()) as Record<string, unknown>
    const validEncryption = envelope.encryption as Record<string, unknown>
    const brokenEncryptions = [
      { ...validEncryption, alg: 'aes-256-cbc' },
      { ...validEncryption, kdf: 'pbkdf2-sha256' },
      { ...validEncryption, nonce: base64FromBytes(new Uint8Array(16)) },
      { ...validEncryption, nonce: 'not base64!!' },
      { ...validEncryption, ciphertext: base64FromBytes(new Uint8Array(8)) },
      { ...validEncryption, ciphertext: 'not base64!!' },
    ]
    const shortHmac = await wire({ content_hmac: 'abcd' })
    const nonHexHmac = await wire({ content_hmac: 'zz'.repeat(32) })

    for (const encryption of brokenEncryptions) {
      expect(() => parseBackupEnvelope(JSON.stringify({ ...envelope, encryption }))).toThrow(
        PackCorruptedError,
      )
    }
    expect(() => parseBackupEnvelope(shortHmac)).toThrow(PackCorruptedError)
    expect(() => parseBackupEnvelope(nonHexHmac)).toThrow(PackCorruptedError)
  })

  it('rejects something that is not a JSON object', () => {
    expect(() => parseBackupEnvelope('not json')).toThrow(PackCorruptedError)
    expect(() => parseBackupEnvelope('{}')).toThrow(PackCorruptedError)
  })
})
