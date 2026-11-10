/**
 * pack v3（ルート鍵 + ラップ）の仕様適合テスト。
 *
 * 期待値は `docs/spec/10-pack-keys.md` §8 のテストベクタそのもの
 * （アプリ側の `crates/nartik/tests/keys_v3.rs` が同じ値を固定している）。
 * **Rust 版と TS 版のバイト一致の正**なので、値を書き換えるときは仕様書と
 * 実装を同時に直すこと。
 */

import { describe, it, expect } from 'vitest'
import {
  APP_SALT,
  MAX_PASSPHRASE_ITERATIONS,
  SUB_WRAP_ITERATIONS,
  WRAP_AAD_PREFIX,
  deriveOwnerId,
  derivePackKey,
  derivePassphraseKek,
  deriveSubWrapKek,
  unwrapPackRoot,
  type RootKeyWrap,
} from '../auth/identity-key.js'
import { parseKeyBundle, unlockPackRoot } from '../auth/key-bundle.js'
import { PackKeyBundleError, PackKeyError } from '../errors.js'

const VECTOR_OWNER_ID = '27b44245034c0ede5be981b0d5d07ab78ce95311defd60ce9d9e8fe2bc25ab7d'
const VECTOR_KEK_HEX = 'd76f7af69d173784da3876982bf29fbf6e35bf79534ea30cd3de3dc4bf62ecc5'
const VECTOR_PACK_KEY_HEX = 'd31e08ee0ca212fdd318a543e187d47549fa45590fcc69b5af670cebce28bccc'
const VECTOR_NONCE_HEX = '000102030405060708090a0b'
const VECTOR_CIPHERTEXT_HEX =
  '756655214168acab16e030def3d23f1a9be48a63a76f696c72b324d65533daf3' +
  '38d683031070104af7987cd683a77d4b'
const VECTOR_SUB = 'test-sub'
const VECTOR_PACK_ID = 'test-pack'

const enc = new TextEncoder()

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

/** §8 のベクタで使う PRK（`00 01 … 1f`）。 */
function vectorPackRootKey(): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => index)
}

/** §8 のベクタ AAD（`ligrol-pack-root:1:<owner_id>`）。 */
function wrapAad(ownerId: string) {
  return enc.encode(`${WRAP_AAD_PREFIX}${ownerId}`)
}

async function importAesGcmKey(raw: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    'raw',
    raw as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** §8 の `sub` ラップ（PRK 32B + タグ 16B = 48B）。 */
const VECTOR_WRAP: RootKeyWrap = {
  kind: 'sub',
  kdf: 'pbkdf2-sha256',
  iterations: SUB_WRAP_ITERATIONS,
  salt: enc.encode(APP_SALT),
  nonce: bytesFromHex(VECTOR_NONCE_HEX),
  ciphertext: bytesFromHex(VECTOR_CIPHERTEXT_HEX),
}

describe('pack v3 KDF test vectors (spec 10 §8)', () => {
  it('owner_id("test-sub") matches the spec vector', async () => {
    await expect(deriveOwnerId(VECTOR_SUB)).resolves.toBe(VECTOR_OWNER_ID)
  })

  it('KEK_sub("test-sub") matches the spec vector (v2 master key, same formula)', async () => {
    const kek = await deriveSubWrapKek(VECTOR_SUB)
    expect(kek).toHaveLength(32)
    expect(hexFromBytes(kek)).toBe(VECTOR_KEK_HEX)
  })

  it('pack_key v3 = HKDF(PRK, pack_id) matches the spec vector', async () => {
    const packKey = await derivePackKey(vectorPackRootKey(), VECTOR_PACK_ID)
    expect(packKey).toHaveLength(32)
    expect(hexFromBytes(packKey)).toBe(VECTOR_PACK_KEY_HEX)
  })

  it('pack_key depends on pack_id (different pack → different key)', async () => {
    const other = await derivePackKey(vectorPackRootKey(), 'other-pack')
    expect(hexFromBytes(other)).not.toBe(VECTOR_PACK_KEY_HEX)
  })

  it('the wrap AAD is "ligrol-pack-root:1:" + owner_id', () => {
    expect(`${WRAP_AAD_PREFIX}${VECTOR_OWNER_ID}`).toBe(
      'ligrol-pack-root:1:27b44245034c0ede5be981b0d5d07ab78ce95311defd60ce9d9e8fe2bc25ab7d',
    )
  })
})

describe('pack v3 wrap test vector (spec 10 §8)', () => {
  it('the vector wrap carries the spec nonce and 48-byte ciphertext', () => {
    expect(hexFromBytes(VECTOR_WRAP.nonce)).toBe(VECTOR_NONCE_HEX)
    expect(hexFromBytes(VECTOR_WRAP.ciphertext)).toBe(VECTOR_CIPHERTEXT_HEX)
    expect(VECTOR_WRAP.ciphertext).toHaveLength(48)
  })

  it('unwrapPackRoot recovers PRK 00..1f from the spec ciphertext', async () => {
    const kek = await deriveSubWrapKek(VECTOR_SUB)
    const prk = await unwrapPackRoot(VECTOR_WRAP, kek, VECTOR_OWNER_ID)
    expect(hexFromBytes(prk)).toBe(hexFromBytes(vectorPackRootKey()))
  })

  it('does not unwrap with another owner_id (AAD mismatch)', async () => {
    const kek = await deriveSubWrapKek(VECTOR_SUB)
    await expect(unwrapPackRoot(VECTOR_WRAP, kek, 'other-owner')).rejects.toThrow(PackKeyError)
  })

  it('does not unwrap with a wrong KEK', async () => {
    const kek = await deriveSubWrapKek('other-sub')
    await expect(unwrapPackRoot(VECTOR_WRAP, kek, VECTOR_OWNER_ID)).rejects.toThrow(PackKeyError)
  })

  it('rejects a KEK that is not 32 bytes', async () => {
    await expect(
      unwrapPackRoot(VECTOR_WRAP, new Uint8Array(16), VECTOR_OWNER_ID),
    ).rejects.toThrow(PackKeyError)
  })

  it('rejects an unknown kdf', async () => {
    const kek = await deriveSubWrapKek(VECTOR_SUB)
    const wrap = { ...VECTOR_WRAP, kdf: 'argon2id' } as unknown as RootKeyWrap
    await expect(unwrapPackRoot(wrap, kek, VECTOR_OWNER_ID)).rejects.toThrow(PackKeyError)
  })
})

describe('derivePassphraseKek', () => {
  it('normalizes NFKC before deriving (composed and decomposed agree)', async () => {
    const salt = bytesFromHex('00112233445566778899aabbccddeeff')
    const composed = await derivePassphraseKek('ばすわーど', salt, 1000)
    // "ば" を分解した形（NFKC 正規化しないと別の鍵になる）
    const decomposed = await derivePassphraseKek('は\u3099すわーど', salt, 1000)
    expect(hexFromBytes(composed)).toBe(hexFromBytes(decomposed))
  })

  it('uses the recorded iterations (different iterations → different KEK)', async () => {
    const salt = bytesFromHex('00112233445566778899aabbccddeeff')
    const first = await derivePassphraseKek('correct horse battery', salt, 1000)
    const second = await derivePassphraseKek('correct horse battery', salt, 2000)
    expect(hexFromBytes(first)).not.toBe(hexFromBytes(second))
  })

  it('rejects iterations of 0 before running PBKDF2', async () => {
    await expect(
      derivePassphraseKek('correct horse battery', new Uint8Array(16), 0),
    ).rejects.toThrow(PackKeyError)
  })

  it('rejects iterations above the 10M cap before running PBKDF2', async () => {
    await expect(
      derivePassphraseKek(
        'correct horse battery',
        new Uint8Array(16),
        MAX_PASSPHRASE_ITERATIONS + 1,
      ),
    ).rejects.toThrow(PackKeyError)
  })
})

describe('derivePackKey', () => {
  it('rejects a pack root key that is not 32 bytes', async () => {
    await expect(derivePackKey(new Uint8Array(16), 'pack-1')).rejects.toThrow(PackKeyError)
  })
})

/** §3.2 の bundle（`sub` ラップ 1 本）を JSON 文字列にする。 */
function subBundleJson(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({
    format_version: 1,
    owner_id: VECTOR_OWNER_ID,
    created_at: 1790000000000,
    updated_at: 1790000000000,
    wraps: [
      {
        kind: 'sub',
        kdf: 'pbkdf2-sha256',
        iterations: SUB_WRAP_ITERATIONS,
        salt: base64FromBytes(VECTOR_WRAP.salt),
        nonce: base64FromBytes(VECTOR_WRAP.nonce),
        ciphertext: base64FromBytes(VECTOR_WRAP.ciphertext),
      },
    ],
    ...overrides,
  })
}

/** PRK を KEK でラップした `wraps[]` 要素（JSON 用）。 */
async function wrapJson(params: {
  kind: 'sub' | 'passphrase'
  kek: Uint8Array
  salt: Uint8Array
  iterations: number
  ownerId: string
  nonce: Uint8Array
}): Promise<Record<string, unknown>> {
  const key = await importAesGcmKey(params.kek)
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv: params.nonce as BufferSource,
        additionalData: wrapAad(params.ownerId),
      },
      key,
      vectorPackRootKey() as BufferSource,
    ),
  )
  return {
    kind: params.kind,
    kdf: 'pbkdf2-sha256',
    iterations: params.iterations,
    salt: base64FromBytes(params.salt),
    nonce: base64FromBytes(params.nonce),
    ciphertext: base64FromBytes(ciphertext),
  }
}

describe('parseKeyBundle', () => {
  it('parses the spec bundle shape into decoded bytes', () => {
    const bundle = parseKeyBundle(subBundleJson())
    expect(bundle.format_version).toBe(1)
    expect(bundle.owner_id).toBe(VECTOR_OWNER_ID)
    expect(bundle.created_at).toBe(1790000000000)
    expect(bundle.wraps).toHaveLength(1)
    const wrap = bundle.wraps[0]!
    expect(wrap.kind).toBe('sub')
    expect(wrap.kdf).toBe('pbkdf2-sha256')
    expect(wrap.iterations).toBe(SUB_WRAP_ITERATIONS)
    expect(hexFromBytes(wrap.salt)).toBe(hexFromBytes(enc.encode(APP_SALT)))
    expect(hexFromBytes(wrap.nonce)).toBe(VECTOR_NONCE_HEX)
    expect(hexFromBytes(wrap.ciphertext)).toBe(VECTOR_CIPHERTEXT_HEX)
  })

  it('rejects an unknown format_version as an unreadable version', () => {
    const error = (() => {
      try {
        parseKeyBundle(subBundleJson({ format_version: 99 }))
        return null
      } catch (thrown) {
        return thrown
      }
    })()
    expect(error).toBeInstanceOf(PackKeyBundleError)
    expect((error as PackKeyBundleError).version).toBe(99)
  })

  it('rejects a bundle without format_version', () => {
    expect(() => parseKeyBundle('{"owner_id":"x","wraps":[]}')).toThrow(PackKeyBundleError)
  })

  it('rejects invalid JSON', () => {
    expect(() => parseKeyBundle('not json')).toThrow(PackKeyBundleError)
  })

  it('rejects iterations of 0 before running PBKDF2', () => {
    const json = subBundleJson()
    const withZero = json.replace(`"iterations":${SUB_WRAP_ITERATIONS}`, '"iterations":0')
    expect(() => parseKeyBundle(withZero)).toThrow(PackKeyBundleError)
  })

  it('rejects iterations above the 10M cap before running PBKDF2', () => {
    const json = subBundleJson()
    const withHuge = json.replace(
      `"iterations":${SUB_WRAP_ITERATIONS}`,
      `"iterations":${MAX_PASSPHRASE_ITERATIONS + 1}`,
    )
    expect(() => parseKeyBundle(withHuge)).toThrow(PackKeyBundleError)
  })

  it('accepts iterations exactly at the 10M cap', () => {
    const json = subBundleJson().replace(
      `"iterations":${SUB_WRAP_ITERATIONS}`,
      `"iterations":${MAX_PASSPHRASE_ITERATIONS}`,
    )
    expect(parseKeyBundle(json).wraps[0]!.iterations).toBe(MAX_PASSPHRASE_ITERATIONS)
  })

  it('rejects an unknown kind', () => {
    const json = subBundleJson().replace('"kind":"sub"', '"kind":"pin"')
    expect(() => parseKeyBundle(json)).toThrow(PackKeyBundleError)
  })

  it('rejects an unknown kdf', () => {
    const json = subBundleJson().replace('"kdf":"pbkdf2-sha256"', '"kdf":"argon2id"')
    expect(() => parseKeyBundle(json)).toThrow(PackKeyBundleError)
  })

  it('rejects base64url nonces (標準アルファベットのみ)', () => {
    const json = subBundleJson().replace(base64FromBytes(VECTOR_WRAP.nonce), 'AAECAwQFBgcICQoL-_')
    expect(() => parseKeyBundle(json)).toThrow(PackKeyBundleError)
  })

  it('rejects a nonce that is not 12 bytes', () => {
    const json = subBundleJson().replace(base64FromBytes(VECTOR_WRAP.nonce), base64FromBytes(new Uint8Array(16)))
    expect(() => parseKeyBundle(json)).toThrow(PackKeyBundleError)
  })

  it('rejects a ciphertext that is not 48 bytes', () => {
    const json = subBundleJson().replace(
      base64FromBytes(VECTOR_WRAP.ciphertext),
      base64FromBytes(new Uint8Array(32)),
    )
    expect(() => parseKeyBundle(json)).toThrow(PackKeyBundleError)
  })

  it('rejects an empty salt', () => {
    const json = subBundleJson().replace(base64FromBytes(VECTOR_WRAP.salt), '')
    expect(() => parseKeyBundle(json)).toThrow(PackKeyBundleError)
  })

  it('rejects duplicate wrap kinds (同じ kind は置換されるべきもの)', () => {
    const wrap = JSON.parse(subBundleJson()).wraps[0]
    const json = JSON.stringify({
      format_version: 1,
      owner_id: VECTOR_OWNER_ID,
      created_at: 0,
      updated_at: 0,
      wraps: [wrap, wrap],
    })
    expect(() => parseKeyBundle(json)).toThrow(PackKeyBundleError)
  })

  it('rejects a non-string owner_id', () => {
    expect(() => parseKeyBundle(subBundleJson({ owner_id: 42 }))).toThrow(PackKeyBundleError)
  })
})

describe('unlockPackRoot', () => {
  const PASS_SALT = bytesFromHex('00112233445566778899aabbccddeeff')
  const PASS_NONCE = bytesFromHex('0b0a09080706050403020100')

  it('unlocks the spec bundle with the sub wrap', async () => {
    const bundle = parseKeyBundle(subBundleJson())
    const prk = await unlockPackRoot(bundle, { sub: VECTOR_SUB })
    expect(hexFromBytes(prk)).toBe(hexFromBytes(vectorPackRootKey()))
  })

  it('refuses a bundle whose owner_id does not match the session sub', async () => {
    const bundle = parseKeyBundle(subBundleJson())
    await expect(unlockPackRoot(bundle, { sub: 'other-sub' })).rejects.toThrow(
      PackKeyBundleError,
    )
  })

  it('requires a passphrase when the bundle has a passphrase wrap', async () => {
    const passphraseKek = await derivePassphraseKek('correct horse battery', PASS_SALT, 1000)
    const passphraseWrap = await wrapJson({
      kind: 'passphrase',
      kek: passphraseKek,
      salt: PASS_SALT,
      iterations: 1000,
      ownerId: VECTOR_OWNER_ID,
      nonce: PASS_NONCE,
    })
    const subWrap = JSON.parse(subBundleJson()).wraps[0]
    const bundle = parseKeyBundle(
      JSON.stringify({
        format_version: 1,
        owner_id: VECTOR_OWNER_ID,
        created_at: 0,
        updated_at: 0,
        wraps: [subWrap, passphraseWrap],
      }),
    )

    await expect(unlockPackRoot(bundle, { sub: VECTOR_SUB })).rejects.toThrow(PackKeyError)
  })

  it('never falls back to the sub wrap when the passphrase is wrong', async () => {
    const passphraseKek = await derivePassphraseKek('correct horse battery', PASS_SALT, 1000)
    const passphraseWrap = await wrapJson({
      kind: 'passphrase',
      kek: passphraseKek,
      salt: PASS_SALT,
      iterations: 1000,
      ownerId: VECTOR_OWNER_ID,
      nonce: PASS_NONCE,
    })
    const subWrap = JSON.parse(subBundleJson()).wraps[0]
    const bundle = parseKeyBundle(
      JSON.stringify({
        format_version: 1,
        owner_id: VECTOR_OWNER_ID,
        created_at: 0,
        updated_at: 0,
        wraps: [subWrap, passphraseWrap],
      }),
    )

    await expect(
      unlockPackRoot(bundle, { sub: VECTOR_SUB, passphrase: 'wrong passphrase' }),
    ).rejects.toThrow(PackKeyError)
  })

  it('unlocks with the passphrase wrap when the passphrase matches', async () => {
    const passphraseKek = await derivePassphraseKek('correct horse battery', PASS_SALT, 1000)
    const passphraseWrap = await wrapJson({
      kind: 'passphrase',
      kek: passphraseKek,
      salt: PASS_SALT,
      iterations: 1000,
      ownerId: VECTOR_OWNER_ID,
      nonce: PASS_NONCE,
    })
    const bundle = parseKeyBundle(
      JSON.stringify({
        format_version: 1,
        owner_id: VECTOR_OWNER_ID,
        created_at: 0,
        updated_at: 0,
        wraps: [passphraseWrap],
      }),
    )

    const prk = await unlockPackRoot(bundle, {
      sub: VECTOR_SUB,
      passphrase: 'correct horse battery',
    })
    expect(hexFromBytes(prk)).toBe(hexFromBytes(vectorPackRootKey()))
  })

  it('uses the sub wrap only when the caller skips the passphrase', async () => {
    const passphraseKek = await derivePassphraseKek('correct horse battery', PASS_SALT, 1000)
    const passphraseWrap = await wrapJson({
      kind: 'passphrase',
      kek: passphraseKek,
      salt: PASS_SALT,
      iterations: 1000,
      ownerId: VECTOR_OWNER_ID,
      nonce: PASS_NONCE,
    })
    const subWrap = JSON.parse(subBundleJson()).wraps[0]
    const bundle = parseKeyBundle(
      JSON.stringify({
        format_version: 1,
        owner_id: VECTOR_OWNER_ID,
        created_at: 0,
        updated_at: 0,
        wraps: [subWrap, passphraseWrap],
      }),
    )

    const prk = await unlockPackRoot(bundle, {
      sub: VECTOR_SUB,
      skipPassphrase: true,
    })
    expect(hexFromBytes(prk)).toBe(hexFromBytes(vectorPackRootKey()))
  })

  it('fails when only a passphrase wrap exists and it was skipped (パスフレーズ必須モード)', async () => {
    const passphraseKek = await derivePassphraseKek('correct horse battery', PASS_SALT, 1000)
    const passphraseWrap = await wrapJson({
      kind: 'passphrase',
      kek: passphraseKek,
      salt: PASS_SALT,
      iterations: 1000,
      ownerId: VECTOR_OWNER_ID,
      nonce: PASS_NONCE,
    })
    const bundle = parseKeyBundle(
      JSON.stringify({
        format_version: 1,
        owner_id: VECTOR_OWNER_ID,
        created_at: 0,
        updated_at: 0,
        wraps: [passphraseWrap],
      }),
    )

    await expect(
      unlockPackRoot(bundle, { sub: VECTOR_SUB, skipPassphrase: true }),
    ).rejects.toThrow(PackKeyError)
  })
})
