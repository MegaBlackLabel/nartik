/**
 * pack v3 の鍵導出（仕様: `docs/spec/10-pack-keys.md` §2 / §3）。
 *
 * ```text
 * PRK (32B 乱数・アカウントごとに 1 個)
 *   └─ pack_key(pack_id) = HKDF-SHA256(ikm = PRK, salt = UTF8(pack_id),
 *                                      info = "nartik-entry-key", 32B)
 *        └─ エントリ = AES-256-GCM(key = pack_key, iv = 12B 乱数, AAD なし)
 *
 * PRK の保管 = ラップ = AES-256-GCM(KEK)(PRK) … 48B（32B の PRK + 16B のタグ）
 *   KEK_sub        = PBKDF2-SHA256(UTF8(sub) ‖ APP_SALT, APP_SALT, 100_000, 32B)
 *   KEK_passphrase = PBKDF2-SHA256(NFKC(passphrase) の UTF-8, salt, iterations, 32B)
 *   ラップの AAD    = UTF8("ligrol-pack-root:1:" + owner_id)
 * ```
 *
 * v2 との違い: **`sub` から pack 鍵は導出できない**。`sub` から導出できるのは
 * `sub` ラップの KEK だけで、PRK（＝pack 鍵の材料）は Drive の
 * `ligrol-keys.json` のラップを解いて取り出す（`unlockPackRoot`）。
 *
 * 鍵材料はこのモジュールでは平文バイト列（`Uint8Array`）として扱う
 * （WebCrypto の non-extractable key にすると §8 のテストベクタと突き合わせられない）。
 * ログ・URL・`localStorage` に出さないこと。
 */

import { PackKeyError } from '../errors.js'

/** `sub` ラップの KEK に使う salt（v2 と同一）。 */
export const APP_SALT = 'nartik-v1-identity-salt-2026'

/** `sub` ラップの PBKDF2 反復回数（v2 の master key と同一）。 */
export const SUB_WRAP_ITERATIONS = 100_000

/** パスフレーズラップの既定の反復回数（ラップごとに記録するので後から上げられる）。 */
export const PASSPHRASE_WRAP_ITERATIONS = 600_000

/** ラップの `iterations` に許容する上限（1000 万回）。 */
export const MAX_PASSPHRASE_ITERATIONS = 10_000_000

/** pack 鍵の HKDF info（v2 と同一）。 */
export const HKDF_INFO = 'nartik-entry-key'

/** ラップの AAD 接頭辞（`owner_id` を連結する — 別アカウントのラップへの差し替えを検出する）。 */
export const WRAP_AAD_PREFIX = 'ligrol-pack-root:1:'

/** 現在唯一の `kdf` 識別子。 */
export const WRAP_KDF = 'pbkdf2-sha256'

/** PRK / KEK / pack 鍵の長さ。 */
export const KEY_BYTES = 32

/** AES-GCM の nonce 長。 */
export const NONCE_BYTES = 12

/** ラップの暗号文長（32B の PRK + 16B のタグ）。 */
export const WRAP_CIPHERTEXT_BYTES = 48

/** ラップの種類（`ligrol-keys.json` の `wraps[].kind`）。 */
export type WrapKind = 'sub' | 'passphrase'

/**
 * PRK を KEK で AES-256-GCM ラップしたもの（`ligrol-keys.json` の `wraps[]` 要素）。
 * 平文は PRK 32 バイトだけなので `ciphertext` は常に 48 バイト。
 */
export interface RootKeyWrap {
  kind: WrapKind
  kdf: typeof WRAP_KDF
  iterations: number
  salt: Uint8Array
  nonce: Uint8Array
  ciphertext: Uint8Array
}

/**
 * `iterations` が PBKDF2 に渡してよい値か。
 *
 * 鍵ファイルは同期先（Drive）からも来るため、書き換えられた値で復元中の端末の
 * CPU を焼かせないよう、**PBKDF2 を走らせる前**に 0 と上限超を弾く
 * （セキュリティ評価 F06）。
 */
export function isSupportedWrapIterations(iterations: number): boolean {
  return (
    Number.isInteger(iterations) &&
    iterations > 0 &&
    iterations <= MAX_PASSPHRASE_ITERATIONS
  )
}

const enc = new TextEncoder()

// TS の `BufferSource` は ArrayBuffer 裏付けのビューしか許さない（SharedArrayBuffer を
// 排除する型）。ここで扱う鍵素材は常に ArrayBuffer 裏付けなので、WebCrypto の境界で
// `as BufferSource` に寄せる（`SharedArrayBuffer` は鍵に使わない）。
async function pbkdf2Sha256(
  password: Uint8Array,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    password as BufferSource,
    'PBKDF2',
    false,
    ['deriveBits'],
  )
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: salt as BufferSource, iterations, hash: 'SHA-256' },
    keyMaterial,
    KEY_BYTES * 8,
  )
  return new Uint8Array(bits)
}

/** `owner_id` = `SHA-256("nartik:v1:" + sub)` の小文字 hex（v2 と同一）。 */
export async function deriveOwnerId(sub: string): Promise<string> {
  const data = enc.encode(`nartik:v1:${sub}`)
  const hashBuffer = await crypto.subtle.digest('SHA-256', data)

  return Array.from(new Uint8Array(hashBuffer))
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

/**
 * `sub` ラップの KEK = `PBKDF2-SHA256(password = UTF8(sub) ‖ APP_SALT,
 * salt = APP_SALT, iterations = 100_000)`（= v2 の master key と同式）。
 *
 * **用途名を v2 の `deriveMasterKey` から変えてある**: この鍵は pack を
 * 直接復号できない（それは v2 の設計）。使えるのはラップを解くことだけ。
 */
export async function deriveSubWrapKek(sub: string): Promise<Uint8Array> {
  return pbkdf2Sha256(
    enc.encode(sub + APP_SALT),
    enc.encode(APP_SALT),
    SUB_WRAP_ITERATIONS,
  )
}

/**
 * パスフレーズラップの KEK。**NFKC 正規化してから UTF-8 化**する
 * （IME / OS による合成文字の差で同じパスフレーズが別鍵にならないようにする）。
 * `iterations` はラップに記録された値を使う（実装定数ではない）。
 */
export async function derivePassphraseKek(
  passphrase: string,
  salt: Uint8Array,
  iterations: number,
): Promise<Uint8Array> {
  if (!isSupportedWrapIterations(iterations)) {
    throw new PackKeyError(`unsupported wrap iterations: ${iterations}`)
  }
  if (salt.byteLength === 0) {
    throw new PackKeyError('passphrase wrap salt must not be empty')
  }
  return pbkdf2Sha256(enc.encode(passphrase.normalize('NFKC')), salt, iterations)
}

/**
 * ラップを KEK で解いて PRK を取り出す。
 *
 * KEK が違う・AAD の `owner_id` が違う・復号結果が 32 バイトでない場合は
 * `PackKeyError`（平文へは落とさない）。
 */
export async function unwrapPackRoot(
  wrap: RootKeyWrap,
  kek: Uint8Array,
  ownerId: string,
): Promise<Uint8Array> {
  if (wrap.kdf !== WRAP_KDF) {
    throw new PackKeyError(`unsupported wrap kdf: ${String(wrap.kdf)}`)
  }
  if (kek.byteLength !== KEY_BYTES) {
    throw new PackKeyError(`wrap KEK must be ${KEY_BYTES} bytes`)
  }
  if (wrap.nonce.byteLength !== NONCE_BYTES) {
    throw new PackKeyError(`wrap nonce must be ${NONCE_BYTES} bytes`)
  }
  if (wrap.ciphertext.byteLength !== WRAP_CIPHERTEXT_BYTES) {
    throw new PackKeyError(`wrap ciphertext must be ${WRAP_CIPHERTEXT_BYTES} bytes`)
  }

  const kekKey = await crypto.subtle.importKey(
    'raw',
    kek as BufferSource,
    'AES-GCM',
    false,
    ['decrypt'],
  )
  let plain: ArrayBuffer
  try {
    plain = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: wrap.nonce as BufferSource,
        additionalData: enc.encode(`${WRAP_AAD_PREFIX}${ownerId}`),
      },
      kekKey,
      wrap.ciphertext as BufferSource,
    )
  } catch {
    // 鍵違い・owner_id の食い違い・改変はいずれも GCM のタグ検証で弾かれる
    throw new PackKeyError('failed to unwrap the pack root key: wrong key or owner_id')
  }
  if (plain.byteLength !== KEY_BYTES) {
    throw new PackKeyError(`unwrapped pack root key must be ${KEY_BYTES} bytes`)
  }
  return new Uint8Array(plain)
}

/**
 * pack 鍵 = `HKDF-SHA256(ikm = PRK, salt = UTF8(packId), info = "nartik-entry-key")`。
 * 本ごとに 1 回導出して使い回す（ページごとに再計算しない）。
 */
export async function derivePackKey(
  packRootKey: Uint8Array,
  packId: string,
): Promise<Uint8Array> {
  if (packRootKey.byteLength !== KEY_BYTES) {
    throw new PackKeyError(`pack root key must be ${KEY_BYTES} bytes`)
  }
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    packRootKey as BufferSource,
    'HKDF',
    false,
    ['deriveBits'],
  )
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt: enc.encode(packId),
      info: enc.encode(HKDF_INFO),
    },
    keyMaterial,
    KEY_BYTES * 8,
  )
  return new Uint8Array(bits)
}

/** pack 鍵（32B）をエントリ暗号/復号用の AES-GCM 鍵にする。 */
export async function importPackKey(packKey: Uint8Array): Promise<CryptoKey> {
  if (packKey.byteLength !== KEY_BYTES) {
    throw new PackKeyError(`pack key must be ${KEY_BYTES} bytes`)
  }
  return crypto.subtle.importKey(
    'raw',
    packKey as BufferSource,
    { name: 'AES-GCM' },
    false,
    ['encrypt', 'decrypt'],
  )
}

/** エントリを AES-256-GCM で暗号化する（AAD なし、IV は毎回乱数 12B）。 */
export async function encryptEntry(
  data: ArrayBuffer,
  packKey: CryptoKey,
): Promise<{ encrypted: ArrayBuffer; iv: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  const encrypted = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    packKey,
    data,
  )
  return { encrypted, iv }
}

/** エントリを復号する（タグ検証に失敗したら例外）。 */
export async function decryptEntry(
  encrypted: ArrayBuffer,
  iv: Uint8Array,
  packKey: CryptoKey,
): Promise<ArrayBuffer> {
  return crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as BufferSource },
    packKey,
    encrypted,
  )
}
