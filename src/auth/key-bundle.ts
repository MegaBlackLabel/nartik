/**
 * Drive の `ligrol-keys.json`（`format_version: 1`）—
 * 仕様: `docs/spec/10-pack-keys.md` §3.2 / §4.2。
 *
 * PRK（pack ルート鍵）をラップして保管するファイルで、**アカウント
 * （`owner_id` = `sub` の一方向ハッシュ）ごとに 1 つ**。同じフォルダの
 * `{pack_id}.nartik` を復号するには、まずここから PRK を取り出す。
 *
 * - `owner_id` が自分の `sub` と一致しない bundle は使わない
 * - `kind=passphrase` があるときは**先に**パスフレーズを試し、失敗しても
 *   `kind=sub` へ黙って落ちない（利用者がスキップした場合だけ `sub` を使う）
 * - `iterations` はラップに記録された値を使い、0 と上限超は PBKDF2 を
 *   走らせる前に拒否する
 */

import {
  NONCE_BYTES,
  WRAP_CIPHERTEXT_BYTES,
  WRAP_KDF,
  deriveOwnerId,
  derivePassphraseKek,
  deriveSubWrapKek,
  isSupportedWrapIterations,
  unwrapPackRoot,
  type RootKeyWrap,
  type WrapKind,
} from './identity-key.js'
import { PackKeyBundleError, PackKeyError } from '../errors.js'
import { decodeBase64 } from './bytes.js'

/** `ligrol-keys.json` の `format_version`（pack の `FORMAT_VERSION` とは別物）。 */
export const KEY_BUNDLE_FORMAT_VERSION = 1

/** Drive の `ligrol-keys.json` の中身。 */
export interface PackKeyBundle {
  format_version: number
  owner_id: string
  created_at: number
  updated_at: number
  wraps: RootKeyWrap[]
}

function parseWrap(value: unknown, index: number): RootKeyWrap {
  const invalid = (detail: string) =>
    new PackKeyBundleError(`invalid wrap at wraps[${index}]: ${detail}`)
  if (typeof value !== 'object' || value === null) {
    throw invalid('expected an object')
  }
  const record = value as Record<string, unknown>

  const kind = record.kind
  if (kind !== 'sub' && kind !== 'passphrase') {
    throw invalid(`unknown kind ${JSON.stringify(kind)}`)
  }
  if (record.kdf !== WRAP_KDF) {
    throw invalid(`unknown kdf ${JSON.stringify(record.kdf)}`)
  }
  const iterations = record.iterations
  if (typeof iterations !== 'number' || !isSupportedWrapIterations(iterations)) {
    throw invalid(`unsupported iterations: ${String(iterations)}`)
  }

  const salt = typeof record.salt === 'string' ? decodeBase64(record.salt) : null
  if (!salt) {
    throw invalid('salt is not base64')
  }
  if (salt.byteLength === 0) {
    throw invalid('salt is empty')
  }

  const nonce = typeof record.nonce === 'string' ? decodeBase64(record.nonce) : null
  if (!nonce || nonce.byteLength !== NONCE_BYTES) {
    throw invalid(`nonce must be ${NONCE_BYTES} bytes of base64`)
  }

  const ciphertext =
    typeof record.ciphertext === 'string' ? decodeBase64(record.ciphertext) : null
  if (!ciphertext || ciphertext.byteLength !== WRAP_CIPHERTEXT_BYTES) {
    throw invalid(`ciphertext must be ${WRAP_CIPHERTEXT_BYTES} bytes of base64`)
  }

  return { kind, kdf: WRAP_KDF, iterations, salt, nonce, ciphertext }
}

/**
 * `ligrol-keys.json` の JSON 文字列を読む。
 *
 * - `format_version` が 1 以外 → `PackKeyBundleError`（`.version` に読んだ値）
 * - 構造が不正（欠けたフィールド・base64 でない値・48B でない暗号文など）
 *   → `PackKeyBundleError`
 * - `iterations` の 0 / 1000 万超は **PBKDF2 を走らせる前に**拒否する
 */
export function parseKeyBundle(json: string): PackKeyBundle {
  let value: unknown
  try {
    value = JSON.parse(json)
  } catch (error) {
    throw new PackKeyBundleError(
      `invalid key bundle JSON: ${error instanceof Error ? error.message : String(error)}`,
    )
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new PackKeyBundleError('invalid key bundle JSON: expected an object')
  }
  const record = value as Record<string, unknown>

  // 版だけは構造が違っても先に読む（新しい版を「壊れている」と誤って報告しないため）
  const formatVersion = record.format_version
  if (typeof formatVersion !== 'number' || !Number.isInteger(formatVersion)) {
    throw new PackKeyBundleError('key bundle has no format_version')
  }
  if (formatVersion !== KEY_BUNDLE_FORMAT_VERSION) {
    throw new PackKeyBundleError(
      `unsupported key bundle format_version: ${formatVersion}`,
      { version: formatVersion },
    )
  }

  if (typeof record.owner_id !== 'string') {
    throw new PackKeyBundleError('invalid key bundle: owner_id must be a string')
  }
  if (
    typeof record.created_at !== 'number' ||
    typeof record.updated_at !== 'number'
  ) {
    throw new PackKeyBundleError(
      'invalid key bundle: created_at / updated_at must be numbers',
    )
  }
  if (!Array.isArray(record.wraps)) {
    throw new PackKeyBundleError('invalid key bundle: wraps must be an array')
  }

  const wraps = record.wraps.map((wrap, index) => parseWrap(wrap, index))
  const seen = new Set<WrapKind>()
  for (const wrap of wraps) {
    if (seen.has(wrap.kind)) {
      throw new PackKeyBundleError(`duplicate wrap kind: ${wrap.kind}`)
    }
    seen.add(wrap.kind)
  }

  return {
    format_version: formatVersion,
    owner_id: record.owner_id,
    created_at: record.created_at,
    updated_at: record.updated_at,
    wraps,
  }
}

/** `kind` のラップを探す（無ければ `undefined`）。 */
export function findWrap(
  bundle: PackKeyBundle,
  kind: WrapKind,
): RootKeyWrap | undefined {
  return bundle.wraps.find((wrap) => wrap.kind === kind)
}

export interface UnlockPackRootOptions {
  /** Google OAuth の `sub`（`owner_id` の照合と `sub` ラップの解錠に使う）。 */
  sub: string
  /** 利用者が入力したパスフレーズ（NFKC 正規化は内部で行う）。 */
  passphrase?: string
  /** 利用者がパスフレーズ入力をスキップした場合のみ `true`（`sub` ラップへ進む）。 */
  skipPassphrase?: boolean
}

/**
 * bundle から PRK を取り出す（仕様 §4.2 の解決順序 2 → 3）。
 *
 * 1. `owner_id` が `sub` と一致しなければ `PackKeyBundleError`（使わない）
 * 2. `kind=passphrase` があれば**先に**それを試す。パスフレーズが未入力なら
 *    `PackKeyError`（スキップされていない限り `sub` へ落ちない）、
 *    入力が違っても `PackKeyError`（`sub` へ黙って落ちない）
 * 3. `kind=sub` を解く。無ければ `PackKeyError`（パスフレーズ必須モード）
 */
export async function unlockPackRoot(
  bundle: PackKeyBundle,
  options: UnlockPackRootOptions,
): Promise<Uint8Array> {
  const ownerId = await deriveOwnerId(options.sub)
  if (bundle.owner_id !== ownerId) {
    throw new PackKeyBundleError(
      'key bundle belongs to another account (owner_id mismatch)',
    )
  }

  const passphraseWrap = findWrap(bundle, 'passphrase')
  if (passphraseWrap) {
    if (options.passphrase !== undefined && options.passphrase !== '') {
      const kek = await derivePassphraseKek(
        options.passphrase,
        passphraseWrap.salt,
        passphraseWrap.iterations,
      )
      try {
        return await unwrapPackRoot(passphraseWrap, kek, ownerId)
      } catch {
        throw new PackKeyError('the passphrase does not unlock the pack root key')
      }
    }
    if (options.skipPassphrase !== true) {
      throw new PackKeyError('passphrase required to unlock the pack root key')
    }
  }

  const subWrap = findWrap(bundle, 'sub')
  if (!subWrap) {
    throw new PackKeyError('key bundle has no usable wrap: passphrase required')
  }
  const subKek = await deriveSubWrapKek(options.sub)
  return unwrapPackRoot(subWrap, subKek, ownerId)
}
