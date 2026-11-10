/**
 * Drive のメタデータバックアップ（`ligrol-backup.json`）v3 の封筒
 * （仕様: `docs/spec/10-pack-keys.md` §11）。
 *
 * 実装の正は `crates/nartik/src/keys.rs`（`BackupEnvelope`）。**数値・バイト列は
 * Rust 版と一致が要件**（Rust が作った封筒をそのまま復号できること）。
 *
 * - 平文は現行のバックアップ JSON そのもの（`db::backup::export_json` の出力）
 * - 暗号化は `AES-256-GCM(backup_cipher_key)`、AAD は `ligrol-backup:3:<owner_id>`
 * - `nonce` は乱数なので**暗号文は毎回変わる** — 変更検知は `content_hmac`
 *   （平文の HMAC-SHA256）で行い、暗号文の md5 は使わない
 */

import { PackCorruptedError, PackKeyError } from '../errors.js'
import { KEY_BYTES, NONCE_BYTES } from './identity-key.js'
import { decodeBase64, encodeBase64, hex32FromString, hexFromBytes } from './bytes.js'

/** 封筒の `format_version`（v2 以前は平文のバックアップ JSON）。 */
export const BACKUP_FORMAT_VERSION = 3

/** 封筒の `encryption.alg`（唯一の値）。 */
export const BACKUP_ALG = 'aes-256-gcm'

/** 封筒の `encryption.kdf`（唯一の値。nonce は乱数なので salt は持たない）。 */
export const BACKUP_KDF = 'hkdf-sha256'

/** バックアップ鍵の HKDF salt（PRK から用途分離した 2 本の鍵を作る）。 */
export const BACKUP_KDF_SALT = 'ligrol-backup:v1'

/** 封筒の暗号鍵の HKDF info。 */
export const BACKUP_CIPHER_INFO = 'ligrol-backup-key'

/** 平文の HMAC 鍵の HKDF info。 */
export const BACKUP_HASH_INFO = 'ligrol-backup-hash'

/** 封筒の AAD 接頭辞（`"{prefix}:{format_version}:{owner_id}"` を AAD にする）。 */
export const BACKUP_AAD_PREFIX = 'ligrol-backup'

/**
 * 封筒の用途ごとのラベル（アプリ側の `EnvelopeLabel` と同じ構造）。
 *
 * `ligrol-backup.json`（§11.3）と `ligrol-thumbs.json`（§11.8）で**鍵の導出と AAD だけ**が
 * 違うので、暗号・HMAC・直列化の実装は 1 本にしてここで切り替える（コピー実装は片方だけ直して
 * 復号が静かに失敗する事故を生む）。
 */
export interface EnvelopeLabel {
  /** AAD の接頭辞（`"{aadPrefix}:{formatVersion}:{ownerId}"`）。 */
  aadPrefix: string
  /** 封筒の `format_version`（AAD にも入る）。 */
  formatVersion: number
  /** HKDF の salt。 */
  kdfSalt: string
  /** 暗号鍵の HKDF info。 */
  cipherInfo: string
  /** 平文 HMAC 鍵の HKDF info。 */
  hashInfo: string
}

/** `ligrol-backup.json` のラベル（v3 封筒）。 */
export const BACKUP_LABEL: EnvelopeLabel = {
  aadPrefix: BACKUP_AAD_PREFIX,
  formatVersion: BACKUP_FORMAT_VERSION,
  kdfSalt: BACKUP_KDF_SALT,
  cipherInfo: BACKUP_CIPHER_INFO,
  hashInfo: BACKUP_HASH_INFO,
}

/**
 * `ligrol-thumbs.json`（表紙バンドル。spec 10 §11.8）のラベル。
 *
 * アプリ側の `crates/nartik/src/keys.rs` の `THUMBS_LABEL` と**バイト単位で一致**させること
 * （1 文字違うと復号が静かに失敗し、「表紙が出ない」に戻る）。
 */
export const THUMBS_LABEL: EnvelopeLabel = {
  aadPrefix: 'ligrol-thumbs',
  formatVersion: 1,
  kdfSalt: 'ligrol-thumbs:v1',
  cipherInfo: 'ligrol-thumbs-key',
  hashInfo: 'ligrol-thumbs-hash',
}

/** AES-GCM のタグ長（暗号文の最小長）。 */
const BACKUP_TAG_BYTES = 16

const enc = new TextEncoder()

/** 封筒の AAD バイト列（ラベルと所有者を縛り、差し替えを検出する）。 */
export function envelopeAad(label: EnvelopeLabel, ownerId: string): Uint8Array {
  return enc.encode(`${label.aadPrefix}:${label.formatVersion}:${ownerId}`)
}

/** `ligrol-backup.json` の AAD（既存の呼び出し元のための薄い入口）。 */
export function backupAad(ownerId: string): Uint8Array {
  return envelopeAad(BACKUP_LABEL, ownerId)
}

/** PRK から導出したバックアップ用の 2 鍵（用途分離。暗号鍵を HMAC に流用しない）。 */
export interface BackupKeys {
  /** `AES-256-GCM` の鍵。 */
  cipherKey: Uint8Array
  /** `content_hmac` の HMAC-SHA256 鍵。 */
  hashKey: Uint8Array
}

/**
 * `backup_cipher_key` / `backup_hash_key` を導出する（仕様 §11.2）。
 *
 * ```text
 * backup_cipher_key = HKDF-SHA256(ikm = PRK, salt = "ligrol-backup:v1", info = "ligrol-backup-key",  32B)
 * backup_hash_key   = HKDF-SHA256(ikm = PRK, salt = "ligrol-backup:v1", info = "ligrol-backup-hash", 32B)
 * ```
 */
export async function deriveEnvelopeKey(
  packRootKey: Uint8Array,
  label: EnvelopeLabel,
): Promise<BackupKeys> {
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
  const salt = enc.encode(label.kdfSalt)
  const derive = async (info: string) =>
    new Uint8Array(
      await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt, info: enc.encode(info) },
        keyMaterial,
        KEY_BYTES * 8,
      ),
    )

  return {
    cipherKey: await derive(label.cipherInfo),
    hashKey: await derive(label.hashInfo),
  }
}

/**
 * `backup_cipher_key` / `backup_hash_key` を導出する（仕様 §11.2）。
 *
 * ```text
 * backup_cipher_key = HKDF-SHA256(ikm = PRK, salt = "ligrol-backup:v1", info = "ligrol-backup-key",  32B)
 * backup_hash_key   = HKDF-SHA256(ikm = PRK, salt = "ligrol-backup:v1", info = "ligrol-backup-hash", 32B)
 * ```
 */
export async function deriveBackupKey(packRootKey: Uint8Array): Promise<BackupKeys> {
  return deriveEnvelopeKey(packRootKey, BACKUP_LABEL)
}

/**
 * 表紙バンドル（`ligrol-thumbs.json`）の 2 鍵を導出する（仕様 §11.8）。
 *
 * ```text
 * thumbs_cipher_key = HKDF-SHA256(ikm = PRK, salt = "ligrol-thumbs:v1", info = "ligrol-thumbs-key",  32B)
 * thumbs_hash_key   = HKDF-SHA256(ikm = PRK, salt = "ligrol-thumbs:v1", info = "ligrol-thumbs-hash", 32B)
 * ```
 */
export async function deriveThumbsKey(packRootKey: Uint8Array): Promise<BackupKeys> {
  return deriveEnvelopeKey(packRootKey, THUMBS_LABEL)
}

/** `ligrol-backup.json` v3 の封筒（読み書きはこの型を介する）。 */
export interface BackupEnvelope {
  formatVersion: number
  ownerId: string
  alg: string
  kdf: string
  nonce: Uint8Array
  ciphertext: Uint8Array
  /** 平文の HMAC-SHA256（32B）。同じ平文なら nonce が違っても同じ値。 */
  contentHmac: Uint8Array
}

/** `content_hmac` の小文字 hex（変更検知の基準値に使う表現）。 */
export function contentHmacHex(envelope: BackupEnvelope): string {
  return hexFromBytes(envelope.contentHmac)
}

async function hmacSha256(hashKey: Uint8Array, message: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    'raw',
    hashKey as BufferSource,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, message as BufferSource))
}

/** 定数時間比較（早期 return で一致位置を漏らさない。Rust の `constant_time_eq` と同じ）。 */
function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) {
    return false
  }
  let diff = 0
  for (let index = 0; index < left.byteLength; index++) {
    diff |= left[index]! ^ right[index]!
  }
  return diff === 0
}

/**
 * 平文を封筒に入れる（`nonce` を省略すると乱数 12B。本番の作成経路）。
 *
 * `nonce` を渡せるのはテストベクタの検算（決定的）のため。
 */
export async function sealBackupEnvelope(
  plaintext: string,
  packRootKey: Uint8Array,
  ownerId: string,
  nonce?: Uint8Array,
): Promise<BackupEnvelope> {
  const nonceBytes = nonce ?? crypto.getRandomValues(new Uint8Array(NONCE_BYTES))
  if (nonceBytes.byteLength !== NONCE_BYTES) {
    throw new PackKeyError(`backup nonce must be ${NONCE_BYTES} bytes`)
  }
  const { cipherKey, hashKey } = await deriveBackupKey(packRootKey)
  const key = await crypto.subtle.importKey('raw', cipherKey as BufferSource, 'AES-GCM', false, [
    'encrypt',
  ])
  const plaintextBytes = enc.encode(plaintext)

  return {
    formatVersion: BACKUP_FORMAT_VERSION,
    ownerId,
    alg: BACKUP_ALG,
    kdf: BACKUP_KDF,
    nonce: nonceBytes,
    ciphertext: new Uint8Array(
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: nonceBytes as BufferSource, additionalData: backupAad(ownerId) as BufferSource },
        key,
        plaintextBytes as BufferSource,
      ),
    ),
    contentHmac: await hmacSha256(hashKey, plaintextBytes),
  }
}

/**
 * 封筒を復号する。**鍵違い・改変・`owner_id` 違いはすべてエラー**で、平文を返さない。
 *
 * `ownerId` は AAD に入れる値（呼び出し側が確認した所有者）。省略すると封筒に
 * 記録された `owner_id` を使う。別の値を渡すと復号に失敗する＝別アカウントの
 * 封筒への差し替えを検出できる。
 */
export async function openBackupEnvelope(
  envelope: BackupEnvelope,
  packRootKey: Uint8Array,
  ownerId: string = envelope.ownerId,
  label: EnvelopeLabel = BACKUP_LABEL,
): Promise<string> {
  // 文言は用途名から作る（`ligrol-backup` → `backup` / `ligrol-thumbs` → `thumbs`）。
  // thumbs の復号失敗が「backup」と名乗ると切り分けで誤誘導になる
  const labelName = label.aadPrefix.replace(/^ligrol-/, '')

  if (
    envelope.formatVersion !== label.formatVersion ||
    envelope.alg !== BACKUP_ALG ||
    envelope.kdf !== BACKUP_KDF
  ) {
    throw new PackCorruptedError(
      `unsupported ${labelName} envelope: v${envelope.formatVersion} ${envelope.alg}/${envelope.kdf}`,
    )
  }

  const { cipherKey, hashKey } = await deriveEnvelopeKey(packRootKey, label)
  const key = await crypto.subtle.importKey('raw', cipherKey as BufferSource, 'AES-GCM', false, [
    'decrypt',
  ])
  let plaintext: ArrayBuffer
  try {
    plaintext = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: envelope.nonce as BufferSource,
        additionalData: envelopeAad(label, ownerId) as BufferSource,
      },
      key,
      envelope.ciphertext as BufferSource,
    )
  } catch {
    throw new PackCorruptedError(`${labelName} decryption failed (wrong key or tampered)`)
  }

  const plaintextBytes = new Uint8Array(plaintext)
  const expected = await hmacSha256(hashKey, plaintextBytes)
  if (!constantTimeEqual(expected, envelope.contentHmac)) {
    throw new PackCorruptedError(`${labelName} content hmac mismatch`)
  }

  try {
    // 不正な UTF-8 を黙って置換文字にしない（Rust 版は UTF-8 でなければエラー）。
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintextBytes)
  } catch {
    throw new PackCorruptedError('backup plaintext is not UTF-8')
  }
}

/**
 * 封筒の wire 表現（`ligrol-backup.json` の中身）。
 * キー順は Rust の `WireEnvelope` と同じ（コンパクトな `JSON.stringify` と一致）。
 */
export function serializeBackupEnvelope(envelope: BackupEnvelope): string {
  return JSON.stringify({
    format_version: envelope.formatVersion,
    owner_id: envelope.ownerId,
    encryption: {
      alg: envelope.alg,
      kdf: envelope.kdf,
      nonce: encodeBase64(envelope.nonce),
      ciphertext: encodeBase64(envelope.ciphertext),
    },
    content_hmac: hexFromBytes(envelope.contentHmac),
  })
}

/**
 * 封筒を読む。`format_version` がラベルの値以外・構造が不正・base64 / hex でない値は
 * `PackCorruptedError`（**平文として扱える形では返さない**）。
 *
 * `label` を省略すると `ligrol-backup.json`（v3）。表紙バンドルは
 * `parseBackupEnvelope(json, THUMBS_LABEL)`（v1、spec 10 §11.8）。
 */
export function parseBackupEnvelope(
  json: string,
  label: EnvelopeLabel = BACKUP_LABEL,
): BackupEnvelope {
  const labelName = label.aadPrefix.replace(/^ligrol-/, '')
  const invalid = (detail: string) => new PackCorruptedError(`invalid ${labelName} envelope: ${detail}`)

  let value: unknown
  try {
    value = JSON.parse(json)
  } catch {
    throw invalid('not a JSON envelope')
  }
  if (typeof value !== 'object' || value === null) {
    throw invalid('not a JSON object')
  }
  const record = value as Record<string, unknown>

  if (record.format_version !== label.formatVersion) {
    throw invalid(`unsupported format_version ${String(record.format_version)}`)
  }
  if (typeof record.owner_id !== 'string') {
    throw invalid('owner_id is not a string')
  }
  const encryption = record.encryption
  if (typeof encryption !== 'object' || encryption === null) {
    throw invalid('encryption is missing')
  }
  const { alg, kdf, nonce, ciphertext } = encryption as Record<string, unknown>
  if (alg !== BACKUP_ALG) {
    throw invalid(`unknown alg ${JSON.stringify(alg)}`)
  }
  if (kdf !== BACKUP_KDF) {
    throw invalid(`unknown kdf ${JSON.stringify(kdf)}`)
  }

  const nonceBytes = typeof nonce === 'string' ? decodeBase64(nonce) : null
  if (!nonceBytes || nonceBytes.byteLength !== NONCE_BYTES) {
    throw invalid(`nonce must be ${NONCE_BYTES} bytes of base64`)
  }
  const ciphertextBytes = typeof ciphertext === 'string' ? decodeBase64(ciphertext) : null
  if (!ciphertextBytes) {
    throw invalid('ciphertext is not base64')
  }
  if (ciphertextBytes.byteLength < BACKUP_TAG_BYTES) {
    throw invalid('ciphertext is shorter than the GCM tag')
  }
  const contentHmac =
    typeof record.content_hmac === 'string' ? hex32FromString(record.content_hmac) : null
  if (!contentHmac) {
    throw invalid('content_hmac is not 32 hex bytes')
  }

  return {
    formatVersion: label.formatVersion,
    ownerId: record.owner_id,
    alg: BACKUP_ALG,
    kdf: BACKUP_KDF,
    nonce: nonceBytes,
    ciphertext: ciphertextBytes,
    contentHmac,
  }
}
