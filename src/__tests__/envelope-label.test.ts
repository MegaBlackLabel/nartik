/**
 * 封筒のラベル（`ligrol-backup.json` / `ligrol-thumbs.json`）。
 *
 * ラベルの salt / info / AAD は**アプリ側の実装とバイト単位で一致**していないと、復号が
 * **静かに失敗**して「表紙が出ない」に戻る（spec 10 §11.8 と
 * `crates/nartik/src/keys.rs` の `THUMBS_LABEL` が正）。ここで値を固定して、片方だけ
 * 直して壊れる事故を防ぐ。
 */

import { describe, expect, it } from 'vitest'
import {
  BACKUP_LABEL,
  THUMBS_LABEL,
  deriveBackupKey,
  deriveThumbsKey,
  envelopeAad,
  openBackupEnvelope,
  parseBackupEnvelope,
  sealBackupEnvelope,
  serializeBackupEnvelope,
} from '../auth/backup-envelope.js'

/** テスト用の PRK（`00 01 … 1f`。本物ではない）。 */
const PRK = Uint8Array.from({ length: 32 }, (_, index) => index)

function textOf(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes)
}

describe('封筒のラベル', () => {
  it('thumbs のラベルは spec 10 §11.8（アプリの THUMBS_LABEL）と一致する', () => {
    expect(THUMBS_LABEL).toEqual({
      aadPrefix: 'ligrol-thumbs',
      formatVersion: 1,
      kdfSalt: 'ligrol-thumbs:v1',
      cipherInfo: 'ligrol-thumbs-key',
      hashInfo: 'ligrol-thumbs-hash',
    })
  })

  it('backup のラベルは spec 10 §11.2 と一致する', () => {
    expect(BACKUP_LABEL).toEqual({
      aadPrefix: 'ligrol-backup',
      formatVersion: 3,
      kdfSalt: 'ligrol-backup:v1',
      cipherInfo: 'ligrol-backup-key',
      hashInfo: 'ligrol-backup-hash',
    })
  })

  it('AAD は "{aadPrefix}:{formatVersion}:{ownerId}"', () => {
    expect(textOf(envelopeAad(THUMBS_LABEL, 'owner-1'))).toBe('ligrol-thumbs:1:owner-1')
    expect(textOf(envelopeAad(BACKUP_LABEL, 'owner-1'))).toBe('ligrol-backup:3:owner-1')
  })

  it('thumbs の 2 鍵は backup と別で、互いにも別（用途分離）', async () => {
    const thumbs = await deriveThumbsKey(PRK)
    const backup = await deriveBackupKey(PRK)

    expect(thumbs.cipherKey).toHaveLength(32)
    expect(thumbs.hashKey).toHaveLength(32)
    expect(thumbs.cipherKey).not.toEqual(thumbs.hashKey)
    expect(thumbs.cipherKey).not.toEqual(backup.cipherKey)
    expect(thumbs.hashKey).not.toEqual(backup.hashKey)
  })

  it('別のラベルの封筒は開けない（backup の封筒を thumbs として開くと失敗する）', async () => {
    const envelope = await sealBackupEnvelope('{"entries":[]}', PRK, 'owner-1')

    // 正しいラベルなら開く
    await expect(openBackupEnvelope(envelope, PRK, 'owner-1')).resolves.toBe('{"entries":[]}')

    // ラベル（format_version と AAD）が違えば開かない
    await expect(openBackupEnvelope(envelope, PRK, 'owner-1', THUMBS_LABEL)).rejects.toThrow()
  })

  it('parse は label の format_version を見る（v1 の封筒は thumbs としてだけ読める）', async () => {
    const sealed = await sealBackupEnvelope('{"entries":[]}', PRK, 'owner-1')
    const v1 = serializeBackupEnvelope(sealed).replace('"format_version":3', '"format_version":1')

    expect(parseBackupEnvelope(v1, THUMBS_LABEL).formatVersion).toBe(1)
    // 既定（backup = v3）では v1 を弾く
    expect(() => parseBackupEnvelope(v1)).toThrow()
  })
})
