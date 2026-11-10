import { describe, it, expect } from 'vitest'
import {
  deriveSubWrapKek,
  derivePackKey,
  importPackKey,
  encryptEntry,
  decryptEntry,
  deriveOwnerId,
} from '../auth/identity-key'

function packRootKey(seed: number): Uint8Array {
  return Uint8Array.from({ length: 32 }, (_, index) => (index + seed) % 256)
}

function hex(value: Uint8Array): string {
  return Array.from(value)
    .map((byte) => byte.toString(16).padStart(2, '0'))
    .join('')
}

describe('identity-key', () => {
  describe('deriveSubWrapKek', () => {
    it('derives 32 deterministic bytes for the same sub', async () => {
      const first = await deriveSubWrapKek('user-sub-123')
      const second = await deriveSubWrapKek('user-sub-123')
      expect(first).toHaveLength(32)
      expect(hex(first)).toBe(hex(second))
    })

    it('different sub → different KEK', async () => {
      const alice = await deriveSubWrapKek('user-sub-alice')
      const bob = await deriveSubWrapKek('user-sub-bob')
      expect(hex(alice)).not.toBe(hex(bob))
    })

    it('cannot decrypt a pack directly (v2 の master key とは用途が違う)', async () => {
      const kek = await deriveSubWrapKek('user-sub-123')
      // 32B の鍵素材として AES-GCM の鍵にはなるが、pack 鍵ではない
      const packKey = await importPackKey(await derivePackKey(packRootKey(0), 'pack-1'))
      const { encrypted, iv } = await encryptEntry(
        new TextEncoder().encode('secret').buffer,
        packKey,
      )
      const kekKey = await crypto.subtle.importKey(
        'raw',
        kek as BufferSource,
        { name: 'AES-GCM' },
        false,
        ['decrypt'],
      )
      await expect(
        crypto.subtle.decrypt(
          { name: 'AES-GCM', iv: iv as BufferSource },
          kekKey,
          encrypted,
        ),
      ).rejects.toThrow()
    })
  })

  describe('derivePackKey', () => {
    it('same PRK + same packId → same derived key bytes (deterministic)', async () => {
      const first = await derivePackKey(packRootKey(0), 'pack-abc')
      const second = await derivePackKey(packRootKey(0), 'pack-abc')
      expect(first).toHaveLength(32)
      expect(hex(first)).toBe(hex(second))
    })

    it('different packId → different pack key', async () => {
      const one = await derivePackKey(packRootKey(0), 'pack-abc')
      const two = await derivePackKey(packRootKey(0), 'pack-xyz')
      expect(hex(one)).not.toBe(hex(two))
    })

    it('different PRK → different pack key (decrypt fails)', async () => {
      const key1 = await importPackKey(await derivePackKey(packRootKey(0), 'pack-abc'))
      const key2 = await importPackKey(await derivePackKey(packRootKey(1), 'pack-abc'))

      const plaintext = new TextEncoder().encode('secret data')
      const { encrypted, iv } = await encryptEntry(plaintext.buffer, key1)

      await expect(decryptEntry(encrypted, iv, key2)).rejects.toThrow()
    })
  })

  describe('encryptEntry / decryptEntry', () => {
    it('encrypt then decrypt returns original data', async () => {
      const packKey = await importPackKey(await derivePackKey(packRootKey(0), 'pack-roundtrip'))

      const original = new TextEncoder().encode('round-trip test data 🔐')
      const { encrypted, iv } = await encryptEntry(original.buffer, packKey)
      const decrypted = await decryptEntry(encrypted, iv, packKey)

      expect(new TextDecoder().decode(decrypted)).toBe('round-trip test data 🔐')
    })

    it('each encryption produces a different IV (random IV)', async () => {
      const packKey = await importPackKey(await derivePackKey(packRootKey(0), 'pack-iv'))
      const data = new TextEncoder().encode('test').buffer

      const { iv: iv1 } = await encryptEntry(data, packKey)
      const { iv: iv2 } = await encryptEntry(data, packKey)

      expect(iv1).toHaveLength(12)
      expect(iv2).toHaveLength(12)
      expect(hex(iv1)).not.toBe(hex(iv2))
    })

    it('decrypt with a wrong key fails', async () => {
      const key1 = await importPackKey(await derivePackKey(packRootKey(0), 'pack-wrong-key-1'))
      const key2 = await importPackKey(await derivePackKey(packRootKey(1), 'pack-wrong-key-2'))

      const data = new TextEncoder().encode('top secret')
      const { encrypted, iv } = await encryptEntry(data.buffer, key1)

      await expect(decryptEntry(encrypted, iv, key2)).rejects.toThrow()
    })
  })

  describe('deriveOwnerId', () => {
    it('returns a hex string of length 64 (SHA-256)', async () => {
      const ownerId = await deriveOwnerId('user-sub-123')
      expect(ownerId).toMatch(/^[0-9a-f]{64}$/)
    })

    it('same sub always produces the same ownerId (deterministic)', async () => {
      const first = await deriveOwnerId('user-sub-123')
      const second = await deriveOwnerId('user-sub-123')
      expect(first).toBe(second)
    })

    it('different sub produces different ownerId', async () => {
      const alice = await deriveOwnerId('alice')
      const bob = await deriveOwnerId('bob')
      expect(alice).not.toBe(bob)
    })

    it('uses the prefix "nartik:v1:" in derivation (not raw sub)', async () => {
      const expected = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode('nartik:v1:user-sub-123'),
      )
      const expectedHex = Array.from(new Uint8Array(expected))
        .map((byte) => byte.toString(16).padStart(2, '0'))
        .join('')

      expect(await deriveOwnerId('user-sub-123')).toBe(expectedHex)
    })
  })
})
