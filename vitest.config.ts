import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    environment: 'happy-dom',
    // 既定の 5 秒では、ファイル並列実行時の負荷で重いテストがタイムアウトして偽の失敗になる。
    // 実測（このマシン）: 1MB の `Uint8Array` を `toEqual` で比較していたテストは単独でも
    // 3.5〜5.5 秒、並列実行時は 6〜11 秒かかっていた。ボトルネックは暗号（PBKDF2 10 万回・
    // AES-GCM）や pack の組み立てではなく vitest の深い比較で、同じ 1MB の
    // `PackBuilder.build()` は 3.4ms、`PackReader.readEntry()` は 1.8ms。
    // 該当の比較は `src/__tests__/byte-compare.ts` の `expectBytesEqual`（長さ + 先頭不一致
    // 位置）に置き換え済み（5.4 秒 → 8ms）。30 秒は他の重いテストの保険として残す。
    testTimeout: 30_000,
    hookTimeout: 30_000,
  },
})
