/**
 * v3 の pack フィクスチャを TS 実装で生成し、同じ実装で読み戻す確認スクリプト。
 *
 *   mise exec -- bun gen-fixtures.ts
 *
 * 出力（リポジトリ直下）:
 * - `plain.nartik` … 平文の v3 pack
 * - `v3-encrypted.nartik` … PRK = `00 01 … 1f` / pack_id = `test-pack` で
 *   全エントリを暗号化した v3 pack
 *
 * アプリ側の相互運用フィクスチャ（`crates/nartik/tests/fixtures/`）と同じ
 * エントリ・同じ鍵にしてあるので、`verify-rust-pack.ts` で両方向を突き合わせられる。
 *
 * fflate の非同期 inflate は bun の `worker_threads` で動かないため、読み戻しは
 * index を直接使って手動で復号・展開する。
 */
import { PackBuilder } from "./src/builder.ts";
import { PackReader } from "./src/reader.ts";
import { EntryFlags } from "./src/format.ts";
import {
  decryptEntry,
  derivePackKey,
  importPackKey,
} from "./src/auth/identity-key.ts";
import { inflateSync } from "fflate";

const enc = new TextEncoder();
const pageA = enc.encode("LIGROL_PAGE_0001:" + "abc".repeat(4000));
const pageB = enc.encode("LIGROL_PAGE_0002:" + "xyz".repeat(2000));
const meta = enc.encode(
  JSON.stringify({ schemaVersion: 1, title: "Test Book", author: "Test Author" })
);

const createdAt = 1728000000000n;
const packId = "test-pack";
const packRootKey = Uint8Array.from({ length: 32 }, (_, index) => index);

// 平文の v3 pack（pack レベルは compress、エントリ個別の compress は混在）
const plain = new PackBuilder({ createdAt, compress: true });
plain.addEntry("pages/page_0002.webp", pageB, "image/webp", { compress: false });
plain.addEntry("pages/page_0001.webp", pageA, "image/webp", { compress: true });
plain.addEntry("metadata.json", meta, "application/json", { compress: false });
const plainBuf = await plain.build();
await Bun.write(import.meta.dir + "/plain.nartik", plainBuf);

// 暗号化した v3 pack（全エントリが pack 鍵で暗号化される）
const encrypted = new PackBuilder({
  createdAt,
  compress: true,
  packRootKey,
  packId,
});
encrypted.addEntry("pages/page_0001.webp", pageA, "image/webp", { compress: true });
encrypted.addEntry("pages/page_0002.webp", pageB, "image/webp", { compress: false });
encrypted.addEntry("metadata.json", meta, "application/json", { compress: false });
const encryptedBuf = await encrypted.build();
await Bun.write(import.meta.dir + "/v3-encrypted.nartik", encryptedBuf);

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    Buffer.compare(Buffer.from(left), Buffer.from(right)) === 0
  );
}

const expected: Record<string, Uint8Array> = {
  "metadata.json": meta,
  "pages/page_0001.webp": pageA,
  "pages/page_0002.webp": pageB,
};

for (const [name, buffer, key] of [
  ["plain", plainBuf, null],
  ["encrypted", encryptedBuf, await importPackKey(await derivePackKey(packRootKey, packId))],
] as const) {
  const reader = PackReader.fromBuffer(buffer);
  console.log(
    name,
    "version",
    reader.metadata.version,
    "entryCount",
    reader.metadata.entryCount,
    "flags",
    reader.metadata.flags
  );

  for (const info of reader.listEntries()) {
    let data = new Uint8Array(
      buffer.slice(Number(info.offset), Number(info.offset) + info.compressedSize)
    );
    if (info.flags & EntryFlags.Encrypted) {
      if (!key) throw new Error(`encrypted entry without a key: ${info.path}`);
      data = new Uint8Array(await decryptEntry(data.buffer, info.iv!, key));
    }
    if (info.flags & EntryFlags.Compressed) {
      data = inflateSync(data);
    }
    const want = expected[info.path];
    if (!want || !equal(data, want)) {
      throw new Error(`${name}: ${info.path} did not round-trip`);
    }
  }
  console.log(name, "roundtrip ok");
}
