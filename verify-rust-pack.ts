/**
 * Rust 版（ligrol-app の crates/nartik）が書いた v3 pack を、TS 版が
 * バイト一致で読めるかの確認スクリプト。
 *
 *   mise exec -- bun verify-rust-pack.ts <pack.nartik> [packId] [prkHex]
 *
 * 既定は仕様 `docs/spec/10-pack-keys.md` §8 のベクタ（PRK = `00 01 … 1f` /
 * pack_id = `test-pack`）。アプリ側のフィクスチャ
 * （`ligrol-app の crates/nartik/tests/fixtures/{plain,encrypted}.nartik`）はこの値で
 * 作られているので、そのまま検証できる。
 *
 * fflate の非同期 inflate は bun の `worker_threads` で動かないため、reader が
 * 解析した index をそのまま使って手動で復号・展開する（検証内容は
 * `PackReader.readEntry` と同じ: 復号 → 展開 → 宣言サイズとの一致）。
 */
import { PackReader } from "./src/reader.ts";
import { EntryFlags } from "./src/format.ts";
import {
  decryptEntry,
  derivePackKey,
  importPackKey,
} from "./src/auth/identity-key.ts";
import { inflateSync } from "fflate";

const enc = new TextEncoder();

/** アプリ側フィクスチャの中身（crates/nartik/tests/interop.rs と同じ）。 */
const EXPECTED: Record<string, Uint8Array> = {
  "metadata.json": enc.encode(
    JSON.stringify({ schemaVersion: 1, title: "Test Book", author: "Test Author" })
  ),
  "pages/page_0001.webp": enc.encode("LIGROL_PAGE_0001:" + "abc".repeat(4000)),
  "pages/page_0002.webp": enc.encode("LIGROL_PAGE_0002:" + "xyz".repeat(2000)),
};

function bytesFromHex(value: string): Uint8Array {
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

function equal(left: Uint8Array, right: Uint8Array): boolean {
  return (
    left.byteLength === right.byteLength &&
    Buffer.compare(Buffer.from(left), Buffer.from(right)) === 0
  );
}

const path = process.argv[2];
if (!path) {
  console.error("usage: bun verify-rust-pack.ts <pack.nartik> [packId] [prkHex]");
  process.exit(2);
}
const packId = process.argv[3] ?? "test-pack";
const packRootKey = bytesFromHex(
  process.argv[4] ??
    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
);

const buffer = await Bun.file(path).arrayBuffer();
const reader = PackReader.fromBuffer(buffer);
console.log(
  "version",
  reader.metadata.version,
  "entryCount",
  reader.metadata.entryCount,
  "flags",
  reader.metadata.flags
);

const packKey = await importPackKey(await derivePackKey(packRootKey, packId));
let failures = 0;

for (const info of reader.listEntries()) {
  let data = new Uint8Array(
    buffer.slice(Number(info.offset), Number(info.offset) + info.compressedSize)
  );
  if (info.flags & EntryFlags.Encrypted) {
    data = new Uint8Array(await decryptEntry(data.buffer, info.iv!, packKey));
  }
  if (info.flags & EntryFlags.Compressed) {
    data = inflateSync(data);
  }
  const expected = EXPECTED[info.path];
  const status =
    data.byteLength === info.size && (!expected || equal(data, expected))
      ? "ok"
      : "FAIL";
  if (status === "FAIL") failures++;
  console.log(
    `${status} ${info.path} flags=0x${info.flags.toString(16)} size=${data.byteLength}/${info.size}`
  );
}

if (failures > 0) {
  process.exit(1);
}
console.log("TS READS RUST v3 PACK OK");
