// nartik - Core Exports

export const VERSION = '0.1.0'

export type {
  PackEntryInfo,
  PackMetadata,
  PackWorkerAPI,
  PackEntryProxy,
} from './types.js'

export type {
  PackProgress,
  PackOptions,
  ReadOptions,
  EntryOptions,
} from './types.js'

export {
  PackError,
  PackVersionError,
  PackCorruptedError,
  PackNotFoundError,
  PackKeyBundleError,
  PackKeyError,
  PackKeyRequiredError,
} from './errors.js'

export type {
  PackStorage,
  PackListEntry,
  PackFile,
} from './manager.js'

export {
  PackManager,
  MemoryPackStorage,
} from './manager.js'

export { OPFSPackStorage } from './storage/opfs.js'

export type {
  FileSystem,
  MigrationProgress,
  MigrationOptions,
  MigrationResult,
} from './migration.js'

export {
  migrateToPacks,
  validatePack,
} from './migration.js'

export {
  crc32,
  parseIndex,
  initCipher,
  encrypt,
  decrypt,
  generateIV,
  wasmAvailable,
  type IndexEntry,
  type CryptoResult,
} from './wasm-bridge.js'

export { PackBuilder } from './builder.js'
export { PackReader } from './reader.js'

export { packSourceFromBlob, packSourceFromBytes } from './source.js'
export type { PackSource } from './source.js'

export {
  APP_SALT,
  HKDF_INFO,
  MAX_PASSPHRASE_ITERATIONS,
  PASSPHRASE_WRAP_ITERATIONS,
  SUB_WRAP_ITERATIONS,
  WRAP_AAD_PREFIX,
  deriveOwnerId,
  derivePackKey,
  derivePassphraseKek,
  deriveSubWrapKek,
  isSupportedWrapIterations,
  unwrapPackRoot,
} from './auth/identity-key.js'

export type { RootKeyWrap, WrapKind } from './auth/identity-key.js'

export {
  BACKUP_AAD_PREFIX,
  BACKUP_ALG,
  BACKUP_CIPHER_INFO,
  BACKUP_FORMAT_VERSION,
  BACKUP_HASH_INFO,
  BACKUP_KDF,
  BACKUP_KDF_SALT,
  BACKUP_LABEL,
  backupAad,
  contentHmacHex,
  deriveBackupKey,
  deriveEnvelopeKey,
  deriveThumbsKey,
  envelopeAad,
  openBackupEnvelope,
  parseBackupEnvelope,
  sealBackupEnvelope,
  serializeBackupEnvelope,
  THUMBS_LABEL,
} from './auth/backup-envelope.js'

export type { BackupEnvelope, BackupKeys, EnvelopeLabel } from './auth/backup-envelope.js'

export {
  KEY_BUNDLE_FORMAT_VERSION,
  findWrap,
  parseKeyBundle,
  unlockPackRoot,
} from './auth/key-bundle.js'

export type {
  PackKeyBundle,
  UnlockPackRootOptions,
} from './auth/key-bundle.js'

export { SQLitePackStorage } from './db/storage.js'
export { packs, packEntries } from './db/schema.js'
export { createPackIndexDB } from './db/client.js'
