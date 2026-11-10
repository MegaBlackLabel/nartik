/**
 * Base error class for all nartik pack operations.
 *
 * All library-specific errors extend `PackError` so consumers can use
 * a single `instanceof` check to distinguish operational failures from
 * generic JavaScript errors.
 */
export class PackError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'PackError'
  }
}

/**
 * Thrown when a pack file uses a format version that the current
 * library does not support.
 */
export class PackVersionError extends PackError {
  constructor(message: string) {
    super(message)
    this.name = 'PackVersionError'
  }
}

/**
 * Thrown when a pack file fails structural or cryptographic validation
 * (e.g. checksum mismatch, truncated data, or invalid magic number).
 */
export class PackCorruptedError extends PackError {
  constructor(message: string) {
    super(message)
    this.name = 'PackCorruptedError'
  }
}

/**
 * Thrown when a requested pack file or entry cannot be found in OPFS
 * or the provided storage handle.
 */
export class PackNotFoundError extends PackError {
  constructor(message: string) {
    super(message)
    this.name = 'PackNotFoundError'
  }
}

/**
 * Thrown when `ligrol-keys.json` (the Drive key bundle) is unusable:
 * an unsupported `format_version`, a malformed field, or a bundle that
 * belongs to another account.
 */
export class PackKeyBundleError extends PackError {
  /** `format_version` read from the bundle (set only for unsupported versions). */
  readonly version?: number

  constructor(message: string, options: { version?: number } = {}) {
    super(message)
    this.name = 'PackKeyBundleError'
    this.version = options.version
  }
}

/**
 * Thrown when a pack root key wrap cannot be unlocked — a wrong passphrase
 * or `sub`, no usable wrap, or a malformed wrap. The library never falls
 * back to plaintext or to another wrap.
 */
export class PackKeyError extends PackError {
  constructor(message: string) {
    super(message)
    this.name = 'PackKeyError'
  }
}

/**
 * Thrown when reading an encrypted entry without a pack key.
 *
 * Callers should unlock the pack root key (`unlockPackRoot`) and retry
 * with `ReadOptions.packRootKey` — the payload is never returned as-is.
 */
export class PackKeyRequiredError extends PackError {
  /** Path of the entry that needs a key. */
  readonly path: string

  constructor(path: string) {
    super(`pack key required to read encrypted entry: ${path}`)
    this.name = 'PackKeyRequiredError'
    this.path = path
  }
}
