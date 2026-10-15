/**
 * HD Wallet WASM - input validation shared by every wrapper
 *
 * The rule: no input reaches native code until its type, its length (exact,
 * or one of an allowed set) and, for keys, its validity are known good. Native
 * exports read fixed-size inputs (32-byte keys, 33-byte public keys, 64- or
 * 96-byte signatures) without a length, so an input of the wrong size would
 * otherwise be completed from, or written past, stale heap memory.
 *
 * Keys are checked by the module itself, never with curve arithmetic in JS:
 * - hd_curve_validate_privkey: the curve's scalar size, and 0 < d < n for
 *   secp256k1, P-256 and P-384 (any 32 bytes are an Ed25519 seed or an X25519
 *   scalar).
 * - hd_curve_validate_pubkey: SEC1 02/03/04 encodings decoding to a curve point
 *   (libsecp256k1 for secp256k1, OpenSSL for P-256/P-384); Ed25519 keys
 *   canonical, decodable and not of small order; X25519 keys 32 bytes.
 *
 * Operations throw on an invalid input. Verification throws only for a
 * programmer error (an argument of the wrong type, an unknown curve or coin)
 * and returns false for every other invalid input: a signature, key or hash of
 * the wrong length, a key that is not a point, a malformed encoding.
 *
 * @module hd-wallet-wasm/input-validation
 */

/** A UTF-16 surrogate without its partner. */
const UNPAIRED_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

/** Curve ids (match the Curve enum in index.mjs and the aligned schema). */
export const CURVE_ID = Object.freeze({
  SECP256K1: 0,
  ED25519: 1,
  P256: 2,
  P384: 3,
  X25519: 4,
});

/** Error codes thrown here (match ErrorCode in index.mjs). */
export const VALIDATION_ERROR = Object.freeze({
  INVALID_ARGUMENT: 2,
  NOT_SUPPORTED: 3,
  OUT_OF_MEMORY: 4,
  INVALID_PRIVATE_KEY: 400,
  INVALID_PUBLIC_KEY: 401,
  INVALID_SIGNATURE: 402,
});

const CURVE_NAMES = Object.freeze(['secp256k1', 'ed25519', 'P-256', 'P-384', 'X25519']);
const PRIVATE_KEY_LENGTH = Object.freeze([32, 32, 32, 48, 32]);
const PUBLIC_KEY_LENGTHS = Object.freeze([
  Object.freeze([33, 65]),
  Object.freeze([32]),
  Object.freeze([33, 65]),
  Object.freeze([49, 97]),
  Object.freeze([32]),
]);

/**
 * Create the validation helpers, throwing errors made by `makeError(code,
 * message)` (HDWalletError for the main API, AlignedError for the aligned API).
 *
 * @param {(code: number, message: string) => Error} makeError
 */
export function createInputValidation(makeError) {
  const {
    INVALID_ARGUMENT,
    NOT_SUPPORTED,
    OUT_OF_MEMORY,
    INVALID_PRIVATE_KEY,
    INVALID_PUBLIC_KEY,
  } = VALIDATION_ERROR;

  function fail(code, message) {
    throw makeError(code, message);
  }

  function describeLengths(lengths) {
    return typeof lengths === 'number' ? `${lengths}` : lengths.join(' or ');
  }

  /** True when `value` is a Uint8Array (Node Buffers included). */
  function isBytes(value) {
    return value instanceof Uint8Array;
  }

  /** True when the length of `bytes` is `lengths` (a number) or one of `lengths`. */
  function hasLength(bytes, lengths) {
    return typeof lengths === 'number' ? bytes.length === lengths : lengths.includes(bytes.length);
  }

  /** Require binary data (a Uint8Array) of any length. */
  function bytes(value, name = 'data', code = INVALID_ARGUMENT) {
    if (!isBytes(value)) fail(code, `${name} must be a Uint8Array`);
    return value;
  }

  /** Require a Uint8Array whose length is `lengths` or one of `lengths`. */
  function bytesOfLength(value, lengths, name = 'data', code = INVALID_ARGUMENT) {
    bytes(value, name, code);
    if (!hasLength(value, lengths)) fail(code, `${name} must be ${describeLengths(lengths)} bytes`);
    return value;
  }

  /** Require a Uint8Array of min..max bytes. */
  function bytesInRange(value, min, max, name = 'data', code = INVALID_ARGUMENT) {
    bytes(value, name, code);
    if (value.length < min || value.length > max) {
      fail(code, `${name} must be ${min}-${max} bytes`);
    }
    return value;
  }

  /** Require a string. */
  function string(value, name = 'value') {
    if (typeof value !== 'string') fail(INVALID_ARGUMENT, `${name} must be a string`);
    return value;
  }

  /**
   * Require a string that reaches native code unchanged as a NUL-terminated
   * UTF-8 C string: no NUL (native code would stop there, so 'pw\0extra'
   * would act as 'pw') and no unpaired surrogate (which has no UTF-8 form;
   * the encoder would merge it with the next character).
   */
  function cString(value, name = 'value') {
    string(value, name);
    if (value.includes('\0')) fail(INVALID_ARGUMENT, `${name} must not contain a NUL character`);
    if (UNPAIRED_SURROGATE.test(value)) fail(INVALID_ARGUMENT, `${name} must be well-formed Unicode`);
    return value;
  }

  /** Whether a string passes cString (for checks that answer false, not throw). */
  function isCString(value) {
    return typeof value === 'string' && !value.includes('\0') && !UNPAIRED_SURROGATE.test(value);
  }

  /** Require an integer number within [min, max]. */
  function integer(value, name, min, max, code = INVALID_ARGUMENT) {
    if (!Number.isInteger(value) || value < min || value > max) {
      fail(code, `${name} must be an integer from ${min} to ${max}`);
    }
    return value;
  }

  /** Require an unsigned 32-bit integer. */
  function uint32(value, name) {
    return integer(value, name, 0, 0xffffffff);
  }

  /**
   * Require a non-negative integer (number, bigint or decimal string) below
   * 2^bits, returned as a bigint.
   */
  function unsignedBigInt(value, name, bits = 64) {
    let n;
    if (typeof value === 'bigint') {
      n = value;
    } else if (typeof value === 'number' && Number.isSafeInteger(value)) {
      n = BigInt(value);
    } else if (typeof value === 'string' && /^(0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(value)) {
      n = BigInt(value);
    } else {
      fail(INVALID_ARGUMENT, `${name} must be a non-negative integer`);
    }
    if (n < 0n || n >= (1n << BigInt(bits))) {
      fail(INVALID_ARGUMENT, `${name} must be a non-negative integer below 2^${bits}`);
    }
    return n;
  }

  /** Require one of the listed values. */
  function oneOf(value, allowed, name) {
    if (!allowed.includes(value)) fail(INVALID_ARGUMENT, `${name} must be one of ${allowed.join(', ')}`);
    return value;
  }

  /** Require a known curve id, optionally one of `allowed` (NOT_SUPPORTED otherwise). */
  function curve(value, allowed) {
    if (!Number.isInteger(value) || value < 0 || value >= CURVE_NAMES.length ||
        (allowed !== undefined && !allowed.includes(value))) {
      const label = Number.isInteger(value) && value >= 0 && value < CURVE_NAMES.length
        ? CURVE_NAMES[value]
        : String(value);
      fail(NOT_SUPPORTED, `Curve ${label} is not supported here`);
    }
    return value;
  }

  function privateKeyLength(curveId) {
    return PRIVATE_KEY_LENGTH[curve(curveId)];
  }

  function publicKeyLengths(curveId) {
    return PUBLIC_KEY_LENGTHS[curve(curveId)];
  }

  // Run a hd_curve_validate_* export on a copy of `value`; true when valid.
  function nativeKeyCheck(wasm, exportName, value, curveId, secret) {
    const check = wasm[exportName];
    if (typeof check !== 'function') {
      fail(NOT_SUPPORTED, `Function ${exportName} is not available in this build`);
    }
    const pointer = wasm._hd_alloc(Math.max(1, value.length));
    if (!pointer) fail(OUT_OF_MEMORY, 'Out of memory');
    try {
      wasm.HEAPU8.set(value, pointer);
      return check(pointer, value.length, curveId) === 0;
    } finally {
      if (secret) wasm._hd_secure_wipe(pointer, Math.max(1, value.length));
      wasm._hd_dealloc(pointer);
    }
  }

  /**
   * Require a valid private key of `curveId`: the scalar size, and 0 < d < n
   * for the short-Weierstrass curves (checked by the module).
   */
  function privateKey(wasm, value, curveId, name = 'privateKey') {
    const length = privateKeyLength(curveId);
    bytesOfLength(value, length, name, INVALID_PRIVATE_KEY);
    if (!nativeKeyCheck(wasm, '_hd_curve_validate_privkey', value, curveId, true)) {
      fail(INVALID_PRIVATE_KEY, `${name} is not a valid ${CURVE_NAMES[curveId]} private key`);
    }
    return value;
  }

  /**
   * True when `value` (which must be a Uint8Array: anything else is a
   * programmer error and throws) is a valid public key of `curveId` in one of
   * `lengths` (the curve's encodings by default).
   */
  function isPublicKey(wasm, value, curveId, lengths = publicKeyLengths(curveId)) {
    curve(curveId);
    bytes(value, 'publicKey', INVALID_PUBLIC_KEY);
    if (!hasLength(value, lengths)) return false;
    return nativeKeyCheck(wasm, '_hd_curve_validate_pubkey', value, curveId, false);
  }

  /** Require a valid public key of `curveId` in one of `lengths`. */
  function publicKey(wasm, value, curveId, name = 'publicKey', lengths = publicKeyLengths(curveId)) {
    curve(curveId);
    bytesOfLength(value, lengths, name, INVALID_PUBLIC_KEY);
    if (!nativeKeyCheck(wasm, '_hd_curve_validate_pubkey', value, curveId, false)) {
      fail(INVALID_PUBLIC_KEY, `${name} is not a valid ${CURVE_NAMES[curveId]} public key`);
    }
    return value;
  }

  return Object.freeze({
    isBytes,
    hasLength,
    bytes,
    bytesOfLength,
    bytesInRange,
    string,
    cString,
    isCString,
    integer,
    uint32,
    unsignedBigInt,
    oneOf,
    curve,
    privateKeyLength,
    publicKeyLengths,
    privateKey,
    publicKey,
    isPublicKey,
  });
}
