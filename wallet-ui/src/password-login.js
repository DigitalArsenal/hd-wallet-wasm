/**
 * Password sign-in (SEC-015).
 *
 * New password sign-ins use the memory-hard SDN profile "password-scrypt-v2"
 * (the native hd-wallet profile, src/password_profile.cpp):
 *
 *   canonical = canonicalize_username(username)   trim ASCII spaces, ASCII
 *                                                 lowercase, 3..64 bytes
 *   policy    = 12..128 characters, no control characters, not all
 *               whitespace, not in the common-password list
 *   seed      = scrypt(password,
 *                      "sdn-hd-wallet/password-scrypt-v2" || 0x00 || canonical,
 *                      N = 2^16, r = 8, p = 1, 64 bytes)
 *
 * The native profile runs first (module.sdn.derivePasswordIdentity): it
 * applies the canonicalization and the policy, and returns the account's
 * public identity. The page then derives the same seed with the WASM scrypt
 * and refuses to continue unless its m/44'/0'/0' xpub equals the native one,
 * so the BIP-44 wallet keys provably come from the native profile, and a KDF
 * that silently failed can never produce a usable seed.
 *
 * On top of the native policy the page requires a real strength estimate
 * (zxcvbn: dictionaries, names, keyboard patterns, repeats, dates, l33t):
 * at least 10^20 estimated guesses. Character classes count for nothing.
 *
 * Wallets made with the retired fast method (SHA-256 + HKDF, no slow KDF:
 * "password-fast-v1-legacy") still open, READ-ONLY, through "Sign in with
 * old password method", so their funds stay reachable; the only spending
 * they allow is the guided sweep to a new wallet.
 */

export const PASSWORD_PROFILE = 'password-scrypt-v2';
export const LEGACY_PASSWORD_PROFILE = 'password-fast-v1-legacy';
export const SCRYPT_N = 65536;
export const SCRYPT_R = 8;
export const SCRYPT_P = 1;
export const SEED_BYTES = 64;
export const SCRYPT_SALT_LABEL = 'sdn-hd-wallet/password-scrypt-v2';
export const MIN_PASSWORD_CHARACTERS = 12;
export const MAX_PASSWORD_CHARACTERS = 128;
export const MAX_CREDENTIAL_BYTES = 256;
/** The estimate a new password must reach: 10^20 guesses (about 66 bits). */
export const MIN_GUESSES_LOG10 = 20;
export const LEGACY_MAX_CREDENTIAL_BYTES = 4096;

const encoder = new TextEncoder();

export class PasswordLoginError extends Error {
  constructor(code, message) {
    super(message ?? MESSAGES[code] ?? code);
    this.name = 'PasswordLoginError';
    this.code = code;
  }
}

const MESSAGES = Object.freeze({
  INVALID_USERNAME: 'A username is 3 to 64 characters (bytes) after trimming spaces.',
  INVALID_PASSWORD: `A password is ${MIN_PASSWORD_CHARACTERS} to ${MAX_PASSWORD_CHARACTERS} characters with no control characters.`,
  COMMON_PASSWORD: 'This password is on the list of the most common passwords.',
  WEAK_PASSWORD: 'This password is too easy to guess. Use five or more uncommon words, or a longer random password.',
  KDF_FAILURE: 'The password could not be processed. Nothing was derived.',
  PROFILE_MISMATCH: 'The password derivation did not match the wallet profile. Nothing was derived.',
});

function fail(code, message) {
  throw new PasswordLoginError(code, message);
}

function wipe(bytes) {
  if (bytes instanceof Uint8Array) {
    try { bytes.fill(0); } catch { /* detached */ }
  }
}

function isWellFormed(text) {
  if (typeof text !== 'string') return false;
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = text.charCodeAt(i + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      i += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function isControl(codePoint) {
  return codePoint <= 0x1f || (codePoint >= 0x7f && codePoint <= 0x9f);
}

const PASSWORD_WHITESPACE = new Set([0x20, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000]);
function isPasswordWhitespace(codePoint) {
  return PASSWORD_WHITESPACE.has(codePoint) || (codePoint >= 0x2000 && codePoint <= 0x200a);
}

/**
 * The native canonicalize_username, in the page: trim ASCII spaces, fold
 * ASCII capitals, 3..64 bytes, no control characters. Returns the canonical
 * string or throws PasswordLoginError('INVALID_USERNAME').
 */
export function canonicalizeUsername(raw) {
  if (!isWellFormed(raw)) fail('INVALID_USERNAME');
  const bytes = encoder.encode(raw);
  if (bytes.length > MAX_CREDENTIAL_BYTES) fail('INVALID_USERNAME');
  for (const char of raw) {
    if (isControl(char.codePointAt(0))) fail('INVALID_USERNAME');
  }
  const trimmed = raw.replace(/^ +| +$/gu, '');
  const length = encoder.encode(trimmed).length;
  if (length < 3 || length > 64) fail('INVALID_USERNAME');
  return trimmed.replace(/[A-Z]/gu, (c) => c.toLowerCase());
}

/**
 * The native length and character policy (the common-password check runs
 * natively and in the strength estimate). Returns null or an error code.
 */
export function passwordPolicyProblem(password) {
  if (!isWellFormed(password)) return 'INVALID_PASSWORD';
  if (encoder.encode(password).length > MAX_CREDENTIAL_BYTES) return 'INVALID_PASSWORD';
  const scalars = [...password].map((c) => c.codePointAt(0));
  if (scalars.some(isControl)) return 'INVALID_PASSWORD';
  if (scalars.length < MIN_PASSWORD_CHARACTERS || scalars.length > MAX_PASSWORD_CHARACTERS) return 'INVALID_PASSWORD';
  if (scalars.every(isPasswordWhitespace)) return 'INVALID_PASSWORD';
  return null;
}

let _estimatorPromise = null;

/**
 * The zxcvbn estimator, loaded on first use (its dictionaries are a separate
 * chunk, fetched only when someone opens the password form).
 */
export function loadStrengthEstimator() {
  _estimatorPromise ??= (async () => {
    const [{ ZxcvbnFactory }, common, en] = await Promise.all([
      import('@zxcvbn-ts/core'),
      import('@zxcvbn-ts/language-common'),
      import('@zxcvbn-ts/language-en'),
    ]);
    const factory = new ZxcvbnFactory({
      dictionary: { ...common.dictionary, ...en.dictionary },
      graphs: common.adjacencyGraphs,
      translations: en.translations,
      // Levenshtein matching costs seconds per check on long inputs; the
      // dictionary, l33t, keyboard, repeat, sequence and date matchers run.
      useLevenshteinDistance: false,
    });
    return Object.freeze({
      estimate(password, userInputs = []) {
        const result = factory.check(String(password ?? ''), userInputs.filter((v) => typeof v === 'string' && v));
        return Object.freeze({
          guessesLog10: Number(result.guessesLog10) || 0,
          bits: (Number(result.guessesLog10) || 0) * Math.log2(10),
          warning: result.feedback?.warning || '',
          suggestions: Object.freeze([...(result.feedback?.suggestions ?? [])]),
        });
      },
    });
  })();
  _estimatorPromise.catch(() => { _estimatorPromise = null; });
  return _estimatorPromise;
}

/**
 * Can this username/password create or open a scrypt-profile wallet?
 * `estimator` is the loaded zxcvbn estimator (no estimator: never OK).
 * Returns { ok, code, message, guessesLog10, bits }.
 */
export function assessNewPassword({ username, password, estimator }) {
  const result = (ok, code, extra = {}) => Object.freeze({
    ok,
    code,
    message: code ? (extra.message || MESSAGES[code] || code) : '',
    guessesLog10: extra.guessesLog10 ?? 0,
    bits: extra.bits ?? 0,
  });
  let canonical;
  try {
    canonical = canonicalizeUsername(String(username ?? ''));
  } catch {
    return result(false, 'INVALID_USERNAME');
  }
  const pw = String(password ?? '');
  if (!estimator) return result(false, 'ESTIMATOR_UNAVAILABLE', { message: 'Loading the password checker…' });
  const estimate = estimator.estimate(pw, [canonical, String(username ?? '')]);
  const extra = { guessesLog10: estimate.guessesLog10, bits: estimate.bits };
  const policy = passwordPolicyProblem(pw);
  if (policy) return result(false, policy, extra);
  if (estimate.guessesLog10 < MIN_GUESSES_LOG10) {
    const hint = [estimate.warning, ...estimate.suggestions].filter(Boolean).join(' ');
    return result(false, 'WEAK_PASSWORD', { ...extra, message: `${MESSAGES.WEAK_PASSWORD}${hint ? ` ${hint}` : ''}` });
  }
  return result(true, '', extra);
}

function scryptSalt(canonical) {
  const label = encoder.encode(SCRYPT_SALT_LABEL);
  const name = encoder.encode(canonical);
  const salt = new Uint8Array(label.length + 1 + name.length);
  salt.set(label, 0);
  salt[label.length] = 0;
  salt.set(name, label.length + 1);
  return salt;
}

async function nativeIdentity(module, method, username, password) {
  const capabilities = module?.sdn;
  if (typeof capabilities?.[method] !== 'function' || typeof capabilities.destroySdnIdentity !== 'function') {
    fail('KDF_FAILURE');
  }
  // The native call wipes the password buffer it is handed.
  const passwordUtf8 = encoder.encode(password);
  let derived;
  try {
    derived = await capabilities[method]({
      usernameUtf8: encoder.encode(username),
      passwordUtf8,
      accountIndex: 0,
    });
  } catch (error) {
    const code = error?.code;
    if (code === 'COMMON_PASSWORD' || code === 'INVALID_PASSWORD' || code === 'INVALID_USERNAME') fail(code);
    fail('KDF_FAILURE');
  } finally {
    wipe(passwordUtf8);
  }
  try {
    const xpub = derived?.identity?.accountXpub;
    const profile = derived?.identity?.seedProfile;
    if (typeof xpub !== 'string' || !xpub.startsWith('xpub')) fail('KDF_FAILURE');
    return { xpub, profile };
  } finally {
    try { capabilities.destroySdnIdentity(derived.handle); } catch { /* the handle is gone either way */ }
  }
}

function nodeXpub(module, seed, path) {
  const root = module.hdkey.fromSeed(seed);
  let node = null;
  try {
    node = path ? root.derivePath(path) : root;
    return node.toXpub();
  } finally {
    try { if (node && node !== root) node.wipe?.(); } catch { /* released */ }
    try { root.wipe?.(); } catch { /* released */ }
  }
}

function checkedSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== SEED_BYTES || seed.every((b) => b === 0)) {
    wipe(seed);
    fail('KDF_FAILURE');
  }
  return seed;
}

/**
 * Derive the 64-byte HD seed of the scrypt profile. The caller owns (and
 * must wipe) the returned bytes.
 */
export async function derivePasswordSeed(module, { username, password }) {
  const canonical = canonicalizeUsername(String(username ?? ''));
  const policy = passwordPolicyProblem(String(password ?? ''));
  if (policy) fail(policy);
  const native = await nativeIdentity(module, 'derivePasswordIdentity', username, password);
  if (native.profile !== PASSWORD_PROFILE) fail('PROFILE_MISMATCH');
  const passwordBytes = encoder.encode(password);
  let seed;
  try {
    seed = module.utils.scrypt(passwordBytes, scryptSalt(canonical), SCRYPT_N, SCRYPT_R, SCRYPT_P, SEED_BYTES);
  } catch {
    fail('KDF_FAILURE');
  } finally {
    wipe(passwordBytes);
  }
  seed = checkedSeed(seed instanceof Uint8Array ? seed : new Uint8Array(seed ?? []));
  let xpub;
  try {
    xpub = nodeXpub(module, seed, "m/44'/0'/0'");
  } catch {
    wipe(seed);
    fail('KDF_FAILURE');
  }
  if (xpub !== native.xpub) {
    wipe(seed);
    fail('PROFILE_MISMATCH');
  }
  return seed;
}

/**
 * Derive the 64-byte HD seed of the RETIRED fast method, exactly as wallet-ui
 * 2.x did (SHA-256(username || password), HKDF "master-key" salted with the
 * username, HKDF "hd-wallet-seed"), cross-checked against the native legacy
 * profile. Only for opening an old wallet read-only and sweeping it.
 */
export async function deriveLegacyPasswordSeed(module, { username, password }) {
  const user = String(username ?? '');
  const pw = String(password ?? '');
  if (!isWellFormed(user) || !user) fail('INVALID_USERNAME', 'Enter the username you used.');
  if (!isWellFormed(pw) || !pw) fail('INVALID_PASSWORD', 'Enter the password you used.');
  if (encoder.encode(user).length > LEGACY_MAX_CREDENTIAL_BYTES || encoder.encode(pw).length > LEGACY_MAX_CREDENTIAL_BYTES) {
    fail('INVALID_PASSWORD', 'That username or password is too long.');
  }
  const native = await nativeIdentity(module, 'deriveLegacyPasswordIdentity', user, pw);
  if (native.profile !== LEGACY_PASSWORD_PROFILE) fail('PROFILE_MISMATCH');
  const usernameBytes = encoder.encode(user);
  const passwordBytes = encoder.encode(pw);
  const joined = new Uint8Array(usernameBytes.length + passwordBytes.length);
  joined.set(usernameBytes, 0);
  joined.set(passwordBytes, usernameBytes.length);
  let initial;
  let master;
  let seed;
  try {
    initial = module.utils.sha256(joined);
    master = module.utils.hkdf(initial, usernameBytes, encoder.encode('master-key'), 32);
    seed = module.utils.hkdf(master, new Uint8Array(0), encoder.encode('hd-wallet-seed'), SEED_BYTES);
  } catch {
    fail('KDF_FAILURE');
  } finally {
    wipe(joined);
    wipe(passwordBytes);
    wipe(initial);
    wipe(master);
  }
  seed = checkedSeed(seed instanceof Uint8Array ? seed : new Uint8Array(seed ?? []));
  let xpub;
  try {
    xpub = nodeXpub(module, seed, null);
  } catch {
    wipe(seed);
    fail('KDF_FAILURE');
  }
  if (xpub !== native.xpub) {
    wipe(seed);
    fail('PROFILE_MISMATCH');
  }
  return seed;
}
