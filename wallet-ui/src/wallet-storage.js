const PROFILE = 'webauthn-prf-hkdf-sha256-aes256gcm-v2';
const IDENTITY_SCHEME = 'sdn-bip32-slip10-purpose-v1';
const SEED_PROFILE = 'password-scrypt-v2';
const RECORD_FIELDS = Object.freeze([
  'aad',
  'canonicalUsername',
  'ciphertextBase64url',
  'createdAt',
  'credentialIdBase64url',
  'hkdfSaltBase64url',
  'nonceBase64url',
  'prfInputBase64url',
  'schemaVersion',
  'storageProfile',
]);
const AAD_FIELDS = Object.freeze([
  'credentialIdBase64url',
  'identityScheme',
  'schemaVersion',
  'seedProfile',
  'storageProfile',
  'usernameSha256',
]);
const RFC3339_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const LOWER_HEX_32 = /^[0-9a-f]{64}$/u;
const BASE64URL = /^[A-Za-z0-9_-]+$/u;
const encoder = new TextEncoder();

export const ACTIVE_REMEMBERED_WALLET_KEY = 'sdn.wallet.remembered.v2';
export const PENDING_REMEMBERED_WALLET_KEY = `${ACTIVE_REMEMBERED_WALLET_KEY}.pending`;
// A canonical v2 record is below 5 KiB at the native 1,024-byte ciphertext and
// credential-ID ceilings. 16 KiB leaves migration headroom without allowing a
// quarantined localStorage value to become an unbounded clipboard/DOM payload.
export const MAX_QUARANTINE_EXPORT_CHARACTERS = 16 * 1024;
export const LEGACY_WALLET_QUARANTINE_KEYS = Object.freeze([
  'wallet_storage_metadata',
  'wallet_storage_encrypted',
  'wallet_storage_passkey_credential',
  'encrypted_wallet',
  'passkey_credential',
  'passkey_wallet',
]);

const deletableKeys = new Set([
  ACTIVE_REMEMBERED_WALLET_KEY,
  PENDING_REMEMBERED_WALLET_KEY,
  ...LEGACY_WALLET_QUARANTINE_KEYS,
]);
const issuedTransactions = new WeakSet();

export class WalletStorageError extends Error {
  constructor(code) {
    super(code);
    this.name = 'WalletStorageError';
    this.code = code;
  }
}

function fail(code) {
  throw new WalletStorageError(code);
}

function ordinaryRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactRecord(input, fields) {
  if (!ordinaryRecord(input)) fail('INVALID_REMEMBERED_WALLET');
  let keys;
  try { keys = Reflect.ownKeys(input); } catch { fail('INVALID_REMEMBERED_WALLET'); }
  if (keys.some((key) => typeof key !== 'string')) fail('INVALID_REMEMBERED_WALLET');
  const expected = [...fields].sort();
  const actual = [...keys].sort();
  if (actual.length !== expected.length
      || actual.some((key, index) => key !== expected[index])) {
    fail('INVALID_REMEMBERED_WALLET');
  }
  const result = {};
  for (const field of expected) {
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(input, field); } catch {
      fail('INVALID_REMEMBERED_WALLET');
    }
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      fail('INVALID_REMEMBERED_WALLET');
    }
    result[field] = descriptor.value;
  }
  return result;
}

function wellFormedString(value) {
  if (typeof value !== 'string') return false;
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    if (first >= 0xd800 && first <= 0xdbff) {
      const second = value.charCodeAt(++index);
      if (!(second >= 0xdc00 && second <= 0xdfff)) return false;
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function encodeBase64url(bytes) {
  let binary = '';
  for (let offset = 0; offset < bytes.length; offset += 0x8000) {
    binary += String.fromCharCode(...bytes.subarray(offset, offset + 0x8000));
  }
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
}

export function decodeCanonicalBase64url(value, { minimum = 0, maximum = 65536, exact = null } = {}) {
  if (typeof value !== 'string' || value.length === 0 || !BASE64URL.test(value)) {
    fail('INVALID_REMEMBERED_WALLET');
  }
  const remainder = value.length % 4;
  if (remainder === 1) fail('INVALID_REMEMBERED_WALLET');
  const padded = value.replace(/-/gu, '+').replace(/_/gu, '/') + '='.repeat((4 - remainder) % 4);
  let binary;
  try { binary = atob(padded); } catch { fail('INVALID_REMEMBERED_WALLET'); }
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  if (encodeBase64url(bytes) !== value || bytes.length < minimum || bytes.length > maximum
      || (exact !== null && bytes.length !== exact)) {
    fail('INVALID_REMEMBERED_WALLET');
  }
  return bytes;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (!ordinaryRecord(value)) fail('INVALID_REMEMBERED_WALLET');
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  )).join(',')}}`;
}

function freezeRecord(record) {
  return Object.freeze({
    aad: Object.freeze({ ...record.aad }),
    canonicalUsername: record.canonicalUsername,
    ciphertextBase64url: record.ciphertextBase64url,
    createdAt: record.createdAt,
    credentialIdBase64url: record.credentialIdBase64url,
    hkdfSaltBase64url: record.hkdfSaltBase64url,
    nonceBase64url: record.nonceBase64url,
    prfInputBase64url: record.prfInputBase64url,
    schemaVersion: record.schemaVersion,
    storageProfile: record.storageProfile,
  });
}

export function validateRememberedWalletRecord(input) {
  const value = exactRecord(input, RECORD_FIELDS);
  const aad = exactRecord(value.aad, AAD_FIELDS);
  const usernameBytes = wellFormedString(value.canonicalUsername)
    ? encoder.encode(value.canonicalUsername)
    : null;
  if (value.schemaVersion !== 2 || value.storageProfile !== PROFILE
      || aad.schemaVersion !== 2 || aad.storageProfile !== PROFILE
      || aad.identityScheme !== IDENTITY_SCHEME || aad.seedProfile !== SEED_PROFILE
      || !usernameBytes || usernameBytes.length < 3 || usernameBytes.length > 64
      || !/^[a-z0-9][a-z0-9._-]*$/u.test(value.canonicalUsername)
      || !LOWER_HEX_32.test(aad.usernameSha256)
      || value.credentialIdBase64url !== aad.credentialIdBase64url
      || !wellFormedString(value.createdAt) || !RFC3339_MILLISECONDS.test(value.createdAt)
      || new Date(value.createdAt).toISOString() !== value.createdAt) {
    fail('INVALID_REMEMBERED_WALLET');
  }
  decodeCanonicalBase64url(value.credentialIdBase64url, { minimum: 1, maximum: 1024 });
  decodeCanonicalBase64url(value.ciphertextBase64url, { minimum: 17, maximum: 1024 });
  decodeCanonicalBase64url(value.hkdfSaltBase64url, { exact: 32 });
  decodeCanonicalBase64url(value.nonceBase64url, { exact: 12 });
  decodeCanonicalBase64url(value.prfInputBase64url, { exact: 32 });
  return freezeRecord({ ...value, aad });
}

export function serializeRememberedWalletRecord(input) {
  return canonicalJson(validateRememberedWalletRecord(input));
}

export function parseRememberedWalletRecord(serialized) {
  if (typeof serialized !== 'string' || serialized.length === 0 || serialized.length > 131072) {
    fail('INVALID_REMEMBERED_WALLET');
  }
  let parsed;
  try { parsed = JSON.parse(serialized); } catch { fail('INVALID_REMEMBERED_WALLET'); }
  const record = validateRememberedWalletRecord(parsed);
  if (canonicalJson(record) !== serialized) fail('INVALID_REMEMBERED_WALLET');
  return record;
}

function readSlot(storage, key, { pending = false } = {}) {
  if (!storage || typeof storage.getItem !== 'function') fail('STORAGE_UNAVAILABLE');
  let raw;
  try { raw = storage.getItem(key); } catch { fail('STORAGE_UNAVAILABLE'); }
  if (raw === null) return Object.freeze({ raw: null, record: null, status: 'empty' });
  if (typeof raw !== 'string') fail('STORAGE_UNAVAILABLE');
  const oversized = raw.length > MAX_QUARANTINE_EXPORT_CHARACTERS;
  if (pending || oversized) {
    return Object.freeze({
      exportable: !oversized,
      oversized,
      raw: oversized ? null : raw,
      rawLength: raw.length,
      record: null,
      status: 'quarantined',
    });
  }
  try {
    const record = parseRememberedWalletRecord(raw);
    return Object.freeze({
      raw,
      record,
      status: pending ? 'quarantined' : 'valid',
    });
  } catch {
    return Object.freeze({
      exportable: true,
      oversized: false,
      raw,
      rawLength: raw.length,
      record: null,
      status: 'quarantined',
    });
  }
}

export function inspectRememberedWalletStorage(storage) {
  const pending = readSlot(storage, PENDING_REMEMBERED_WALLET_KEY, { pending: true });
  const active = readSlot(storage, ACTIVE_REMEMBERED_WALLET_KEY);
  const pendingEmpty = pending.status === 'empty';
  const activeSafe = active.status === 'empty' || active.status === 'valid';
  return Object.freeze({
    active,
    canRestore: pendingEmpty && active.status === 'valid',
    canSetup: pendingEmpty && activeSafe,
    pending,
  });
}

export function beginRememberedWalletWrite(storage, candidate) {
  const state = inspectRememberedWalletStorage(storage);
  if (!state.canSetup) fail('STORAGE_QUARANTINED');
  const serialized = serializeRememberedWalletRecord(candidate);
  try { storage.setItem(PENDING_REMEMBERED_WALLET_KEY, serialized); } catch (error) { throw error; }
  let readback;
  try { readback = storage.getItem(PENDING_REMEMBERED_WALLET_KEY); } catch { fail('STORAGE_UNAVAILABLE'); }
  if (readback !== serialized) fail('STORAGE_WRITE_FAILED');
  parseRememberedWalletRecord(readback);
  const transaction = Object.freeze({
    previousActiveRaw: state.active.raw,
    serialized,
    storage,
  });
  issuedTransactions.add(transaction);
  return transaction;
}

export function commitRememberedWalletWrite(storage, transaction) {
  if (!issuedTransactions.has(transaction) || transaction.storage !== storage) {
    fail('INVALID_STORAGE_TRANSACTION');
  }
  issuedTransactions.delete(transaction);
  let pending;
  let active;
  try {
    pending = storage.getItem(PENDING_REMEMBERED_WALLET_KEY);
    active = storage.getItem(ACTIVE_REMEMBERED_WALLET_KEY);
  } catch {
    fail('STORAGE_UNAVAILABLE');
  }
  if (pending !== transaction.serialized || active !== transaction.previousActiveRaw) {
    fail('STORAGE_COLLISION');
  }
  storage.removeItem(PENDING_REMEMBERED_WALLET_KEY);
  if (storage.getItem(PENDING_REMEMBERED_WALLET_KEY) !== null) fail('STORAGE_WRITE_FAILED');
  storage.setItem(ACTIVE_REMEMBERED_WALLET_KEY, transaction.serialized);
}

function readQuarantineCandidate(storage, key) {
  if (!deletableKeys.has(key)) fail('INVALID_STORAGE_KEY');
  if (!storage || typeof storage.getItem !== 'function') fail('STORAGE_UNAVAILABLE');
  let raw;
  try { raw = storage.getItem(key); } catch { fail('STORAGE_UNAVAILABLE'); }
  if (raw === null) return null;
  if (typeof raw !== 'string') fail('STORAGE_UNAVAILABLE');
  if (key === ACTIVE_REMEMBERED_WALLET_KEY
      && raw.length <= MAX_QUARANTINE_EXPORT_CHARACTERS) {
    try {
      parseRememberedWalletRecord(raw);
      fail('NOT_QUARANTINED');
    } catch (error) {
      if (error instanceof WalletStorageError && error.code === 'NOT_QUARANTINED') throw error;
    }
  }
  return Object.freeze({
    exportable: raw.length <= MAX_QUARANTINE_EXPORT_CHARACTERS,
    key,
    oversized: raw.length > MAX_QUARANTINE_EXPORT_CHARACTERS,
    raw,
    rawLength: raw.length,
  });
}

function publicQuarantineEntry(candidate) {
  return Object.freeze({
    exportable: candidate.exportable,
    key: candidate.key,
    oversized: candidate.oversized,
    rawLength: candidate.rawLength,
  });
}

export function inspectQuarantinedWalletStorage(storage) {
  const entries = [];
  for (const key of [
    ACTIVE_REMEMBERED_WALLET_KEY,
    PENDING_REMEMBERED_WALLET_KEY,
    ...LEGACY_WALLET_QUARANTINE_KEYS,
  ]) {
    let candidate;
    try { candidate = readQuarantineCandidate(storage, key); } catch (error) {
      if (error instanceof WalletStorageError && error.code === 'NOT_QUARANTINED') continue;
      throw error;
    }
    if (candidate) entries.push(publicQuarantineEntry(candidate));
  }
  return Object.freeze(entries);
}

export function inspectLegacyWalletQuarantine(storage) {
  return Object.freeze(inspectQuarantinedWalletStorage(storage).filter(
    ({ key }) => LEGACY_WALLET_QUARANTINE_KEYS.includes(key),
  ));
}

export function exportQuarantinedWalletRecord(storage, key) {
  const candidate = readQuarantineCandidate(storage, key);
  if (!candidate) fail('QUARANTINE_NOT_FOUND');
  if (!candidate.exportable) fail('QUARANTINE_EXPORT_TOO_LARGE');
  return candidate.raw;
}

export function deleteQuarantinedWalletRecord(storage, key, confirmation) {
  if (!deletableKeys.has(key)) fail('INVALID_STORAGE_KEY');
  if (confirmation !== key) fail('CONFIRMATION_REQUIRED');
  const candidate = readQuarantineCandidate(storage, key);
  if (!candidate) fail('QUARANTINE_NOT_FOUND');
  try {
    storage.removeItem(key);
    if (storage.getItem(key) !== null) fail('STORAGE_WRITE_FAILED');
  } catch (error) {
    if (error instanceof WalletStorageError) throw error;
    fail('STORAGE_UNAVAILABLE');
  }
}

export function forgetRememberedWallet(storage, confirmation) {
  if (confirmation !== ACTIVE_REMEMBERED_WALLET_KEY) fail('CONFIRMATION_REQUIRED');
  const active = readSlot(storage, ACTIVE_REMEMBERED_WALLET_KEY);
  if (active.status === 'empty') fail('REMEMBER_UNAVAILABLE');
  if (active.status !== 'valid') fail('STORAGE_QUARANTINED');
  try {
    storage.removeItem(ACTIVE_REMEMBERED_WALLET_KEY);
    if (storage.getItem(ACTIVE_REMEMBERED_WALLET_KEY) !== null) {
      fail('STORAGE_WRITE_FAILED');
    }
  } catch (error) {
    if (error instanceof WalletStorageError) throw error;
    fail('STORAGE_UNAVAILABLE');
  }
}

export default Object.freeze({
  ACTIVE_REMEMBERED_WALLET_KEY,
  LEGACY_WALLET_QUARANTINE_KEYS,
  MAX_QUARANTINE_EXPORT_CHARACTERS,
  PENDING_REMEMBERED_WALLET_KEY,
  beginRememberedWalletWrite,
  commitRememberedWalletWrite,
  deleteQuarantinedWalletRecord,
  exportQuarantinedWalletRecord,
  forgetRememberedWallet,
  inspectLegacyWalletQuarantine,
  inspectQuarantinedWalletStorage,
  inspectRememberedWalletStorage,
  parseRememberedWalletRecord,
  serializeRememberedWalletRecord,
  validateRememberedWalletRecord,
});
