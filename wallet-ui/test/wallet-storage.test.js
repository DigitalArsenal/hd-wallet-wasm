import { beforeEach, describe, expect, test } from 'vitest';

import {
  ACTIVE_REMEMBERED_WALLET_KEY,
  LEGACY_WALLET_QUARANTINE_KEYS,
  MAX_QUARANTINE_EXPORT_CHARACTERS,
  PENDING_REMEMBERED_WALLET_KEY,
  beginRememberedWalletWrite,
  commitRememberedWalletWrite,
  deleteQuarantinedWalletRecord,
  exportQuarantinedWalletRecord,
  forgetRememberedWallet,
  inspectQuarantinedWalletStorage,
  inspectRememberedWalletStorage,
  parseRememberedWalletRecord,
  serializeRememberedWalletRecord,
} from '../src/wallet-storage.js';

const PROFILE = 'webauthn-prf-hkdf-sha256-aes256gcm-v2';

function base64url(length, start = 0) {
  const bytes = Uint8Array.from({ length }, (_unused, index) => (start + index) & 0xff);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
}

function record(overrides = {}) {
  const credentialIdBase64url = base64url(32, 0xa0);
  const aad = {
    credentialIdBase64url,
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    schemaVersion: 2,
    seedProfile: 'password-scrypt-v2',
    storageProfile: PROFILE,
    usernameSha256: '6'.repeat(64),
  };
  return {
    aad,
    canonicalUsername: 'alice_01',
    ciphertextBase64url: base64url(96, 1),
    createdAt: '2026-07-21T12:00:00.000Z',
    credentialIdBase64url,
    hkdfSaltBase64url: base64url(32, 0x20),
    nonceBase64url: base64url(12, 0x40),
    prfInputBase64url: base64url(32, 0x60),
    schemaVersion: 2,
    storageProfile: PROFILE,
    ...overrides,
  };
}

class FakeStorage {
  constructor(entries = []) {
    this.map = new Map(entries);
    this.operations = [];
  }

  getItem(key) {
    this.operations.push(['getItem', key]);
    return this.map.has(key) ? this.map.get(key) : null;
  }

  setItem(key, value) {
    this.operations.push(['setItem', key, String(value)]);
    this.map.set(key, String(value));
  }

  removeItem(key) {
    this.operations.push(['removeItem', key]);
    this.map.delete(key);
  }
}

describe('remembered wallet v2 storage parser', () => {
  test('accepts and round-trips only canonical exact v2 JCS', () => {
    const serialized = serializeRememberedWalletRecord(record());
    const parsed = parseRememberedWalletRecord(serialized);

    expect(serialized).toBe(JSON.stringify(parsed));
    expect(Object.keys(parsed)).toEqual([
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
    expect(Object.keys(parsed.aad)).toEqual([
      'credentialIdBase64url',
      'identityScheme',
      'schemaVersion',
      'seedProfile',
      'storageProfile',
      'usernameSha256',
    ]);
  });

  test('accepts the native 1024-byte ciphertext ceiling and rejects one byte more', () => {
    expect(() => serializeRememberedWalletRecord(record({
      ciphertextBase64url: base64url(1024, 1),
    }))).not.toThrow();
    expect(() => serializeRememberedWalletRecord(record({
      ciphertextBase64url: base64url(1025, 1),
    }))).toThrowError(/INVALID_REMEMBERED_WALLET/u);
  });

  test.each([
    ['whitespace around JCS', (value) => ` ${value}`],
    ['noncanonical base64url', (value) => value.replace('"nonceBase64url":"', '"nonceBase64url":"=')],
    ['unknown schema', (value) => value.replace('"schemaVersion":2', '"schemaVersion":3')],
    ['PIN legacy data', () => JSON.stringify({ method: 'pin', version: 3 })],
    ['PRF-disabled legacy data', () => JSON.stringify({ hasPRF: false, version: 3 })],
    ['raw seed plaintext', () => JSON.stringify({ seedBase64url: base64url(32), version: 2 })],
  ])('quarantines %s without reinterpreting it', (_name, mutate) => {
    const active = mutate(serializeRememberedWalletRecord(record()));
    const storage = new FakeStorage([[ACTIVE_REMEMBERED_WALLET_KEY, active]]);

    expect(inspectRememberedWalletStorage(storage)).toMatchObject({
      active: { raw: active, status: 'quarantined' },
      canRestore: false,
      canSetup: false,
    });
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(active);
  });

  test('treats every crash-left pending value as quarantine and never auto-promotes it', () => {
    const active = serializeRememberedWalletRecord(record());
    const pending = serializeRememberedWalletRecord(record({ createdAt: '2026-07-21T12:01:00.000Z' }));
    const storage = new FakeStorage([
      [ACTIVE_REMEMBERED_WALLET_KEY, active],
      [PENDING_REMEMBERED_WALLET_KEY, pending],
    ]);

    expect(inspectRememberedWalletStorage(storage)).toMatchObject({
      active: { status: 'valid' },
      pending: { raw: pending, status: 'quarantined' },
      canRestore: false,
      canSetup: false,
    });
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(active);
    expect(storage.map.get(PENDING_REMEMBERED_WALLET_KEY)).toBe(pending);
  });
});

describe('remembered wallet v2 storage transaction', () => {
  let storage;

  beforeEach(() => {
    storage = new FakeStorage();
  });

  test('writes pending, verifies its exact readback, removes it, then commits active last', () => {
    const candidate = record();
    const serialized = serializeRememberedWalletRecord(candidate);
    const transaction = beginRememberedWalletWrite(storage, candidate);

    expect(storage.map.get(PENDING_REMEMBERED_WALLET_KEY)).toBe(serialized);
    expect(storage.map.has(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(false);

    commitRememberedWalletWrite(storage, transaction);

    expect(storage.map.has(PENDING_REMEMBERED_WALLET_KEY)).toBe(false);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(serialized);
    expect(storage.operations.at(-1)).toEqual(['setItem', ACTIVE_REMEMBERED_WALLET_KEY, serialized]);
  });

  test('a pending collision blocks setup without writing', () => {
    const pending = serializeRememberedWalletRecord(record());
    storage.map.set(PENDING_REMEMBERED_WALLET_KEY, pending);

    expect(() => beginRememberedWalletWrite(storage, record())).toThrowError(/STORAGE_QUARANTINED/u);
    expect(storage.operations.some(([operation]) => operation === 'setItem')).toBe(false);
    expect(storage.map.get(PENDING_REMEMBERED_WALLET_KEY)).toBe(pending);
  });

  test('a malformed active collision blocks replacement without writing', () => {
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, '{"version":1}');

    expect(() => beginRememberedWalletWrite(storage, record())).toThrowError(/STORAGE_QUARANTINED/u);
    expect(storage.operations.some(([operation]) => operation === 'setItem')).toBe(false);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe('{"version":1}');
  });

  test('a final active write failure preserves the previous active record', () => {
    const previous = serializeRememberedWalletRecord(record({ createdAt: '2026-07-20T12:00:00.000Z' }));
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, previous);
    const transaction = beginRememberedWalletWrite(storage, record());
    const originalSet = storage.setItem.bind(storage);
    storage.setItem = (key, value) => {
      if (key === ACTIVE_REMEMBERED_WALLET_KEY) throw new Error('quota fault');
      originalSet(key, value);
    };

    expect(() => commitRememberedWalletWrite(storage, transaction)).toThrowError(/quota fault/u);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(previous);
  });

  test('deletion requires an exact key confirmation and reads back null', () => {
    const pending = serializeRememberedWalletRecord(record());
    storage.map.set(PENDING_REMEMBERED_WALLET_KEY, pending);

    expect(() => deleteQuarantinedWalletRecord(
      storage,
      PENDING_REMEMBERED_WALLET_KEY,
      ACTIVE_REMEMBERED_WALLET_KEY,
    )).toThrowError(/CONFIRMATION_REQUIRED/u);
    expect(storage.map.get(PENDING_REMEMBERED_WALLET_KEY)).toBe(pending);

    deleteQuarantinedWalletRecord(storage, PENDING_REMEMBERED_WALLET_KEY, PENDING_REMEMBERED_WALLET_KEY);
    expect(storage.map.has(PENDING_REMEMBERED_WALLET_KEY)).toBe(false);
    expect(storage.operations.slice(-2)).toEqual([
      ['removeItem', PENDING_REMEMBERED_WALLET_KEY],
      ['getItem', PENDING_REMEMBERED_WALLET_KEY],
    ]);
  });

  test('forget requires exact confirmation, deletes only a valid active record, and reads back null', () => {
    const active = serializeRememberedWalletRecord(record());
    const pending = '{"crash":"left"}';
    const legacyKey = 'wallet_storage_encrypted';
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, active);
    storage.map.set(PENDING_REMEMBERED_WALLET_KEY, pending);
    storage.map.set(legacyKey, 'legacy-ciphertext');

    expect(() => forgetRememberedWallet(storage, 'forget')).toThrowError(/CONFIRMATION_REQUIRED/u);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(active);

    forgetRememberedWallet(storage, ACTIVE_REMEMBERED_WALLET_KEY);

    expect(storage.map.has(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(false);
    expect(storage.map.get(PENDING_REMEMBERED_WALLET_KEY)).toBe(pending);
    expect(storage.map.get(legacyKey)).toBe('legacy-ciphertext');
    const removal = storage.operations.findLastIndex(
      ([operation, key]) => operation === 'removeItem' && key === ACTIVE_REMEMBERED_WALLET_KEY,
    );
    expect(storage.operations.slice(removal, removal + 2)).toEqual([
      ['removeItem', ACTIVE_REMEMBERED_WALLET_KEY],
      ['getItem', ACTIVE_REMEMBERED_WALLET_KEY],
    ]);
  });

  test('forget refuses to reinterpret a quarantined active record', () => {
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, '{"method":"pin"}');

    expect(() => forgetRememberedWallet(
      storage,
      ACTIVE_REMEMBERED_WALLET_KEY,
    )).toThrowError(/STORAGE_QUARANTINED/u);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe('{"method":"pin"}');
  });

  test('generic quarantine operations exclude a structurally valid active record', () => {
    const active = serializeRememberedWalletRecord(record());
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, active);

    expect(inspectQuarantinedWalletStorage(storage)).toEqual([]);
    expect(() => exportQuarantinedWalletRecord(
      storage,
      ACTIVE_REMEMBERED_WALLET_KEY,
    )).toThrowError(/NOT_QUARANTINED/u);
    expect(() => deleteQuarantinedWalletRecord(
      storage,
      ACTIVE_REMEMBERED_WALLET_KEY,
      ACTIVE_REMEMBERED_WALLET_KEY,
    )).toThrowError(/NOT_QUARANTINED/u);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(active);
  });

  test('classifies malformed active, every pending value, and every present legacy key', () => {
    const pending = serializeRememberedWalletRecord(record());
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, '{"broken":true}');
    storage.map.set(PENDING_REMEMBERED_WALLET_KEY, pending);
    for (const key of LEGACY_WALLET_QUARANTINE_KEYS) storage.map.set(key, `legacy:${key}`);

    const entries = inspectQuarantinedWalletStorage(storage);
    expect(entries.map(({ key }) => key)).toEqual([
      ACTIVE_REMEMBERED_WALLET_KEY,
      PENDING_REMEMBERED_WALLET_KEY,
      ...LEGACY_WALLET_QUARANTINE_KEYS,
    ]);
    expect(entries.every((entry) => entry.exportable === true && entry.oversized === false)).toBe(true);
    expect(exportQuarantinedWalletRecord(storage, ACTIVE_REMEMBERED_WALLET_KEY)).toBe('{"broken":true}');
    expect(exportQuarantinedWalletRecord(storage, PENDING_REMEMBERED_WALLET_KEY)).toBe(pending);
  });

  test('refuses a 2,000,000-character export without retaining it but permits exact deletion', () => {
    expect(MAX_QUARANTINE_EXPORT_CHARACTERS).toBeGreaterThan(4096);
    expect(MAX_QUARANTINE_EXPORT_CHARACTERS).toBeLessThan(2_000_000);
    const oversized = 'x'.repeat(2_000_000);
    const key = LEGACY_WALLET_QUARANTINE_KEYS[0];
    storage.map.set(key, oversized);

    const [entry] = inspectQuarantinedWalletStorage(storage);
    expect(entry).toEqual({
      exportable: false,
      key,
      oversized: true,
      rawLength: 2_000_000,
    });
    expect(entry).not.toHaveProperty('raw');
    expect(() => exportQuarantinedWalletRecord(storage, key)).toThrowError(/QUARANTINE_EXPORT_TOO_LARGE/u);
    expect(storage.map.get(key)).toBe(oversized);

    deleteQuarantinedWalletRecord(storage, key, key);
    expect(storage.map.has(key)).toBe(false);
    expect(storage.operations.slice(-2)).toEqual([
      ['removeItem', key],
      ['getItem', key],
    ]);
  });
});
