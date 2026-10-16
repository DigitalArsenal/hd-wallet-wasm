// Per-seed storage (account-storage.js): two seeds never share a profile or
// contacts, the 2.x keys migrate once and are deleted, Forget removes every
// hdw:<fp>:* key, and nothing secret ever lands in storage.

import initHDWallet from 'hd-wallet-wasm';
import { describe, expect, it } from 'vitest';

import {
  CURRENCIES,
  LEGACY_KEYS,
  accountRecordKey,
  createAccountStorage,
  migrateCurrency,
  migrateLegacyStorage,
  profileFromLegacyVcard,
  readCurrency,
  readSection,
  writeCurrency,
  writeSection,
} from '../src/account-storage.js';
import { buildContactEpm, contactFromEpm, upsertContact } from '../src/contact-card.js';
import {
  accountXpub,
  accountXprv,
  deriveAccountAddresses,
  deriveIdentity,
  namespaceFingerprint,
  toHex,
  withChainKey,
  withEdKey,
} from '../src/identity-keys.js';
import { memoryStorage } from './helpers/stub-dom.mjs';

const A = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const B = `${'zoo '.repeat(11)}wrong`;
const wallet = await initHDWallet();

function seedSession(phrase, storage) {
  const seed = wallet.mnemonic.toSeed(phrase);
  const root = wallet.hdkey.fromSeed(seed);
  const fp = namespaceFingerprint(wallet, root.toXpub());
  return { phrase, seed, root, fp, store: createAccountStorage({ fp, storage }) };
}

describe('namespacing', () => {
  it('keys every record by seed fingerprint and account number', () => {
    expect(accountRecordKey('0123456789abcdef', 2, 'profile')).toBe('hdw:0123456789abcdef:a2:profile');
    expect(() => accountRecordKey('nope', 0, 'profile')).toThrow();
    expect(() => accountRecordKey('0123456789abcdef', 0, 'mnemonic')).toThrow();
  });

  it('two seeds do not share a profile or contacts', () => {
    const storage = memoryStorage();
    const a = seedSession(A, storage);
    const b = seedSession(B, storage);
    a.store.write(0, 'profile', { name: 'Alice' });
    a.store.write(0, 'contacts', [{ peerId: 'x', name: 'Bob' }]);
    expect(b.store.read(0, 'profile')).toBeNull();
    expect(b.store.read(0, 'contacts', [])).toEqual([]);
    b.store.write(0, 'profile', { name: 'Brenda' });
    expect(a.store.read(0, 'profile')).toEqual({ name: 'Alice' });
    expect(seedSession(A, storage).store.read(0, 'profile')).toEqual({ name: 'Alice' });
  });

  it('accounts of one seed are separate, and the current account number is remembered', () => {
    const storage = memoryStorage();
    const a = seedSession(A, storage);
    a.store.write(0, 'profile', { name: 'Zero' });
    a.store.write(1, 'profile', { name: 'One' });
    expect(a.store.read(1, 'profile')).toEqual({ name: 'One' });
    expect(a.store.readAccount()).toBe(0);
    a.store.writeAccount(7);
    expect(seedSession(A, storage).store.readAccount()).toBe(7);
  });

  it('Forget removes every hdw:<fp>:* key and nothing else', () => {
    const storage = memoryStorage({ 'hd-wallet-price-cache-v1': '{}', 'hdw-currency': 'EUR' });
    const a = seedSession(A, storage);
    const b = seedSession(B, storage);
    a.store.writeAccount(1);
    for (const record of ['profile', 'contacts', 'trust-imported-txs', 'trust-drain-baselines', 'scan-cache']) {
      a.store.write(0, record, { x: 1 });
      a.store.write(1, record, { x: 1 });
    }
    b.store.write(0, 'profile', { name: 'B' });
    a.store.forget();
    expect(storage.entries().filter(([key]) => key.startsWith(`hdw:${a.fp}:`))).toEqual([]);
    expect(b.store.read(0, 'profile')).toEqual({ name: 'B' });
    expect(storage.getItem('hdw-currency')).toBe('EUR');
    expect(storage.getItem('hd-wallet-price-cache-v1')).toBe('{}');
  });

  it('survives blocked storage', () => {
    const blocked = {
      getItem() { throw new Error('blocked'); },
      setItem() { throw new Error('blocked'); },
      removeItem() { throw new Error('blocked'); },
      key() { throw new Error('blocked'); },
      get length() { throw new Error('blocked'); },
    };
    const store = createAccountStorage({ fp: '0123456789abcdef', storage: blocked });
    expect(store.read(0, 'profile', 'fallback')).toBe('fallback');
    expect(store.write(0, 'profile', {})).toBe(false);
    expect(store.readAccount()).toBe(0);
    expect(() => store.forget()).not.toThrow();
  });
});

describe('the one-time 2.x migration', () => {
  function legacyStorage() {
    return memoryStorage({
      'hd-wallet-wallets': '[{"id":0}]',
      'hd-wallet-active-accounts': '[]',
      'hd-wallet-vcard-identity': JSON.stringify({
        'vcard-prefix': 'Dr.',
        'vcard-firstname': 'Ada',
        'vcard-lastname': 'Lovelace',
        'vcard-org': 'Analytical Engines',
        'vcard-title': 'Analyst',
        'vcard-email': 'ada@example.org',
        'vcard-city': 'London',
      }),
      'hd-wallet-messaging-key-config-v1': '{"keyType":"sol"}',
      'hd-wallet-scan-balance-cache-v1': '{}',
      'trust-rules': '[]',
      'trust-imported-txs': JSON.stringify([{ txHash: 'abc', type: 'trust' }]),
      'trust-drain-baselines': JSON.stringify({ '0xabc': { balance: 1 } }),
      'wallet-pki-keys': '{"iv":"x","ciphertext":"y"}',
      'bond-currency': 'GBP',
    });
  }

  it('moves the vCard identity and trust records into account 0, then deletes all ten legacy keys', () => {
    const storage = legacyStorage();
    const a = seedSession(A, storage);
    const moved = migrateLegacyStorage(a.store, storage);
    expect(moved).toEqual(['profile', 'trust-imported-txs', 'trust-drain-baselines']);
    expect(a.store.read(0, 'profile')).toMatchObject({
      name: 'Dr. Ada Lovelace',
      organization: 'Analytical Engines',
      jobTitle: 'Analyst',
      email: 'ada@example.org',
      city: 'London',
    });
    expect(a.store.read(0, 'trust-imported-txs')).toEqual([{ txHash: 'abc', type: 'trust' }]);
    for (const key of LEGACY_KEYS) expect(storage.getItem(key), key).toBeNull();
    expect(storage.getItem('hdw-currency')).toBe('GBP');
    expect(LEGACY_KEYS).toHaveLength(10);
  });

  it('runs once: a second seed finds nothing left to take', () => {
    const storage = legacyStorage();
    migrateLegacyStorage(seedSession(A, storage).store, storage);
    const b = seedSession(B, storage);
    expect(migrateLegacyStorage(b.store, storage)).toEqual([]);
    expect(b.store.read(0, 'profile')).toBeNull();
  });

  it('maps an empty vCard record to nothing', () => {
    expect(profileFromLegacyVcard({})).toBeNull();
    expect(profileFromLegacyVcard(null)).toBeNull();
  });
});

describe('per-viewer settings', () => {
  it('currency is one of the seven, migrated once from bond-currency', () => {
    const storage = memoryStorage({ 'bond-currency': 'JPY' });
    expect(migrateCurrency(storage)).toBe('JPY');
    expect(storage.getItem('bond-currency')).toBeNull();
    expect(readCurrency(storage)).toBe('JPY');
    expect(writeCurrency('BTC', storage)).toBe(false);
    expect(writeCurrency('CHF', storage)).toBe(true);
    expect(readCurrency(storage)).toBe('CHF');
    expect(CURRENCIES).toEqual(['USD', 'EUR', 'GBP', 'JPY', 'CHF', 'CAD', 'AUD']);
    expect(readCurrency(memoryStorage())).toBe('USD');
  });

  it('the last section is remembered globally', () => {
    const storage = memoryStorage();
    writeSection('people', storage);
    expect(readSection(storage)).toBe('people');
  });
});

describe('nothing secret in storage', () => {
  it('after a profile, contact and cache flow no private key, xprv or mnemonic is stored', () => {
    const storage = memoryStorage();
    const a = seedSession(A, storage);
    const identity = deriveIdentity(wallet, a.seed, 0);
    const addresses = deriveAccountAddresses(wallet, a.root, 0);
    a.store.write(0, 'profile', { name: 'Ada' });
    const epm = buildContactEpm(wallet, {
      profile: { name: 'Ada' },
      identity,
      accountXpub: accountXpub(a.root, 0),
      addresses,
      withChainKey: (path, fn) => withChainKey(a.root, path, fn),
      withEdKey: (fn) => withEdKey(wallet, a.seed, 0, fn),
    });
    a.store.write(0, 'contacts', upsertContact([], contactFromEpm(wallet, epm)));
    a.store.write(0, 'scan-cache', { [`btc:${addresses.btc.address}`]: { balance: '0', ts: Date.now() } });

    const secrets = [];
    const edPriv = withEdKey(wallet, a.seed, 0, (key) => new Uint8Array(key));
    for (const path of ["m/44'/0'/0'/0/0", "m/44'/60'/0'/0/0", "m/44'/501'/0'/0/0"]) {
      secrets.push(withChainKey(a.root, path, (key) => new Uint8Array(key)));
    }
    secrets.push(edPriv);
    const forms = [];
    for (const secret of secrets) {
      forms.push(toHex(secret), wallet.utils.encodeBase58(secret), wallet.utils.encodeBase64(secret));
    }
    forms.push(accountXprv(a.root, 0), a.root.toXprv(), A, toHex(a.seed));
    const everything = storage.entries().map(([key, value]) => `${key}=${value}`).join('\n');
    for (const form of forms) expect(everything.includes(form), 'a secret form leaked into storage').toBe(false);
    for (const secret of secrets) secret.fill(0);
  });
});
