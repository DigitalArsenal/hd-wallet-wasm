/**
 * Per-seed, per-account browser storage for the account view.
 *
 * Every key is namespaced by the seed's fingerprint (identity-keys.js
 * namespaceFingerprint) so two seeds on one browser never share a profile,
 * contacts or trust history:
 *
 *   hdw:<fp>:account                      the last account number used
 *   hdw:<fp>:a<N>:profile                 profile fields and photo (JPEG data URL)
 *   hdw:<fp>:a<N>:contacts                imported $EPM contact cards (public data)
 *   hdw:<fp>:a<N>:trust-imported-txs      trust records carried over from 2.x
 *   hdw:<fp>:a<N>:trust-drain-baselines   drain-watch balances
 *   hdw:<fp>:a<N>:scan-cache              balance cache for the account's addresses
 *
 * Per-viewer conveniences stay global: the price cache, `hdw-currency` and
 * `hdw-account-section`.
 *
 * Nothing here ever holds a private key, an xprv or a mnemonic. Every access
 * is wrapped so a blocked or full storage degrades to "nothing stored".
 */

export const ACCOUNT_SECTION_KEY = 'hdw-account-section';
export const CURRENCY_KEY = 'hdw-currency';
export const LEGACY_CURRENCY_KEY = 'bond-currency';
export const PRICE_CACHE_KEY = 'hd-wallet-price-cache-v1';

export const ACCOUNT_RECORDS = Object.freeze([
  'profile',
  'contacts',
  'trust-imported-txs',
  'trust-drain-baselines',
  'scan-cache',
]);

/** The ten wallet-ui 2.x keys the first seed login after the upgrade removes. */
export const LEGACY_KEYS = Object.freeze([
  'hd-wallet-wallets',
  'hd-wallet-active-accounts',
  'hd-wallet-vcard-identity',
  'hd-wallet-messaging-key-config-v1',
  'hd-wallet-scan-balance-cache-v1',
  'trust-rules',
  'trust-imported-txs',
  'trust-drain-baselines',
  'wallet-pki-keys',
  'bond-currency',
]);

/**
 * 2.x keys that held private keys (the PKI demo's saved key pairs). They are
 * removed on every start, whatever kind of session follows, so a viewer who
 * only ever signs in with an external wallet doesn't keep them either.
 */
export const LEGACY_SECRET_KEYS = Object.freeze(['wallet-pki-keys']);

export function dropLegacySecrets(storage = browserStorage()) {
  if (!storage) return;
  for (const key of LEGACY_SECRET_KEYS) safeRemove(storage, key);
}

export const CURRENCIES = Object.freeze(['USD', 'EUR', 'GBP', 'JPY', 'CHF', 'CAD', 'AUD']);

/** The browser's localStorage, or null when it is blocked. */
export function browserStorage() {
  try {
    const storage = globalThis.localStorage;
    return storage && typeof storage.getItem === 'function' ? storage : null;
  } catch {
    return null;
  }
}

function safeGet(storage, key) {
  try { return storage?.getItem(key) ?? null; } catch { return null; }
}

function safeSet(storage, key, value) {
  try {
    storage?.setItem(key, value);
    return true;
  } catch {
    return false;
  }
}

function safeRemove(storage, key) {
  try { storage?.removeItem(key); } catch { /* blocked storage keeps nothing anyway */ }
}

function parseJson(raw, fallback) {
  if (typeof raw !== 'string' || raw === '') return fallback;
  try {
    const value = JSON.parse(raw);
    return value === null || value === undefined ? fallback : value;
  } catch {
    return fallback;
  }
}

function requireFingerprint(fp) {
  if (typeof fp !== 'string' || !/^[0-9a-f]{16}$/u.test(fp)) {
    throw new TypeError('A 16-hex-character seed fingerprint is required');
  }
  return fp;
}

export function namespacePrefix(fp) {
  return `hdw:${requireFingerprint(fp)}:`;
}

export function accountRecordKey(fp, account, record) {
  if (!ACCOUNT_RECORDS.includes(record)) throw new TypeError(`Unknown account record ${record}`);
  const n = Number(account);
  if (!Number.isInteger(n) || n < 0) throw new TypeError('Invalid account number');
  return `${namespacePrefix(fp)}a${n}:${record}`;
}

/**
 * The storage of one seed. `fp` comes from namespaceFingerprint().
 */
export function createAccountStorage({ fp, storage = browserStorage() }) {
  const prefix = namespacePrefix(fp);
  return Object.freeze({
    fp,
    prefix,
    readAccount() {
      const n = Number(safeGet(storage, `${prefix}account`));
      return Number.isInteger(n) && n >= 0 && n <= 99 ? n : 0;
    },
    writeAccount(account) {
      safeSet(storage, `${prefix}account`, String(account));
    },
    read(account, record, fallback = null) {
      return parseJson(safeGet(storage, accountRecordKey(fp, account, record)), fallback);
    },
    write(account, record, value) {
      return safeSet(storage, accountRecordKey(fp, account, record), JSON.stringify(value));
    },
    remove(account, record) {
      safeRemove(storage, accountRecordKey(fp, account, record));
    },
    /** Every key of this seed, `hdw:<fp>:*`. */
    keys() {
      const keys = [];
      try {
        for (let index = 0; index < storage.length; index += 1) {
          const key = storage.key(index);
          if (typeof key === 'string' && key.startsWith(prefix)) keys.push(key);
        }
      } catch { /* blocked storage has no keys */ }
      return keys;
    },
    /** Settings › Forget this wallet on this device. */
    forget() {
      for (const key of this.keys()) safeRemove(storage, key);
    },
  });
}

/**
 * Map the 2.x vCard identity record onto the 3.0 profile fields.
 */
export function profileFromLegacyVcard(record) {
  if (!record || typeof record !== 'object') return null;
  const text = (id) => (typeof record[id] === 'string' ? record[id].trim() : '');
  const name = [
    text('vcard-prefix'),
    text('vcard-firstname'),
    text('vcard-middlename'),
    text('vcard-lastname'),
    text('vcard-suffix'),
  ].filter(Boolean).join(' ');
  const profile = {
    name,
    jobTitle: text('vcard-title'),
    organization: text('vcard-org'),
    email: text('vcard-email'),
    phone: text('vcard-phone'),
    street: text('vcard-street'),
    city: text('vcard-city'),
    region: text('vcard-region'),
    postalCode: text('vcard-postal'),
    country: text('vcard-country'),
  };
  return Object.values(profile).some(Boolean) ? profile : null;
}

/**
 * One-time move of the 2.x global records into this seed's account 0, then
 * removal of all ten legacy keys. Running it again finds nothing to move.
 * Returns the names of the records it moved.
 */
export function migrateLegacyStorage(accountStorage, storage = browserStorage()) {
  const moved = [];
  if (!storage) return moved;
  const legacyProfile = profileFromLegacyVcard(parseJson(safeGet(storage, 'hd-wallet-vcard-identity'), null));
  if (legacyProfile && !accountStorage.read(0, 'profile')) {
    accountStorage.write(0, 'profile', legacyProfile);
    moved.push('profile');
  }
  const imported = parseJson(safeGet(storage, 'trust-imported-txs'), null);
  if (Array.isArray(imported) && imported.length && !accountStorage.read(0, 'trust-imported-txs')) {
    accountStorage.write(0, 'trust-imported-txs', imported);
    moved.push('trust-imported-txs');
  }
  const baselines = parseJson(safeGet(storage, 'trust-drain-baselines'), null);
  if (baselines && typeof baselines === 'object' && !Array.isArray(baselines)
      && Object.keys(baselines).length && !accountStorage.read(0, 'trust-drain-baselines')) {
    accountStorage.write(0, 'trust-drain-baselines', baselines);
    moved.push('trust-drain-baselines');
  }
  migrateCurrency(storage);
  for (const key of LEGACY_KEYS) safeRemove(storage, key);
  return moved;
}

/** The viewer's display currency, migrating the 2.x `bond-currency` once. */
export function migrateCurrency(storage = browserStorage()) {
  const current = safeGet(storage, CURRENCY_KEY);
  if (CURRENCIES.includes(current)) return current;
  const legacy = safeGet(storage, LEGACY_CURRENCY_KEY);
  const next = CURRENCIES.includes(legacy) ? legacy : 'USD';
  safeSet(storage, CURRENCY_KEY, next);
  safeRemove(storage, LEGACY_CURRENCY_KEY);
  return next;
}

export function readCurrency(storage = browserStorage()) {
  const value = safeGet(storage, CURRENCY_KEY);
  if (CURRENCIES.includes(value)) return value;
  return migrateCurrency(storage);
}

export function writeCurrency(currency, storage = browserStorage()) {
  if (!CURRENCIES.includes(currency)) return false;
  return safeSet(storage, CURRENCY_KEY, currency);
}

export function readSection(storage = browserStorage()) {
  return safeGet(storage, ACCOUNT_SECTION_KEY);
}

export function writeSection(section, storage = browserStorage()) {
  safeSet(storage, ACCOUNT_SECTION_KEY, section);
}
