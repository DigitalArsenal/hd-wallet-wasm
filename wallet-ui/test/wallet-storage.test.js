import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import initHDWallet from 'hd-wallet-wasm';
import WalletStorage, { StorageMethod } from '../src/wallet-storage.js';

class FakeLocalStorage {
  constructor() {
    this._m = new Map();
  }
  getItem(k) {
    return this._m.has(k) ? this._m.get(k) : null;
  }
  setItem(k, v) {
    this._m.set(String(k), String(v));
  }
  removeItem(k) {
    this._m.delete(String(k));
  }
  clear() {
    this._m.clear();
  }
}

const STORAGE_PREFIX = 'wallet_storage_';
const METADATA_KEY = `${STORAGE_PREFIX}metadata`;
const ENCRYPTED_DATA_KEY = `${STORAGE_PREFIX}encrypted`;

function bytesToBase64(bytes) {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

let walletPromise = null;
function getWallet() {
  if (!walletPromise) walletPromise = initHDWallet();
  return walletPromise;
}

async function hkdfDerive(ikm, saltBytes, infoStr, length) {
  const wallet = await getWallet();
  return wallet.utils.hkdf(ikm, saltBytes, new TextEncoder().encode(infoStr), length);
}

async function legacyEncryptPinV2(pin, walletData, saltBytes) {
  const wallet = await getWallet();
  const pinBytes = new TextEncoder().encode(pin);
  const km = wallet.utils.pbkdf2(pinBytes, saltBytes, 100000, 32);

  const hkdfSalt = new TextEncoder().encode('wallet-storage-v2');
  const encryptionKey = await hkdfDerive(km, hkdfSalt, 'pin-encryption-key', 32);
  const iv = await hkdfDerive(km, hkdfSalt, 'pin-encryption-iv', 12);

  const plaintext = new TextEncoder().encode(JSON.stringify(walletData));
  const { ciphertext, tag } = wallet.utils.aesGcm.encrypt(encryptionKey, plaintext, iv);
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);

  return sealed;
}

describe('wallet-storage (PIN)', () => {
  const originalLocalStorage = globalThis.localStorage;
  let storage;

  beforeEach(() => {
    storage = new FakeLocalStorage();
    globalThis.localStorage = storage;
  });

  afterEach(() => {
    globalThis.localStorage = originalLocalStorage;
  });

  it('storeWithPIN/retrieveWithPIN round-trips', async () => {
    const pin = '123456';
    const walletData = { type: 'masterSeed', masterSeed: [1, 2, 3], username: 'alice' };

    await WalletStorage.storeWithPIN(pin, walletData);
    const recovered = await WalletStorage.retrieveWithPIN(pin);

    expect(recovered).toEqual(walletData);
  });

  it('stores random IV alongside ciphertext (v3)', async () => {
    const pin = '123456';
    const walletData = { hello: 'world' };

    await WalletStorage.storeWithPIN(pin, walletData);

    const encrypted = JSON.parse(storage.getItem(ENCRYPTED_DATA_KEY));
    const meta = JSON.parse(storage.getItem(METADATA_KEY));

    expect(meta.method).toBe(StorageMethod.PIN);
    expect(meta.version).toBe(3);
    expect(typeof encrypted.ciphertext).toBe('string');
    expect(typeof encrypted.salt).toBe('string');
    expect(typeof encrypted.iv).toBe('string');
    expect(base64ToBytes(encrypted.iv)).toBeInstanceOf(Uint8Array);
    expect(base64ToBytes(encrypted.iv).length).toBe(12);
  });

  it('rejects wrong PIN', async () => {
    const pin = '123456';
    const walletData = { hello: 'world' };
    await WalletStorage.storeWithPIN(pin, walletData);

    await expect(WalletStorage.retrieveWithPIN('000000')).rejects.toThrow(/Invalid PIN|corrupted/i);
  });

  it('decrypts legacy v2 deterministic-IV blobs and upgrades to v3', async () => {
    const pin = '123456';
    const walletData = { type: 'masterSeed', masterSeed: [9, 8, 7] };
    const salt = (await getWallet()).utils.getRandomBytes(16);
    const ciphertext = await legacyEncryptPinV2(pin, walletData, salt);

    storage.setItem(ENCRYPTED_DATA_KEY, JSON.stringify({
      ciphertext: bytesToBase64(ciphertext),
      salt: bytesToBase64(salt),
      // v2 had no iv field
    }));
    storage.setItem(METADATA_KEY, JSON.stringify({
      method: StorageMethod.PIN,
      timestamp: Date.now(),
      version: 2,
    }));

    const recovered = await WalletStorage.retrieveWithPIN(pin);
    expect(recovered).toEqual(walletData);

    const upgraded = JSON.parse(storage.getItem(ENCRYPTED_DATA_KEY));
    const upgradedMeta = JSON.parse(storage.getItem(METADATA_KEY));
    expect(upgradedMeta.version).toBe(3);
    expect(typeof upgraded.iv).toBe('string');
    expect(base64ToBytes(upgraded.iv).length).toBe(12);
  });
});
