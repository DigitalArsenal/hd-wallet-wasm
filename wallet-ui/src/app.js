/**
 * HD Wallet UI - Main Application
 *
 * Standalone wallet interface with HD key derivation, multi-chain address
 * generation, balance fetching, vCard export, and PIN/passkey storage.
 */

// =============================================================================
// External Imports
// =============================================================================

import initHDWallet, { Curve, getSigningKey, getEncryptionKey, buildSigningPath, buildEncryptionPath, WellKnownCoinType } from 'hd-wallet-wasm';
import { keccak_256 } from '@noble/hashes/sha3';
import QRCode from 'qrcode';
import { Buffer } from 'buffer';
import { createV3 } from 'vcard-cryptoperson';

// SpaceDataStandards EME (Encrypted Message Envelope)
import { EME, EMET } from '@sds/lib/js/EME/EME.js';
import * as flatbuffers from 'flatbuffers';

// Make Buffer available globally for various crypto libraries
window.Buffer = Buffer;

// =============================================================================
// Local Module Imports
// =============================================================================

import { getModalHTML } from './template.js';
import { createExternalWalletPanel } from './external/panel.js';
import WalletStorage, { StorageMethod } from './wallet-storage.js';
import { safeCopyText } from './clipboard.js';
import { normalizeTabHash } from './hash.js';

import {
  cryptoConfig,
  coinTypeToConfig,
  PKI_STORAGE_KEY,
} from './constants.js';

import {
  toHexCompact,
  toHex,
  hexToBytes,
  ensureUint8Array,
  generateBtcAddress,
  generateEthAddress,
  generateSolAddress,
  deriveEthAddress,
  // deriveSuiAddress, // Commented out — BTC/ETH/SOL only
  // deriveMonadAddress,
  // deriveCardanoAddress,
  generateAddresses,
  generateAddressForCoin,
  truncateAddress,
  fetchBtcBalance,
  fetchEthBalance,
  fetchSolBalance,
  // fetchSuiBalance, // Commented out — BTC/ETH/SOL only
  // fetchMonadBalance,
  // fetchAdaBalance,
  // generateXrpAddress,
  // fetchXrpBalance,
  apiUrl,
} from './address-derivation.js';

// =============================================================================
// DOM Helper
// =============================================================================

let _root = document;
const $ = (id) => {
  const el = _root.getElementById ? _root.getElementById(id) : _root.querySelector(`#${id}`);
  if (el) return el;
  // Fallback to document for elements in the light DOM (e.g. widget mode)
  if (_root !== document) return document.getElementById(id);
  return null;
};

export { normalizeTabHash };

const $q = (sel) => _root.querySelector(sel) || (_root !== document ? document.querySelector(sel) : null);
const $qa = (sel) => {
  const list = _root.querySelectorAll(sel);
  if (list.length > 0 || _root === document) return list;
  return document.querySelectorAll(sel);
};

// =============================================================================
// Wallet Info Box (dismissible notice)
// =============================================================================

function dismissWalletInfo() {
  localStorage.setItem('walletInfoDismissed', '1');
  $('wallet-info-expanded').style.display = 'none';
  $('wallet-info-collapsed').style.display = 'flex';
}

function showWalletInfo() {
  localStorage.removeItem('walletInfoDismissed');
  $('wallet-info-expanded').style.display = 'flex';
  $('wallet-info-collapsed').style.display = 'none';
}

function initWalletInfoBox() {
  if (localStorage.getItem('walletInfoDismissed') === '1') {
    $('wallet-info-expanded').style.display = 'none';
    $('wallet-info-collapsed').style.display = 'flex';
  }
}

function toggleXpubInfo() {
  const box = $('xpub-info-box');
  if (box) box.style.display = box.style.display === 'none' ? 'flex' : 'none';
}

function toggleMemoryInfo() {
  const box = $('memory-info-box');
  if (box) box.style.display = box.style.display === 'none' ? 'flex' : 'none';
}

function bindInfoHandlers() {
  $('wallet-info-dismiss')?.addEventListener('click', dismissWalletInfo);
  $('wallet-info-collapsed')?.addEventListener('click', showWalletInfo);
  $('xpub-info-toggle')?.addEventListener('click', toggleXpubInfo);
  $('xpub-info-close')?.addEventListener('click', toggleXpubInfo);
  $('memory-info-toggle')?.addEventListener('click', toggleMemoryInfo);
  $('memory-info-close')?.addEventListener('click', toggleMemoryInfo);
}

// =============================================================================
// Utilities
// =============================================================================

function setTruncatedValue(el, value) {
  if (!el) return;
  el.textContent = middleTruncate(value, 17, 17);
}

function middleTruncate(str, startChars, endChars) {
  if (!str || str.length <= startChars + endChars + 3) return str;
  return str.slice(0, startChars) + '…' + str.slice(-endChars);
}

function toBase64(arr) {
  return btoa(String.fromCharCode(...arr));
}

function base64ToBytes(b64) {
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function bytesToBase64(bytes) {
  // Avoid spreading large arrays into String.fromCharCode.
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

// =============================================================================
// WASM-backed cryptographic helpers
// =============================================================================

function hdWallet() {
  if (!state.hdWalletModule) throw new Error('HD wallet WASM module not initialized');
  return state.hdWalletModule;
}

function asUint8Array(value) {
  if (value instanceof Uint8Array) return value;
  if (ArrayBuffer.isView(value)) {
    return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  }
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  throw new Error('Expected byte array');
}

async function sha256(data) {
  return hdWallet().utils.sha256(asUint8Array(data));
}

async function hkdf(ikm, salt, info, length) {
  return hdWallet().utils.hkdf(asUint8Array(ikm), asUint8Array(salt), asUint8Array(info), length);
}

async function aesGcmEncryptJson(keyBytes, obj, aadStr) {
  if (!(keyBytes instanceof Uint8Array)) throw new Error('Invalid AES key');
  const iv = hdWallet().utils.getRandomBytes(12);
  const plaintext = new TextEncoder().encode(JSON.stringify(obj));
  const aad = aadStr ? new TextEncoder().encode(aadStr) : new Uint8Array(0);
  const { ciphertext, tag } = hdWallet().utils.aesGcm.encrypt(keyBytes, plaintext, iv, aad);
  const sealed = new Uint8Array(ciphertext.length + tag.length);
  sealed.set(ciphertext, 0);
  sealed.set(tag, ciphertext.length);
  return { iv, ciphertext: sealed };
}

async function aesGcmDecryptJson(keyBytes, iv, ciphertextBytes, aadStr) {
  if (!(keyBytes instanceof Uint8Array)) throw new Error('Invalid AES key');
  const sealed = asUint8Array(ciphertextBytes);
  if (sealed.length <= 16) throw new Error('Ciphertext is too short');
  const aad = aadStr ? new TextEncoder().encode(aadStr) : new Uint8Array(0);
  const plaintext = hdWallet().utils.aesGcm.decrypt(
    keyBytes,
    sealed.subarray(0, sealed.length - 16),
    sealed.subarray(sealed.length - 16),
    asUint8Array(iv),
    aad
  );
  return JSON.parse(new TextDecoder().decode(plaintext));
}

// =============================================================================
// Key Generation
// =============================================================================

function generateKeyPair(curveType) {
  const w = hdWallet();
  if (curveType === Curve.SECP256K1) {
    return generateEcKeyPair(w, Curve.SECP256K1, 32);
  }
  if (curveType === Curve.X25519) {
    const privateKey = w.utils.getRandomBytes(32);
    const publicKey = w.curves.x25519.publicKey(privateKey);
    return { privateKey, publicKey };
  }
  throw new Error(`Unsupported curve type: ${curveType}`);
}

function generateEcKeyPair(w, curveType, privateKeyLength) {
  let lastError = null;
  for (let i = 0; i < 16; i += 1) {
    const privateKey = w.utils.getRandomBytes(privateKeyLength);
    try {
      const publicKey = w.curves.publicKeyFromPrivate(privateKey, curveType);
      return { privateKey, publicKey };
    } catch (err) {
      lastError = err;
      privateKey.fill(0);
    }
  }
  throw lastError || new Error('Failed to generate curve keypair');
}

async function p256GenerateKeyPairAsync() {
  return generateEcKeyPair(hdWallet(), Curve.P256, 32);
}

async function p384GenerateKeyPairAsync() {
  return generateEcKeyPair(hdWallet(), Curve.P384, 48);
}

// =============================================================================
// State
// =============================================================================

// Integration callback — set via options.onLogin in createWalletUI / init
let _onLoginCallback = null;

// When false, login() will NOT auto-open the Account modal after authentication.
// Set via options.openAccountAfterLogin in createWalletUI / init (default: true).
let _openAccountAfterLogin = true;

const state = {
  initialized: false,
  loggedIn: false,
  selectedCrypto: 'btc',
  addresses: {
    btc: null,
    eth: null,
    sol: null,
  },
  wallet: {
    x25519: null,
    ed25519: null,
    secp256k1: null,
    p256: null,
  },
  // HD wallet state
  hdWalletModule: null,
  masterSeed: null,
  hdRoot: null,
  mnemonic: null,
  // Encryption keys (derived from password/seed)
  encryptionKey: null,
  encryptionIV: null,
  // vCard photo (base64 data URI)
  vcardPhoto: null,
  // Active accounts discovered by scanning or manually added
  activeAccounts: [],
  // Wallet groups (Phantom-style: each wallet = same account index across chains)
  wallets: [{ id: 0, name: 'Wallet 1', accountIndex: 0 }],
  activeWalletId: 0,
  walletManageTab: 'active',
  walletFiatTotals: {},
  walletFiatCurrency: 'USD',
  balanceCache: {},
  balanceCacheLoaded: false,
  balanceRateLimitUntil: {},
  scanInProgress: false,
  // PKI Demo state
  pki: {
    alice: null,
    bob: null,
    algorithm: 'x25519',
  },
};

// =============================================================================
// Entropy Calculation & Password Strength
// =============================================================================

function calculateEntropy(password) {
  if (!password) return 0;

  let charsetSize = 0;
  if (/[a-z]/.test(password)) charsetSize += 26;
  if (/[A-Z]/.test(password)) charsetSize += 26;
  if (/[0-9]/.test(password)) charsetSize += 10;
  if (/[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password)) charsetSize += 32;
  if (/\s/.test(password)) charsetSize += 1;
  if (/[^\x00-\x7F]/.test(password)) charsetSize += 100;

  if (charsetSize === 0) return 0;
  return Math.round(password.length * Math.log2(charsetSize));
}

function updatePasswordStrength(password) {
  const entropy = calculateEntropy(password);
  const fill = $('strength-fill');
  const bits = $('entropy-bits');
  const btn = $('derive-from-password');

  if (bits) bits.textContent = `${entropy}`;

  const MIN_SAFE_ENTROPY = 112;

  let strength, percentage;

  if (entropy < 40) {
    strength = 'weak';
    percentage = Math.min(25, (entropy / 40) * 25);
  } else if (entropy < 80) {
    strength = 'fair';
    percentage = 25 + ((entropy - 40) / 40) * 25;
  } else if (entropy < MIN_SAFE_ENTROPY) {
    strength = 'good';
    percentage = 50 + ((entropy - 80) / (MIN_SAFE_ENTROPY - 80)) * 25;
  } else {
    strength = 'strong';
    percentage = 75 + Math.min(25, ((entropy - MIN_SAFE_ENTROPY) / 50) * 25);
  }

  if (fill) {
    fill.style.width = `${percentage}%`;
    // Gradient: deep red (0) → orange (50%) → green (100%)
    const ratio = percentage / 100;
    let r, g;
    if (ratio < 0.5) {
      r = 180 + Math.round(75 * (ratio / 0.5));  // 180→255
      g = Math.round(140 * (ratio / 0.5));        // 0→140
    } else {
      r = 255 - Math.round(200 * ((ratio - 0.5) / 0.5)); // 255→55
      g = 140 + Math.round(115 * ((ratio - 0.5) / 0.5)); // 140→255
    }
    fill.style.background = `rgb(${r}, ${g}, 30)`;
  }

  const username = $('wallet-username')?.value;
  if (btn) btn.disabled = !username || password.length < 24;
}

// =============================================================================
// Key Derivation
// =============================================================================

async function deriveKeysFromPassword(username, password) {
  const encoder = new TextEncoder();
  const usernameSalt = encoder.encode(username);
  const passwordBytes = encoder.encode(password);

  const initialHash = await sha256(new Uint8Array([...usernameSalt, ...passwordBytes]));
  const masterKey = await hkdf(initialHash, usernameSalt, encoder.encode('master-key'), 32);

  // Create 64-byte seed for HD wallet (password-based, not BIP39)
  const hdSeed = await hkdf(masterKey, new Uint8Array(0), encoder.encode('hd-wallet-seed'), 64);

  try {
    // Derive session keys from the master seed so "remember wallet" can unlock without
    // storing the user password/seed phrase at rest.
    return await deriveKeysFromMasterSeed(hdSeed);
  } finally {
    // Best-effort JS-layer cleanup (strings cannot be wiped).
    passwordBytes.fill(0);
    initialHash.fill(0);
    masterKey.fill(0);
    hdSeed.fill(0);
  }
}

async function deriveKeysFromSeed(seedPhrase) {
  const encoder = new TextEncoder();
  const seed = state.hdWalletModule.mnemonic.toSeed(seedPhrase);
  const seedBytes = seed instanceof Uint8Array ? seed : new Uint8Array(seed);

  try {
    return await deriveKeysFromMasterSeed(seedBytes);
  } finally {
    // Don't retain the seed phrase in JS state.
    // (Seed phrase strings can't be wiped; we just avoid storing them.)
    seedBytes.fill(0);
  }
}

async function deriveKeysFromMasterSeed(masterSeedBytes) {
  const encoder = new TextEncoder();

  // Copy seed into state; callers can wipe their input buffer.
  state.masterSeed = new Uint8Array(masterSeedBytes);
  state.hdRoot = state.hdWalletModule.hdkey.fromSeed(state.masterSeed);
  state.mnemonic = null;

  // Session encryption key for local encrypted blobs (PKI, etc).
  state.encryptionKey = await hkdf(state.masterSeed, new Uint8Array(0), encoder.encode('buffer-encryption-key'), 32);
  state.encryptionIV = await hkdf(state.masterSeed, new Uint8Array(0), encoder.encode('buffer-encryption-iv'), 16);

  const keys = deriveKeysFromHDRoot(state.hdRoot);
  keys.x25519 = generateKeyPair(Curve.X25519);
  keys.p256 = await p256GenerateKeyPairAsync();
  keys.p384 = await p384GenerateKeyPairAsync();
  return keys;
}

/**
 * Derive secp256k1 and ed25519 signing keys from the HD root using BIP44 signing paths.
 * This ensures addresses match what the HD derivation grid produces.
 */
function deriveKeysFromHDRoot(hdRoot) {
  // BTC signing key m/44'/0'/0'/0/0 — secp256k1
  const btcSigning = getSigningKey(hdRoot, 0, 0, 0);

  // SOL signing key m/44'/501'/0'/0/0 — ed25519
  const solSigning = getSigningKey(hdRoot, 501, 0, 0);
  const ed25519PubKey = hdWallet().curves.ed25519.publicKeyFromSeed(solSigning.privateKey);

  return {
    secp256k1: { privateKey: btcSigning.privateKey, publicKey: btcSigning.publicKey },
    ed25519: { privateKey: solSigning.privateKey, publicKey: ed25519PubKey },
  };
}

/**
 * Derive all blockchain addresses from the HD root using signing paths.
 * Each coin uses its own BIP44 signing path: m/44'/{coinType}'/0'/0/0
 */
function deriveAllAddressesFromHD() {
  if (!state.hdRoot) return {};

  const deriveAddress = (coinType) => {
    try {
      const path = buildSigningPath(coinType, 0, 0);
      const derived = state.hdRoot.derivePath(path);
      const pubKey = derived.publicKey();
      return generateAddressForCoin(pubKey, coinType);
    } catch (e) {
      console.error(`Failed to derive address for coinType ${coinType}:`, e);
      return null;
    }
  };

  // For SOL, derive ed25519 key and use it directly
  let solAddress = null;
  try {
    const solPath = buildSigningPath(501, 0, 0);
    const solDerived = state.hdRoot.derivePath(solPath);
    const solPrivKey = solDerived.privateKey();
    solAddress = generateSolAddress(hdWallet().curves.ed25519.publicKeyFromSeed(solPrivKey));
  } catch (e) {
    console.error('Failed to derive SOL address:', e);
  }

  return {
    btc: deriveAddress(0),
    eth: deriveAddress(60),
    sol: solAddress,
    // xrp: deriveAddress(144), // Commented out — BTC/ETH/SOL only
  };
}

function generateSeedPhrase() {
  return state.hdWalletModule.mnemonic.generate(24);
}

function validateSeedPhrase(phrase) {
  return state.hdWalletModule.mnemonic.validate(phrase.trim().toLowerCase());
}

// =============================================================================
// HD Wallet Derivation
// =============================================================================

function deriveHDKey(path) {
  if (!state.hdRoot) {
    throw new Error('HD wallet not initialized');
  }
  try {
    return state.hdRoot.derivePath(path);
  } catch (e) {
    console.error('HD derivation error:', e, 'path:', path);
    throw e;
  }
}

function deriveAccountPeerId() {
  if (!state.hdRoot) return null;
  try {
    return state.hdRoot.peerIdString();
  } catch (e) {
    console.warn('Failed to derive account PeerID:', e);
    return null;
  }
}

function updatePathDisplay() {
  const coin = $('hd-coin')?.value;
  const account = $('hd-account')?.value || '0';
  const index = $('hd-index')?.value || '0';

  const signingPath = buildSigningPath(coin, account, index);
  const encryptionPath = buildEncryptionPath(coin, account, index);

  const signingPathEl = $('signing-path');
  const encryptionPathEl = $('encryption-path');

  if (signingPathEl) signingPathEl.textContent = signingPath;
  if (encryptionPathEl) encryptionPathEl.textContent = encryptionPath;
}

// =============================================================================
// Active Accounts: Derivation, Persistence, Scanning, Rendering
// =============================================================================

/**
 * Derive an address for a given BIP44 path.
 * SOL (501) uses ed25519; BTC (0) and ETH (60) use secp256k1.
 * @returns {{ address: string, publicKey: Uint8Array, path: string }}
 */
function deriveAddressForPath(coinType, account, index) {
  if (!state.hdRoot) throw new Error('HD wallet not initialized');
  const path = buildSigningPath(coinType, account, index);
  const derived = state.hdRoot.derivePath(path);

  if (coinType === 501) {
    // Solana: ed25519
    const privKey = derived.privateKey();
    const pubKey = hdWallet().curves.ed25519.publicKeyFromSeed(privKey);
    return { address: generateSolAddress(pubKey), publicKey: pubKey, path };
  }

  // BTC/ETH: secp256k1
  const pubKey = derived.publicKey();
  return { address: generateAddressForCoin(pubKey, coinType), publicKey: pubKey, path };
}

const ACTIVE_ACCOUNTS_KEY = 'hd-wallet-active-accounts';
const WALLETS_KEY = 'hd-wallet-wallets';
const DEFAULT_WALLET_COUNT = 10;
const WALLET_OVERLAY_VIEWS = ['wallet-wallets-view', 'wallet-export-view', 'wallet-advanced-view', 'wallet-send-view'];
const BALANCE_CACHE_KEY = 'hd-wallet-scan-balance-cache-v1';
const BALANCE_CACHE_TTL_MS = 2 * 60 * 1000;
const BALANCE_CACHE_STALE_MS = 30 * 60 * 1000;
const SCAN_REQUEST_DELAY_MS = 700;
const SCAN_RETRY_BASE_DELAY_MS = 1200;
const SCAN_MAX_RETRIES = 2;
const BALANCE_RATE_LIMIT_COOLDOWN_MS = 2 * 60 * 1000;
let _scanLastRequestAt = 0;
let _balanceCacheDirty = false;

function getDefaultWalletState() {
  return [{ id: 0, name: 'Wallet 1', accountIndex: 0, inactive: false }];
}

function getDefaultWalletName(accountIndex) {
  return `Wallet ${accountIndex + 1}`;
}

function normalizeWalletName(rawName, accountIndex) {
  const fallback = getDefaultWalletName(accountIndex);
  const trimmed = (rawName || '').toString().trim();
  if (!trimmed) return fallback;
  if (/^wallet(?:\s+\d+)?$/i.test(trimmed)) return fallback;
  return trimmed;
}

function ensureWalletNamesNormalized() {
  let changed = false;
  state.wallets.forEach((wallet) => {
    const normalized = normalizeWalletName(wallet.name, wallet.accountIndex);
    if (normalized !== wallet.name) {
      wallet.name = normalized;
      changed = true;
    }
  });
  if (changed) saveWallets();
  return changed;
}

function getWalletDerivationEntries(wallet) {
  return [
    { coinType: 0, name: 'BTC', account: wallet.accountIndex, index: 0 },
    { coinType: 60, name: 'ETH', account: 0, index: wallet.accountIndex },
    { coinType: 501, name: 'SOL', account: wallet.accountIndex, index: 0 },
  ];
}

function getWalletIdForPath(coinType, account, index) {
  const accountIndex = coinType === 60 ? index : account;
  const wallet = state.wallets.find(w => w.accountIndex === accountIndex);
  return wallet ? wallet.id : 0;
}

function isWalletInactive(wallet) {
  return Boolean(wallet?.inactive);
}

function getActiveWallets() {
  return state.wallets.filter(wallet => !isWalletInactive(wallet));
}

function getInactiveWallets() {
  return state.wallets.filter(wallet => isWalletInactive(wallet));
}

function normalizeWallets(wallets) {
  const normalized = [];
  const source = Array.isArray(wallets) ? wallets : [];
  const usedIds = new Set();
  const usedAccountIndexes = new Set();

  for (const wallet of source) {
    const id = Number.parseInt(wallet?.id, 10);
    const accountIndex = Number.parseInt(wallet?.accountIndex, 10);
    if (Number.isNaN(id) || Number.isNaN(accountIndex)) continue;
    if (usedIds.has(id) || usedAccountIndexes.has(accountIndex)) continue;

    const name = normalizeWalletName(wallet?.name, accountIndex);
    const inactive = Boolean(wallet?.inactive);
    normalized.push({ id, name, accountIndex, inactive });
    usedIds.add(id);
    usedAccountIndexes.add(accountIndex);
  }

  let nextId = normalized.reduce((max, wallet) => Math.max(max, wallet.id), -1) + 1;
  for (let accountIndex = 0; accountIndex < DEFAULT_WALLET_COUNT; accountIndex++) {
    if (usedAccountIndexes.has(accountIndex)) continue;
    while (usedIds.has(nextId)) nextId++;
    normalized.push({
      id: nextId,
      name: getDefaultWalletName(accountIndex),
      accountIndex,
      inactive: false,
    });
    usedIds.add(nextId);
  }

  if (normalized.length === 0) return getDefaultWalletState();
  normalized.sort((a, b) => a.accountIndex - b.accountIndex || a.id - b.id);
  return normalized;
}

function normalizeActiveAccounts(accounts) {
  const source = Array.isArray(accounts) ? accounts : [];
  return source.map((acct) => {
    const existingWalletId = Number.parseInt(acct.walletId, 10);
    const walletExists = state.wallets.some(w => w.id === existingWalletId);
    const walletId = walletExists
      ? existingWalletId
      : getWalletIdForPath(Number.parseInt(acct.coinType, 10), Number.parseInt(acct.account, 10), Number.parseInt(acct.index, 10));
    return { ...acct, walletId };
  });
}

function ensureWalletAccounts() {
  if (!state.hdRoot) return false;

  const existing = new Set(
    state.activeAccounts.map(a => `${a.walletId ?? getWalletIdForPath(a.coinType, a.account, a.index)}:${a.coinType}:${a.account}:${a.index}`)
  );
  let added = false;

  for (const wallet of state.wallets) {
    for (const entry of getWalletDerivationEntries(wallet)) {
      const key = `${wallet.id}:${entry.coinType}:${entry.account}:${entry.index}`;
      if (existing.has(key)) continue;
      try {
        const { address, path } = deriveAddressForPath(entry.coinType, entry.account, entry.index);
        state.activeAccounts.push({
          coinType: entry.coinType,
          name: entry.name,
          account: entry.account,
          index: entry.index,
          address,
          path,
          balance: '--',
          active: false,
          walletId: wallet.id,
        });
        existing.add(key);
        added = true;
      } catch (e) {
        console.warn('Failed to derive wallet account:', entry, e);
      }
    }
  }

  if (added) saveActiveAccounts();
  return added;
}

function getWalletById(walletId) {
  return state.wallets.find(w => w.id === walletId);
}

function getCurrentWallet() {
  const activeWallets = getActiveWallets();
  if (activeWallets.length === 0) return null;
  const current = activeWallets.find(wallet => wallet.id === state.activeWalletId);
  return current || activeWallets[0] || null;
}

function getAccountWalletId(acct) {
  if (!acct) return 0;
  if (acct.walletId !== undefined && getWalletById(acct.walletId)) return acct.walletId;
  return getWalletIdForPath(acct.coinType, acct.account, acct.index);
}

function isSigningAccountForWallet(acct, wallet) {
  if (!acct || !wallet) return false;
  const coinType = Number.parseInt(acct.coinType, 10);
  const account = Number.parseInt(acct.account, 10);
  const index = Number.parseInt(acct.index, 10);
  if (Number.isNaN(coinType) || Number.isNaN(account) || Number.isNaN(index)) return false;

  if (coinType === 60) return account === 0 && index === wallet.accountIndex;
  if (coinType === 0 || coinType === 501) return account === wallet.accountIndex && index === 0;
  return false;
}

function isSigningAccount(acct) {
  const wallet = getWalletById(getAccountWalletId(acct));
  return isSigningAccountForWallet(acct, wallet);
}

function updateCustomPathWalletLabel() {
  const label = $('custom-path-wallet-label');
  const wallet = getCurrentWallet();
  if (!label) return;
  label.textContent = wallet ? `${wallet.name} (account ${wallet.accountIndex})` : `${getDefaultWalletName(0)} (account 0)`;
}

function updateCustomPathDefault() {
  const chainSelect = $('custom-path-chain');
  const input = $('custom-path-input');
  const wallet = getCurrentWallet();
  if (!chainSelect || !input || !wallet) return;

  const coinType = Number.parseInt(chainSelect.value, 10);
  if (Number.isNaN(coinType)) return;
  const account = coinType === 60 ? 0 : wallet.accountIndex;
  const index = coinType === 60 ? wallet.accountIndex : 0;
  input.value = buildSigningPath(coinType, account, index);
  input.dataset.autogenerated = 'true';
}

function renderWalletSelector() {
  const select = $('wallet-active-select');
  if (!select) return;
  ensureWalletNamesNormalized();

  const currentWallet = getCurrentWallet();
  if (!currentWallet) {
    select.innerHTML = '';
    return;
  }
  state.activeWalletId = currentWallet.id;

  select.innerHTML = '';
  const displayCurrency = state.walletFiatCurrency || getSelectedCurrency();
  const activeWallets = getActiveWallets();
  activeWallets.forEach((wallet) => {
    const option = document.createElement('option');
    option.value = String(wallet.id);
    const walletValue = state.walletFiatTotals[wallet.id] ?? 0;
    option.textContent = `${wallet.name} (${formatCurrencyValue(walletValue, displayCurrency)})`;
    select.appendChild(option);
  });
  select.value = String(state.activeWalletId);
  updateCustomPathWalletLabel();
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function loadBalanceCache() {
  try {
    const raw = localStorage.getItem(BALANCE_CACHE_KEY);
    if (!raw) return {};
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {};
  } catch {
    return {};
  }
}

function saveBalanceCache() {
  if (!_balanceCacheDirty) return;
  try {
    localStorage.setItem(BALANCE_CACHE_KEY, JSON.stringify(state.balanceCache));
    _balanceCacheDirty = false;
  } catch (e) {
    console.warn('Failed to save balance cache:', e);
  }
}

function pruneBalanceCache() {
  const now = Date.now();
  let changed = false;
  Object.entries(state.balanceCache).forEach(([key, entry]) => {
    if (!entry || typeof entry.ts !== 'number' || now - entry.ts > BALANCE_CACHE_STALE_MS) {
      delete state.balanceCache[key];
      changed = true;
    }
  });
  if (changed) _balanceCacheDirty = true;
}

function getBalanceCacheKey(coinType, address) {
  return `${coinType}:${address}`;
}

function isNumericBalance(balance) {
  const n = Number.parseFloat(balance);
  return Number.isFinite(n) && n >= 0;
}

function getCachedBalance(coinType, address, { allowStale = false } = {}) {
  const key = getBalanceCacheKey(coinType, address);
  const entry = state.balanceCache[key];
  if (!entry || typeof entry.balance !== 'string' || typeof entry.ts !== 'number') return null;

  const age = Date.now() - entry.ts;
  if (age <= BALANCE_CACHE_TTL_MS) return { ...entry, stale: false };
  if (allowStale && age <= BALANCE_CACHE_STALE_MS) return { ...entry, stale: true };
  return null;
}

function setCachedBalance(coinType, address, balance) {
  if (!isNumericBalance(balance)) return;
  state.balanceCache[getBalanceCacheKey(coinType, address)] = {
    balance: String(balance),
    ts: Date.now(),
  };
  _balanceCacheDirty = true;
}

function hydrateAccountsFromBalanceCache() {
  let changed = false;
  for (const acct of state.activeAccounts) {
    if (!acct?.address) continue;
    const cached = getCachedBalance(acct.coinType, acct.address, { allowStale: true });
    if (!cached || !isNumericBalance(cached.balance)) continue;

    const prev = Number.parseFloat(acct.balance);
    const next = Number.parseFloat(cached.balance);
    if (!Number.isFinite(prev) || Math.abs(prev - next) > 1e-12) {
      acct.balance = cached.balance;
      changed = true;
    }
    if (next > 0 && !acct.active) {
      acct.active = true;
      changed = true;
    }
  }
  if (changed) saveActiveAccounts();
  return changed;
}

function isRateLimitError(message) {
  const text = (message || '').toLowerCase();
  return text.includes('429')
    || text.includes('rate')
    || text.includes('limit')
    || text.includes('too many')
    || text.includes('throttl')
    || text.includes('quota');
}

async function waitForScanThrottle() {
  const now = Date.now();
  const elapsed = now - _scanLastRequestAt;
  if (elapsed < SCAN_REQUEST_DELAY_MS) {
    await sleep(SCAN_REQUEST_DELAY_MS - elapsed);
  }
  _scanLastRequestAt = Date.now();
}

function findExistingAccountForTarget(target) {
  return state.activeAccounts.find(a =>
    getAccountWalletId(a) === target.walletId
    && a.coinType === target.coinType
    && a.account === target.account
    && a.index === target.index
  );
}

async function fetchBalanceForScanTarget(target, address) {
  const cooldownUntil = state.balanceRateLimitUntil[target.coinType] || 0;
  if (Date.now() < cooldownUntil) {
    const stale = getCachedBalance(target.coinType, address, { allowStale: true });
    if (stale) {
      return {
        ok: true,
        balance: stale.balance,
        source: 'cache',
        stale: true,
        error: 'Rate-limited; using cached balance',
      };
    }
    return {
      ok: false,
      balance: '--',
      source: 'none',
      stale: false,
      error: 'Rate-limited; retrying later',
    };
  }

  const fresh = getCachedBalance(target.coinType, address);
  if (fresh) {
    return {
      ok: true,
      balance: fresh.balance,
      source: 'cache',
      stale: false,
    };
  }

  let lastError = '';
  for (let attempt = 0; attempt <= SCAN_MAX_RETRIES; attempt++) {
    await waitForScanThrottle();
    try {
      const result = await target.fetchBalance(address);
      const balance = result?.balance;
      const error = result?.error;
      if (!error && isNumericBalance(balance)) {
        state.balanceRateLimitUntil[target.coinType] = 0;
        setCachedBalance(target.coinType, address, balance);
        return {
          ok: true,
          balance: String(balance),
          source: 'network',
          stale: false,
        };
      }

      lastError = error || 'Unknown balance fetch error';
      if (isRateLimitError(lastError)) {
        state.balanceRateLimitUntil[target.coinType] = Date.now() + BALANCE_RATE_LIMIT_COOLDOWN_MS;
      }
    } catch (e) {
      lastError = e?.message || 'Unknown balance fetch exception';
      if (isRateLimitError(lastError)) {
        state.balanceRateLimitUntil[target.coinType] = Date.now() + BALANCE_RATE_LIMIT_COOLDOWN_MS;
      }
    }

    const retryable = isRateLimitError(lastError) || lastError.length > 0;
    if (attempt < SCAN_MAX_RETRIES && retryable) {
      const delay = SCAN_RETRY_BASE_DELAY_MS * (attempt + 1);
      await sleep(delay);
      continue;
    }
  }

  const stale = getCachedBalance(target.coinType, address, { allowStale: true });
  if (stale) {
    return {
      ok: true,
      balance: stale.balance,
      source: 'cache',
      stale: true,
      error: lastError,
    };
  }

  return {
    ok: false,
    balance: '--',
    source: 'none',
    stale: false,
    error: lastError || 'Balance unavailable',
  };
}

function saveActiveAccounts() {
  try {
    const serializable = state.activeAccounts.map(a => ({
      coinType: a.coinType,
      name: a.name,
      account: a.account,
      index: a.index,
      address: a.address,
      balance: a.balance,
      active: a.active,
      path: a.path,
      walletId: a.walletId ?? 0,
    }));
    localStorage.setItem(ACTIVE_ACCOUNTS_KEY, JSON.stringify(serializable));
  } catch (e) {
    console.warn('Failed to save active accounts:', e);
  }
}

function loadActiveAccounts() {
  try {
    const saved = localStorage.getItem(ACTIVE_ACCOUNTS_KEY);
    return saved ? JSON.parse(saved) : [];
  } catch {
    return [];
  }
}

function saveWallets() {
  try {
    localStorage.setItem(WALLETS_KEY, JSON.stringify(state.wallets));
  } catch (e) {
    console.warn('Failed to save wallets:', e);
  }
}

function loadWallets() {
  try {
    const saved = localStorage.getItem(WALLETS_KEY);
    return normalizeWallets(saved ? JSON.parse(saved) : getDefaultWalletState());
  } catch {
    return normalizeWallets(getDefaultWalletState());
  }
}

/**
 * Create a new wallet (Phantom-style: all chains at same account index N).
 * BTC: m/44'/0'/N'/0/0, ETH: m/44'/60'/0'/0/N, SOL: m/44'/501'/N'/0
 */
function createNewWallet(walletName) {
  if (!state.hdRoot) return;

  const maxIdx = state.wallets.reduce((m, w) => Math.max(m, w.accountIndex), -1);
  const nextIdx = maxIdx + 1;
  const nextId = state.wallets.reduce((m, w) => Math.max(m, w.id), -1) + 1;
  const name = normalizeWalletName(walletName, nextIdx);

  const wallet = { id: nextId, name, accountIndex: nextIdx, inactive: false };
  state.wallets.push(wallet);
  saveWallets();

  // Derive addresses for each chain at the new account index
  const chainDerivations = [
    { coinType: 0,   name: 'BTC', account: nextIdx, index: 0 },     // BTC: m/44'/0'/N'/0/0
    { coinType: 60,  name: 'ETH', account: 0,       index: nextIdx }, // ETH: m/44'/60'/0'/0/N
    { coinType: 501, name: 'SOL', account: nextIdx,  index: 0 },     // SOL: m/44'/501'/N'/0
  ];

  for (const cd of chainDerivations) {
    try {
      const { address, path } = deriveAddressForPath(cd.coinType, cd.account, cd.index);
      state.activeAccounts.push({
        coinType: cd.coinType,
        name: cd.name,
        account: cd.account,
        index: cd.index,
        address,
        path,
        balance: '--',
        active: false,
        walletId: nextId,
      });
    } catch (e) {
      console.warn('Failed to derive for new wallet:', cd.name, e);
    }
  }

  saveActiveAccounts();
  state.activeWalletId = nextId;
  renderAccountsList();
  renderWalletList();
  renderWalletSelector();
  updateCustomPathDefault();
}

function renameWallet(walletId, newName) {
  const wallet = state.wallets.find(w => w.id === walletId);
  if (!wallet) return;
  wallet.name = normalizeWalletName(newName, wallet.accountIndex);
  saveWallets();
  renderAccountsList();
  renderWalletSelector();
  updateCustomPathWalletLabel();
}

function setWalletInactive(walletId, inactive) {
  const wallet = getWalletById(walletId);
  if (!wallet) return;

  if (!inactive && !isWalletInactive(wallet)) return;
  if (inactive && isWalletInactive(wallet)) return;

  if (inactive && getActiveWallets().length <= 1) {
    alert('At least one active wallet is required.');
    return;
  }

  wallet.inactive = inactive;
  if (inactive && state.activeWalletId === walletId) {
    const fallback = getActiveWallets()[0];
    state.activeWalletId = fallback ? fallback.id : 0;
  }

  saveWallets();
  renderWalletList();
  renderWalletSelector();
  renderAccountsList();
  updateCustomPathDefault();
  updateWalletBondTotal();
}

function setWalletManageTab(tabName) {
  state.walletManageTab = tabName === 'inactive' ? 'inactive' : 'active';

  const activeBtn = $('wallet-manage-tab-active');
  const inactiveBtn = $('wallet-manage-tab-inactive');
  if (activeBtn) activeBtn.classList.toggle('active', state.walletManageTab === 'active');
  if (inactiveBtn) inactiveBtn.classList.toggle('active', state.walletManageTab === 'inactive');

  renderWalletList();
}

function renderWalletList() {
  const listEl = $('wallet-list');
  if (!listEl) return;
  listEl.innerHTML = '';
  ensureWalletNamesNormalized();

  const activeWalletCount = getActiveWallets().length;
  const walletsToRender = state.walletManageTab === 'inactive'
    ? getInactiveWallets()
    : getActiveWallets();

  if (walletsToRender.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'wallet-manage-empty';
    empty.textContent = state.walletManageTab === 'inactive'
      ? 'No inactive wallets.'
      : 'No active wallets.';
    listEl.appendChild(empty);
    return;
  }

  for (const w of walletsToRender) {
    const count = state.activeAccounts.filter(a => getAccountWalletId(a) === w.id && isSigningAccountForWallet(a, w)).length;
    const actionLabel = isWalletInactive(w) ? 'Active' : 'Inactive';
    const disableAction = !isWalletInactive(w) && activeWalletCount <= 1;
    const derivationSummary = getWalletDerivationEntries(w)
      .map(entry => buildSigningPath(entry.coinType, entry.account, entry.index))
      .join(' • ');
    const derivationTitle = derivationSummary.replace(/"/g, '&quot;');
    const row = document.createElement('div');
    row.className = 'wallet-name-row';
    row.innerHTML =
      '<div class="wallet-name-cell">' +
      '<input class="wallet-name-input glass-input compact" value="' + (w.name || '').replace(/"/g, '&quot;') + '" data-wallet-id="' + w.id + '">' +
      '<div class="wallet-derivation-path" title="' + derivationTitle + '">' + derivationSummary + '</div>' +
      '</div>' +
      '<span class="wallet-account-count">' + count + ' account' + (count !== 1 ? 's' : '') + '</span>' +
      '<button class="wallet-status-btn glass-btn small' + (disableAction ? ' disabled' : '') + '" data-wallet-id="' + w.id + '" data-target-inactive="' + (!isWalletInactive(w)) + '" ' + (disableAction ? 'disabled' : '') + '>' + actionLabel + '</button>';
    listEl.appendChild(row);
  }

  listEl.querySelectorAll('.wallet-name-input').forEach(input => {
    input.addEventListener('change', (e) => {
      const id = Number.parseInt(e.target.dataset.walletId, 10);
      const wallet = getWalletById(id);
      renameWallet(id, e.target.value.trim() || getDefaultWalletName(wallet ? wallet.accountIndex : id));
    });
  });

  listEl.querySelectorAll('.wallet-status-btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      const id = Number.parseInt(e.currentTarget.dataset.walletId, 10);
      if (Number.isNaN(id)) return;
      const targetInactive = e.currentTarget.dataset.targetInactive === 'true';
      setWalletInactive(id, targetInactive);
    });
  });
}

// --- Wallet Overlay Navigation ---

function hideWalletOverlays() {
  WALLET_OVERLAY_VIEWS.forEach((viewId) => {
    const view = $(viewId);
    if (view) view.style.display = 'none';
  });
}

function showWalletMainView() {
  const main = $('wallet-main-view');
  hideWalletOverlays();
  if (main) main.style.display = 'block';
}

function showWalletView(viewId) {
  const main = $('wallet-main-view');
  hideWalletOverlays();
  if (main) main.style.display = 'none';
  const view = $(viewId);
  if (view) view.style.display = viewId === 'wallet-wallets-view' ? 'flex' : 'block';
}

function showWalletsView() {
  showWalletView('wallet-wallets-view');
  setWalletManageTab(state.walletManageTab);
}

function showExportView() {
  showWalletView('wallet-export-view');
}

function showAdvancedView() {
  showWalletView('wallet-advanced-view');
  updateCustomPathWalletLabel();
  updateCustomPathDefault();
}

function showSendView(preselectedIdx) {
  showWalletView('wallet-send-view');
  populateSendForm(preselectedIdx);
}

function hideSendView() {
  showWalletMainView();
  // Reset form
  const compose = $('send-compose-step');
  const review = $('send-review-step');
  if (compose) compose.style.display = 'block';
  if (review) review.style.display = 'none';
}

function addCustomPathAccount() {
  if (!state.hdRoot) return;
  const chainSelect = $('custom-path-chain');
  const pathInput = $('custom-path-input');
  if (!chainSelect || !pathInput) return;

  const coinType = Number.parseInt(chainSelect.value, 10);
  const pathStr = pathInput.value.trim();
  if (!pathStr || Number.isNaN(coinType)) return;

  // Parse account/index from path (m/44'/coin'/account'/0/index)
  const parts = pathStr.replace(/'/g, '').split('/');
  const account = Number.parseInt(parts[3], 10) || 0;
  const index = Number.parseInt(parts[5], 10) || 0;
  const wallet = getCurrentWallet();
  const walletId = wallet ? wallet.id : 0;
  if (!wallet) return;

  const proposed = { coinType, account, index, walletId };
  if (!isSigningAccountForWallet(proposed, wallet)) {
    alert('Only signing-path accounts are supported for wallet availability.');
    updateCustomPathDefault();
    return;
  }

  const chainName = CHAIN_CONFIG.find(c => c.coinType === coinType)?.name || 'BTC';
  const exists = state.activeAccounts.some(
    a => getAccountWalletId(a) === walletId
      && a.coinType === coinType
      && a.account === account
      && a.index === index
  );
  if (exists) return;

  try {
    const { address, path } = deriveAddressForPath(coinType, account, index);
    state.activeAccounts.push({
      coinType,
      name: chainName,
      account,
      index,
      address,
      path,
      balance: '--',
      active: false,
      walletId,
    });
    saveActiveAccounts();
    renderAccountsList();
    updateWalletBondTotal();
    updateCustomPathDefault();
  } catch (e) {
    console.warn('Failed to add custom path:', e);
  }
}

/**
 * Merge newly scanned accounts with existing ones.
 * Preserves user's active/inactive choices; updates balances.
 */
function mergeAccounts(existing, scanned) {
  const key = (a) => `${getAccountWalletId(a)}:${a.coinType}:${a.account}:${a.index}`;
  const map = new Map();

  // Existing accounts keep their active state
  for (const a of existing) {
    map.set(key(a), { ...a, walletId: getAccountWalletId(a) });
  }

  // Scanned accounts update balances, add new entries
  for (const a of scanned) {
    const k = key(a);
    if (map.has(k)) {
      const prev = map.get(k);
      prev.balance = a.balance;
      prev.address = a.address;
      prev.path = a.path;
      prev.name = a.name;
      prev.walletId = getAccountWalletId(a);
    } else {
      map.set(k, { ...a, walletId: getAccountWalletId(a) });
    }
  }

  return Array.from(map.values());
}

const CHAIN_CONFIG = [
  { coinType: 0,   name: 'BTC', fetchBalance: fetchBtcBalance },
  { coinType: 60,  name: 'ETH', fetchBalance: fetchEthBalance },
  { coinType: 501, name: 'SOL', fetchBalance: fetchSolBalance },
];

async function scanActiveAccounts() {
  if (!state.hdRoot) return;
  if (state.scanInProgress) return;
  state.scanInProgress = true;

  if (!state.balanceCacheLoaded) {
    state.balanceCache = loadBalanceCache();
    state.balanceCacheLoaded = true;
  }
  pruneBalanceCache();
  const ensuredAccounts = ensureWalletAccounts();
  const hydratedFromCache = hydrateAccountsFromBalanceCache();
  if (ensuredAccounts || hydratedFromCache) {
    renderAccountsList();
  }
  updateWalletBondTotal();

  const statusEl = $('wallet-scan-status');
  const barEl = $('wallet-scan-bar');
  const scanBtn = $('wallet-scan-btn');
  if (statusEl) statusEl.style.display = 'block';
  if (barEl) barEl.style.width = '0%';
  if (scanBtn) scanBtn.disabled = true;

  try {
    const found = [];
    const chainByCoinType = new Map(CHAIN_CONFIG.map(chain => [chain.coinType, chain]));
    const targets = [];
    const seen = new Set();
    const addTarget = (coinType, account, index, walletId, name) => {
      const chain = chainByCoinType.get(coinType);
      if (!chain) return;
      const key = `${walletId}:${coinType}:${account}:${index}`;
      if (seen.has(key)) return;
      seen.add(key);
      targets.push({
        coinType,
        account,
        index,
        walletId,
        name: name || chain.name,
        fetchBalance: chain.fetchBalance,
      });
    };

    getActiveWallets().forEach((wallet) => {
      getWalletDerivationEntries(wallet).forEach((entry) => {
        addTarget(entry.coinType, entry.account, entry.index, wallet.id, entry.name);
      });
    });

    for (let ti = 0; ti < targets.length; ti++) {
      const target = targets[ti];
      if (barEl) barEl.style.width = Math.round(((ti + 1) / targets.length) * 100) + '%';

      let derived;
      try {
        derived = deriveAddressForPath(target.coinType, target.account, target.index);
      } catch (deriveErr) {
        console.warn(`Derivation failed ${target.name} ${target.account}/${target.index}:`, deriveErr);
        continue;
      }

      const existing = findExistingAccountForTarget(target);
      const result = await fetchBalanceForScanTarget(target, derived.address);
      if (!result.ok) {
        console.warn(`Balance fetch failed ${target.name} ${target.account}/${target.index}:`, result.error);
      }

      // Never clobber a known balance with "--" when the network call fails/rate-limits.
      const resolvedBalance = result.ok
        ? result.balance
        : (existing?.balance && existing.balance !== '--' ? existing.balance : '--');
      const balNum = Number.parseFloat(resolvedBalance);

      found.push({
        coinType: target.coinType,
        name: target.name,
        account: target.account,
        index: target.index,
        address: derived.address,
        path: derived.path,
        balance: resolvedBalance,
        active: Number.isFinite(balNum) ? balNum > 0 : (existing?.active || false),
        walletId: target.walletId,
      });

      // Surface funded accounts quickly instead of waiting for full scan completion.
      if (Number.isFinite(balNum) && balNum > 0) {
        state.activeAccounts = mergeAccounts(state.activeAccounts, [found[found.length - 1]]).filter(isSigningAccount);
        saveActiveAccounts();
        renderAccountsList();
        updateWalletBondTotal();
      }
    }

    state.activeAccounts = mergeAccounts(state.activeAccounts, found).filter(isSigningAccount);
    saveActiveAccounts();
    saveBalanceCache();
    renderAccountsList();
    updateWalletBondTotal();
  } finally {
    if (statusEl) statusEl.style.display = 'none';
    if (scanBtn) scanBtn.disabled = false;
    state.scanInProgress = false;
  }
}

const CHAIN_ICONS = {
  BTC: { color: '#F7931A', symbol: '\u20BF' },
  ETH: { color: '#627EEA', symbol: '\u039E' },
  SOL: { color: '#9945FF', symbol: 'S' },
};

const CHAIN_FULL_NAMES = {
  BTC: 'Bitcoin',
  ETH: 'Ethereum',
  SOL: 'Solana',
};

function getVisibleWalletEntries() {
  const wallet = getCurrentWallet();
  if (!wallet) return [];
  const chainOrder = { BTC: 0, ETH: 1, SOL: 2 };
  const entries = state.activeAccounts
    .map((acct, idx) => ({ acct, idx, walletId: getAccountWalletId(acct) }))
    .filter(entry => entry.walletId === wallet.id && isSigningAccountForWallet(entry.acct, wallet));

  entries.sort((a, b) => {
    const chainDelta = (chainOrder[a.acct.name] ?? 99) - (chainOrder[b.acct.name] ?? 99);
    if (chainDelta !== 0) return chainDelta;
    const accountDelta = (a.acct.account ?? 0) - (b.acct.account ?? 0);
    if (accountDelta !== 0) return accountDelta;
    return (a.acct.index ?? 0) - (b.acct.index ?? 0);
  });
  return entries;
}

function getWalletAccountForChain(chainName) {
  const matches = getVisibleWalletEntries()
    .map(entry => entry.acct)
    .filter(acct => acct.name === chainName);
  if (matches.length === 0) return null;

  const funded = matches.filter(acct => (Number.parseFloat(acct.balance) || 0) > 0);
  const activeFunded = funded.find(acct => acct.active);
  if (activeFunded) return activeFunded;
  if (funded.length > 0) return funded[0];

  const active = matches.find(acct => acct.active);
  if (active) return active;
  return matches[0];
}

function updateWalletActionMenus() {
  ['BTC', 'ETH', 'SOL'].forEach((chain) => {
    const available = Boolean(getWalletAccountForChain(chain));
    $qa(`.ph-action-menu-item[data-chain="${chain}"]`).forEach((btn) => {
      btn.disabled = !available;
      btn.title = available ? '' : `No ${chain} account in this wallet`;
    });
  });
}

function closeWalletActionMenus() {
  $('wallet-send-menu')?.classList.remove('visible');
  $('wallet-receive-menu')?.classList.remove('visible');
}

function renderAccountsList() {
  const listEl = $('wallet-accounts-list');
  const emptyEl = $('wallet-accounts-empty');
  if (!listEl) return;

  // Clear all dynamic content (wallet headers + token rows)
  listEl.querySelectorAll('.ph-token-row, .ph-wallet-header').forEach(r => r.remove());

  // External session: ONE row — the connected account (no derivation, no
  // wallet selector). Wallet-supplied strings go in via textContent only.
  if (state.externalAccount && !state.hdRoot) {
    if (emptyEl) emptyEl.style.display = 'none';
    const acct = state.externalAccount;
    const symbol = acct.chain.toUpperCase();
    const icon = CHAIN_ICONS[symbol] || { color: '#888', symbol: '?' };
    const bal = parseFloat(acct.balance);
    const balDisplay = isNaN(bal) ? '--' : (bal > 0 ? bal.toFixed(bal < 0.001 ? 8 : 4) : '0');

    const row = document.createElement('div');
    row.className = 'ph-token-row';
    row.innerHTML =
      '<div class="ph-token-icon" style="background:' + icon.color + '">' + icon.symbol + '</div>' +
      '<div class="ph-token-info">' +
        '<div class="ph-token-name"></div>' +
        '<div class="ph-token-path"></div>' +
      '</div>' +
      '<div class="ph-token-amounts">' +
        '<div class="ph-token-balance">' + balDisplay + ' ' + symbol + '</div>' +
        '<div class="ph-token-fiat" id="ph-fiat-external"></div>' +
      '</div>';
    row.querySelector('.ph-token-name').textContent =
      acct.walletName || (CHAIN_FULL_NAMES[symbol] || symbol);
    const pathEl = row.querySelector('.ph-token-path');
    pathEl.textContent = truncateAddress(acct.address);
    pathEl.title = acct.address;
    listEl.appendChild(row);

    if (!isNaN(bal) && bal > 0) {
      fetchCryptoPrices(getSelectedCurrency()).then((prices) => {
        const price = Number.parseFloat(prices?.[symbol]);
        const fiatEl = $('ph-fiat-external');
        if (fiatEl && Number.isFinite(price) && price > 0) {
          fiatEl.textContent = formatCurrencyValue(bal * price, getSelectedCurrency());
        }
      }).catch(() => {});
    }
    updateWalletActionMenus();
    return;
  }

  const entries = getVisibleWalletEntries();
  if (entries.length === 0) {
    if (emptyEl) emptyEl.style.display = 'flex';
    const emptySub = emptyEl?.querySelector('.ph-token-empty-sub');
    if (emptySub) {
      const wallet = getCurrentWallet();
      emptySub.textContent = wallet
        ? `No accounts yet for ${wallet.name}. Tap Scan or add one from Advanced.`
        : 'No accounts yet.';
    }
    updateWalletActionMenus();
    return;
  }

  if (emptyEl) emptyEl.style.display = 'none';

  const pricesPromise = fetchCryptoPrices(getSelectedCurrency()).catch(() => null);

  for (const { acct, idx } of entries) {
    const row = document.createElement('div');
    row.className = 'ph-token-row' + (acct.active ? '' : ' ph-token-inactive');
    row.dataset.idx = idx;

    const bal = parseFloat(acct.balance);
    const balDisplay = isNaN(bal) ? acct.balance : (bal > 0 ? bal.toFixed(bal < 0.001 ? 8 : 4) : '0');
    const icon = CHAIN_ICONS[acct.name] || { color: '#888', symbol: '?' };
    const fullName = CHAIN_FULL_NAMES[acct.name] || acct.name;
    const pathLabel = acct.path || "m/44'/" + acct.coinType + "'/" + acct.account + "'/0/" + acct.index;

    row.innerHTML =
      '<div class="ph-token-icon" style="background:' + icon.color + '">' + icon.symbol + '</div>' +
      '<div class="ph-token-info">' +
        '<div class="ph-token-name">' + fullName + '</div>' +
        '<div class="ph-token-path">' + pathLabel + '</div>' +
      '</div>' +
      '<div class="ph-token-amounts">' +
        '<div class="ph-token-balance">' + balDisplay + ' ' + acct.name + '</div>' +
        '<div class="ph-token-fiat" id="ph-fiat-' + idx + '"></div>' +
      '</div>';

    row.addEventListener('click', () => {
      showReceiveModal(acct);
    });

    listEl.appendChild(row);
  }
  updateWalletActionMenus();

  pricesPromise.then(prices => {
    if (!prices) return;
    const currency = getSelectedCurrency();
    entries.forEach(({ acct, idx }) => {
      const bal = parseFloat(acct.balance) || 0;
      const priceKey = acct.name.toUpperCase();
      const fiatVal = bal * (prices[priceKey] || 0);
      const el = $('ph-fiat-' + idx);
      if (el) el.textContent = fiatVal > 0 ? formatCurrencyValue(fiatVal, currency) : '';
    });
  });
}

function toggleAccountActive(idx) {
  if (idx < 0 || idx >= state.activeAccounts.length) return;
  state.activeAccounts[idx].active = !state.activeAccounts[idx].active;
  saveActiveAccounts();
  renderAccountsList();
}

async function handleAccountAction(action, idx) {
  const acct = state.activeAccounts[idx];
  if (!acct) return;

  switch (action) {
    case 'receive':
      showReceiveModal(acct);
      break;
    case 'copy':
      await safeCopyText(acct.address);
      break;
    case 'toggle':
      toggleAccountActive(idx);
      break;
    case 'remove':
      state.activeAccounts.splice(idx, 1);
      saveActiveAccounts();
      renderAccountsList();
      break;
  }
}

async function showReceiveModal(acct) {
  // Create a simple receive overlay
  let overlay = $('wallet-receive-overlay');
  if (!overlay) {
    overlay = document.createElement('div');
    overlay.id = 'wallet-receive-overlay';
    overlay.className = 'wallet-receive-overlay';
    overlay.innerHTML = `
      <div class="wallet-receive-card">
        <h4 id="wallet-receive-title" class="section-label"></h4>
        <canvas id="wallet-receive-qr"></canvas>
        <code id="wallet-receive-address" class="wallet-receive-address"></code>
        <div class="wallet-receive-actions">
          <button id="wallet-receive-copy" class="glass-btn small">Copy Address</button>
          <button id="wallet-receive-close" class="glass-btn small">Close</button>
        </div>
      </div>
    `;
    $('wallet-tab-content')?.appendChild(overlay);
  }

  const titleEl = overlay.querySelector('#wallet-receive-title');
  const addrEl = overlay.querySelector('#wallet-receive-address');
  if (titleEl) titleEl.textContent = `Receive ${acct.name}`;
  if (addrEl) addrEl.textContent = acct.address;

  try {
    const qrCanvas = overlay.querySelector('#wallet-receive-qr');
    if (qrCanvas) {
      await QRCode.toCanvas(qrCanvas, acct.address, {
        width: 180,
        margin: 2,
        color: { dark: '#1e293b', light: '#ffffff' },
      });
    }
  } catch (e) {
    console.warn('QR generation failed:', e);
  }

  overlay.style.display = 'flex';

  overlay.querySelector('#wallet-receive-copy')?.addEventListener('click', () => {
    void safeCopyText(acct.address);
  }, { once: true });

  overlay.querySelector('#wallet-receive-close')?.addEventListener('click', () => {
    overlay.style.display = 'none';
  }, { once: true });
}

// =============================================================================
// Send Flow
// =============================================================================

function populateSendForm(preselectedIdx) {
  const select = $('send-from-account');
  if (!select) return;
  select.innerHTML = '';

  const walletEntries = getVisibleWalletEntries();
  const walletAccounts = walletEntries.map(entry => entry.acct);
  const activeAccts = walletAccounts.filter(a => a.active || parseFloat(a.balance) > 0);
  const accts = activeAccts.length > 0 ? [...activeAccts] : [...walletAccounts];
  const preselectedAcct = typeof preselectedIdx === 'number' ? state.activeAccounts[preselectedIdx] : null;
  if (preselectedAcct && walletAccounts.includes(preselectedAcct) && !accts.includes(preselectedAcct)) {
    accts.unshift(preselectedAcct);
  }

  accts.forEach((acct) => {
    const opt = document.createElement('option');
    const origIdx = state.activeAccounts.indexOf(acct);
    opt.value = origIdx;
    const bal = parseFloat(acct.balance);
    const balStr = isNaN(bal) ? '' : (' — ' + bal.toFixed(bal < 0.001 ? 8 : 4) + ' ' + acct.name);
    opt.textContent = acct.name + ' ' + truncateAddress(acct.address) + balStr;
    select.appendChild(opt);
  });

  if (typeof preselectedIdx === 'number') {
    select.value = String(preselectedIdx);
  }

  if (select.options.length > 0) {
    updateSendFromSelection();
  } else {
    const balEl = $('send-available-balance');
    const labelEl = $('send-currency-label');
    if (balEl) balEl.textContent = '--';
    if (labelEl) labelEl.textContent = '--';
  }

  // Reset review step
  const compose = $('send-compose-step');
  const review = $('send-review-step');
  if (compose) compose.style.display = 'block';
  if (review) review.style.display = 'none';
  const statusEl = $('send-status');
  if (statusEl) statusEl.style.display = 'none';

  // Clear inputs
  const toAddr = $('send-to-address');
  const amount = $('send-amount');
  if (toAddr) toAddr.value = '';
  if (amount) amount.value = '';
  const fiatEst = $('send-fiat-estimate');
  if (fiatEst) fiatEst.textContent = '';
  const reviewBtn = $('send-review-btn');
  if (reviewBtn) reviewBtn.disabled = true;
}

function updateSendFromSelection() {
  const select = $('send-from-account');
  if (!select) return;
  const idx = parseInt(select.value);
  const acct = state.activeAccounts[idx];
  if (!acct) return;

  const balEl = $('send-available-balance');
  const labelEl = $('send-currency-label');
  if (balEl) {
    const bal = parseFloat(acct.balance);
    balEl.textContent = (isNaN(bal) ? acct.balance : bal.toFixed(bal < 0.001 ? 8 : 4)) + ' ' + acct.name;
  }
  if (labelEl) labelEl.textContent = acct.name;
}

function validateSendForm() {
  const select = $('send-from-account');
  const toAddr = $('send-to-address');
  const amount = $('send-amount');
  const reviewBtn = $('send-review-btn');
  if (!select || !toAddr || !amount || !reviewBtn) return;

  const idx = parseInt(select.value);
  const acct = state.activeAccounts[idx];
  const addr = toAddr.value.trim();
  const amt = parseFloat(amount.value);

  reviewBtn.disabled = !(acct && addr.length > 10 && amt > 0);
}

function showSendReview() {
  const select = $('send-from-account');
  const toAddr = $('send-to-address');
  const amount = $('send-amount');
  if (!select || !toAddr || !amount) return;

  const idx = parseInt(select.value);
  const acct = state.activeAccounts[idx];
  if (!acct) return;

  const amt = parseFloat(amount.value);
  const fee = acct.name === 'BTC' ? 0.0001 : (acct.name === 'ETH' ? 0.002 : 0.000005);

  const reviewTo = $('send-review-to');
  const reviewAmt = $('send-review-amount');
  const reviewFee = $('send-review-fee');
  const reviewTotal = $('send-review-total');

  if (reviewTo) reviewTo.textContent = toAddr.value.trim();
  if (reviewAmt) reviewAmt.textContent = amt.toFixed(amt < 0.001 ? 8 : 4) + ' ' + acct.name;
  if (reviewFee) reviewFee.textContent = '~' + fee + ' ' + acct.name;
  if (reviewTotal) reviewTotal.textContent = (amt + fee).toFixed(8) + ' ' + acct.name;

  const compose = $('send-compose-step');
  const review = $('send-review-step');
  if (compose) compose.style.display = 'none';
  if (review) review.style.display = 'block';
}

async function executeSend() {
  const select = $('send-from-account');
  const toAddr = $('send-to-address');
  const amount = $('send-amount');
  const statusEl = $('send-status');
  const confirmBtn = $('send-confirm-btn');

  if (!select || !toAddr || !amount) return;

  const idx = parseInt(select.value);
  const acct = state.activeAccounts[idx];
  if (!acct) return;

  const to = toAddr.value.trim();
  const amt = parseFloat(amount.value);

  if (statusEl) {
    statusEl.style.display = 'block';
    statusEl.className = 'send-status send-status-pending';
    statusEl.textContent = 'Broadcasting transaction...';
  }
  if (confirmBtn) confirmBtn.disabled = true;

  try {
    let txHash;

    if (acct.coinType === 0) {
      txHash = await sendBtcTransaction(acct, to, amt);
    } else if (acct.coinType === 60) {
      txHash = await sendEthTransaction(acct, to, amt);
    } else if (acct.coinType === 501) {
      txHash = await sendSolTransaction(acct, to, amt);
    } else {
      throw new Error('Unsupported chain: ' + acct.name);
    }

    if (statusEl) {
      statusEl.className = 'send-status send-status-success';
      statusEl.innerHTML = 'Transaction sent! Hash: <code class="truncate">' + (txHash || 'pending') + '</code>';
    }

    // Refresh balances after a short delay
    setTimeout(() => {
      scanActiveAccounts();
    }, 5000);
  } catch (e) {
    console.error('Send failed:', e);
    if (statusEl) {
      statusEl.className = 'send-status send-status-error';
      statusEl.textContent = 'Failed: ' + (e.message || 'Unknown error');
    }
  } finally {
    if (confirmBtn) confirmBtn.disabled = false;
  }
}

// --- Per-chain transaction construction ---

async function sendBtcTransaction(acct, toAddress, amountBtc) {
  const module = state.hdWalletModule;
  if (!module?.bitcoin?.tx) throw new Error('Bitcoin tx builder not available');

  // Fetch UTXOs
  const utxoResp = await fetch(apiUrl('https://blockchain.info/unspent?active=' + acct.address));
  if (!utxoResp.ok) throw new Error('Failed to fetch UTXOs (address may have no unspent outputs)');
  const utxoData = await utxoResp.json();
  const utxos = utxoData.unspent_outputs || [];
  if (utxos.length === 0) throw new Error('No UTXOs available');

  const amountSats = BigInt(Math.round(amountBtc * 1e8));
  const feeSats = BigInt(10000); // ~0.0001 BTC flat fee estimate
  const totalNeeded = amountSats + feeSats;

  // Select UTXOs (simple greedy)
  let inputSum = BigInt(0);
  const selectedUtxos = [];
  for (const utxo of utxos) {
    selectedUtxos.push(utxo);
    inputSum += BigInt(utxo.value);
    if (inputSum >= totalNeeded) break;
  }
  if (inputSum < totalNeeded) throw new Error('Insufficient funds');

  // Build transaction
  const tx = module.bitcoin.tx.create();
  for (const utxo of selectedUtxos) {
    tx.addInput(utxo.tx_hash_big_endian, utxo.tx_output_n);
  }
  tx.addOutput(toAddress, amountSats);

  // Change output
  const change = inputSum - amountSats - feeSats;
  if (change > BigInt(546)) { // dust threshold
    tx.addOutput(acct.address, change);
  }

  // Sign each input
  const path = acct.path || buildSigningPath(acct.coinType, acct.account, acct.index);
  const derived = state.hdRoot.derivePath(path);
  const privKey = derived.privateKey();
  for (let i = 0; i < selectedUtxos.length; i++) {
    tx.sign(i, privKey);
  }

  const rawTx = tx.serialize();
  const hexTx = Array.from(rawTx).map(b => b.toString(16).padStart(2, '0')).join('');

  // Broadcast
  const broadcastResp = await fetch(apiUrl('https://blockchain.info/pushtx'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: 'tx=' + hexTx,
  });
  if (!broadcastResp.ok) {
    const errText = await broadcastResp.text();
    throw new Error('Broadcast failed: ' + errText);
  }

  return tx.getTxid();
}

async function sendEthTransaction(acct, toAddress, amountEth) {
  const module = state.hdWalletModule;
  if (!module?.ethereum?.tx) throw new Error('Ethereum tx builder not available');

  const ETH_RPC = 'https://cloudflare-eth.com';
  const rpc = async (method, params) => {
    const resp = await fetch(ETH_RPC, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
    });
    const data = await resp.json();
    if (data.error) throw new Error(data.error.message);
    return data.result;
  };

  // Get nonce, gas price, estimate gas
  const [nonceHex, baseFeeBlock] = await Promise.all([
    rpc('eth_getTransactionCount', [acct.address, 'latest']),
    rpc('eth_getBlockByNumber', ['latest', false]),
  ]);

  const nonce = parseInt(nonceHex, 16);
  const baseFee = BigInt(baseFeeBlock.baseFeePerGas || '0x0');
  const maxPriorityFee = BigInt(2000000000); // 2 gwei
  const maxFee = baseFee * BigInt(2) + maxPriorityFee;
  const gasLimit = BigInt(21000);

  // Convert ETH to wei
  const weiStr = BigInt(Math.round(amountEth * 1e18));

  const tx = module.ethereum.tx.createEIP1559({
    nonce,
    maxFeePerGas: maxFee,
    maxPriorityFeePerGas: maxPriorityFee,
    gasLimit,
    to: toAddress,
    value: weiStr,
    chainId: 1,
  });

  // Sign
  const path = acct.path || buildSigningPath(acct.coinType, acct.account, acct.index);
  const derived = state.hdRoot.derivePath(path);
  const privKey = derived.privateKey();
  tx.sign(privKey);

  const rawTx = tx.serialize();
  const hexTx = '0x' + Array.from(rawTx).map(b => b.toString(16).padStart(2, '0')).join('');

  // Broadcast
  const txHash = await rpc('eth_sendRawTransaction', [hexTx]);
  return txHash;
}

async function sendSolTransaction(acct, toAddress, amountSol) {
  // Solana transfer via RPC (no WASM builder — manual SystemProgram.transfer)
  const SOL_ENDPOINTS = [
    'https://api.mainnet-beta.solana.com',
    'https://solana-mainnet.g.alchemy.com/v2/demo',
    'https://rpc.ankr.com/solana',
  ];

  const rpc = async (method, params) => {
    for (const endpoint of SOL_ENDPOINTS) {
      try {
        const resp = await fetch(endpoint, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        });
        const data = await resp.json();
        if (data.error) throw new Error(data.error.message);
        return data.result;
      } catch (e) {
        continue;
      }
    }
    throw new Error('All Solana RPC endpoints failed');
  };

  // For Solana, we need @solana/web3.js which may not be available
  // Try dynamic import, otherwise fail gracefully
  throw new Error('Solana send requires @solana/web3.js (not yet integrated). Use a Solana wallet to send SOL.');
}

async function updateSendFiatEstimate() {
  const select = $('send-from-account');
  const amount = $('send-amount');
  const fiatEst = $('send-fiat-estimate');
  if (!select || !amount || !fiatEst) return;

  const idx = parseInt(select.value);
  const acct = state.activeAccounts[idx];
  if (!acct) return;

  const amt = parseFloat(amount.value) || 0;
  if (amt <= 0) { fiatEst.textContent = ''; return; }

  try {
    const currency = getSelectedCurrency();
    const prices = await fetchCryptoPrices(currency);
    const price = prices[acct.name.toUpperCase()] || 0;
    const fiat = amt * price;
    fiatEst.textContent = fiat > 0 ? '~ ' + formatCurrencyValue(fiat, currency) : '';
  } catch {
    fiatEst.textContent = '';
  }
}

async function updateWalletBondTotal() {
  const valueEl = $('wallet-bond-value');

  try {
    const currency = getSelectedCurrency();
    const prices = await fetchCryptoPrices(currency);

    let total = 0;
    const walletTotals = {};
    let hasPositiveBalance = false;
    let missingPriceForFundedAccount = false;
    for (const acct of state.activeAccounts.filter(isSigningAccount)) {
      const bal = Number.parseFloat(acct.balance);
      if (!Number.isFinite(bal) || bal <= 0) continue;
      hasPositiveBalance = true;

      const priceKey = acct.name.toUpperCase();
      const price = Number.parseFloat(prices[priceKey]);
      if (!Number.isFinite(price) || price <= 0) {
        missingPriceForFundedAccount = true;
        continue;
      }

      const fiatValue = bal * price;
      total += fiatValue;
      const walletId = getAccountWalletId(acct);
      walletTotals[walletId] = (walletTotals[walletId] || 0) + fiatValue;
    }

    // External session: the connected address's balance IS the bond.
    if (state.externalAccount) {
      const bal = Number.parseFloat(state.externalAccount.balance);
      if (Number.isFinite(bal) && bal > 0) {
        hasPositiveBalance = true;
        const price = Number.parseFloat(prices[state.externalAccount.chain.toUpperCase()]);
        if (Number.isFinite(price) && price > 0) {
          total += bal * price;
        } else {
          missingPriceForFundedAccount = true;
        }
      }
    }

    if (hasPositiveBalance && total <= 0 && missingPriceForFundedAccount) {
      throw new Error('Funded accounts found but fiat pricing is unavailable');
    }

    state.walletFiatTotals = walletTotals;
    state.walletFiatCurrency = currency;

    const formatted = formatCurrencyValue(total, currency);
    if (valueEl) valueEl.textContent = formatted;
    renderWalletSelector();

    // Also update the header bond total
    const accountTotalEl = $('account-total-value');
    if (accountTotalEl) {
      accountTotalEl.textContent = 'Bond: ' + formatted;
    }
  } catch (e) {
    console.warn('Bond total calculation failed:', e);
    // Keep last known totals if pricing endpoint is temporarily unavailable.
    const cachedTotals = state.walletFiatTotals || {};
    const cachedTotal = Object.values(cachedTotals).reduce((sum, v) => sum + (Number.isFinite(v) ? v : 0), 0);
    if (cachedTotal > 0) {
      const displayCurrency = state.walletFiatCurrency || getSelectedCurrency();
      const formatted = formatCurrencyValue(cachedTotal, displayCurrency);
      if (valueEl) valueEl.textContent = formatted;
      const accountTotalEl = $('account-total-value');
      if (accountTotalEl) accountTotalEl.textContent = 'Bond: ' + formatted;
    } else if (valueEl && !valueEl.textContent) {
      valueEl.textContent = '$0.00';
    }
    renderWalletSelector();
  }
}


async function deriveAndDisplayAddress() {
  console.log('deriveAndDisplayAddress called, hdRoot:', !!state.hdRoot);

  const hdNotInitialized = $('hd-not-initialized');
  const derivedResult = $('derived-result');

  if (!state.hdRoot) {
    console.log('HD not initialized, showing warning.');
    if (hdNotInitialized) hdNotInitialized.style.display = 'block';
    if (derivedResult) derivedResult.style.display = 'none';
    return;
  }

  if (hdNotInitialized) hdNotInitialized.style.display = 'none';

  const coin = $('hd-coin')?.value;
  const account = $('hd-account')?.value || '0';
  const index = $('hd-index')?.value || '0';
  const coinType = parseInt(coin);
  const coinOption = $('hd-coin')?.selectedOptions[0];
  const cryptoName = coinOption?.dataset.name || 'Unknown';
  const cryptoSymbol = coinOption?.dataset.symbol || '???';

  const signingPath = buildSigningPath(coin, account, index);
  const encryptionPath = buildEncryptionPath(coin, account, index);

  console.log('Deriving signing path:', signingPath);
  console.log('Deriving encryption path:', encryptionPath);

  try {
    const signingKey = deriveHDKey(signingPath);
    const signingPubKey = signingKey.publicKey();

    const encryptionKey = deriveHDKey(encryptionPath);
    const encryptionPubKey = encryptionKey.publicKey();

    const address = generateAddressForCoin(signingPubKey, coinType);
    console.log('Generated address:', address);

    const config = coinTypeToConfig[coinType];
    const explorerUrl = config ? config.explorer + address : null;

    if (derivedResult) derivedResult.style.display = 'block';

    const signingPathEl = $('signing-path');
    const encryptionPathEl = $('encryption-path');
    if (signingPathEl) signingPathEl.textContent = signingPath;
    if (encryptionPathEl) encryptionPathEl.textContent = encryptionPath;

    const signingPubkeyEl = $('signing-pubkey');
    const encryptionPubkeyEl = $('encryption-pubkey');
    if (signingPubkeyEl) signingPubkeyEl.textContent = toHexCompact(signingPubKey);
    if (encryptionPubkeyEl) encryptionPubkeyEl.textContent = toHexCompact(encryptionPubKey);

    const derivedCryptoName = $('derived-crypto-name');
    const derivedIcon = $('derived-icon');
    const derivedAddress = $('derived-address');
    if (derivedCryptoName) derivedCryptoName.textContent = cryptoName;
    if (derivedIcon) derivedIcon.textContent = cryptoSymbol.substring(0, 2);
    if (derivedAddress) derivedAddress.textContent = address;

    const explorerLink = $('derived-explorer-link');
    if (explorerLink) {
      if (explorerUrl) {
        explorerLink.href = explorerUrl;
        explorerLink.style.display = 'inline-flex';
      } else {
        explorerLink.style.display = 'none';
      }
    }

    // Generate QR code
    try {
      const qrCanvas = $('address-qr');
      if (qrCanvas) {
        await QRCode.toCanvas(qrCanvas, address, {
          width: 64,
          margin: 1,
          color: { dark: '#1e293b', light: '#ffffff' },
        });
      }
    } catch (qrErr) {
      console.warn('QR generation failed:', qrErr);
    }

  } catch (err) {
    console.error('Derivation failed:', err);
  }
}

// =============================================================================
// PKI Key Derivation from HD Wallet
// =============================================================================

function deriveKeyFromPath(path) {
  if (!state.hdRoot) {
    throw new Error('HD wallet not initialized');
  }
  const derived = state.hdRoot.derivePath(path);
  return derived.privateKey();
}

function deriveX25519FromSeed(seed) {
  const privateKey = new Uint8Array(seed);
  const publicKey = hdWallet().curves.x25519.publicKey(privateKey);
  return {
    privateKey,
    publicKey: new Uint8Array(publicKey),
  };
}

function deriveSecp256k1FromSeed(seed) {
  const privateKey = new Uint8Array(seed);
  const publicKey = hdWallet().curves.publicKeyFromPrivate(privateKey, Curve.SECP256K1);
  return {
    privateKey,
    publicKey: new Uint8Array(publicKey),
  };
}

function deriveP256FromSeed(seed) {
  const privateKey = new Uint8Array(seed);
  const publicKey = hdWallet().curves.publicKeyFromPrivate(privateKey, Curve.P256);
  return {
    privateKey,
    publicKey: new Uint8Array(publicKey),
  };
}

function derivePKIKeysFromHD() {
  if (!state.hdRoot) {
    console.warn('HD wallet not initialized, cannot derive PKI keys');
    return false;
  }

  const algorithm = $('pki-algorithm')?.value || 'x25519';
  state.pki.algorithm = algorithm;

  try {
    const alicePath = "m/44'/0'/0'/0/0";
    const bobPath = "m/44'/0'/0'/0/1";

    const aliceSeed = deriveKeyFromPath(alicePath);
    const bobSeed = deriveKeyFromPath(bobPath);

    switch (algorithm) {
      case 'x25519':
        state.pki.alice = deriveX25519FromSeed(aliceSeed);
        state.pki.bob = deriveX25519FromSeed(bobSeed);
        break;
      case 'secp256k1':
        state.pki.alice = deriveSecp256k1FromSeed(aliceSeed);
        state.pki.bob = deriveSecp256k1FromSeed(bobSeed);
        break;
      case 'p256':
        state.pki.alice = deriveP256FromSeed(aliceSeed);
        state.pki.bob = deriveP256FromSeed(bobSeed);
        break;
      default:
        state.pki.alice = deriveX25519FromSeed(aliceSeed);
        state.pki.bob = deriveX25519FromSeed(bobSeed);
    }

    return true;
  } catch (e) {
    console.error('Failed to derive PKI keys from HD:', e);
    return false;
  }
}

function savePKIKeys() {
  if (!state.pki.alice || !state.pki.bob) {
    console.warn('Cannot save PKI keys: alice or bob is null');
    return;
  }

  // SECURITY: Never persist private keys in plaintext localStorage.
  // Persist encrypted only when a session encryption key exists (i.e., after wallet login).
  if (!(state.encryptionKey instanceof Uint8Array) || state.encryptionKey.length < 16) {
    console.warn('Skipping PKI key persistence: session encryption key not available (login required)');
    return;
  }

  const plaintext = {
    algorithm: state.pki.algorithm,
    alice: {
      publicKey: toHexCompact(state.pki.alice.publicKey),
      privateKey: toHexCompact(state.pki.alice.privateKey),
    },
    bob: {
      publicKey: toHexCompact(state.pki.bob.publicKey),
      privateKey: toHexCompact(state.pki.bob.privateKey),
    },
    savedAt: new Date().toISOString(),
  };

  aesGcmEncryptJson(state.encryptionKey, plaintext, 'wallet-ui|pki-keys')
    .then(({ iv, ciphertext }) => {
      const stored = {
        v: 1,
        iv: bytesToBase64(iv),
        ciphertext: bytesToBase64(ciphertext),
      };
      localStorage.setItem(PKI_STORAGE_KEY, JSON.stringify(stored));
    })
    .catch((e) => {
      console.warn('Failed to encrypt+save PKI keys to localStorage:', e);
    });
}

async function loadPKIKeys() {
  try {
    const stored = localStorage.getItem(PKI_STORAGE_KEY);
    if (!stored) return false;

    const data = JSON.parse(stored);
    const hasEncryptedShape = data && typeof data === 'object' && typeof data.iv === 'string' && typeof data.ciphertext === 'string';

    // Legacy plaintext format (insecure): refuse to load until logged in, then upgrade.
    const hasLegacyPlaintextShape = data?.alice?.privateKey && data?.bob?.privateKey && data?.algorithm;

    if (!hasEncryptedShape && !hasLegacyPlaintextShape) {
      console.warn('Invalid PKI data in localStorage');
      return false;
    }

    if (!(state.encryptionKey instanceof Uint8Array) || state.encryptionKey.length < 16) {
      // Not logged in yet; don't load private keys.
      return false;
    }

    let plaintext;
    if (hasEncryptedShape) {
      const iv = base64ToBytes(data.iv);
      const ciphertext = base64ToBytes(data.ciphertext);
      plaintext = await aesGcmDecryptJson(state.encryptionKey, iv, ciphertext, 'wallet-ui|pki-keys');
    } else {
      // Legacy plaintext: load and immediately re-encrypt on next save.
      plaintext = data;
      // Upgrade-in-place.
      try {
        const { iv, ciphertext } = await aesGcmEncryptJson(state.encryptionKey, plaintext, 'wallet-ui|pki-keys');
        localStorage.setItem(PKI_STORAGE_KEY, JSON.stringify({
          v: 1,
          iv: bytesToBase64(iv),
          ciphertext: bytesToBase64(ciphertext),
        }));
      } catch (e) {
        console.warn('Failed to upgrade legacy plaintext PKI storage:', e);
      }
    }

    if (!plaintext?.alice || !plaintext?.bob || !plaintext?.algorithm) {
      console.warn('Invalid decrypted PKI data');
      return false;
    }

    state.pki.algorithm = plaintext.algorithm;
    state.pki.alice = {
      publicKey: hexToBytes(plaintext.alice.publicKey),
      privateKey: hexToBytes(plaintext.alice.privateKey),
    };
    state.pki.bob = {
      publicKey: hexToBytes(plaintext.bob.publicKey),
      privateKey: hexToBytes(plaintext.bob.privateKey),
    };

    // Update UI
    const alicePublicKey = $('alice-public-key');
    const alicePrivateKey = $('alice-private-key');
    const bobPublicKey = $('bob-public-key');
    const bobPrivateKey = $('bob-private-key');
    const pkiParties = $('pki-parties');
    const pkiDemo = $('pki-demo');
    const pkiSecurity = $('pki-security');
    const pkiClearKeys = $('pki-clear-keys');

    const pkiAlgorithm = $('pki-algorithm');
    if (pkiAlgorithm) pkiAlgorithm.value = plaintext.algorithm;
    if (alicePublicKey) alicePublicKey.textContent = plaintext.alice.publicKey;
    if (alicePrivateKey) alicePrivateKey.textContent = plaintext.alice.privateKey;
    if (bobPublicKey) bobPublicKey.textContent = plaintext.bob.publicKey;
    if (bobPrivateKey) bobPrivateKey.textContent = plaintext.bob.privateKey;
    if (pkiParties) pkiParties.style.display = 'grid';
    if (pkiDemo) pkiDemo.style.display = 'block';
    if (pkiSecurity) pkiSecurity.style.display = 'block';
    if (pkiClearKeys) pkiClearKeys.style.display = 'inline-flex';

    return true;
  } catch (e) {
    console.warn('Failed to load PKI keys from localStorage:', e);
    return false;
  }
}

function clearPKIKeys() {
  try {
    localStorage.removeItem(PKI_STORAGE_KEY);
  } catch (e) {
    console.warn('Failed to clear PKI keys:', e);
  }

  try {
    if (state.pki?.alice?.privateKey instanceof Uint8Array) state.pki.alice.privateKey.fill(0);
    if (state.pki?.bob?.privateKey instanceof Uint8Array) state.pki.bob.privateKey.fill(0);
  } catch {
    // ignore
  }

  state.pki.alice = null;
  state.pki.bob = null;
  state.pki.algorithm = 'x25519';

  const els = ['alice-public-key', 'alice-private-key', 'bob-public-key', 'bob-private-key'];
  els.forEach(id => {
    const el = $(id);
    if (el) el.textContent = '--';
  });

  const loginPrompt = $('pki-login-prompt');
  if (loginPrompt) loginPrompt.style.display = 'block';
  const pkiControls = $('pki-controls');
  if (pkiControls) pkiControls.style.display = 'none';
  const pkiParties = $('pki-parties');
  if (pkiParties) pkiParties.style.display = 'none';
  const pkiDemo = $('pki-demo');
  if (pkiDemo) pkiDemo.style.display = 'none';
  const pkiSecurity = $('pki-security');
  if (pkiSecurity) pkiSecurity.style.display = 'none';
  const pkiClearKeys = $('pki-clear-keys');
  if (pkiClearKeys) pkiClearKeys.style.display = 'none';
}

async function generatePKIKeyPairs() {
  // First try to derive from HD wallet
  if (state.hdRoot && derivePKIKeysFromHD()) {
    // PKI keys derived from HD wallet
  } else {
    // Fallback to random generation
    const algorithm = $('pki-algorithm')?.value || 'x25519';
    state.pki.algorithm = algorithm;

    try {
      if (algorithm === 'p256') {
        state.pki.alice = await p256GenerateKeyPairAsync();
        state.pki.bob = await p256GenerateKeyPairAsync();
      } else if (algorithm === 'p384') {
        state.pki.alice = await p384GenerateKeyPairAsync();
        state.pki.bob = await p384GenerateKeyPairAsync();
      } else {
        const curveType = algorithm === 'secp256k1' ? Curve.SECP256K1 : Curve.X25519;
        state.pki.alice = generateKeyPair(curveType);
        state.pki.bob = generateKeyPair(curveType);
      }
    } catch (e) {
      console.error('Failed to generate PKI keys:', e);
      alert('Failed to generate keys: ' + e.message);
      return;
    }
  }

  savePKIKeys();

  // Display keys
  const alicePub = $('alice-public-key');
  const alicePriv = $('alice-private-key');
  const bobPub = $('bob-public-key');
  const bobPriv = $('bob-private-key');
  if (alicePub) alicePub.textContent = toHexCompact(state.pki.alice.publicKey);
  if (alicePriv) alicePriv.textContent = toHexCompact(state.pki.alice.privateKey);
  if (bobPub) bobPub.textContent = toHexCompact(state.pki.bob.publicKey);
  if (bobPriv) bobPriv.textContent = toHexCompact(state.pki.bob.privateKey);

  const algorithmNames = {
    x25519: 'X25519 (Curve25519)',
    secp256k1: 'secp256k1 (Bitcoin/Ethereum)',
    p256: 'P-256 / secp256r1 (NIST)',
    p384: 'P-384 / secp384r1 (NIST)',
  };
  const algDisplay = $('pki-algorithm-display');
  if (algDisplay) algDisplay.textContent = algorithmNames[state.pki.algorithm] || state.pki.algorithm;

  const selector = $('pki-algorithm');
  if (selector) selector.value = state.pki.algorithm;

  // Show UI sections
  const loginPrompt = $('pki-login-prompt');
  if (loginPrompt) loginPrompt.style.display = 'none';
  const pkiControls = $('pki-controls');
  if (pkiControls) pkiControls.style.display = 'flex';
  const pkiParties = $('pki-parties');
  if (pkiParties) pkiParties.style.display = 'grid';
  const pkiDemo = $('pki-demo');
  if (pkiDemo) pkiDemo.style.display = 'block';
  const pkiSecurity = $('pki-security');
  if (pkiSecurity) pkiSecurity.style.display = 'block';
  const pkiClearKeys = $('pki-clear-keys');
  if (pkiClearKeys) pkiClearKeys.style.display = 'inline-flex';
}

// =============================================================================
// Login / Logout
// =============================================================================

/**
 * EXTERNAL-WALLET SESSION (owner 2026-08-20: "we need the old interface back
 * with the bond, etc."): a connected external wallet opens the SAME account
 * interface an HD login does — the bond total, the account row with its live
 * balance, the bond-tab address rows, name resolution, and trust scanning —
 * all driven by the connected ADDRESS. No custody is fabricated: state.hdRoot
 * and state.wallet stay null, so every custody surface (xpub/xprv/seed, PKI,
 * derivation, export) keeps its existing guarded behavior. DISCONNECT in the
 * external panel is the logout affordance for this session.
 */
async function loginExternal(account) {
  state.loggedIn = true;
  const chain = account.lane === 'evm' ? 'eth' : 'sol';
  state.externalAccount = { ...account, chain, balance: null };
  state.addresses = { [chain]: account.address };
  state.selectedCrypto = chain;

  // Close the login modal; flip nav + hero to the signed-in state.
  $('login-modal')?.classList.remove('active');
  const heroWalletType = $('hero-wallet-type');
  const heroAddress = $('hero-address');
  const heroStats = $('hero-stats');
  if (heroWalletType) heroWalletType.textContent = account.walletName || cryptoConfig[chain].name;
  if (heroAddress) heroAddress.textContent = truncateAddress(account.address);
  if (heroStats) heroStats.classList.remove('hidden');
  const navLogin = $('nav-login');
  const navKeys = $('nav-keys');
  const navLogout = $('nav-logout');
  if (navLogin) navLogin.style.display = 'none';
  if (navKeys) navKeys.style.display = 'flex';
  if (navLogout) navLogout.style.display = 'flex';
  const mobileLogin = $('mobile-login');
  const mobileLogout = $('mobile-logout');
  if (mobileLogin) mobileLogin.style.display = 'none';
  if (mobileLogout) mobileLogout.style.display = 'block';

  // The account's public identity is its ADDRESS — the header and wallet-tab
  // rows that show the xpub for HD sessions show the address here.
  const headerLabel = $q('.account-address-label');
  const headerDisplay = $('account-address-display');
  if (headerLabel) headerLabel.textContent = 'address';
  if (headerDisplay) {
    headerDisplay.textContent = account.address;
    headerDisplay.title = account.address;
  }
  const walletTabXpub = $('wallet-tab-xpub');
  if (walletTabXpub) {
    walletTabXpub.textContent = account.address;
    walletTabXpub.title = account.address;
  }

  // Custody-only controls have nothing to act on without keys — hide them
  // rather than leave dead buttons. Receive stays: it shows the connected
  // address as a QR (see the receive handler's external branch).
  $q('.wallet-selector-row')?.style.setProperty('display', 'none');
  $('wallet-scan-btn')?.style.setProperty('display', 'none');
  $('wallet-send-action')?.style.setProperty('display', 'none');
  $('wallet-export-btn-main')?.style.setProperty('display', 'none');
  $('wallet-advanced-btn-main')?.style.setProperty('display', 'none');

  populateWalletAddresses();
  renderAccountsList();
  updateWalletBondTotal();

  // Open the Account modal so the user sees the account they just connected.
  if (_openAccountAfterLogin) {
    $('keys-modal')?.classList.add('active');
  }

  clearNameCache();
  resolveNames().then(names => updateAccountTitle(names));

  // Trust scanning runs off state.addresses — the address IS the identity.
  if (state._startTrustScanning) state._startTrustScanning();

  // Live balance for the connected address, then the bond total from it.
  try {
    const result = chain === 'eth'
      ? await fetchEthBalance(account.address)
      : await fetchSolBalance(account.address);
    state.externalAccount.balance = result?.balance ?? '--';
  } catch (e) {
    console.warn('External balance fetch failed:', e);
  }
  renderAccountsList();
  updateWalletBondTotal();
}

function login(keys) {
  state.loggedIn = true;
  state.wallet = keys;
  state.addresses = deriveAllAddressesFromHD();
  state.selectedCrypto = 'btc';

  // Fire onLogin callback with SDN identity (BIP-44 Bitcoin coin type 0)
  if (_onLoginCallback && state.hdRoot) {
    try {
      const sdnSigning = getSigningKey(state.hdRoot, 0, 0, 0);
      const sdnPrivKey = sdnSigning.privateKey;
      const sdnPubKey = hdWallet().curves.ed25519.publicKeyFromSeed(sdnPrivKey);
      // Don't keep derived private key bytes around longer than needed.
      if (sdnPrivKey instanceof Uint8Array) sdnPrivKey.fill(0);
      const xpub = state.hdRoot.toXpub();
      _onLoginCallback({
        xpub,
        peerId: deriveAccountPeerId(),
        signingPublicKey: sdnPubKey,
        async sign(message) {
          const msgBytes = typeof message === 'string'
            ? new TextEncoder().encode(message)
            : message;
          const signing = getSigningKey(state.hdRoot, 0, 0, 0);
          try {
            return hdWallet().curves.ed25519.sign(msgBytes, signing.privateKey);
          } finally {
            if (signing?.privateKey instanceof Uint8Array) signing.privateKey.fill(0);
          }
        },
      });
    } catch (err) {
      console.error('onLogin callback error:', err);
    }
  }

  // Close login modal if open
  $('login-modal')?.classList.remove('active');

  // Update hero stats display
  const heroWalletType = $('hero-wallet-type');
  const heroAddress = $('hero-address');
  const heroStats = $('hero-stats');
  if (heroWalletType) heroWalletType.textContent = cryptoConfig[state.selectedCrypto].name;
  if (heroAddress) heroAddress.textContent = truncateAddress(state.addresses[state.selectedCrypto]);
  if (heroStats) heroStats.classList.remove('hidden');

  // Show nav action buttons, hide login button
  const navLogin = $('nav-login');
  const navKeys = $('nav-keys');
  const navLogout = $('nav-logout');
  if (navLogin) navLogin.style.display = 'none';
  if (navKeys) navKeys.style.display = 'flex';
  if (navLogout) navLogout.style.display = 'flex';

  // Update mobile menu buttons
  const mobileLogin = $('mobile-login');
  const mobileLogout = $('mobile-logout');
  if (mobileLogin) mobileLogin.style.display = 'none';
  if (mobileLogout) mobileLogout.style.display = 'block';

  // Update HD wallet root keys display
  if (state.hdRoot) {
    const xpubEl = $('wallet-xpub');
    const xprvEl = $('wallet-xprv');
    const seedEl = $('wallet-seed-phrase');

    if (xpubEl) {
      setTruncatedValue(xpubEl, state.hdRoot.toXpub() || 'N/A');
    }
    // Populate wallet tab xpub display
    const walletTabXpubEl = $('wallet-tab-xpub');
    if (walletTabXpubEl) {
      setTruncatedValue(walletTabXpubEl, state.hdRoot.toXpub() || 'N/A');
    }
    // Populate wallet tab PeerID display
    const walletTabPeerIdEl = $('wallet-tab-peerid');
    const peerIdRow = $('ph-portfolio-peerid-row');
    if (walletTabPeerIdEl && peerIdRow) {
      const peerIdStr = deriveAccountPeerId();
      if (peerIdStr) {
        setTruncatedValue(walletTabPeerIdEl, peerIdStr);
        peerIdRow.style.display = '';
      }
    }
    populateAccountAddressDropdown();
    if (xprvEl) {
      xprvEl.textContent = 'Hidden (click reveal)';
      xprvEl.dataset.revealed = 'false';
    }
    if (seedEl) {
      seedEl.textContent = 'Not retained by the app';
      seedEl.dataset.revealed = 'false';
    }

    // Load persisted wallets and active accounts
    state.wallets = loadWallets();
    state.activeAccounts = normalizeActiveAccounts(loadActiveAccounts());
    const currentWallet = getCurrentWallet() || getActiveWallets()[0] || state.wallets[0];
    state.activeWalletId = currentWallet ? currentWallet.id : 0;
    ensureWalletAccounts();
    state.activeAccounts = state.activeAccounts.filter(isSigningAccount);
    saveActiveAccounts();
    saveWallets();
    renderAccountsList();
    renderWalletSelector();
    updateCustomPathDefault();

    // Auto-scan for funded accounts in the background
    scanActiveAccounts().catch(e => console.warn('Auto-scan failed:', e));
  }

  // Derive PKI keys from HD wallet if available
  if (state.hdRoot) {
    generatePKIKeyPairs();
  } else if (state.pki.alice && state.pki.bob) {
    const alicePub = $('alice-public-key');
    const alicePriv = $('alice-private-key');
    const bobPub = $('bob-public-key');
    const bobPriv = $('bob-private-key');
    if (alicePub) alicePub.textContent = toHexCompact(state.pki.alice.publicKey);
    if (alicePriv) alicePriv.textContent = toHexCompact(state.pki.alice.privateKey);
    if (bobPub) bobPub.textContent = toHexCompact(state.pki.bob.publicKey);
    if (bobPriv) bobPriv.textContent = toHexCompact(state.pki.bob.privateKey);

    const algorithmNames = {
      x25519: 'X25519 (Curve25519)',
      secp256k1: 'secp256k1 (Bitcoin)',
      p256: 'P-256 (NIST)',
      p384: 'P-384 (NIST)',
    };
    const algDisplay = $('pki-algorithm-display');
    if (algDisplay) algDisplay.textContent = algorithmNames[state.pki.algorithm] || state.pki.algorithm;
    const loginPrompt = $('pki-login-prompt');
    if (loginPrompt) loginPrompt.style.display = 'none';
    const pkiControls = $('pki-controls');
    if (pkiControls) pkiControls.style.display = 'flex';
    const pkiParties = $('pki-parties');
    if (pkiParties) pkiParties.style.display = 'grid';
    const pkiDemo = $('pki-demo');
    if (pkiDemo) pkiDemo.style.display = 'block';
    const pkiSecurity = $('pki-security');
    if (pkiSecurity) pkiSecurity.style.display = 'block';
    const pkiClearKeys = $('pki-clear-keys');
    if (pkiClearKeys) pkiClearKeys.style.display = 'inline-flex';
  } else {
    // PKI persistence is encrypted and requires the session key (available only after login).
    // Kick off an async load attempt; if it fails, generate fresh keys.
    loadPKIKeys().then((ok) => {
      if (!ok) generatePKIKeyPairs();
    }).catch(() => {
      generatePKIKeyPairs();
    });
  }

  // Update wallet addresses and balances
  updateAdversarialSecurity();

  // Open Account modal so user can see the wallet they just loaded
  if (_openAccountAfterLogin) {
    $('keys-modal')?.classList.add('active');
  }

  // Resolve names and update title
  clearNameCache();
  resolveNames().then(names => updateAccountTitle(names));

  // Start trust auto-scanning
  if (state._startTrustScanning) state._startTrustScanning();
}

function logout() {
  // Stop trust auto-scanning
  if (state._stopTrustScanning) state._stopTrustScanning();

  clearNameCache();
  const titleEl = $('account-title');
  if (titleEl) titleEl.textContent = 'Account';
  state.loggedIn = false;

  // Best-effort wipe of JS buffers (strings are not wipeable).
  const wipe = (u8) => {
    if (u8 instanceof Uint8Array) u8.fill(0);
  };
  try {
    wipe(state.wallet?.x25519?.privateKey);
    wipe(state.wallet?.ed25519?.privateKey);
    wipe(state.wallet?.secp256k1?.privateKey);
    wipe(state.wallet?.p256?.privateKey);
    wipe(state.encryptionKey);
    wipe(state.encryptionIV);
    wipe(state.masterSeed);
    wipe(state.pki?.alice?.privateKey);
    wipe(state.pki?.bob?.privateKey);
    state.hdRoot?.wipe?.();
  } catch {
    // ignore
  }

  state.wallet = { x25519: null, ed25519: null, secp256k1: null, p256: null };
  state.encryptionKey = null;
  state.encryptionIV = null;
  state.masterSeed = null;
  state.hdRoot = null;
  state.mnemonic = null;
  state.externalAccount = null;
  state.addresses = null;

  // Restore the custody controls an external session hid.
  $q('.wallet-selector-row')?.style.removeProperty('display');
  $('wallet-scan-btn')?.style.removeProperty('display');
  $('wallet-send-action')?.style.removeProperty('display');
  $('wallet-export-btn-main')?.style.removeProperty('display');
  $('wallet-advanced-btn-main')?.style.removeProperty('display');
  const extHeaderLabel = $q('.account-address-label');
  if (extHeaderLabel) extHeaderLabel.textContent = 'xpub';
  const extHeaderDisplay = $('account-address-display');
  if (extHeaderDisplay) {
    extHeaderDisplay.textContent = '';
    extHeaderDisplay.title = '';
  }

  localStorage.removeItem(PKI_STORAGE_KEY);

  // Update hero stats
  const heroWalletType = $('hero-wallet-type');
  const heroAddress = $('hero-address');
  const heroStats = $('hero-stats');
  if (heroWalletType) heroWalletType.textContent = '--';
  if (heroAddress) heroAddress.textContent = '--';
  if (heroStats) heroStats.classList.add('hidden');

  // Show login button, hide other nav action buttons
  const navLogin = $('nav-login');
  const navKeys = $('nav-keys');
  const navLogout = $('nav-logout');
  if (navLogin) navLogin.style.display = 'flex';
  if (navKeys) navKeys.style.display = 'none';
  if (navLogout) navLogout.style.display = 'none';

  // Update mobile menu buttons
  const mobileLogin = $('mobile-login');
  const mobileLogout = $('mobile-logout');
  if (mobileLogin) mobileLogin.style.display = 'block';
  if (mobileLogout) mobileLogout.style.display = 'none';

  // Clear form inputs
  const usernameEl = $('wallet-username');
  const passwordEl = $('wallet-password');
  const seedEl = $('seed-phrase');
  if (usernameEl) usernameEl.value = '';
  if (passwordEl) passwordEl.value = '';
  if (seedEl) seedEl.value = '';
  updatePasswordStrength('');

  // Clear HD wallet UI
  const derivedResult = $('derived-result');
  if (derivedResult) derivedResult.style.display = 'none';
}

// =============================================================================
// Export Wallet
// =============================================================================

async function exportWallet(format) {
  if (!state.loggedIn) {
    alert('Please log in first to export wallet data.');
    return;
  }

  let data, filename, mimeType;

  switch (format) {
    case 'mnemonic':
      if (!state.mnemonic) {
        alert('Seed phrase not available. For security, the app does not retain the mnemonic after login.');
        return;
      }
      data = state.mnemonic;
      filename = 'wallet-seed-phrase.txt';
      mimeType = 'text/plain';
      break;

    case 'xpub':
      if (!state.hdRoot?.toXpub) {
        alert('Extended public key not available.');
        return;
      }
      data = state.hdRoot.toXpub();
      filename = 'wallet-xpub.txt';
      mimeType = 'text/plain';
      break;

    case 'xprv':
      if (!state.hdRoot?.toXprv) {
        alert('Extended private key not available.');
        return;
      }
      if (!confirm('Warning: You are about to export your master private key. Anyone with this key can access all your funds. Continue?')) {
        return;
      }
      data = state.hdRoot.toXprv();
      filename = 'wallet-xprv.txt';
      mimeType = 'text/plain';
      break;

    case 'hex':
      if (!state.masterSeed) {
        alert('Master seed not available.');
        return;
      }
      if (!confirm('Warning: You are about to export your raw master seed in hex format. This is extremely sensitive data. Continue?')) {
        return;
      }
      data = toHexCompact(state.masterSeed);
      filename = 'wallet-seed-hex.txt';
      mimeType = 'text/plain';
      break;

    default:
      alert('Unknown export format: ' + format);
      return;
  }

  // Download the file
  downloadData(data, filename, mimeType);
}

function downloadData(data, filename, mimeType) {
  const blob = new Blob([data], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// =============================================================================
// Wallet Address Population & Balance Fetching
// =============================================================================

// Account header — show xpub only
function populateAccountAddressDropdown() {
  const addrEl = $('account-address-display');
  if (!addrEl) return;

  const xpubStr = state.hdRoot ? state.hdRoot.toXpub() : '';
  addrEl.textContent = `${xpubStr.slice(0,10)}...${xpubStr.slice(-10)}`;
  addrEl.title = xpubStr;

  const copyBtn = $('account-address-copy');
  if (copyBtn) {
    copyBtn.onclick = async () => {
      if (xpubStr && await safeCopyText(xpubStr)) {
        copyBtn.title = 'Copied!';
        setTimeout(() => { copyBtn.title = 'Copy xpub'; }, 1500);
      }
    };
  }

  // Populate PeerID row (derived from account-level secp256k1 key)
  const peerIdStr = deriveAccountPeerId();
  const peerIdRow = $('account-peerid-row');
  const peerIdEl = $('account-peerid-display');
  if (peerIdStr && peerIdRow && peerIdEl) {
    peerIdRow.style.display = '';
    peerIdEl.textContent = `${peerIdStr.slice(0,8)}...${peerIdStr.slice(-8)}`;
    peerIdEl.title = peerIdStr;
  }
  const peerCopyBtn = $('account-peerid-copy');
  if (peerCopyBtn) {
    peerCopyBtn.onclick = async () => {
      if (peerIdStr && await safeCopyText(peerIdStr)) {
        peerCopyBtn.title = 'Copied!';
        setTimeout(() => { peerCopyBtn.title = 'Copy PeerID'; }, 1500);
      }
    };
  }
}

function populateWalletAddresses() {
  // External sessions have addresses (the connected account) without custody.
  if (!state.wallet && !state.externalAccount) return;

  const btcAddress = state.addresses?.btc || '--';
  const ethAddress = state.addresses?.eth || '--';
  const solAddress = state.addresses?.sol || '--';

  // let suiAddress = '--';
  // let monadAddress = ethAddress; // Monad uses same address as ETH (same coin type 60)
  // let adaAddress = '--';

  // // Derive SUI and ADA from HD root using their signing paths
  // if (state.hdRoot) {
  //   try {
  //     // SUI: coin type 784, uses ed25519
  //     const suiPath = buildSigningPath(784, 0, 0);
  //     const suiDerived = state.hdRoot.derivePath(suiPath);
  //     const suiPrivKey = suiDerived.privateKey();
  //     const suiPubKey = ed25519.getPublicKey(suiPrivKey);
  //     suiAddress = deriveSuiAddress(suiPubKey, 'ed25519');
  //   } catch (e) {
  //     console.error('Failed to derive SUI address:', e);
  //   }

  //   try {
  //     // ADA: coin type 1815, uses ed25519
  //     const adaPath = buildSigningPath(1815, 0, 0);
  //     const adaDerived = state.hdRoot.derivePath(adaPath);
  //     const adaPrivKey = adaDerived.privateKey();
  //     const adaPubKey = ed25519.getPublicKey(adaPrivKey);
  //     adaAddress = deriveCardanoAddress(adaPubKey);
  //   } catch (e) {
  //     console.error('Failed to derive ADA address:', e);
  //   }
  // }

  const updateAddressCard = (network, address, explorerBase) => {
    const addrEl = $(`wallet-${network}-address`);
    const linkEl = $(`wallet-${network}-explorer`);

    if (addrEl && address !== '--') {
      addrEl.textContent = address.length > 20
        ? address.slice(0, 10) + '...' + address.slice(-8)
        : address;
      addrEl.title = address;
    }

    if (linkEl && address !== '--') {
      linkEl.href = explorerBase + address;
    }
  };

  updateAddressCard('btc', btcAddress, 'https://blockstream.info/address/');
  updateAddressCard('eth', ethAddress, 'https://etherscan.io/address/');
  updateAddressCard('sol', solAddress, 'https://solscan.io/account/');
  // updateAddressCard('sui', suiAddress, 'https://suiscan.xyz/mainnet/account/');
  // updateAddressCard('monad', monadAddress, 'https://monadscan.com/address/');
  // updateAddressCard('ada', adaAddress, 'https://cardanoscan.io/address/');

  // const xrpAddress = state.addresses?.xrp || '--';

  // Also populate bond tab addresses
  const bondAddresses = {
    btc: { addr: btcAddress, explorer: 'https://blockstream.info/address/' },
    eth: { addr: ethAddress, explorer: 'https://etherscan.io/address/' },
    sol: { addr: solAddress, explorer: 'https://solscan.io/account/' },
    // sui: { addr: suiAddress, explorer: 'https://suiscan.xyz/mainnet/account/' },
    // monad: { addr: monadAddress, explorer: 'https://monadscan.com/address/' },
    // ada: { addr: adaAddress, explorer: 'https://cardanoscan.io/address/' },
    // xrp: { addr: xrpAddress, explorer: 'https://xrpscan.com/account/' },
  };

  Object.entries(bondAddresses).forEach(([net, { addr, explorer }]) => {
    const addrEl = $(`bond-${net}-address`);
    const linkEl = $(`bond-${net}-explorer`);
    if (addrEl && addr !== '--') {
      addrEl.textContent = addr.length > 20
        ? addr.slice(0, 10) + '...' + addr.slice(-8)
        : addr;
      addrEl.title = addr;
    }
    if (linkEl && addr !== '--') {
      linkEl.href = explorer + addr;
    }
  });
}

// =============================================================================
// Currency Conversion (Coinbase API)
// =============================================================================

const CURRENCY_SYMBOLS = {
  USD: '$', EUR: '€', GBP: '£', JPY: '¥', CAD: 'C$', AUD: 'A$',
  CHF: 'CHF', CNY: '¥', BTC: '₿',
};

const CURRENCY_OPTIONS = Object.keys(CURRENCY_SYMBOLS);

const PRICE_CACHE_KEY = 'hd-wallet-price-cache-v1';
const PRICE_CACHE_TTL_MS = 60 * 1000;
const PRICE_CACHE_STALE_MS = 30 * 60 * 1000;
let priceCache = { data: null, currency: null, timestamp: 0 };

function loadStoredPriceCache() {
  try {
    const raw = localStorage.getItem(PRICE_CACHE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') return null;
    if (typeof parsed.currency !== 'string' || typeof parsed.timestamp !== 'number') return null;
    if (!parsed.data || typeof parsed.data !== 'object') return null;
    return parsed;
  } catch {
    return null;
  }
}

function saveStoredPriceCache(entry) {
  try {
    localStorage.setItem(PRICE_CACHE_KEY, JSON.stringify(entry));
  } catch (e) {
    console.warn('Failed to save price cache:', e);
  }
}

function getSelectedCurrency() {
  return localStorage.getItem('bond-currency') || 'USD';
}

function setSelectedCurrency(currency) {
  localStorage.setItem('bond-currency', currency);
}

async function fetchCryptoPrices(currency) {
  const now = Date.now();
  if (priceCache.data && priceCache.currency === currency && now - priceCache.timestamp < PRICE_CACHE_TTL_MS) {
    return priceCache.data;
  }

  const stored = loadStoredPriceCache();
  if (stored && stored.currency === currency && now - stored.timestamp < PRICE_CACHE_TTL_MS) {
    priceCache = { data: stored.data, currency: stored.currency, timestamp: stored.timestamp };
    return stored.data;
  }

  const cryptos = ['BTC', 'ETH', 'SOL'];
  const prices = {};
  const setPrice = (symbol, rawValue) => {
    const value = Number.parseFloat(rawValue);
    if (!Number.isFinite(value) || value <= 0) return;
    prices[symbol] = value;
  };

  if (currency === 'BTC') {
    // For BTC denomination, fetch each crypto's price in BTC
    prices.BTC = 1;
    const others = ['ETH', 'SOL'];
    const results = await Promise.allSettled(
      others.map(async (crypto) => {
        const url = apiUrl(`https://api.coinbase.com/v2/exchange-rates?currency=${crypto}`);
        const res = await fetch(url);
        if (!res.ok) throw new Error(`Coinbase HTTP ${res.status}`);
        const json = await res.json();
        return { crypto, rate: json.data?.rates?.BTC };
      })
    );
    results.forEach(r => {
      if (r.status === 'fulfilled') setPrice(r.value.crypto, r.value.rate);
    });
  } else {
    // Fetch fiat spot prices for each supported chain coin.
    const results = await Promise.allSettled(
      cryptos.map(async (crypto) => {
        const url = apiUrl(`https://api.coinbase.com/v2/prices/${crypto}-${currency}/spot`);
        const res = await fetch(url);
        if (!res.ok) throw new Error(`Coinbase HTTP ${res.status}`);
        const json = await res.json();
        return { crypto, price: json.data?.amount };
      })
    );
    results.forEach(r => {
      if (r.status === 'fulfilled') setPrice(r.value.crypto, r.value.price);
    });
  }

  // Secondary provider fallback when Coinbase is unavailable/rate-limited.
  if (Object.keys(prices).length < cryptos.length) {
    const missing = cryptos.filter(symbol => !Number.isFinite(prices[symbol]) || prices[symbol] <= 0);
    if (missing.length > 0) {
      try {
        const vs = currency.toLowerCase();
        const geckoUrl = apiUrl(`https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,solana&vs_currencies=${vs}`);
        const geckoRes = await fetch(geckoUrl);
        if (geckoRes.ok) {
          const gecko = await geckoRes.json();
          const idBySymbol = { BTC: 'bitcoin', ETH: 'ethereum', SOL: 'solana' };
          missing.forEach((symbol) => {
            const id = idBySymbol[symbol];
            if (!id) return;
            setPrice(symbol, gecko?.[id]?.[vs]);
          });
        }
      } catch (e) {
        console.warn('CoinGecko price fallback failed:', e);
      }
    }
  }

  const hasAnyPrice = cryptos.some(symbol => Number.isFinite(prices[symbol]) && prices[symbol] > 0);
  if (!hasAnyPrice) {
    const staleSources = [priceCache, stored].filter(entry =>
      entry?.data
      && entry.currency === currency
      && now - entry.timestamp < PRICE_CACHE_STALE_MS
    );
    if (staleSources.length > 0) {
      const stale = staleSources[0];
      priceCache = { data: stale.data, currency: stale.currency, timestamp: stale.timestamp };
      return stale.data;
    }
    throw new Error(`No ${currency} prices available`);
  }

  priceCache = { data: prices, currency, timestamp: now };
  saveStoredPriceCache(priceCache);
  return prices;
}

function formatCurrencyValue(value, currency) {
  const symbol = CURRENCY_SYMBOLS[currency] || currency;
  if (currency === 'BTC') {
    return `${symbol}${value.toFixed(8)}`;
  }
  if (currency === 'JPY' || currency === 'CNY') {
    return `${symbol}${Math.round(value).toLocaleString()}`;
  }
  return `${symbol}${value.toFixed(2)}`;
}

// =============================================================================
// Name Resolution (ENS, BNS, Solana Names)
// =============================================================================

let nameCache = null;

async function resolveENSName(ethAddress) {
  if (!ethAddress) return null;
  try {
    // ENS reverse resolution: call addr.reverse resolver
    const addr = ethAddress.toLowerCase().slice(2);
    // namehash of <addr>.addr.reverse
    const node = await ensReverseNode(addr);
    // Call the ENS universal resolver
    const data = '0x691f3431' + node.slice(2); // name(bytes32)
    const response = await fetch(apiUrl('https://cloudflare-eth.com'), {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0', id: 1,
        method: 'eth_call',
        params: [{ to: '0xa58E81fe9b61B5c3fE2AFD33CF304c454AbFc7Cb', data }, 'latest'],
      }),
    });
    const json = await response.json();
    if (json.result && json.result !== '0x' && json.result.length > 130) {
      const name = decodeENSName(json.result);
      if (name && name.endsWith('.eth')) return name;
    }
  } catch (e) { console.warn('ENS resolution failed:', e); }
  return null;
}

async function ensReverseNode(addrHex) {
  // namehash for <addr>.addr.reverse
  // Start with namehash('') = 0x0...0
  let node = new Uint8Array(32);
  node = keccak_256(new Uint8Array([...node, ...keccak_256(new TextEncoder().encode('reverse'))]));
  node = keccak_256(new Uint8Array([...node, ...keccak_256(new TextEncoder().encode('addr'))]));
  node = keccak_256(new Uint8Array([...node, ...keccak_256(new TextEncoder().encode(addrHex))]));
  return '0x' + Array.from(node).map(b => b.toString(16).padStart(2, '0')).join('');
}

function decodeENSName(hexResult) {
  try {
    // ABI-decode the string result
    const bytes = hexResult.slice(2);
    const offset = parseInt(bytes.slice(0, 64), 16) * 2;
    const length = parseInt(bytes.slice(offset, offset + 64), 16);
    const nameHex = bytes.slice(offset + 64, offset + 64 + length * 2);
    let name = '';
    for (let i = 0; i < nameHex.length; i += 2) {
      name += String.fromCharCode(parseInt(nameHex.slice(i, i + 2), 16));
    }
    return name;
  } catch { return null; }
}

async function resolveBNSName(btcAddress) {
  if (!btcAddress) return null;
  try {
    const response = await fetch(apiUrl(`https://api.hiro.so/v1/addresses/stacks/${btcAddress}`));
    if (!response.ok) return null;
    const json = await response.json();
    const names = json.names || [];
    if (names.length > 0) return names[0]; // Returns e.g. "alice.btc"
  } catch (e) { console.warn('BNS resolution failed:', e); }
  return null;
}

async function resolveSolanaName(solAddress) {
  if (!solAddress) return null;
  try {
    // Use Solana Name Service reverse lookup via public API
    const response = await fetch(`https://sns-sdk-proxy.bonfida.workers.dev/v2/domain/${solAddress}`);
    if (!response.ok) return null;
    const json = await response.json();
    if (json.result && json.result.length > 0) {
      return json.result[0] + '.sol';
    }
  } catch (e) { console.warn('Solana name resolution failed:', e); }
  return null;
}

async function resolveNames() {
  if (nameCache) return nameCache;

  const btcAddress = state.addresses?.btc;
  const ethAddress = state.addresses?.eth;
  const solAddress = state.addresses?.sol;

  const [bns, ens, sol] = await Promise.allSettled([
    resolveBNSName(btcAddress),
    resolveENSName(ethAddress),
    resolveSolanaName(solAddress),
  ]);

  nameCache = {
    bns: bns.status === 'fulfilled' ? bns.value : null,
    ens: ens.status === 'fulfilled' ? ens.value : null,
    sol: sol.status === 'fulfilled' ? sol.value : null,
  };
  return nameCache;
}

function clearNameCache() {
  nameCache = null;
}

function updateAccountTitle(names) {
  const titleEl = $('account-title');
  if (!titleEl) return;

  const resolved = [];
  if (names.bns) resolved.push({ name: names.bns, service: 'BNS' });
  if (names.ens) resolved.push({ name: names.ens, service: 'ENS' });
  if (names.sol) resolved.push({ name: names.sol, service: 'SOL' });

  if (resolved.length === 0) {
    // Fallback to truncated xpub
    const xpub = state.hdRoot?.toXpub?.() || '';
    titleEl.innerHTML = xpub ? middleTruncate(xpub, 12, 8) : 'Account';
    return;
  }

  titleEl.innerHTML = resolved.map(({ name, service }) =>
    `${name}<sub class="name-service-label">${service}</sub>`
  ).join(' · ');
}

// =============================================================================
// Currency Selector UI
// =============================================================================

function initCurrencySelector() {
  const gearBtn = $('bond-currency-gear');
  const popover = $('bond-currency-popover');
  if (!gearBtn || !popover) return;

  // Populate options
  const current = getSelectedCurrency();
  popover.innerHTML = CURRENCY_OPTIONS.map(c =>
    `<button class="currency-option${c === current ? ' active' : ''}" data-currency="${c}">${CURRENCY_SYMBOLS[c]} ${c}</button>`
  ).join('');

  gearBtn.addEventListener('click', (e) => {
    e.stopPropagation();
    popover.classList.toggle('visible');
  });

  popover.addEventListener('click', async (e) => {
    const btn = e.target.closest('[data-currency]');
    if (!btn) return;
    const currency = btn.dataset.currency;
    setSelectedCurrency(currency);
    popover.querySelectorAll('.currency-option').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    popover.classList.remove('visible');
    priceCache = { data: null, currency: null, timestamp: 0 }; // invalidate
    await updateAdversarialSecurity();
  });

  // Close popover on outside click
  document.addEventListener('click', () => popover.classList.remove('visible'));
}

// =============================================================================
// Adversarial Security / Bond Balances
// =============================================================================

async function updateAdversarialSecurity() {
  const hasWallet = state.wallet && (state.wallet.secp256k1 || state.wallet.ed25519);
  if (!hasWallet) return;

  // Wallet tab bond total is now updated by scanActiveAccounts/updateWalletBondTotal
  updateWalletBondTotal();
}

// =============================================================================
// vCard Generation
// =============================================================================

function generateVCard(info, { skipPhoto = false } = {}) {
  const person = { KEY: [] };

  if (info.firstName || info.lastName) {
    if (info.lastName) person.FAMILY_NAME = info.lastName;
    if (info.firstName) person.GIVEN_NAME = info.firstName;
    if (info.middleName) person.ADDITIONAL_NAME = info.middleName;
    if (info.prefix) person.HONORIFIC_PREFIX = info.prefix;
    if (info.suffix) person.HONORIFIC_SUFFIX = info.suffix;
  }

  const contacts = [];
  if (info.email) {
    contacts.push({ EMAIL: info.email, CONTACT_TYPE: 'HOME' });
  }
  if (info.phone) {
    contacts.push({ TELEPHONE: info.phone, CONTACT_TYPE: 'CELL' });
  }
  if (contacts.length) {
    person.CONTACT_POINT = contacts;
  }

  if (info.org) {
    person.AFFILIATION = { LEGAL_NAME: info.org };
  }

  if (info.title) {
    person.HAS_OCCUPATION = { NAME: info.title };
  }

  if (!skipPhoto && state.vcardPhoto) {
    person.IMAGE = state.vcardPhoto;
  }

  if (info.includeKeys && state.wallet?.x25519) {
    person.KEY = [
      // Always include xPub
      ...(state.hdRoot?.toXpub ? [{
        XPUB: state.hdRoot.toXpub(),
        LABEL: '',
      }] : []),
      // X25519 encryption key
      {
        PUBLIC_KEY: toBase64(state.wallet.x25519.publicKey),
        LABEL: 'X25519',
      },
      // Active accounts from wallet scan
      ...state.activeAccounts
        .filter(a => a.active && isSigningAccount(a))
        .flatMap(a => {
          const entries = [];
          const pathLabel = a.path || `m/44'/${a.coinType}'/${a.account}'/0/${a.index}`;
          try {
            const { publicKey } = deriveAddressForPath(a.coinType, a.account, a.index);
            const curve = a.coinType === 501 ? 'Ed25519' : 'secp256k1';
            entries.push({
              PUBLIC_KEY: toBase64(publicKey),
              LABEL: `${curve} ${pathLabel}`,
            });
          } catch {}
          if (a.address) {
            entries.push({
              KEY_ADDRESS: a.address,
              LABEL: pathLabel,
            });
          }
          return entries;
        }),
    ];
  } else if (info.xpubOnly && state.hdRoot?.toXpub) {
    person.KEY = [{ XPUB: state.hdRoot.toXpub(), LABEL: '' }];
  }

  const note = info.includeKeys
    ? 'Generated by Space Data Network'
    : undefined;

  let vcard = createV3(person, note);

  // Add NICKNAME field (not supported by createV3)
  if (info.nickname) {
    vcard = vcard.replace('END:VCARD', `NICKNAME:${info.nickname}\nEND:VCARD`);
  }


  // Convert PHOTO from data URI format to iOS-compatible inline base64 format
  vcard = vcard.replace(
    /PHOTO;VALUE=URI:data:image\/(\w+);base64,([^\n]+)\n/,
    (_, type, b64) => {
      const vcardType = type.toUpperCase();
      let folded = `PHOTO;ENCODING=b;TYPE=${vcardType}:`;
      for (let i = 0; i < b64.length; i += 74) {
        folded += '\n ' + b64.slice(i, i + 74);
      }
      return folded + '\n';
    }
  );

  return vcard;
}

// =============================================================================
// vCard Digital Signature (Ed25519)
// =============================================================================

function getSignableBody(vcardText) {
  const lines = vcardText.split('\n');
  const sigItems = new Set();
  for (const line of lines) {
    const m = line.match(/^item(\d+)\.X-ABLabel:Digital Signature/);
    if (m) sigItems.add(m[1]);
  }
  return lines.filter(line => {
    if (line.trim() === 'END:VCARD') return false;
    for (const n of sigItems) {
      if (line.startsWith(`item${n}.`)) return false;
    }
    return true;
  }).join('\n') + '\n';
}

function signVCard(vcardText) {
  if (!state.wallet?.ed25519?.privateKey) return vcardText;

  const body = getSignableBody(vcardText);
  const messageBytes = new TextEncoder().encode(body);
  const signature = hdWallet().curves.ed25519.sign(messageBytes, state.wallet.ed25519.privateKey);
  const sigB64 = toBase64(signature);

  // Encode signature + derivation path (coinType=501, account=0, index=0)
  const sigValue = `${sigB64}:501:0:0`;

  // Find highest itemN and key index
  let maxItem = 0;
  let maxKeyIdx = 0;
  const itemRe = /item(\d+)\./g;
  const keyIdxRe = /#(\d+)/g;
  let match;
  while ((match = itemRe.exec(vcardText)) !== null) {
    maxItem = Math.max(maxItem, parseInt(match[1], 10));
  }
  while ((match = keyIdxRe.exec(vcardText)) !== null) {
    maxKeyIdx = Math.max(maxKeyIdx, parseInt(match[1], 10));
  }

  const sigLines =
    `item${maxItem + 1}.X-ABLabel:Digital Signature #${maxKeyIdx + 1}\n` +
    `item${maxItem + 1}.X-ABRELATEDNAMES:${sigValue}\n`;

  return body + sigLines + 'END:VCARD';
}

function verifyVCardSignature(vcardText) {
  // Parse all itemN label/value pairs
  const lines = vcardText.split('\n');
  const items = {};
  for (const line of lines) {
    const labelMatch = line.match(/^item(\d+)\.X-ABLabel:(.+)/);
    if (labelMatch) {
      items[labelMatch[1]] = items[labelMatch[1]] || {};
      items[labelMatch[1]].label = labelMatch[2].trim();
    }
    const valueMatch = line.match(/^item(\d+)\.X-ABRELATEDNAMES:(.+)/);
    if (valueMatch) {
      items[valueMatch[1]] = items[valueMatch[1]] || {};
      items[valueMatch[1]].value = valueMatch[2].trim();
    }
  }

  // Find Digital Signature entry
  let sigValue = null;
  for (const item of Object.values(items)) {
    if (item.label?.startsWith('Digital Signature') && item.value) {
      sigValue = item.value;
    }
  }

  if (!sigValue) {
    return { verified: false, path: null, publicKey: null, error: 'unsigned' };
  }

  // Parse signature value: base64sig:coinType:account:index
  const parts = sigValue.split(':');
  if (parts.length < 4) {
    return { verified: false, path: null, publicKey: null, error: 'Malformed signature' };
  }
  const sigB64 = parts[0];
  const coinType = parts[1];
  const account = parts[2];
  const index = parts[3];
  const path = `m/44'/${coinType}'/${account}'/0/${index}`;

  // Find Ed25519 public key — look for "Public Key" entries with 32-byte (44-char base64) values
  let ed25519PubB64 = null;
  for (const item of Object.values(items)) {
    if (item.label?.startsWith('Public Key') && item.value) {
      try {
        const decoded = Uint8Array.from(atob(item.value), c => c.charCodeAt(0));
        if (decoded.length === 32) {
          ed25519PubB64 = item.value;
          break;
        }
      } catch { /* not base64 */ }
    }
  }

  if (!ed25519PubB64) {
    return { verified: false, path, publicKey: null, error: 'No Ed25519 public key found' };
  }

  // Reconstruct signable body and verify
  const body = getSignableBody(vcardText);
  const messageBytes = new TextEncoder().encode(body);
  const sigBytes = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
  const pubKeyBytes = Uint8Array.from(atob(ed25519PubB64), c => c.charCodeAt(0));

  try {
    const valid = hdWallet().curves.ed25519.verify(messageBytes, sigBytes, pubKeyBytes);
    return { verified: valid, path, publicKey: ed25519PubB64, error: valid ? null : 'Signature invalid' };
  } catch (e) {
    return { verified: false, path, publicKey: ed25519PubB64, error: e.message };
  }
}

function hideImportedVcardPreview() {
  state.importedVcardPreview = null;
  const resultEl = $('vcf-import-result');
  const fieldsEl = $('vcf-import-fields');
  const sigStatus = $('vcf-import-sig-status');
  if (fieldsEl) fieldsEl.innerHTML = '';
  if (sigStatus) {
    sigStatus.innerHTML = '';
    sigStatus.style.display = 'none';
  }
  if (resultEl) resultEl.style.display = 'none';
}

function applyImportedVcardPreview() {
  const imported = state.importedVcardPreview;
  if (!imported) return;

  for (const id of vcardFieldIds) {
    const el = $(id);
    if (el) el.value = imported.formValues[id] || '';
  }

  state.vcardPhoto = imported.photo || null;
  if (imported.photo) {
    showPhotoPreview(imported.photo);
  } else {
    resetPhotoPreview();
  }

  saveVcardIdentity();
  updateIdentityCardSummary();
  setPhotoActionsVisible(false);
  $('vcard-edit-view').style.display = 'none';
  $('vcard-form-view').style.display = '';
  hideImportedVcardPreview();
}

function parseAndDisplayVCF(vcfText) {
  const lines = vcfText.replace(/\r?\n /g, '').split(/\r?\n/);
  const fields = {};
  const keys = [];
  let photo = null;
  const formValues = Object.fromEntries(vcardFieldIds.map(id => [id, '']));

  for (const line of lines) {
    const colonIdx = line.indexOf(':');
    if (colonIdx === -1) continue;
    const prop = line.substring(0, colonIdx).toUpperCase();
    const value = line.substring(colonIdx + 1);

    if (prop === 'FN') {
      fields.name = value;
    } else if (prop === 'N') {
      const parts = value.split(';');
      formValues['vcard-lastname'] = parts[0] || '';
      formValues['vcard-firstname'] = parts[1] || '';
      formValues['vcard-middlename'] = parts[2] || '';
      formValues['vcard-prefix'] = parts[3] || '';
      formValues['vcard-suffix'] = parts[4] || '';
      if (!fields.name) {
        fields.name = [parts[3], parts[1], parts[2], parts[0], parts[4]].filter(Boolean).join(' ');
      }
    } else if (prop === 'NICKNAME') {
      formValues['vcard-nickname'] = value;
    } else if (prop.startsWith('EMAIL')) {
      formValues['vcard-email'] ||= value;
      fields.email = value;
    } else if (prop.startsWith('ORG')) {
      const normalized = value.replace(/;/g, ', ');
      formValues['vcard-org'] ||= normalized;
      fields.org = normalized;
    } else if (prop.startsWith('TITLE')) {
      formValues['vcard-title'] ||= value;
      fields.title = value;
    } else if (prop.startsWith('TEL')) {
      formValues['vcard-phone'] ||= value;
      fields.tel = value;
    } else if (prop.startsWith('ADR')) {
      const parts = value.split(';');
      formValues['vcard-street'] ||= [parts[1], parts[2]].filter(Boolean).join(' ');
      formValues['vcard-city'] ||= parts[3] || '';
      formValues['vcard-region'] ||= parts[4] || '';
      formValues['vcard-postal'] ||= parts[5] || '';
      formValues['vcard-country'] ||= parts[6] || '';
    } else if (prop.startsWith('PHOTO')) {
      if (prop.includes('VALUE=URI') || value.startsWith('data:') || value.startsWith('http')) {
        photo = value;
      } else if (prop.includes('ENCODING=B') || prop.includes('ENCODING=b')) {
        const typeMatch = prop.match(/TYPE=(\w+)/i);
        const imgType = typeMatch ? typeMatch[1].toLowerCase() : 'jpeg';
        photo = `data:image/${imgType};base64,${value}`;
      }
    } else if (prop.startsWith('KEY')) {
      const typeMatch = prop.match(/TYPE=(\w+)/i);
      keys.push({ type: typeMatch ? typeMatch[1] : 'Unknown', value });
    } else if (prop.startsWith('X-CRYPTO-KEY') || prop.startsWith('X-KEY')) {
      keys.push({ type: prop.split(';')[0], value });
    }
  }

  if (!formValues['vcard-firstname'] && !formValues['vcard-lastname'] && fields.name) {
    formValues['vcard-firstname'] = fields.name;
  }

  const resultEl = $('vcf-import-result');
  const photoEl = $('vcf-import-photo');
  const fieldsEl = $('vcf-import-fields');
  if (!resultEl || !fieldsEl) return;

  if (photoEl) {
    const fallbackSvg = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:32px;height:32px;opacity:0.3">
          <path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/>
        </svg>`;
    if (photo) {
      photoEl.innerHTML = `<img src="${photo}" alt="Contact photo">`;
      const img = photoEl.querySelector('img');
      if (img) img.onerror = () => { photoEl.innerHTML = fallbackSvg; };
    } else {
      photoEl.innerHTML = fallbackSvg;
    }
  }

  let html = '';
  const fieldMap = [
    ['Name', fields.name],
    ['Email', fields.email],
    ['Org', fields.org],
    ['Title', fields.title],
    ['Phone', fields.tel],
  ];
  for (const [label, val] of fieldMap) {
    if (val) {
      html += `<div class="vcf-import-field">
        <span class="vcf-import-field-label">${label}</span>
        <span class="vcf-import-field-value">${val}</span>
      </div>`;
    }
  }

  if (keys.length > 0) {
    html += '<div class="vcf-import-keys">';
    for (const k of keys) {
      html += `<div class="vcf-import-key"><strong>${k.type}:</strong> <code>${k.value}</code></div>`;
    }
    html += '</div>';
  }

  // Verify digital signature
  const sigStatus = $('vcf-import-sig-status');
  if (sigStatus) {
    const result = verifyVCardSignature(vcfText);
    if (result.error === 'unsigned') {
      sigStatus.className = 'vcard-sig-badge sig-unsigned';
      sigStatus.innerHTML = 'No signature';
    } else if (result.verified) {
      sigStatus.className = 'vcard-sig-badge sig-verified';
      sigStatus.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg> Verified (${result.path})`;
    } else {
      sigStatus.className = 'vcard-sig-badge sig-invalid';
      sigStatus.innerHTML = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/></svg> Invalid signature`;
    }
    sigStatus.style.display = 'flex';
  }

  state.importedVcardPreview = {
    formValues,
    photo,
  };

  fieldsEl.innerHTML = html;
  resultEl.style.display = 'block';
}

// =============================================================================
// Grid Canvas Animation
// =============================================================================

function initGridAnimation() {
  const canvas = $('grid-canvas') || document.getElementById('grid-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  const gridSize = 40;
  const dotRadius = 1.5;

  const travelers = [];
  const maxTravelers = 30;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  function createTraveler() {
    const horizontal = Math.random() > 0.5;
    const value = Math.floor(Math.random() * 256).toString(16).padStart(2, '0').toUpperCase();

    if (horizontal) {
      const row = Math.floor(Math.random() * (canvas.height / gridSize)) * gridSize;
      return {
        x: Math.random() > 0.5 ? -20 : canvas.width + 20,
        y: row,
        dx: (Math.random() > 0.5 ? 1 : -1) * (0.3 + Math.random() * 0.4),
        dy: 0,
        value,
        opacity: 0.3 + Math.random() * 0.4
      };
    } else {
      const col = Math.floor(Math.random() * (canvas.width / gridSize)) * gridSize;
      return {
        x: col,
        y: Math.random() > 0.5 ? -20 : canvas.height + 20,
        dx: 0,
        dy: (Math.random() > 0.5 ? 1 : -1) * (0.3 + Math.random() * 0.4),
        value,
        opacity: 0.3 + Math.random() * 0.4
      };
    }
  }

  for (let i = 0; i < maxTravelers; i++) {
    travelers.push(createTraveler());
  }

  function draw() {
    ctx.clearRect(0, 0, canvas.width, canvas.height);

    ctx.fillStyle = 'rgba(255, 255, 255, 0.15)';
    for (let x = 0; x <= canvas.width; x += gridSize) {
      for (let y = 0; y <= canvas.height; y += gridSize) {
        ctx.beginPath();
        ctx.arc(x, y, dotRadius, 0, Math.PI * 2);
        ctx.fill();
      }
    }

    ctx.font = '10px monospace';
    for (let i = 0; i < travelers.length; i++) {
      const t = travelers[i];

      t.x += t.dx;
      t.y += t.dy;

      if (t.x < -30 || t.x > canvas.width + 30 || t.y < -30 || t.y > canvas.height + 30) {
        travelers[i] = createTraveler();
        continue;
      }

      ctx.fillStyle = `rgba(100, 200, 255, ${t.opacity})`;
      ctx.fillText(t.value, t.x - 6, t.y + 3);
    }

    requestAnimationFrame(draw);
  }

  draw();
}

// =============================================================================
// WebAuthn / Passkey Helpers
// =============================================================================

function isPasskeySupported() {
  return window.PublicKeyCredential !== undefined &&
    typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function';
}

// =============================================================================
// Login Handler Setup
// =============================================================================

// Track selected remember method (pin or passkey) for each login type
const rememberMethod = {
  password: 'passkey',
  seed: 'passkey'
};

function setupLoginHandlers() {
  // External wallet — the FIRST sign-in method. The panel is the shared
  // hd-wallet-ui/external component; it discovers injected wallets
  // (EIP-6963 / Wallet Standard) and connects. A successful connect opens
  // the SAME account interface an HD login does (bond, balances, trust),
  // driven by the connected address — never touching HD custody state
  // (state.hdRoot stays null; nav logout ends the session).
  const externalMount = $('external-wallet-mount');
  if (externalMount && !externalMount.childElementCount) {
    createExternalWalletPanel({
      mount: externalMount,
      onConnected: (account) => {
        loginExternal(account).catch((e) => console.warn('External sign-in failed:', e));
      },
    });
  }

  // Migrate from old storage format if needed
  WalletStorage.migrateStorage();

  // Check for stored wallet using module
  const storageMetadata = WalletStorage.getStorageMetadata();
  const storageMethod = storageMetadata?.method || StorageMethod.NONE;

  if (storageMethod !== StorageMethod.NONE) {
    const storedTab = $('stored-tab');
    if (storedTab) storedTab.style.display = '';

    const dateEl = $('stored-wallet-date');
    if (dateEl && storageMetadata?.date) {
      dateEl.textContent = `Saved on ${storageMetadata.date}`;
    }

    const pinSection = $('stored-pin-section');
    const passkeySection = $('stored-passkey-section');
    const divider = $('stored-divider');

    if (divider) divider.style.display = 'none';

    if (storageMethod === StorageMethod.PIN) {
      if (pinSection) pinSection.style.display = 'block';
      if (passkeySection) passkeySection.style.display = 'none';
    } else if (storageMethod === StorageMethod.PASSKEY) {
      if (pinSection) pinSection.style.display = 'none';
      if (passkeySection) passkeySection.style.display = 'block';
    }

    // Pre-select stored tab (but don't open modal automatically)
    $qa('.method-tab').forEach(t => t.classList.remove('active'));
    $qa('.method-content').forEach(c => c.classList.remove('active'));
    if (storedTab) storedTab.classList.add('active');
    const storedMethod = $('stored-method');
    if (storedMethod) storedMethod.classList.add('active');
  }

  // Hide passkey buttons if not supported
  if (!isPasskeySupported()) {
    const ppBtn = $('passkey-btn-password');
    if (ppBtn) ppBtn.style.display = 'none';
    const psBtn = $('passkey-btn-seed');
    if (psBtn) psBtn.style.display = 'none';
  }

  // Method tab switching
  $qa('.method-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $qa('.method-tab').forEach(t => t.classList.remove('active'));
      $qa('.method-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      const methodEl = $(`${tab.dataset.method}-method`);
      if (methodEl) methodEl.classList.add('active');
    });
  });

  // Remember method selector (PIN vs Passkey)
  $qa('.remember-method-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.target;
      const method = btn.dataset.method;
      rememberMethod[target] = method;

      $qa(`.remember-method-btn[data-target="${target}"]`).forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const pinGroup = $(`pin-group-${target}`);
      const passkeyInfo = $(`passkey-info-${target}`);
      if (pinGroup) pinGroup.style.display = method === 'pin' ? 'block' : 'none';
      if (passkeyInfo) passkeyInfo.style.display = method === 'passkey' ? 'flex' : 'none';
    });
  });

  // Remember wallet checkbox handlers
  $('remember-wallet-password')?.addEventListener('change', (e) => {
    const opts = $('remember-options-password');
    if (opts) opts.style.display = e.target.checked ? 'block' : 'none';
    if (e.target.checked && rememberMethod.password === 'pin') {
      $('pin-input-password')?.focus();
    }
  });

  $('remember-wallet-seed')?.addEventListener('change', (e) => {
    const opts = $('remember-options-seed');
    if (opts) opts.style.display = e.target.checked ? 'block' : 'none';
    if (e.target.checked && rememberMethod.seed === 'pin') {
      $('pin-input-seed')?.focus();
    }
  });

  // PIN input validation
  ['pin-input-password', 'pin-input-seed', 'pin-input-unlock'].forEach(id => {
    $(id)?.addEventListener('input', (e) => {
      e.target.value = e.target.value.replace(/\D/g, '').slice(0, 6);
      if (id === 'pin-input-unlock') {
        const unlockBtn = $('unlock-stored-wallet');
        if (unlockBtn) unlockBtn.disabled = e.target.value.length !== 6;
      }
    });
  });

  // Password input handler
  $('wallet-password')?.addEventListener('input', (e) => {
    updatePasswordStrength(e.target.value);
  });

  // Password show/hide toggle
  $('toggle-password-vis')?.addEventListener('click', () => {
    const pw = $('wallet-password');
    const btn = $('toggle-password-vis');
    if (!pw || !btn) return;
    const showing = pw.type === 'text';
    pw.type = showing ? 'password' : 'text';
    btn.querySelector('.eye-open').style.display = showing ? '' : 'none';
    btn.querySelector('.eye-closed').style.display = showing ? 'none' : '';
    btn.title = showing ? 'Show password' : 'Hide password';
    pw.focus();
  });

  $('wallet-username')?.addEventListener('input', () => {
    const pw = $('wallet-password');
    if (pw) updatePasswordStrength(pw.value);
  });

  // Derive from password button
  $('derive-from-password')?.addEventListener('click', async () => {
    const username = $('wallet-username')?.value;
    const password = $('wallet-password')?.value;
    const rememberWallet = $('remember-wallet-password')?.checked;
    const usePasskey = rememberMethod.password === 'passkey';
    const pin = $('pin-input-password')?.value;

    if (!username || !password || password.length < 24) {
      return;
    }

    if (rememberWallet && !usePasskey && (!pin || pin.length !== 6)) {
      alert('Please enter a 6-digit PIN to store your wallet');
      return;
    }

    const btn = $('derive-from-password');
    btn.disabled = true;
    btn.textContent = 'Logging in...';

    try {
      const keys = await deriveKeysFromPassword(username, password);

      // Best-effort: don't keep the password in the input field after login.
      const pwEl = $('wallet-password');
      if (pwEl) pwEl.value = '';

      if (rememberWallet) {
        const walletData = {
          type: 'masterSeed',
          source: 'password',
          username,
          masterSeed: Array.from(state.masterSeed),
        };

        if (usePasskey) {
          await WalletStorage.storeWithPasskey(walletData, {
            rpName: 'HD Wallet',
            userName: username,
            userDisplayName: username
          });
          const pinSect = $('stored-pin-section');
          if (pinSect) pinSect.style.display = 'none';
          const psSect = $('stored-passkey-section');
          if (psSect) psSect.style.display = 'block';
        } else {
          await WalletStorage.storeWithPIN(pin, walletData);
          const pinSect = $('stored-pin-section');
          if (pinSect) pinSect.style.display = 'block';
          const psSect = $('stored-passkey-section');
          if (psSect) psSect.style.display = 'none';
        }
        const storedTab = $('stored-tab');
        if (storedTab) storedTab.style.display = '';
        const divider = $('stored-divider');
        if (divider) divider.style.display = 'none';
        const dateEl = $('stored-wallet-date');
        if (dateEl) dateEl.textContent = `Saved on ${new Date().toLocaleDateString()}`;
      }

      login(keys);
    } catch (err) {
      console.error('Login error:', err);
      alert('Error: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Login';
    }
  });

  // Generate seed phrase button
  $('generate-seed')?.addEventListener('click', () => {
    const seedEl = $('seed-phrase');
    if (seedEl) seedEl.value = generateSeedPhrase();
    const deriveBtn = $('derive-from-seed');
    if (deriveBtn) deriveBtn.disabled = false;
  });

  // Validate seed phrase button
  $('validate-seed')?.addEventListener('click', () => {
    const seedEl = $('seed-phrase');
    const valid = validateSeedPhrase(seedEl?.value || '');
    if (valid) {
      alert('Valid BIP39 seed phrase!');
      const deriveBtn = $('derive-from-seed');
      if (deriveBtn) deriveBtn.disabled = false;
    } else {
      alert('Invalid seed phrase');
      const deriveBtn = $('derive-from-seed');
      if (deriveBtn) deriveBtn.disabled = true;
    }
  });

  // Seed phrase input validation
  $('seed-phrase')?.addEventListener('input', () => {
    const phrase = $('seed-phrase')?.value.trim();
    const deriveBtn = $('derive-from-seed');
    if (phrase && phrase.split(/\s+/).length >= 12) {
      if (deriveBtn) deriveBtn.disabled = !validateSeedPhrase(phrase);
    } else {
      if (deriveBtn) deriveBtn.disabled = true;
    }
  });

  // Derive from seed button
  $('derive-from-seed')?.addEventListener('click', async () => {
    const phrase = $('seed-phrase')?.value;
    if (!phrase || !validateSeedPhrase(phrase)) return;

    const rememberWallet = $('remember-wallet-seed')?.checked;
    const usePasskey = rememberMethod.seed === 'passkey';
    const pin = $('pin-input-seed')?.value;

    if (rememberWallet && !usePasskey && (!pin || pin.length !== 6)) {
      alert('Please enter a 6-digit PIN to store your wallet');
      return;
    }

    const btn = $('derive-from-seed');
    btn.disabled = true;
    btn.textContent = 'Logging in...';

    try {
      const keys = await deriveKeysFromSeed(phrase);

      // Best-effort: don't keep the mnemonic in the textarea after login.
      const seedEl = $('seed-phrase');
      if (seedEl) seedEl.value = '';

      if (rememberWallet) {
        const walletData = {
          type: 'masterSeed',
          source: 'seed',
          masterSeed: Array.from(state.masterSeed),
        };

        if (usePasskey) {
          await WalletStorage.storeWithPasskey(walletData, {
            rpName: 'HD Wallet',
            userName: 'seed-wallet',
            userDisplayName: 'Seed Phrase Wallet'
          });
          const pinSect = $('stored-pin-section');
          if (pinSect) pinSect.style.display = 'none';
          const psSect = $('stored-passkey-section');
          if (psSect) psSect.style.display = 'block';
        } else {
          await WalletStorage.storeWithPIN(pin, walletData);
          const pinSect = $('stored-pin-section');
          if (pinSect) pinSect.style.display = 'block';
          const psSect = $('stored-passkey-section');
          if (psSect) psSect.style.display = 'none';
        }
        const storedTab = $('stored-tab');
        if (storedTab) storedTab.style.display = '';
        const divider = $('stored-divider');
        if (divider) divider.style.display = 'none';
        const dateEl = $('stored-wallet-date');
        if (dateEl) dateEl.textContent = `Saved on ${new Date().toLocaleDateString()}`;
      }

      login(keys);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Login';
    }
  });

  // Unlock stored wallet with PIN
  $('unlock-stored-wallet')?.addEventListener('click', async () => {
    const pin = $('pin-input-unlock')?.value;
    if (!pin || pin.length !== 6) {
      alert('Please enter a 6-digit PIN');
      return;
    }

    const btn = $('unlock-stored-wallet');
    btn.disabled = true;
    btn.textContent = 'Unlocking...';

    try {
      const walletData = await WalletStorage.retrieveWithPIN(pin);

      let keys;
      const storedSeed = walletData.masterSeed || walletData.seed || walletData.hdSeed;
      if (storedSeed) {
        keys = await deriveKeysFromMasterSeed(new Uint8Array(storedSeed));
      } else if (walletData.type === 'password') {
        // Legacy format: stored password/seedPhrase (deprecated). Unlock, then upgrade storage.
        keys = await deriveKeysFromPassword(walletData.username, walletData.password);
        await WalletStorage.storeWithPIN(pin, {
          type: 'masterSeed',
          source: 'password',
          username: walletData.username,
          masterSeed: Array.from(state.masterSeed),
        });
      } else if (walletData.type === 'seed') {
        keys = await deriveKeysFromSeed(walletData.seedPhrase);
        await WalletStorage.storeWithPIN(pin, {
          type: 'masterSeed',
          source: 'seed',
          masterSeed: Array.from(state.masterSeed),
        });
      } else {
        throw new Error('Unknown stored wallet format');
      }

      login(keys);
    } catch (err) {
      alert('Error: ' + err.message);
      const pinInput = $('pin-input-unlock');
      if (pinInput) pinInput.value = '';
    } finally {
      btn.disabled = false;
      btn.textContent = 'Unlock with PIN';
    }
  });

  // Unlock stored wallet with Passkey
  $('unlock-with-passkey')?.addEventListener('click', async () => {
    const btn = $('unlock-with-passkey');
    btn.disabled = true;
    btn.innerHTML = 'Authenticating...';

    try {
      const walletData = await WalletStorage.retrieveWithPasskey();

      let keys;
      const storedSeed = walletData.masterSeed || walletData.seed || walletData.hdSeed;
      if (storedSeed) {
        keys = await deriveKeysFromMasterSeed(new Uint8Array(storedSeed));
      } else if (walletData.type === 'password') {
        keys = await deriveKeysFromPassword(walletData.username, walletData.password);
        await WalletStorage.storeWithPasskey({
          type: 'masterSeed',
          source: 'password',
          username: walletData.username,
          masterSeed: Array.from(state.masterSeed),
        }, {
          rpName: 'HD Wallet',
          userName: walletData.username || 'wallet-user',
          userDisplayName: walletData.username || 'Wallet User'
        });
      } else if (walletData.type === 'seed') {
        keys = await deriveKeysFromSeed(walletData.seedPhrase);
        await WalletStorage.storeWithPasskey({
          type: 'masterSeed',
          source: 'seed',
          masterSeed: Array.from(state.masterSeed),
        }, {
          rpName: 'HD Wallet',
          userName: 'seed-wallet',
          userDisplayName: 'Seed Phrase Wallet'
        });
      } else {
        throw new Error('Unknown stored wallet format');
      }

      login(keys);
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      btn.disabled = false;
      btn.innerHTML = 'Unlock with Passkey';
    }
  });

  // Forget stored wallet
  $('forget-stored-wallet')?.addEventListener('click', () => {
    if (confirm('Are you sure you want to forget your stored wallet? You will need to enter your password or seed phrase again.')) {
      WalletStorage.clearStorage();
      const storedTab = $('stored-tab');
      if (storedTab) storedTab.style.display = 'none';
      const pinSect = $('stored-pin-section');
      if (pinSect) pinSect.style.display = 'block';
      const psSect = $('stored-passkey-section');
      if (psSect) psSect.style.display = 'none';
      const divider = $('stored-divider');
      if (divider) divider.style.display = 'none';
      // Switch to password tab
      $qa('.method-tab').forEach(t => t.classList.remove('active'));
      $qa('.method-content').forEach(c => c.classList.remove('active'));
      const pwMethod = $('password-method');
      if (pwMethod) pwMethod.classList.add('active');
      const pwTab = $q('.method-tab[data-method="password"]');
      if (pwTab) pwTab.classList.add('active');
    }
  });
}

// =============================================================================
// Main App UI Handlers
// =============================================================================

function setupMainAppHandlers() {
  // Nav actions
  $('nav-login')?.addEventListener('click', () => {
    $('login-modal')?.classList.add('active');
  });
  $('hero-login')?.addEventListener('click', () => {
    $('login-modal')?.classList.add('active');
  });
  $('nav-logout')?.addEventListener('click', logout);
  $('nav-keys')?.addEventListener('click', async () => {
    $('keys-modal')?.classList.add('active');
    if (state.loggedIn) {
      const names = await resolveNames();
      updateAccountTitle(names);
    }
  });

  // Modal close handlers
  $qa('.modal').forEach(modal => {
    modal.addEventListener('click', (e) => {
      if (e.target === modal || e.target.classList.contains('modal-close')) {
        modal.classList.remove('active');
      }
    });
  });

  // Account modal tab switching
  $qa('.modal-tab[data-modal-tab]').forEach(tab => {
    tab.addEventListener('click', () => {
      $qa('.modal-tab[data-modal-tab]').forEach(t => t.classList.remove('active'));
      $qa('.modal-tab-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      const target = $(tab.dataset.modalTab);
      if (target) target.classList.add('active');
    });
  });

  // Messaging sub-tab switching
  $qa('.messaging-sub-tab').forEach(tab => {
    tab.addEventListener('click', () => {
      $qa('.messaging-sub-tab').forEach(t => t.classList.remove('active'));
      $qa('.messaging-sub-content').forEach(c => c.classList.remove('active'));
      tab.classList.add('active');
      const target = $(tab.dataset.messagingSub);
      if (target) target.classList.add('active');
    });
  });

  // Identity card summary — updates the read-only card display from form fields
  function updateIdentityCardSummary() {
    const prefix = $('vcard-prefix')?.value || '';
    const first = $('vcard-firstname')?.value || '';
    const middle = $('vcard-middlename')?.value || '';
    const last = $('vcard-lastname')?.value || '';
    const suffix = $('vcard-suffix')?.value || '';
    const nick = $('vcard-nickname')?.value || '';
    const parts = [prefix, first, middle, last, suffix].filter(Boolean);
    const nameEl = $('identity-card-name');
    if (nameEl) {
      const namePart = parts.length > 0 ? parts.join(' ') : '--';
      if (nick) {
        nameEl.innerHTML = `${namePart} <span class="nickname">(${nick})</span>`;
      } else {
        nameEl.textContent = namePart;
      }
    }

    const titleEl = $('identity-card-title');
    if (titleEl) titleEl.textContent = $('vcard-title')?.value || '';

    const orgEl = $('identity-card-org');
    if (orgEl) orgEl.textContent = $('vcard-org')?.value || '';

    const emailEl = $('identity-card-email');
    if (emailEl) emailEl.textContent = $('vcard-email')?.value || '';

    const phoneEl = $('identity-card-phone');
    if (phoneEl) phoneEl.textContent = $('vcard-phone')?.value || '';
  }


  // vCard identity auto-save
  const VCARD_STORAGE_KEY = 'hd-wallet-vcard-identity';
  const vcardFieldIds = [
    'vcard-prefix', 'vcard-firstname', 'vcard-middlename', 'vcard-lastname',
    'vcard-suffix', 'vcard-nickname', 'vcard-email', 'vcard-phone', 'vcard-org', 'vcard-title',
    'vcard-street', 'vcard-city', 'vcard-region', 'vcard-postal', 'vcard-country'
  ];

  function saveVcardIdentity() {
    const data = {};
    for (const id of vcardFieldIds) {
      const el = $(id);
      if (el) data[id] = el.value;
    }
    if (state.vcardPhoto) data._photo = state.vcardPhoto;
    try { localStorage.setItem(VCARD_STORAGE_KEY, JSON.stringify(data)); } catch (e) { /* ignore */ }
  }

  function restoreVcardIdentity() {
    try {
      const raw = localStorage.getItem(VCARD_STORAGE_KEY);
      if (!raw) return;
      const data = JSON.parse(raw);
      for (const id of vcardFieldIds) {
        const el = $(id);
        if (el && data[id]) el.value = data[id];
      }
      if (data._photo) {
        state.vcardPhoto = data._photo;
        showPhotoPreview(data._photo);
      }
    } catch (e) { /* ignore */ }
  }

  restoreVcardIdentity();
  updateIdentityCardSummary();

  // Snapshot of field values before editing (for Back/cancel)
  let _vcardEditSnapshot = {};

  function snapshotVcardFields() {
    _vcardEditSnapshot = {};
    for (const id of vcardFieldIds) {
      const el = $(id);
      if (el) _vcardEditSnapshot[id] = el.value;
    }
  }

  function restoreVcardSnapshot() {
    for (const id of vcardFieldIds) {
      const el = $(id);
      if (el && _vcardEditSnapshot[id] !== undefined) el.value = _vcardEditSnapshot[id];
    }
  }

  // Edit button — switch to edit view
  $('identity-edit-btn')?.addEventListener('click', () => {
    setPhotoActionsVisible(false);
    stopCamera();
    snapshotVcardFields();
    $('vcard-form-view').style.display = 'none';
    $('vcard-edit-view').style.display = 'flex';
  });

  // Save button — persist and return to card view
  $('identity-save-btn')?.addEventListener('click', () => {
    saveVcardIdentity();
    updateIdentityCardSummary();
    setPhotoActionsVisible(false);
    $('vcard-edit-view').style.display = 'none';
    $('vcard-form-view').style.display = '';
  });

  // Back button — discard changes and return to card view
  $('identity-back-btn')?.addEventListener('click', () => {
    restoreVcardSnapshot();
    setPhotoActionsVisible(false);
    stopCamera();
    $('vcard-edit-view').style.display = 'none';
    $('vcard-form-view').style.display = '';
  });

  const photoActions = $('vcard-photo-actions');
  const photoEditBtn = $('vcard-photo-edit-btn');
  function setPhotoActionsVisible(visible) {
    if (photoActions) photoActions.classList.toggle('visible', visible);
    if (photoEditBtn) {
      photoEditBtn.classList.toggle('is-open', visible);
      photoEditBtn.title = visible ? 'Close Photo Menu' : 'Edit Photo';
    }
  }
  function arePhotoActionsVisible() {
    return !!photoActions?.classList.contains('visible');
  }
  setPhotoActionsVisible(false);

  function encodeVcardPhoto(source, sourceWidth, sourceHeight) {
    if (!source || !sourceWidth || !sourceHeight) return null;
    const maxDimension = 1024;
    const quality = 0.9;
    const scale = Math.min(1, maxDimension / Math.max(sourceWidth, sourceHeight));
    const outputWidth = Math.max(1, Math.round(sourceWidth * scale));
    const outputHeight = Math.max(1, Math.round(sourceHeight * scale));
    const canvas = document.createElement('canvas');
    canvas.width = outputWidth;
    canvas.height = outputHeight;
    const ctx = canvas.getContext('2d');
    if (!ctx) return null;
    ctx.imageSmoothingEnabled = true;
    ctx.imageSmoothingQuality = 'high';
    ctx.drawImage(source, 0, 0, sourceWidth, sourceHeight, 0, 0, outputWidth, outputHeight);
    return canvas.toDataURL('image/jpeg', quality);
  }

  photoEditBtn?.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (arePhotoActionsVisible()) {
      setPhotoActionsVisible(false);
      stopCamera();
      return;
    }
    setPhotoActionsVisible(true);
  });

  // Photo upload handler
  $('vcard-photo-input')?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const img = new Image();
      img.onload = () => {
        const dataUrl = encodeVcardPhoto(img, img.width, img.height);
        if (!dataUrl) return;
        state.vcardPhoto = dataUrl;
        stopCamera();
        showPhotoPreview(dataUrl);
        setPhotoActionsVisible(false);
        saveVcardIdentity();
      };
      img.src = ev.target.result;
    };
    reader.readAsDataURL(file);
  });

  // Photo remove handler with confirmation modal
  $('vcard-photo-remove')?.addEventListener('click', () => {
    const modal = $('photo-remove-confirm-modal');
    if (modal) modal.classList.add('active');
  });

  $('photo-remove-yes')?.addEventListener('click', () => {
    state.vcardPhoto = null;
    resetPhotoPreview();
    saveVcardIdentity();
    const removeBtn = $('vcard-photo-remove');
    if (removeBtn) removeBtn.style.display = 'none';
    const input = $('vcard-photo-input');
    if (input) input.value = '';
    // Show upload/camera buttons again
    const uploadLabel = document.querySelector('label[for="vcard-photo-input"]');
    if (uploadLabel) uploadLabel.style.display = '';
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      const cameraBtn = $('vcard-camera-btn');
      if (cameraBtn) cameraBtn.style.display = '';
    }
    setPhotoActionsVisible(false);
    const modal = $('photo-remove-confirm-modal');
    if (modal) modal.classList.remove('active');
  });

  $('photo-remove-no')?.addEventListener('click', () => {
    const modal = $('photo-remove-confirm-modal');
    if (modal) modal.classList.remove('active');
  });

  function resetPhotoPreview() {
    const preview = $('vcard-photo-preview');
    if (!preview) return;
    preview.querySelectorAll('img').forEach(el => el.remove());
    const placeholder = preview.querySelector('.photo-placeholder-icon');
    if (placeholder) placeholder.style.display = '';
    const video = $('vcard-camera-video');
    if (video) video.style.display = 'none';
    const removeBtn = $('vcard-photo-remove');
    if (removeBtn) removeBtn.style.display = 'none';
    const uploadLabel = document.querySelector('label[for="vcard-photo-input"]');
    if (uploadLabel) uploadLabel.style.display = '';
    const cameraBtn = $('vcard-camera-btn');
    if (cameraBtn && navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      cameraBtn.style.display = '';
    }
  }

  function showPhotoPreview(dataUrl) {
    const preview = $('vcard-photo-preview');
    if (!preview) return;
    const placeholder = preview.querySelector('.photo-placeholder-icon');
    if (placeholder) placeholder.style.display = 'none';
    const video = $('vcard-camera-video');
    if (video) video.style.display = 'none';
    preview.querySelectorAll('img').forEach(el => el.remove());
    const img = document.createElement('img');
    img.src = dataUrl;
    img.alt = 'Photo';
    img.onerror = () => { img.remove(); resetPhotoPreview(); };
    preview.appendChild(img);
    const removeBtn = $('vcard-photo-remove');
    if (removeBtn) removeBtn.style.display = '';
    const uploadLabel = document.querySelector('label[for="vcard-photo-input"]');
    if (uploadLabel) uploadLabel.style.display = '';
    const cameraBtn = $('vcard-camera-btn');
    if (cameraBtn && navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      cameraBtn.style.display = '';
    }
  }

  // Camera support
  let cameraStream = null;
  if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
    const cameraBtn = $('vcard-camera-btn');
    if (cameraBtn) cameraBtn.style.display = '';

    cameraBtn?.addEventListener('click', async () => {
      try {
        cameraStream = await navigator.mediaDevices.getUserMedia({
          video: {
            facingMode: 'user',
            width: { ideal: 1280, max: 1920 },
            height: { ideal: 720, max: 1080 },
          }
        });
        const video = $('vcard-camera-video');
        if (video) {
          video.srcObject = cameraStream;
          video.style.display = '';
          await video.play();
        }
        const preview = $('vcard-photo-preview');
        if (preview) {
          const placeholder = preview.querySelector('.photo-placeholder-icon');
          if (placeholder) placeholder.style.display = 'none';
          preview.querySelectorAll('img').forEach(el => el.style.display = 'none');
        }
        cameraBtn.style.display = 'none';
        const uploadLabel = document.querySelector('label[for="vcard-photo-input"]');
        if (uploadLabel) uploadLabel.style.display = 'none';
        const removeBtn = $('vcard-photo-remove');
        if (removeBtn) removeBtn.style.display = 'none';
        const captureBtn = $('vcard-camera-capture');
        const cancelBtn = $('vcard-camera-cancel');
        if (captureBtn) captureBtn.style.display = '';
        if (cancelBtn) cancelBtn.style.display = '';
      } catch (err) {
        console.error('Camera access denied:', err);
        alert('Could not access camera. Please check your browser permissions.');
      }
    });

    $('vcard-camera-capture')?.addEventListener('click', () => {
      const video = $('vcard-camera-video');
      if (!video) return;
      const vw = video.videoWidth;
      const vh = video.videoHeight;
      const dataUrl = encodeVcardPhoto(video, vw, vh);
      if (!dataUrl) return;
      state.vcardPhoto = dataUrl;
      stopCamera();
      showPhotoPreview(dataUrl);
      setPhotoActionsVisible(false);
      saveVcardIdentity();
    });

    $('vcard-camera-cancel')?.addEventListener('click', () => {
      stopCamera();
      if (state.vcardPhoto) {
        showPhotoPreview(state.vcardPhoto);
      } else {
        resetPhotoPreview();
      }
    });
  }

  function stopCamera() {
    if (cameraStream) {
      cameraStream.getTracks().forEach(t => t.stop());
      cameraStream = null;
    }
    const video = $('vcard-camera-video');
    if (video) {
      video.srcObject = null;
      video.style.display = 'none';
    }
    const cameraBtn = $('vcard-camera-btn');
    const uploadLabel = document.querySelector('label[for="vcard-photo-input"]');
    const removeBtn = $('vcard-photo-remove');
    const captureBtn = $('vcard-camera-capture');
    const cancelBtn = $('vcard-camera-cancel');
    if (uploadLabel) uploadLabel.style.display = '';
    if (removeBtn) removeBtn.style.display = state.vcardPhoto ? '' : 'none';
    if (cameraBtn && navigator.mediaDevices && navigator.mediaDevices.getUserMedia) cameraBtn.style.display = '';
    if (captureBtn) captureBtn.style.display = 'none';
    if (cancelBtn) cancelBtn.style.display = 'none';
  }

  // VCF import handler
  $('vcf-import-input')?.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const vcfText = ev.target.result;
      parseAndDisplayVCF(vcfText);
    };
    reader.readAsText(file);
    e.target.value = '';
  });

  $('vcf-import-apply')?.addEventListener('click', () => {
    applyImportedVcardPreview();
  });

  $('vcf-import-close')?.addEventListener('click', () => {
    hideImportedVcardPreview();
  });

  // Reveal sensitive key buttons
  $qa('.reveal-key-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const targetEl = $(targetId);
      if (targetEl) {
        const isRevealed = targetEl.dataset.revealed === 'true';
        const nextRevealed = !isRevealed;
        targetEl.dataset.revealed = nextRevealed ? 'true' : 'false';

        if (nextRevealed) {
          if (targetId === 'wallet-xprv') {
            targetEl.textContent = state.hdRoot?.toXprv?.() || 'N/A';
          } else if (targetId === 'wallet-seed-phrase') {
            targetEl.textContent = state.mnemonic || 'Not retained by the app';
          }
        } else {
          if (targetId === 'wallet-xprv') {
            targetEl.textContent = 'Hidden (click reveal)';
          } else if (targetId === 'wallet-seed-phrase') {
            targetEl.textContent = 'Not retained by the app';
          }
        }

        btn.innerHTML = isRevealed
          ? '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>'
          : '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
      }
    });
  });

  // Copy key buttons
  $qa('.copy-key-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const targetId = btn.dataset.copy;
      const targetEl = $(targetId);
      if (targetEl) {
        try {
          let value = '';
          if (targetId === 'wallet-xpub' || targetId === 'wallet-tab-xpub') {
            value = state.hdRoot?.toXpub?.() || '';
          } else if (targetId === 'wallet-tab-peerid') {
            value = deriveAccountPeerId() || '';
          } else if (targetId === 'wallet-xprv') {
            if (targetEl.dataset.revealed !== 'true') {
              alert('Reveal the xprv first to copy it.');
              return;
            }
            if (!confirm('Warning: copying your master private key (xprv) is extremely sensitive. Continue?')) {
              return;
            }
            value = state.hdRoot?.toXprv?.() || '';
          } else if (targetId === 'wallet-seed-phrase') {
            alert('Seed phrase not available. For security, the app does not retain the mnemonic after login.');
            return;
          } else {
            value = targetEl.textContent || '';
          }
          if (!value) {
            throw new Error('Nothing to copy');
          }
          if (await safeCopyText(value)) {
            btn.classList.add('copied');
            setTimeout(() => btn.classList.remove('copied'), 1500);
          } else {
            throw new Error('Clipboard unavailable');
          }
        } catch (err) {
          console.error('Copy failed:', err);
        }
      }
    });
  });

  // Export wallet options
  $qa('.export-option').forEach(option => {
    option.addEventListener('click', async () => {
      const format = option.dataset.format;
      await exportWallet(format);
    });
  });

  // Mobile menu toggle
  const mobileMenuBtn = $('nav-menu-btn');
  const mobileMenu = $('nav-mobile-menu');

  if (mobileMenuBtn && mobileMenu) {
    mobileMenuBtn.addEventListener('click', () => {
      mobileMenu.classList.toggle('open');
      const isOpen = mobileMenu.classList.contains('open');
      mobileMenuBtn.innerHTML = isOpen
        ? '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>'
        : '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
    });

    const mobileLogin = $('mobile-login');
    const mobileLogout = $('mobile-logout');

    if (mobileLogin) {
      mobileLogin.addEventListener('click', () => {
        $('login-modal')?.classList.add('active');
        mobileMenu.classList.remove('open');
        mobileMenuBtn.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
      });
    }

    if (mobileLogout) {
      mobileLogout.addEventListener('click', () => {
        logout();
        mobileMenu.classList.remove('open');
        mobileMenuBtn.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
      });
    }
  }

  // Navigation links - scroll to sections
  $qa('.nav-link[data-tab]').forEach(link => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      $qa('.nav-link[data-tab]').forEach(l => l.classList.remove('active'));
      link.classList.add('active');
      const tabEl = $(`${link.dataset.tab}-tab`);
      if (tabEl) {
        tabEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      if (mobileMenu) {
        mobileMenu.classList.remove('open');
        if (mobileMenuBtn) {
          mobileMenuBtn.innerHTML = '<svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="3" y1="6" x2="21" y2="6"/><line x1="3" y1="12" x2="21" y2="12"/><line x1="3" y1="18" x2="21" y2="18"/></svg>';
        }
      }
    });
  });

  // Wallet tab controls
  $('wallet-active-select')?.addEventListener('change', (e) => {
    const walletId = Number.parseInt(e.target.value, 10);
    if (Number.isNaN(walletId)) return;
    state.activeWalletId = walletId;
    closeWalletActionMenus();
    renderWalletSelector();
    renderAccountsList();
    updateCustomPathDefault();
  });
  $('wallet-manage-btn')?.addEventListener('click', () => {
    closeWalletActionMenus();
    showWalletsView();
  });
  $('wallet-scan-btn')?.addEventListener('click', () => {
    scanActiveAccounts();
  });
  const sendAction = $('wallet-send-action');
  const receiveAction = $('wallet-receive-action');
  $('wallet-send-btn')?.addEventListener('click', (e) => {
    e.stopPropagation();
    updateWalletActionMenus();
    const sendMenu = $('wallet-send-menu');
    const receiveMenu = $('wallet-receive-menu');
    if (!sendMenu || !receiveMenu) return;
    const nextVisible = !sendMenu.classList.contains('visible');
    receiveMenu.classList.remove('visible');
    sendMenu.classList.toggle('visible', nextVisible);
  });
  $('wallet-receive-btn-main')?.addEventListener('click', (e) => {
    e.stopPropagation();
    // External session: one account, one address — straight to its QR.
    if (state.externalAccount && !state.hdRoot) {
      showReceiveModal({
        name: state.externalAccount.chain.toUpperCase(),
        address: state.externalAccount.address,
      });
      return;
    }
    updateWalletActionMenus();
    const sendMenu = $('wallet-send-menu');
    const receiveMenu = $('wallet-receive-menu');
    if (!sendMenu || !receiveMenu) return;
    const nextVisible = !receiveMenu.classList.contains('visible');
    sendMenu.classList.remove('visible');
    receiveMenu.classList.toggle('visible', nextVisible);
  });
  $qa('#wallet-send-menu .ph-action-menu-item').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const chain = btn.dataset.chain;
      const acct = getWalletAccountForChain(chain);
      closeWalletActionMenus();
      if (!acct) return;
      showSendView(state.activeAccounts.indexOf(acct));
    });
  });
  $qa('#wallet-receive-menu .ph-action-menu-item').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const chain = btn.dataset.chain;
      const acct = getWalletAccountForChain(chain);
      closeWalletActionMenus();
      if (!acct) return;
      showReceiveModal(acct);
    });
  });
  _root.addEventListener('click', (e) => {
    if (sendAction?.contains(e.target) || receiveAction?.contains(e.target)) return;
    closeWalletActionMenus();
  });
  $('wallet-export-btn-main')?.addEventListener('click', () => {
    closeWalletActionMenus();
    showExportView();
  });
  $('wallet-advanced-btn-main')?.addEventListener('click', () => {
    closeWalletActionMenus();
    showAdvancedView();
  });
  $('wallet-wallets-back')?.addEventListener('click', () => {
    showWalletMainView();
  });
  $('wallet-manage-tab-active')?.addEventListener('click', () => {
    setWalletManageTab('active');
  });
  $('wallet-manage-tab-inactive')?.addEventListener('click', () => {
    setWalletManageTab('inactive');
  });
  $('wallet-export-back')?.addEventListener('click', () => {
    showWalletMainView();
  });
  $('wallet-advanced-back')?.addEventListener('click', () => {
    showWalletMainView();
  });
  // New Wallet in wallets view
  $('wallet-new-btn')?.addEventListener('click', () => {
    createNewWallet();
  });
  // Custom derivation path
  $('custom-path-add')?.addEventListener('click', () => {
    addCustomPathAccount();
  });
  $('custom-path-chain')?.addEventListener('change', () => {
    updateCustomPathDefault();
  });
  $('custom-path-input')?.addEventListener('input', (e) => {
    e.target.dataset.autogenerated = 'false';
  });
  // Send flow
  $('wallet-send-back')?.addEventListener('click', () => {
    hideSendView();
  });
  $('send-from-account')?.addEventListener('change', () => {
    updateSendFromSelection();
  });
  $('send-to-address')?.addEventListener('input', () => {
    validateSendForm();
  });
  $('send-amount')?.addEventListener('input', () => {
    validateSendForm();
    updateSendFiatEstimate();
  });
  $('send-max-btn')?.addEventListener('click', () => {
    const select = $('send-from-account');
    const amountInput = $('send-amount');
    if (!select || !amountInput) return;
    const idx = parseInt(select.value);
    const acct = state.activeAccounts[idx];
    if (!acct) return;
    const bal = parseFloat(acct.balance);
    if (!isNaN(bal) && bal > 0) {
      amountInput.value = bal;
      validateSendForm();
      updateSendFiatEstimate();
    }
  });
  $('send-review-btn')?.addEventListener('click', () => {
    showSendReview();
  });
  $('send-confirm-btn')?.addEventListener('click', () => {
    executeSend();
  });
  $('send-edit-btn')?.addEventListener('click', () => {
    const compose = $('send-compose-step');
    const review = $('send-review-step');
    if (compose) compose.style.display = 'block';
    if (review) review.style.display = 'none';
  });

  // PKI clear keys
  $('pki-clear-keys')?.addEventListener('click', clearPKIKeys);

  // PKI algorithm change
  $('pki-algorithm')?.addEventListener('change', async () => {
    const newAlgorithm = $('pki-algorithm').value;
    state.pki.algorithm = newAlgorithm;

    if (state.hdRoot) {
      derivePKIKeysFromHD();
      savePKIKeys();
    } else {
      try {
        if (newAlgorithm === 'p256') {
          state.pki.alice = await p256GenerateKeyPairAsync();
          state.pki.bob = await p256GenerateKeyPairAsync();
        } else if (newAlgorithm === 'p384') {
          state.pki.alice = await p384GenerateKeyPairAsync();
          state.pki.bob = await p384GenerateKeyPairAsync();
        } else {
          const curveType = newAlgorithm === 'secp256k1' ? Curve.SECP256K1 : Curve.X25519;
          state.pki.alice = generateKeyPair(curveType);
          state.pki.bob = generateKeyPair(curveType);
        }
        savePKIKeys();
      } catch (err) {
        console.error('Failed to generate keys for', newAlgorithm, err);
        return;
      }
    }

    // Update display
    const alicePub = $('alice-public-key');
    const alicePriv = $('alice-private-key');
    const bobPub = $('bob-public-key');
    const bobPriv = $('bob-private-key');
    if (alicePub) alicePub.textContent = toHexCompact(state.pki.alice.publicKey);
    if (alicePriv) alicePriv.textContent = toHexCompact(state.pki.alice.privateKey);
    if (bobPub) bobPub.textContent = toHexCompact(state.pki.bob.publicKey);
    if (bobPriv) bobPriv.textContent = toHexCompact(state.pki.bob.privateKey);

    const algorithmNames = {
      x25519: 'X25519 (Curve25519)',
      secp256k1: 'secp256k1 (Bitcoin/Ethereum)',
      p256: 'P-256 / secp256r1 (NIST)',
      p384: 'P-384 / secp384r1 (NIST)',
    };
    const algDisplay = $('pki-algorithm-display');
    if (algDisplay) algDisplay.textContent = algorithmNames[newAlgorithm] || newAlgorithm;
  });

  // vCard generation
  $('generate-vcard')?.addEventListener('click', async () => {
    const info = {
      prefix: $('vcard-prefix')?.value || '',
      firstName: $('vcard-firstname')?.value || '',
      middleName: $('vcard-middlename')?.value || '',
      lastName: $('vcard-lastname')?.value || '',
      suffix: $('vcard-suffix')?.value || '',
      nickname: $('vcard-nickname')?.value || '',
      email: $('vcard-email')?.value || '',
      phone: $('vcard-phone')?.value || '',
      org: $('vcard-org')?.value || '',
      title: $('vcard-title')?.value || '',
      includeKeys: true,
    };

    if (!info.firstName && !info.lastName) {
      alert('Please enter at least a first or last name');
      return;
    }

    const vcard = signVCard(generateVCard(info));
    const vcardForQR = signVCard(generateVCard(info, { skipPhoto: true }));
    state._exportedVCard = vcard;

    try {
      const qrCanvas = $('qr-code');
      if (qrCanvas) {
        await QRCode.toCanvas(qrCanvas, vcardForQR, {
          width: 256,
          margin: 2,
          color: { dark: '#1e293b', light: '#ffffff' },
        });
      }
      const formView = $('vcard-form-view');
      const resultView = $('vcard-result-view');
      if (formView) formView.style.display = 'none';
      if (resultView) resultView.style.display = '';

      // Show/hide signature badge
      const sigBadge = $('vcard-sig-badge');
      if (sigBadge) {
        sigBadge.style.display = state.wallet?.ed25519?.privateKey ? 'flex' : 'none';
      }

      // Populate raw view (strip PHOTO base64 data)
      const rawView = $('vcard-raw-view');
      if (rawView) {
        const rawText = vcard.replace(/PHOTO;ENCODING=b;TYPE=\w+:[\s\S]*?(?=\n[A-Z])/m, 'PHOTO:[image data omitted]');
        rawView.textContent = rawText;
      }

      // Reset toggle to QR
      $('vcard-toggle-qr')?.classList.add('active');
      $('vcard-toggle-raw')?.classList.remove('active');
      document.querySelector('.qr-container')?.style.setProperty('display', '');
      if (rawView) rawView.style.display = 'none';
    } catch (err) {
      alert('Error generating QR code: ' + err.message);
    }
  });

  // Toggle QR / Raw
  $('vcard-toggle-qr')?.addEventListener('click', () => {
    $('vcard-toggle-qr')?.classList.add('active');
    $('vcard-toggle-raw')?.classList.remove('active');
    const qr = document.querySelector('#vcard-result-view .qr-container');
    const raw = $('vcard-raw-view');
    if (qr) qr.style.display = '';
    if (raw) raw.style.display = 'none';
  });

  $('vcard-toggle-raw')?.addEventListener('click', () => {
    $('vcard-toggle-raw')?.classList.add('active');
    $('vcard-toggle-qr')?.classList.remove('active');
    const qr = document.querySelector('#vcard-result-view .qr-container');
    const raw = $('vcard-raw-view');
    if (qr) qr.style.display = 'none';
    if (raw) raw.style.display = '';
  });

  // Back to editor from result view
  $('vcard-back-btn')?.addEventListener('click', () => {
    const resultView = $('vcard-result-view');
    const formView = $('vcard-form-view');
    if (resultView) resultView.style.display = 'none';
    if (formView) formView.style.display = '';
  });

  // Download vCard
  $('download-vcard')?.addEventListener('click', () => {
    const vcard = state._exportedVCard || '';
    const blob = new Blob([vcard], { type: 'text/vcard' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'contact.vcf';
    a.click();
    URL.revokeObjectURL(url);
  });

  // Copy vCard
  $('copy-vcard')?.addEventListener('click', async () => {
    const vcard = state._exportedVCard || '';
    try {
      if (!await safeCopyText(vcard)) {
        throw new Error('Clipboard unavailable');
      }
      const btn = $('copy-vcard');
      if (btn) {
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy vCard'; }, 2000);
      }
    } catch (err) {
      alert('Failed to copy: ' + err.message);
    }
  });

  // Refresh balances button
  $('refresh-balances')?.addEventListener('click', () => {
    updateAdversarialSecurity();
  });

  // Escape key closes modals
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      $qa('.modal.active').forEach(m => m.classList.remove('active'));
    }
  });

  // Trust system handlers
  setupTrustHandlers();
}

// =============================================================================
// Trust System Handlers
// =============================================================================

function setupTrustHandlers() {
  let trustScanInterval = null;
  let trustScanRunning = false;
  let trustNextAllowedAt = 0;
  const TRUST_SCAN_INTERVAL_MS = 3 * 60 * 1000; // 3 minutes
  const TRUST_SCAN_FAIL_COOLDOWN_MS = 5 * 60 * 1000; // 5 minutes on failure
  const TRUST_RULES_KEY = 'trust-rules';
  const TRUST_IMPORTED_KEY = 'trust-imported-txs';

  // Auto-scan trust transactions
  async function runTrustScan() {
    if (!state.loggedIn || !state.addresses) return;
    if (trustScanRunning) return;
    if (Date.now() < trustNextAllowedAt) return;
    trustScanRunning = true;

    const statusEl = $('trust-scan-status');
    const labelEl = $('trust-scan-label');
    const countEl = $('trust-scan-count');
    if (statusEl) statusEl.classList.add('active');
    if (labelEl) labelEl.textContent = 'Scanning...';

    try {
      const { scanAllTrustTransactions, renderTrustList } = await import('./trust-ui.js');
      const { buildTrustGraph, analyzeTrustRelationships } = await import('./blockchain-trust.js');

      // Scan on-chain transactions
      const onChainTxs = await scanAllTrustTransactions(state.addresses);

      // Merge with imported transactions
      let importedTxs = [];
      try {
        const raw = localStorage.getItem(TRUST_IMPORTED_KEY);
        if (raw) importedTxs = JSON.parse(raw);
      } catch (e) { /* ignore */ }

      const allTxs = [...onChainTxs, ...importedTxs];

      // Deduplicate by txHash
      const seen = new Set();
      const dedupedTxs = allTxs.filter(tx => {
        if (seen.has(tx.txHash)) return false;
        seen.add(tx.txHash);
        return true;
      });

      // Build graph and analyze relationships
      const graph = buildTrustGraph(dedupedTxs);
      const relationships = analyzeTrustRelationships(state.addresses, dedupedTxs);

      // Apply trust rules
      const rules = loadTrustRules();
      if (rules.length > 0) {
        applyTrustRules(relationships, rules);
      }

      // Store in state
      state.trustGraph = graph;
      state.trustTransactions = dedupedTxs;
      state.trustRelationships = relationships;

      // Update UI
      const listEl = $('trust-list');
      if (listEl) {
        renderTrustList(listEl, relationships, state.addresses);
      }

      if (labelEl) labelEl.textContent = 'Last scan: just now';
      if (countEl) countEl.textContent = `${relationships.length} relationships`;

      console.log(`Trust scan: ${dedupedTxs.length} txs, ${relationships.length} relationships`);
      trustNextAllowedAt = 0;
    } catch (err) {
      console.error('Trust scan failed:', err);
      trustNextAllowedAt = Date.now() + TRUST_SCAN_FAIL_COOLDOWN_MS;
      if (labelEl) labelEl.textContent = 'Scan delayed (endpoint limited)';
    } finally {
      trustScanRunning = false;
    }
  }

  // Start auto-scanning
  function startTrustScanning() {
    if (trustScanInterval) {
      clearInterval(trustScanInterval);
      trustScanInterval = null;
    }
    runTrustScan();
    trustScanInterval = setInterval(runTrustScan, TRUST_SCAN_INTERVAL_MS);
  }

  // Stop auto-scanning
  function stopTrustScanning() {
    if (trustScanInterval) {
      clearInterval(trustScanInterval);
      trustScanInterval = null;
    }
    const statusEl = $('trust-scan-status');
    if (statusEl) statusEl.classList.remove('active');
  }

  // Load trust rules from localStorage
  function loadTrustRules() {
    try {
      const raw = localStorage.getItem(TRUST_RULES_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) { return []; }
  }

  // Apply trust rules to relationships
  function applyTrustRules(relationships, rules) {
    for (const rel of relationships) {
      for (const rule of rules) {
        switch (rule.type) {
          case 'mutual_tx_count':
            if (rel.direction === 'mutual' && rel.txCount >= rule.params.threshold) {
              rel.ruleLevel = Math.max(rel.ruleLevel || 0, rule.resultLevel);
            }
            break;
          case 'last_interaction_days': {
            const daysSince = (Date.now() - rel.lastSeen) / (1000 * 60 * 60 * 24);
            if (daysSince <= rule.params.threshold) {
              rel.ruleLevel = Math.max(rel.ruleLevel || 0, rule.resultLevel);
            }
            break;
          }
          case 'bidirectional_trust':
            if (rel.direction === 'mutual') {
              rel.ruleLevel = Math.min((rel.level || 2) + 1, 5);
            }
            break;
          case 'address_blocklist':
            // Handled by NEVER trust level on-chain
            break;
        }
      }
    }
  }

  // Establish trust button
  $('establish-trust-btn')?.addEventListener('click', async () => {
    if (!state.loggedIn) { alert('Please login first'); return; }
    const { showEstablishTrustModal } = await import('./trust-ui.js');
    showEstablishTrustModal(({ level, network, recipientAddress }) => {
      console.log('Establish trust:', { level, network, recipientAddress });
      // TODO: Build, sign, and broadcast trust transaction
      alert(`Trust transaction would be published on ${network.toUpperCase()} for level ${level}.\nTransaction signing/broadcasting is not yet implemented.`);
    });
  });

  // Rules button
  $('trust-rules-btn')?.addEventListener('click', async () => {
    const { showRulesModal } = await import('./trust-ui.js');
    const currentRules = loadTrustRules();
    showRulesModal(currentRules, (updatedRules) => {
      localStorage.setItem(TRUST_RULES_KEY, JSON.stringify(updatedRules));
      // Re-apply rules
      if (state.trustRelationships) {
        applyTrustRules(state.trustRelationships, updatedRules);
        runTrustScan();
      }
    });
  });

  // Export trust data
  $('trust-export-btn')?.addEventListener('click', async () => {
    if (!state.trustTransactions || state.trustTransactions.length === 0) {
      alert('No trust data to export. Wait for a scan to complete.');
      return;
    }
    const { exportTrustData } = await import('./trust-ui.js');
    const xpub = state.hdRoot ? state.hdRoot.toXpub() : '';
    exportTrustData(state.trustTransactions, xpub);
  });

  // Import trust data
  $('trust-import-input')?.addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    try {
      const { importTrustData } = await import('./trust-ui.js');
      const importedTxs = await importTrustData(file);

      // Merge with existing imported txs
      let existing = [];
      try {
        const raw = localStorage.getItem(TRUST_IMPORTED_KEY);
        if (raw) existing = JSON.parse(raw);
      } catch (err) { /* ignore */ }

      const merged = [...existing, ...importedTxs];
      const seen = new Set();
      const deduped = merged.filter(tx => {
        if (seen.has(tx.txHash)) return false;
        seen.add(tx.txHash);
        return true;
      });

      localStorage.setItem(TRUST_IMPORTED_KEY, JSON.stringify(deduped));
      alert(`Imported ${importedTxs.length} trust transactions.`);

      // Re-scan to incorporate
      runTrustScan();
    } catch (err) {
      console.error('Trust import failed:', err);
      alert('Failed to import trust data: ' + err.message);
    }
    e.target.value = '';
  });

  // Expose start/stop for login/logout
  state._startTrustScanning = startTrustScanning;
  state._stopTrustScanning = stopTrustScanning;

  // =========================================================================
  // Encryption Tab Handlers (ECIES: ECDH + HKDF + AES-256-GCM)
  // =========================================================================

  const MESSAGING_KEY_CONFIG_KEY = 'hd-wallet-messaging-key-config-v1';
  const messagingKeyDefaults = Object.freeze({
    btc: { path: "m/44'/0'/0'/1/0", algorithm: 'secp256k1', publicKeyFormat: 'compressed' },
    eth: { path: "m/44'/60'/0'/1/0", algorithm: 'secp256k1', publicKeyFormat: 'uncompressed' },
    sol: { path: "m/44'/501'/0'/1/0", algorithm: 'x25519', publicKeyFormat: 'raw' },
  });

  const wipeBytes = (u8) => {
    if (u8 instanceof Uint8Array) u8.fill(0);
  };

  function getMessagingKeyType() {
    const v = $('messaging-key-type')?.value;
    return v === 'eth' || v === 'sol' ? v : 'btc';
  }

  function getMessagingDefaultPath(keyType = getMessagingKeyType()) {
    return messagingKeyDefaults[keyType]?.path || messagingKeyDefaults.btc.path;
  }

  function getMessagingHDPath(keyType = getMessagingKeyType()) {
    const el = $('messaging-hd-path');
    const raw = el?.value || '';
    const path = raw.trim();
    return path || getMessagingDefaultPath(keyType);
  }

  function setMessagingRecipientPlaceholder(keyType = getMessagingKeyType()) {
    const input = $('encrypt-recipient-pubkey');
    if (!input) return;
    if (keyType === 'sol') {
      input.placeholder = "Paste recipient's X25519 public key (hex, 32 bytes)";
      return;
    }
    if (keyType === 'eth') {
      input.placeholder = "Paste recipient's secp256k1 public key (hex, 65 bytes preferred)";
      return;
    }
    input.placeholder = "Paste recipient's secp256k1 public key (hex, 33 bytes preferred)";
  }

  function loadMessagingKeyConfig() {
    try {
      const raw = localStorage.getItem(MESSAGING_KEY_CONFIG_KEY);
      if (!raw) return null;
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object') return null;
      return {
        keyType: parsed.keyType,
        path: parsed.path,
      };
    } catch {
      return null;
    }
  }

  function saveMessagingKeyConfig(keyType, path) {
    try {
      localStorage.setItem(MESSAGING_KEY_CONFIG_KEY, JSON.stringify({ keyType, path }));
    } catch {
      // ignore
    }
  }

  function initMessagingKeyControls() {
    const keyTypeEl = $('messaging-key-type');
    const pathEl = $('messaging-hd-path');
    const resetBtn = $('messaging-hd-path-default');
    if (!keyTypeEl || !pathEl) return;

    const saved = loadMessagingKeyConfig();
    const hasSaved = !!saved;
    if (saved?.keyType === 'btc' || saved?.keyType === 'eth' || saved?.keyType === 'sol') {
      keyTypeEl.value = saved.keyType;
    } else {
      keyTypeEl.value = 'btc';
    }

    if (typeof saved?.path === 'string' && saved.path.trim()) {
      pathEl.value = saved.path.trim();
    } else if (hasSaved || !pathEl.value?.trim()) {
      pathEl.value = getMessagingDefaultPath(keyTypeEl.value);
    }

    setMessagingRecipientPlaceholder(keyTypeEl.value);

    const onChange = () => {
      const keyType = getMessagingKeyType();
      const path = getMessagingHDPath(keyType);
      saveMessagingKeyConfig(keyType, path);
      setMessagingRecipientPlaceholder(keyType);
      if (state.hdRoot) updateEncryptionTab();
    };

    keyTypeEl.addEventListener('change', () => {
      const prev = pathEl.value?.trim();
      const prevDefaults = Object.values(messagingKeyDefaults).map(v => v.path);
      const nextKeyType = getMessagingKeyType();
      const nextDefault = getMessagingDefaultPath(nextKeyType);
      // If user hasn't customized, keep the path in sync with key type.
      if (!prev || prevDefaults.includes(prev)) {
        pathEl.value = nextDefault;
      }
      onChange();
    });
    pathEl.addEventListener('input', onChange);
    resetBtn?.addEventListener('click', () => {
      const keyType = getMessagingKeyType();
      pathEl.value = getMessagingDefaultPath(keyType);
      onChange();
    });
  }

  function hexToBytesStrict(hex, expectedLen = null) {
    if (typeof hex !== 'string') throw new Error('Expected hex string');
    const cleaned = hex.trim().toLowerCase().replace(/^0x/, '');
    if (!cleaned) throw new Error('Empty hex string');
    if (cleaned.length % 2 !== 0) throw new Error('Invalid hex length');
    if (!/^[0-9a-f]+$/.test(cleaned)) throw new Error('Invalid hex string');
    const bytes = new Uint8Array(cleaned.length / 2);
    for (let i = 0; i < cleaned.length; i += 2) {
      bytes[i / 2] = parseInt(cleaned.slice(i, i + 2), 16);
    }
    if (expectedLen !== null && bytes.length !== expectedLen) {
      throw new Error(`Expected ${expectedLen} bytes, got ${bytes.length}`);
    }
    return bytes;
  }

  function deriveKeyMaterialForMessaging(w, keyType, path) {
    if (!state.hdRoot || !w) throw new Error('HD wallet not initialized');
    const derived = deriveHDKey(path);
    try {
      if (keyType === 'sol') {
        const priv = derived.privateKey();
        const pub = w.curves.x25519.publicKey(priv);
        return { algorithm: 'x25519', privateKey: priv, publicKey: pub, path };
      }

      const priv = derived.privateKey();
      const pubCompressed = derived.publicKey();
      if (keyType === 'eth') {
        const pub = derived.publicKeyUncompressed();
        return { algorithm: 'secp256k1', privateKey: priv, publicKey: pub, path };
      }
      return { algorithm: 'secp256k1', privateKey: priv, publicKey: pubCompressed, path };
    } finally {
      derived.wipe();
    }
  }

  function deriveMessagingPublicKey(w, keyType, path) {
    if (!state.hdRoot || !w) throw new Error('HD wallet not initialized');
    const derived = deriveHDKey(path);
    try {
      if (keyType === 'sol') {
        const priv = derived.privateKey();
        try {
          return w.curves.x25519.publicKey(priv);
        } finally {
          wipeBytes(priv);
        }
      }
      if (keyType === 'eth') {
        return derived.publicKeyUncompressed();
      }
      return derived.publicKey();
    } finally {
      derived.wipe();
    }
  }

  function normalizeSecp256k1PublicKeyBytes(publicKey) {
    if (!(publicKey instanceof Uint8Array)) throw new Error('Invalid public key');
    // Ethereum public keys are sometimes provided as raw 64-byte x||y without the 0x04 prefix.
    if (publicKey.length === 64) {
      const out = new Uint8Array(65);
      out[0] = 0x04;
      out.set(publicKey, 1);
      return out;
    }
    if (publicKey.length !== 33 && publicKey.length !== 65) {
      throw new Error('secp256k1 public key must be 33 (compressed) or 65 (uncompressed) bytes');
    }
    return publicKey;
  }

  function normalizeRecipientPublicKeyForAlgorithm(algorithm, publicKey) {
    if (algorithm === 'x25519') {
      if (!(publicKey instanceof Uint8Array) || publicKey.length !== 32) {
        throw new Error('X25519 public key must be 32 bytes');
      }
      return publicKey;
    }
    return normalizeSecp256k1PublicKeyBytes(publicKey);
  }

  function eciesInfoForAlgorithm(algorithm) {
    const infoStr = algorithm === 'x25519'
      ? 'ecies-x25519-aes256gcm'
      : 'ecies-secp256k1-aes256gcm';
    return new TextEncoder().encode(infoStr);
  }

  function envelopeAlgorithmParameters(keyType, algorithm) {
    if (algorithm === 'x25519') return 'x25519';
    // secp256k1 modes
    return keyType === 'eth' ? 'secp256k1-uncompressed' : 'secp256k1-compressed';
  }

  function updateEncryptionTab() {
    const w = state.hdWalletModule;
    if (!state.hdRoot || !w) return;

    const keyType = getMessagingKeyType();
    const path = getMessagingHDPath(keyType);

    const senderPubEl = $('encrypt-sender-pubkey');
    const senderPathEl = $('encrypt-sender-path');
    const senderAlgoEl = $('encrypt-sender-algo');
    const encryptBtn = $('encrypt-btn');

    if (senderPathEl) senderPathEl.textContent = path;
    const baseAlgo = messagingKeyDefaults[keyType]?.algorithm || '--';
    if (senderAlgoEl) {
      senderAlgoEl.textContent = baseAlgo === '--'
        ? '--'
        : envelopeAlgorithmParameters(keyType, baseAlgo);
    }
    if (encryptBtn) encryptBtn.disabled = true;

    try {
      const publicKey = deriveMessagingPublicKey(w, keyType, path);
      if (senderPubEl) senderPubEl.textContent = toHexCompact(publicKey);
      if (encryptBtn) encryptBtn.disabled = false;
    } catch (e) {
      if (senderPubEl) senderPubEl.textContent = '--';
      if (senderAlgoEl) senderAlgoEl.textContent = 'invalid path';
    }
  }

  initMessagingKeyControls();

  // Update encryption tab when it becomes active
  $qa('.modal-tab[data-modal-tab="messaging-tab-content"]').forEach(tab => {
    tab.addEventListener('click', () => {
      if (state.hdRoot) updateEncryptionTab();
    });
  });

  // "Self" button - fill recipient with own public key for testing
  $('encrypt-use-self')?.addEventListener('click', () => {
    const senderPub = $('encrypt-sender-pubkey')?.textContent;
    if (senderPub && senderPub !== '--') {
      $('encrypt-recipient-pubkey').value = senderPub;
    }
  });

  // ---- EME state for current encryption result ----
  let currentEME = null;   // EMET instance
  let currentFormat = 'json';

  function emeToJSON(eme) {
    return JSON.stringify({
      ENCRYPTED_BLOB: eme.ENCRYPTED_BLOB,
      EPHEMERAL_PUBLIC_KEY: eme.EPHEMERAL_PUBLIC_KEY,
      MAC: eme.MAC,
      NONCE: eme.NONCE,
      TAG: eme.TAG,
      IV: eme.IV,
      SALT: eme.SALT,
      PUBLIC_KEY_IDENTIFIER: eme.PUBLIC_KEY_IDENTIFIER,
      CIPHER_SUITE: eme.CIPHER_SUITE,
      KDF_PARAMETERS: eme.KDF_PARAMETERS,
      ENCRYPTION_ALGORITHM_PARAMETERS: eme.ENCRYPTION_ALGORITHM_PARAMETERS,
    }, null, 2);
  }

  function emeToFlatBuffer(eme) {
    const builder = new flatbuffers.Builder(1);
    const packed = eme.pack(builder);
    builder.finishSizePrefixed(packed, '$EME');
    return builder.asUint8Array();
  }

  function emeToFlatBufferBase64(eme) {
    return Buffer.from(emeToFlatBuffer(eme)).toString('base64');
  }

  function updateBundleDisplay() {
    if (!currentEME) return;
    const textarea = $('encrypt-bundle');
    if (!textarea) return;
    if (currentFormat === 'json') {
      textarea.value = emeToJSON(currentEME);
    } else {
      textarea.value = emeToFlatBufferBase64(currentEME);
    }
  }

  // Format toggle buttons
  $qa('.encrypt-fmt-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      $qa('.encrypt-fmt-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      currentFormat = btn.dataset.format;
      const label = $('encrypt-format-label');
      if (label) label.textContent = currentFormat === 'json'
        ? 'EME (Encrypted Message Envelope) — SpaceDataStandards.org'
        : 'EME FlatBuffer binary (base64-encoded)';
      updateBundleDisplay();
    });
  });

  // Encrypt button
  $('encrypt-btn')?.addEventListener('click', () => {
    const w = state.hdWalletModule;
    if (!w || !state.hdRoot) {
      alert('Please login first.');
      return;
    }

    const recipientHex = $('encrypt-recipient-pubkey')?.value?.trim();
    const plainStr = $('encrypt-plaintext')?.value;
    if (!recipientHex || !plainStr) {
      alert('Please enter both a recipient public key and a message.');
      return;
    }

    try {
      const keyType = getMessagingKeyType();
      const path = getMessagingHDPath(keyType);
      const { algorithm, privateKey: senderPriv, publicKey: senderPub } = deriveKeyMaterialForMessaging(w, keyType, path);

      let shared = null;
      let aesKey = null;
      try {
        // Parse recipient public key from hex
        const recipientPubRaw = hexToBytesStrict(recipientHex);
        const recipientPub = normalizeRecipientPublicKeyForAlgorithm(algorithm, recipientPubRaw);

        // 1. ECDH shared secret
        shared = algorithm === 'x25519'
          ? w.curves.x25519.ecdh(senderPriv, recipientPub)
          : w.curves.secp256k1.ecdh(senderPriv, recipientPub);

        // 2. HKDF: derive 32-byte AES key from shared secret
        const salt = w.utils.getRandomBytes(32);
        const info = eciesInfoForAlgorithm(algorithm);
        aesKey = w.utils.hkdf(shared, salt, info, 32);

        // 3. AES-256-GCM encrypt
        const iv = w.utils.generateIv();
        const plaintext = new TextEncoder().encode(plainStr);
        const { ciphertext, tag } = w.utils.aesGcm.encrypt(aesKey, plaintext, iv);

        // Display field-level results
        $('encrypt-out-ciphertext').textContent = toHexCompact(ciphertext);
        $('encrypt-out-tag').textContent = toHexCompact(tag);
        $('encrypt-out-iv').textContent = toHexCompact(iv);
        $('encrypt-out-salt').textContent = toHexCompact(salt);
        $('encrypt-out-sender-pub').textContent = toHexCompact(senderPub);

        // Build EME (Encrypted Message Envelope) standard object
        currentEME = new EMET(
          Array.from(ciphertext),                    // ENCRYPTED_BLOB
          toHexCompact(senderPub),                   // EPHEMERAL_PUBLIC_KEY
          null,                                      // MAC (not used, tag covers it)
          null,                                      // NONCE (we use IV field instead)
          toHexCompact(tag),                         // TAG
          toHexCompact(iv),                          // IV
          toHexCompact(salt),                        // SALT
          null,                                      // PUBLIC_KEY_IDENTIFIER
          'aes-256-gcm',                             // CIPHER_SUITE
          'hkdf-sha256',                             // KDF_PARAMETERS
          envelopeAlgorithmParameters(keyType, algorithm), // ENCRYPTION_ALGORITHM_PARAMETERS
        );

        updateBundleDisplay();

        // Switch to result step
        $('encrypt-step-compose').style.display = 'none';
        $('encrypt-step-result').style.display = 'block';
      } finally {
        wipeBytes(senderPriv);
        wipeBytes(shared);
        wipeBytes(aesKey);
      }
    } catch (err) {
      console.error('Encryption failed:', err);
      alert('Encryption failed: ' + err.message);
    }
  });

  // Copy bundle
  $('encrypt-copy-bundle')?.addEventListener('click', () => {
    const bundle = $('encrypt-bundle')?.value;
    if (bundle) {
      void safeCopyText(bundle);
    }
  });

  // Download bundle
  $('encrypt-download-bundle')?.addEventListener('click', () => {
    if (!currentEME) return;
    let blob, filename;
    if (currentFormat === 'json') {
      blob = new Blob([emeToJSON(currentEME)], { type: 'application/json' });
      filename = 'message.eme.json';
    } else {
      const buf = emeToFlatBuffer(currentEME);
      blob = new Blob([buf], { type: 'application/octet-stream' });
      filename = 'message.eme.fbs';
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  });

  // Parse EME from input (JSON or base64 FlatBuffer)
  function parseEMEPayload(input) {
    const trimmed = input.trim();
    // Try JSON first
    if (trimmed.startsWith('{')) {
      return JSON.parse(trimmed);
    }
    // Try base64 FlatBuffer (size-prefixed)
    const buf = new Uint8Array(Buffer.from(trimmed, 'base64'));
    const bb = new flatbuffers.ByteBuffer(buf);
    const root = EME.getSizePrefixedRootAsEME(bb);
    const eme = root.unpack();
    return eme;
  }

  // Decrypt button
  $('decrypt-btn')?.addEventListener('click', () => {
    const w = state.hdWalletModule;
    if (!w || !state.hdRoot) {
      alert('Please login first.');
      return;
    }

    const payloadStr = $('decrypt-payload')?.value?.trim();
    if (!payloadStr) {
      alert('Paste an EME payload to decrypt.');
      return;
    }

    try {
      const payload = parseEMEPayload(payloadStr);
      const senderPubRaw = hexToBytesStrict(payload.EPHEMERAL_PUBLIC_KEY, null);
      const tag = hexToBytesStrict(payload.TAG, 16);
      const iv = hexToBytesStrict(payload.IV, 12);
      const salt = hexToBytesStrict(payload.SALT, 32);

      // ENCRYPTED_BLOB can be a number array (from EMET) or hex string
      let ciphertext;
      if (Array.isArray(payload.ENCRYPTED_BLOB)) {
        ciphertext = new Uint8Array(payload.ENCRYPTED_BLOB);
      } else {
        ciphertext = hexToBytesStrict(payload.ENCRYPTED_BLOB, null);
      }

      const keyType = getMessagingKeyType();
      const path = getMessagingHDPath(keyType);

      // Prefer payload algorithm; fall back to current UI selection.
      const algoParams = typeof payload.ENCRYPTION_ALGORITHM_PARAMETERS === 'string'
        ? payload.ENCRYPTION_ALGORITHM_PARAMETERS.toLowerCase()
        : '';
      const algorithm = algoParams.includes('x25519')
        ? 'x25519'
        : (messagingKeyDefaults[keyType]?.algorithm || 'secp256k1');

      const senderPub = normalizeRecipientPublicKeyForAlgorithm(algorithm, senderPubRaw);

      // Derive recipient private key from configured path.
      const derived = deriveHDKey(path);
      const recipientPriv = derived.privateKey();
      derived.wipe();

      let shared = null;
      let aesKey = null;
      try {
        // 1. ECDH shared secret (using sender's public key)
        shared = algorithm === 'x25519'
          ? w.curves.x25519.ecdh(recipientPriv, senderPub)
          : w.curves.secp256k1.ecdh(recipientPriv, senderPub);

        // 2. HKDF: derive same AES key
        const info = eciesInfoForAlgorithm(algorithm);
        aesKey = w.utils.hkdf(shared, salt, info, 32);

        // 3. AES-256-GCM decrypt
        const decrypted = w.utils.aesGcm.decrypt(aesKey, ciphertext, tag, iv);
        const decStr = new TextDecoder().decode(decrypted);

        $('decrypt-result-value').textContent = decStr;

        // Switch to result step
        $('decrypt-step-input').style.display = 'none';
        $('decrypt-step-result').style.display = 'block';
      } finally {
        wipeBytes(recipientPriv);
        wipeBytes(shared);
        wipeBytes(aesKey);
      }
    } catch (err) {
      console.error('Decryption failed:', err);
      alert('Decryption failed: ' + err.message);
    }
  });

  // Enable decrypt button when payload is pasted
  $('decrypt-payload')?.addEventListener('input', () => {
    const btn = $('decrypt-btn');
    if (btn) btn.disabled = !$('decrypt-payload')?.value?.trim();
  });

  // Back button: encrypt result -> compose
  $('encrypt-back-btn')?.addEventListener('click', () => {
    $('encrypt-step-result').style.display = 'none';
    $('encrypt-step-compose').style.display = 'block';
  });

  // Back button: decrypt result -> input
  $('decrypt-back-btn')?.addEventListener('click', () => {
    $('decrypt-step-result').style.display = 'none';
    $('decrypt-step-input').style.display = 'block';
  });
}

// =============================================================================
// Homepage Handlers
// =============================================================================

function setupHomepageHandlers() {
  // Version tag
  const versionTag = $('version-tag');
  if (versionTag) {
    try {
      const pkg = __APP_VERSION__;
      versionTag.textContent = pkg ? `v${pkg}` : '';
    } catch { /* ignore */ }
  }

  // Code copy buttons
  document.querySelectorAll('.code-copy-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const code = btn.closest('.code-block')?.querySelector('code');
      if (code) {
        safeCopyText(code.textContent).then((copied) => {
          if (!copied) return;
          btn.title = 'Copied!';
          setTimeout(() => { btn.title = 'Copy code'; }, 2000);
        });
      }
    });
  });
}

// =============================================================================
// Initialization
// =============================================================================

export async function init(rootElement, options = {}) {
  const { autoOpenWallet = false, onLogin = null, openAccountAfterLogin = true } = typeof rootElement === 'object' && !(rootElement instanceof Node)
    ? (options = rootElement, {}) : options;
  if (rootElement && rootElement instanceof Node) _root = rootElement;
  if (typeof onLogin === 'function') _onLoginCallback = onLogin;
  _openAccountAfterLogin = openAccountAfterLogin;

  // Inject modal HTML if not already present in the DOM
  if (!document.getElementById('keys-modal')) {
    const container = document.createElement('div');
    container.id = 'hd-wallet-ui-container';
    container.innerHTML = getModalHTML();
    document.body.appendChild(container);
  }

  const status = $('status');
  const loadingOverlay = $('loading-overlay');

  // Initialize grid animation
  initGridAnimation();

  // Initialize wallet info box state
  initWalletInfoBox();
  bindInfoHandlers();

  try {
    // Load HD wallet WASM
    if (status) status.textContent = 'Loading HD wallet module...';
    state.hdWalletModule = await initHDWallet();

    // Load saved PKI keys if available.
    // (If not logged in yet, this will return false since encrypted keys require the session key.)
    const hasSavedKeys = await loadPKIKeys();

    state.initialized = true;

    // Update nav status
    const navStatus = $('nav-status');
    if (navStatus) {
      navStatus.className = 'nav-status ready';
    }

    // Hide loading overlay with fade
    if (loadingOverlay) {
      loadingOverlay.classList.add('hidden');
      setTimeout(() => {
        loadingOverlay.style.display = 'none';
      }, 500);
    }

    setupLoginHandlers();
    setupMainAppHandlers();
    initCurrencySelector();
    setupHomepageHandlers();

    // Handle initial hash navigation
    const initialHash = window.location.hash.slice(1);
    const normalizedTab = normalizeTabHash(initialHash);
    if (normalizedTab) {
      const tabEl = $(`${normalizedTab}-tab`);
      if (tabEl) {
        setTimeout(() => {
          tabEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
          $qa('.nav-link[data-tab]').forEach(link => {
            link.classList.remove('active');
            if (link.dataset.tab === normalizedTab) {
              link.classList.add('active');
            }
          });
        }, 100);
      }
    }

    // Check if there's a stored wallet
    const storageMetadata = WalletStorage.getStorageMetadata();
    const hasStoredWallet = storageMetadata?.method && storageMetadata.method !== StorageMethod.NONE;

    // Auto-open login modal if stored wallet found (opt-in for integrators)
    if (hasStoredWallet && autoOpenWallet) {
      const loginModal = $('login-modal');
      if (loginModal) {
        loginModal.classList.add('active');
        // Switch to stored wallet tab
        const storedTab = loginModal.querySelector('[data-tab="stored"]');
        if (storedTab) storedTab.click();
      }
    }

    // Auto-login with saved PKI keys if no stored wallet
    if (hasSavedKeys && !hasStoredWallet) {
      const tempEd25519Seed = hdWallet().utils.getRandomBytes(32);
      const tempKeys = {
        x25519: generateKeyPair(Curve.X25519),
        ed25519: {
          privateKey: tempEd25519Seed,
          publicKey: hdWallet().curves.ed25519.publicKeyFromSeed(tempEd25519Seed),
        },
        secp256k1: generateKeyPair(Curve.SECP256K1),
        p256: await p256GenerateKeyPairAsync(),
        p384: await p384GenerateKeyPairAsync(),
      };

      login(tempKeys);
    }

  } catch (err) {
    console.error('Initialization failed:', err);
    if (status) status.textContent = `Error: ${err.message}`;
  }
}

/**
 * Create a wallet UI instance that can be controlled programmatically.
 * Consumers attach openLogin / openAccount to their own buttons.
 *
 * @param {Node}   [rootElement]  - Optional root element for DOM queries
 * @param {Object} [options]      - Options passed to init()
 * @param {Function} [options.onLogin] - Callback fired after successful login with
 *   `{ xpub, signingPublicKey, sign(message) }` for SDN identity (BIP-44 coin type 0)
 * @param {boolean}  [options.openAccountAfterLogin=true] - When false, the Account
 *   modal will NOT auto-open after login. Useful for integrations that handle
 *   post-login UX themselves (e.g. challenge-response auth flows).
 * @returns {Promise<{openLogin: Function, openAccount: Function, destroy: Function}>}
 */
export async function createWalletUI(rootElement, options = {}) {
  await init(rootElement, options);

  return {
    /** Open the login modal */
    openLogin() {
      const modal = document.getElementById('login-modal');
      if (modal) modal.classList.add('active');
    },
    /** Open the account / keys modal (requires login first) */
    openAccount() {
      const modal = document.getElementById('keys-modal');
      if (modal) modal.classList.add('active');
    },
    /** Remove all injected wallet UI elements from the DOM */
    destroy() {
      const container = document.getElementById('hd-wallet-ui-container');
      if (container) container.remove();
    },
  };
}
