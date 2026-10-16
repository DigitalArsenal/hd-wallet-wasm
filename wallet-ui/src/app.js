/**
 * HD Wallet UI - Main Application (the in-page demo behind the landing page)
 *
 * This file keeps login, the session and the wiring. The account view itself
 * lives in its own modules:
 *
 *   account-view.js   shell, identity bar, section tabs, #account/<section> routing
 *   identity-keys.js  per-account Ed25519 / X25519 keys, peer ID, storage fingerprint
 *   account-storage.js  hdw:<fp>:… namespaced storage and the 2.x migration
 *   contact-card.js   the signed $EPM contact card
 *   envelopes.js      $PNM / $REC / $ENC / $FIL / $EPM builders (spec §4)
 *   profile-ui.js, messages-ui.js, people-ui.js, assets-ui.js, settings-ui.js
 *
 * Private keys are never kept: every operation derives the key it needs from
 * the session seed and zeroes it afterwards. The session holds only the seed
 * (zeroed at logout), the BIP-32 root handle and public identity values.
 */

// =============================================================================
// External Imports
// =============================================================================

import initHDWallet from 'hd-wallet-wasm';
import { Buffer } from 'buffer';

// Make Buffer available globally for various crypto libraries
window.Buffer = Buffer;

// =============================================================================
// Local Module Imports
// =============================================================================

import { getModalHTML } from './template.js';
import { createSeedSlots, flashResult } from './seed-slots.js';
import { createExternalWalletPanel } from './external/panel.js';
import { decodeBase58 } from './external/accounts.js';
import {
  ACTIVE_REMEMBERED_WALLET_KEY,
  PENDING_REMEMBERED_WALLET_KEY,
  deleteQuarantinedWalletRecord,
  exportQuarantinedWalletRecord,
  inspectLegacyWalletQuarantine,
  inspectRememberedWalletStorage,
} from './wallet-storage.js';
import { clearSecretClipboard, copySecretText, safeCopyText } from './clipboard.js';
import { normalizeTabHash } from './hash.js';
import { SessionGenerationGuard } from './session-generation.js';
import { createWalletOriginApp } from '../origin-app/app.mjs';
import { PhotoUrlController } from '../origin-app/photo.mjs';
import { resolveRegistryBinding } from '../origin-app/registry.mjs';
import { cryptoConfig } from './constants.js';
import {
  apiUrl,
  fetchBtcBalance,
  fetchEthBalance,
  fetchSolBalance,
  truncateAddress,
} from './address-derivation.js';
import {
  accountXprv,
  accountXpub,
  buildLoginPayload,
  chainPaths,
  deriveAccountAddresses,
  deriveIdentity,
  namespaceFingerprint,
  normalizeAccount,
  shortAddress,
  withChainKey,
  withEdKey,
  withXKey,
} from './identity-keys.js';
import {
  browserStorage,
  createAccountStorage,
  dropLegacySecrets,
  migrateLegacyStorage,
  readCurrency,
  writeCurrency,
} from './account-storage.js';
import {
  contactCardBytes,
  contactCardFileName,
  contactFromCardBytes,
  initialsOf,
  normalizeProfile,
  photoBytesFromDataUrl,
  sanitizeStoredContact,
  upsertContact,
} from './contact-card.js';
import { createAccountShell, isAccountHash, parseAccountHash } from './account-view.js';
import { createProfilePane } from './profile-ui.js';
import { createMessagesPane } from './messages-ui.js';
import { createPeoplePane } from './people-ui.js';
import { createAssetsPane, ASSET_CHAINS } from './assets-ui.js';
import { createSettingsPane } from './settings-ui.js';
import { downloadBytes, setBusy } from './ui-dom.js';
import { createBalanceScanner } from './balances.js';
import { buildEthTransaction, createSendFlow } from './send-flow.js';
import {
  MIN_GUESSES_LOG10,
  assessNewPassword,
  canonicalizeUsername,
  deriveLegacyPasswordSeed,
  derivePasswordSeed,
  loadStrengthEstimator,
} from './password-login.js';
import {
  ETH_MAINNET_CHAIN_ID,
  assertEthTransactionMatches,
  decodeEip1559,
  parseEthRecipient,
} from './send-safety.js';

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

const $qa = (sel) => {
  const list = _root.querySelectorAll(sel);
  if (list.length > 0 || _root === document) return list;
  return document.querySelectorAll(sel);
};

function createNode(tag, className, text) {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (text !== undefined) element.textContent = String(text);
  return element;
}

function appendTrustedStaticTemplate(container, source) {
  const parser = new DOMParser();
  const parsed = parser.parseFromString(String(source), 'text/html');
  const nodes = Array.from(parsed.body.childNodes, (child) => document.importNode(child, true));
  container.replaceChildren(...nodes);
}

function setStaticSymbol(element, symbol, label) {
  if (!element) return;
  element.replaceChildren(document.createTextNode(symbol));
  if (label) element.setAttribute('aria-label', label);
}

// =============================================================================
// Wallet Info Box (dismissible notice)
// =============================================================================

function dismissWalletInfo() {
  try { localStorage.setItem('walletInfoDismissed', '1'); } catch { /* per-viewer only */ }
  $('wallet-info-expanded').style.display = 'none';
  $('wallet-info-collapsed').style.display = 'flex';
}

function showWalletInfo() {
  try { localStorage.removeItem('walletInfoDismissed'); } catch { /* per-viewer only */ }
  $('wallet-info-expanded').style.display = 'flex';
  $('wallet-info-collapsed').style.display = 'none';
}

function initWalletInfoBox() {
  let dismissed = false;
  try { dismissed = localStorage.getItem('walletInfoDismissed') === '1'; } catch { /* default shown */ }
  if (dismissed && $('wallet-info-expanded')) {
    $('wallet-info-expanded').style.display = 'none';
    $('wallet-info-collapsed').style.display = 'flex';
  }
}

function bindInfoHandlers() {
  $('wallet-info-dismiss')?.addEventListener('click', dismissWalletInfo);
  $('wallet-info-collapsed')?.addEventListener('click', showWalletInfo);
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

function bytesToHexStr(bytes) {
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, '0')).join('');
}

// =============================================================================
// State
// =============================================================================

// Integration callback — set via options.onLogin in init
let _onLoginCallback = null;

// When false, login() will NOT auto-open the account view after authentication.
let _openAccountAfterLogin = true;

// Trust event surface (owner 2026-08-21): consuming apps (SDN dashboard,
// /beta) receive trust lifecycle + drain alerts through the init
// onTrustEvent option AND through the external wallet panel controller's
// notifyTrustEvent.
let _onTrustEventCallback = null;
let _externalPanelController = null;

function dispatchTrustEvent(event) {
  const stamped = { at: Date.now(), ...event };
  _externalPanelController?.notifyTrustEvent?.(stamped);
  if (typeof _onTrustEventCallback === 'function') {
    try {
      _onTrustEventCallback(stamped);
    } catch (e) {
      console.warn('onTrustEvent callback failed:', e);
    }
  }
}

const TRUST_SCAN_MIN_INTERVAL_MS = 2 * 60 * 1000;
const TRUST_SCAN_FAIL_COOLDOWN_MS = 5 * 60 * 1000;
const MAX_CONTACT_CARD_BYTES = 256 * 1024;

function emptyAddresses() {
  return { btc: null, eth: null, sol: null };
}

const state = {
  initialized: false,
  loggedIn: false,
  // 'seed' (mnemonic), 'password' (password-derived seed) or 'external'
  sessionKind: null,
  selectedCrypto: 'btc',
  addresses: { btc: null, eth: null, sol: null },
  // HD wallet state
  hdWalletModule: null,
  masterSeed: null,
  hdRoot: null,
  // The current BIP-44 account number and its public identity
  account: 0,
  identity: null,
  chainAccounts: null,
  storage: null,
  externalAccount: null,
  // Balances for the current account's addresses
  balances: {},
  balanceUpdatedAt: 0,
  balanceError: '',
  balanceScanning: false,
  balanceGeneration: null,
  prices: null,
  // Trust
  trustTransactions: [],
  trustRelationships: [],
  trustCheckedAt: 0,
  trustScanning: false,
  trustError: '',
};
const legacySessionGuard = new SessionGenerationGuard();
const walletOriginRegistry = Object.freeze({ resolveRegistryBinding });

function currentLegacySession() {
  return legacySessionGuard.capture();
}

function isCurrentLegacySession(sessionGeneration) {
  return state.loggedIn && legacySessionGuard.isCurrent(sessionGeneration);
}

function isHdSession() {
  return state.loggedIn
    && (state.sessionKind === 'seed' || state.sessionKind === 'password' || state.sessionKind === 'password-legacy')
    && state.masterSeed instanceof Uint8Array && Boolean(state.hdRoot);
}

/** A wallet opened with the retired fast password method: read-only. */
function isLegacyPasswordSession() {
  return isHdSession() && state.sessionKind === 'password-legacy';
}

// =============================================================================
// Password strength and sign-in (SEC-015)
// =============================================================================
//
// New password wallets derive through the memory-hard scrypt profile
// (password-login.js: native canonicalization, length and common-password
// policy, scrypt N=2^16 r=8 p=1, cross-checked against the native profile).
// Sign-in is gated on a zxcvbn guess estimate, never on character classes.
// Wallets from the retired fast method open read-only and can only sweep
// their funds to a new wallet.

const LEGACY_READ_ONLY_MESSAGE = 'This wallet uses the old password method and is read-only. Move its funds to a new wallet from Assets.';
let _strengthEstimator = null;
let _strengthLoadFailed = false;

function ensureStrengthEstimator() {
  if (_strengthEstimator) return Promise.resolve(_strengthEstimator);
  return loadStrengthEstimator().then((estimator) => {
    _strengthEstimator = estimator;
    _strengthLoadFailed = false;
    updatePasswordStrength($('wallet-password')?.value ?? '');
    emitEvent('migration');
    return estimator;
  }, (error) => {
    _strengthLoadFailed = true;
    updatePasswordStrength($('wallet-password')?.value ?? '');
    throw error;
  });
}

function setPasswordFeedback(text, { error = false } = {}) {
  const feedback = $('password-feedback');
  if (!feedback) return;
  feedback.textContent = text;
  feedback.classList.toggle('is-error', Boolean(error && text));
}

function paintStrength(guessesLog10) {
  const fill = $('strength-fill');
  if (!fill) return;
  // The threshold mark sits at 75%: 10^MIN_GUESSES_LOG10 guesses.
  const percentage = Math.max(0, Math.min(100, (guessesLog10 / MIN_GUESSES_LOG10) * 75));
  fill.style.width = `${percentage}%`;
  const ratio = percentage / 100;
  let r;
  let g;
  if (ratio < 0.5) {
    r = 180 + Math.round(75 * (ratio / 0.5));
    g = Math.round(140 * (ratio / 0.5));
  } else {
    r = 255 - Math.round(200 * ((ratio - 0.5) / 0.5));
    g = 140 + Math.round(115 * ((ratio - 0.5) / 0.5));
  }
  fill.style.background = `rgb(${r}, ${g}, 30)`;
}

function updatePasswordStrength(password) {
  const bits = $('entropy-bits');
  const btn = $('derive-from-password');
  const legacyBtn = $('derive-from-legacy-password');
  const username = $('wallet-username')?.value ?? '';
  if (legacyBtn) legacyBtn.disabled = !username || !password;
  if (!password) {
    if (bits) bits.textContent = '0';
    paintStrength(0);
    setPasswordFeedback('');
    if (btn) btn.disabled = true;
    return;
  }
  if (!_strengthEstimator) {
    if (btn) btn.disabled = true;
    if (bits) bits.textContent = '0';
    paintStrength(0);
    if (_strengthLoadFailed) {
      setPasswordFeedback('The password checker could not load, so password sign-in is unavailable.', { error: true });
    } else {
      setPasswordFeedback('Loading the password checker…');
      void ensureStrengthEstimator().catch(() => {});
    }
    return;
  }
  const assessment = assessNewPassword({ username, password, estimator: _strengthEstimator });
  if (bits) bits.textContent = String(Math.round(assessment.bits));
  paintStrength(assessment.guessesLog10);
  setPasswordFeedback(assessment.ok ? 'Strong enough for a password wallet.' : assessment.message, { error: !assessment.ok });
  if (btn) btn.disabled = !assessment.ok;
}

// =============================================================================
// Key Derivation
// =============================================================================

async function deriveKeysFromPassword(username, password) {
  const seed = await derivePasswordSeed(hdWallet(), { username, password });
  try {
    return installMasterSeed(seed);
  } finally {
    seed.fill(0);
  }
}

async function deriveKeysFromLegacyPassword(username, password) {
  const seed = await deriveLegacyPasswordSeed(hdWallet(), { username, password });
  try {
    return installMasterSeed(seed);
  } finally {
    seed.fill(0);
  }
}

async function deriveKeysFromSeed(seedPhrase) {
  // The phrase that was validated is the phrase that is derived (B20): the
  // word slots already hand over lowercase words joined by single spaces.
  const normalized = String(seedPhrase).trim().toLowerCase().split(/\s+/u).join(' ');
  const seed = state.hdWalletModule.mnemonic.toSeed(normalized);
  const seedBytes = seed instanceof Uint8Array ? seed : new Uint8Array(seed);

  try {
    return installMasterSeed(seedBytes);
  } finally {
    // Seed phrase strings can't be wiped; we just avoid storing them.
    seedBytes.fill(0);
  }
}

/** Copy the seed into the session and build the BIP-32 root. */
function installMasterSeed(masterSeedBytes) {
  wipeSession();
  state.masterSeed = new Uint8Array(masterSeedBytes);
  state.hdRoot = state.hdWalletModule.hdkey.fromSeed(state.masterSeed);
  return true;
}

function generateSeedPhrase() {
  return state.hdWalletModule.mnemonic.generate(24);
}

function validateSeedPhrase(phrase) {
  return state.hdWalletModule.mnemonic.validate(phrase.trim().toLowerCase());
}

// The login modal's seed word slots (seed-slots.js). They are the only place
// the typed, pasted or generated phrase lives; readSeedPhrase() is the single
// way to read it.
let _seedSlots = null;
let _seedSlotsMaskChanged = () => {};

function readSeedPhrase() {
  return _seedSlots ? _seedSlots.read() : '';
}

function clearSeedPhrase() {
  _seedSlots?.clear();
  _seedSlotsMaskChanged();
}

function seedPhraseIsValid(phrase) {
  if (!phrase || !state.hdWalletModule || _seedSlots?.overflow) return false;
  try {
    return Boolean(validateSeedPhrase(phrase));
  } catch {
    return false;
  }
}

// Login is enabled for a valid phrase of 12 or more words (never after a
// paste of more than 24 words).
function updateSeedLoginButton() {
  const deriveBtn = $('derive-from-seed');
  if (!deriveBtn) return;
  const phrase = readSeedPhrase();
  deriveBtn.disabled = !(phrase && phrase.split(' ').length >= 12 && seedPhraseIsValid(phrase));
}

function seedWordIsUnknown(word) {
  try {
    return !state.hdWalletModule.mnemonic.checkWord(word);
  } catch {
    return false;
  }
}

// =============================================================================
// Session identity (account N)
// =============================================================================

/** Derive the identity, addresses and storage of account N for the HD session. */
function deriveAccountSession(account) {
  const wasm = hdWallet();
  const n = normalizeAccount(account);
  state.account = n;
  state.identity = deriveIdentity(wasm, state.masterSeed, n);
  state.chainAccounts = deriveAccountAddresses(wasm, state.hdRoot, n);
  state.addresses = {
    btc: state.chainAccounts.btc.address,
    eth: state.chainAccounts.eth.address,
    sol: state.chainAccounts.sol.address,
  };
  state.balances = {};
  state.balanceUpdatedAt = 0;
  state.balanceError = '';
  state.trustTransactions = [];
  state.trustRelationships = [];
  state.trustCheckedAt = 0;
  state.trustError = '';
}

function notifyLogin() {
  if (!_onLoginCallback || !isHdSession() || !state.identity) return;
  try {
    _onLoginCallback(buildLoginPayload({ rootXpub: state.hdRoot.toXpub(), identity: state.identity }));
  } catch (err) {
    console.error('onLogin callback error:', err);
  }
}

function scopedEdKey(fn) {
  if (!isHdSession()) throw new Error('This needs a seed-phrase session.');
  if (isLegacyPasswordSession()) throw new Error(LEGACY_READ_ONLY_MESSAGE);
  return withEdKey(hdWallet(), state.masterSeed, state.account, fn);
}

function scopedXKey(fn) {
  if (!isHdSession()) throw new Error('This needs a seed-phrase session.');
  return withXKey(hdWallet(), state.masterSeed, state.account, fn);
}

// A read-only (old password method) session signs nothing but the sweep:
// withSweepSigning() opens this gate for the synchronous signing step of a
// sweep plan that prepareSendFromAccount checked.
let _sweepSigning = false;

function scopedChainKey(path, fn) {
  if (!isHdSession()) throw new Error('This needs a seed-phrase session.');
  if (isLegacyPasswordSession() && !_sweepSigning) throw new Error(LEGACY_READ_ONLY_MESSAGE);
  return withChainKey(state.hdRoot, path, fn);
}

function withSweepSigning(run) {
  _sweepSigning = true;
  try {
    return run();
  } finally {
    _sweepSigning = false;
  }
}

// =============================================================================
// Profile and contacts (namespaced storage)
// =============================================================================

const _events = new Map();

function onEvent(name, handler) {
  if (!_events.has(name)) _events.set(name, new Set());
  _events.get(name).add(handler);
  return () => _events.get(name)?.delete(handler);
}

function emitEvent(name) {
  for (const handler of [..._events.get(name) ?? []]) {
    try { handler(); } catch (e) { console.warn(`account ${name} listener failed:`, e); }
  }
}

function readProfile() {
  if (!state.storage) return normalizeProfile({});
  return normalizeProfile(state.storage.read(state.account, 'profile', {}));
}

function saveProfile(profile) {
  if (!state.storage) return;
  state.storage.write(state.account, 'profile', normalizeProfile(profile));
  void refreshIdentityBar();
  emitEvent('profile');
}

function readContacts() {
  if (!state.storage) return [];
  const raw = state.storage.read(state.account, 'contacts', []);
  return (Array.isArray(raw) ? raw : []).map(sanitizeStoredContact).filter(Boolean);
}

function writeContacts(contacts) {
  state.storage?.write(state.account, 'contacts', contacts);
  emitEvent('contacts');
}

async function loadEnvelopes() {
  return import('./envelopes.js');
}

async function importContactFile(file) {
  if (!isHdSession()) throw new Error('This needs a seed-phrase session.');
  if (!file || !Number.isSafeInteger(file.size) || file.size <= 0 || file.size > MAX_CONTACT_CARD_BYTES) {
    throw new Error('This is not an SDS contact card (.epm).');
  }
  const sessionGeneration = currentLegacySession();
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (!isCurrentLegacySession(sessionGeneration)) throw new Error('Wallet session ended');
  const envelopes = await loadEnvelopes();
  const contact = contactFromCardBytes(hdWallet(), envelopes, bytes);
  if (!isCurrentLegacySession(sessionGeneration)) throw new Error('Wallet session ended');
  writeContacts(upsertContact(readContacts(), contact));
  return contact;
}

function removeContact(peerId) {
  writeContacts(readContacts().filter((contact) => contact.peerId !== peerId));
}

async function buildContactCard() {
  if (!isHdSession()) throw new Error('This needs a seed-phrase session.');
  const wasm = hdWallet();
  const profile = readProfile();
  const envelopes = await loadEnvelopes();
  if (!isHdSession()) throw new Error('Wallet session ended');
  const bytes = contactCardBytes(wasm, envelopes, {
    profile,
    identity: state.identity,
    addresses: state.chainAccounts,
    withChainKey: scopedChainKey,
    withEdKey: scopedEdKey,
  });
  return { bytes, fileName: contactCardFileName(profile.name) };
}

// =============================================================================
// Balances: the current account's three addresses
// =============================================================================

const CHAIN_FETCHERS = Object.freeze({ btc: fetchBtcBalance, eth: fetchEthBalance, sol: fetchSolBalance });

// The balance cache lives with the account (hdw:<fp>:a<N>:scan-cache); an
// external session keeps it in memory only.
let _memoryBalanceCache = {};

function readBalanceCache() {
  if (state.storage) {
    const cache = state.storage.read(state.account, 'scan-cache', {});
    return cache && typeof cache === 'object' && !Array.isArray(cache) ? cache : {};
  }
  return _memoryBalanceCache;
}

function writeBalanceCache(cache) {
  if (state.storage) state.storage.write(state.account, 'scan-cache', cache);
  else _memoryBalanceCache = cache;
}

const balanceScanner = createBalanceScanner({
  fetchers: CHAIN_FETCHERS,
  readCache: readBalanceCache,
  writeCache: writeBalanceCache,
});

/** The scan targets: exactly the current account's addresses (3), or the connected one. */
function balanceTargets() {
  return ['btc', 'eth', 'sol']
    .filter((chain) => state.addresses?.[chain])
    .map((chain) => ({ chain, address: state.addresses[chain] }));
}

/**
 * Fetch the balances of the current account's addresses: 3 requests at most
 * (the 2-minute cache answers the rest), then the prices once.
 */
async function refreshBalances({ force = false } = {}) {
  const sessionGeneration = currentLegacySession();
  if (!isCurrentLegacySession(sessionGeneration)) return;
  if (state.balanceScanning && state.balanceGeneration === sessionGeneration) return;
  state.balanceScanning = true;
  state.balanceGeneration = sessionGeneration;
  state.balanceError = '';
  const account = state.account;
  const current = () => isCurrentLegacySession(sessionGeneration) && account === state.account;
  emitEvent('assets');
  try {
    const targets = balanceTargets();
    const { balances, failures, cancelled } = await balanceScanner.scan(targets, current, { force });
    if (cancelled || !current()) return;
    Object.assign(state.balances, balances);
    if (state.externalAccount) {
      state.externalAccount.balance = state.balances[state.externalAccount.chain] ?? state.externalAccount.balance;
    }
    try {
      state.prices = await fetchCryptoPrices(getSelectedCurrency());
    } catch (e) {
      console.warn('Price fetch failed:', e?.message || e);
    }
    if (!current()) return;
    state.balanceUpdatedAt = Date.now();
    state.balanceError = failures === targets.length && targets.length > 0 ? 'Balances are unavailable right now.' : '';
  } finally {
    if (state.balanceGeneration === sessionGeneration) {
      state.balanceScanning = false;
      state.balanceGeneration = null;
      emitEvent('assets');
    }
  }
}

function assetsState() {
  const currency = getSelectedCurrency();
  const prices = state.prices;
  let total = 0;
  let priced = false;
  const rows = ASSET_CHAINS
    .filter((chain) => state.addresses?.[chain.id])
    .map((chain) => {
      const balance = state.balances[chain.id] ?? '--';
      const amount = Number.parseFloat(balance);
      const price = Number.parseFloat(prices?.[chain.ticker]);
      let valueText = '';
      if (Number.isFinite(amount) && Number.isFinite(price) && price > 0) {
        const value = amount * price;
        total += value;
        priced = true;
        valueText = formatCurrencyValue(value, currency);
      }
      return {
        chain: chain.id,
        address: state.addresses[chain.id],
        path: state.chainAccounts?.[chain.id]?.path ?? '',
        balance,
        valueText,
      };
    });
  return {
    rows,
    currency,
    updatedAt: state.balanceUpdatedAt,
    totalText: priced || state.balanceUpdatedAt ? formatCurrencyValue(total, currency) : '--',
    scanning: state.balanceScanning,
    error: state.balanceError,
  };
}

// =============================================================================
// Send (Bitcoin and Ethereum): prepare → review the DECODED transaction → send
// =============================================================================

// send-flow.js builds the unsigned transaction at review time and shows the
// recipient and amount decoded from its bytes; Send signs that exact plan and
// refuses to broadcast unless the signed bytes decode to it (SEC-014/057).
let _sendFlow = null;

function sendFlow() {
  if (!_sendFlow) {
    _sendFlow = createSendFlow({
      wasm: hdWallet,
      ethRpc,
      fetchBtcUtxos: (address) => fetchVerifiedBtcUtxos(address),
      broadcastBtc: (rawHex) => broadcastBtcTx(rawHex),
      withChainKey: (path, fn) => scopedChainKey(path, fn),
      btcSign: (opts) => signBtcTransaction(opts),
    });
  }
  return _sendFlow;
}

let _trustModule = null;
async function trustModule() {
  _trustModule ??= await import('./blockchain-trust.js');
  return _trustModule;
}

async function fetchVerifiedBtcUtxos(address) {
  return (await trustModule()).fetchBtcUtxos(address);
}

async function broadcastBtcTx(rawHex) {
  return (await trustModule()).broadcastBtcRawTx(rawHex);
}

// Called inside the scoped-key callback, which is synchronous; prepare()
// has already loaded the module.
function signBtcTransaction(opts) {
  if (!_trustModule) throw new Error('Bitcoin signer not loaded.');
  return _trustModule.btcSignedTransaction(opts);
}

/**
 * Review step: parse, fetch, build unsigned and decode. Returns the plan the
 * review screen shows (plan.review) and Send executes.
 */
async function prepareSendFromAccount({ chain, to, amount, sweep = false }) {
  const sessionGeneration = currentLegacySession();
  if (!isHdSession()) throw new Error('Sending needs a seed-phrase session.');
  if (isLegacyPasswordSession() && !sweep) throw new Error(LEGACY_READ_ONLY_MESSAGE);
  // A sweep moves a read-only (old password method) wallet's whole balance,
  // and only ever to the new wallet the migration just derived.
  if (sweep && (!isLegacyPasswordSession() || !state.migrationDestination?.[chain]
      || String(to) !== state.migrationDestination[chain])) {
    throw new Error('Funds can only be swept to the new wallet set up on this page.');
  }
  const entry = state.chainAccounts?.[chain];
  if (!entry) throw new Error('No address for this chain.');
  if (chain === 'btc') await trustModule();
  const plan = await sendFlow().prepare({ chain, from: entry, to: String(to ?? ''), amount: String(amount ?? ''), sweep });
  if (!isCurrentLegacySession(sessionGeneration)) throw new Error('Wallet session ended');
  _preparedPlans.set(plan, { sessionGeneration, sweep });
  return plan;
}

const _preparedPlans = new WeakMap();

/** Send step: only a plan this session prepared (and the user reviewed). */
async function sendFromAccount(plan) {
  const prepared = _preparedPlans.get(plan);
  if (!prepared || !isCurrentLegacySession(prepared.sessionGeneration)) {
    throw new Error('Review the transaction again before sending.');
  }
  _preparedPlans.delete(plan);
  if (isLegacyPasswordSession() && !prepared.sweep) throw new Error(LEGACY_READ_ONLY_MESSAGE);
  const sessionGeneration = prepared.sessionGeneration;
  const txHash = prepared.sweep
    ? await withSweepSigning(() => sendFlow().execute(plan))
    : await sendFlow().execute(plan);
  if (isCurrentLegacySession(sessionGeneration)) {
    setTimeout(() => {
      if (isCurrentLegacySession(sessionGeneration)) void refreshBalances({ force: true });
    }, 5000);
  }
  return txHash;
}

const ETH_RPC = 'https://cloudflare-eth.com';

async function ethRpc(method, params) {
  const resp = await fetch(apiUrl(ETH_RPC), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  if (!resp.ok) throw new Error(`Ethereum RPC error ${resp.status}`);
  const data = await resp.json();
  if (data?.error) throw new Error(String(data.error.message ?? 'Ethereum RPC error'));
  return data?.result;
}

async function ethFeeParameters() {
  const block = await ethRpc('eth_getBlockByNumber', ['latest', false]);
  const baseFee = BigInt(block?.baseFeePerGas || '0x0');
  const maxPriorityFee = 2000000000n; // 2 gwei
  return { maxPriorityFee, maxFee: baseFee * 2n + maxPriorityFee };
}

function formatEth(wei) {
  const value = Number(wei) / 1e18;
  return `${value.toFixed(value < 0.001 ? 6 : 4)} ETH`;
}

async function ethSendFeeLine() {
  const { maxFee } = await ethFeeParameters();
  return `Network fee: up to ${formatEth(maxFee * 21000n)}`;
}

// =============================================================================
// Currency Conversion (Coinbase API, CoinGecko fallback)
// =============================================================================

const CURRENCY_SYMBOLS = {
  USD: '$', EUR: '€', GBP: '£', JPY: '¥', CAD: 'C$', AUD: 'A$', CHF: 'CHF ',
};

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
  return readCurrency();
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

  const results = await Promise.allSettled(
    cryptos.map(async (crypto) => {
      const url = apiUrl(`https://api.coinbase.com/v2/prices/${crypto}-${currency}/spot`);
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Coinbase HTTP ${res.status}`);
      const json = await res.json();
      return { crypto, price: json.data?.amount };
    })
  );
  results.forEach((r) => {
    if (r.status === 'fulfilled') setPrice(r.value.crypto, r.value.price);
  });

  // Secondary provider fallback when Coinbase is unavailable/rate-limited.
  const missing = cryptos.filter((symbol) => !Number.isFinite(prices[symbol]) || prices[symbol] <= 0);
  if (missing.length > 0) {
    try {
      const vs = currency.toLowerCase();
      const geckoUrl = apiUrl(`https://api.coingecko.com/api/v3/simple/price?ids=bitcoin,ethereum,solana&vs_currencies=${vs}`);
      const geckoRes = await fetch(geckoUrl);
      if (geckoRes.ok) {
        const gecko = await geckoRes.json();
        const idBySymbol = { BTC: 'bitcoin', ETH: 'ethereum', SOL: 'solana' };
        missing.forEach((symbol) => setPrice(symbol, gecko?.[idBySymbol[symbol]]?.[vs]));
      }
    } catch (e) {
      console.warn('CoinGecko price fallback failed:', e);
    }
  }

  const hasAnyPrice = cryptos.some((symbol) => Number.isFinite(prices[symbol]) && prices[symbol] > 0);
  if (!hasAnyPrice) {
    const staleSources = [priceCache, stored].filter((entry) =>
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
  const symbol = CURRENCY_SYMBOLS[currency] ?? `${currency} `;
  if (currency === 'JPY') return `${symbol}${Math.round(value).toLocaleString()}`;
  return `${symbol}${value.toFixed(2)}`;
}

async function setCurrency(currency) {
  if (!writeCurrency(currency)) return;
  priceCache = { data: null, currency: null, timestamp: 0 };
  state.prices = null;
  emitEvent('assets');
  if (!state.loggedIn) return;
  try {
    const prices = await fetchCryptoPrices(currency);
    if (getSelectedCurrency() === currency) {
      state.prices = prices;
      emitEvent('assets');
    }
  } catch (e) {
    console.warn('Price fetch failed:', e?.message || e);
  }
}

// =============================================================================
// Trust: scan, publish, revoke and drain watch (current account only)
// =============================================================================

let trustScanGeneration = null;
let trustNextAllowedAt = 0;

function readImportedTrust() {
  const raw = state.storage?.read(state.account, 'trust-imported-txs', []);
  return Array.isArray(raw) ? raw : [];
}

/**
 * Scan the current account's addresses for trust records. Runs when People
 * opens (at most once per two minutes) and on Refresh; never in the
 * background.
 */
async function runTrustScan(sessionGeneration = currentLegacySession(), { force = false } = {}) {
  if (!isCurrentLegacySession(sessionGeneration) || !state.addresses) return;
  if (state.trustScanning && trustScanGeneration === sessionGeneration) return;
  const now = Date.now();
  if (now < trustNextAllowedAt) return;
  if (!force && state.trustCheckedAt && now - state.trustCheckedAt < TRUST_SCAN_MIN_INTERVAL_MS) return;
  state.trustScanning = true;
  state.trustError = '';
  trustScanGeneration = sessionGeneration;
  const account = state.account;
  const addressesSnapshot = Object.freeze({ ...state.addresses });
  emitEvent('trust');

  try {
    const bt = await import('./blockchain-trust.js');
    if (!isCurrentLegacySession(sessionGeneration)) return;
    const onChainTxs = [];
    if (addressesSnapshot.btc) onChainTxs.push(...await bt.scanBitcoinTrustTransactions(addressesSnapshot.btc));
    if (!isCurrentLegacySession(sessionGeneration)) return;
    if (addressesSnapshot.sol) onChainTxs.push(...await bt.scanSolanaTrustTransactions(addressesSnapshot.sol));
    if (!isCurrentLegacySession(sessionGeneration)) return;
    if (addressesSnapshot.eth) onChainTxs.push(...await bt.scanEthereumTrustTransactions(addressesSnapshot.eth));
    if (!isCurrentLegacySession(sessionGeneration) || account !== state.account) return;

    const seen = new Set();
    const dedupedTxs = [...onChainTxs, ...readImportedTrust()].filter((tx) => {
      if (!tx?.txHash || seen.has(tx.txHash)) return false;
      seen.add(tx.txHash);
      return true;
    });
    const relationships = bt.analyzeTrustRelationships(addressesSnapshot, dedupedTxs);

    // Drain watch: monitor trusted counterparties' published addresses.
    await monitorTrustDrains(relationships, sessionGeneration);
    if (!isCurrentLegacySession(sessionGeneration) || account !== state.account) return;

    state.trustTransactions = dedupedTxs;
    state.trustRelationships = relationships;
    state.trustCheckedAt = Date.now();
    trustNextAllowedAt = 0;
  } catch (err) {
    if (!isCurrentLegacySession(sessionGeneration)) return;
    console.warn('Trust scan failed:', err?.message || err);
    trustNextAllowedAt = Date.now() + TRUST_SCAN_FAIL_COOLDOWN_MS;
    state.trustError = 'The trust check is delayed (endpoint limited).';
  } finally {
    if (trustScanGeneration === sessionGeneration) {
      state.trustScanning = false;
      trustScanGeneration = null;
      emitEvent('trust');
    }
  }
}

function clearTrustState() {
  trustScanGeneration = null;
  trustNextAllowedAt = 0;
  state.trustTransactions = [];
  state.trustRelationships = [];
  state.trustCheckedAt = 0;
  state.trustScanning = false;
  state.trustError = '';
}

const TX_HASH_HEX_RE = /^[0-9a-fA-F]{64}$/;
const EVM_ADDR_RE = /^0x[0-9a-fA-F]{40}$/;

// BTC/ETH hashes are 32-byte hex; Solana signatures are base58 — reduce
// any of them to the 64-hex/32-byte form the revocation record embeds.
function normalizeTxHashHex(hash) {
  const raw = String(hash ?? '').trim();
  const hex = raw.startsWith('0x') || raw.startsWith('0X') ? raw.slice(2) : raw;
  if (TX_HASH_HEX_RE.test(hex)) return hex.toLowerCase();
  const bytes = decodeBase58(raw);
  if (bytes && bytes.length === 32) return bytesToHexStr(bytes);
  throw new Error('Revocation needs a 32-byte original transaction hash (BTC/ETH hex or Solana signature).');
}

// Scanner chain names ('bitcoin'/'ethereum'/'solana', external 'eth'/'sol')
// -> publish-lane slug.
function chainForTxRecord(record) {
  const c = String(record?.chain || record?.network || '').toLowerCase();
  if (c.startsWith('bitcoin') || c === 'btc') return 'btc';
  if (c.startsWith('ethereum') || c === 'eth') return 'eth';
  if (c.startsWith('solana') || c === 'sol') return 'sol';
  return null;
}

// The outbound on-chain trust record we published toward `address` — the
// revocation must bind its hash.
function matchOutboundTrustTx(address) {
  const target = String(address ?? '').toLowerCase();
  const own = new Set(Object.values(state.addresses ?? {}).filter(Boolean).map((a) => a.toLowerCase()));
  return (state.trustTransactions || []).find((tx) =>
    tx.type === 'trust'
    && own.has(String(tx.from ?? '').toLowerCase())
    && String(tx.recipientPubkey ?? '').toLowerCase() === target
    && chainForTxRecord(tx) !== null
  ) || null;
}

function trustSupportsChain(chain) {
  if (state.externalAccount && !state.hdRoot) return chain === 'eth' || chain === 'sol';
  return ['btc', 'eth', 'sol'].includes(chain) && Boolean(state.addresses?.[chain]);
}

/**
 * Build, sign and broadcast a trust or revocation record on btc/eth/sol with
 * the CURRENT account's keys. External wallet: the connected provider signs
 * and sends (eth_sendTransaction / solana:signAndSendTransaction).
 *
 * @returns {Promise<{txHash: string, chain: string}>}
 */
async function publishTrustRecord({
  recordType,
  network,
  recipientAddress = null,
  level = null,
  originalTxHash = null,
}) {
  const bt = await import('./blockchain-trust.js');

  const metadataBytes = recordType === 'revocation'
    ? bt.encodeRevocationMetadata(normalizeTxHashHex(originalTxHash))
    : bt.encodeTrustMetadata(level, recipientAddress);

  const external = !!(state.externalAccount && !state.hdRoot);
  const paths = chainPaths(state.account);

  if (network === 'btc') {
    if (external) {
      throw new Error('Bitcoin trust publishing needs the built-in wallet (the external lane covers EVM and Solana).');
    }
    const sender = state.addresses.btc;
    const utxos = await bt.fetchBtcUtxos(sender);
    if (!utxos.length) throw new Error('No confirmed UTXOs — keep a small BTC balance to cover the trust fee.');
    const { rawHex } = scopedChainKey(paths.btc, (signPrivateKey) => bt.btcTrustTransaction({
      utxos, metadataBytes, changeAddress: sender, signPrivateKey, feeSats: 5000,
    }));
    return { txHash: await bt.broadcastBtcRawTx(rawHex), chain: 'btc' };
  }

  if (network === 'eth') {
    // The record is a zero-value transaction TO the trusted address: the
    // address is parsed strictly (SEC-014) and the built transaction is
    // decoded and compared before and after signing.
    const to = parseEthRecipient(recipientAddress).lower;
    if (external) {
      const ethSend = state.externalAccount.transport?.ethSendTransaction;
      if (!ethSend) throw new Error('The connected EVM wallet offers no eth_sendTransaction.');
      return { txHash: await ethSend({ to, data: metadataBytes, value: '0x0' }), chain: 'eth' };
    }
    const module = state.hdWalletModule;
    if (!module?.ethereum?.tx) throw new Error('Ethereum tx builder not available.');
    const sender = state.addresses.eth;
    const rpc = trustEthRpc(bt);
    const [nonceHex, head, chainIdHex] = await Promise.all([
      rpc('eth_getTransactionCount', [sender, 'pending']),
      rpc('eth_getBlockByNumber', ['latest', false]),
      rpc('eth_chainId', []),
    ]);
    // Trust records live on Ethereum mainnet; an RPC that answers for another
    // chain is not used.
    if (chainIdHex !== '0x1') throw new Error('The Ethereum RPC is not on mainnet.');
    if (typeof nonceHex !== 'string' || !/^0x[0-9a-f]{1,16}$/u.test(nonceHex)) throw new Error('The Ethereum RPC returned a malformed nonce.');
    if (typeof head?.baseFeePerGas !== 'string' || !/^0x[0-9a-f]{1,24}$/u.test(head.baseFeePerGas)) throw new Error('The Ethereum RPC returned a malformed base fee.');
    const baseFee = BigInt(head.baseFeePerGas);
    const maxPriorityFee = 2000000000n; // 2 gwei
    const expected = {
      chainId: ETH_MAINNET_CHAIN_ID,
      nonce: BigInt(nonceHex),
      maxFeePerGas: baseFee * 2n + maxPriorityFee,
      maxPriorityFeePerGas: maxPriorityFee,
      // 21000 base + 16/byte of data + margin; trust records are <= 80 bytes.
      gasLimit: 21000n + BigInt(metadataBytes.length * 16) + 4000n,
      to,
      value: 0n,
      data: metadataBytes,
    };
    const tx = buildEthTransaction(module, expected);
    let signed;
    try {
      assertEthTransactionMatches(decodeEip1559(tx.serialize()), expected, { signed: false });
      scopedChainKey(paths.eth, (signPrivateKey) => tx.sign(signPrivateKey));
      signed = tx.serialize();
    } finally {
      try { tx.destroy?.(); } catch { /* released either way */ }
    }
    assertEthTransactionMatches(decodeEip1559(signed), expected, { signed: true });
    const txHash = await rpc('eth_sendRawTransaction', ['0x' + bytesToHexStr(signed)]);
    return { txHash, chain: 'eth' };
  }

  if (network === 'sol') {
    const sender = state.addresses.sol;
    const recentBlockhash = await bt.solanaGetLatestBlockhash();
    if (external) {
      const solSend = state.externalAccount.transport?.solanaSignAndSendTransaction;
      if (!solSend) throw new Error('The connected Solana wallet offers no solana:signAndSendTransaction.');
      const { raw } = bt.buildSolanaTrustTx({
        feePayer: sender, recentBlockhash, metadataBytes, signPrivateKey: null,
      });
      const signature = await solSend(raw);
      const txHash = typeof signature === 'string' ? signature : bt.base58EncodeBytes(signature);
      return { txHash, chain: 'sol' };
    }
    const built = scopedChainKey(paths.sol, (signPrivateKey) => bt.buildSolanaTrustTx({
      feePayer: sender, recentBlockhash, metadataBytes, signPrivateKey,
    }));
    const txHash = await bt.broadcastSolanaRawTx(built.rawBase64);
    return { txHash, chain: 'sol' };
  }

  throw new Error(`Unsupported trust network: ${network}`);
}

function trustEthRpc(bt) {
  return async (method, params) => {
    let lastError = 'ETH RPC unavailable';
    for (const endpoint of bt.getEthereumTrustRpcEndpoints()) {
      try {
        const resp = await fetch(apiUrl(endpoint), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        });
        if (!resp.ok) { lastError = `HTTP ${resp.status}`; continue; }
        const data = await resp.json();
        if (data.error) { lastError = data.error.message || 'ETH RPC error'; continue; }
        return data.result;
      } catch (e) { lastError = e?.message || 'ETH RPC fetch failed'; }
    }
    throw new Error(`Cannot reach an Ethereum RPC (${lastError})`);
  };
}

async function trustFeeEstimate(network) {
  if (network === 'btc') return '5,000 sats';
  if (network === 'sol') return '0.000005 SOL';
  const bt = await import('./blockchain-trust.js');
  const head = await trustEthRpc(bt)('eth_getBlockByNumber', ['latest', false]);
  const baseFee = BigInt(head?.baseFeePerGas || '0x0');
  const maxFee = baseFee * 2n + 2000000000n;
  return formatEth(maxFee * (21000n + 80n * 16n + 4000n));
}

async function publishTrust({ network, level, recipientAddress }) {
  const sessionGeneration = currentLegacySession();
  if (!isCurrentLegacySession(sessionGeneration)) throw new Error('Wallet session ended');
  const { txHash } = await publishTrustRecord({ recordType: 'trust', network, level, recipientAddress });
  dispatchTrustEvent({ type: 'trust-published', network, level, recipientAddress, txHash });
  if (isCurrentLegacySession(sessionGeneration)) void runTrustScan(sessionGeneration, { force: true });
  return { txHash };
}

async function revokeTrust(record) {
  const sessionGeneration = currentLegacySession();
  if (!isCurrentLegacySession(sessionGeneration)) throw new Error('Wallet session ended');
  const network = chainForTxRecord(record);
  const { txHash } = await publishTrustRecord({
    recordType: 'revocation',
    network,
    recipientAddress: record.recipientPubkey,
    originalTxHash: normalizeTxHashHex(record.txHash),
  });
  dispatchTrustEvent({ type: 'trust-revoked', network, recipientAddress: record.recipientPubkey, txHash });
  if (isCurrentLegacySession(sessionGeneration)) void runTrustScan(sessionGeneration, { force: true });
  return { txHash };
}

// Drain watch: for every outbound/mutual relationship, monitor the trusted
// counterparty's published address balance client-side. A drop past the
// drain ratio from the last funded observation flags the relationship
// ("Drained" in People) and fires a drain trust event.
async function monitorTrustDrains(relationships, sessionGeneration) {
  if (!relationships || !relationships.length) return;
  const { evaluateTrustDrain, getTrustDrainDropRatio } = await import('./blockchain-trust.js');
  const dropRatio = getTrustDrainDropRatio();

  const detectChain = (address) => {
    const a = String(address ?? '').trim();
    if (EVM_ADDR_RE.test(a)) return 'eth';
    if (/^(1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$/.test(a) || /^bc1[a-z0-9]{25,90}$/.test(a)) return 'btc';
    if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(a)) return 'sol';
    return null;
  };

  const account = state.account;
  const stored = state.storage?.read(account, 'trust-drain-baselines', {}) ?? {};
  const baselines = stored && typeof stored === 'object' && !Array.isArray(stored) ? stored : {};
  let changed = false;

  const watched = relationships
    .filter((rel) => rel.direction !== 'inbound' && detectChain(rel.address))
    .map((rel) => ({ rel, chain: detectChain(rel.address) }));

  await Promise.all(watched.map(async ({ rel, chain }) => {
    const key = String(rel.address).toLowerCase();
    const baseline = baselines[key];
    const prev = baseline ? Number(baseline.balance) : NaN;
    try {
      const result = await CHAIN_FETCHERS[chain](rel.address);
      if (!isCurrentLegacySession(sessionGeneration)) return;
      const cur = Number(result?.balance);
      if (!Number.isFinite(cur)) return; // '--' = fetch failure, not a drain

      // Recovery: balance returned to at least half the drained level.
      if (baseline?.drained && cur >= prev * 0.5) {
        baseline.balance = cur;
        baseline.at = Date.now();
        baseline.drained = false;
        rel.drained = false;
        changed = true;
        return;
      }

      const evalRes = evaluateTrustDrain({ previousBalance: prev, currentBalance: cur, dropRatio });
      if (evalRes.drained || baseline?.drained) rel.drained = true;
      if (evalRes.drained && !baseline?.drained) {
        rel.previousBalance = prev;
        rel.currentBalance = cur;
        dispatchTrustEvent({
          type: 'drain', network: chain, address: rel.address,
          previousBalance: prev, currentBalance: cur,
          dropRatioObserved: evalRes.dropRatioObserved, dropRatio,
        });
      }

      // Baseline = the highest funded level observed (the expected bond);
      // it stays put while the address is drained so the alert persists.
      if (!baseline || cur > prev) {
        baselines[key] = {
          balance: cur,
          at: Date.now(),
          drained: !!(evalRes.drained || baseline?.drained),
        };
        changed = true;
      }
    } catch (err) {
      console.warn(`Drain check failed for ${rel.address}:`, err?.message || err);
    }
  }));

  if (changed && isCurrentLegacySession(sessionGeneration) && account === state.account) {
    state.storage?.write(account, 'trust-drain-baselines', baselines);
  }
}

// =============================================================================
// Account view wiring
// =============================================================================

let _shell = null;
let _panes = null;
const _barPhoto = new PhotoUrlController();
let _barPhotoKey = '';
let _barPhotoUrl = '';

function sessionView() {
  const kind = !state.loggedIn ? null : (state.externalAccount && !state.hdRoot ? 'external' : (isHdSession() ? 'seed' : null));
  return {
    kind,
    method: state.sessionKind,
    readOnly: isLegacyPasswordSession(),
    account: state.account,
    identity: kind === 'seed' ? state.identity : null,
    external: state.externalAccount
      ? { address: state.externalAccount.address, chain: state.externalAccount.chain, walletName: state.externalAccount.walletName }
      : null,
    addresses: { ...state.addresses },
  };
}

function statusText() {
  if (state.externalAccount && !state.hdRoot) {
    const name = state.externalAccount.walletName || (state.externalAccount.chain === 'eth' ? 'MetaMask' : 'Phantom');
    return `${name} · ${shortAddress(state.externalAccount.address, 6, 4)}`;
  }
  if (!isHdSession()) return '';
  const method = state.sessionKind === 'password-legacy'
    ? 'Old password method · read-only'
    : (state.sessionKind === 'password' ? 'Password' : 'Seed phrase');
  return state.account !== 0 ? `${method} · Account ${state.account}` : method;
}

async function refreshIdentityBar() {
  if (!_shell) return;
  const session = sessionView();
  const profile = session.kind === 'seed' ? readProfile() : normalizeProfile({});
  const name = session.kind === 'external' ? (state.externalAccount?.walletName || '') : profile.name;
  const avatar = { initials: initialsOf(name) };
  const photoKey = profile.photo || '';
  if (photoKey && photoKey === _barPhotoKey && _barPhotoUrl) {
    avatar.url = _barPhotoUrl;
  } else if (photoKey) {
    const bytes = photoBytesFromDataUrl(photoKey);
    try {
      if (!bytes) throw new Error('photo');
      _barPhotoUrl = await _barPhoto.replace(bytes);
      _barPhotoKey = photoKey;
      avatar.url = _barPhotoUrl;
    } catch {
      _barPhotoKey = '';
      _barPhotoUrl = '';
    }
  } else {
    _barPhoto.logout();
    _barPhotoKey = '';
    _barPhotoUrl = '';
  }
  if (!_shell) return;
  _shell.setIdentity({
    name,
    avatar,
    peerId: session.kind === 'seed' ? state.identity?.peerId ?? '' : '',
    statusText: statusText(),
    onAddName: session.kind === 'seed' ? () => _shell.showSection('profile', { focus: true, intent: { edit: true } }) : null,
  });
}

/**
 * Migration from the old password method: derive the NEW wallet (scrypt
 * profile, account 0) from the new username and password, keep only its
 * public addresses as the sweep destination, and wipe its seed. The user then
 * signs in with the new password to use it.
 */
async function setUpMigrationDestination({ username, password }) {
  if (!isLegacyPasswordSession()) throw new Error('Only a wallet opened with the old password method is migrated.');
  const sessionGeneration = currentLegacySession();
  const assessment = assessNewPassword({ username, password, estimator: _strengthEstimator });
  if (!assessment.ok) throw new Error(assessment.message);
  const wasm = hdWallet();
  const seed = await derivePasswordSeed(wasm, { username, password });
  let root = null;
  let destination;
  try {
    root = wasm.hdkey.fromSeed(seed);
    const addresses = deriveAccountAddresses(wasm, root, 0);
    destination = Object.freeze({
      username: canonicalizeUsername(username),
      btc: addresses.btc.address,
      eth: addresses.eth.address,
      sol: addresses.sol.address,
    });
  } finally {
    seed.fill(0);
    try { root?.wipe?.(); } catch { /* released */ }
  }
  if (!isCurrentLegacySession(sessionGeneration) || !isLegacyPasswordSession()) throw new Error('Wallet session ended');
  if (destination.btc === state.addresses.btc || destination.eth === state.addresses.eth) {
    throw new Error('The new wallet must differ from the old one.');
  }
  state.migrationDestination = destination;
  emitEvent('migration');
  return { ...destination };
}

function accountContext() {
  return Object.freeze({
    document,
    wasm: hdWallet,
    session: sessionView,
    isCurrent: () => state.loggedIn,
    on: onEvent,
    loadEnvelopes,
    download: (bytes, name, mime) => downloadBytes(document, bytes, name, mime),
    copy: safeCopyText,
    showSection: (section, options = {}) => _shell?.showSection(section, { focus: true, ...options }),
    profile: { get: readProfile, save: saveProfile },
    contacts: { list: readContacts, importFile: importContactFile, remove: removeContact },
    contactCard: { build: buildContactCard },
    keys: {
      withEdKey: scopedEdKey,
      withXKey: scopedXKey,
      accountXpub: () => (isHdSession() ? accountXpub(state.hdRoot, state.account) : ''),
      accountXprv: () => (isHdSession() ? accountXprv(state.hdRoot, state.account) : ''),
    },
    trust: {
      state: () => ({
        relationships: state.trustRelationships,
        transactions: state.trustTransactions,
        checkedAt: state.trustCheckedAt,
        scanning: state.trustScanning,
        error: state.trustError,
      }),
      refresh: ({ force = false } = {}) => runTrustScan(currentLegacySession(), { force }),
      publish: publishTrust,
      revoke: revokeTrust,
      outboundRecord: matchOutboundTrustTx,
      canPublish: () => state.loggedIn && !isLegacyPasswordSession() && (isHdSession() || Boolean(state.externalAccount)),
      supportsChain: trustSupportsChain,
      feeEstimate: trustFeeEstimate,
    },
    assets: {
      state: assetsState,
      refresh: refreshBalances,
      canSend: (chain) => isHdSession() && !isLegacyPasswordSession() && (chain === 'btc' || chain === 'eth'),
      prepare: prepareSendFromAccount,
      send: sendFromAccount,
      feeLine: (chain) => (chain === 'eth' ? ethSendFeeLine() : Promise.resolve('Network fee: 10,000 sats')),
    },
    migration: {
      active: () => isLegacyPasswordSession(),
      username: () => state.legacyUsername ?? '',
      loadEstimator: () => ensureStrengthEstimator(),
      assess: ({ username, password }) => assessNewPassword({ username, password, estimator: _strengthEstimator }),
      setUp: setUpMigrationDestination,
      destination: () => (state.migrationDestination ? { ...state.migrationDestination } : null),
      prepareSweep: (chain) => prepareSendFromAccount({ chain, to: state.migrationDestination?.[chain] ?? '', amount: '', sweep: true }),
      send: sendFromAccount,
    },
    settings: {
      currency: getSelectedCurrency,
      setCurrency,
      switchAccount,
      signOut: () => logout(),
      forget: forgetWallet,
    },
  });
}

function setupAccountView() {
  const root = $('account-view');
  if (!root || _shell) return;
  const ctx = accountContext();
  _panes = {
    profile: createProfilePane(root.querySelector('#account-pane-profile'), ctx),
    messages: createMessagesPane(root.querySelector('#account-pane-messages'), ctx),
    people: createPeoplePane(root.querySelector('#account-pane-people'), ctx),
    assets: createAssetsPane(root.querySelector('#account-pane-assets'), ctx),
    settings: createSettingsPane(root.querySelector('#account-pane-settings'), ctx),
  };
  _shell = createAccountShell({
    document,
    window,
    root,
    panes: _panes,
    canOpen: () => state.loggedIn,
  });
  onEvent('profile', () => { void refreshIdentityBar(); });
}

function openAccount(section) {
  if (!state.loggedIn) {
    openLogin();
    return false;
  }
  setupAccountView();
  void refreshIdentityBar();
  return _shell?.open(section) ?? false;
}

function closeAccount() {
  _shell?.close();
}

function openLogin() {
  if (state.loggedIn) {
    openAccount();
    return;
  }
  $('login-modal')?.classList.add('active');
}

async function switchAccount(account) {
  if (!isHdSession()) throw new Error('Only a seed-phrase session has account numbers.');
  const n = normalizeAccount(account);
  if (String(n) !== String(account) && Number(account) !== n) throw new Error('Choose a whole number from 0 to 99.');
  legacySessionGuard.begin();
  deriveAccountSession(n);
  state.storage?.writeAccount(n);
  updateHero();
  await refreshIdentityBar();
  emitEvent('identity');
  // Every pane re-renders for the new account (the open one at once, the
  // others when shown, since a switch resets them).
  if (_shell?.isOpen()) _shell.showSection(_shell.currentSection() ?? 'settings', { updateHash: false });
  notifyLogin();
  // Balances are looked up when Assets opens (it re-renders above if it is
  // the open section), not on every switch (SEC-054).
}

function forgetWallet() {
  state.storage?.forget();
  logout();
}

// =============================================================================
// Login / Logout
// =============================================================================

function setSignedInChrome(signedIn) {
  const navLogin = $('nav-login');
  const navKeys = $('nav-keys');
  const navLogout = $('nav-logout');
  if (navLogin) navLogin.style.display = signedIn ? 'none' : 'flex';
  if (navKeys) navKeys.style.display = signedIn ? 'flex' : 'none';
  if (navLogout) navLogout.style.display = signedIn ? 'flex' : 'none';
  const mobileLogin = $('mobile-login');
  const mobileLogout = $('mobile-logout');
  if (mobileLogin) mobileLogin.style.display = signedIn ? 'none' : 'block';
  if (mobileLogout) mobileLogout.style.display = signedIn ? 'block' : 'none';
}

function updateHero() {
  const heroWalletType = $('hero-wallet-type');
  const heroAddress = $('hero-address');
  const heroStats = $('hero-stats');
  if (!state.loggedIn) {
    if (heroWalletType) heroWalletType.textContent = '--';
    if (heroAddress) heroAddress.textContent = '--';
    if (heroStats) heroStats.classList.add('hidden');
    return;
  }
  const chain = state.selectedCrypto;
  if (heroWalletType) heroWalletType.textContent = state.externalAccount?.walletName || cryptoConfig[chain]?.name || '--';
  if (heroAddress) heroAddress.textContent = truncateAddress(state.addresses[chain] || '');
  if (heroStats) heroStats.classList.remove('hidden');
}

/**
 * EXTERNAL-WALLET SESSION: a connected external wallet opens the account view
 * driven by the connected ADDRESS. No custody is fabricated: state.hdRoot
 * stays null, so Profile and Messages say a seed phrase is needed, People and
 * Assets work from the address, and Settings offers Currency and Sign out.
 */
async function loginExternal(account) {
  legacySessionGuard.begin();
  wipeSession();
  state.loggedIn = true;
  state.sessionKind = 'external';
  const chain = account.lane === 'evm' ? 'eth' : 'sol';
  state.externalAccount = { ...account, chain, balance: null };
  state.addresses = { ...emptyAddresses(), [chain]: account.address };
  state.selectedCrypto = chain;
  state.storage = null;
  state.identity = null;
  state.chainAccounts = null;
  _memoryBalanceCache = {};

  $('login-modal')?.classList.remove('active');
  clearSeedPhrase();
  setSignedInChrome(true);
  updateHero();

  if (_openAccountAfterLogin) openAccount();
  else void refreshIdentityBar();
  // No balance lookups until Assets opens (SEC-054).
}

function login(kind = 'seed') {
  legacySessionGuard.begin();
  state.loggedIn = true;
  state.sessionKind = kind;
  if (kind !== 'password-legacy') state.legacyUsername = null;
  state.migrationDestination = null;
  state.externalAccount = null;
  state.balanceScanning = false;
  state.balanceGeneration = null;
  state.selectedCrypto = 'btc';

  const wasm = hdWallet();
  const fp = namespaceFingerprint(wasm, state.hdRoot.toXpub());
  state.storage = createAccountStorage({ fp, storage: browserStorage() });
  migrateLegacyStorage(state.storage, browserStorage());
  deriveAccountSession(state.storage.readAccount());

  // Close login modal if open (and drop any phrase left in its word slots)
  $('login-modal')?.classList.remove('active');
  clearSeedPhrase();
  setSignedInChrome(true);
  updateHero();

  // Legacy hosts receive public account metadata only: the SDN identity of
  // the current account (Ed25519 peer ID, signing and encryption keys).
  notifyLogin();

  if (_openAccountAfterLogin) openAccount();
  else void refreshIdentityBar();

  // SEC-054: no balance or price lookups at sign-in. Each one sends this
  // account's addresses, with the user's IP, to a third-party API; they run
  // when Assets opens (assets-ui show()) or on Refresh balances.
}

/** Zero and drop every secret the session holds. */
function wipeSession() {
  try { state.masterSeed?.fill?.(0); } catch { /* best effort */ }
  try { state.hdRoot?.wipe?.(); } catch { /* best effort */ }
  state.masterSeed = null;
  state.hdRoot = null;
  state.identity = null;
  state.chainAccounts = null;
  state.migrationDestination = null;
}

function logout() {
  legacySessionGuard.invalidate();
  _shell?.close();
  for (const pane of Object.values(_panes ?? {})) {
    try { pane.reset(); } catch { /* best effort */ }
  }
  state.loggedIn = false;
  wipeSession();
  // A copied xprv does not outlive the session on the clipboard (SEC-081).
  void clearSecretClipboard();
  clearTrustState();
  state.sessionKind = null;
  state.legacyUsername = null;
  state.storage = null;
  state.account = 0;
  state.externalAccount = null;
  state.addresses = { btc: null, eth: null, sol: null };
  state.balances = {};
  state.balanceUpdatedAt = 0;
  state.balanceError = '';
  state.balanceScanning = false;
  state.balanceGeneration = null;
  state.prices = null;
  _memoryBalanceCache = {};
  balanceScanner.reset();
  _barPhoto.logout();
  _barPhotoKey = '';
  _barPhotoUrl = '';
  _shell?.setIdentity({});

  setSignedInChrome(false);
  updateHero();

  // Clear form inputs
  const usernameEl = $('wallet-username');
  const passwordEl = $('wallet-password');
  if (usernameEl) usernameEl.value = '';
  if (passwordEl) passwordEl.value = '';
  clearSeedPhrase();
  updateSeedLoginButton();
  updatePasswordStrength('');

  $('login-modal')?.classList.remove('active');
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
  let travelerSequence = 0;

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
  }
  resize();
  window.addEventListener('resize', resize);

  function createTraveler() {
    const sequence = travelerSequence++;
    const horizontal = sequence % 2 === 0;
    const value = ((sequence * 73) + 19).toString(16).slice(-2).padStart(2, '0').toUpperCase();
    const direction = sequence % 4 < 2 ? 1 : -1;
    const speed = 0.3 + ((sequence % 5) * 0.08);
    const opacity = 0.3 + ((sequence % 4) * 0.1);

    if (horizontal) {
      const rowCount = Math.max(1, Math.floor(canvas.height / gridSize));
      const row = (sequence % rowCount) * gridSize;
      return {
        x: direction > 0 ? -20 : canvas.width + 20,
        y: row,
        dx: direction * speed,
        dy: 0,
        value,
        opacity,
      };
    }
    const columnCount = Math.max(1, Math.floor(canvas.width / gridSize));
    const col = (sequence % columnCount) * gridSize;
    return {
      x: col,
      y: direction > 0 ? -20 : canvas.height + 20,
      dx: 0,
      dy: direction * speed,
      value,
      opacity,
    };
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

      ctx.fillStyle = `rgba(245, 165, 36, ${t.opacity * 0.6})`;
      ctx.fillText(t.value, t.x - 6, t.y + 3);
    }

    requestAnimationFrame(draw);
  }

  draw();
}

// =============================================================================
// Login Handler Setup
// =============================================================================

function quarantinedWalletEntries(storage) {
  if (!storage) return [];
  try {
    const legacy = inspectLegacyWalletQuarantine(storage);
    const remembered = inspectRememberedWalletStorage(storage);
    const records = [...legacy];
    if (remembered.active.status === 'quarantined') {
      records.push({ key: ACTIVE_REMEMBERED_WALLET_KEY, raw: remembered.active.raw });
    }
    if (remembered.pending.status === 'quarantined') {
      records.push({ key: PENDING_REMEMBERED_WALLET_KEY, raw: remembered.pending.raw });
    }
    return records;
  } catch {
    return [];
  }
}

function setLegacyWalletQuarantineStatus(message) {
  const status = $('legacy-wallet-quarantine-status');
  if (status) status.textContent = message;
}

function renderLegacyWalletQuarantine() {
  const section = $('legacy-wallet-quarantine');
  const list = $('legacy-wallet-quarantine-list');
  if (!section || !list) return;
  const storage = browserStorage();
  const entries = quarantinedWalletEntries(storage);
  list.replaceChildren();
  setLegacyWalletQuarantineStatus('');
  section.style.display = entries.length > 0 ? 'block' : 'none';
  for (const entry of entries) {
    const row = createNode('div', 'stored-wallet-quarantine-row');
    const key = createNode('code', 'stored-wallet-quarantine-key', entry.key);
    const exportButton = createNode('button', 'glass-btn small', 'Export');
    exportButton.type = 'button';
    exportButton.addEventListener('click', async (event) => {
      if (event.isTrusted !== true) return;
      try {
        const raw = exportQuarantinedWalletRecord(storage, entry.key);
        // A stored wallet record is key material: it leaves the clipboard
        // after 30 seconds, like a copied xprv (SEC-081).
        const copied = raw !== null && await copySecretText(raw);
        setLegacyWalletQuarantineStatus(copied
          ? `Exported ${entry.key} to the clipboard. It is cleared from the clipboard in 30 seconds.`
          : 'Quarantined record export failed.');
      } catch {
        setLegacyWalletQuarantineStatus('Quarantined record export failed.');
      }
    });
    const deleteButton = createNode('button', 'glass-btn small', 'Delete');
    deleteButton.type = 'button';
    deleteButton.addEventListener('click', (event) => {
      if (event.isTrusted !== true) return;
      const confirmation = window.prompt?.(`Type ${entry.key} to delete this quarantined record.`) ?? null;
      if (confirmation !== entry.key) {
        setLegacyWalletQuarantineStatus('Deletion cancelled.');
        return;
      }
      try {
        deleteQuarantinedWalletRecord(storage, entry.key, confirmation);
        renderLegacyWalletQuarantine();
      } catch {
        setLegacyWalletQuarantineStatus('Quarantined record deletion failed.');
      }
    });
    row.append(key, exportButton, deleteButton);
    list.append(row);
  }
}

function setupLoginHandlers() {
  // External wallet — the FIRST sign-in method. The panel is the shared
  // hd-wallet-ui/external component; it discovers injected wallets
  // (EIP-6963 / Wallet Standard) and connects.
  const externalMount = $('external-wallet-mount');
  if (externalMount && !externalMount.childElementCount) {
    const panelController = createExternalWalletPanel({
      mount: externalMount,
      onConnected: (account) => {
        loginExternal(account).catch((e) => console.warn('External sign-in failed:', e));
      },
    });
    _externalPanelController = panelController;
  }

  renderLegacyWalletQuarantine();

  // Method tab switching. Leaving the Seed Phrase tab drops any phrase left
  // in its word slots.
  $qa('.method-tab').forEach((tab) => {
    tab.addEventListener('click', () => {
      const leavingSeed = $('seed-method')?.classList.contains('active') && tab.dataset.method !== 'seed';
      $qa('.method-tab').forEach((t) => t.classList.remove('active'));
      $qa('.method-content').forEach((c) => c.classList.remove('active'));
      tab.classList.add('active');
      const methodEl = $(`${tab.dataset.method}-method`);
      if (methodEl) methodEl.classList.add('active');
      if (tab.dataset.method === 'password') void ensureStrengthEstimator().catch(() => {});
      if (leavingSeed) {
        clearSeedPhrase();
        updateSeedLoginButton();
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
    btn.querySelector('.eye-open').style.display = showing ? 'inline' : 'none';
    btn.querySelector('.eye-closed').style.display = showing ? 'none' : 'inline';
    btn.title = showing ? 'Show password' : 'Hide password';
    btn.setAttribute('aria-label', btn.title);
    pw.focus();
  });

  $('wallet-username')?.addEventListener('input', () => {
    const pw = $('wallet-password');
    if (pw) updatePasswordStrength(pw.value);
  });

  // The password form never submits (no inline handler: the page's CSP
  // forbids them); Enter does nothing until a button is pressed.
  $('password-method')?.addEventListener('submit', (event) => event.preventDefault());

  // Sign in (scrypt profile). The estimate is checked again here: the
  // button state alone is not trusted.
  $('derive-from-password')?.addEventListener('click', async () => {
    const username = $('wallet-username')?.value ?? '';
    const password = $('wallet-password')?.value ?? '';
    const assessment = assessNewPassword({ username, password, estimator: _strengthEstimator });
    if (!assessment.ok) {
      setPasswordFeedback(assessment.message, { error: true });
      return;
    }
    const btn = $('derive-from-password');
    setBusy(btn, true, 'Signing in…');
    let failure = null;
    try {
      await deriveKeysFromPassword(username, password);
      const pwEl = $('wallet-password');
      if (pwEl) pwEl.value = '';
      login('password');
    } catch (err) {
      failure = err;
    } finally {
      setBusy(btn, false);
    }
    updatePasswordStrength($('wallet-password')?.value ?? '');
    if (failure) setPasswordFeedback(failure?.message || 'Sign-in failed.', { error: true });
  });

  // Sign in with the old (fast, pre-3.0) password method: read-only, so the
  // wallet's funds stay reachable and can be swept to a new wallet.
  $('derive-from-legacy-password')?.addEventListener('click', async () => {
    const username = $('wallet-username')?.value ?? '';
    const password = $('wallet-password')?.value ?? '';
    if (!username || !password) return;
    const btn = $('derive-from-legacy-password');
    setBusy(btn, true, 'Opening…');
    let failure = null;
    try {
      await deriveKeysFromLegacyPassword(username, password);
      const pwEl = $('wallet-password');
      if (pwEl) pwEl.value = '';
      state.legacyUsername = username;
      login('password-legacy');
    } catch (err) {
      failure = err;
    } finally {
      setBusy(btn, false);
    }
    updatePasswordStrength($('wallet-password')?.value ?? '');
    if (failure) setPasswordFeedback(failure?.message || 'Sign-in failed.', { error: true });
  });

  // Seed phrase word slots: typing, pasting (fills every slot) and Generate
  // all land here; Login follows the phrase's validity. A paste of more than
  // 24 words is an error and keeps Login disabled.
  const seedMount = $('seed-phrase');
  if (seedMount) {
    _seedSlots = createSeedSlots(seedMount, {
      document,
      onChange: updateSeedLoginButton,
      onOverflow: () => {
        flashResult($('validate-seed'), { ok: false });
        updateSeedLoginButton();
      },
    });
  }

  // The words are masked until "Show words" (SEC-081). Generate shows them:
  // a new phrase has to be written down.
  const seedToggle = $('toggle-seed-vis');
  const syncSeedToggle = () => {
    if (!seedToggle || !_seedSlots) return;
    const shown = !_seedSlots.masked;
    seedToggle.textContent = shown ? 'Hide words' : 'Show words';
    seedToggle.setAttribute('aria-pressed', shown ? 'true' : 'false');
  };
  seedToggle?.addEventListener('click', () => {
    _seedSlots?.setMasked(!_seedSlots.masked);
    syncSeedToggle();
  });
  _seedSlotsMaskChanged = syncSeedToggle;

  // Generate seed phrase button
  $('generate-seed')?.addEventListener('click', () => {
    _seedSlots?.setWords(generateSeedPhrase());
    _seedSlots?.setMasked(false);
    syncSeedToggle();
    const deriveBtn = $('derive-from-seed');
    if (deriveBtn) deriveBtn.disabled = false;
  });

  // Validate seed phrase button: the button itself reports the result
  // ("Validated" / "Error") and fades back.
  $('validate-seed')?.addEventListener('click', () => {
    const phrase = readSeedPhrase();
    const valid = seedPhraseIsValid(phrase);
    if (valid) {
      _seedSlots?.clearMarks();
    } else if (!_seedSlots?.overflow) {
      _seedSlots?.markInvalid(seedWordIsUnknown);
    }
    flashResult($('validate-seed'), { ok: valid });
    const deriveBtn = $('derive-from-seed');
    if (deriveBtn) deriveBtn.disabled = !valid;
  });

  // Derive from seed button
  $('derive-from-seed')?.addEventListener('click', async () => {
    const phrase = readSeedPhrase();
    if (!phrase || !seedPhraseIsValid(phrase)) return;

    const btn = $('derive-from-seed');
    btn.disabled = true;
    btn.textContent = 'Logging in...';

    try {
      await deriveKeysFromSeed(phrase);

      // Best-effort: don't keep the mnemonic in the word slots after login.
      clearSeedPhrase();

      login('seed');
    } catch (err) {
      alert('Error: ' + err.message);
    } finally {
      btn.textContent = 'Login';
      // Enabled again only while the slots still hold a valid phrase (after a
      // successful login they are empty).
      updateSeedLoginButton();
    }
  });
}

// =============================================================================
// Main App UI Handlers
// =============================================================================

/**
 * Close a dialog. The login window drops any phrase left in its word slots.
 */
function closeModal(modal) {
  modal.classList.remove('active');
  if (modal.id === 'login-modal') {
    clearSeedPhrase();
    updateSeedLoginButton();
  }
}

function setupMainAppHandlers() {
  // Nav actions
  $('nav-login')?.addEventListener('click', () => {
    $('login-modal')?.classList.add('active');
  });
  $('hero-login')?.addEventListener('click', () => {
    $('login-modal')?.classList.add('active');
  });
  $('nav-logout')?.addEventListener('click', logout);
  $('nav-keys')?.addEventListener('click', () => {
    openAccount();
  });

  // Modal close handlers. Only a deliberate close counts: a click whose
  // mousedown and mouseup were both on the backdrop, the ✕ button, or Escape.
  // (A text selection dragged out of the window does not close it.)
  $qa('.modal').forEach((modal) => {
    let pressedOnBackdrop = false;
    modal.addEventListener('mousedown', (e) => {
      pressedOnBackdrop = e.target === modal;
    });
    modal.addEventListener('click', (e) => {
      const backdrop = e.target === modal && pressedOnBackdrop;
      pressedOnBackdrop = false;
      if (backdrop || e.target.closest?.('.modal-close')) closeModal(modal);
    });
  });

  // Escape key closes dialogs (the account view handles its own Escape).
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      $qa('.modal.active').forEach((m) => closeModal(m));
    }
  });

  // Mobile menu toggle
  const mobileMenuBtn = $('nav-menu-btn');
  const mobileMenu = $('nav-mobile-menu');

  if (mobileMenuBtn && mobileMenu) {
    mobileMenuBtn.addEventListener('click', () => {
      mobileMenu.classList.toggle('open');
      const isOpen = mobileMenu.classList.contains('open');
      setStaticSymbol(mobileMenuBtn, isOpen ? '×' : '☰', isOpen ? 'Close menu' : 'Open menu');
    });

    const mobileLogin = $('mobile-login');
    const mobileLogout = $('mobile-logout');

    if (mobileLogin) {
      mobileLogin.addEventListener('click', () => {
        $('login-modal')?.classList.add('active');
        mobileMenu.classList.remove('open');
        setStaticSymbol(mobileMenuBtn, '☰', 'Open menu');
      });
    }

    if (mobileLogout) {
      mobileLogout.addEventListener('click', () => {
        logout();
        mobileMenu.classList.remove('open');
        setStaticSymbol(mobileMenuBtn, '☰', 'Open menu');
      });
    }
  }

  // Navigation links - scroll to sections
  $qa('.nav-link[data-tab]').forEach((link) => {
    link.addEventListener('click', (e) => {
      e.preventDefault();
      $qa('.nav-link[data-tab]').forEach((l) => l.classList.remove('active'));
      link.classList.add('active');
      const tabEl = $(`${link.dataset.tab}-tab`);
      if (tabEl) {
        tabEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
      }
      if (mobileMenu) {
        mobileMenu.classList.remove('open');
        if (mobileMenuBtn) {
          setStaticSymbol(mobileMenuBtn, '☰', 'Open menu');
        }
      }
    });
  });

  setupAccountView();
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
  document.querySelectorAll('.code-copy-btn').forEach((btn) => {
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

export function normalizeCreateWalletUIArguments(rootElementOrOptions, options = {}) {
  const NodeConstructor = globalThis.Node;
  const isNode = typeof NodeConstructor === 'function'
    && rootElementOrOptions instanceof NodeConstructor;
  if (isNode || rootElementOrOptions === null || rootElementOrOptions === undefined) {
    return { element: rootElementOrOptions ?? null, options: options ?? {} };
  }
  if (typeof rootElementOrOptions !== 'object' || Array.isArray(rootElementOrOptions)) {
    throw new TypeError('createWalletUI expects an element or an options object');
  }
  const { element = null, ...objectOptions } = rootElementOrOptions;
  if (element !== null
      && !(typeof NodeConstructor === 'function' && element instanceof NodeConstructor)) {
    throw new TypeError('createWalletUI element must be a DOM Node');
  }
  return { element, options: objectOptions };
}

/**
 * Boot the in-page demo: inject the login window and the account view, load
 * WASM and wire everything. Resolves to the host controls
 * `{ openAccount, closeAccount, openLogin, logout, destroy }`.
 *
 * @param {Node|object} [rootElementOrOptions]
 * @param {object} [options]
 * @param {Function} [options.onLogin] - Called after login and after every
 *   account switch with `{ xpub, peerId, signingPublicKey, encryptionPublicKey, account }`:
 *   the SDN Ed25519 identity peer ID and public keys of the current account
 *   (m/44'/0'/N'/0'/0' and m/44'/0'/N'/1'/0'). No private key is passed.
 * @param {Function} [options.onTrustEvent] - Trust lifecycle + drain events.
 * @param {boolean} [options.openAccountAfterLogin=true]
 */
export async function init(rootElementOrOptions, options = {}) {
  const normalized = normalizeCreateWalletUIArguments(rootElementOrOptions, options);
  const rootElement = normalized.element;
  const {
    onLogin = null,
    onTrustEvent = null,
    openAccountAfterLogin = true,
  } = normalized.options;
  if (rootElement) _root = rootElement;
  if (typeof onLogin === 'function') _onLoginCallback = onLogin;
  if (typeof onTrustEvent === 'function') _onTrustEventCallback = onTrustEvent;
  _openAccountAfterLogin = openAccountAfterLogin;

  // Inject the template if not already present in the DOM
  if (!document.getElementById('account-view')) {
    const container = document.createElement('div');
    container.id = 'hd-wallet-ui-container';
    appendTrustedStaticTemplate(container, getModalHTML());
    document.body.appendChild(container);
  }

  const status = $('status');
  const loadingOverlay = $('loading-overlay');

  initGridAnimation();
  initWalletInfoBox();
  bindInfoHandlers();
  dropLegacySecrets(browserStorage());

  try {
    if (status) status.textContent = 'Loading HD wallet module...';
    state.hdWalletModule = await initHDWallet();
    state.initialized = true;

    const navStatus = $('nav-status');
    if (navStatus) {
      navStatus.className = 'nav-status ready';
    }

    if (loadingOverlay) {
      loadingOverlay.classList.add('hidden');
      setTimeout(() => {
        loadingOverlay.style.display = 'none';
      }, 500);
    }

    setupLoginHandlers();
    setupMainAppHandlers();
    setupHomepageHandlers();

    // An #account/<section> link without a session has nothing to show.
    if (isAccountHash(window.location.hash) && parseAccountHash(window.location.hash) !== null && !state.loggedIn) {
      try { history.replaceState(history.state ?? null, '', `${location.pathname}${location.search}`); } catch { /* ignore */ }
    }

    // Handle initial hash navigation
    const initialHash = window.location.hash.slice(1);
    const normalizedTab = normalizeTabHash(initialHash);
    if (normalizedTab) {
      const tabEl = $(`${normalizedTab}-tab`);
      if (tabEl) {
        setTimeout(() => {
          tabEl.scrollIntoView({ behavior: 'smooth', block: 'start' });
          $qa('.nav-link[data-tab]').forEach((link) => {
            link.classList.remove('active');
            if (link.dataset.tab === normalizedTab) {
              link.classList.add('active');
            }
          });
        }, 100);
      }
    }
  } catch (err) {
    console.error('Initialization failed:', err);
    if (status) status.textContent = `Error: ${err.message}`;
    state.hdWalletModule = null;
    state.initialized = false;
    throw err;
  }

  return Object.freeze({
    openAccount: (section) => { openAccount(section); },
    closeAccount: () => { closeAccount(); },
    openLogin: () => { openLogin(); },
    logout: () => { logout(); },
    destroy: () => {
      logout();
      _shell?.destroy();
      for (const pane of Object.values(_panes ?? {})) {
        try { pane.destroy?.(); } catch { /* best effort */ }
      }
      _shell = null;
      _panes = null;
      document.getElementById('hd-wallet-ui-container')?.remove();
    },
  });
}

/**
 * Create an isolated wallet-origin UI instance that can be controlled
 * programmatically. Both public call forms normalize into this same controller;
 * no native handle or signing capability is returned to the caller.
 * The isolated Account surface owns the separate `forget-stored-wallet` action;
 * legacy logout never deletes remembered or quarantined records.
 *
 * @param {Node}   [rootElement]  - Optional root element for DOM queries
 * @param {Object} [options]      - Wallet-origin dependencies and UI options
 * @returns {Promise<{openLogin: Function, openAccount: Function, logout: Function, destroy: Function}>}
 */
export async function createWalletUI(rootElementOrOptions, options = {}) {
  const normalized = normalizeCreateWalletUIArguments(rootElementOrOptions, options);
  const configuration = normalized.options ?? {};
  const documentObject = configuration.document
    ?? normalized.element?.ownerDocument
    ?? globalThis.document;
  const windowObject = configuration.window
    ?? documentObject?.defaultView
    ?? globalThis.window;
  const wasm = await (configuration.wasm ?? initHDWallet());
  const app = createWalletOriginApp({
    clipboard: configuration.clipboard,
    credentialPrompt: configuration.credentialPrompt,
    document: documentObject,
    fetch: configuration.fetch,
    location: configuration.location,
    mount: normalized.element ?? documentObject?.body,
    registry: configuration.registry ?? walletOriginRegistry,
    relay: configuration.relay,
    rng: configuration.rng,
    wasm,
    window: windowObject,
  });
  const open = () => app.start();
  return Object.freeze({
    openLogin: open,
    openAccount: open,
    logout: () => app.logout(),
    destroy: () => app.stop('destroy'),
  });
}
