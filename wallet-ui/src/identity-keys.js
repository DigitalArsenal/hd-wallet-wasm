/**
 * Per-account SDN identity keys, derived on demand from the session seed.
 *
 * The account number N selects every key the account view uses:
 *
 *   - Ed25519 signing key   SLIP-10 m/44'/0'/N'/0'/0'  (the SDN identity, EPM Signing)
 *   - X25519 encryption key SLIP-10 m/44'/0'/N'/1'/0'  (the EPM Encryption key)
 *   - Bitcoin   m/44'/0'/N'/0/0, Ethereum m/44'/60'/0'/0/N, Solana m/44'/501'/N'/0/0
 *     (BIP-32, the paths the wallet has always used, so addresses do not move)
 *
 * Only public values leave this module. Every private key is derived for one
 * operation, handed to a callback, and zeroed in a `finally` block. All
 * hashing and curve math runs in the one hd-wallet-wasm instance passed in.
 */

import { Curve } from 'hd-wallet-wasm';

import { generateAddressForCoin, generateSolAddress } from './address-derivation.js';

/** The highest account number the Settings control accepts. */
export const MAX_ACCOUNT = 99;

export function normalizeAccount(value) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0 || number > MAX_ACCOUNT) return 0;
  return number;
}

export function signingKeyPath(account) {
  return `m/44'/0'/${normalizeAccount(account)}'/0'/0'`;
}

export function encryptionKeyPath(account) {
  return `m/44'/0'/${normalizeAccount(account)}'/1'/0'`;
}

export function accountKeyPath(account) {
  return `m/44'/0'/${normalizeAccount(account)}'`;
}

/** The per-chain address paths for account N (unchanged from wallet-ui 2.x). */
export function chainPaths(account) {
  const n = normalizeAccount(account);
  return Object.freeze({
    btc: `m/44'/0'/${n}'/0/0`,
    eth: `m/44'/60'/0'/0/${n}`,
    sol: `m/44'/501'/${n}'/0/0`,
  });
}

function wipe(bytes) {
  if (bytes instanceof Uint8Array) bytes.fill(0);
}

/**
 * Call fn(key) and zero the key when fn is done: at once for a plain result,
 * or when the returned promise settles.
 */
export function runScoped(key, fn, release = () => wipe(key)) {
  let result;
  try {
    result = fn(key);
  } catch (error) {
    release();
    throw error;
  }
  if (result && typeof result.then === 'function') {
    return Promise.resolve(result).finally(release);
  }
  release();
  return result;
}

function requireSeed(seed) {
  if (!(seed instanceof Uint8Array) || seed.length < 16) {
    throw new Error('This needs a seed-phrase session.');
  }
  return seed;
}

/**
 * Run `fn(privateKey)` with the account's Ed25519 signing key and zero the key
 * afterwards, whatever `fn` does.
 */
export function withEdKey(wasm, seed, account, fn) {
  const { privateKey, chainCode } = wasm.slip10.deriveEd25519Path(requireSeed(seed), signingKeyPath(account));
  wipe(chainCode);
  return runScoped(privateKey, fn);
}

/** As withEdKey, for the account's X25519 encryption key. */
export function withXKey(wasm, seed, account, fn) {
  const { privateKey, chainCode } = wasm.slip10.deriveEd25519Path(requireSeed(seed), encryptionKeyPath(account));
  wipe(chainCode);
  return runScoped(privateKey, fn);
}

/** The libp2p peer ID string of an Ed25519 public key (12D3KooW…). */
export function peerIdFromEd25519(wasm, edPub) {
  return wasm.libp2p.peerIdToString(wasm.libp2p.peerIdFromPublicKey(edPub, Curve.ED25519));
}

/**
 * The public identity of account N: `{ account, edPub, xPub, peerId }`.
 * No private key survives the call.
 */
export function deriveIdentity(wasm, seed, account) {
  const n = normalizeAccount(account);
  const edPub = withEdKey(wasm, seed, n, (key) => new Uint8Array(wasm.curves.ed25519.publicKeyFromSeed(key)));
  const xPub = withXKey(wasm, seed, n, (key) => new Uint8Array(wasm.curves.x25519.publicKey(key)));
  return Object.freeze({ account: n, edPub, xPub, peerId: peerIdFromEd25519(wasm, edPub) });
}

/**
 * The public payload a host's onLogin callback receives for account N: the
 * SDN Ed25519 identity peer ID, the Ed25519 signing key (m/44'/0'/N'/0'/0')
 * and the X25519 encryption key (m/44'/0'/N'/1'/0'). Copies, never views of
 * session buffers; no private key.
 */
export function buildLoginPayload({ rootXpub, identity }) {
  return Object.freeze({
    xpub: String(rootXpub ?? ''),
    peerId: identity.peerId,
    signingPublicKey: new Uint8Array(identity.edPub),
    encryptionPublicKey: new Uint8Array(identity.xPub),
    account: identity.account,
  });
}

/** Lowercase hex. */
export function toHex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

/**
 * The storage namespace of a seed: the first 16 hex characters of
 * sha256(utf8(root xpub)), hashed in WASM.
 */
export function namespaceFingerprint(wasm, rootXpub) {
  const digest = wasm.utils.sha256(new TextEncoder().encode(String(rootXpub)));
  return toHex(digest).slice(0, 16);
}

/** `12D3KooW…x7Qp`: the first 8 characters, an ellipsis, the last 4. */
export function shortPeerId(peerId) {
  const value = String(peerId ?? '');
  if (value.length <= 13) return value;
  return `${value.slice(0, 8)}…${value.slice(-4)}`;
}

/** `bc1qxy…9f0c`-style short form for an address. */
export function shortAddress(address, head = 6, tail = 4) {
  const value = String(address ?? '');
  if (value.length <= head + tail + 1) return value;
  return `${value.slice(0, head)}…${value.slice(-tail)}`;
}

/**
 * Run `fn(privateKey, node)` with the BIP-32 private key at `path` and zero it
 * afterwards. Used for the Bitcoin/Ethereum/Solana chain keys.
 */
export function withChainKey(hdRoot, path, fn) {
  if (!hdRoot) throw new Error('This needs a seed-phrase session.');
  const node = hdRoot.derivePath(path);
  let privateKey;
  try {
    privateKey = node.privateKey();
  } catch (error) {
    try { node.wipe?.(); } catch { /* released */ }
    throw error;
  }
  return runScoped(privateKey, (key) => fn(key, node), () => {
    wipe(privateKey);
    try { node.wipe?.(); } catch { /* the handle is released either way */ }
  });
}

/**
 * The three addresses of account N with their public keys:
 * `{ btc: { address, publicKey, path }, eth: {...}, sol: {...} }`.
 */
export function deriveAccountAddresses(wasm, hdRoot, account) {
  const paths = chainPaths(account);
  const result = {};
  for (const [chain, path] of Object.entries(paths)) {
    if (chain === 'sol') {
      const publicKey = withChainKey(hdRoot, path, (key) => new Uint8Array(wasm.curves.ed25519.publicKeyFromSeed(key)));
      result.sol = Object.freeze({ address: generateSolAddress(publicKey), publicKey, path });
    } else {
      const node = hdRoot.derivePath(path);
      try {
        const publicKey = new Uint8Array(node.publicKey());
        const coinType = chain === 'btc' ? 0 : 60;
        result[chain] = Object.freeze({ address: generateAddressForCoin(publicKey, coinType), publicKey, path });
      } finally {
        try { node.wipe?.(); } catch { /* released */ }
      }
    }
  }
  return Object.freeze(result);
}

/** The account-level extended public key at m/44'/0'/N'. */
export function accountXpub(hdRoot, account) {
  const node = hdRoot.derivePath(accountKeyPath(account));
  try {
    return node.toXpub();
  } finally {
    try { node.wipe?.(); } catch { /* released */ }
  }
}

/** The account-level extended private key at m/44'/0'/N' (Settings › Reveal only). */
export function accountXprv(hdRoot, account) {
  const node = hdRoot.derivePath(accountKeyPath(account));
  try {
    return node.toXprv();
  } finally {
    try { node.wipe?.(); } catch { /* released */ }
  }
}
