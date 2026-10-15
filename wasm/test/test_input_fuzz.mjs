// Input fuzz: every wrapper refuses an input it cannot use before it reaches
// native code (2.1.1 security fix).
//
// Native exports read fixed-size inputs (keys, public keys, hashes,
// signatures) without a length. Up to 2.1.1-rc a wrapper that passed a short
// input let native code complete it from stale heap (heap bytes came back in
// WIFs and public keys, a truncated P-256 signature verified) and a long one
// was silently truncated; a short key could also make a wipe write past its
// allocation. Here, before each call, freed heap is filled with a marker
// pattern; each call with an invalid length, an invalid scalar or an invalid
// point must throw a library error (verification: return false), and no
// returned value may contain the marker. Afterwards the module must still
// sign and verify.
//
// Keys are throwaway test keys derived from public labels.
import { createHash } from 'node:crypto';
import init, { Curve, CoinType, BitcoinAddressType, BitcoinScriptType, Network } from '../src/index.mjs';
import { verifyChainProof, verifyEPMSignature } from '../src/epm-attestation.mjs';
import { test, assert, assertEqual, bytesToHex, hexToBytes } from './test_all.mjs';

const wallet = await init();
const enc = new TextEncoder();
const sha256 = (label) => new Uint8Array(createHash('sha256').update(label).digest());
const sha512 = (bytes) => new Uint8Array(createHash('sha512').update(bytes).digest());
const toBytes = (n, size) => hexToBytes(n.toString(16).padStart(size * 2, '0'));
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
};
// A throwaway key of `size` bytes, below every curve order (first byte 0x01).
const testKey = (label, size = 32) => {
  const bytes = new Uint8Array(size);
  bytes.set(sha256(label).slice(0, Math.min(32, size)));
  if (size > 32) bytes.set(sha256(`${label}/2`).slice(0, size - 32), 32);
  bytes[0] = 0x01;
  return bytes;
};

// ---------------------------------------------------------------------------
// Heap marker
// ---------------------------------------------------------------------------

const MARKER = Uint8Array.of(0x6d, 0xa1, 0x7e, 0x55);
const markerBytes = (size) => {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) out[i] = MARKER[i % MARKER.length];
  return out;
};
// Fill freed heap with the marker: each call copies the marker into a fresh
// allocation of that size and frees it again.
const SPRAY_SIZES = [1 << 20, 1 << 16, 4096, 1024, 512, 256, 128, 97, 96, 72, 66, 65, 64, 49, 48, 34, 33, 32, 31, 20, 16, 8, 4, 1];
function sprayHeap() {
  for (const size of SPRAY_SIZES) wallet.utils.sha256(markerBytes(size));
}
// Four consecutive marker bytes at any phase.
function containsMarker(bytes) {
  for (let i = 0; i + 4 <= bytes.length; i++) {
    const phase = MARKER.indexOf(bytes[i]);
    if (phase < 0) continue;
    let run = 0;
    while (run < 4 && bytes[i + run] === MARKER[(phase + run) % 4]) run++;
    if (run === 4) return true;
  }
  return false;
}
const BASE58 = /^[1-9A-HJ-NP-Za-km-z]+$/;
// Every byte string a returned value carries: bytes as is, strings in each
// encoding the API returns (hex, base58/WIF, base64, PEM).
function returnedBytes(value, out = []) {
  if (value instanceof Uint8Array) {
    out.push(value);
  } else if (typeof value === 'string') {
    out.push(enc.encode(value));
    const pem = value.match(/-----BEGIN [^-]+-----([\s\S]*?)-----END/);
    const text = pem ? pem[1].replace(/\s+/g, '') : value;
    const hex = text.startsWith('0x') ? text.slice(2) : text;
    if (hex.length % 2 === 0 && /^[0-9a-fA-F]+$/.test(hex)) out.push(hexToBytes(hex));
    if (BASE58.test(text)) {
      try { out.push(wallet.utils.decodeBase58(text)); } catch { /* not base58 */ }
    }
    if (/^[A-Za-z0-9+/]+={0,2}$/.test(text) && text.length % 4 === 0) {
      out.push(new Uint8Array(Buffer.from(text, 'base64')));
    }
  } else if (Array.isArray(value)) {
    for (const item of value) returnedBytes(item, out);
  } else if (value !== null && typeof value === 'object') {
    for (const item of Object.values(value)) returnedBytes(item, out);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Case runner
// ---------------------------------------------------------------------------

let caseCount = 0;
const wrappersCovered = new Set();

// A library error: HDWalletError / AlignedError (numeric code), never a
// WebAssembly trap ("memory access out of bounds", an abort).
function isLibraryError(error) {
  return error instanceof Error && Number.isInteger(error.code) &&
    !(error instanceof WebAssembly.RuntimeError) && !/memory access|unreachable|abort/i.test(error.message);
}

/**
 * Run each case of one wrapper with the heap sprayed first. `expect` is
 * 'throw' (a library error), 'false' (a verify returning false) or a
 * function(result) => string|null for other results.
 */
function fuzz(wrapper, expect, cases) {
  test(`fuzz: ${wrapper} (${cases.length} invalid inputs)`, () => {
    wrappersCovered.add(wrapper);
    const failures = [];
    for (const [label, call] of cases) {
      caseCount++;
      sprayHeap();
      let result;
      let error = null;
      try {
        result = call();
      } catch (caught) {
        error = caught;
      }
      if (error !== null) {
        if (!isLibraryError(error)) failures.push(`${label}: ${error?.constructor?.name} ${error?.message}`);
        else if (expect !== 'throw') failures.push(`${label}: threw ${error.message}, expected ${typeof expect === 'string' ? expect : 'a result'}`);
        continue;
      }
      if (returnedBytes(result).some(containsMarker)) {
        failures.push(`${label}: returned heap marker bytes`);
        continue;
      }
      if (expect === 'throw') failures.push(`${label}: returned ${typeof result === 'string' ? result.slice(0, 24) : typeof result} instead of throwing`);
      else if (expect === 'false' && result !== false) failures.push(`${label}: returned ${String(result)} instead of false`);
      else if (typeof expect === 'function') {
        const problem = expect(result);
        if (problem) failures.push(`${label}: ${problem}`);
      }
    }
    assert(failures.length === 0, `${failures.length}/${cases.length} cases failed:\n      ${failures.join('\n      ')}`);
  });
}

// ---------------------------------------------------------------------------
// Inputs
// ---------------------------------------------------------------------------

const ORDERS = {
  [Curve.SECP256K1]: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  [Curve.P256]: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  [Curve.P384]: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
};
const PRIME_SECP256K1 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
const ED25519_L = (1n << 252n) + 27742317777372353535851937790883648493n;

// Wrong lengths for an input of `size` bytes: 0, size - 1, size + 1, far larger.
const badLengths = (size, label) => [0, size - 1, size + 1, 4096].map((n) => [`${label} ${n} bytes`, testKey(`${label}-${n}`, n)]);
// Invalid scalars for a short-Weierstrass curve: 0, n, n + 1, all ff.
const badScalars = (curve, label) => {
  const size = curve === Curve.P384 ? 48 : 32;
  const n = ORDERS[curve];
  return [
    [`${label} 0`, new Uint8Array(size)],
    [`${label} n`, toBytes(n, size)],
    [`${label} n+1`, toBytes(n + 1n, size)],
    [`${label} all-ff`, new Uint8Array(size).fill(0xff)],
  ];
};
const badPrivateKeys = (curve, label = 'key') => [
  ...badLengths(curve === Curve.P384 ? 48 : 32, label),
  ...(curve === Curve.ED25519 || curve === Curve.X25519 ? [] : badScalars(curve, label)),
];

const K = testKey('fuzz-secp256k1');
const KP256 = testKey('fuzz-p256');
const KP384 = testKey('fuzz-p384', 48);
const KED = testKey('fuzz-ed25519');
const PUB = wallet.curves.publicKeyFromPrivate(K, Curve.SECP256K1);
const PUB_U = wallet.curves.decompressPublicKey(PUB, Curve.SECP256K1);
const PUB_P256 = wallet.curves.publicKeyFromPrivate(KP256, Curve.P256);
const PUB_P384 = wallet.curves.publicKeyFromPrivate(KP384, Curve.P384);
const PUB_ED = wallet.curves.ed25519.publicKeyFromSeed(KED);
const MSG = enc.encode('fuzz message');
const HASH = sha256('fuzz hash');

// Invalid secp256k1 / P-256 public keys: wrong lengths, x >= p, a bad prefix,
// off-curve points, hybrid encodings.
const badPoints = (fieldSize, label = 'pub') => [
  ...[0, 1, fieldSize, fieldSize + 2, 2 * fieldSize + 2, 4096].map((n) => [`${label} ${n} bytes`, testKey(`${label}-${n}`, n)]),
  [`${label} x >= p`, concat(Uint8Array.of(0x02), new Uint8Array(fieldSize).fill(0xff))],
  [`${label} prefix 05`, concat(Uint8Array.of(0x05), PUB.subarray(1, fieldSize + 1))],
  // x = 7 is no x-coordinate of secp256k1, P-256 or P-384.
  [`${label} off-curve x`, concat(Uint8Array.of(0x02), new Uint8Array(fieldSize - 1), Uint8Array.of(0x07))],
  [`${label} uncompressed off-curve`, concat(Uint8Array.of(0x04), new Uint8Array(2 * fieldSize).fill(0x07))],
  [`${label} hybrid 06`, fieldSize === 32 ? concat(Uint8Array.of(0x06), PUB_U.subarray(1)) : new Uint8Array(2 * fieldSize + 1)],
];
const BAD_SECP_POINTS = badPoints(32);
const OFF_CURVE_PUB = BAD_SECP_POINTS.find(([label]) => label === 'pub off-curve x')[1];
const BAD_P384_POINTS = badPoints(48);
// x = p (reduces to 0 mod p): a coordinate out of range.
BAD_SECP_POINTS.push(['pub x = p', concat(Uint8Array.of(0x02), toBytes(PRIME_SECP256K1, 32))]);

// ---------------------------------------------------------------------------
// Private keys: every signer, deriver and exporter
// ---------------------------------------------------------------------------

const btcTx = () => wallet.bitcoin.tx.create()
  .addInput({ txid: '5a'.repeat(32), vout: 0, amount: 1000n, scriptType: BitcoinScriptType.P2WPKH, pubkey: PUB })
  .addOutput(wallet.bitcoin.getAddress(PUB, BitcoinAddressType.P2WPKH), 900n);
const ethTx = () => wallet.ethereum.tx.createEIP1559({
  chainId: 1, nonce: 0, maxPriorityFeePerGas: 1n, maxFeePerGas: 2n, gasLimit: 21000n,
  to: '0x000000000000000000000000000000000000dEaD', value: 1n,
});
const typedData = {
  types: { EIP712Domain: [{ name: 'name', type: 'string' }], Mail: [{ name: 'contents', type: 'string' }] },
  primaryType: 'Mail',
  domain: { name: 'fuzz', chainId: 1 },
  message: { contents: 'hi' },
};

const secpSigners = {
  'curves.publicKeyFromPrivate(secp256k1)': (k) => wallet.curves.publicKeyFromPrivate(k, Curve.SECP256K1),
  'curves.secp256k1.sign': (k) => wallet.curves.secp256k1.sign(MSG, k),
  'curves.secp256k1.signRecoverable': (k) => wallet.curves.secp256k1.signRecoverable(HASH, k),
  'curves.secp256k1.ecdh': (k) => wallet.curves.secp256k1.ecdh(k, PUB),
  'curves.ecdh(secp256k1)': (k) => wallet.curves.ecdh(Curve.SECP256K1, k, PUB),
  'coin.signMessage(bitcoin)': (k) => wallet.coin.signMessage(CoinType.BITCOIN, MSG, k),
  'coin.signMessage(ethereum)': (k) => wallet.coin.signMessage(CoinType.ETHEREUM, MSG, k),
  'coin.signMessage(cosmos)': (k) => wallet.coin.signMessage(CoinType.COSMOS, MSG, k),
  'bitcoin.toWIF': (k) => wallet.bitcoin.toWIF(k),
  'bitcoin.signMessage': (k) => wallet.bitcoin.signMessage('fuzz', k),
  'bitcoin.tx.sign': (k) => {
    const tx = btcTx();
    try { return tx.sign(k).serialize(); } finally { tx.destroy(); }
  },
  'ethereum.signMessage': (k) => wallet.ethereum.signMessage('fuzz', k),
  'ethereum.signTypedData': (k) => wallet.ethereum.signTypedData(typedData, k),
  'ethereum.tx.sign': (k) => {
    const tx = ethTx();
    try { return tx.sign(k).serialize(); } finally { tx.destroy(); }
  },
  'cosmos.signAmino': (k) => wallet.cosmos.signAmino({ chain_id: 'fuzz' }, k),
  'cosmos.signDirect(2 args)': (k) => wallet.cosmos.signDirect(MSG, k),
  'cosmos.signDirect(5 args)': (k) => wallet.cosmos.signDirect(MSG, MSG, 'fuzz-1', 7n, k),
  'ecies.decrypt(secp256k1)': (k) => wallet.ecies.decrypt(Curve.SECP256K1, k, new Uint8Array(200)),
  'aligned.signer.signBatch(secp256k1)': (k) => wallet.aligned.signer.signBatch(k, [HASH]),
  'aligned.keyDeriver.deriveBatch(plain key)': (k) => wallet.aligned.keyDeriver.deriveBatch(
    { privateKey: k, chainCode: sha256('fuzz-chain'), publicKey: PUB }, 0, 2),
};
if (wallet.x509.isAvailable()) {
  secpSigners['x509.exportPrivateKeyPem(secp256k1)'] = (k) => wallet.x509.exportPrivateKeyPem(Curve.SECP256K1, k);
}
for (const [wrapper, call] of Object.entries(secpSigners)) {
  fuzz(wrapper, 'throw', badPrivateKeys(Curve.SECP256K1).map(([label, key]) => [label, () => call(key)]));
}

const p256Signers = {
  'curves.publicKeyFromPrivate(P-256)': (k) => wallet.curves.publicKeyFromPrivate(k, Curve.P256),
  'curves.p256.sign': (k) => wallet.curves.p256.sign(MSG, k),
  'curves.p256.ecdh': (k) => wallet.curves.p256.ecdh(k, PUB_P256),
  'aligned.signer.signBatch(P-256)': (k) => wallet.aligned.signer.signBatch(k, [HASH], Curve.P256),
};
if (wallet.x509.isAvailable()) {
  p256Signers['x509.exportPrivateKeyPem(P-256)'] = (k) => wallet.x509.exportPrivateKeyPem(Curve.P256, k);
}
for (const [wrapper, call] of Object.entries(p256Signers)) {
  fuzz(wrapper, 'throw', badPrivateKeys(Curve.P256).map(([label, key]) => [label, () => call(key)]));
}

const p384Signers = {
  'curves.publicKeyFromPrivate(P-384)': (k) => wallet.curves.publicKeyFromPrivate(k, Curve.P384),
  'curves.p384.sign': (k) => wallet.curves.p384.sign(MSG, k),
  'curves.p384.ecdh': (k) => wallet.curves.p384.ecdh(k, PUB_P384),
};
for (const [wrapper, call] of Object.entries(p384Signers)) {
  fuzz(wrapper, 'throw', badPrivateKeys(Curve.P384).map(([label, key]) => [label, () => call(key)]));
}

// Ed25519 seeds and X25519 scalars: any 32 bytes, so only lengths are invalid.
const edSigners = {
  'curves.ed25519.sign': (k) => wallet.curves.ed25519.sign(MSG, k),
  'curves.ed25519.publicKeyFromSeed': (k) => wallet.curves.ed25519.publicKeyFromSeed(k),
  'curves.x25519.publicKey': (k) => wallet.curves.x25519.publicKey(k),
  'curves.x25519.ecdh': (k) => wallet.curves.x25519.ecdh(k, wallet.curves.x25519.publicKey(KED)),
  'coin.signMessage(solana)': (k) => wallet.coin.signMessage(CoinType.SOLANA, MSG, k),
  'coin.signMessage(polkadot)': (k) => wallet.coin.signMessage(CoinType.POLKADOT, MSG, k),
  'solana.signMessage': (k) => wallet.solana.signMessage(MSG, k),
  'solana.derivePubkey': (k) => wallet.solana.derivePubkey(k),
  'polkadot.signMessage': (k) => wallet.polkadot.signMessage(MSG, k),
  'polkadot.derivePubkey': (k) => wallet.polkadot.derivePubkey(k),
  'aligned.signer.signBatch(ed25519)': (k) => wallet.aligned.signer.signBatch(k, [HASH], Curve.ED25519),
};
for (const [wrapper, call] of Object.entries(edSigners)) {
  fuzz(wrapper, 'throw', badPrivateKeys(Curve.ED25519).map(([label, key]) => [label, () => call(key)]));
}

// ---------------------------------------------------------------------------
// Hashes and other fixed-size inputs
// ---------------------------------------------------------------------------

fuzz('curves.secp256k1.signRecoverable(hash)', 'throw',
  badLengths(32, 'hash').map(([label, hash]) => [label, () => wallet.curves.secp256k1.signRecoverable(hash, K)]));
fuzz('curves.secp256k1.recover', 'throw', [
  ...badLengths(32, 'hash').map(([label, hash]) => [label, () => wallet.curves.secp256k1.recover(hash, new Uint8Array(64).fill(1), 0)]),
  ...badLengths(64, 'sig').map(([label, sig]) => [label, () => wallet.curves.secp256k1.recover(HASH, sig, 0)]),
]);
fuzz('aligned.signer.signBatch(hash)', 'throw',
  badLengths(32, 'hash').map(([label, hash]) => [label, () => wallet.aligned.signer.signBatch(K, [hash])]));
fuzz('solana.findPDA(programId)', 'throw',
  badLengths(32, 'programId').map(([label, id]) => [label, () => wallet.solana.findPDA(id, [enc.encode('seed')])]));
fuzz('aligned.keyDeriver.deriveBatch(chainCode)', 'throw',
  badLengths(32, 'chainCode').map(([label, chainCode]) => [label, () => wallet.aligned.keyDeriver.deriveBatch(
    { privateKey: K, chainCode, publicKey: PUB }, 0, 1)]));
fuzz('slip10.deriveEd25519Path(seed)', 'throw',
  badLengths(64, 'seed').map(([label, seed]) => [label, () => wallet.slip10.deriveEd25519Path(seed, "m/44'/501'/0'")]));

// ---------------------------------------------------------------------------
// Public keys: every address builder, ECDH, compression and peer ID
// ---------------------------------------------------------------------------

const secpPubConsumers = {
  'curves.decompressPublicKey': (p) => wallet.curves.decompressPublicKey(p, Curve.SECP256K1),
  'curves.compressPublicKey': (p) => wallet.curves.compressPublicKey(p, Curve.SECP256K1),
  'curves.secp256k1.ecdh(publicKey)': (p) => wallet.curves.secp256k1.ecdh(K, p),
  'curves.ecdh(secp256k1, publicKey)': (p) => wallet.curves.ecdh(Curve.SECP256K1, K, p),
  'coin.addressFromPubkey(bitcoin)': (p) => wallet.coin.addressFromPubkey(CoinType.BITCOIN, p),
  'coin.addressFromPubkey(ethereum)': (p) => wallet.coin.addressFromPubkey(CoinType.ETHEREUM, p),
  'coin.addressFromPubkey(cosmos)': (p) => wallet.coin.addressFromPubkey(CoinType.COSMOS, p),
  'bitcoin.getAddress(P2PKH)': (p) => wallet.bitcoin.getAddress(p, BitcoinAddressType.P2PKH),
  'bitcoin.getAddress(P2SH)': (p) => wallet.bitcoin.getAddress(p, BitcoinAddressType.P2SH),
  'bitcoin.getAddress(P2WPKH)': (p) => wallet.bitcoin.getAddress(p, BitcoinAddressType.P2WPKH),
  'bitcoin.getAddress(P2TR)': (p) => wallet.bitcoin.getAddress(p, BitcoinAddressType.P2TR),
  'bitcoin.tx.addInput(pubkey)': (p) => {
    const tx = wallet.bitcoin.tx.create();
    try {
      return tx.addInput({ txid: '5a'.repeat(32), vout: 0, amount: 1000n, scriptType: BitcoinScriptType.P2WPKH, pubkey: p }).serialize();
    } finally {
      tx.destroy();
    }
  },
  'ethereum.getAddress': (p) => wallet.ethereum.getAddress(p),
  'cosmos.getAddress': (p) => wallet.cosmos.getAddress(p),
  'libp2p.peerIdFromPublicKey(secp256k1)': (p) => wallet.libp2p.peerIdFromPublicKey(p, Curve.SECP256K1),
  'ecies.encrypt(secp256k1)': (p) => wallet.ecies.encrypt(Curve.SECP256K1, p, MSG),
  'aligned.keyDeriver.deriveBatch(publicKey)': (p) => wallet.aligned.keyDeriver.deriveBatch(
    { privateKey: K, chainCode: sha256('fuzz-chain'), publicKey: p }, 0, 1),
};
for (const [wrapper, call] of Object.entries(secpPubConsumers)) {
  // compressPublicKey takes an uncompressed key: its own off-curve points.
  // P2TR also takes a 32-byte x-only key (covered below). decompressPublicKey
  // reads 33 bytes whatever it is given: short keys with a valid prefix, each
  // completed from the heap to a different x (about half of them on the curve).
  const shortPrefixed = Array.from({ length: 12 }, (_, i) => [
    `pub 0${2 + (i & 1)} + ${i} bytes`,
    concat(Uint8Array.of(2 + (i & 1)), PUB.subarray(1, 1 + i)),
  ]);
  const cases = wrapper === 'curves.decompressPublicKey'
    ? [...BAD_SECP_POINTS, ...shortPrefixed, ['pub 32 bytes of a real key', PUB.slice(0, 32)]]
    : wrapper === 'curves.compressPublicKey'
    ? [...BAD_SECP_POINTS.filter(([label]) => !label.includes('x >= p') && !label.includes('x = p')),
      ['pub x >= p (uncompressed)', concat(Uint8Array.of(0x04), new Uint8Array(32).fill(0xff), PUB_U.subarray(33))],
      ['pub y flipped', concat(PUB_U.subarray(0, 64), Uint8Array.of(PUB_U[64] ^ 1))]]
    : wrapper === 'bitcoin.getAddress(P2TR)'
      ? BAD_SECP_POINTS.filter(([label]) => label !== 'pub 32 bytes')
      : BAD_SECP_POINTS;
  fuzz(wrapper, 'throw', cases.map(([label, pub]) => [label, () => call(pub)]));
}
// An x-only key that is no curve x-coordinate (P2TR 32-byte form).
fuzz('bitcoin.getAddress(P2TR x-only)', 'throw', [
  ['x-only off-curve', () => wallet.bitcoin.getAddress(concat(new Uint8Array(31), Uint8Array.of(0x07)), BitcoinAddressType.P2TR)],
  ['x-only x >= p', () => wallet.bitcoin.getAddress(new Uint8Array(32).fill(0xff), BitcoinAddressType.P2TR)],
]);

const p256PubConsumers = {
  'curves.p256.ecdh(publicKey)': (p) => wallet.curves.p256.ecdh(KP256, p),
  'libp2p.peerIdFromPublicKey(P-256)': (p) => wallet.libp2p.peerIdFromPublicKey(p, Curve.P256),
  'ecies.encrypt(P-256)': (p) => wallet.ecies.encrypt(Curve.P256, p, MSG),
};
for (const [wrapper, call] of Object.entries(p256PubConsumers)) {
  fuzz(wrapper, 'throw', badPoints(32).map(([label, pub]) => [label, () => call(pub)]));
}
fuzz('curves.p384.ecdh(publicKey)', 'throw', BAD_P384_POINTS.map(([label, pub]) => [label, () => wallet.curves.p384.ecdh(KP384, pub)]));

// Ed25519 keys: wrong lengths everywhere; libp2p peer IDs also need a valid point.
const edPubLengths = badLengths(32, 'pub');
fuzz('libp2p.peerIdFromPublicKey(ed25519)', 'throw', [
  ...edPubLengths.map(([label, pub]) => [label, () => wallet.libp2p.peerIdFromPublicKey(pub, Curve.ED25519)]),
  ['pub identity (small order)', () => wallet.libp2p.peerIdFromPublicKey(concat(Uint8Array.of(1), new Uint8Array(31)), Curve.ED25519)],
  ['pub y = p (non-canonical)', () => wallet.libp2p.peerIdFromPublicKey(concat(Uint8Array.of(0xed), new Uint8Array(30).fill(0xff), Uint8Array.of(0x7f)), Curve.ED25519)],
]);
fuzz('solana.getAddress', 'throw', edPubLengths.map(([label, pub]) => [label, () => wallet.solana.getAddress(pub)]));
fuzz('polkadot.getAddress', 'throw', edPubLengths.map(([label, pub]) => [label, () => wallet.polkadot.getAddress(pub)]));
fuzz('coin.addressFromPubkey(solana)', 'throw', [0, 31, 34, 4096].map((n) => [`pub ${n} bytes`, () => wallet.coin.addressFromPubkey(CoinType.SOLANA, testKey(`sol-${n}`, n))]));
fuzz('curves.x25519.ecdh(publicKey)', 'throw', [
  ...edPubLengths.map(([label, pub]) => [label, () => wallet.curves.x25519.ecdh(KED, pub)]),
  ['pub low order 0', () => wallet.curves.x25519.ecdh(KED, new Uint8Array(32))],
  ['pub low order 1', () => wallet.curves.x25519.ecdh(KED, concat(Uint8Array.of(1), new Uint8Array(31)))],
]);

// ---------------------------------------------------------------------------
// Verification: false for every invalid signature, key or hash
// ---------------------------------------------------------------------------

const SIG = wallet.curves.secp256k1.sign(MSG, K);
const SIG_P256 = wallet.curves.p256.sign(MSG, KP256);
const SIG_P384 = wallet.curves.p384.sign(MSG, KP384);
const SIG_ED = wallet.curves.ed25519.sign(MSG, KED);

fuzz('curves.secp256k1.verify', 'false', [
  ...badLengths(64, 'sig').map(([label, sig]) => [label, () => wallet.curves.secp256k1.verify(MSG, sig, PUB)]),
  ...BAD_SECP_POINTS.map(([label, pub]) => [label, () => wallet.curves.secp256k1.verify(MSG, SIG, pub)]),
]);

// Strict DER (2.1.1 round 2). A secp256k1 signature that is not 64 bytes is
// read as DER; the old parser trusted its inner lengths (reading past the
// buffer) and took many encodings of one signature. Only X.690 DER verifies.
const derInt = (m) => {
  let i = 0;
  while (i < m.length - 1 && m[i] === 0) i++;
  const v = Array.from(m.slice(i));
  return v[0] & 0x80 ? [0x02, v.length + 1, 0x00, ...v] : [0x02, v.length, ...v];
};
const derOf = (sig) => {
  const body = [...derInt(sig.slice(0, 32)), ...derInt(sig.slice(32))];
  return [0x30, body.length, ...body];
};
const SIG_DER = derOf(SIG);
test('fuzz: curves.secp256k1.verify accepts the genuine signature as DER', () => {
  assert(wallet.curves.secp256k1.verify(MSG, Uint8Array.from(SIG_DER), PUB), 'DER of the genuine signature verifies');
});
const derVariants = (() => {
  const d = SIG_DER;
  const sAt = 4 + d[3];
  const edit = (fn) => { const v = d.slice(); fn(v); return Uint8Array.from(v); };
  return [
    ['r length past the end', Uint8Array.from([0x30, 0x00, 0x02, 0x7f, 1, 2, 3, 4])],
    ['sequence length 0', edit((v) => { v[1] = 0; })],
    ['sequence length one short', edit((v) => { v[1] -= 1; })],
    ['sequence length one long', edit((v) => { v[1] += 1; })],
    ['trailing byte', edit((v) => { v.push(0); })],
    ['trailing byte inside the sequence', edit((v) => { v.push(0); v[1] += 1; })],
    ['truncated', edit((v) => { v.pop(); })],
    ['r tag', edit((v) => { v[2] = 0x03; })],
    ['s tag', edit((v) => { v[sAt] = 0x04; })],
    ['r with an extra 0x00', edit((v) => { v.splice(4, 0, 0); v[3] += 1; v[1] += 1; })],
    ['s with an extra 0x00', edit((v) => { v.splice(sAt + 2, 0, 0); v[sAt + 1] += 1; v[1] += 1; })],
    ['r + 2^256', edit((v) => { v.splice(4, 0, 1); v[3] += 1; v[1] += 1; })],
    ['s + 2^256', edit((v) => { v.splice(sAt + 2, 0, 1); v[sAt + 1] += 1; v[1] += 1; })],
    ['negative r', edit((v) => { v[4] |= 0x80; })],
    ['long-form sequence length', edit((v) => { v.splice(1, 0, 0x81); })],
    ['long-form r length', edit((v) => { v.splice(3, 0, 0x81); v[1] += 1; })],
    ['no s', edit((v) => { v.length = sAt; v[1] = sAt - 2; })],
    ['r = 0, s = 1', Uint8Array.from([0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01])],
  ];
})();
fuzz('curves.secp256k1.verify(DER)', 'false', derVariants.map(([label, sig]) => [label, afterGenuineDer(sig)]));
function afterGenuineDer(sig) {
  return () => {
    assert(wallet.curves.secp256k1.verify(MSG, Uint8Array.from(SIG_DER), PUB) === true, 'genuine DER must verify');
    return wallet.curves.secp256k1.verify(MSG, sig, PUB);
  };
}

// A truncated or oversized P-256/P-384 signature, presented right after the
// genuine one verified: the missing bytes must not come from the heap.
const afterGenuine = (verify, genuine, bad) => () => {
  assert(verify(genuine) === true, 'genuine signature must verify');
  return verify(bad);
};
const verifyP256 = (sig, pub = PUB_P256) => wallet.curves.p256.verify(MSG, sig, pub);
const verifyP384 = (sig, pub = PUB_P384) => wallet.curves.p384.verify(MSG, sig, pub);
fuzz('curves.p256.verify', 'false', [
  ...[0, 56, 62, 63, 65, 72, 128].map((n) => [`sig ${n} bytes after genuine`, afterGenuine(verifyP256, SIG_P256,
    n <= 64 ? SIG_P256.slice(0, n) : concat(SIG_P256, new Uint8Array(n - 64).fill(0x11)))]),
  ...badPoints(32).map(([label, pub]) => [label, () => verifyP256(SIG_P256, pub)]),
]);
fuzz('curves.p384.verify', 'false', [
  ...[0, 94, 95, 97, 128].map((n) => [`sig ${n} bytes after genuine`, afterGenuine(verifyP384, SIG_P384,
    n <= 96 ? SIG_P384.slice(0, n) : concat(SIG_P384, new Uint8Array(n - 96).fill(0x11)))]),
  ...BAD_P384_POINTS.map(([label, pub]) => [label, () => verifyP384(SIG_P384, pub)]),
]);

// Ed25519, RFC 8032 strict: wrong lengths, S + L, a small-order or
// non-canonical key or R.
const leToBig = (bytes) => bytes.reduceRight((n, b) => (n << 8n) | BigInt(b), 0n);
const bigToLe = (n, size = 32) => {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) { out[i] = Number(n & 0xffn); n >>= 8n; }
  return out;
};
const sigSPlusL = concat(SIG_ED.subarray(0, 32), bigToLe(leToBig(SIG_ED.subarray(32)) + ED25519_L));
// With A the identity, [S]B == R + [k]A holds for any message when R = [S]B:
// take S = a mod L for a seed's clamped scalar a, so R is that seed's key.
const identityKey = concat(Uint8Array.of(1), new Uint8Array(31));
const seedHash = sha512(KED).slice(0, 32);
seedHash[0] &= 248; seedHash[31] &= 127; seedHash[31] |= 64;
const forgedS = leToBig(seedHash) % ED25519_L;
const identitySig = concat(PUB_ED, bigToLe(forgedS));
// The identity key encoded with y = p + 1 (non-canonical).
const identityNonCanonical = concat(Uint8Array.of(0xee), new Uint8Array(30).fill(0xff), Uint8Array.of(0x7f));
const verifyEd = (sig, pub = PUB_ED, msg = MSG) => wallet.curves.ed25519.verify(msg, sig, pub);
assert(verifyEd(SIG_ED) === true, 'genuine Ed25519 signature must verify');
fuzz('curves.ed25519.verify', 'false', [
  ...badLengths(64, 'sig').map(([label, sig]) => [label, () => verifyEd(sig)]),
  ...badLengths(32, 'pub').map(([label, pub]) => [label, () => verifyEd(SIG_ED, pub)]),
  ['S + L (malleable twin)', () => verifyEd(sigSPlusL)],
  ['small-order key (identity) with R = [S]B', () => verifyEd(identitySig, identityKey, enc.encode('any message'))],
  ['non-canonical identity key', () => verifyEd(identitySig, identityNonCanonical, enc.encode('any message'))],
  ['small-order R', () => verifyEd(concat(identityKey, SIG_ED.subarray(32)))],
]);

const BTC_SIG = wallet.coin.signMessage(CoinType.BITCOIN, MSG, K);
fuzz('coin.verifyMessage', 'false', [
  ...badLengths(65, 'sig').map(([label, sig]) => [label, () => wallet.coin.verifyMessage(CoinType.BITCOIN, MSG, sig, PUB)]),
  ['bitcoin header 0', () => wallet.coin.verifyMessage(CoinType.BITCOIN, MSG, concat(Uint8Array.of(0), BTC_SIG.subarray(1)), PUB)],
  ['ethereum garbage', () => wallet.coin.verifyMessage(CoinType.ETHEREUM, MSG, new Uint8Array(65).fill(0xff), PUB)],
  ['ethereum off-curve key', () => wallet.coin.verifyMessage(CoinType.ETHEREUM, MSG, new Uint8Array(65), OFF_CURVE_PUB)],
  ['cosmos 63-byte sig', () => wallet.coin.verifyMessage(CoinType.COSMOS, MSG, new Uint8Array(63), PUB)],
  ['solana 31-byte key', () => wallet.coin.verifyMessage(CoinType.SOLANA, MSG, new Uint8Array(64), new Uint8Array(31))],
  ['polkadot 65-byte sig', () => wallet.coin.verifyMessage(CoinType.POLKADOT, MSG, new Uint8Array(65), PUB_ED)],
]);
const btcAddress = wallet.bitcoin.getAddress(PUB, BitcoinAddressType.P2PKH);
fuzz('bitcoin.verifyMessage', 'false', [
  ['not base64', () => wallet.bitcoin.verifyMessage('fuzz', '!!not base64!!', btcAddress)],
  ['64 bytes', () => wallet.bitcoin.verifyMessage('fuzz', Buffer.from(new Uint8Array(64)).toString('base64'), btcAddress)],
  ['66 bytes', () => wallet.bitcoin.verifyMessage('fuzz', Buffer.from(new Uint8Array(66)).toString('base64'), btcAddress)],
  ['empty', () => wallet.bitcoin.verifyMessage('fuzz', '', btcAddress)],
]);
for (const [wrapper, verify, sigSize, pubSize, pub] of [
  ['cosmos.verifySignature', (m, s, p) => wallet.cosmos.verifySignature(m, s, p), 64, 33, PUB],
  ['cosmos.verify', (m, s, p) => wallet.cosmos.verify(s, m, p), 64, 33, PUB],
  ['solana.verifyMessage', (m, s, p) => wallet.solana.verifyMessage(m, s, p), 64, 32, PUB_ED],
  ['polkadot.verifyMessage', (m, s, p) => wallet.polkadot.verifyMessage(m, s, p), 64, 32, PUB_ED],
]) {
  fuzz(wrapper, 'false', [
    ...badLengths(sigSize, 'sig').map(([label, sig]) => [label, () => verify(MSG, sig, pub)]),
    ...badLengths(pubSize, 'pub').map(([label, p]) => [label, () => verify(MSG, new Uint8Array(sigSize), p)]),
  ]);
}

// Batch verification: each invalid entry (or every entry, for an invalid key)
// is reported invalid, including a truncated hash or signature presented
// right after the genuine batch verified.
const batchHash = sha256('fuzz batch');
const [batchSig] = wallet.aligned.signer.signBatch(K, [batchHash]);
const allInvalid = (results) => (Array.isArray(results) && results.length > 0 && results.every((r) => r.valid === false)
  ? null : `expected every entry invalid, got ${JSON.stringify(results)}`);
const verifyBatchAfterGenuine = (entry, pub = PUB) => () => {
  const [genuine] = wallet.aligned.signer.verifyBatch(PUB, [{ hash: batchHash, signature: batchSig.signature }]);
  assert(genuine.valid === true, 'genuine batch entry must verify');
  return wallet.aligned.signer.verifyBatch(pub, [entry]);
};
fuzz('aligned.signer.verifyBatch', allInvalid, [
  ...[0, 16, 31, 33, 4096].map((n) => [`hash ${n} bytes`, verifyBatchAfterGenuine({ hash: batchHash.slice(0, n).length === n ? batchHash.slice(0, n) : concat(batchHash, new Uint8Array(n - 32)), signature: batchSig.signature })]),
  ...[0, 31, 48, 63, 65].map((n) => [`sig ${n} bytes`, verifyBatchAfterGenuine({ hash: batchHash, signature: n <= 64 ? batchSig.signature.slice(0, n) : concat(batchSig.signature, new Uint8Array(n - 64)) })]),
  ...BAD_SECP_POINTS.map(([label, pub]) => [label, verifyBatchAfterGenuine({ hash: batchHash, signature: batchSig.signature }, pub)]),
]);

// Attestation verifiers: untrusted hex and lengths are "not verified".
const proof = {
  CHAIN: 'bitcoin', ALGORITHM: 'secp256k1-compact-bitcoin', ENCODING: 'compact',
  PUBLIC_KEY: bytesToHex(PUB), SIGNATURE: bytesToHex(new Uint8Array(65)), SIGNED_PAYLOAD: bytesToHex(MSG),
};
fuzz('verifyChainProof', 'false', [
  ['odd-length signature hex', () => verifyChainProof(wallet, { ...proof, SIGNATURE: 'abc' })],
  ['non-hex public key', () => verifyChainProof(wallet, { ...proof, PUBLIC_KEY: 'zz'.repeat(33) })],
  ['missing payload', () => verifyChainProof(wallet, { ...proof, SIGNED_PAYLOAD: undefined })],
  ['ed25519 short signature', () => verifyChainProof(wallet, { ...proof, ALGORITHM: 'ed25519', PUBLIC_KEY: bytesToHex(PUB_ED), SIGNATURE: bytesToHex(SIG_ED.slice(0, 63)) })],
  ['ed25519 S + L', () => verifyChainProof(wallet, { ...proof, ALGORITHM: 'ed25519', PUBLIC_KEY: bytesToHex(PUB_ED), SIGNATURE: bytesToHex(sigSPlusL), SIGNED_PAYLOAD: bytesToHex(MSG) })],
]);
fuzz('verifyEPMSignature', 'false', [
  ['malformed signature hex', () => verifyEPMSignature(wallet, { SIGNATURE: 'xyz', NAME: 'fuzz' }, PUB)],
  ['ed25519 short signature', () => verifyEPMSignature(wallet, { SIGNATURE: bytesToHex(SIG_ED.slice(0, 63)), NAME: 'fuzz' }, PUB_ED)],
]);

// ---------------------------------------------------------------------------
// Wrong types are programmer errors: they throw, verification included
// ---------------------------------------------------------------------------

// An Ethereum transaction never signs without a valid recipient, and its
// integer fields are never wrapped modulo 2^64 (2.1.1).
const signEth = (build) => () => {
  const tx = build();
  try { return tx.sign(K).serialize(); } finally { tx.destroy(); }
};
const eth1559 = (overrides) => signEth(() => wallet.ethereum.tx.createEIP1559({
  chainId: 1, nonce: 0, maxPriorityFeePerGas: 1n, maxFeePerGas: 2n, gasLimit: 21000n,
  to: '0x000000000000000000000000000000000000dEaD', value: 1n, ...overrides,
}));
const ethLegacy = (overrides) => signEth(() => wallet.ethereum.tx.create({
  chainId: 1, nonce: 0, gasPrice: 1n, gasLimit: 21000n,
  to: '0x000000000000000000000000000000000000dEaD', value: 1n, ...overrides,
}));
fuzz('ethereum.tx recipient and integer fields', 'throw', [
  ...[
    ['ENS name', 'vitalik.eth'],
    ['39 hex', '0x' + 'ab'.repeat(19) + 'a'],
    ['41 hex', '0x' + 'ab'.repeat(20) + 'a'],
    ['extra character', '0x' + 'ab'.repeat(20) + 'x'],
    ['non-hex', '0x' + 'zz'.repeat(20)],
    ['bare 0x', '0x'],
    ['Bitcoin address', 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'],
    ['Solana address', '7EcDhSYGxXyscszYEp35KHN8vvw3svAuLKTzXwCFLtV'],
  ].flatMap(([label, to]) => [[`eip1559 to ${label}`, eth1559({ to })], [`legacy to ${label}`, ethLegacy({ to })]]),
  ['eip1559 no to', eth1559({ to: undefined })],
  ['eip1559 empty to', eth1559({ to: '' })],
  ['eip1559 to 0x0x + 38 hex', eth1559({ to: '0x0x' + 'ab'.repeat(19) })],
  ['legacy to 0x0x + 38 hex', ethLegacy({ to: '0x0x' + 'ab'.repeat(19) })],
  ['eip1559 to 0X0x + 38 hex', eth1559({ to: '0X0x' + 'ab'.repeat(19) })],
  ['eip1559 to the zero address', eth1559({ to: '0x' + '00'.repeat(20) })],
  ['legacy to the zero address', ethLegacy({ to: '00'.repeat(20) })],
  ['eip1559 to a broken EIP-55 checksum', eth1559({ to: '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD' })],
  ['eip1559 to fullwidth digits', eth1559({ to: '0x' + '\uFF11'.repeat(40) })],
  ['eip1559 to address with a leading space', eth1559({ to: ' 0x' + 'ab'.repeat(20) })],
  ['legacy no to', ethLegacy({ to: undefined })],
  ['legacy create({chainId}) only', signEth(() => wallet.ethereum.tx.create({ chainId: 1 }))],
  // 2.1.2: no default nonce or chain ID.
  ['eip1559 no nonce', eth1559({ nonce: undefined })],
  ['legacy no nonce', ethLegacy({ nonce: undefined })],
  ['eip1559 nonce null', eth1559({ nonce: null })],
  ['eip1559 no chainId', eth1559({ chainId: undefined })],
  ['legacy no chainId', ethLegacy({ chainId: undefined })],
  ['eip1559 chainId 0', eth1559({ chainId: 0 })],
  ['legacy chainId 0', ethLegacy({ chainId: 0 })],
  ['value 2^256', eth1559({ value: 1n << 256n })],
  ['value -1', eth1559({ value: -1n })],
  ['value 0.5', eth1559({ value: 0.5 })],
  ['value 2^53 + 1 as a number', eth1559({ value: 2 ** 53 + 2 })],
  ['nonce 2^64', eth1559({ nonce: 1n << 64n })],
  ['gasLimit 2^64 + 21000', eth1559({ gasLimit: (1n << 64n) + 21000n })],
  ['maxFeePerGas 2^64', eth1559({ maxFeePerGas: 1n << 64n })],
  ['maxPriorityFeePerGas -1', eth1559({ maxPriorityFeePerGas: -1n })],
  ['chainId -1', eth1559({ chainId: -1 })],
  ['legacy gasPrice 2^64', ethLegacy({ gasPrice: 1n << 64n })],
  ['legacy value 2^256', ethLegacy({ value: 1n << 256n })],
]);

// Strings reach native code as NUL-terminated UTF-8 (2.1.1 round 2). A NUL
// used to end the string there ('pw\0extra' derived the seed of 'pw', an
// address + '\0garbage' signed to the address) and an unpaired surrogate was
// merged with the next character. Both are refused; validators answer false.
const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const ETH_ADDR = '0x52908400098527886E0F7030069857D2E4169EE7';
test('fuzz: the string fixtures are valid without the extra characters', () => {
  assert(wallet.mnemonic.validate(MNEMONIC), 'mnemonic');
  assert(wallet.ethereum.validateAddress(ETH_ADDR), 'Ethereum address');
  assert(wallet.bitcoin.validateAddress(btcAddress), 'Bitcoin address');
});
fuzz('strings with a NUL or an unpaired surrogate', 'throw', [
  ['mnemonic.toSeed passphrase "pw\\0extra"', () => wallet.mnemonic.toSeed(MNEMONIC, 'pw\u0000extra')],
  ['mnemonic.toSeed passphrase "\\0"', () => wallet.mnemonic.toSeed(MNEMONIC, '\u0000')],
  ['mnemonic.toSeed passphrase with an unpaired high surrogate', () => wallet.mnemonic.toSeed(MNEMONIC, 'pw\uD800x')],
  ['mnemonic.toSeed passphrase with an unpaired low surrogate', () => wallet.mnemonic.toSeed(MNEMONIC, '\uDC00pw')],
  ['mnemonic.toSeed mnemonic + "\\0junk"', () => wallet.mnemonic.toSeed(MNEMONIC + '\u0000junk')],
  ['eip1559 to address + "\\0garbage"', eth1559({ to: ETH_ADDR + '\u0000garbage' })],
  ['legacy to address + "\\0"', ethLegacy({ to: ETH_ADDR + '\u0000' })],
  ['eip1559 to address + unpaired surrogate', eth1559({ to: ETH_ADDR + '\uD800' })],
  ['bitcoin.fromWIF(WIF + "\\0")', () => wallet.bitcoin.fromWIF(wallet.bitcoin.toWIF(K) + '\u0000')],
]);
fuzz('validators given a NUL or an unpaired surrogate', 'false', [
  ['mnemonic.validate(mnemonic + "\\0junk")', () => wallet.mnemonic.validate(MNEMONIC + '\u0000junk')],
  ['mnemonic.validate(mnemonic + unpaired surrogate)', () => wallet.mnemonic.validate(MNEMONIC + '\uD800')],
  ['ethereum.validateAddress(address + "\\0")', () => wallet.ethereum.validateAddress(ETH_ADDR + '\u0000')],
  ['bitcoin.validateAddress(address + "\\0x")', () => wallet.bitcoin.validateAddress(btcAddress + '\u0000x')],
  ['coin.validateAddress(BTC, address + "\\0")', () => wallet.coin.validateAddress(CoinType.BITCOIN, btcAddress + '\u0000')],
]);

fuzz('wrong argument types', 'throw', [
  ['sha256(string)', () => wallet.utils.sha256('not bytes')],
  ['sha256(array)', () => wallet.utils.sha256([1, 2, 3])],
  ['secp256k1.sign(string key)', () => wallet.curves.secp256k1.sign(MSG, 'k'.repeat(32))],
  ['secp256k1.verify(string signature)', () => wallet.curves.secp256k1.verify(MSG, 'sig', PUB)],
  ['ed25519.verify(array key)', () => wallet.curves.ed25519.verify(MSG, SIG_ED, Array.from(PUB_ED))],
  ['p256.verify(null key)', () => wallet.curves.p256.verify(MSG, SIG_P256, null)],
  ['coin.verifyMessage(unknown coin)', () => wallet.coin.verifyMessage(0x7fffffff, MSG, new Uint8Array(65), PUB)],
  ['bitcoin.verifyMessage(bytes signature)', () => wallet.bitcoin.verifyMessage('m', new Uint8Array(65), btcAddress)],
  ['ecies.encrypt(unknown curve name)', () => wallet.ecies.encrypt('secp256r1', PUB, MSG)],
  ['hdkey.deriveChild(1.5)', () => {
    const key = wallet.hdkey.fromSeed(sha256('fuzz-seed'));
    try { return key.deriveChild(1.5).publicKey(); } finally { key.wipe(); }
  }],
  ['bitcoin.tx.addInput(short txid)', () => wallet.bitcoin.tx.create().addInput({ txid: 'ab', vout: 0, amount: 1n, pubkey: PUB })],
  ['ethereum.verifyMessage(v = 29)', () => wallet.ethereum.verifyMessage('fuzz', `0x${'11'.repeat(64)}1d`)],
  ['aligned.keyDeriver.streamKeys(batchSize 0)', () => wallet.aligned.keyDeriver.streamKeys({ privateKey: K, chainCode: sha256('c'), publicKey: PUB }, 0, 0).next()],
]);

// ---------------------------------------------------------------------------
// The module still works
// ---------------------------------------------------------------------------

test('fuzz: the module still signs and verifies after every invalid input', () => {
  sprayHeap();
  const sig = wallet.curves.secp256k1.sign(MSG, K);
  assertEqual(bytesToHex(sig), bytesToHex(SIG), 'secp256k1 signature unchanged');
  assert(wallet.curves.secp256k1.verify(MSG, sig, PUB), 'secp256k1 verifies');
  assert(wallet.curves.p256.verify(MSG, wallet.curves.p256.sign(MSG, KP256), PUB_P256), 'P-256 verifies');
  assert(wallet.curves.p384.verify(MSG, wallet.curves.p384.sign(MSG, KP384), PUB_P384), 'P-384 verifies');
  assert(wallet.curves.ed25519.verify(MSG, wallet.curves.ed25519.sign(MSG, KED), PUB_ED), 'Ed25519 verifies');
  const recoverable = wallet.curves.secp256k1.signRecoverable(HASH, K);
  assertEqual(bytesToHex(wallet.curves.secp256k1.recover(HASH, recoverable.signature, recoverable.recoveryId)), bytesToHex(PUB), 'recover');
  const message = 'still alive';
  assertEqual(wallet.ethereum.verifyMessage(message, wallet.ethereum.signMessage(message, K)),
    wallet.ethereum.getAddress(PUB_U), 'Ethereum round trip');
  assert(wallet.bitcoin.verifyMessage(message, wallet.bitcoin.signMessage(message, K), btcAddress), 'Bitcoin round trip');
  assertEqual(wallet.bitcoin.fromWIF(wallet.bitcoin.toWIF(K)).privateKey.length, 32, 'WIF round trip');
  assertEqual(wallet.utils.sha256(new Uint8Array(0)).length, 32, 'sha256');
  console.log(`    (${caseCount} invalid inputs across ${wrappersCovered.size} wrappers)`);
});
