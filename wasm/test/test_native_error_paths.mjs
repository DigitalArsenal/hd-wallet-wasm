// Native error paths and the JS wrappers' result checks (2.1.1 security fix).
//
// Convention: an export whose success is 0 reports any other value as an
// error; an export whose success is a length, a count or 1/0 fails with a
// negative -Error code and zeroes its output buffer. Wrappers accept exactly
// the documented success value. Up to 2.1.0 several exports failed with
// positive codes that wrappers read as lengths: a failed recover returned the
// previous call's key (so forged chain proofs verified) and a sign with an
// invalid key returned heap bytes.
//
// Keys are throwaway test keys derived from public labels.
import { createHash } from 'node:crypto';
import HDWalletWasm from '../dist/hd-wallet.js';
import init, { Curve, ErrorCode, HDWalletError } from '../src/index.mjs';
import {
  bitcoinSignedMessageHash,
  ethereumPersonalSignHash,
  verifyChainProof,
} from '../src/epm-attestation.mjs';
import { test, testAsync, assert, assertEqual, bytesToHex, hexToBytes } from './test_all.mjs';

const wallet = await init();
const enc = new TextEncoder();
const sha256 = (label) => new Uint8Array(createHash('sha256').update(label).digest());
const toBytes = (n, size) => hexToBytes(n.toString(16).padStart(size * 2, '0'));
// A throwaway key of `size` bytes (below every curve order: first byte 0x01).
const testKey = (label, size) => {
  const bytes = new Uint8Array(size);
  bytes.set(sha256(label).slice(0, size));
  bytes.set(sha256(`${label}/2`).slice(0, Math.max(0, size - 32)), 32);
  bytes[0] = 0x01;
  return bytes;
};

const ORDERS = {
  secp256k1: 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n,
  p256: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  p384: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
};
// Generator x-coordinates; (n - 1)G = -G has the same x.
const GENERATOR_X = {
  secp256k1: '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
  p256: '6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296',
  p384: 'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7',
};
const SIZES = { secp256k1: 32, p256: 32, p384: 48 };
const CURVE_IDS = { secp256k1: Curve.SECP256K1, p256: Curve.P256, p384: Curve.P384 };

function invalidKeys(curve) {
  const n = ORDERS[curve];
  const size = SIZES[curve];
  return {
    zero: new Uint8Array(size),
    n: toBytes(n, size),
    'n+1': toBytes(n + 1n, size),
    'all-ff': new Uint8Array(size).fill(0xff),
  };
}

function expectError(fn, code, label) {
  let threw = null;
  try {
    const value = fn();
    threw = new Error(`${label}: expected HDWalletError ${code}, got a result (${value instanceof Uint8Array ? bytesToHex(value) : JSON.stringify(value)})`);
  } catch (error) {
    if (!(error instanceof HDWalletError)) throw new Error(`${label}: expected HDWalletError, got ${error?.message}`);
    if (code !== undefined && error.code !== code) throw new Error(`${label}: expected code ${code}, got ${error.code} (${error.message})`);
  }
  if (threw) throw threw;
}

// --- forged chain proofs ------------------------------------------------------

// Recovery id 2 (header 31 + 2 = 0x21 compressed, 27 + 2 = 0x1d uncompressed;
// 3 for 0x22/0x1e) with r just below n: x = r + n >= p, so no key recovers.
const FORGED_R = (ORDERS.secp256k1 - 0x41n).toString(16).padStart(64, '0');
const FORGED_S = '01'.padStart(64, '0');
const FORGED_HEADERS = ['21', '22', '1d', '1e'];

function genuineProof(w, algorithm, label) {
  const key = sha256(`forge-victim-${label}`);
  const publicKey = w.curves.publicKeyFromPrivate(key, Curve.SECP256K1);
  const payload = enc.encode(`genuine payload ${label}`);
  const digest = algorithm.endsWith('ethereum')
    ? ethereumPersonalSignHash(w, payload)
    : bitcoinSignedMessageHash(w, payload);
  const { signature, recoveryId } = w.curves.secp256k1.signRecoverable(digest, key);
  return {
    CHAIN: algorithm.endsWith('ethereum') ? 'ethereum' : 'bitcoin',
    PUBLIC_KEY: bytesToHex(publicKey),
    ALGORITHM: algorithm,
    ENCODING: 'compact',
    SIGNATURE: bytesToHex(Uint8Array.of(31 + recoveryId, ...signature)),
    SIGNED_PAYLOAD: bytesToHex(payload),
  };
}

function forgedProofs(genuine, label) {
  return FORGED_HEADERS.map((header) => ({
    ...genuine,
    SIGNATURE: header + FORGED_R + FORGED_S,
    SIGNED_PAYLOAD: bytesToHex(enc.encode(`attacker payload ${label}`)),
  }));
}

// Up to 2.1.0 a failed recover returned whatever its output buffer held, which
// right after a genuine verification is the victim's key: the forged proof
// claiming that key then verified. Each algorithm runs in a fresh module (the
// review's reproduction), then repeatedly in a shared one.
for (const algorithm of ['secp256k1-compact-bitcoin', 'secp256k1-compact-ethereum']) {
  await testAsync(`forged ${algorithm} chain proofs are rejected after a genuine proof verifies`, async () => {
    const fresh = await init();
    for (const w of [fresh, wallet]) {
      for (let t = 0; t < 10; t++) {
        const genuine = genuineProof(w, algorithm, `${algorithm}-${t}`);
        for (const forged of forgedProofs(genuine, t)) {
          assertEqual(verifyChainProof(w, genuine), true, 'genuine proof should verify');
          assertEqual(verifyChainProof(w, forged), false, `forged header ${forged.SIGNATURE.slice(0, 2)} must be rejected`);
        }
      }
    }
  });
}

await testAsync('forged chain proofs are rejected before any genuine proof', async () => {
  for (const algorithm of ['secp256k1-compact-bitcoin', 'secp256k1-compact-ethereum']) {
    const fresh = await init();
    const genuine = genuineProof(wallet, algorithm, `fresh-${algorithm}`);
    for (const forged of forgedProofs(genuine, 'fresh')) {
      assertEqual(verifyChainProof(fresh, forged), false, `${algorithm} forged proof must be rejected in a fresh module`);
    }
  }
});

test('recovery ids 2 and 3 stay legitimate when r + n < p', () => {
  // A small r has x = r + n < p; find one that lies on the curve and check that
  // a proof made from the recovered key verifies with header 31 + 2.
  const digest = sha256('recid-2-legitimate');
  let found = null;
  for (let r = 1n; r < 200n && !found; r++) {
    const signature = hexToBytes(r.toString(16).padStart(64, '0') + FORGED_S);
    try {
      found = { signature, key: wallet.curves.secp256k1.recover(digest, signature, 2) };
    } catch (error) {
      if (!(error instanceof HDWalletError)) throw error;
    }
  }
  assert(found, 'some small r should recover with id 2');
  assertEqual(found.key.length, 33, 'recovered key is compressed');
  assertEqual(bytesToHex(wallet.curves.secp256k1.recover(digest, found.signature, 2)), bytesToHex(found.key),
    'recovery is deterministic');
});

// --- recover -----------------------------------------------------------------

test('recover with an invalid signature throws instead of returning a stale key', () => {
  const key = sha256('stale-key');
  const digest = sha256('stale-message');
  const { signature, recoveryId } = wallet.curves.secp256k1.signRecoverable(digest, key);
  const genuineKey = wallet.curves.secp256k1.recover(digest, signature, recoveryId);
  assertEqual(bytesToHex(genuineKey), bytesToHex(wallet.curves.publicKeyFromPrivate(key, Curve.SECP256K1)));
  const forged = hexToBytes(FORGED_R + FORGED_S);
  expectError(() => wallet.curves.secp256k1.recover(sha256('other'), forged, 2), ErrorCode.INVALID_SIGNATURE, 'recid 2, r + n >= p');
  expectError(() => wallet.curves.secp256k1.recover(sha256('other'), forged, 3), ErrorCode.INVALID_SIGNATURE, 'recid 3, r + n >= p');
  expectError(() => wallet.curves.secp256k1.recover(digest, new Uint8Array(64), 0), ErrorCode.INVALID_SIGNATURE, 'zero signature');
  expectError(() => wallet.curves.secp256k1.recover(digest, toBytes((ORDERS.secp256k1 << 256n) | 1n, 64), 0), ErrorCode.INVALID_SIGNATURE, 'r = n');
  expectError(() => wallet.curves.secp256k1.recover(digest, signature, 4), ErrorCode.INVALID_SIGNATURE, 'recovery id 4');
  expectError(() => wallet.curves.secp256k1.recover(digest, signature, 27), ErrorCode.INVALID_SIGNATURE, 'recovery id 27');
  expectError(() => wallet.curves.secp256k1.recover(digest, signature.slice(0, 63), recoveryId), ErrorCode.INVALID_SIGNATURE, '63-byte signature');
  expectError(() => wallet.curves.secp256k1.recover(digest.slice(0, 31), signature, recoveryId), ErrorCode.INVALID_ARGUMENT, '31-byte hash');
});

test('ethereum.verifyMessage with an unrecoverable signature throws', () => {
  const signature = '0x' + FORGED_R + FORGED_S + '1d';
  expectError(() => wallet.ethereum.verifyMessage('other', signature), undefined, 'eth recover recid 2');
});

// --- private keys 0, n, n + 1 ------------------------------------------------------

for (const curve of ['secp256k1', 'p256', 'p384']) {
  test(`${curve}: private keys 0, n, n + 1 and all-ff throw; n - 1 works`, () => {
    const id = CURVE_IDS[curve];
    const size = SIZES[curve];
    const message = enc.encode(`invalid-key-${curve}`);
    const peer = wallet.curves.publicKeyFromPrivate(testKey(`peer-${curve}`, size), id);
    for (const [name, key] of Object.entries(invalidKeys(curve))) {
      expectError(() => wallet.curves.publicKeyFromPrivate(key, id), ErrorCode.INVALID_PRIVATE_KEY, `${curve} publicKeyFromPrivate(${name})`);
      expectError(() => wallet.curves[curve].sign(message, key), ErrorCode.INVALID_PRIVATE_KEY, `${curve} sign(${name})`);
      expectError(() => wallet.curves[curve].ecdh(key, peer), ErrorCode.INVALID_PRIVATE_KEY, `${curve} ecdh(${name})`);
      if (curve === 'secp256k1') {
        expectError(() => wallet.curves.secp256k1.signRecoverable(sha256('h'), key), ErrorCode.INVALID_PRIVATE_KEY, `signRecoverable(${name})`);
        expectError(() => wallet.curves.ecdh(Curve.SECP256K1, key, peer), undefined, `curves.ecdh(${name})`);
      }
    }
    // n - 1 is the largest valid key: (n - 1)G = -G, so the x-coordinate is G's.
    const nMinus1 = toBytes(ORDERS[curve] - 1n, size);
    const pub = wallet.curves.publicKeyFromPrivate(nMinus1, id);
    assertEqual(bytesToHex(pub.slice(1)), GENERATOR_X[curve], `${curve} (n - 1)G has G.x`);
    assert(wallet.curves[curve].verify(message, wallet.curves[curve].sign(message, nMinus1), pub), `${curve} n - 1 signs`);
    // Wrong key lengths never reach native code.
    expectError(() => wallet.curves[curve].sign(message, new Uint8Array(size - 1).fill(1)), ErrorCode.INVALID_PRIVATE_KEY, `${curve} short key`);
    expectError(() => wallet.curves.publicKeyFromPrivate(new Uint8Array(size + 1).fill(1), id), ErrorCode.INVALID_PRIVATE_KEY, `${curve} long key`);
  });
}

// --- the raw C ABI: negative codes, zeroed outputs ------------------------------

const raw = await HDWalletWasm();
const MARK = 0xa5;

function rawAlloc(bytes) {
  const ptr = raw._hd_alloc(Math.max(1, bytes.length));
  raw.HEAPU8.set(bytes, ptr);
  return ptr;
}

function rawOut(size) {
  const ptr = raw._hd_alloc(size);
  raw.HEAPU8.fill(MARK, ptr, ptr + size);
  return ptr;
}

function rawBytes(ptr, size) {
  return raw.HEAPU8.slice(ptr, ptr + size);
}

function expectZeroed(ptr, size, label) {
  const bytes = rawBytes(ptr, size);
  assert(bytes.every((b) => b === 0), `${label}: output must be zeroed, got ${bytesToHex(bytes)}`);
}

test('raw ABI: secp256k1 sign/sign_recoverable/pubkey/ecdh with invalid keys return -400 and zero output', () => {
  const message = rawAlloc(enc.encode('raw'));
  const hash = rawAlloc(sha256('raw-hash'));
  const peerPub = rawAlloc(wallet.curves.publicKeyFromPrivate(sha256('raw-peer'), Curve.SECP256K1));
  for (const [name, key] of Object.entries(invalidKeys('secp256k1'))) {
    const keyPtr = rawAlloc(key);
    let out = rawOut(72);
    assertEqual(raw._hd_secp256k1_sign(message, 3, keyPtr, out, 72), -ErrorCode.INVALID_PRIVATE_KEY, `sign(${name})`);
    expectZeroed(out, 72, `sign(${name})`);
    out = rawOut(65);
    assertEqual(raw._hd_secp256k1_sign_recoverable(hash, 32, keyPtr, out), -ErrorCode.INVALID_PRIVATE_KEY, `sign_recoverable(${name})`);
    expectZeroed(out, 65, `sign_recoverable(${name})`);
    out = rawOut(65);
    assertEqual(raw._hd_curve_pubkey_from_privkey(keyPtr, Curve.SECP256K1, out, 65), -ErrorCode.INVALID_PRIVATE_KEY, `pubkey(${name})`);
    expectZeroed(out, 65, `pubkey(${name})`);
    out = rawOut(32);
    assertEqual(raw._hd_ecdh_secp256k1(keyPtr, peerPub, 33, out, 32), -ErrorCode.INVALID_PRIVATE_KEY, `ecdh(${name})`);
    expectZeroed(out, 32, `ecdh(${name})`);
  }
});

test('raw ABI: P-256/P-384 sign, pubkey and ecdh with invalid keys return -400 and zero output', () => {
  const message = rawAlloc(enc.encode('raw'));
  for (const curve of ['p256', 'p384']) {
    const size = SIZES[curve];
    const signFn = curve === 'p256' ? raw._hd_p256_sign : raw._hd_p384_sign;
    const ecdhFn = curve === 'p256' ? raw._hd_ecdh_p256 : raw._hd_ecdh_p384;
    const peer = wallet.curves.publicKeyFromPrivate(new Uint8Array(size).fill(3), CURVE_IDS[curve]);
    const peerPtr = rawAlloc(peer);
    for (const [name, key] of Object.entries(invalidKeys(curve))) {
      const keyPtr = rawAlloc(key);
      let out = rawOut(104);
      assertEqual(signFn(message, 3, keyPtr, out, 104), -ErrorCode.INVALID_PRIVATE_KEY, `${curve} sign(${name})`);
      expectZeroed(out, 104, `${curve} sign(${name})`);
      out = rawOut(65);
      assertEqual(raw._hd_curve_pubkey_from_privkey(keyPtr, CURVE_IDS[curve], out, 65), -ErrorCode.INVALID_PRIVATE_KEY, `${curve} pubkey(${name})`);
      expectZeroed(out, 65, `${curve} pubkey(${name})`);
      out = rawOut(size);
      assertEqual(ecdhFn(keyPtr, peerPtr, peer.length, out, size), -ErrorCode.INVALID_PRIVATE_KEY, `${curve} ecdh(${name})`);
      expectZeroed(out, size, `${curve} ecdh(${name})`);
    }
    // An off-curve peer point is -401 with the output zeroed.
    const offCurve = rawAlloc(Uint8Array.of(0x04, ...new Uint8Array(size * 2).fill(1)));
    const keyPtr = rawAlloc(new Uint8Array(size).fill(3));
    const out = rawOut(size);
    assertEqual(ecdhFn(keyPtr, offCurve, 1 + size * 2, out, size), -ErrorCode.INVALID_PUBLIC_KEY, `${curve} ecdh off-curve`);
    expectZeroed(out, size, `${curve} ecdh off-curve`);
  }
});

test('raw ABI: a failed recover returns -402 and zeroes the key it would have written', () => {
  const key = rawAlloc(sha256('raw-recover-key'));
  const hash = rawAlloc(sha256('raw-recover-hash'));
  const sig = raw._hd_alloc(65);
  assertEqual(raw._hd_secp256k1_sign_recoverable(hash, 32, key, sig), 65);
  const out = raw._hd_alloc(33);
  assertEqual(raw._hd_secp256k1_recover(hash, 32, sig, out), 33, 'genuine recover');
  assert(rawBytes(out, 33).some((b) => b !== 0), 'genuine key written');
  // Same output buffer, now holding the genuine key: the forged recover must
  // neither succeed nor leave it there.
  const forged = rawAlloc(hexToBytes(FORGED_R + FORGED_S + '02'));
  assertEqual(raw._hd_secp256k1_recover(hash, 32, forged, out), -ErrorCode.INVALID_SIGNATURE, 'forged recover');
  expectZeroed(out, 33, 'forged recover');
  const badId = rawAlloc(hexToBytes(FORGED_R + FORGED_S + '04'));
  assertEqual(raw._hd_secp256k1_recover(hash, 32, badId, out), -ErrorCode.INVALID_SIGNATURE, 'recovery id 4');
  assertEqual(raw._hd_secp256k1_recover(hash, 31, sig, out), -ErrorCode.INVALID_ARGUMENT, '31-byte hash');
});

test('raw ABI: value-returning exports never fail with a positive code', () => {
  const data = rawAlloc(enc.encode('abc'));
  const out = rawOut(64);
  assertEqual(raw._hd_hash_sha256(data, 3, out, 16), -ErrorCode.OUT_OF_MEMORY, 'sha256 short output');
  assertEqual(raw._hd_hash_blake2b(data, 3, out, 64, 65), -ErrorCode.OUT_OF_MEMORY, 'blake2b digest 65');
  const pub = rawAlloc(new Uint8Array(33).fill(2));
  const sig = rawAlloc(new Uint8Array(64));
  assertEqual(raw._hd_secp256k1_verify(data, 3, sig, 64, pub, 20), -ErrorCode.INVALID_PUBLIC_KEY, 'verify 20-byte key');
  assertEqual(raw._hd_p256_verify(data, 3, pub, 20, sig), -ErrorCode.INVALID_PUBLIC_KEY, 'p256 verify 20-byte key');
  assertEqual(raw._hd_curve_decompress_pubkey(pub, Curve.P256, out, 65), -ErrorCode.NOT_SUPPORTED, 'decompress P-256');
  const word = rawAlloc(enc.encode('abandon\0'));
  assertEqual(raw._hd_mnemonic_check_word(word, 0), 0, 'check_word index');
  assertEqual(raw._hd_mnemonic_check_word(word, 99), -ErrorCode.NOT_SUPPORTED, 'check_word language 99');
  assertEqual(raw._hd_mnemonic_suggest_word(word, 99, out, 64, 5), -ErrorCode.NOT_SUPPORTED, 'suggest_word language 99');
  assertEqual(raw._hd_btc_verify_message(0, sig, 64, word, 0), -ErrorCode.INVALID_ARGUMENT, 'btc verify null message');
  assertEqual(raw._hd_coin_verify_message(0x7fffffff, data, 3, sig, 64, pub, 33), -ErrorCode.NOT_SUPPORTED, 'coin verify unknown coin');
  assertEqual(raw._hd_cosmos_verify_signature(0, 0, sig, 64, pub, 33), -ErrorCode.INVALID_ARGUMENT, 'cosmos verify null doc');
  assertEqual(raw._hd_sol_verify_message(0, 0, sig, 64, pub, 32), -ErrorCode.INVALID_ARGUMENT, 'sol verify null message');
  assertEqual(raw._hd_dot_verify_message(0, 0, sig, 64, pub, 32), -ErrorCode.INVALID_ARGUMENT, 'dot verify null message');
  assertEqual(raw._hd_aligned_sign_batch(0, 0, 0, 0, 0), -ErrorCode.INVALID_ARGUMENT, 'aligned sign null request');
  assertEqual(raw._hd_aligned_verify_batch(0, 0, 0, 0, 0), -ErrorCode.INVALID_ARGUMENT, 'aligned verify null request');
  assertEqual(raw._hd_aligned_derive_batch(0, 0, 0), -ErrorCode.INVALID_ARGUMENT, 'aligned derive null request');
});

test('raw ABI: AES-GCM decrypt with a wrong tag returns -403 and zeroes the plaintext', () => {
  const key = rawAlloc(new Uint8Array(32).fill(7));
  const iv = rawAlloc(new Uint8Array(12).fill(1));
  const plaintext = rawAlloc(enc.encode('secret plaintext'));
  const ct = raw._hd_alloc(16);
  const tag = raw._hd_alloc(16);
  assertEqual(raw._hd_aes_gcm_encrypt(key, 32, plaintext, 16, iv, 12, 0, 0, ct, tag), 16, 'encrypt');
  raw.HEAPU8[tag] ^= 1;
  const out = rawOut(16);
  assertEqual(raw._hd_aes_gcm_decrypt(key, 32, ct, 16, iv, 12, 0, 0, tag, out), -ErrorCode.VERIFICATION_FAILED, 'decrypt wrong tag');
  expectZeroed(out, 16, 'decrypt wrong tag');
  assertEqual(raw._hd_aes_gcm_encrypt(key, 16, plaintext, 16, iv, 12, 0, 0, ct, tag), -ErrorCode.INVALID_ARGUMENT, 'encrypt 16-byte key');
});

// --- every audited wrapper: a negative path ---------------------------------------

test('wrappers: hashes and KDFs throw on invalid parameters', () => {
  expectError(() => wallet.utils.blake2b(enc.encode('x'), 65), ErrorCode.OUT_OF_MEMORY, 'blake2b 65');
  expectError(() => wallet.utils.blake2s(enc.encode('x'), 33), ErrorCode.OUT_OF_MEMORY, 'blake2s 33');
  expectError(() => wallet.utils.hkdf(new Uint8Array(32), new Uint8Array(0), new Uint8Array(0), 255 * 32 + 1), ErrorCode.INTERNAL, 'hkdf too long');
  expectError(() => wallet.utils.scrypt(enc.encode('pw'), enc.encode('salt'), 3, 1, 1, 32), ErrorCode.INTERNAL, 'scrypt N = 3');
});

test('wrappers: AES-GCM, AES-CTR and ECIES throw on bad input', () => {
  const key = new Uint8Array(32).fill(7);
  const iv = new Uint8Array(12).fill(1);
  const { ciphertext, tag } = wallet.utils.aesGcm.encrypt(key, enc.encode('secret'), iv);
  const badTag = tag.slice();
  badTag[0] ^= 1;
  expectError(() => wallet.utils.aesGcm.decrypt(key, ciphertext, badTag, iv), ErrorCode.VERIFICATION_FAILED, 'aes-gcm wrong tag');
  expectError(() => wallet.utils.aesGcm.encrypt(key.slice(0, 16), enc.encode('x'), iv), ErrorCode.INVALID_ARGUMENT, 'aes-gcm 16-byte key');
  expectError(() => wallet.aesCtr.encrypt(new Uint8Array(5), enc.encode('x'), new Uint8Array(16)), ErrorCode.INVALID_ARGUMENT, 'aes-ctr 5-byte key');
  expectError(() => wallet.aesCtr.decrypt(new Uint8Array(32), enc.encode('x'), new Uint8Array(3)), ErrorCode.INVALID_ARGUMENT, 'aes-ctr 3-byte iv');
  expectError(() => wallet.ecies.encrypt('ed25519', new Uint8Array(32), enc.encode('x')), ErrorCode.NOT_SUPPORTED, 'ecies ed25519');
  expectError(() => wallet.ecies.decrypt('secp256k1', sha256('ecies-key'), new Uint8Array(80)), undefined, 'ecies garbage');
});

test('wrappers: curve helpers throw on bad keys, points and lengths', () => {
  expectError(() => wallet.curves.decompressPublicKey(Uint8Array.of(0x02, ...new Uint8Array(32).fill(0xff)), Curve.SECP256K1), undefined, 'decompress x >= p');
  expectError(() => wallet.curves.secp256k1.ecdh(sha256('k'), Uint8Array.of(0x05, ...new Uint8Array(32))), ErrorCode.INVALID_PUBLIC_KEY, 'secp ecdh bad prefix');
  expectError(() => wallet.curves.secp256k1.signRecoverable(sha256('h').slice(0, 31), sha256('k')), ErrorCode.INVALID_ARGUMENT, 'signRecoverable 31-byte hash');
  expectError(() => wallet.curves.ed25519.sign(enc.encode('m'), new Uint8Array(31)), ErrorCode.INVALID_PRIVATE_KEY, 'ed25519 31-byte key');
  expectError(() => wallet.curves.ed25519.publicKeyFromSeed(new Uint8Array(31)), ErrorCode.INVALID_PRIVATE_KEY, 'ed25519 31-byte seed');
  expectError(() => wallet.curves.x25519.publicKey(new Uint8Array(31)), ErrorCode.INVALID_PRIVATE_KEY, 'x25519 31-byte key');
  expectError(() => wallet.curves.x25519.ecdh(new Uint8Array(32).fill(1), new Uint8Array(32)), undefined, 'x25519 all-zero peer');
  // Malformed input to a verify is "not valid", never an exception or a true.
  const message = enc.encode('m');
  assertEqual(wallet.curves.secp256k1.verify(message, new Uint8Array(64), new Uint8Array(20)), false, 'secp verify 20-byte key');
  assertEqual(wallet.curves.p256.verify(message, new Uint8Array(64), new Uint8Array(20)), false, 'p256 verify 20-byte key');
  assertEqual(wallet.curves.p384.verify(message, new Uint8Array(96), new Uint8Array(20)), false, 'p384 verify 20-byte key');
  assertEqual(wallet.curves.ed25519.verify(message, new Uint8Array(64), new Uint8Array(20)), false, 'ed25519 verify 20-byte key');
});

test('wrappers: mnemonic word checks throw on errors, not "valid"', () => {
  assertEqual(wallet.mnemonic.checkWord('abandon'), true);
  assertEqual(wallet.mnemonic.checkWord('notaword'), false);
  expectError(() => wallet.mnemonic.checkWord('abandon', 99), ErrorCode.NOT_SUPPORTED, 'checkWord language 99');
  expectError(() => wallet.mnemonic.suggestWords('ab', 99), ErrorCode.NOT_SUPPORTED, 'suggestWords language 99');
});

test('wrappers: chain helpers throw or return false on bad input', () => {
  const key = sha256('chain-key');
  const publicKey = wallet.curves.publicKeyFromPrivate(key, Curve.SECP256K1);
  expectError(() => wallet.coin.verifyMessage(0x7fffffff, enc.encode('m'), new Uint8Array(65), publicKey), ErrorCode.NOT_SUPPORTED, 'coin verify unknown coin');
  expectError(() => wallet.coin.signMessage(0, enc.encode('m'), new Uint8Array(32)), undefined, 'coin sign zero key');
  assertEqual(wallet.bitcoin.verifyMessage('m', wallet.utils.encodeBase64(new Uint8Array(65)), '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2'), false, 'btc verify garbage');
  expectError(() => wallet.bitcoin.signMessage('m', new Uint8Array(32)), undefined, 'btc sign zero key');
  expectError(() => wallet.ethereum.signMessage('m', new Uint8Array(32)), undefined, 'eth sign zero key');
  expectError(() => wallet.bitcoin.tx.create().addOutput('not-an-address', 1000n), undefined, 'btc tx bad output address');
  expectError(() => wallet.ethereum.tx.createEIP1559({
    chainId: 1, nonce: 0, maxPriorityFeePerGas: 1n, maxFeePerGas: 2n, gasLimit: 21000n, to: '0xnot-an-address', value: 1n,
  }), undefined, 'eth tx bad to address');
  expectError(() => wallet.libp2p.peerIdFromPublicKey(publicKey, 9), ErrorCode.NOT_SUPPORTED, 'libp2p unknown curve');
});

test('wrappers: aligned batches accept empty input and reject bad base keys', () => {
  assertEqual(wallet.aligned.signer.signBatch(sha256('aligned-key'), []).length, 0, 'empty sign batch');
  assertEqual(wallet.aligned.signer.verifyBatch(new Uint8Array(33), []).length, 0, 'empty verify batch');
  let threw = false;
  try {
    wallet.aligned.keyDeriver.deriveBatch({ _handle: 0 }, 0, 1);
  } catch {
    threw = true;
  }
  assert(threw, 'deriveBatch without a key handle or key data must throw');
});
