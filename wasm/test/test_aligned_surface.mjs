/**
 * HD Wallet WASM - Aligned API Surface Tests
 *
 * Extends aligned coverage beyond deriveBatch basics:
 * - signer/verify batch call paths
 * - keyToBytes conversion
 * - size metadata exports
 * - error handling for invalid aligned inputs
 */

import init from '../src/index.mjs';
import { test, assert, assertEqual } from './test_all.mjs';

const wallet = await init();
wallet.injectEntropy(new Uint8Array(32).fill(5));

const master = wallet.hdkey.fromSeed(new Uint8Array(16).fill(1));

test('aligned API exposes stable singleton accessors', () => {
  assert(wallet.aligned, 'aligned API should exist');
  assert(wallet.aligned.keyDeriver, 'aligned.keyDeriver should exist');
  assert(wallet.aligned.signer, 'aligned.signer should exist');
  assert(wallet.aligned.keyDeriver === wallet.aligned.keyDeriver, 'keyDeriver getter should be memoized');
  assert(wallet.aligned.signer === wallet.aligned.signer, 'signer getter should be memoized');
});

test('aligned API reports struct sizes', () => {
  assert(wallet.aligned.derivedKeyEntrySize > 0, 'derivedKeyEntrySize should be positive');
  assert(wallet.aligned.extendedKeyDataSize > 0, 'extendedKeyDataSize should be positive');
  assert(wallet.aligned.batchDeriveRequestSize > 0, 'batchDeriveRequestSize should be positive');
});

test('aligned keyToBytes exports fixed-size extended key payload', () => {
  const bytes = wallet.aligned.keyToBytes(master);
  assert(bytes instanceof Uint8Array, 'keyToBytes should return Uint8Array');
  assertEqual(bytes.length, wallet.aligned.extendedKeyDataSize, 'keyToBytes length should match ExtendedKeyData size');
});

test('aligned signer.signBatch returns indexed signature entries', () => {
  const hashes = [
    wallet.utils.sha256(new TextEncoder().encode('aligned-a')),
    wallet.utils.sha256(new TextEncoder().encode('aligned-b')),
  ];
  const privateKey = master.privateKey();
  const signatures = wallet.aligned.signer.signBatch(privateKey, hashes);

  assertEqual(signatures.length, hashes.length, 'signBatch result count should match hash count');
  for (let i = 0; i < signatures.length; i++) {
    const entry = signatures[i];
    assertEqual(entry.index, i, 'signBatch entry index should track source hash order');
    assertEqual(entry.error, 0, 'Expected successful signature');
    assert(entry.signature instanceof Uint8Array, 'Expected signature payload');
    assertEqual(entry.signature.length, 64, 'Aligned signatures should be compact 64-byte form');
    assert(entry.recoveryId >= 0 && entry.recoveryId <= 3, 'Recovery ID should be in [0, 3] for secp256k1');
  }
});

test('aligned signer.verifyBatch returns typed verification records', () => {
  const hashes = [
    wallet.utils.sha256(new TextEncoder().encode('aligned-v1')),
    wallet.utils.sha256(new TextEncoder().encode('aligned-v2')),
  ];
  const privateKey = master.privateKey();
  const signatures = wallet.aligned.signer.signBatch(privateKey, hashes);
  const publicKey = master.publicKey();

  const entries = signatures.map((entry, i) => ({
    hash: hashes[i],
    signature: entry.signature || new Uint8Array(64),
  }));

  const verifyResults = wallet.aligned.signer.verifyBatch(publicKey, entries);
  assertEqual(verifyResults.length, entries.length, 'verifyBatch result count should match input count');
  for (let i = 0; i < verifyResults.length; i++) {
    const entry = verifyResults[i];
    assertEqual(entry.index, i, 'verifyBatch result index should be preserved');
    assertEqual(entry.valid, true, 'Signed entries should verify');
    assertEqual(entry.error, 0, 'verifyBatch success should return OK');
  }
});

test('aligned signer.verifyBatch rejects tampered signatures', () => {
  const hash = wallet.utils.sha256(new TextEncoder().encode('aligned-tamper'));
  const privateKey = master.privateKey();
  const publicKey = master.publicKey();
  const signatures = wallet.aligned.signer.signBatch(privateKey, [hash]);
  const tampered = new Uint8Array(signatures[0].signature);
  tampered[0] ^= 0x01;

  const verifyResults = wallet.aligned.signer.verifyBatch(publicKey, [{ hash, signature: tampered }]);
  assertEqual(verifyResults.length, 1, 'Expected one verification result');
  assertEqual(verifyResults[0].valid, false, 'Tampered signature should fail verification');
  assert(verifyResults[0].error !== 0, 'Tampered verification should return non-OK error');
});

test('aligned keyDeriver rejects invalid base key objects', () => {
  let threw = false;
  try {
    wallet.aligned.keyDeriver.deriveBatch({ bad: true }, 0, 1);
  } catch (error) {
    threw = true;
    assertEqual(error.name, 'AlignedError', 'Expected AlignedError for invalid base key');
  }
  assert(threw, 'Expected deriveBatch to throw for invalid base key');
});

master.wipe();
