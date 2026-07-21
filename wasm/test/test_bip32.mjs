/**
 * HD Wallet WASM - BIP-32 Tests
 */

import init, { Curve } from '../src/index.mjs';
import { test, testAsync, assert, assertEqual, bytesToHex, hexToBytes } from './test_all.mjs';

// Initialize WASM module. Failure is fatal because this suite requires it.
const wallet = await init();

// BIP-32 Test Vector 1
// Seed: 000102030405060708090a0b0c0d0e0f
const testVector1Seed = hexToBytes('000102030405060708090a0b0c0d0e0f');

test('BIP-32 Test Vector 1 - Master key', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);

  assertEqual(master.depth, 0, 'Master depth should be 0');
  assertEqual(master.childIndex, 0, 'Master child index should be 0');
  assertEqual(master.parentFingerprint, 0, 'Master parent fingerprint should be 0');

  const xprv = master.toXprv();
  assertEqual(xprv, 'xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi',
    'Master xprv should match test vector');

  const xpub = master.toXpub();
  assertEqual(xpub, 'xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8',
    'Master xpub should match test vector');

  master.wipe();
});

test('BIP-32 Test Vector 1 - m/0\'', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const child = master.deriveHardened(0);

  assertEqual(child.depth, 1, 'Child depth should be 1');

  const xprv = child.toXprv();
  assertEqual(xprv, 'xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7',
    'm/0\' xprv should match test vector');

  child.wipe();
  master.wipe();
});

test('BIP-32 Test Vector 1 - m/0\'/1', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const child = master.derivePath("m/0'/1");

  assertEqual(child.depth, 2, 'Child depth should be 2');

  const xpub = child.toXpub();
  assertEqual(xpub, 'xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ',
    'm/0\'/1 xpub should match test vector');

  child.wipe();
  master.wipe();
});

test('BIP-32 Test Vector 1 - full path derivation', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const child = master.derivePath("m/0'/1/2'/2/1000000000");

  assertEqual(child.depth, 5, 'Child depth should be 5');

  const xprv = child.toXprv();
  assertEqual(xprv, 'xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76',
    'Full path xprv should match test vector');

  child.wipe();
  master.wipe();
});

// BIP-32 Test Vector 2
// Seed: fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542
const testVector2Seed = hexToBytes('fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542');

test('BIP-32 Test Vector 2 - Master key', () => {
  const master = wallet.hdkey.fromSeed(testVector2Seed);

  const xprv = master.toXprv();
  assertEqual(xprv, 'xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U',
    'Master xprv should match test vector 2');

  master.wipe();
});

test('BIP-32 Test Vector 2 - m/0', () => {
  const master = wallet.hdkey.fromSeed(testVector2Seed);
  const child = master.deriveChild(0);

  const xpub = child.toXpub();
  assertEqual(xpub, 'xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH',
    'm/0 xpub should match test vector 2');

  child.wipe();
  master.wipe();
});

// Test key serialization round-trip
test('xprv serialization round-trip', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const xprv = master.toXprv();

  const restored = wallet.hdkey.fromXprv(xprv);
  assertEqual(restored.toXprv(), xprv, 'Restored xprv should match original');

  restored.wipe();
  master.wipe();
});

test('xpub serialization round-trip', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const xpub = master.toXpub();

  const restored = wallet.hdkey.fromXpub(xpub);
  assertEqual(restored.toXpub(), xpub, 'Restored xpub should match original');
  assert(restored.isNeutered, 'Restored from xpub should be neutered');

  restored.wipe();
  master.wipe();
});

// Test neutered key
test('neutered key cannot derive hardened', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const neutered = master.neutered();

  assert(neutered.isNeutered, 'Neutered key should be neutered');

  let threw = false;
  try {
    neutered.deriveHardened(0);
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Deriving hardened from neutered key should throw');

  neutered.wipe();
  master.wipe();
});

test('neutered key can derive non-hardened', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const neutered = master.neutered();

  const child = neutered.deriveChild(0);
  assert(child.isNeutered, 'Child of neutered key should be neutered');

  // Compare with full derivation
  const fullChild = master.deriveChild(0).neutered();
  assertEqual(child.toXpub(), fullChild.toXpub(), 'Public key derivation should match');

  child.wipe();
  fullChild.wipe();
  neutered.wipe();
  master.wipe();
});

// Test private/public key extraction
test('get private key', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const privateKey = master.privateKey();

  assertEqual(privateKey.length, 32, 'Private key should be 32 bytes');

  const expectedHex = 'e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35';
  assertEqual(bytesToHex(privateKey), expectedHex, 'Private key should match test vector');

  master.wipe();
});

test('get public key', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const publicKey = master.publicKey();

  assertEqual(publicKey.length, 33, 'Compressed public key should be 33 bytes');

  const expectedHex = '0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2';
  assertEqual(bytesToHex(publicKey), expectedHex, 'Public key should match test vector');

  master.wipe();
});

test('get chain code', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const chainCode = master.chainCode();

  assertEqual(chainCode.length, 32, 'Chain code should be 32 bytes');

  const expectedHex = '873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508';
  assertEqual(bytesToHex(chainCode), expectedHex, 'Chain code should match test vector');

  master.wipe();
});

// Test path building
test('build BIP-44 path', () => {
  const path = wallet.hdkey.buildPath(44, 0, 0, 0, 0);
  assertEqual(path, "m/44'/0'/0'/0/0", 'BIP-44 path should be correct');
});

test('build BIP-44 Ethereum path', () => {
  const path = wallet.hdkey.buildPath(44, 60, 0, 0, 0);
  assertEqual(path, "m/44'/60'/0'/0/0", 'Ethereum path should be correct');
});

// Test key clone
test('key clone is independent', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  const clone = master.clone();

  assertEqual(clone.toXprv(), master.toXprv(), 'Clone should have same xprv');

  master.wipe();

  // Clone should still work after original is wiped
  const cloneXprv = clone.toXprv();
  assert(cloneXprv.startsWith('xprv'), 'Clone should still be valid after original wiped');

  clone.wipe();
});

// Test wipe
test('wiped key throws on access', () => {
  const master = wallet.hdkey.fromSeed(testVector1Seed);
  master.wipe();

  let threw = false;
  try {
    master.toXprv();
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Accessing wiped key should throw');
});
