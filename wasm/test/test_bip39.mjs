/**
 * HD Wallet WASM - BIP-39 Tests
 */

import init, { ErrorCode, Language } from '../src/index.mjs';
import { test, testAsync, skip, assert, assertEqual, bytesToHex, hexToBytes } from './test_all.mjs';

// Initialize WASM module. Failure is fatal because this suite requires it.
const wallet = await init();

// Inject entropy for mnemonic generation
const entropy = new Uint8Array(32);
if (typeof crypto !== 'undefined' && crypto.getRandomValues) {
  crypto.getRandomValues(entropy);
} else {
  // Fallback for older Node.js
  const { randomBytes } = await import('crypto');
  const buf = randomBytes(32);
  entropy.set(buf);
}
wallet.injectEntropy(entropy);

// Test mnemonic generation
test('generate 12-word mnemonic', () => {
  const mnemonic = wallet.mnemonic.generate(12);
  const words = mnemonic.split(' ');
  assertEqual(words.length, 12, 'Expected 12 words');
});

test('generate 24-word mnemonic', () => {
  const mnemonic = wallet.mnemonic.generate(24);
  const words = mnemonic.split(' ');
  assertEqual(words.length, 24, 'Expected 24 words');
});

test('validate valid mnemonic', () => {
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const isValid = wallet.mnemonic.validate(mnemonic);
  assert(isValid, 'Mnemonic should be valid');
});

test('invalidate mnemonic with wrong checksum', () => {
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon';
  const isValid = wallet.mnemonic.validate(mnemonic);
  assert(!isValid, 'Mnemonic should be invalid (wrong checksum)');
});

test('invalidate mnemonic with invalid word', () => {
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon notaword';
  const isValid = wallet.mnemonic.validate(mnemonic);
  assert(!isValid, 'Mnemonic should be invalid (invalid word)');
});

// Test mnemonic to seed conversion
test('mnemonic to seed without passphrase', () => {
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = wallet.mnemonic.toSeed(mnemonic);
  assertEqual(seed.length, 64, 'Seed should be 64 bytes');

  // Known test vector
  const expectedHex = '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4';
  assertEqual(bytesToHex(seed), expectedHex, 'Seed should match test vector');
});

test('mnemonic to seed with passphrase', () => {
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = wallet.mnemonic.toSeed(mnemonic, 'TREZOR');
  assertEqual(seed.length, 64, 'Seed should be 64 bytes');

  // Known test vector with TREZOR passphrase
  const expectedHex = 'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04';
  assertEqual(bytesToHex(seed), expectedHex, 'Seed with passphrase should match test vector');
});

// Test entropy conversion
test('mnemonic to entropy', () => {
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const entropy = wallet.mnemonic.toEntropy(mnemonic);
  assertEqual(entropy.length, 16, 'Entropy should be 16 bytes for 12-word mnemonic');

  const expectedHex = '00000000000000000000000000000000';
  assertEqual(bytesToHex(entropy), expectedHex, 'Entropy should match');
});

test('entropy to mnemonic', () => {
  const entropy = hexToBytes('00000000000000000000000000000000');
  const mnemonic = wallet.mnemonic.fromEntropy(entropy);
  assertEqual(mnemonic, 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
});

test('entropy round-trip', () => {
  const originalMnemonic = wallet.mnemonic.generate(24);
  const entropy = wallet.mnemonic.toEntropy(originalMnemonic);
  const recoveredMnemonic = wallet.mnemonic.fromEntropy(entropy);
  assertEqual(recoveredMnemonic, originalMnemonic, 'Mnemonic should survive round-trip');
});

// Test word validation
test('check valid word', () => {
  const isValid = wallet.mnemonic.checkWord('abandon');
  assert(isValid, 'abandon should be a valid word');
});

test('check invalid word', () => {
  const isValid = wallet.mnemonic.checkWord('notaword');
  assert(!isValid, 'notaword should not be valid');
});

// Test word suggestions
test('word suggestions', () => {
  const suggestions = wallet.mnemonic.suggestWords('aban');
  assert(suggestions.includes('abandon'), 'Suggestions should include abandon');
  assert(suggestions.length <= 5, 'Should return at most 5 suggestions');
});

// Test different entropy sizes
test('15-word mnemonic (160-bit entropy)', () => {
  const mnemonic = wallet.mnemonic.generate(15);
  const words = mnemonic.split(' ');
  assertEqual(words.length, 15, 'Expected 15 words');
  assert(wallet.mnemonic.validate(mnemonic), 'Generated mnemonic should be valid');
});

test('18-word mnemonic (192-bit entropy)', () => {
  const mnemonic = wallet.mnemonic.generate(18);
  const words = mnemonic.split(' ');
  assertEqual(words.length, 18, 'Expected 18 words');
  assert(wallet.mnemonic.validate(mnemonic), 'Generated mnemonic should be valid');
});

test('21-word mnemonic (224-bit entropy)', () => {
  const mnemonic = wallet.mnemonic.generate(21);
  const words = mnemonic.split(' ');
  assertEqual(words.length, 21, 'Expected 21 words');
  assert(wallet.mnemonic.validate(mnemonic), 'Generated mnemonic should be valid');
});

// Test Japanese mnemonic when the optional wordlist is compiled in.
const japaneseTestName = 'Japanese mnemonic generation';
try {
  const mnemonic = wallet.mnemonic.generate(12, Language.JAPANESE);
  test(japaneseTestName, () => {
    const words = mnemonic.split('\u3000'); // Japanese space
    assertEqual(words.length, 12, 'Expected 12 words');
    assert(wallet.mnemonic.validate(mnemonic, Language.JAPANESE), 'Japanese mnemonic should be valid');
  });
} catch (error) {
  if (error?.name === 'HDWalletError' && error.code === ErrorCode.NOT_SUPPORTED) {
    skip(japaneseTestName, `Japanese wordlist not compiled (${error.message})`);
  } else {
    throw error;
  }
}
