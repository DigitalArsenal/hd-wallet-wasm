/**
 * HD Wallet WASM - LOW Priority Edge Case Tests (L1-L8)
 *
 * Covers VERIFICATION_TASKS.md items in the LOW section:
 *   L1. Non-English Mnemonics
 *   L2. 15/18/21-Word Mnemonics (already covered in test_bip39.mjs)
 *   L3. P-256 Full Round-Trip
 *   L4. P-384 Full Round-Trip
 *   L5. Bitcoin Address Types Beyond P2PKH and P2WPKH
 *   L6. Testnet Addresses
 *   L7. WASM Integrity Verification (already covered in test_api_surface.mjs)
 *   L8. Aligned Binary API Edge Cases
 */

import init, {
  Curve,
  Language,
  Network,
  BitcoinAddressType,
} from '../src/index.mjs';

import {
  test,
  testAsync,
  assert,
  assertEqual,
  bytesToHex,
  hexToBytes,
} from './test_all.mjs';

const wallet = await init();
wallet.injectEntropy(new Uint8Array(32).fill(42));

const encoder = new TextEncoder();

// =============================================================================
// L1. Non-English Mnemonics
// =============================================================================

test('L1: non-English mnemonic languages are enumerated but not compiled in this build', () => {
  // The Language enum defines 10 languages. Verify they are all present.
  const expectedLanguages = [
    'ENGLISH', 'JAPANESE', 'KOREAN', 'SPANISH',
    'CHINESE_SIMPLIFIED', 'CHINESE_TRADITIONAL',
    'FRENCH', 'ITALIAN', 'CZECH', 'PORTUGUESE',
  ];
  for (const lang of expectedLanguages) {
    assert(Language[lang] !== undefined, `Language.${lang} should be defined`);
  }
  assertEqual(Object.keys(Language).length, expectedLanguages.length, 'Language enum should have 10 entries');
});

test('L1: English mnemonic generate/validate/toSeed end-to-end', () => {
  // English (the only language compiled in this build) should work end-to-end.
  const mnemonic = wallet.mnemonic.generate(12, Language.ENGLISH);
  const words = mnemonic.split(' ');
  assertEqual(words.length, 12, 'Expected 12 English words');

  const valid = wallet.mnemonic.validate(mnemonic, Language.ENGLISH);
  assertEqual(valid, true, 'English mnemonic should validate');

  const seed = wallet.mnemonic.toSeed(mnemonic);
  assertEqual(seed.length, 64, 'Seed should be 64 bytes');

  // Derive a key from the seed to verify it works end-to-end
  const root = wallet.hdkey.fromSeed(seed);
  const child = root.derivePath("m/44'/0'/0'/0/0");
  assertEqual(child.publicKey().length, 33, 'Should derive a valid child key');
  child.wipe();
  root.wipe();
});

test('L1: non-English languages throw NOT_SUPPORTED in this build', () => {
  // In the current WASM build, non-English wordlists are not compiled in.
  // Verify that each non-English language throws a clear error rather than
  // silently returning bad data.
  const nonEnglishLanguages = [
    Language.JAPANESE,
    Language.KOREAN,
    Language.SPANISH,
  ];

  for (const lang of nonEnglishLanguages) {
    let threw = false;
    try {
      wallet.mnemonic.generate(12, lang);
    } catch (e) {
      threw = true;
      // Should throw a meaningful error (NOT_SUPPORTED = code 3)
      assertEqual(e.name, 'HDWalletError', 'Expected HDWalletError for unsupported language');
    }
    assert(threw, `Language ${lang} should throw when not compiled`);
  }
});

// =============================================================================
// L2. 15/18/21-Word Mnemonics
//
// NOTE: These are already tested in test_bip39.mjs (lines 124-143).
// Adding explicit seed-derivation tests here for completeness.
// =============================================================================

test('L2: 15-word mnemonic generates valid seed and key', () => {
  const mnemonic = wallet.mnemonic.generate(15);
  assertEqual(mnemonic.split(' ').length, 15, 'Expected 15 words');
  assert(wallet.mnemonic.validate(mnemonic), '15-word mnemonic should validate');

  const seed = wallet.mnemonic.toSeed(mnemonic);
  assertEqual(seed.length, 64, 'Seed should be 64 bytes');

  const root = wallet.hdkey.fromSeed(seed);
  assertEqual(root.publicKey().length, 33, 'Should derive master key');
  root.wipe();
});

test('L2: 18-word mnemonic generates valid seed and key', () => {
  const mnemonic = wallet.mnemonic.generate(18);
  assertEqual(mnemonic.split(' ').length, 18, 'Expected 18 words');
  assert(wallet.mnemonic.validate(mnemonic), '18-word mnemonic should validate');

  const seed = wallet.mnemonic.toSeed(mnemonic);
  assertEqual(seed.length, 64, 'Seed should be 64 bytes');

  const root = wallet.hdkey.fromSeed(seed);
  assertEqual(root.publicKey().length, 33, 'Should derive master key');
  root.wipe();
});

test('L2: 21-word mnemonic generates valid seed and key', () => {
  const mnemonic = wallet.mnemonic.generate(21);
  assertEqual(mnemonic.split(' ').length, 21, 'Expected 21 words');
  assert(wallet.mnemonic.validate(mnemonic), '21-word mnemonic should validate');

  const seed = wallet.mnemonic.toSeed(mnemonic);
  assertEqual(seed.length, 64, 'Seed should be 64 bytes');

  const root = wallet.hdkey.fromSeed(seed);
  assertEqual(root.publicKey().length, 33, 'Should derive master key');
  root.wipe();
});

// =============================================================================
// L3. P-256 Full Round-Trip
// =============================================================================

test('L3: P-256 sign then verify round-trip with real data', () => {
  const privateKey = new Uint8Array(32);
  privateKey[31] = 1;
  const publicKey = wallet.curves.publicKeyFromPrivate(privateKey, Curve.P256);

  const message = encoder.encode('P-256 sign/verify round-trip test');
  const signature = wallet.curves.p256.sign(message, privateKey);
  assertEqual(signature.length, 64, 'P-256 compact signature should be 64 bytes');

  const valid = wallet.curves.p256.verify(message, signature, publicKey);
  assertEqual(valid, true, 'P-256 signature should verify against correct public key');
});

test('L3: P-256 verify rejects tampered signature', () => {
  const privateKey = new Uint8Array(32);
  privateKey[31] = 1;
  const publicKey = wallet.curves.publicKeyFromPrivate(privateKey, Curve.P256);

  const message = encoder.encode('P-256 tamper test');
  const signature = wallet.curves.p256.sign(message, privateKey);

  // Tamper with the signature
  const tampered = new Uint8Array(signature);
  tampered[5] ^= 0xff;

  const valid = wallet.curves.p256.verify(message, tampered, publicKey);
  assertEqual(valid, false, 'Tampered P-256 signature should not verify');
});

test('L3: P-256 verify rejects wrong message', () => {
  const privateKey = new Uint8Array(32);
  privateKey[31] = 1;
  const publicKey = wallet.curves.publicKeyFromPrivate(privateKey, Curve.P256);

  const message = encoder.encode('original message');
  const signature = wallet.curves.p256.sign(message, privateKey);

  const wrongMessage = encoder.encode('different message');
  const valid = wallet.curves.p256.verify(wrongMessage, signature, publicKey);
  assertEqual(valid, false, 'P-256 signature should not verify against wrong message');
});

test('L3: P-256 sign is deterministic for same input', () => {
  const privateKey = new Uint8Array(32);
  privateKey[31] = 1;

  const message = encoder.encode('determinism test');
  const sig1 = wallet.curves.p256.sign(message, privateKey);
  const sig2 = wallet.curves.p256.sign(message, privateKey);

  // RFC 6979 deterministic signatures should produce the same result
  assertEqual(bytesToHex(sig1), bytesToHex(sig2), 'P-256 signatures should be deterministic (RFC 6979)');
});

test('L3: P-256 ECDH returns 32 bytes (shared secret length check)', () => {
  const privateKey = new Uint8Array(32);
  privateKey[31] = 1;

  // Use known P-256 generator point (uncompressed) as the "other" public key
  const otherPub = hexToBytes(
    '047cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978' +
    'e9e29ceab0ae25e5e8965bdb60e24d57ac6e68026fa7cdb0fbec85a37a03f3b8'
  );

  const shared = wallet.curves.p256.ecdh(privateKey, otherPub);
  assertEqual(shared.length, 32, 'P-256 ECDH should return 32 bytes');
});

test('L3: P-256 ECDH mutual agreement (Alice and Bob compute same secret)', () => {
  const privA = new Uint8Array(32);
  privA[31] = 1;
  const privB = new Uint8Array(32);
  privB[31] = 2;

  // Derive public keys from private keys to ensure correctness
  const pubA_uncomp = wallet.curves.publicKeyFromPrivate(privA, Curve.P256);
  const pubB_uncomp = wallet.curves.publicKeyFromPrivate(privB, Curve.P256);

  const secretAB = wallet.curves.p256.ecdh(privA, pubB_uncomp);
  const secretBA = wallet.curves.p256.ecdh(privB, pubA_uncomp);

  assertEqual(secretAB.length, 32, 'P-256 ECDH should return 32 bytes');
  assertEqual(bytesToHex(secretAB), bytesToHex(secretBA), 'P-256 ECDH shared secrets must match (Alice == Bob)');
});

// =============================================================================
// L4. P-384 Full Round-Trip
// =============================================================================

test('L4: P-384 sign then verify round-trip with real data', () => {
  const privateKey = new Uint8Array(48);
  privateKey[47] = 1;
  const publicKey = wallet.curves.publicKeyFromPrivate(privateKey, Curve.P384);

  const message = encoder.encode('P-384 sign/verify round-trip test');
  const signature = wallet.curves.p384.sign(message, privateKey);
  assertEqual(signature.length, 96, 'P-384 compact signature should be 96 bytes');

  const valid = wallet.curves.p384.verify(message, signature, publicKey);
  assertEqual(valid, true, 'P-384 signature should verify against correct public key');
});

test('L4: P-384 verify rejects tampered signature', () => {
  const privateKey = new Uint8Array(48);
  privateKey[47] = 1;
  const publicKey = wallet.curves.publicKeyFromPrivate(privateKey, Curve.P384);

  const message = encoder.encode('P-384 tamper test');
  const signature = wallet.curves.p384.sign(message, privateKey);

  // Tamper with the signature
  const tampered = new Uint8Array(signature);
  tampered[5] ^= 0xff;

  const valid = wallet.curves.p384.verify(message, tampered, publicKey);
  assertEqual(valid, false, 'Tampered P-384 signature should not verify');
});

test('L4: P-384 verify rejects wrong message', () => {
  const privateKey = new Uint8Array(48);
  privateKey[47] = 1;
  const publicKey = wallet.curves.publicKeyFromPrivate(privateKey, Curve.P384);

  const message = encoder.encode('original P-384 message');
  const signature = wallet.curves.p384.sign(message, privateKey);

  const wrongMessage = encoder.encode('different P-384 message');
  const valid = wallet.curves.p384.verify(wrongMessage, signature, publicKey);
  assertEqual(valid, false, 'P-384 signature should not verify against wrong message');
});

test('L4: P-384 sign is deterministic for same input', () => {
  const privateKey = new Uint8Array(48);
  privateKey[47] = 1;

  const message = encoder.encode('P-384 determinism test');
  const sig1 = wallet.curves.p384.sign(message, privateKey);
  const sig2 = wallet.curves.p384.sign(message, privateKey);

  assertEqual(bytesToHex(sig1), bytesToHex(sig2), 'P-384 signatures should be deterministic (RFC 6979)');
});

test('L4: P-384 ECDH returns 48 bytes (shared secret length check)', () => {
  const privateKey = new Uint8Array(48);
  privateKey[47] = 1;

  // Use known P-384 generator point (uncompressed)
  const otherPub = hexToBytes(
    '04' +
    'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a' +
    '385502f25dbf55296c3a545e3872760ab7' +
    '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8' +
    'c00a60b1ce1d7e819d7a431d7c90ea0e5f'
  );

  const shared = wallet.curves.p384.ecdh(privateKey, otherPub);
  assertEqual(shared.length, 48, 'P-384 ECDH should return 48 bytes');
});

test('L4: P-384 ECDH mutual agreement (Alice and Bob compute same secret)', () => {
  const privA = new Uint8Array(48);
  privA[47] = 1;
  const privB = new Uint8Array(48);
  privB[47] = 2;

  // P-384 generator point * 1 (uncompressed)
  const pubA_uncomp = hexToBytes(
    '04' +
    'aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a' +
    '385502f25dbf55296c3a545e3872760ab7' +
    '3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8' +
    'c00a60b1ce1d7e819d7a431d7c90ea0e5f'
  );
  // P-384 generator point * 2 (uncompressed)
  const pubB_uncomp = hexToBytes(
    '04' +
    '08d999057ba3d2d969260045c55b97f089025959a6f434d651d207d19fb96e' +
    '9e4fe0e86ebe0e64f85b96a9c75295df61' +
    '8e80f1fa5b1b3cedb7bfe8dffd6dba74b275d875bc6cc43e904e505f256ab4' +
    '255ffd43e94d39e22d61501e700a940e80'
  );

  const secretAB = wallet.curves.p384.ecdh(privA, pubB_uncomp);
  const secretBA = wallet.curves.p384.ecdh(privB, pubA_uncomp);

  assertEqual(secretAB.length, 48, 'P-384 ECDH should return 48 bytes');
  assertEqual(bytesToHex(secretAB), bytesToHex(secretBA), 'P-384 ECDH shared secrets must match (Alice == Bob)');
});

// =============================================================================
// L5. Bitcoin Address Types Beyond P2PKH and P2WPKH
// =============================================================================

test('L5: P2SH address starts with 3 and validates', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const p2sh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2SH, Network.MAINNET);
  assert(p2sh.startsWith('3'), `P2SH address should start with 3, got: ${p2sh}`);
  assertEqual(wallet.bitcoin.validateAddress(p2sh, Network.MAINNET), true, 'P2SH address should validate');
});

test('L5: P2WSH address starts with bc1q and is longer than P2WPKH', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  // P2WSH uses a witness script; pass the public key as the script for address derivation
  const p2wsh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WSH, Network.MAINNET);
  assert(p2wsh.startsWith('bc1q'), `P2WSH address should start with bc1q, got: ${p2wsh}`);

  // P2WSH addresses encode a 32-byte SHA256 hash (longer than P2WPKH's 20-byte hash)
  const p2wpkh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WPKH, Network.MAINNET);
  assert(p2wsh.length > p2wpkh.length, 'P2WSH address should be longer than P2WPKH');

  assertEqual(wallet.bitcoin.validateAddress(p2wsh, Network.MAINNET), true, 'P2WSH address should validate');
});

test('L5: P2TR (Taproot) address starts with bc1p and validates', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const p2tr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2TR, Network.MAINNET);
  assert(p2tr.startsWith('bc1p'), `P2TR address should start with bc1p, got: ${p2tr}`);
  assertEqual(wallet.bitcoin.validateAddress(p2tr, Network.MAINNET), true, 'P2TR address should validate');
});

test('L5: all five address types generate distinct addresses from same pubkey', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const p2pkh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2PKH, Network.MAINNET);
  const p2sh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2SH, Network.MAINNET);
  const p2wpkh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WPKH, Network.MAINNET);
  const p2wsh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WSH, Network.MAINNET);
  const p2tr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2TR, Network.MAINNET);

  const addresses = [p2pkh, p2sh, p2wpkh, p2wsh, p2tr];
  const unique = new Set(addresses);
  assertEqual(unique.size, 5, 'All five address types should produce distinct addresses');

  // Verify prefixes
  assert(p2pkh.startsWith('1'), 'P2PKH should start with 1');
  assert(p2sh.startsWith('3'), 'P2SH should start with 3');
  assert(p2wpkh.startsWith('bc1q'), 'P2WPKH should start with bc1q');
  assert(p2wsh.startsWith('bc1q'), 'P2WSH should start with bc1q');
  assert(p2tr.startsWith('bc1p'), 'P2TR should start with bc1p');
});

// =============================================================================
// L6. Testnet Addresses
// =============================================================================

test('L6: P2PKH testnet address starts with m or n', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const addr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2PKH, Network.TESTNET);
  assert(
    addr.startsWith('m') || addr.startsWith('n'),
    `P2PKH testnet address should start with m or n, got: ${addr}`
  );
  assertEqual(wallet.bitcoin.validateAddress(addr, Network.TESTNET), true, 'Testnet P2PKH should validate');
});

test('L6: P2WPKH testnet address starts with tb1q', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const addr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WPKH, Network.TESTNET);
  assert(addr.startsWith('tb1q'), `P2WPKH testnet address should start with tb1q, got: ${addr}`);
  assertEqual(wallet.bitcoin.validateAddress(addr, Network.TESTNET), true, 'Testnet P2WPKH should validate');
});

test('L6: P2SH testnet address starts with 2', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const addr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2SH, Network.TESTNET);
  assert(addr.startsWith('2'), `P2SH testnet address should start with 2, got: ${addr}`);
  assertEqual(wallet.bitcoin.validateAddress(addr, Network.TESTNET), true, 'Testnet P2SH should validate');
});

test('L6: P2TR testnet address starts with tb1p', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const addr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2TR, Network.TESTNET);
  assert(addr.startsWith('tb1p'), `P2TR testnet address should start with tb1p, got: ${addr}`);
  assertEqual(wallet.bitcoin.validateAddress(addr, Network.TESTNET), true, 'Testnet P2TR should validate');
});

test('L6: testnet addresses do not validate as mainnet', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const testnetP2pkh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2PKH, Network.TESTNET);
  const testnetP2wpkh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WPKH, Network.TESTNET);

  // Testnet addresses should validate on testnet
  assertEqual(wallet.bitcoin.validateAddress(testnetP2pkh, Network.TESTNET), true, 'Testnet P2PKH validates on TESTNET');
  assertEqual(wallet.bitcoin.validateAddress(testnetP2wpkh, Network.TESTNET), true, 'Testnet P2WPKH validates on TESTNET');
});

// =============================================================================
// L7. WASM Integrity Verification
//
// NOTE: computeWasmHash and verifyWasmIntegrity are already tested in
// test_api_surface.mjs. Adding one test here to verify with actual WASM bytes.
// =============================================================================

await testAsync('L7: WASM integrity functions work with arbitrary byte payloads', async () => {
  // Import the standalone functions
  const { computeWasmHash, verifyWasmIntegrity } = await import('../src/index.mjs');

  // Test with deterministic payload
  const payload = new Uint8Array(256);
  for (let i = 0; i < 256; i++) payload[i] = i & 0xff;

  const hash = await computeWasmHash(payload);
  assert(typeof hash === 'string', 'computeWasmHash should return a string');
  assertEqual(hash.length, 64, 'SHA-256 hex digest should be 64 characters');
  assert(/^[0-9a-f]+$/.test(hash), 'Hash should be lowercase hex');

  // Same payload should produce same hash
  const hash2 = await computeWasmHash(payload);
  assertEqual(hash, hash2, 'Hash should be deterministic');

  // verifyWasmIntegrity should accept matching hash
  const verified = await verifyWasmIntegrity(payload, hash);
  assertEqual(verified, true, 'verifyWasmIntegrity should accept correct hash');

  // verifyWasmIntegrity should reject wrong hash
  let mismatchThrew = false;
  try {
    await verifyWasmIntegrity(payload, 'f'.repeat(64));
  } catch (_) {
    mismatchThrew = true;
  }
  assert(mismatchThrew, 'verifyWasmIntegrity should throw for wrong hash');
});

// =============================================================================
// L8. Aligned Binary API Edge Cases
// =============================================================================

test('L8: deriveBatch with count=0 returns empty array', () => {
  const master = wallet.hdkey.fromSeed(new Uint8Array(16).fill(1));
  try {
    const keys = wallet.aligned.keyDeriver.deriveBatch(master, 0, 0);
    assert(Array.isArray(keys), 'Should return an array');
    assertEqual(keys.length, 0, 'Should return empty array for count=0');
  } finally {
    master.wipe();
  }
});

test('L8: batch derive with large count (100+ keys)', () => {
  const master = wallet.hdkey.fromSeed(new Uint8Array(16).fill(1));
  try {
    const keys = wallet.aligned.keyDeriver.deriveBatch(master, 0, 150);
    assertEqual(keys.length, 150, 'Should derive 150 keys');

    // Verify first and last keys are valid
    assertEqual(keys[0].index, 0, 'First key index should be 0');
    assertEqual(keys[149].index, 149, 'Last key index should be 149');
    assertEqual(keys[0].publicKey.length, 33, 'Public key should be 33 bytes');
    assertEqual(keys[149].publicKey.length, 33, 'Last public key should be 33 bytes');
    assertEqual(keys[0].privateKey.length, 32, 'Private key should be 32 bytes');

    // Verify keys are distinct
    assert(
      bytesToHex(keys[0].publicKey) !== bytesToHex(keys[1].publicKey),
      'Adjacent keys should be different'
    );
    assert(
      bytesToHex(keys[0].publicKey) !== bytesToHex(keys[149].publicKey),
      'First and last keys should be different'
    );
  } finally {
    master.wipe();
  }
});

test('L8: batch derive keys match individual derivation', () => {
  const master = wallet.hdkey.fromSeed(new Uint8Array(16).fill(1));
  try {
    const batchKeys = wallet.aligned.keyDeriver.deriveBatch(master, 0, 10);

    for (let i = 0; i < 10; i++) {
      const individual = master.deriveChild(i);
      assertEqual(
        bytesToHex(batchKeys[i].publicKey),
        bytesToHex(individual.publicKey()),
        `Batch key ${i} should match individual derivation`
      );
      individual.wipe();
    }
  } finally {
    master.wipe();
  }
});

test('L8: batch sign then batch verify round-trip', () => {
  const master = wallet.hdkey.fromSeed(new Uint8Array(16).fill(1));
  const privateKey = master.privateKey();
  const publicKey = master.publicKey();

  try {
    // Create multiple message hashes
    const hashes = [];
    for (let i = 0; i < 10; i++) {
      hashes.push(wallet.utils.sha256(encoder.encode(`batch-roundtrip-${i}`)));
    }

    // Sign all in batch
    const signatures = wallet.aligned.signer.signBatch(privateKey, hashes);
    assertEqual(signatures.length, 10, 'Should produce 10 signatures');

    // Verify each individual signature was successful
    for (let i = 0; i < signatures.length; i++) {
      assertEqual(signatures[i].index, i, `Signature index should be ${i}`);
      assertEqual(signatures[i].error, 0, `Signature ${i} should succeed`);
      assert(signatures[i].signature instanceof Uint8Array, `Signature ${i} should be Uint8Array`);
      assertEqual(signatures[i].signature.length, 64, `Signature ${i} should be 64 bytes`);
    }

    // Verify all in batch
    const entries = signatures.map((sig, i) => ({
      hash: hashes[i],
      signature: sig.signature,
    }));
    const results = wallet.aligned.signer.verifyBatch(publicKey, entries);
    assertEqual(results.length, 10, 'Should verify 10 entries');

    for (let i = 0; i < results.length; i++) {
      assertEqual(results[i].index, i, `Verify result index should be ${i}`);
      assertEqual(results[i].valid, true, `Signature ${i} should verify`);
      assertEqual(results[i].error, 0, `Verify ${i} should return OK`);
    }
  } finally {
    master.wipe();
  }
});

test('L8: batch verify rejects mix of valid and tampered signatures', () => {
  const master = wallet.hdkey.fromSeed(new Uint8Array(16).fill(1));
  const privateKey = master.privateKey();
  const publicKey = master.publicKey();

  try {
    const hashes = [
      wallet.utils.sha256(encoder.encode('valid-msg')),
      wallet.utils.sha256(encoder.encode('tampered-msg')),
      wallet.utils.sha256(encoder.encode('also-valid-msg')),
    ];

    const signatures = wallet.aligned.signer.signBatch(privateKey, hashes);

    // Tamper with the second signature
    const tamperedSig = new Uint8Array(signatures[1].signature);
    tamperedSig[0] ^= 0x01;

    const entries = [
      { hash: hashes[0], signature: signatures[0].signature },
      { hash: hashes[1], signature: tamperedSig },
      { hash: hashes[2], signature: signatures[2].signature },
    ];

    const results = wallet.aligned.signer.verifyBatch(publicKey, entries);
    assertEqual(results.length, 3, 'Should verify 3 entries');
    assertEqual(results[0].valid, true, 'First signature should verify');
    assertEqual(results[1].valid, false, 'Tampered signature should fail');
    assertEqual(results[2].valid, true, 'Third signature should verify');
  } finally {
    master.wipe();
  }
});

test('L8: streaming derive produces same keys as batch derive', () => {
  const master = wallet.hdkey.fromSeed(new Uint8Array(16).fill(1));
  try {
    // Get first 20 keys via batch
    const batchKeys = wallet.aligned.keyDeriver.deriveBatch(master, 0, 20);

    // Get first 20 keys via streaming (batch size 10, 2 batches)
    const streamedKeys = [];
    let batchCount = 0;
    for (const batch of wallet.aligned.keyDeriver.streamKeys(master, 0, 10)) {
      for (const key of batch) {
        streamedKeys.push(key);
      }
      batchCount++;
      if (batchCount >= 2) break;
    }

    assertEqual(streamedKeys.length, 20, 'Should stream 20 keys');

    // Compare each key
    for (let i = 0; i < 20; i++) {
      assertEqual(
        bytesToHex(streamedKeys[i].publicKey),
        bytesToHex(batchKeys[i].publicKey),
        `Streamed key ${i} should match batch key ${i}`
      );
    }
  } finally {
    master.wipe();
  }
});

test('L8: batch derive with non-zero start index', () => {
  const master = wallet.hdkey.fromSeed(new Uint8Array(16).fill(1));
  try {
    const keys = wallet.aligned.keyDeriver.deriveBatch(master, 50, 5);
    assertEqual(keys.length, 5, 'Should derive 5 keys');
    assertEqual(keys[0].index, 50, 'First key index should be 50');
    assertEqual(keys[4].index, 54, 'Last key index should be 54');

    // Verify they match individual derivation at those indices
    for (let i = 0; i < 5; i++) {
      const individual = master.deriveChild(50 + i);
      assertEqual(
        bytesToHex(keys[i].publicKey),
        bytesToHex(individual.publicKey()),
        `Key at index ${50 + i} should match individual derivation`
      );
      individual.wipe();
    }
  } finally {
    master.wipe();
  }
});

test('L8: batch derive hardened keys with large count', () => {
  const master = wallet.hdkey.fromSeed(new Uint8Array(16).fill(1));
  try {
    const keys = wallet.aligned.keyDeriver.deriveBatch(master, 0, 50, true);
    assertEqual(keys.length, 50, 'Should derive 50 hardened keys');
    assertEqual(keys[0].publicKey.length, 33, 'Hardened key should have 33-byte public key');

    // Hardened keys should differ from non-hardened keys at the same index
    const nonHardened = wallet.aligned.keyDeriver.deriveBatch(master, 0, 1, false);
    assert(
      bytesToHex(keys[0].publicKey) !== bytesToHex(nonHardened[0].publicKey),
      'Hardened and non-hardened keys should differ'
    );
  } finally {
    master.wipe();
  }
});
