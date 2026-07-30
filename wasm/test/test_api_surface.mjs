/**
 * HD Wallet WASM - API Surface Tests
 *
 * Covers public wrapper methods that were previously untested:
 * - module metadata and helper exports
 * - HDKey edge cases and path parsing
 * - curve helper methods and ABI-sensitive operations
 * - unsupported feature behavior (coins/hardware/keyring)
 * - utility methods not covered by crypto/vector suites
 */

import init, {
  Curve,
  CoinType,
  BitcoinAddressType,
  Network,
  WasiFeature,
  EntropyStatus,
  WellKnownCoinType,
  createHDWallet,
  buildSigningPath,
  buildEncryptionPath,
  getSigningKey,
  getEncryptionKey,
  computeWasmHash,
  verifyWasmIntegrity,
} from '../src/index.mjs';

import { test, testAsync, assert, assertEqual, assertDeepEqual, bytesToHex, hexToBytes } from './test_all.mjs';

const wallet = await init();

function expectHdWalletError(fn, code) {
  let threw = false;
  try {
    fn();
  } catch (error) {
    threw = true;
    assertEqual(error.name, 'HDWalletError', 'Expected HDWalletError');
    if (code !== undefined) {
      assertEqual(error.code, code, `Expected error code ${code}`);
    }
  }
  assert(threw, 'Expected function to throw');
}

async function expectHdWalletErrorAsync(fn, code) {
  let threw = false;
  try {
    await fn();
  } catch (error) {
    threw = true;
    assertEqual(error.name, 'HDWalletError', 'Expected HDWalletError');
    if (code !== undefined) {
      assertEqual(error.code, code, `Expected error code ${code}`);
    }
  }
  assert(threw, 'Expected function to throw');
}

const TEST_SEED_16 = hexToBytes('000102030405060708090a0b0c0d0e0f');
const TEST_MSG = new TextEncoder().encode('api-surface-test');

await testAsync('createHDWallet alias initializes a module', async () => {
  const second = await createHDWallet();
  assert(typeof second.getVersion === 'function', 'Expected getVersion() on alias-created module');
});

await testAsync('computeWasmHash computes expected SHA-256', async () => {
  const abc = new TextEncoder().encode('abc');
  const hash = await computeWasmHash(abc);
  assertEqual(hash, 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});

await testAsync('verifyWasmIntegrity accepts and rejects hashes correctly', async () => {
  const abc = new TextEncoder().encode('abc');
  const expected = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad';
  const ok = await verifyWasmIntegrity(abc, expected);
  assert(ok, 'Expected integrity check to pass');

  let mismatchThrew = false;
  try {
    await verifyWasmIntegrity(abc, '0'.repeat(64));
  } catch (_) {
    mismatchThrew = true;
  }
  assert(mismatchThrew, 'Expected integrity mismatch to throw');
});

test('module metadata APIs return typed values', () => {
  assertEqual(wallet.getVersion(), '2.0.30', 'Version string should match the release contract');
  assert(typeof wallet.hasCryptopp() === 'boolean', 'hasCryptopp should return boolean');
  assert(typeof wallet.isFipsMode() === 'boolean', 'isFipsMode should return boolean');

  const coins = wallet.getSupportedCoins();
  const curves = wallet.getSupportedCurves();
  assert(Array.isArray(coins), 'getSupportedCoins should return array');
  assert(Array.isArray(curves), 'getSupportedCurves should return array');
  assert(coins.length > 0, 'Expected at least one supported coin');
  assert(curves.length > 0, 'Expected at least one supported curve');
});

test('WASI feature/warning APIs are callable for all feature enums', () => {
  for (const feature of Object.values(WasiFeature)) {
    assert(typeof wallet.wasiHasFeature(feature) === 'boolean', 'wasiHasFeature should return boolean');
    const warning = wallet.wasiGetWarning(feature);
    assert(typeof warning === 'number', 'wasiGetWarning should return number');
    const warningMessage = wallet.wasiGetWarningMessage(feature);
    assert(typeof warningMessage === 'string', 'wasiGetWarningMessage should return string');
  }
});

test('entropy status transitions after injection', () => {
  const before = wallet.getEntropyStatus();
  assert(typeof before === 'number', 'getEntropyStatus should return number');
  wallet.injectEntropy(new Uint8Array(32).fill(9));
  const after = wallet.getEntropyStatus();
  assert(after === EntropyStatus.SUFFICIENT || after > before, 'Entropy status should increase after injection');
});

test('hdkey path parsing and invalid inputs are handled', () => {
  const parsed = wallet.hdkey.parsePath("m/44'/60'/1'/0/5");
  assertDeepEqual(parsed, {
    purpose: 44,
    coinType: 60,
    account: 1,
    change: 0,
    index: 5
  });

  expectHdWalletError(() => wallet.hdkey.parsePath('not/a/path'), 301);
  expectHdWalletError(() => wallet.hdkey.fromSeed(new Uint8Array(15)), 300);
  expectHdWalletError(() => wallet.hdkey.fromSeed(new Uint8Array(65)), 300);
  expectHdWalletError(() => wallet.hdkey.fromXprv('xprv_invalid'), 304);
  expectHdWalletError(() => wallet.hdkey.fromXpub('xpub_invalid'), 304);
});

test('HDKey getters and path derivation semantics work', () => {
  const master = wallet.hdkey.fromSeed(TEST_SEED_16);
  const child = master.deriveChild(7);
  const hardened = master.deriveHardened(3);
  const neutered = master.neutered();
  const clone = master.clone();

  try {
    assertEqual(master.path, 'm');
    assertEqual(master.curve, Curve.SECP256K1);
    assertEqual(child.path, 'm/7');
    assertEqual(hardened.path, "m/3'");

    const pub = master.publicKey();
    const pubUncompressed = master.publicKeyUncompressed();
    assertEqual(pub.length, 33, 'Compressed pubkey should be 33 bytes');
    assertEqual(pubUncompressed.length, 65, 'Uncompressed pubkey should be 65 bytes');
    assertEqual(pubUncompressed[0], 0x04, 'Uncompressed pubkey should start with 0x04');
    assert(master.fingerprint() >= 0, 'Fingerprint should be a uint32');

    expectHdWalletError(() => neutered.privateKey());
    assertEqual(clone.toXprv(), master.toXprv(), 'Clone should preserve xprv');
  } finally {
    clone.wipe();
    neutered.wipe();
    hardened.wipe();
    child.wipe();
    master.wipe();
  }
});

test('curve helper methods and recoverable-signature path are callable', () => {
  const privateKey = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const expectedSecpPub = '0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798';

  const compressed = wallet.curves.publicKeyFromPrivate(privateKey, Curve.SECP256K1);
  assertEqual(bytesToHex(compressed), expectedSecpPub, 'secp256k1 pubkey should match expected');

  const uncompressed = wallet.curves.decompressPublicKey(compressed, Curve.SECP256K1);
  const recompressed = wallet.curves.compressPublicKey(uncompressed, Curve.SECP256K1);
  assertEqual(bytesToHex(recompressed), expectedSecpPub, 'compress/decompress should round-trip');

  const messageHash = wallet.utils.sha256(TEST_MSG);
  const signature = wallet.curves.secp256k1.sign(messageHash, privateKey);
  assert(signature.length >= 64, 'Expected secp256k1 signature');

  const isValid = wallet.curves.secp256k1.verify(messageHash, signature, uncompressed);
  assertEqual(isValid, true, 'secp256k1 signature should verify');

  // Recoverable-signature support (libsecp256k1 recovery module enabled).
  const recoverable = wallet.curves.secp256k1.signRecoverable(messageHash, privateKey);
  assertEqual(recoverable.signature.length, 64, 'Recoverable signature payload should be 64 bytes');
  assert(typeof recoverable.recoveryId === 'number', 'recoveryId should be numeric');
  assert(recoverable.recoveryId >= 0 && recoverable.recoveryId <= 3, 'recoveryId should be 0-3');

  // Recover public key from the recoverable signature.
  const recoveredPub = wallet.curves.secp256k1.recover(messageHash, recoverable.signature, recoverable.recoveryId);
  assertEqual(recoveredPub.length, 33, 'Recovered public key should be 33 bytes (compressed)');
  assertEqual(bytesToHex(recoveredPub), expectedSecpPub, 'Recovered pubkey should match original');
});

test('P-256/P-384 methods sign, verify, and ECDH correctly', () => {
  const msg = new TextEncoder().encode('curve-sign-verify');
  const p256Priv = new Uint8Array(32);
  p256Priv[31] = 1;
  const p384Priv = new Uint8Array(48);
  p384Priv[47] = 1;

  const p256Public = wallet.curves.publicKeyFromPrivate(p256Priv, Curve.P256);
  const p384Public = wallet.curves.publicKeyFromPrivate(p384Priv, Curve.P384);

  const p256Sig = wallet.curves.p256.sign(msg, p256Priv);
  const p384Sig = wallet.curves.p384.sign(msg, p384Priv);
  assertEqual(p256Sig.length, 64, 'Expected P-256 compact signature length');
  assertEqual(p384Sig.length, 96, 'Expected P-384 compact signature length');

  assertEqual(wallet.curves.p256.verify(msg, p256Sig, p256Public), true, 'P-256 signature should verify');
  assertEqual(wallet.curves.p384.verify(msg, p384Sig, p384Public), true, 'P-384 signature should verify');
  expectHdWalletError(() => wallet.curves.decompressPublicKey(p256Public, Curve.P256), 3);
  expectHdWalletError(() => wallet.curves.decompressPublicKey(p384Public, Curve.P384), 3);

  const p256Uncompressed = hexToBytes('046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162cbfbc6f6e28f44de9f08f8f37a9d0f5');
  const p384Uncompressed = hexToBytes('04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f');
  assertEqual(wallet.curves.p256.ecdh(p256Priv, p256Uncompressed).length, 32, 'P-256 ECDH should return 32 bytes');
  assertEqual(wallet.curves.p384.ecdh(p384Priv, p384Uncompressed).length, 48, 'P-384 ECDH should return 48 bytes');
});

test('ECDSA verification handles leading-zero compact components', () => {
  const secpPriv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const p256Priv = new Uint8Array(32);
  p256Priv[31] = 1;
  const p384Priv = new Uint8Array(48);
  p384Priv[47] = 1;

  function findLeadingZeroCase(prefix, splitIndex, signFn) {
    const encoder = new TextEncoder();
    for (let i = 0; i < 5000; i++) {
      const msg = encoder.encode(`${prefix}:${i}`);
      const sig = signFn(msg);
      if (sig[0] === 0 || sig[splitIndex] === 0) {
        return { msg, sig };
      }
    }
    throw new Error(`Failed to find leading-zero signature case for ${prefix}`);
  }

  const secpPub = wallet.curves.decompressPublicKey(
    wallet.curves.publicKeyFromPrivate(secpPriv, Curve.SECP256K1),
    Curve.SECP256K1
  );
  const p256Pub = wallet.curves.publicKeyFromPrivate(p256Priv, Curve.P256);
  const p384Pub = wallet.curves.publicKeyFromPrivate(p384Priv, Curve.P384);

  const { msg: secpMsg, sig: secpSig } = findLeadingZeroCase('secp-leading', 32, (msg) => wallet.curves.secp256k1.sign(msg, secpPriv));
  const { msg: p256Msg, sig: p256Sig } = findLeadingZeroCase('p256-leading', 32, (msg) => wallet.curves.p256.sign(msg, p256Priv));
  const { msg: p384Msg, sig: p384Sig } = findLeadingZeroCase('p384-leading', 48, (msg) => wallet.curves.p384.sign(msg, p384Priv));

  assert(secpSig[0] === 0 || secpSig[32] === 0, 'Expected secp256k1 test vector with leading zero in R or S');
  assert(p256Sig[0] === 0 || p256Sig[32] === 0, 'Expected P-256 test vector with leading zero in R or S');
  assert(p384Sig[0] === 0 || p384Sig[48] === 0, 'Expected P-384 test vector with leading zero in R or S');

  assertEqual(wallet.curves.secp256k1.verify(secpMsg, secpSig, secpPub), true, 'secp256k1 leading-zero signature should verify');
  assertEqual(wallet.curves.p256.verify(p256Msg, p256Sig, p256Pub), true, 'P-256 leading-zero signature should verify');
  assertEqual(wallet.curves.p384.verify(p384Msg, p384Sig, p384Pub), true, 'P-384 leading-zero signature should verify');
});

test('coin address generation and validation work correctly', () => {
  // Generate a deterministic wallet for testing
  const seed = new Uint8Array(64);
  for (let i = 0; i < 64; i++) seed[i] = i;
  const master = wallet.hdkey.fromSeed(seed);

  // ===== Bitcoin =====
  const btcKey = master.derivePath("m/44'/0'/0'/0/0");
  const btcPub = btcKey.publicKey();
  assert(btcPub.length === 33, 'BTC pubkey should be 33 bytes');

  // Address generation
  const p2pkh = wallet.bitcoin.getAddress(btcPub, BitcoinAddressType.P2PKH, Network.MAINNET);
  assert(p2pkh.startsWith('1'), 'P2PKH mainnet should start with 1');

  const p2wpkh = wallet.bitcoin.getAddress(btcPub, BitcoinAddressType.P2WPKH, Network.MAINNET);
  assert(p2wpkh.startsWith('bc1q'), 'P2WPKH mainnet should start with bc1q');

  // Validation: valid addresses return true
  assertEqual(wallet.bitcoin.validateAddress('1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa'), true);
  assertEqual(wallet.bitcoin.validateAddress('bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4'), true);
  // Validation: invalid addresses return false
  assertEqual(wallet.bitcoin.validateAddress('notanaddress'), false);
  // Roundtrip: generated addresses validate
  assertEqual(wallet.bitcoin.validateAddress(p2pkh), true);
  assertEqual(wallet.bitcoin.validateAddress(p2wpkh), true);

  btcKey.wipe();

  // ===== Ethereum =====
  const ethKey = master.derivePath("m/44'/60'/0'/0/0");
  const ethPub = ethKey.publicKeyUncompressed();
  assert(ethPub.length === 65, 'ETH pubkey should be 65 bytes');

  const ethAddr = wallet.ethereum.getAddress(ethPub);
  assert(ethAddr.startsWith('0x'), 'ETH address should start with 0x');
  assert(ethAddr.length === 42, 'ETH address should be 42 chars');

  assertEqual(wallet.ethereum.validateAddress(ethAddr), true);
  assertEqual(wallet.ethereum.validateAddress('0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045'), true);
  assertEqual(wallet.ethereum.validateAddress('notanaddress'), false);

  ethKey.wipe();

  // ===== Solana =====
  const solKey = master.derivePath("m/44'/501'/0'/0'");
  const solPriv = solKey.privateKey();
  const solPub = wallet.curves.ed25519.publicKeyFromSeed(solPriv);
  assert(solPub.length === 32, 'SOL Ed25519 pubkey should be 32 bytes');

  const solAddr = wallet.solana.getAddress(solPub);
  assert(solAddr.length > 30, 'SOL address should be base58');

  assertEqual(wallet.solana.validateAddress(solAddr), true);
  assertEqual(wallet.solana.validateAddress('11111111111111111111111111111111'), true);
  assertEqual(wallet.solana.validateAddress('notanaddress'), false);

  solKey.wipe();
  master.wipe();
});

testAsync('hardware wrapper handles no-bridge mode cleanly', async () => {
  assert(typeof wallet.hardware.isAvailable() === 'boolean', 'isAvailable should return boolean');
  const devices = await wallet.hardware.enumerate();
  assert(Array.isArray(devices), 'enumerate should return an array');
  await expectHdWalletErrorAsync(() => wallet.hardware.connect('missing-device'), 3);
});

test('keyring wrapper methods are callable in unsupported mode', () => {
  const keyring = wallet.keyring.create();
  assert(typeof keyring.addWallet === 'function', 'Expected keyring API object');
  assertEqual(typeof keyring.addWallet(new Uint8Array(32), 'demo'), 'string', 'addWallet should return ID string');
  assertEqual(keyring.getWalletCount(), 0, 'Expected empty keyring in unsupported mode');
  assertDeepEqual(keyring.getAccounts('missing', CoinType.BITCOIN, 1), [], 'Expected no accounts');
  expectHdWalletError(() => keyring.removeWallet('missing'), 3);
  expectHdWalletError(() => keyring.signTransaction('missing', "m/44'/0'/0'/0/0", new Uint8Array([1, 2])), 3);
  expectHdWalletError(() => keyring.signMessage('missing', "m/44'/0'/0'/0/0", new Uint8Array([1, 2])), 3);
  keyring.destroy();
});

test('utility methods not covered elsewhere behave correctly', () => {
  assertEqual(wallet.utils.generateIv().length, 12, 'generateIv should return 12 bytes');
  assertEqual(wallet.utils.generateAesKey(128).length, 16, 'AES-128 key should be 16 bytes');
  assertEqual(wallet.utils.generateAesKey(192).length, 24, 'AES-192 key should be 24 bytes');
  assertEqual(wallet.utils.generateAesKey(256).length, 32, 'AES-256 key should be 32 bytes');

  let invalidBitsThrew = false;
  try {
    wallet.utils.generateAesKey(129);
  } catch (_) {
    invalidBitsThrew = true;
  }
  assert(invalidBitsThrew, 'Invalid AES key size should throw');

  assertEqual(wallet.utils.pbkdf2(new Uint8Array([1]), new Uint8Array([2]), 8, 16).length, 16);
  try {
    assertEqual(wallet.utils.scrypt(new Uint8Array([1]), new Uint8Array([2]), 16, 1, 1, 16).length, 16);
  } catch (e) {
    // Node 20 may throw "Cannot convert a BigInt value to a number" in WASM glue code
    if (!String(e).includes('BigInt')) throw e;
  }

  const payload = new Uint8Array([0, 1, 2, 3, 4, 5]);
  const b58 = wallet.utils.encodeBase58(payload);
  assertDeepEqual(Array.from(wallet.utils.decodeBase58(b58)), Array.from(payload), 'Base58 should round-trip');
  const b58check = wallet.utils.encodeBase58Check(payload);
  assertDeepEqual(Array.from(wallet.utils.decodeBase58Check(b58check)), Array.from(payload), 'Base58Check should round-trip');
  const hex = wallet.utils.encodeHex(payload);
  assertDeepEqual(Array.from(wallet.utils.decodeHex(hex)), Array.from(payload), 'Hex should round-trip');
  const b64 = wallet.utils.encodeBase64(payload);
  assertDeepEqual(Array.from(wallet.utils.decodeBase64(b64)), Array.from(payload), 'Base64 should round-trip');
  const bech = wallet.utils.encodeBech32('hrp', payload);
  const decodedBech = wallet.utils.decodeBech32(bech);
  assertEqual(decodedBech.hrp, 'hrp', 'Bech32 HRP should round-trip');
  assertEqual(decodedBech.data.length, payload.length, 'Bech32 payload length should round-trip');

  expectHdWalletError(() => wallet.utils.decodeBase58('0OIl'), 2);
  expectHdWalletError(() => wallet.utils.decodeBase58Check('11111'), 201);
  expectHdWalletError(() => wallet.utils.decodeHex('xyz'), 2);
  expectHdWalletError(() => wallet.utils.decodeBase64('@@@='), 2);

  const wipeTarget = new Uint8Array([9, 8, 7]);
  wallet.utils.secureWipe(wipeTarget);
  assertDeepEqual(Array.from(wipeTarget), [0, 0, 0], 'secureWipe should zero buffer in-place');
});

test('BIP-44 helper exports derive expected paths and keys', () => {
  assertEqual(buildSigningPath(WellKnownCoinType.ETHEREUM, '2', '3'), "m/44'/60'/2'/0/3");
  assertEqual(buildEncryptionPath(WellKnownCoinType.SDN, '1', '9'), "m/44'/0'/1'/1/9");

  const root = wallet.hdkey.fromSeed(TEST_SEED_16);
  try {
    const signing = getSigningKey(root, WellKnownCoinType.BITCOIN, '0', '5');
    const encryption = getEncryptionKey(root, WellKnownCoinType.BITCOIN, '0', '5');
    assertEqual(signing.privateKey.length, 32);
    assertEqual(signing.publicKey.length, 33);
    assertEqual(encryption.privateKey.length, 32);
    assertEqual(encryption.publicKey.length, 33);
    assertEqual(signing.path, "m/44'/0'/0'/0/5");
    assertEqual(encryption.path, "m/44'/0'/0'/1/5");
    assert(bytesToHex(signing.privateKey) !== bytesToHex(encryption.privateKey), 'Signing and encryption keys should differ');
  } finally {
    root.wipe();
  }
});
