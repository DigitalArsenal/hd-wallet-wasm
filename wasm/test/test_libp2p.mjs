/**
 * HD Wallet WASM - libp2p PeerID / IPNS Hash Tests
 */

import init, { Curve } from '../src/index.mjs';
import { test, assert, assertEqual, bytesToHex, hexToBytes } from './test_all.mjs';

const wallet = await init();

// =============================================================================
// Protobuf / Multihash Structure Tests
// =============================================================================

test('libp2p: secp256k1 peerID has correct identity multihash structure', () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const master = wallet.hdkey.fromSeed(seed);
  const pubKey = master.publicKey();
  assertEqual(pubKey.length, 33, 'Compressed pubkey should be 33 bytes');

  const peerId = wallet.libp2p.peerIdFromPublicKey(pubKey, Curve.SECP256K1);
  // Identity multihash: 0x00 + varint(37) + protobuf(37 bytes)
  assertEqual(peerId.length, 39, 'PeerID should be 39 bytes');
  assertEqual(peerId[0], 0x00, 'Should use identity multihash (code 0x00)');
  assertEqual(peerId[1], 0x25, 'Length varint should be 37 (0x25)');
  // Protobuf field 1: tag=0x08, value=2 (Secp256k1)
  assertEqual(peerId[2], 0x08, 'Protobuf field 1 tag');
  assertEqual(peerId[3], 0x02, 'KeyType should be 2 (Secp256k1)');
  // Protobuf field 2: tag=0x12, length=33, data=pubkey
  assertEqual(peerId[4], 0x12, 'Protobuf field 2 tag');
  assertEqual(peerId[5], 0x21, 'Data length should be 33 (0x21)');
  for (let i = 0; i < 33; i++) {
    assertEqual(peerId[6 + i], pubKey[i], `Public key byte ${i} should match`);
  }
  master.wipe();
});

test('libp2p: ed25519 peerID has correct identity multihash structure', () => {
  const seed = hexToBytes('9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60');
  const pubKey = wallet.curves.ed25519.publicKeyFromSeed(seed);

  const peerId = wallet.libp2p.peerIdFromPublicKey(pubKey, Curve.ED25519);
  // Identity multihash: 0x00 + varint(36) + protobuf(36 bytes)
  assertEqual(peerId.length, 38, 'Ed25519 peerID should be 38 bytes');
  assertEqual(peerId[0], 0x00, 'Should use identity multihash');
  assertEqual(peerId[1], 0x24, 'Length varint should be 36 (0x24)');
  assertEqual(peerId[2], 0x08, 'Protobuf field 1 tag');
  assertEqual(peerId[3], 0x01, 'KeyType should be 1 (Ed25519)');
  assertEqual(peerId[4], 0x12, 'Protobuf field 2 tag');
  assertEqual(peerId[5], 0x20, 'Data length should be 32 (0x20)');
});

test('libp2p: P-256 peerID has correct identity multihash structure', () => {
  const privKey = hexToBytes('c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721');
  const pubKey = wallet.curves.publicKeyFromPrivate(privKey, Curve.P256);
  assertEqual(pubKey.length, 33, 'P-256 compressed pubkey should be 33 bytes');

  const peerId = wallet.libp2p.peerIdFromPublicKey(pubKey, Curve.P256);
  assertEqual(peerId.length, 39, 'P-256 peerID should be 39 bytes');
  assertEqual(peerId[3], 0x03, 'KeyType should be 3 (ECDSA/P-256)');
});

// =============================================================================
// PeerID String Encoding Tests
// =============================================================================

test('libp2p: peerIdToString returns valid base58', () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const master = wallet.hdkey.fromSeed(seed);
  const pubKey = master.publicKey();
  const peerId = wallet.libp2p.peerIdFromPublicKey(pubKey, Curve.SECP256K1);
  const peerIdStr = wallet.libp2p.peerIdToString(peerId);

  assert(peerIdStr.length > 0, 'PeerID string should not be empty');
  assert(/^[123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz]+$/.test(peerIdStr),
    'PeerID string should be valid base58');
  master.wipe();
});

// =============================================================================
// IPNS Hash Tests
// =============================================================================

test('libp2p: IPNS hash starts with k (base36 multibase prefix)', () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const master = wallet.hdkey.fromSeed(seed);
  const peerId = wallet.libp2p.peerIdFromPublicKey(master.publicKey(), Curve.SECP256K1);
  const ipns = wallet.libp2p.ipnsHash(peerId);

  assert(ipns.startsWith('k'), 'IPNS hash should start with k');
  assert(/^k[0-9a-z]+$/.test(ipns), 'IPNS hash should be base36 lowercase after prefix');
  master.wipe();
});

test('libp2p: IPNS hash base32 starts with b', () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const master = wallet.hdkey.fromSeed(seed);
  const peerId = wallet.libp2p.peerIdFromPublicKey(master.publicKey(), Curve.SECP256K1);
  const ipns = wallet.libp2p.ipnsHashBase32(peerId);

  assert(ipns.startsWith('b'), 'IPNS base32 hash should start with b');
  assert(/^b[a-z2-7]+$/.test(ipns), 'IPNS hash should be base32 lowercase after prefix');
  master.wipe();
});

// =============================================================================
// HDKey Convenience Method Tests
// =============================================================================

test('libp2p: HDKey.peerId() matches libp2p.peerIdFromPublicKey()', () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const master = wallet.hdkey.fromSeed(seed);

  const directPeerId = wallet.libp2p.peerIdFromPublicKey(master.publicKey(), Curve.SECP256K1);
  const methodPeerId = master.peerId();

  assertEqual(bytesToHex(directPeerId), bytesToHex(methodPeerId),
    'HDKey.peerId() should match libp2p.peerIdFromPublicKey()');
  master.wipe();
});

test('libp2p: HDKey.peerIdString() matches libp2p.peerIdToString()', () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const master = wallet.hdkey.fromSeed(seed);

  const fromNamespace = wallet.libp2p.peerIdToString(master.peerId());
  const fromMethod = master.peerIdString();

  assertEqual(fromNamespace, fromMethod,
    'HDKey.peerIdString() should match libp2p.peerIdToString()');
  master.wipe();
});

test('libp2p: HDKey.ipnsHash() matches libp2p.ipnsHash()', () => {
  const seed = hexToBytes('000102030405060708090a0b0c0d0e0f');
  const master = wallet.hdkey.fromSeed(seed);

  const fromNamespace = wallet.libp2p.ipnsHash(master.peerId());
  const fromMethod = master.ipnsHash();

  assertEqual(fromNamespace, fromMethod,
    'HDKey.ipnsHash() should match libp2p.ipnsHash()');
  master.wipe();
});

// =============================================================================
// Determinism Tests
// =============================================================================

test('libp2p: same mnemonic + path produces same peerID', () => {
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed1 = wallet.mnemonic.toSeed(mnemonic);
  const seed2 = wallet.mnemonic.toSeed(mnemonic);

  const root1 = wallet.hdkey.fromSeed(seed1);
  const root2 = wallet.hdkey.fromSeed(seed2);
  const key1 = root1.derivePath("m/44'/0'/0'/0/0");
  const key2 = root2.derivePath("m/44'/0'/0'/0/0");

  assertEqual(bytesToHex(key1.peerId()), bytesToHex(key2.peerId()),
    'Same mnemonic and path should produce same peerID');
  assertEqual(key1.peerIdString(), key2.peerIdString(),
    'Same mnemonic and path should produce same peerID string');
  assertEqual(key1.ipnsHash(), key2.ipnsHash(),
    'Same mnemonic and path should produce same IPNS hash');

  key1.wipe(); key2.wipe(); root1.wipe(); root2.wipe();
});

test('libp2p: different derivation paths produce different peerIDs', () => {
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const seed = wallet.mnemonic.toSeed(mnemonic);
  const root = wallet.hdkey.fromSeed(seed);

  const key1 = root.derivePath("m/44'/0'/0'/0/0");
  const key2 = root.derivePath("m/44'/0'/0'/0/1");

  assert(bytesToHex(key1.peerId()) !== bytesToHex(key2.peerId()),
    'Different paths should produce different peerIDs');

  key1.wipe(); key2.wipe(); root.wipe();
});

// =============================================================================
// Unsupported Curve Tests
// =============================================================================

test('libp2p: P384 throws unsupported error', () => {
  const fakeKey = new Uint8Array(49);
  let threw = false;
  try {
    wallet.libp2p.peerIdFromPublicKey(fakeKey, Curve.P384);
  } catch (e) {
    threw = true;
    assert(e.message.includes('not supported'), 'Error should mention not supported');
  }
  assert(threw, 'Should throw for P384');
});

test('libp2p: X25519 throws unsupported error', () => {
  const fakeKey = new Uint8Array(32);
  let threw = false;
  try {
    wallet.libp2p.peerIdFromPublicKey(fakeKey, Curve.X25519);
  } catch (e) {
    threw = true;
  }
  assert(threw, 'Should throw for X25519');
});
