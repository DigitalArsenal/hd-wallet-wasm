/**
 * HD Wallet WASM - Extended Feature Verification Tests
 *
 * Covers verification-task items not exercised by the baseline suites:
 * - ECIES encrypt/decrypt
 * - AES-CTR encrypt/decrypt
 * - SLIP-10 Ed25519 path derivation
 * - Coin message signing helpers and "missing wrapper" surfaces
 */

import init, {
  Curve,
  Network,
  BitcoinAddressType,
  BitcoinScriptType,
} from '../src/index.mjs';

import { test, assert, assertEqual, assertThrows, bytesToHex, hexToBytes } from './test_all.mjs';

// Node-only reference implementation for AES-CTR vectors.
import { createCipheriv } from 'crypto';

const wallet = await init();

const encoder = new TextEncoder();

test('ECIES: encrypt/decrypt round-trip (secp256k1 + AAD)', () => {
  const recipientPriv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const recipientPub = wallet.curves.publicKeyFromPrivate(recipientPriv, Curve.SECP256K1);
  const plaintext = encoder.encode('ecies-roundtrip');
  const aad = encoder.encode('aad');

  const ciphertext = wallet.ecies.encrypt('secp256k1', recipientPub, plaintext, aad);
  const decrypted = wallet.ecies.decrypt('secp256k1', recipientPriv, ciphertext, aad);
  assertEqual(bytesToHex(decrypted), bytesToHex(plaintext), 'Expected decrypted plaintext to match');

  // Wrong key should fail.
  const wrongPriv = new Uint8Array(32);
  wrongPriv[31] = 2;
  assertThrows(() => wallet.ecies.decrypt('secp256k1', wrongPriv, ciphertext, aad));

  // Tampering should fail.
  const tampered = ciphertext.slice();
  tampered[tampered.length - 1] ^= 1;
  assertThrows(() => wallet.ecies.decrypt('secp256k1', recipientPriv, tampered, aad));
});

test('AES-CTR: round-trip and matches Node crypto for NIST inputs', () => {
  const key = hexToBytes('2b7e151628aed2a6abf7158809cf4f3c'); // AES-128
  const iv = hexToBytes('f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff');  // 16-byte IV
  const plaintext = hexToBytes(
    '6bc1bee22e409f96e93d7e117393172a' +
    'ae2d8a571e03ac9c9eb76fac45af8e51' +
    '30c81c46a35ce411e5fbc1191a0a52ef' +
    'f69f2445df4f9b17ad2b417be66c3710'
  );

  const ct = wallet.aesCtr.encrypt(key, plaintext, iv);
  const pt = wallet.aesCtr.decrypt(key, ct, iv);
  assertEqual(bytesToHex(pt), bytesToHex(plaintext), 'AES-CTR decrypt should round-trip');

  const cipher = createCipheriv('aes-128-ctr', Buffer.from(key), Buffer.from(iv));
  const expected = Buffer.concat([cipher.update(Buffer.from(plaintext)), cipher.final()]);
  assertEqual(bytesToHex(ct), expected.toString('hex'), 'AES-CTR ciphertext should match Node crypto reference');

  const wrongKey = key.slice();
  wrongKey[0] ^= 1;
  const wrongPt = wallet.aesCtr.decrypt(wrongKey, ct, iv);
  assert(bytesToHex(wrongPt) !== bytesToHex(plaintext), 'Wrong key should not decrypt to the original plaintext');
});

test('SLIP-10: deriveEd25519Path produces usable Ed25519 key material', () => {
  const seed = new Uint8Array(64);
  for (let i = 0; i < seed.length; i++) seed[i] = i;

  const path = "m/44'/1957'/0'/0'/0'";
  const first = wallet.slip10.deriveEd25519Path(seed, path);
  const second = wallet.slip10.deriveEd25519Path(seed, path);

  assertEqual(first.privateKey.length, 32, 'Expected 32-byte derived private key');
  assertEqual(first.chainCode.length, 32, 'Expected 32-byte derived chain code');
  assertEqual(bytesToHex(first.privateKey), bytesToHex(second.privateKey), 'Derivation should be deterministic');
  assertEqual(bytesToHex(first.chainCode), bytesToHex(second.chainCode), 'Derivation should be deterministic');

  const pub = wallet.curves.ed25519.publicKeyFromSeed(first.privateKey);
  const msg = encoder.encode('slip10-ed25519');
  const sig = wallet.curves.ed25519.sign(msg, first.privateKey);
  assertEqual(wallet.curves.ed25519.verify(msg, sig, pub), true, 'Derived key should sign/verify');
});

test('Bitcoin: WIF encode/decode round-trip (compressed/uncompressed)', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');

  const wifCompressed = wallet.bitcoin.toWIF(priv, true, Network.MAINNET);
  assert(wifCompressed[0] === 'K' || wifCompressed[0] === 'L', 'Compressed WIF should start with K or L');
  const decodedCompressed = wallet.bitcoin.fromWIF(wifCompressed);
  assertEqual(decodedCompressed.compressed, true);
  assertEqual(bytesToHex(decodedCompressed.privateKey), bytesToHex(priv));

  const wifUncompressed = wallet.bitcoin.toWIF(priv, false, Network.MAINNET);
  assertEqual(wifUncompressed[0], '5', 'Uncompressed WIF should start with 5');
  const decodedUncompressed = wallet.bitcoin.fromWIF(wifUncompressed);
  assertEqual(decodedUncompressed.compressed, false);
  assertEqual(bytesToHex(decodedUncompressed.privateKey), bytesToHex(priv));
});

test('Bitcoin: message signing verifies against derived address', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);
  const address = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2PKH, Network.MAINNET);

  const msg = 'Hello Bitcoin!';
  const sig = wallet.bitcoin.signMessage(msg, priv, true);
  assertEqual(wallet.bitcoin.verifyMessage(msg, sig, address, Network.MAINNET), true);
  assertEqual(wallet.bitcoin.verifyMessage('Hello Bitcoin?', sig, address, Network.MAINNET), false);
  assertEqual(wallet.bitcoin.verifyMessage(msg, sig, '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', Network.MAINNET), false);
});

test('Bitcoin: decodeAddress/detectAddressType cover common formats + testnet', () => {
  const p2pkh = '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa';
  assertEqual(wallet.bitcoin.detectAddressType(p2pkh, Network.MAINNET), BitcoinAddressType.P2PKH);
  const decoded = wallet.bitcoin.decodeAddress(p2pkh);
  assertEqual(decoded.type, BitcoinAddressType.P2PKH);
  assertEqual(decoded.hash.length, 20);
  assertEqual(decoded.network, Network.MAINNET);

  const bech32 = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
  assertEqual(wallet.bitcoin.detectAddressType(bech32, Network.MAINNET), BitcoinAddressType.P2WPKH);
  const decodedBech32 = wallet.bitcoin.decodeAddress(bech32);
  assertEqual(decodedBech32.type, BitcoinAddressType.P2WPKH);
  assertEqual(decodedBech32.hash.length, 20);
  assertEqual(decodedBech32.network, Network.MAINNET);

  // Generated address types validate and detect correctly.
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const p2sh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2SH, Network.MAINNET);
  assert(p2sh.startsWith('3'), 'Expected P2SH address to start with 3');
  assertEqual(wallet.bitcoin.detectAddressType(p2sh, Network.MAINNET), BitcoinAddressType.P2SH);
  assertEqual(wallet.bitcoin.validateAddress(p2sh, Network.MAINNET), true);

  const witnessScript = new Uint8Array([0x51]); // OP_1 (any script works for P2WSH address derivation)
  const p2wsh = wallet.bitcoin.getAddress(witnessScript, BitcoinAddressType.P2WSH, Network.MAINNET);
  assert(p2wsh.startsWith('bc1q'), 'Expected P2WSH address to start with bc1q');
  assertEqual(wallet.bitcoin.detectAddressType(p2wsh, Network.MAINNET), BitcoinAddressType.P2WSH);
  assertEqual(wallet.bitcoin.validateAddress(p2wsh, Network.MAINNET), true);

  const p2tr = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2TR, Network.MAINNET);
  assert(p2tr.startsWith('bc1p'), 'Expected P2TR address to start with bc1p');
  assertEqual(wallet.bitcoin.detectAddressType(p2tr, Network.MAINNET), BitcoinAddressType.P2TR);
  assertEqual(wallet.bitcoin.validateAddress(p2tr, Network.MAINNET), true);

  const testnetP2wpkh = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2WPKH, Network.TESTNET);
  assert(testnetP2wpkh.startsWith('tb1q'), 'Expected testnet P2WPKH to start with tb1q');
  assertEqual(wallet.bitcoin.validateAddress(testnetP2wpkh, Network.TESTNET), true);
});

test('Ethereum: EIP-55 checksum verification and EIP-191 sign/recover', () => {
  const checksummed = '0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045';
  const lowercase = '0xd8da6bf26964af9d7eed9e03e53415d37aa96045';
  assertEqual(wallet.ethereum.verifyChecksum(checksummed), true);
  assertEqual(wallet.ethereum.verifyChecksum(lowercase), false);

  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const compressed = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);
  const uncompressed = wallet.curves.decompressPublicKey(compressed, Curve.SECP256K1);
  const expectedAddress = wallet.ethereum.getAddress(uncompressed);

  const msg = 'Hello Ethereum!';
  const sig = wallet.ethereum.signMessage(msg, priv);
  assert(sig.startsWith('0x') && sig.length === 132, 'Expected 65-byte 0x-prefixed signature hex');
  const recovered = wallet.ethereum.verifyMessage(msg, sig);
  assertEqual(recovered.toLowerCase(), expectedAddress.toLowerCase(), 'Recovered address should match expected signer');

  // hashMessage matches manual keccak(prefix || message) computation.
  const msgBytes = encoder.encode(msg);
  const prefix = encoder.encode(`\x19Ethereum Signed Message:\n${msgBytes.length}`);
  const expectedHash = wallet.utils.keccak256(new Uint8Array([...prefix, ...msgBytes]));
  assertEqual(bytesToHex(wallet.ethereum.hashMessage(msg)), bytesToHex(expectedHash));
});

test('Ethereum: EIP-712 typed data signing returns a 65-byte signature', () => {
  const typedData = {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Person: [
        { name: 'name', type: 'string' },
        { name: 'wallet', type: 'address' },
      ],
      Mail: [
        { name: 'from', type: 'Person' },
        { name: 'to', type: 'Person' },
        { name: 'contents', type: 'string' },
      ],
    },
    primaryType: 'Mail',
    domain: {
      name: 'Ether Mail',
      version: '1',
      chainId: 1,
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    message: {
      from: {
        name: 'Cow',
        wallet: '0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826',
      },
      to: {
        name: 'Bob',
        wallet: '0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB',
      },
      contents: 'Hello, Bob!',
    },
  };

  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const sig = wallet.ethereum.signTypedData(typedData, priv);
  assert(sig.startsWith('0x') && sig.length === 132, 'Expected 65-byte 0x-prefixed signature hex');
});

test('Cosmos: address, prefix conversion, and amino signing verify round-trip', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const addr = wallet.cosmos.getAddress(pub, 'cosmos');
  assert(addr.startsWith('cosmos1'), 'Expected cosmos address prefix');
  assertEqual(wallet.cosmos.validateAddress(addr, 'cosmos'), true);
  assertEqual(wallet.cosmos.validateAddress(addr, 'osmo'), false);

  const osmo = wallet.cosmos.convertPrefix(addr, 'osmo');
  assert(osmo.startsWith('osmo1'), 'Expected osmo prefix conversion');
  assertEqual(wallet.cosmos.validateAddress(osmo, 'osmo'), true);

  const signDoc = {
    account_number: '1',
    chain_id: 'cosmoshub-4',
    fee: { amount: [], gas: '200000' },
    memo: '',
    msgs: [],
    sequence: '0',
  };

  const sig = wallet.cosmos.signAmino(signDoc, priv);
  assertEqual(sig.length, 64, 'Expected 64-byte amino signature');

  // Verify uses the canonical JSON bytes produced by signAmino.
  const canonical = `{\"account_number\":\"1\",\"chain_id\":\"cosmoshub-4\",\"fee\":{\"amount\":[],\"gas\":\"200000\"},\"memo\":\"\",\"msgs\":[],\"sequence\":\"0\"}`;
  const ok = wallet.cosmos.verifySignature(new TextEncoder().encode(canonical), sig, pub);
  assertEqual(ok, true, 'Expected amino signature verification to succeed');
});

test('Polkadot: address encode/decode and message signing verify round-trip', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.polkadot.derivePubkey(priv);

  const addr0 = wallet.polkadot.getAddress(pub, 0);
  assertEqual(wallet.polkadot.validateAddress(addr0, 0), true);
  const decoded = wallet.polkadot.decodeAddress(addr0);
  assertEqual(decoded.prefix, 0);
  assertEqual(bytesToHex(decoded.publicKey), bytesToHex(pub));

  const addr42 = wallet.polkadot.convertPrefix(addr0, 42);
  assertEqual(wallet.polkadot.validateAddress(addr42, 42), true);

  const msg = encoder.encode('polkadot-msg');
  const sig = wallet.polkadot.signMessage(msg, priv);
  assertEqual(sig.length, 64, 'Expected 64-byte Ed25519 signature');
  assertEqual(wallet.polkadot.verifyMessage(msg, sig, pub), true);
});

test('Solana: addressToPubkey/derivePubkey and PDA/ATA helpers are callable', () => {
  const seed = new Uint8Array(32);
  seed[31] = 7;
  const pub = wallet.curves.ed25519.publicKeyFromSeed(seed);
  const addr = wallet.solana.getAddress(pub);

  const roundTrip = wallet.solana.addressToPubkey(addr);
  assertEqual(bytesToHex(roundTrip), bytesToHex(pub));

  const derived = wallet.solana.derivePubkey(seed);
  assertEqual(bytesToHex(derived), bytesToHex(pub));

  // PDA: deterministic and yields a valid address.
  const programId = pub;
  const pda1 = wallet.solana.findPDA(programId, [encoder.encode('seed')]);
  const pda2 = wallet.solana.findPDA(programId, [encoder.encode('seed')]);
  assertEqual(pda1.address, pda2.address);
  assertEqual(pda1.bump, pda2.bump);
  assertEqual(wallet.solana.validateAddress(pda1.address), true);

  // ATA: deterministic and yields a valid address.
  const mint = 'So11111111111111111111111111111111111111112'; // Wrapped SOL mint
  const ata = wallet.solana.getAssociatedTokenAddress(addr, mint);
  assertEqual(wallet.solana.validateAddress(ata), true);
});

// =========================================================================
// M1. Bitcoin Message Signing/Verification (supplemental assertions)
// =========================================================================

test('Bitcoin: signMessage returns base64 string, verifyMessage rejects tampering', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);
  const address = wallet.bitcoin.getAddress(pub, BitcoinAddressType.P2PKH, Network.MAINNET);

  // signMessage returns a non-empty base64-encoded string
  const sig = wallet.bitcoin.signMessage('Hello', priv, true);
  assert(typeof sig === 'string' && sig.length > 0, 'signMessage should return a non-empty string');

  // Decode the base64 to verify it is 65 bytes (1 header + 32 r + 32 s)
  const sigBytes = wallet.utils.decodeBase64(sig);
  assertEqual(sigBytes.length, 65, 'Bitcoin message signature should be 65 bytes');

  // Positive verification
  assertEqual(wallet.bitcoin.verifyMessage('Hello', sig, address, Network.MAINNET), true,
    'verifyMessage should return true for matching message, sig, and address');

  // Tampered message
  assertEqual(wallet.bitcoin.verifyMessage('Hello!', sig, address, Network.MAINNET), false,
    'verifyMessage should return false for tampered message');

  // Wrong address (Satoshi's genesis address)
  assertEqual(wallet.bitcoin.verifyMessage('Hello', sig, '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', Network.MAINNET), false,
    'verifyMessage should return false for wrong address');
});

// =========================================================================
// M2. Ethereum Message Signing / EIP-191 (supplemental tampered-sig test)
// =========================================================================

test('Ethereum: EIP-191 verifyMessage with tampered signature recovers different address', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const compressed = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);
  const uncompressed = wallet.curves.decompressPublicKey(compressed, Curve.SECP256K1);
  const expectedAddress = wallet.ethereum.getAddress(uncompressed);

  const msg = 'Hello';
  const sig = wallet.ethereum.signMessage(msg, priv);
  assert(sig.startsWith('0x') && sig.length === 132, 'Expected 65-byte 0x-prefixed signature hex');

  const recovered = wallet.ethereum.verifyMessage(msg, sig);
  assertEqual(recovered.toLowerCase(), expectedAddress.toLowerCase(),
    'Recovered address should match signer');

  // Tamper with the r-component of the signature (byte index 2..3 in hex after 0x)
  const sigHex = sig.slice(2); // strip 0x
  const sigArray = [];
  for (let i = 0; i < sigHex.length; i += 2) {
    sigArray.push(parseInt(sigHex.slice(i, i + 2), 16));
  }
  sigArray[0] ^= 0x01; // flip a bit in r
  const tamperedSig = '0x' + sigArray.map(b => b.toString(16).padStart(2, '0')).join('');

  let tamperedRecoveredDiffers = false;
  try {
    const tamperedRecovered = wallet.ethereum.verifyMessage(msg, tamperedSig);
    // If recovery succeeds, the address must differ from the original signer
    tamperedRecoveredDiffers = tamperedRecovered.toLowerCase() !== expectedAddress.toLowerCase();
  } catch (_) {
    // Tampered signature may also throw, which is acceptable
    tamperedRecoveredDiffers = true;
  }
  assert(tamperedRecoveredDiffers,
    'Tampered signature should recover a different address or throw');
});

// =========================================================================
// M3. Ethereum Typed Data Signing / EIP-712 (supplemental determinism test)
// =========================================================================

test('Ethereum: EIP-712 signTypedData is deterministic and produces distinct sigs for different data', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');

  const typedData1 = {
    types: {
      EIP712Domain: [
        { name: 'name', type: 'string' },
        { name: 'version', type: 'string' },
        { name: 'chainId', type: 'uint256' },
        { name: 'verifyingContract', type: 'address' },
      ],
      Test: [
        { name: 'value', type: 'uint256' },
      ],
    },
    primaryType: 'Test',
    domain: {
      name: 'TestDapp',
      version: '1',
      chainId: 1,
      verifyingContract: '0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC',
    },
    message: { value: 42 },
  };

  const sig1a = wallet.ethereum.signTypedData(typedData1, priv);
  const sig1b = wallet.ethereum.signTypedData(typedData1, priv);
  assertEqual(sig1a, sig1b, 'EIP-712 signing should be deterministic');

  // Change the message value
  const typedData2 = JSON.parse(JSON.stringify(typedData1));
  typedData2.message.value = 99;
  const sig2 = wallet.ethereum.signTypedData(typedData2, priv);
  assert(sig2 !== sig1a, 'Different typed data should produce different signatures');

  // Both must be valid 65-byte signatures
  assert(sig1a.startsWith('0x') && sig1a.length === 132, 'Signature 1 should be 65 bytes hex');
  assert(sig2.startsWith('0x') && sig2.length === 132, 'Signature 2 should be 65 bytes hex');
});

// =========================================================================
// M4. Solana Message Signing/Verification
// =========================================================================

test('Solana: signMessage returns 64-byte Ed25519 signature, verifyMessage round-trips', () => {
  // Use a 32-byte seed as Ed25519 private key
  const privKey = new Uint8Array(32);
  privKey[31] = 7;
  const pubKey = wallet.solana.derivePubkey(privKey);

  const msg = encoder.encode('Hello Solana!');
  const sig = wallet.solana.signMessage(msg, privKey);

  // Signature should be 64 bytes (Ed25519)
  assertEqual(sig.length, 64, 'Solana signMessage should return a 64-byte signature');

  // Verification should succeed with correct pubkey
  assertEqual(wallet.solana.verifyMessage(msg, sig, pubKey), true,
    'verifyMessage should return true for valid signature');
});

test('Solana: verifyMessage rejects wrong pubkey', () => {
  const privKey = new Uint8Array(32);
  privKey[31] = 7;

  const msg = encoder.encode('Hello Solana!');
  const sig = wallet.solana.signMessage(msg, privKey);

  // Derive a different pubkey from a different seed
  const wrongPriv = new Uint8Array(32);
  wrongPriv[31] = 8;
  const wrongPub = wallet.solana.derivePubkey(wrongPriv);

  let verifyResult = false;
  try {
    verifyResult = wallet.solana.verifyMessage(msg, sig, wrongPub);
  } catch (_) {
    // Throws are also acceptable for invalid verification
    verifyResult = false;
  }
  assertEqual(verifyResult, false, 'verifyMessage should return false for wrong pubkey');
});

test('Solana: verifyMessage rejects tampered message', () => {
  const privKey = new Uint8Array(32);
  privKey[31] = 7;
  const pubKey = wallet.solana.derivePubkey(privKey);

  const msg = encoder.encode('Hello Solana!');
  const sig = wallet.solana.signMessage(msg, privKey);

  const tamperedMsg = encoder.encode('Hello Solana?');
  let verifyResult = false;
  try {
    verifyResult = wallet.solana.verifyMessage(tamperedMsg, sig, pubKey);
  } catch (_) {
    verifyResult = false;
  }
  assertEqual(verifyResult, false, 'verifyMessage should return false for tampered message');
});

test('Solana: signMessage is deterministic', () => {
  const privKey = new Uint8Array(32);
  privKey[31] = 7;

  const msg = encoder.encode('determinism-test');
  const sig1 = wallet.solana.signMessage(msg, privKey);
  const sig2 = wallet.solana.signMessage(msg, privKey);
  assertEqual(bytesToHex(sig1), bytesToHex(sig2), 'Solana signMessage should be deterministic');
});

// =========================================================================
// M5. Cosmos Signing (signDirect + verify round-trip)
// =========================================================================

test('Cosmos: signDirect with raw sign-doc bytes and verify round-trip', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  // Build a minimal protobuf-like SignDoc (just arbitrary bytes for the test).
  // signDirect(signDocBytes, privateKey) overload (2-argument form) signs the raw bytes.
  const signDocBytes = encoder.encode('test-cosmos-sign-direct-payload');

  const sig = wallet.cosmos.signDirect(signDocBytes, priv);
  assertEqual(sig.length, 64, 'Expected 64-byte direct signature');

  // Verify round-trip with verifySignature
  const ok = wallet.cosmos.verifySignature(signDocBytes, sig, pub);
  assertEqual(ok, true, 'Expected direct signature verification to succeed');

  // Verification with tampered bytes should fail
  const tampered = encoder.encode('test-cosmos-sign-direct-TAMPERED');
  const tamperedOk = wallet.cosmos.verifySignature(tampered, sig, pub);
  assertEqual(tamperedOk, false, 'Tampered payload should not verify');
});

test('Cosmos: signDirect with body/authInfo/chainId/accountNumber form', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  // Minimal protobuf-encoded body and authInfo (just raw bytes for testing)
  const bodyBytes = new Uint8Array([0x0a, 0x02, 0x08, 0x01]);
  const authInfoBytes = new Uint8Array([0x12, 0x04, 0x0a, 0x02, 0x08, 0x01]);
  const chainId = 'cosmoshub-4';
  const accountNumber = 1;

  const sig = wallet.cosmos.signDirect(bodyBytes, authInfoBytes, chainId, accountNumber, priv);
  assertEqual(sig.length, 64, 'Expected 64-byte direct signature from full-form signDirect');

  // signDirect builds a SignDoc internally; we cannot easily verify it with verifySignature
  // without replicating the protobuf encoding. Instead, verify that calling it twice
  // with the same inputs produces the same signature (determinism).
  const sig2 = wallet.cosmos.signDirect(bodyBytes, authInfoBytes, chainId, accountNumber, priv);
  assertEqual(bytesToHex(sig), bytesToHex(sig2), 'signDirect should be deterministic');
});

test('Cosmos: verify alias works equivalently to verifySignature', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);

  const signDoc = {
    account_number: '0',
    chain_id: 'test-chain',
    fee: { amount: [], gas: '100000' },
    memo: '',
    msgs: [],
    sequence: '0',
  };

  const sig = wallet.cosmos.signAmino(signDoc, priv);
  const canonical = `{"account_number":"0","chain_id":"test-chain","fee":{"amount":[],"gas":"100000"},"memo":"","msgs":[],"sequence":"0"}`;
  const docBytes = new TextEncoder().encode(canonical);

  // verify is an alias for verifySignature with swapped arg order
  const okDirect = wallet.cosmos.verifySignature(docBytes, sig, pub);
  const okAlias = wallet.cosmos.verify(sig, docBytes, pub);
  assertEqual(okDirect, true, 'verifySignature should succeed');
  assertEqual(okAlias, true, 'verify alias should succeed');
});

// =========================================================================
// M6. Polkadot Signing (supplemental wrong-pubkey and tampered-message tests)
// =========================================================================

test('Polkadot: verifyMessage rejects wrong pubkey', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.polkadot.derivePubkey(priv);

  const msg = encoder.encode('polkadot-wrong-key-test');
  const sig = wallet.polkadot.signMessage(msg, priv);
  assertEqual(wallet.polkadot.verifyMessage(msg, sig, pub), true,
    'Correct pubkey should verify');

  // Different key
  const wrongPriv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000002');
  const wrongPub = wallet.polkadot.derivePubkey(wrongPriv);

  let verifyResult = false;
  try {
    verifyResult = wallet.polkadot.verifyMessage(msg, sig, wrongPub);
  } catch (_) {
    verifyResult = false;
  }
  assertEqual(verifyResult, false, 'Wrong pubkey should not verify');
});

test('Polkadot: verifyMessage rejects tampered message', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');
  const pub = wallet.polkadot.derivePubkey(priv);

  const msg = encoder.encode('polkadot-original');
  const sig = wallet.polkadot.signMessage(msg, priv);

  const tampered = encoder.encode('polkadot-tampered');
  let verifyResult = false;
  try {
    verifyResult = wallet.polkadot.verifyMessage(tampered, sig, pub);
  } catch (_) {
    verifyResult = false;
  }
  assertEqual(verifyResult, false, 'Tampered message should not verify');
});

test('Polkadot: signMessage is deterministic', () => {
  const priv = hexToBytes('0000000000000000000000000000000000000000000000000000000000000001');

  const msg = encoder.encode('polkadot-determinism');
  const sig1 = wallet.polkadot.signMessage(msg, priv);
  const sig2 = wallet.polkadot.signMessage(msg, priv);
  assertEqual(bytesToHex(sig1), bytesToHex(sig2), 'Polkadot signMessage should be deterministic');
});
