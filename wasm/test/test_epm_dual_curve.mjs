// EPM sign/verify across both curves (ed25519 default + secp256k1). The secp256k1
// scheme (ECDSA-DER over sha256(content)) must match the Go/C++ EPM verifiers.
import init from '../src/index.mjs';
import { test, assert, hexToBytes } from './test_all.mjs';
import { signEPMContent, verifyEPMSignature } from '../src/epm-attestation.mjs';

let wallet;
try {
  wallet = await init();
} catch {
  console.log('  Skipping EPM dual-curve tests: WASM module not available');
}

if (wallet) {
  test('EPM ed25519 (default curve) sign -> verify round-trips', () => {
    const seed = new Uint8Array(32).fill(7);
    const pub = wallet.curves.ed25519.publicKeyFromSeed(seed);
    const epm = {
      ENTITY_TYPE: 'User',
      KEYS: [{
        PUBLIC_KEY: '07'.repeat(32),
        KEY_TYPE: 'Signing',
        KEY_PATH: "m/44'/0'/0'/0'/0'",
        ALGORITHM: 'ed25519',
        ENCODING: 'raw-ed25519',
      }],
    };
    const { signature, timestamp } = signEPMContent(wallet, epm, seed);
    const signed = { ...epm, SIGNATURE: signature, SIGNATURE_TIMESTAMP: timestamp };
    assert(verifyEPMSignature(wallet, signed, pub), 'ed25519 EPM verifies (inferred from 32-byte key)');
    assert(
      !verifyEPMSignature(wallet, { ...signed, SIGNATURE_TIMESTAMP: timestamp + 1 }, pub),
      'tampered ed25519 timestamp fails',
    );
    for (const [field, value] of [
      ['KEY_PATH', "m/44'/0'/0'/0'/1'"],
      ['ALGORITHM', 'secp256k1'],
      ['ENCODING', 'compact'],
    ]) {
      const tampered = { ...signed, KEYS: [{ ...signed.KEYS[0], [field]: value }] };
      assert(!verifyEPMSignature(wallet, tampered, pub), `tampered ed25519 ${field} fails`);
    }
  });

  test('EPM secp256k1 sign -> verify round-trips + negatives', () => {
    const priv = new Uint8Array(32);
    priv[31] = 1; // scalar = 1 -> compressed pubkey is the secp256k1 generator point
    const pub = hexToBytes('0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798');
    const epm = {
      ENTITY_TYPE: 'User',
      KEYS: [{
        XPUB: 'xpub-vector',
        KEY_TYPE: 'Signing',
        KEY_PATH: "m/44'/0'/0'/0/0",
        ALGORITHM: 'secp256k1',
        ENCODING: 'compact',
      }],
    };
    const { signature, timestamp } = signEPMContent(wallet, epm, priv, { curve: 'secp256k1' });
    const signed = { ...epm, SIGNATURE: signature, SIGNATURE_TIMESTAMP: timestamp };
    assert(verifyEPMSignature(wallet, signed, pub), 'secp256k1 EPM verifies (inferred from 33-byte key)');
    assert(
      verifyEPMSignature(wallet, signed, pub, { curve: 'secp256k1' }),
      'secp256k1 EPM verifies with explicit curve',
    );
    assert(
      !verifyEPMSignature(wallet, { ...signed, SIGNATURE_TIMESTAMP: timestamp + 1 }, pub),
      'tampered secp256k1 timestamp fails',
    );
    for (const [field, value] of [
      ['KEY_PATH', "m/44'/0'/0'/0/1"],
      ['ALGORITHM', 'ed25519'],
      ['ENCODING', 'raw-ed25519'],
    ]) {
      const tampered = { ...signed, KEYS: [{ ...signed.KEYS[0], [field]: value }] };
      assert(!verifyEPMSignature(wallet, tampered, pub), `tampered secp256k1 ${field} fails`);
    }
  });
}
