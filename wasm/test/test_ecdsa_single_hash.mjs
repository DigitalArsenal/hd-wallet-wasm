// ECDSA hashes once. curves.*.sign/verify hash the message (SHA-256; SHA-384
// for P-384); EPM secp256k1 signatures are DER over SHA-256(content); chain
// proofs sign their chain's signed-message digest; sdn-plugin secp256k1-sha256
// signs the message. Every vector here is checked by an independent verifier
// (Node's OpenSSL, or SDN's Go verifiers), and a double-hashed signature, the
// 2.0.x behaviour, must fail.
//
// Frozen vectors: throwaway keys (bytes 0x11/0x22/0x33 repeated). The EPM DER
// and both chain proofs were verified on 2026-10-14 by SDN's Go code
// (sdn-server internal/epm verifySignatureForKey, verifyBitcoinChainProof,
// verifyEthereumChainProof, at space-data-network 4a2873bfe); the EIP-191
// vector is sdn-server/internal/chainsig/testdata/eip191-personal-sign-vectors.json.
import { createHash, createPublicKey, verify as nodeVerify } from 'node:crypto';
import init from '../src/index.mjs';
import { test, assert, assertEqual, bytesToHex, hexToBytes } from './test_all.mjs';
import {
  bitcoinSignedMessageHash,
  buildBitcoinChainProof,
  buildCanonicalPayload,
  buildEPMSigningContent,
  buildEthereumChainProof,
  compactSignatureToDer,
  ethereumPersonalSignHash,
  signEPMContent,
  verifyChainProof,
  verifyEPMSignature,
} from '../src/epm-attestation.mjs';

const wallet = await init();
const enc = new TextEncoder();
const throwawayKey = (byte) => new Uint8Array(32).fill(byte);

// SubjectPublicKeyInfo for an EC point (compressed or not), for Node's OpenSSL.
const CURVE_OID = {
  secp256k1: '06052b8104000a',
  p256: '06082a8648ce3d030107',
  p384: '06052b81040022',
};

function derTlv(tag, bodyHex) {
  const len = bodyHex.length / 2;
  const lenHex = len < 0x80 ? len.toString(16).padStart(2, '0') : '81' + len.toString(16).padStart(2, '0');
  return tag + lenHex + bodyHex;
}

function nodeKey(curve, point) {
  const algorithm = derTlv('30', '06072a8648ce3d0201' + CURVE_OID[curve]);
  const spki = derTlv('30', algorithm + derTlv('03', '00' + bytesToHex(point)));
  return createPublicKey({ key: Buffer.from(hexToBytes(spki)), format: 'der', type: 'spki' });
}

function nodeVerifies(hash, curve, uncompressed, message, signature, dsaEncoding) {
  return nodeVerify(hash, message, { key: nodeKey(curve, uncompressed), dsaEncoding }, signature);
}

// --- frozen cross-language vectors -------------------------------------------

const EPM_VECTOR = {
  epm: { ENTITY_TYPE: 'User', LEGAL_NAME: 'Single Hash Vector', SIGNATURE_TIMESTAMP: 1791900000 },
  publicKey: '034f355bdcb7cc0af728ef3cceb9615d90684bb5b2ca5f859ab0f0b704075871aa',
  signatureDer:
    '304402200f5371812f35f73a756f2be0ca8d6ccd88fa08c0bfeb68616fc8f1a0911ee90502206014171f26807b5f1beec7c2708c5c818a3954c42d6677df1c7fbbcebd5f27ba',
  // ECDSA over SHA-256(SHA-256(content)): what 2.0.x emitted. Must not verify.
  doubleHashedDer:
    '30450221009c619934049b46478671b2ec634237567fe82028614872c21b343fe88cb60148022003017ff59c4de7498f7bb6d6f51fd2a372228c89e3f2592df0bae3ee19fd533d',
};

const CHAIN_PAYLOAD = buildCanonicalPayload({
  xpub: 'xpubSingleHashVector',
  signingPubKeyHex: '00'.repeat(32),
  encryptionPubKeyHex: '01'.repeat(32),
  issuedAt: 1791900000,
});

const BITCOIN_PROOF = {
  address: 'bc1q2vfxp232rx0z9rzn0hay9jptagk8c86d9w4l7k',
  publicKeyHex: '02466d7fcae563e5cb09a0d1870bb580344804617879a14949cf22285f1bae3f27',
  keyPath: "m/84'/0'/0'/0/0",
  signature:
    '202a7344aeb2bb886fe7d49eb6802c8b7b19ed853d8acfd57150cadabb20e377af1aa27f0c002fdd67af33c728c82f8adcebe47ededf0887536737d7e26aaf2b06',
};

const ETHEREUM_PROOF = {
  address: '0x5CbDd86a2FA8Dc4bDdd8a8f69dBa48572EeC07FB',
  publicKeyHex: '023c72addb4fdf09af94f0c94d7fe92a386a7e70cf8a1d85916386bb2535c7b1b1',
  keyPath: "m/44'/60'/0'/0/0",
  signature:
    '2054dbf8630f13a4586d16d7394a2a84c4bef4b8bf3f3e35b5f5b03bcaafdb82c043d949c1217e64068aa2903a047cb27209b3f21c2632b200ae4180f30ca6ec10',
};

// sdn-server/internal/chainsig/testdata/eip191-personal-sign-vectors.json
const SDN_EIP191_VECTOR = {
  message: 'SDN EIP-191 cross-implementation vector 145',
  signatureCompactVrs:
    '1f1b4be460396cf41cdd9fe834abd9e6eb17ede58b9cdd2c61946eff4e3c733e060079d1506289950356551cf7b83f43c5d552c8020032b55d296ab310910e8385',
  publicKey: '0317f7d114db45e9f689acff44aff64ce107868f21e8177cca2802c8ca5b89c710',
};

// --- curves.*.sign / verify hash the message ---------------------------------

test('secp256k1.sign is ECDSA over SHA-256(message): Node crypto verifies it', () => {
  const priv = throwawayKey(0x11);
  const pub = wallet.curves.decompressPublicKey(wallet.curves.publicKeyFromPrivate(priv, 0), 0);
  const message = enc.encode('hash once');
  const sig = wallet.curves.secp256k1.sign(message, priv);
  assertEqual(sig.length, 64, 'compact r||s');
  assert(nodeVerifies('sha256', 'secp256k1', pub, message, sig, 'ieee-p1363'), 'Node verifies sha256(message)');
  assert(wallet.curves.secp256k1.verify(message, sig, pub), 'wallet verifies the message');

  const doubled = wallet.curves.secp256k1.sign(wallet.utils.sha256(message), priv);
  assert(!nodeVerifies('sha256', 'secp256k1', pub, message, doubled, 'ieee-p1363'), 'Node refuses a double hash');
  assert(!wallet.curves.secp256k1.verify(message, doubled, pub), 'wallet refuses a double hash');
});

test('p256.sign hashes with SHA-256 and p384.sign with SHA-384: Node crypto verifies both', () => {
  const message = enc.encode('hash once, NIST curves');
  const p256Priv = throwawayKey(0x21);
  const p256Pub = wallet.curves.publicKeyFromPrivate(p256Priv, 2);
  const p256Sig = wallet.curves.p256.sign(message, p256Priv);
  assert(nodeVerifies('sha256', 'p256', p256Pub, message, p256Sig, 'ieee-p1363'), 'Node verifies P-256');
  assert(!nodeVerifies('sha256', 'p256', p256Pub, message, wallet.curves.p256.sign(wallet.utils.sha256(message), p256Priv), 'ieee-p1363'),
    'Node refuses a double-hashed P-256 signature');

  const p384Priv = new Uint8Array(48).fill(0x31);
  const p384Pub = wallet.curves.publicKeyFromPrivate(p384Priv, 3);
  const p384Sig = wallet.curves.p384.sign(message, p384Priv);
  assert(nodeVerifies('sha384', 'p384', p384Pub, message, p384Sig, 'ieee-p1363'), 'Node verifies P-384 over SHA-384');
});

// --- EPM secp256k1 ----------------------------------------------------------

test('EPM secp256k1: frozen DER vector reproduces, verifies in hd-wallet and Node crypto', () => {
  const priv = throwawayKey(0x11);
  const pub = hexToBytes(EPM_VECTOR.publicKey);
  const content = buildEPMSigningContent(EPM_VECTOR.epm);
  const der = compactSignatureToDer(wallet.curves.secp256k1.sign(content, priv));
  assertEqual(bytesToHex(der), EPM_VECTOR.signatureDer, 'RFC 6979 reproduces the frozen DER');

  const uncompressed = wallet.curves.decompressPublicKey(pub, 0);
  assert(nodeVerifies('sha256', 'secp256k1', uncompressed, content, der, 'der'), 'Node crypto.verify(sha256, DER)');
  assert(verifyEPMSignature(wallet, { ...EPM_VECTOR.epm, SIGNATURE: EPM_VECTOR.signatureDer }, pub), 'verifyEPMSignature accepts');
});

test('EPM secp256k1: a double-hashed signature is refused everywhere', () => {
  const pub = hexToBytes(EPM_VECTOR.publicKey);
  const content = buildEPMSigningContent(EPM_VECTOR.epm);
  const uncompressed = wallet.curves.decompressPublicKey(pub, 0);
  assert(!verifyEPMSignature(wallet, { ...EPM_VECTOR.epm, SIGNATURE: EPM_VECTOR.doubleHashedDer }, pub), 'hd-wallet refuses');
  assert(!nodeVerifies('sha256', 'secp256k1', uncompressed, content, hexToBytes(EPM_VECTOR.doubleHashedDer), 'der'), 'Node refuses');
});

test('EPM secp256k1: signEPMContent emits DER that Node crypto verifies; compact is refused', () => {
  const priv = throwawayKey(0x11);
  const pub = hexToBytes(EPM_VECTOR.publicKey);
  const epm = { ENTITY_TYPE: 'User', LEGAL_NAME: 'Live' };
  const { signature, timestamp } = signEPMContent(wallet, epm, priv, { curve: 'secp256k1' });
  const signed = { ...epm, SIGNATURE: signature, SIGNATURE_TIMESTAMP: timestamp };
  const sig = hexToBytes(signature);
  assertEqual(sig[0], 0x30, 'DER SEQUENCE');
  const content = buildEPMSigningContent(signed);
  assert(nodeVerifies('sha256', 'secp256k1', wallet.curves.decompressPublicKey(pub, 0), content, sig, 'der'), 'Node verifies');
  assert(verifyEPMSignature(wallet, signed, pub), 'hd-wallet verifies');

  const compact = wallet.curves.secp256k1.sign(content, priv);
  assert(!verifyEPMSignature(wallet, { ...signed, SIGNATURE: bytesToHex(compact) }, pub), 'compact r||s is not the EPM encoding');
});

// --- chain proofs -----------------------------------------------------------

test('Chain proofs: SDN Go EIP-191 vector verifies through verifyChainProof', () => {
  const message = enc.encode(SDN_EIP191_VECTOR.message);
  const proof = {
    CHAIN: 'ethereum',
    PUBLIC_KEY: SDN_EIP191_VECTOR.publicKey,
    SIGNATURE: SDN_EIP191_VECTOR.signatureCompactVrs,
    SIGNED_PAYLOAD: bytesToHex(message),
    ALGORITHM: 'secp256k1-compact-ethereum',
    ENCODING: 'compact',
  };
  assert(verifyChainProof(wallet, proof), 'SDN EIP-191 vector verifies');
  assert(!verifyChainProof(wallet, { ...proof, SIGNED_PAYLOAD: bytesToHex(enc.encode('other')) }), 'other message fails');
  assert(!verifyChainProof(wallet, { ...proof, ALGORITHM: 'secp256k1-compact-bitcoin' }), 'not a Bitcoin signed message');
});

test('Chain proofs: frozen Bitcoin/Ethereum proofs (verified by SDN Go) reproduce and verify', () => {
  const btc = buildBitcoinChainProof(wallet, {
    ...BITCOIN_PROOF,
    privateKey: throwawayKey(0x22),
    canonicalPayload: CHAIN_PAYLOAD,
  });
  assertEqual(btc.SIGNATURE, BITCOIN_PROOF.signature, 'Bitcoin proof signature');
  assert(verifyChainProof(wallet, btc), 'Bitcoin proof verifies');
  // The same bytes Bitcoin's signmessage produces (native coins/bitcoin).
  const native = Buffer.from(wallet.bitcoin.signMessage(CHAIN_PAYLOAD, throwawayKey(0x22)), 'base64');
  assertEqual(bytesToHex(native), BITCOIN_PROOF.signature, 'matches native Bitcoin signmessage');

  const eth = buildEthereumChainProof(wallet, {
    ...ETHEREUM_PROOF,
    privateKey: throwawayKey(0x33),
    canonicalPayload: CHAIN_PAYLOAD,
  });
  assertEqual(eth.SIGNATURE, ETHEREUM_PROOF.signature, 'Ethereum proof signature');
  assert(verifyChainProof(wallet, eth), 'Ethereum proof verifies');
});

test('Chain proofs: signatures over a non-protocol digest are refused', () => {
  const payload = enc.encode(CHAIN_PAYLOAD);
  const priv = throwawayKey(0x22);
  const pub = BITCOIN_PROOF.publicKeyHex;
  const compactOver = (digest) => {
    const { signature, recoveryId } = wallet.curves.secp256k1.signRecoverable(digest, priv);
    return '' + (31 + recoveryId).toString(16) + bytesToHex(signature);
  };
  const base = {
    CHAIN: 'bitcoin',
    PUBLIC_KEY: pub,
    SIGNED_PAYLOAD: bytesToHex(payload),
    ALGORITHM: 'secp256k1-compact-bitcoin',
    ENCODING: 'compact',
  };
  // 2.0.x signed sha256(payload) and verified sha256(sha256(payload)).
  assert(!verifyChainProof(wallet, { ...base, SIGNATURE: compactOver(wallet.utils.sha256(payload)) }), 'sha256(payload) refused');
  assert(!verifyChainProof(wallet, { ...base, SIGNATURE: compactOver(wallet.utils.sha256(bitcoinSignedMessageHash(wallet, payload))) }),
    'a re-hashed signed-message digest refused');
  assert(verifyChainProof(wallet, { ...base, SIGNATURE: compactOver(bitcoinSignedMessageHash(wallet, payload)) }), 'the protocol digest verifies');
  assert(!verifyChainProof(wallet, {
    ...base,
    ALGORITHM: 'secp256k1-compact-ethereum',
    SIGNATURE: compactOver(wallet.utils.sha256(ethereumPersonalSignHash(wallet, payload))),
  }), 'a re-hashed personal_sign digest refused');
});

// --- sdn-plugin sign_detached / verify_detached -------------------------------

function frame(payload) {
  return {
    portId: 'message',
    typeRef: { schemaName: 'DetachedSigningRequest.fbs', fileIdentifier: 'SGRQ', schemaHash: [], acceptsAnyFlatbuffer: false },
    payload,
  };
}

test('sdn-plugin secp256k1-sha256: signs the message once; Node verifies; double hash refused', () => {
  const priv = throwawayKey(0x11);
  const pub = wallet.curves.publicKeyFromPrivate(priv, 0);
  const messageBytes = enc.encode('detached message');
  const signed = wallet.plugin.invoke('sign_detached', {
    inputs: [frame({ curve: 'secp256k1', messageBytes, signerPrivateKey: priv })],
  }).outputs[0].payload;
  assertEqual(signed.algorithm, 'secp256k1-sha256', 'algorithm label');
  assertEqual(bytesToHex(signed.digest), bytesToHex(wallet.utils.sha256(messageBytes)), 'reported digest is SHA-256(message)');
  assert(nodeVerifies('sha256', 'secp256k1', wallet.curves.decompressPublicKey(pub, 0), messageBytes, signed.signature, 'ieee-p1363'),
    'Node verifies the detached signature');

  const verified = (signature) => wallet.plugin.invoke('verify_detached', {
    inputs: [frame({ curve: 'secp256k1', messageBytes, signature, publicKey: pub })],
  }).outputs[0].payload.valid;
  assertEqual(verified(signed.signature), true, 'verify_detached accepts');
  assertEqual(verified(wallet.curves.secp256k1.sign(wallet.utils.sha256(messageBytes), priv)), false, 'verify_detached refuses a double hash');

  let threw = false;
  try {
    wallet.plugin.invoke('sign_detached', {
      inputs: [frame({ curve: 'secp256k1', messageBytes, digest: new Uint8Array(32), signerPrivateKey: priv })],
    });
  } catch {
    threw = true;
  }
  assert(threw, 'a caller digest other than SHA-256(message) is refused');
});

test('sdn-plugin walletSign gets the message, not a digest, for secp256k1', () => {
  const priv = throwawayKey(0x11);
  const pub = wallet.curves.publicKeyFromPrivate(priv, 0);
  const messageBytes = enc.encode('wallet-held key');
  let seen = null;
  const plugin = wallet.plugin.withCapabilities({
    walletSign(request) {
      seen = request;
      return { signature: wallet.curves.secp256k1.sign(request.messageBytes, priv), publicKey: pub };
    },
  });
  const signed = plugin.invoke('sign_detached', {
    inputs: [frame({ curve: 'secp256k1', messageBytes })],
  }).outputs[0].payload;
  assertEqual(seen.digest, null, 'walletSign is not handed a digest');
  assertEqual(bytesToHex(seen.messageBytes), bytesToHex(messageBytes), 'walletSign gets the message');
  const valid = wallet.plugin.invoke('verify_detached', {
    inputs: [frame({ curve: 'secp256k1', messageBytes, signature: signed.signature, publicKey: pub })],
  }).outputs[0].payload.valid;
  assertEqual(valid, true, 'wallet-signed detached signature verifies');
});

// --- RFC 6979 deterministic nonces (2.1.1) -----------------------------------
//
// RFC 6979 Appendix A.2.5 (P-256, SHA-256) and A.2.6 (P-384, SHA-384), the
// hashes curves.p256.sign / curves.p384.sign apply. Up to 2.1.0 every curve's
// nonce came from HMAC-SHA256 into hash-sized V and K, so each P-384 nonce
// ended in sixteen 0x01 bytes (the private key falls to a lattice attack on a
// handful of signatures). The native tests also cover the SHA-384/SHA-512
// rows on P-256 and the SHA-256/SHA-512 rows on P-384, which no WASM entry
// point reaches (each curve signs with its own hash).

const RFC6979 = {
  p256: {
    curve: 2,
    hash: 'sha256',
    n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
    x: 'c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721',
    pub: '0460fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6'
      + '7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299',
    rows: {
      sample: {
        k: 'a6e3c57dd01abe90086538398355dd4c3b17aa873382b0f24d6129493d8aad60',
        r: 'efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716',
        s: 'f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8',
      },
      test: {
        k: 'd16b6ae827f17175e040871a1c7ec3500192c4c92677336ec2537acaee0008e0',
        r: 'f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367',
        s: '019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083',
      },
    },
  },
  p384: {
    curve: 3,
    hash: 'sha384',
    n: 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973n,
    x: '6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5',
    pub: '04ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13'
      + '8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720',
    rows: {
      sample: {
        k: '94ed910d1a099dad3254e9242ae85abde4ba15168eaf0ca87a555fd56d10fbca2907e3e83ba95368623b8c4686915cf9',
        r: '94edbb92a5ecb8aad4736e56c691916b3f88140666ce9fa73d64c4ea95ad133c81a648152e44acf96e36dd1e80fabe46',
        s: '99ef4aeb15f178cea1fe40db2603138f130e740a19624526203b6351d0a3a94fa329c145786e679e7b82c71a38628ac8',
      },
      test: {
        k: '015ee46a5bf88773ed9123a5ab0807962d193719503c527b031b4c2d225092ada71f4a459bc0da98adb95837db8312ea',
        r: '8203b63d3c853e8d77227fb377bcf7b7b772e97892a80f36ab775d509d7a5feb0542a7f0812998da8f1dd3ca3cf023db',
        s: 'ddd0760448d42d8a43af45af836fce4de8be06b485e9b61b827c2f13173923e06a739f040649a667bf3b828246baa5a5',
      },
    },
  },
};

const big = (bytes) => BigInt('0x' + bytesToHex(bytes));
function powMod(base, exp, mod) {
  let result = 1n;
  base %= mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    base = (base * base) % mod;
    exp >>= 1n;
  }
  return result;
}
// k = s^-1 (z + r d) mod n from a signature over a known message and key.
function recoverNonce(name, message, signature) {
  const v = RFC6979[name];
  const half = signature.length / 2;
  const r = big(signature.slice(0, half));
  const s = big(signature.slice(half));
  const z = big(createHash(v.hash).update(message).digest());
  const d = BigInt('0x' + v.x);
  return (powMod(s, v.n - 2n, v.n) * (z + r * d)) % v.n;
}

for (const name of ['p256', 'p384']) {
  const v = RFC6979[name];
  const sign = wallet.curves[name].sign;
  for (const [message, row] of Object.entries(v.rows)) {
    test(`RFC 6979 ${name === 'p256' ? 'A.2.5 P-256' : 'A.2.6 P-384'} with ${v.hash.toUpperCase()}, "${message}": r, s and k match`, () => {
      const sig = sign(enc.encode(message), hexToBytes(v.x));
      assertEqual(bytesToHex(sig), row.r + row.s, 'r || s');
      const k = recoverNonce(name, enc.encode(message), sig);
      assertEqual(k.toString(16).padStart(row.k.length, '0'), row.k, 'k');
      assert(wallet.curves[name].verify(enc.encode(message), sig, hexToBytes(v.pub)), 'wallet verifies');
      assert(nodeVerifies(v.hash, name, hexToBytes(v.pub), enc.encode(message), sig, 'ieee-p1363'), 'Node verifies');
    });
  }
}

test('P-384 nonces carry no constant tail (the 2.1.0 nonce ended in 0x01 x 16)', () => {
  const constantTail = BigInt('0x' + '01'.repeat(16));
  const seen = new Set();
  for (let i = 0; i < 8; i++) {
    const message = enc.encode(`nonce tail ${i}`);
    const sig = wallet.curves.p384.sign(message, hexToBytes(RFC6979.p384.x));
    const k = recoverNonce('p384', message, sig);
    assert((k & ((1n << 128n) - 1n)) !== constantTail, `nonce ${i} ends in sixteen 0x01 bytes`);
    seen.add(k & ((1n << 128n) - 1n));
  }
  assertEqual(seen.size, 8, 'every nonce has its own low 128 bits');
});
