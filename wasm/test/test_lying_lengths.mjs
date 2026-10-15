// Binary inputs whose `length` lies (2.1.2 security fix).
//
// HEAPU8.set copies a typed array's own bytes, but the wrappers used to pass
// the caller's `length` to native code. A Uint8Array subclass (or an own
// `length` property) that claimed more bytes than it held made native code
// read freed heap: AES-GCM encrypted 4096 bytes, 4095 of them a secret hashed
// just before. One that claimed fewer bytes than it held got a smaller
// allocation, so the copy wrote past it. Now every wrapper copies the array
// once from its own bytes and length and passes that length on, and the
// validators refuse an array whose `length` is not its own. Each call below
// must throw a library error or give exactly the result of an honest array.
import init, { Curve, HDWalletError, X509Encoding } from '../src/index.mjs';
import { test, assert, assertEqual, bytesToHex, hexToBytes } from './test_all.mjs';

const wallet = await init();
const enc = new TextEncoder();

// Freed heap holds this marker after a secret was hashed.
const MARKER = 0x5c;
const secret = (size) => new Uint8Array(size).fill(MARKER);
const leaveSecretOnHeap = (size = 4096) => wallet.utils.sha256(secret(size));

// Arrays whose length lies: always, only after the first read, or through an
// own property of a plain Uint8Array.
function constantLie(bytes, claim) {
  const Lying = class extends Uint8Array {
    get length() { return claim; }
  };
  return new Lying(bytes);
}
function laterLie(bytes, claim) {
  let reads = 0;
  const Lying = class extends Uint8Array {
    get length() {
      reads += 1;
      return reads === 1 ? super.length : claim;
    }
  };
  return new Lying(bytes);
}
function ownPropertyLie(bytes, claim) {
  const out = Uint8Array.from(bytes);
  Object.defineProperty(out, 'length', { get: () => claim });
  return out;
}
const LIARS = [
  ['constant lie', constantLie],
  ['lie after the first read', laterLie],
  ['own length property', ownPropertyLie],
];

// A comparable form of any result.
function canonical(value) {
  if (value instanceof Uint8Array) return `bytes:${bytesToHex(value)}`;
  if (typeof value === 'bigint') return `bigint:${value}`;
  if (value === undefined) return 'undefined';
  return JSON.stringify(value, (key, v) => {
    if (v instanceof Uint8Array) return `bytes:${bytesToHex(v)}`;
    if (typeof v === 'bigint') return `bigint:${v}`;
    return v;
  });
}

// Every liar of `honest` (claiming `claims`) must be refused with a library
// error or give the honest result. Returns the problems found.
function checkLiars(label, honest, call, claims) {
  const expected = canonical(call(Uint8Array.from(honest)));
  const problems = [];
  for (const [liarName, makeLiar] of LIARS) {
    for (const claim of claims) {
      leaveSecretOnHeap();
      let got;
      try {
        got = canonical(call(makeLiar(honest, claim)));
      } catch (error) {
        if (!(error instanceof HDWalletError)) {
          problems.push(`${label}, ${liarName} ${claim}: ${error?.constructor?.name} ${error?.message}`);
        }
        continue;
      }
      if (got !== expected) problems.push(`${label}, ${liarName} ${claim}: result differs from the honest array's`);
    }
  }
  return problems;
}

test('lying lengths: AES-GCM never encrypts freed heap (the disclosure repro)', () => {
  const key = hexToBytes('11'.repeat(32));
  const iv = hexToBytes('22'.repeat(12));
  leaveSecretOnHeap(4096);
  let ciphertext = null;
  let tag = null;
  try {
    ({ ciphertext, tag } = wallet.utils.aesGcm.encrypt(key, constantLie([1], 4096), iv));
  } catch (error) {
    assert(error instanceof HDWalletError, `expected a library error, got ${error?.message}`);
  }
  if (ciphertext !== null) {
    const plaintext = wallet.utils.aesGcm.decrypt(key, ciphertext, tag, iv);
    const leaked = plaintext.filter((b) => b === MARKER).length;
    assertEqual(leaked, 0, `${leaked} bytes of the freed secret were encrypted`);
    assertEqual(bytesToHex(plaintext), '01', 'only the array\'s own byte is encrypted');
  }
});

test('lying lengths: a short claim never writes past the allocation (the overflow repro)', () => {
  const big = new Uint8Array(65536);
  for (let i = 0; i < big.length; i++) big[i] = i & 0xff;
  const expected = bytesToHex(wallet.utils.sha256(big));
  let got = null;
  try {
    got = bytesToHex(wallet.utils.sha256(constantLie(big, 1)));
  } catch (error) {
    assert(error instanceof HDWalletError, `expected a library error, got ${error?.constructor?.name} ${error?.message}`);
  }
  if (got !== null) assertEqual(got, expected, 'hash of the array\'s own bytes');
  // The heap is intact: the module still signs and verifies.
  const priv = hexToBytes('01'.repeat(32));
  const msg = wallet.utils.sha256(enc.encode('after the overflow repro'));
  const sig = wallet.curves.secp256k1.sign(msg, priv);
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);
  assert(wallet.curves.secp256k1.verify(msg, sig, pub), 'module still signs and verifies');
  assertEqual(bytesToHex(wallet.utils.sha256(big)), expected, 'hashing still correct');
});

test('lying lengths: hashes, KDFs and ciphers use the array\'s own bytes', () => {
  const data = enc.encode('lying lengths');
  const key = hexToBytes('33'.repeat(32));
  const iv12 = hexToBytes('44'.repeat(12));
  const iv16 = hexToBytes('55'.repeat(16));
  const claims = [4096, 3, 0];
  const problems = [];
  for (const name of ['sha256', 'sha512', 'keccak256', 'ripemd160', 'hash160', 'blake2b', 'blake2s']) {
    problems.push(...checkLiars(`utils.${name}`, data, (x) => wallet.utils[name](x), claims));
  }
  problems.push(...checkLiars('utils.hkdf ikm', data, (x) => wallet.utils.hkdf(x, data, data, 32), claims));
  problems.push(...checkLiars('utils.hkdf salt', data, (x) => wallet.utils.hkdf(data, x, data, 32), claims));
  problems.push(...checkLiars('utils.hkdf info', data, (x) => wallet.utils.hkdf(data, data, x, 32), claims));
  problems.push(...checkLiars('utils.pbkdf2 password', data, (x) => wallet.utils.pbkdf2(x, data, 2, 32), claims));
  problems.push(...checkLiars('utils.pbkdf2 salt', data, (x) => wallet.utils.pbkdf2(data, x, 2, 32), claims));
  problems.push(...checkLiars('utils.scrypt password', data, (x) => wallet.utils.scrypt(x, data, 16, 1, 1, 32), claims));
  problems.push(...checkLiars('utils.scrypt salt', data, (x) => wallet.utils.scrypt(data, x, 16, 1, 1, 32), claims));
  problems.push(...checkLiars('aesGcm.encrypt plaintext', data, (x) => wallet.utils.aesGcm.encrypt(key, x, iv12), claims));
  problems.push(...checkLiars('aesGcm.encrypt aad', data, (x) => wallet.utils.aesGcm.encrypt(key, data, iv12, x), claims));
  problems.push(...checkLiars('aesGcm.encrypt key', key, (x) => wallet.utils.aesGcm.encrypt(x, data, iv12), [64, 16]));
  const sealed = wallet.utils.aesGcm.encrypt(key, data, iv12);
  problems.push(...checkLiars('aesGcm.decrypt ciphertext', sealed.ciphertext,
    (x) => wallet.utils.aesGcm.decrypt(key, x, sealed.tag, iv12), claims));
  problems.push(...checkLiars('aesCtr.encrypt plaintext', data, (x) => wallet.aesCtr.encrypt(key, x, iv16), claims));
  const ctr = wallet.aesCtr.encrypt(key, data, iv16);
  problems.push(...checkLiars('aesCtr.decrypt ciphertext', ctr, (x) => wallet.aesCtr.decrypt(key, x, iv16), claims));
  assertEqual(problems.slice(0, 20).join('\n'), '', `${problems.length} lying inputs reached native code`);
});

test('lying lengths: ECIES, signing, verification and ECDH use the array\'s own bytes', () => {
  const msg = wallet.utils.sha256(enc.encode('message'));
  const data = enc.encode('ecies plaintext');
  const claims = [4096, 7];
  const problems = [];
  for (const [name, curve, size] of [['secp256k1', Curve.SECP256K1, 32], ['p256', Curve.P256, 32], ['p384', Curve.P384, 48]]) {
    const priv = new Uint8Array(size).fill(0x07);
    const pub = wallet.curves.publicKeyFromPrivate(priv, curve);
    const peerPriv = new Uint8Array(size).fill(0x09);
    const peerPub = wallet.curves.publicKeyFromPrivate(peerPriv, curve);
    const api = wallet.curves[name];
    const sig = api.sign(msg, priv);
    problems.push(...checkLiars(`${name}.sign message`, msg, (x) => api.sign(x, priv), claims));
    problems.push(...checkLiars(`${name}.sign key`, priv, (x) => api.sign(msg, x), claims));
    problems.push(...checkLiars(`${name}.verify signature`, sig, (x) => api.verify(msg, x, pub), claims));
    problems.push(...checkLiars(`${name}.verify public key`, pub, (x) => api.verify(msg, sig, x), claims));
    problems.push(...checkLiars(`${name}.ecdh public key`, peerPub, (x) => api.ecdh(priv, x), claims));
    problems.push(...checkLiars(`${name}.ecdh private key`, priv, (x) => api.ecdh(x, peerPub), claims));
  }
  const edPriv = new Uint8Array(32).fill(0x0b);
  const edPub = wallet.curves.ed25519.publicKeyFromSeed(edPriv);
  const edSig = wallet.curves.ed25519.sign(msg, edPriv);
  problems.push(...checkLiars('ed25519.sign message', msg, (x) => wallet.curves.ed25519.sign(x, edPriv), claims));
  problems.push(...checkLiars('ed25519.verify signature', edSig, (x) => wallet.curves.ed25519.verify(msg, x, edPub), claims));

  const priv = new Uint8Array(32).fill(0x07);
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);
  // ECIES encryption is randomized: compare what decrypts.
  const roundTrip = (x) => wallet.ecies.decrypt(Curve.SECP256K1, priv, wallet.ecies.encrypt(Curve.SECP256K1, pub, x));
  problems.push(...checkLiars('ecies.encrypt plaintext', data, roundTrip, claims));
  const sealed = wallet.ecies.encrypt(Curve.SECP256K1, pub, data);
  problems.push(...checkLiars('ecies.decrypt ciphertext', sealed, (x) => wallet.ecies.decrypt(Curve.SECP256K1, priv, x), claims));
  assertEqual(problems.slice(0, 20).join('\n'), '', `${problems.length} lying inputs reached native code`);
});

test('lying lengths: transaction parse and sign, X.509 parse use the array\'s own bytes', () => {
  const claims = [4096, 5];
  const problems = [];
  const ethKey = hexToBytes('46'.repeat(32));
  const raw = wallet.ethereum.tx.createEIP1559({
    chainId: 1, nonce: 3, maxPriorityFeePerGas: 1n, maxFeePerGas: 2n, gasLimit: 21_000n,
    to: '0x3535353535353535353535353535353535353535', value: 1n,
  }).sign(ethKey).serialize();
  const parseHash = (x) => {
    const tx = wallet.ethereum.tx.parse(x);
    try { return tx.getHash(); } finally { tx.destroy(); }
  };
  problems.push(...checkLiars('ethereum.tx.parse', raw, parseHash, claims));
  const signWith = (k) => {
    const tx = wallet.ethereum.tx.createEIP1559({
      chainId: 1, nonce: 3, maxPriorityFeePerGas: 1n, maxFeePerGas: 2n, gasLimit: 21_000n,
      to: '0x3535353535353535353535353535353535353535', value: 1n,
    });
    try { return tx.sign(k).serialize(); } finally { tx.destroy(); }
  };
  problems.push(...checkLiars('ethereum tx sign key', ethKey, signWith, [64, 16]));

  if (wallet.x509.isAvailable()) {
    const certKey = wallet.x509.generatePrivateKey(Curve.P256);
    const pem = wallet.x509.createSelfSignedCertificate({
      subjectDn: 'CN=lying.example', serialHex: '01', notBeforeUnix: 1704067200, notAfterUnix: 1735689600,
    }, Curve.P256, certKey, X509Encoding.PEM);
    problems.push(...checkLiars('x509.parseCertificate', enc.encode(pem),
      (x) => wallet.x509.parseCertificate(x, X509Encoding.PEM), claims));
  }
  assertEqual(problems.slice(0, 20).join('\n'), '', `${problems.length} lying inputs reached native code`);
});

// ---------------------------------------------------------------------------
// 2.1.2 (round 3)
// ---------------------------------------------------------------------------

// A library error: HDWalletError, or the aligned API's error with a numeric code.
const isLibraryError = (error) => error instanceof HDWalletError ||
  (error?.name === 'AlignedError' && typeof error.code === 'number');
function outcome(call) {
  try {
    return { value: canonical(call()) };
  } catch (error) {
    return { error };
  }
}

test('networks: the generic coin API takes network ids 0 and 1 only', () => {
  const testnet = 'tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy';
  assert(wallet.coin.validateAddress(0, testnet, 1), 'testnet address on testnet');
  const accepted = [2, 255, 257, -255, -1].filter((network) => wallet.coin.validateAddress(0, testnet, network));
  assertEqual(accepted.join(', '), '', 'network ids read as testnet');
});

test('re-reads: values read twice after the check (Proxy arrays, getters) are refused or used once', () => {
  const problems = [];
  // solana.findPDA: a Proxy whose length answers 2, then 40.
  const programId = new Uint8Array(32).fill(0x11);
  const seeds = [enc.encode('a'), enc.encode('b')];
  const expected = canonical(wallet.solana.findPDA(programId, seeds));
  let lengthReads = 0;
  const shifty = new Proxy(seeds, {
    get(target, key, receiver) {
      if (key === 'length') return ++lengthReads === 1 ? 2 : 40;
      return Reflect.get(target, key, receiver);
    },
  });
  const pda = outcome(() => wallet.solana.findPDA(programId, shifty));
  if (pda.error ? !isLibraryError(pda.error) : pda.value !== expected) problems.push('findPDA with a shifting seed count');

  // aligned verifyBatch: an entry whose hash getter answers another array later.
  const priv = new Uint8Array(32).fill(0x07);
  const pub = wallet.curves.publicKeyFromPrivate(priv, Curve.SECP256K1);
  const hash = wallet.utils.sha256(enc.encode('batch'));
  const [signed] = wallet.aligned.signer.signBatch(priv, [hash]);
  const honest = canonical(wallet.aligned.signer.verifyBatch(pub, [{ hash, signature: signed.signature }]));
  let hashReads = 0;
  const entry = { signature: signed.signature };
  Object.defineProperty(entry, 'hash', { get: () => (++hashReads === 1 ? hash : new Uint8Array(32).fill(0x99)) });
  const batch = outcome(() => wallet.aligned.signer.verifyBatch(pub, [entry]));
  if (batch.error ? !isLibraryError(batch.error) : batch.value !== honest) problems.push('verifyBatch with a changing hash');

  // Liars through cosmos.signDirect (5 arguments) and the IPNS hashes.
  const body = enc.encode('body');
  const authInfo = enc.encode('auth');
  for (const [liarName, makeLiar] of LIARS) {
    const direct = outcome(() => wallet.cosmos.signDirect(makeLiar(body, 4096), authInfo, 'chain', 1n, priv));
    if (direct.error ? !isLibraryError(direct.error)
      : direct.value !== canonical(wallet.cosmos.signDirect(body, authInfo, 'chain', 1n, priv))) {
      problems.push(`cosmos.signDirect body, ${liarName}`);
    }
    const peerId = wallet.libp2p.peerIdFromPublicKey(pub, Curve.SECP256K1);
    for (const name of ['ipnsHash', 'ipnsHashBase32']) {
      const got = outcome(() => wallet.libp2p[name](makeLiar(peerId, 64)));
      if (got.error ? !isLibraryError(got.error) : got.value !== canonical(wallet.libp2p[name](peerId))) {
        problems.push(`libp2p.${name}, ${liarName}`);
      }
    }
  }

  // utils.secureWipe zeroes every byte the array holds, whatever it claims.
  const secretBytes = constantLie(new Uint8Array(64).fill(0x5c), 1);
  wallet.utils.secureWipe(secretBytes);
  if (new Uint8Array(secretBytes).some((b) => b !== 0)) problems.push('secureWipe left bytes past a short length claim');
  assertEqual(problems.join('\n'), '', 'every value is read once');
});

test('detached and non-Uint8Array inputs are the library\'s INVALID_ARGUMENT in every family', () => {
  const detached = () => {
    const bytes = new Uint8Array(16).fill(1);
    structuredClone(bytes.buffer, { transfer: [bytes.buffer] });
    return bytes;
  };
  const key = new Uint8Array(32).fill(0x33);
  const iv = new Uint8Array(12).fill(0x44);
  const certificate = enc.encode('-----BEGIN CERTIFICATE-----\nAA==\n-----END CERTIFICATE-----\n');
  const families = [
    ['utils.sha256', (x) => wallet.utils.sha256(x)],
    ['aesGcm.encrypt plaintext', (x) => wallet.utils.aesGcm.encrypt(key, x, iv)],
    ['aesGcm.encrypt aad', (x) => wallet.utils.aesGcm.encrypt(key, enc.encode('p'), iv, x)],
    ['secp256k1.sign message', (x) => wallet.curves.secp256k1.sign(x, key)],
    ['ethereum.tx.parse', (x) => wallet.ethereum.tx.parse(x)],
  ];
  if (wallet.x509.isAvailable()) {
    families.push(['x509.parseCertificate', (x) => wallet.x509.parseCertificate(x, X509Encoding.PEM)]);
  }
  const problems = [];
  for (const [name, call] of families) {
    const inputs = [
      ['detached', detached()],
      ['ArrayBuffer', name.startsWith('x509') ? certificate.slice().buffer : new Uint8Array(16).buffer],
      ['DataView', new DataView(new ArrayBuffer(16))],
      ['Int8Array', new Int8Array(16)],
    ];
    for (const [kind, input] of inputs) {
      try {
        call(input);
        problems.push(`${name}: ${kind} accepted`);
      } catch (error) {
        if (!(error instanceof HDWalletError) || error.code !== 2) {
          problems.push(`${name}: ${kind} threw ${error?.constructor?.name} ${error?.code ?? ''} ${error?.message}`);
        }
      }
    }
  }
  assertEqual(problems.join('\n'), '', 'refused with INVALID_ARGUMENT');
});
