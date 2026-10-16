// Hostile inputs to envelopes.js: files a stranger can drop on Verify or
// Decrypt. Every one must come back as a result ({kind:'unknown'},
// {ok:false}, reason 'not-peer-id'), never an exception and never a stall.
// Public BIP-39 test vector only.

import initHDWallet from 'hd-wallet-wasm';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  buildRecFile,
  classifyInput,
  decryptFile,
  encryptContent,
  extractTrailer,
  parsePeerId,
  peerIdFromEd25519,
  signContent,
  verifyInput,
} from '../src/envelopes.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

let w;
let me;

beforeAll(async () => {
  w = await initHDWallet();
  const seed = w.mnemonic.toSeed(MNEMONIC);
  const edPriv = w.slip10.deriveEd25519Path(seed, "m/44'/0'/0'/0'/0'").privateKey;
  const xPriv = w.slip10.deriveEd25519Path(seed, "m/44'/0'/0'/1'/0'").privateKey;
  seed.fill(0);
  const edPub = w.curves.ed25519.publicKeyFromSeed(edPriv);
  me = { edPriv, xPriv, xPub: w.curves.x25519.publicKey(xPriv), peerId: peerIdFromEd25519(w, edPub) };
});

// The byte offset, inside `bytes`, of the ENC table's vtable entry for `vOff`.
function encVtableSlot(bytes, vOff) {
  const t = extractTrailer(w, bytes);
  const recStart = t.payload.length;
  const rec = bytes.subarray(recStart, bytes.length - 8);
  const dv = new DataView(rec.buffer, rec.byteOffset, rec.length);
  const table = (pos) => ({ pos, vt: pos - dv.getInt32(pos, true) });
  const ref = (at) => at + dv.getUint32(at, true);
  const root = table(dv.getUint32(0, true));
  const records = ref(root.pos + dv.getUint16(root.vt + 6, true));
  const record0 = table(ref(records + 4));
  const encTable = table(ref(record0.pos + dv.getUint16(record0.vt + 6, true)));
  return recStart + encTable.vt + vOff;
}

function withoutEncField(bytes, vOff) {
  const out = Uint8Array.from(bytes);
  const slot = encVtableSlot(out, vOff);
  out[slot] = 0;
  out[slot + 1] = 0;
  return out;
}

describe('a peer ID is length-checked before it is decoded', () => {
  it('refuses a long "peer ID" at once', () => {
    const start = performance.now();
    expect(parsePeerId(w, 'z'.repeat(1_000_000))).toBeNull();
    expect(parsePeerId(w, '1'.repeat(65))).toBeNull();
    expect(performance.now() - start).toBeLessThan(50);
    expect(parsePeerId(w, me.peerId)).toMatchObject({ keyType: 'Ed25519' });
  });

  it('a .rec whose signer address is 80,000 characters verifies (as not a peer ID) without stalling', () => {
    const content = new TextEncoder().encode('hello');
    const notice = signContent(w, { content, name: 'm.txt', signingKey: me.edPriv });
    const hostile = buildRecFile(w, content, { ...notice, MULTIFORMAT_ADDRESS: `/p2p/${'z'.repeat(80_000)}` });
    const start = performance.now();
    const result = verifyInput(w, hostile);
    expect(performance.now() - start).toBeLessThan(500);
    expect(result).toMatchObject({ kind: 'rec', valid: false, reason: 'not-peer-id' });
  });
});

describe('an ENC record without its key or nonce', () => {
  for (const [field, vOff] of [['EPHEMERAL_PUBLIC_KEY', 12], ['NONCE_START', 14]]) {
    it(`is not an encrypted file when ${field} is absent, and nothing throws`, () => {
      const sealed = encryptContent(w, { content: 'x', recipientPublicKey: me.xPub }).bytes;
      const hostile = withoutEncField(sealed, vOff);
      expect(() => classifyInput(w, hostile)).not.toThrow();
      expect(classifyInput(w, hostile).kind).toBe('unknown');
      expect(verifyInput(w, hostile)).toMatchObject({ kind: 'unknown', valid: false, reason: 'not-sds' });
      expect(decryptFile(w, hostile, { encryptionKey: me.xPriv })).toMatchObject({ ok: false, error: 'not-enc' });
    });
  }

  it('an absent RECIPIENT_KEY_ID is still allowed (the spec makes it optional)', () => {
    const sealed = encryptContent(w, { content: 'still opens', recipientPublicKey: me.xPub }).bytes;
    // Dropping the field changes the AAD, so the tag no longer matches: the
    // point is that it is read as absent (auth-failed), not as garbage or a crash.
    const r = decryptFile(w, withoutEncField(sealed, 16), { encryptionKey: me.xPriv });
    expect(r).toMatchObject({ ok: false, error: 'auth-failed' });
  });

  it('every vtable slot of the ENC table, zeroed or set to 0xffff, gives a result and never an exception', () => {
    const sealed = encryptContent(w, { content: 'fuzz', recipientPublicKey: me.xPub, signingKey: me.edPriv }).bytes;
    for (let vOff = 4; vOff <= 24; vOff += 2) {
      for (const value of [0x0000, 0xffff, 0x0004]) {
        const out = Uint8Array.from(sealed);
        const slot = encVtableSlot(out, vOff);
        out[slot] = value & 0xff;
        out[slot + 1] = value >> 8;
        expect(() => verifyInput(w, out), `slot ${vOff} = ${value}`).not.toThrow();
        const r = decryptFile(w, out, { encryptionKey: me.xPriv });
        expect(typeof r.ok, `slot ${vOff} = ${value}`).toBe('boolean');
      }
    }
  });
});

describe('encrypting to a key X25519 refuses', () => {
  it('names the problem instead of "Unknown error"', () => {
    let error = null;
    try {
      encryptContent(w, { content: 'x', recipientPublicKey: new Uint8Array(32) });
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({ code: 'bad-recipient-key', message: 'This is not a valid encryption key.' });
  });
});

describe('an all-zero X25519 shared secret is never used (SEC-002 defence in depth)', () => {
  // A WASM whose ECDH fails open: it returns 32 zero bytes instead of
  // throwing (hd-wallet-wasm up to 2.1.0 read some ECDH failures as success).
  const failOpen = () => ({
    ...w,
    curves: { ...w.curves, x25519: { ...w.curves.x25519, ecdh: () => new Uint8Array(32) } },
  });

  it('encrypting refuses the key instead of sealing under a predictable key', () => {
    let error = null;
    let sealed = null;
    try {
      sealed = encryptContent(failOpen(), { content: 'secret', recipientPublicKey: me.xPub });
    } catch (caught) {
      error = caught;
    }
    expect(sealed).toBeNull();
    expect(error).toMatchObject({ code: 'bad-recipient-key' });
  });

  it('decrypting a file whose ephemeral key gives an all-zero secret fails, and nothing throws', () => {
    const sealed = encryptContent(w, { content: 'secret', recipientPublicKey: me.xPub });
    const result = decryptFile(failOpen(), sealed.bytes, { encryptionKey: me.xPriv, fileName: sealed.fileName });
    expect(result).toMatchObject({ ok: false, error: 'auth-failed' });
  });

  it('a short or non-byte secret is refused the same way', () => {
    const odd = (value) => ({ ...w, curves: { ...w.curves, x25519: { ...w.curves.x25519, ecdh: () => value } } });
    for (const value of [new Uint8Array(31), Array(32).fill(1), null]) {
      expect(() => encryptContent(odd(value), { content: 'x', recipientPublicKey: me.xPub })).toThrow('This is not a valid encryption key.');
    }
  });
});
