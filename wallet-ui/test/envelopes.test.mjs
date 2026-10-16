import initHDWallet from 'hd-wallet-wasm';
import { beforeAll, describe, expect, it, vi } from 'vitest';

import {
  DECRYPT_ERROR_TEXT,
  DEFAULT_TEXT_NAME,
  ENVELOPE_MIME,
  MAX_INPUT_BYTES,
  MESSAGE_CONTEXT,
  SYMMETRIC_AES_256_GCM,
  TEXT_MEDIA_TYPE,
  VERIFY_REASON_TEXT,
  buildFileRecord,
  buildPnmFile,
  buildRecFile,
  classifyInput,
  createCidV1Raw,
  decryptFile,
  decryptedFallbackName,
  encryptContent,
  envelopeFileName,
  extractTrailer,
  parsePeerId,
  peerIdFromEd25519,
  sealBytes,
  signContent,
  textPreview,
  verifyInput,
} from '../src/envelopes.js';

// Public BIP-39 test vectors only: throwaway identities, never real keys.
const MNEMONIC_A = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const MNEMONIC_B = 'legal winner thank year wave sausage worth useful legal winner thank yellow';
const enc = new TextEncoder();

let w;
let alice;
let bob;

function identity(mnemonic, account = 0) {
  const seed = w.mnemonic.toSeed(mnemonic);
  const edPriv = w.slip10.deriveEd25519Path(seed, `m/44'/0'/${account}'/0'/0'`).privateKey;
  const xPriv = w.slip10.deriveEd25519Path(seed, `m/44'/0'/${account}'/1'/0'`).privateKey;
  seed.fill(0);
  const edPub = w.curves.ed25519.publicKeyFromSeed(edPriv);
  return { edPriv, xPriv, edPub, xPub: w.curves.x25519.publicKey(xPriv), peerId: peerIdFromEd25519(w, edPub) };
}

function indexOfBytes(haystack, needle, from = 0) {
  outer: for (let i = from; i <= haystack.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) if (haystack[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

function flipAt(bytes, index, mask = 0x01) {
  const out = bytes.slice();
  out[index] ^= mask;
  return out;
}

// Replace one hex character with another hex character (keeps the string valid hex).
function flipHexChar(bytes, index) {
  const out = bytes.slice();
  out[index] = out[index] === 0x30 ? 0x31 : 0x30;
  return out;
}

function u64le(value) {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(value), true);
  return out;
}

function derFromCompact(compact) {
  const int = (b) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    let v = b.slice(i);
    if (v[0] & 0x80) v = Uint8Array.of(0, ...v);
    return Uint8Array.of(0x02, v.length, ...v);
  };
  const r = int(compact.subarray(0, 32));
  const s = int(compact.subarray(32));
  return Uint8Array.of(0x30, r.length + s.length, ...r, ...s);
}

function hex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

beforeAll(async () => {
  w = await initHDWallet();
  alice = identity(MNEMONIC_A);
  bob = identity(MNEMONIC_B);
});

describe('identity helpers', () => {
  it('peer IDs are the libp2p Ed25519 identity multihash and parse back to the key', () => {
    expect(alice.peerId).toMatch(/^12D3KooW/);
    const manual = w.utils.encodeBase58(Uint8Array.of(0x00, 0x24, 0x08, 0x01, 0x12, 0x20, ...alice.edPub));
    expect(alice.peerId).toBe(manual);
    const parsed = parsePeerId(w, alice.peerId);
    expect(parsed.keyType).toBe('Ed25519');
    expect(Array.from(parsed.publicKey)).toEqual(Array.from(alice.edPub));
    expect(parsePeerId(w, 'QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N')).toBeNull();
    expect(parsePeerId(w, 'not a peer id')).toBeNull();
  });

  it('account numbers give different identities', () => {
    const a1 = identity(MNEMONIC_A, 1);
    expect(a1.peerId).not.toBe(alice.peerId);
    expect(hex(a1.xPub)).not.toBe(hex(alice.xPub));
  });
});

describe('naming and MIME (§4.1)', () => {
  it('appends the envelope extension to the working name', () => {
    expect(envelopeFileName(w, 'message.txt', 'rec')).toBe('message.txt.rec');
    expect(envelopeFileName(w, 'message.txt', 'pnm')).toBe('message.txt.pnm');
    expect(envelopeFileName(w, 'message.txt', 'enc')).toBe('message.txt.enc');
    expect(envelopeFileName(w, '', 'rec')).toBe(`${DEFAULT_TEXT_NAME}.rec`);
    expect(envelopeFileName(w, 'report.pdf', 'enc')).toBe('report.pdf.enc');
    expect(decryptedFallbackName(w, 'blob.bin.enc')).toBe('blob.bin');
  });

  it('exports the MIME table', () => {
    expect(ENVELOPE_MIME).toEqual({
      rec: 'application/octet-stream',
      pnm: 'application/vnd.sdn.pnm',
      enc: 'application/octet-stream',
      epm: 'application/octet-stream',
    });
  });
});

describe('sign and verify', () => {
  it('signs typed text into a .rec that verifies with content, signer and time', () => {
    const notice = signContent(w, { content: 'hello SDN', signingKey: alice.edPriv });
    expect(notice.FILE_NAME).toBe('message.txt');
    expect(notice.MULTIFORMAT_ADDRESS).toBe(`/p2p/${alice.peerId}`);
    expect(notice.FILE_ID).toBe(`${alice.peerId}:wallet:message.txt:${notice.PUBLISH_TIMESTAMP}`);
    expect(notice.SIGNATURE).toMatch(/^[0-9a-f]{128}$/);
    expect(notice.TIMESTAMP_SIGNATURE).toMatch(/^[0-9a-f]{128}$/);
    expect(notice.SIGNATURE_TYPE).toBe('Ed25519');
    expect(notice.CID).toBe(createCidV1Raw(w, enc.encode('hello SDN')));

    const rec = buildRecFile(w, notice.content, notice);
    expect(Array.from(rec.subarray(0, 9))).toEqual(Array.from(enc.encode('hello SDN')));
    const result = verifyInput(w, rec);
    expect(result).toMatchObject({ kind: 'rec', valid: true, reason: null, timestampValid: true, fileName: 'message.txt', size: 9 });
    expect(result.signer.peerId).toBe(alice.peerId);
    expect(textPreview(w, result.content)).toBe('hello SDN');
  });

  it('signs text exactly as typed (no normalization)', () => {
    const text = 'café \r\n tab\t';
    const notice = signContent(w, { content: text, signingKey: alice.edPriv });
    const result = verifyInput(w, buildRecFile(w, notice.content, notice));
    expect(result.valid).toBe(true);
    expect(textPreview(w, result.content)).toBe(text);
  });

  it('signs a binary file into .rec and detached .pnm', () => {
    const bytes = w.utils.getRandomBytes(4096);
    const notice = signContent(w, { content: bytes, name: 'test.pdf', signingKey: alice.edPriv });
    const rec = buildRecFile(w, bytes, notice);
    const recResult = verifyInput(w, rec);
    expect(recResult.valid).toBe(true);
    expect(Array.from(recResult.content)).toEqual(Array.from(bytes));
    expect(textPreview(w, Uint8Array.of(0xff, 0xfe))).toBeNull();

    const pnm = buildPnmFile(w, notice);
    // Size-prefixed FlatBuffer: u32 size, u32 root offset, then the "$PNM" identifier.
    expect(new TextDecoder().decode(pnm.subarray(8, 12))).toBe('$PNM');
    expect(new DataView(pnm.buffer, pnm.byteOffset).getUint32(0, true)).toBe(pnm.length - 4);
    expect(verifyInput(w, pnm)).toMatchObject({ kind: 'pnm', needsOriginal: true });
    expect(verifyInput(w, pnm).notice.CID).toBe(notice.CID);
    expect(verifyInput(w, pnm, { original: bytes })).toMatchObject({ kind: 'pnm', valid: true, timestampValid: true, fileName: 'test.pdf' });

    const other = bytes.slice();
    other[0] ^= 0xff;
    expect(verifyInput(w, pnm, { original: other })).toMatchObject({ valid: false, reason: 'changed' });
  });

  it('a one-byte payload tamper anywhere in the content reports "changed"', () => {
    const content = enc.encode('the quick brown fox');
    const notice = signContent(w, { content, signingKey: alice.edPriv });
    const rec = buildRecFile(w, content, notice);
    for (const i of [0, 7, content.length - 1]) {
      const r = verifyInput(w, flipAt(rec, i));
      expect(r).toMatchObject({ kind: 'rec', valid: false, reason: 'changed' });
    }
    expect(VERIFY_REASON_TEXT.changed).toBe('The content was changed after signing.');
  });

  it('a flipped signature reports "does not match"; a flipped timestamp signature leaves the content valid', () => {
    const content = enc.encode('payload');
    const notice = signContent(w, { content, signingKey: alice.edPriv });
    const rec = buildRecFile(w, content, notice);

    const sigAt = indexOfBytes(rec, enc.encode(notice.SIGNATURE));
    expect(sigAt).toBeGreaterThan(content.length);
    expect(verifyInput(w, flipHexChar(rec, sigAt + 10))).toMatchObject({ valid: false, reason: 'signature' });

    const tsSigAt = indexOfBytes(rec, enc.encode(notice.TIMESTAMP_SIGNATURE));
    const r = verifyInput(w, flipHexChar(rec, tsSigAt + 10));
    expect(r).toMatchObject({ valid: true, reason: null, timestampValid: false });

    // PUBLISH_TIMESTAMP itself changed (one digit of the seconds field).
    // The string itself (u32 length 24, then the text), not its copy inside FILE_ID.
    const tsAt = indexOfBytes(rec, Uint8Array.of(24, 0, 0, 0, ...enc.encode(notice.PUBLISH_TIMESTAMP)), content.length) + 4;
    const tsFlip = flipAt(rec, tsAt + 18, 0x01);
    const r2 = verifyInput(w, tsFlip);
    expect(r2.notice.PUBLISH_TIMESTAMP).not.toBe(notice.PUBLISH_TIMESTAMP);
    expect(r2).toMatchObject({ valid: true, timestampValid: false });
  });

  it('another key or a non-peer-ID address does not verify', () => {
    const content = enc.encode('x');
    const notice = signContent(w, { content, signingKey: alice.edPriv });
    const forged = { ...notice, MULTIFORMAT_ADDRESS: `/p2p/${bob.peerId}` };
    expect(verifyInput(w, buildRecFile(w, content, forged))).toMatchObject({ valid: false, reason: 'signature' });
    const ipfs = { ...notice, MULTIFORMAT_ADDRESS: `/ipfs/${notice.CID}` };
    expect(verifyInput(w, buildRecFile(w, content, ipfs))).toMatchObject({ valid: false, reason: 'not-peer-id' });
    const mislabelled = { ...notice, SIGNATURE_TYPE: 'Secp256k1' };
    expect(verifyInput(w, buildRecFile(w, content, mislabelled))).toMatchObject({ valid: false, reason: 'signature' });
  });

  it('anything else is "not a signed SDS file"', () => {
    expect(verifyInput(w, enc.encode('just text'))).toMatchObject({ kind: 'unknown', valid: false, reason: 'not-sds' });
    expect(verifyInput(w, new Uint8Array(0))).toMatchObject({ kind: 'unknown', reason: 'not-sds' });
    // A trailer footer with garbage before it.
    const junk = Uint8Array.of(...enc.encode('abcdefgh'), 8, 0, 0, 0, 0x24, 0x52, 0x45, 0x43);
    expect(verifyInput(w, junk)).toMatchObject({ kind: 'unknown' });
    // A truncated .pnm.
    const notice = signContent(w, { content: 'x', signingKey: alice.edPriv });
    expect(verifyInput(w, buildPnmFile(w, notice).subarray(0, 40))).toMatchObject({ kind: 'unknown' });
  });

  it('verifies a Secp256k1 PNM with a 16Uiu2 peer ID and strict DER, and rejects non-strict DER', () => {
    const priv = w.utils.sha256(enc.encode('throwaway secp256k1 test key'));
    const pub = w.curves.publicKeyFromPrivate(priv, 0);
    expect(pub.length).toBe(33);
    const peerId = w.libp2p.peerIdToString(w.libp2p.peerIdFromPublicKey(pub, 0));
    expect(peerId).toMatch(/^16Uiu2/);
    const content = enc.encode('secp payload');
    const cid = createCidV1Raw(w, content);
    const ts = '2026-10-15T00:00:00.000Z';
    const sig = derFromCompact(w.curves.secp256k1.sign(enc.encode(cid), priv));
    const tsSig = derFromCompact(w.curves.secp256k1.sign(enc.encode(ts), priv));
    const notice = {
      MULTIFORMAT_ADDRESS: `/p2p/${peerId}`,
      PUBLISH_TIMESTAMP: ts,
      CID: cid,
      FILE_NAME: 'secp.txt',
      FILE_ID: `${peerId}:wallet:secp.txt:${ts}`,
      SIGNATURE: hex(sig),
      TIMESTAMP_SIGNATURE: hex(tsSig),
      SIGNATURE_TYPE: 'Secp256k1',
      TIMESTAMP_SIGNATURE_TYPE: 'Secp256k1',
    };
    const ok = verifyInput(w, buildPnmFile(w, notice), { original: content });
    expect(ok).toMatchObject({ valid: true, timestampValid: true });
    expect(ok.signer.keyType).toBe('Secp256k1');

    // Non-minimal INTEGER (an extra leading zero on r) is not strict DER.
    const rLen = sig[3];
    const loose = Uint8Array.of(0x30, sig[1] + 1, 0x02, rLen + 1, 0x00, ...sig.subarray(4));
    expect(verifyInput(w, buildPnmFile(w, { ...notice, SIGNATURE: hex(loose) }), { original: content }))
      .toMatchObject({ valid: false, reason: 'signature' });
    // A raw compact signature is not DER either.
    const compact = w.curves.secp256k1.sign(enc.encode(cid), priv);
    expect(verifyInput(w, buildPnmFile(w, { ...notice, SIGNATURE: hex(compact) }), { original: content }))
      .toMatchObject({ valid: false, reason: 'signature' });
  });

  it('does not mutate the caller key', () => {
    const before = hex(alice.edPriv);
    signContent(w, { content: 'k', signingKey: alice.edPriv });
    expect(hex(alice.edPriv)).toBe(before);
  });
});

describe('encrypt and decrypt', () => {
  it('round-trips typed text to myself, unsigned', () => {
    const out = encryptContent(w, { content: 'hello SDN', recipientPublicKey: alice.xPub });
    expect(out).toMatchObject({ fileName: 'message.txt.enc', mime: 'application/octet-stream', signed: false, notice: null });
    const r = decryptFile(w, out.bytes, { encryptionKey: alice.xPriv, fileName: out.fileName });
    expect(r.ok).toBe(true);
    expect(r.isFileRecord).toBe(true);
    expect(r.signature).toBeNull();
    expect(r.file).toMatchObject({ name: 'message.txt', mediaType: TEXT_MEDIA_TYPE, size: 9 });
    expect(new TextDecoder().decode(r.file.content)).toBe('hello SDN');
  });

  it('round-trips a 5 MiB binary to another identity, byte-identical, with name, type and mtime', () => {
    const bytes = new Uint8Array(5 * 1024 * 1024);
    for (let off = 0; off < bytes.length; off += 65536) bytes.set(w.utils.getRandomBytes(65536), off);
    const out = encryptContent(w, {
      content: bytes,
      name: 'plain.bin',
      mediaType: 'application/x-test',
      modifiedAtMs: 1760000000123,
      recipientPublicKey: bob.xPub,
    });
    expect(out.fileName).toBe('plain.bin.enc');
    const r = decryptFile(w, out.bytes, { encryptionKey: bob.xPriv });
    expect(r.ok).toBe(true);
    expect(r.file).toMatchObject({ name: 'plain.bin', mediaType: 'application/x-test', size: bytes.length, modifiedAtMs: 1760000000123 });
    expect(hex(w.utils.sha256(r.file.content))).toBe(hex(w.utils.sha256(bytes)));
    // Alice cannot open Bob's file.
    expect(decryptFile(w, out.bytes, { encryptionKey: alice.xPriv })).toMatchObject({ ok: false, error: 'wrong-recipient' });
  });

  it('defaults a binary without a type to application/octet-stream', () => {
    const out = encryptContent(w, { content: Uint8Array.of(1, 2, 3), name: 'x.dat', recipientPublicKey: alice.xPub });
    expect(decryptFile(w, out.bytes, { encryptionKey: alice.xPriv }).file.mediaType).toBe('application/octet-stream');
  });

  it('sign + encrypt reports a valid signer after decrypt', () => {
    const out = encryptContent(w, { content: 'signed secret', recipientPublicKey: bob.xPub, signingKey: alice.edPriv });
    expect(out.signed).toBe(true);
    expect(out.notice.MULTIFORMAT_ADDRESS).toBe(`/p2p/${alice.peerId}`);
    expect(out.notice.content).toBeUndefined();
    const r = decryptFile(w, out.bytes, { encryptionKey: bob.xPriv });
    expect(r.ok).toBe(true);
    expect(r.signature).toMatchObject({ valid: true, reason: null, timestampValid: true });
    expect(r.signature.signer.peerId).toBe(alice.peerId);
    expect(r.signature.notice.FILE_NAME).toBe('message.txt');
    expect(new TextDecoder().decode(r.file.content)).toBe('signed secret');
  });

  it('writes the ENC header the spec fixes', () => {
    const before = Date.now();
    const out = encryptContent(w, { content: 'h', recipientPublicKey: bob.xPub });
    const t = extractTrailer(w, out.bytes);
    const footer = out.bytes.subarray(out.bytes.length - 8);
    expect(new TextDecoder().decode(footer.subarray(4))).toBe('$REC');
    expect(new DataView(footer.buffer, footer.byteOffset).getUint32(0, true)).toBe(t.recordCollection.length);
    expect(t.records.map((r) => r.standard)).toEqual(['ENC']);
    expect(t.records[0].type).toBe(39);
    expect(t.enc).toMatchObject({
      version: 1,
      keyExchange: 0,
      symmetric: SYMMETRIC_AES_256_GCM,
      keyDerivation: 0,
      context: MESSAGE_CONTEXT,
      rootType: 'FIL',
      schemaHash: null,
    });
    expect(SYMMETRIC_AES_256_GCM).toBe(1);
    expect(MESSAGE_CONTEXT).toBe('space-data-network/wallet/message/v1');
    expect(t.enc.ephemeralPublicKey.length).toBe(32);
    expect(t.enc.nonceStart.length).toBe(12);
    expect(hex(t.enc.recipientKeyId)).toBe(hex(w.utils.sha256(bob.xPub)));
    expect(Number(t.enc.timestamp)).toBeGreaterThanOrEqual(before);
    // ct ‖ tag: plaintext FIL length + 16.
    expect(classifyInput(w, out.bytes).kind).toBe('enc');
    expect(verifyInput(w, out.bytes)).toEqual({ kind: 'enc' });
  });

  it('every tampered byte class fails to decrypt', () => {
    const out = encryptContent(w, { content: 'tamper me', recipientPublicKey: alice.xPub, timestamp: undefined });
    const bytes = out.bytes;
    const t = extractTrailer(w, bytes);
    const ctLen = t.payload.length - 16;
    const recStart = t.payload.length;
    const decrypt = (b) => decryptFile(w, b, { encryptionKey: alice.xPriv });
    expect(decrypt(bytes).ok).toBe(true);

    // ciphertext and tag
    expect(decrypt(flipAt(bytes, 0))).toMatchObject({ ok: false, error: 'auth-failed' });
    expect(decrypt(flipAt(bytes, ctLen - 1))).toMatchObject({ ok: false, error: 'auth-failed' });
    expect(decrypt(flipAt(bytes, ctLen))).toMatchObject({ ok: false, error: 'auth-failed' });
    expect(decrypt(flipAt(bytes, ctLen + 15))).toMatchObject({ ok: false, error: 'auth-failed' });

    // AAD fields inside the $ENC record
    const find = (needle) => {
      const at = indexOfBytes(bytes, needle, recStart);
      expect(at).toBeGreaterThanOrEqual(recStart);
      return at;
    };
    const fields = {
      nonce: find(t.enc.nonceStart),
      ephemeral: find(t.enc.ephemeralPublicKey),
      context: find(enc.encode(MESSAGE_CONTEXT)) + 5,
      rootType: find(enc.encode('FIL\0')) + 2,
      timestamp: find(u64le(t.enc.timestamp)),
    };
    for (const [field, at] of Object.entries(fields)) {
      const r = decrypt(flipAt(bytes, at));
      expect({ field, ok: r.ok, error: r.error }).toEqual({ field, ok: false, error: 'auth-failed' });
    }
    expect(decrypt(flipAt(bytes, find(t.enc.recipientKeyId)))).toMatchObject({ ok: false, error: 'wrong-recipient' });

    // the trailer itself
    expect(decrypt(flipAt(bytes, bytes.length - 1))).toMatchObject({ ok: false, error: 'not-enc' });
    expect(decrypt(flipAt(bytes, bytes.length - 8, 0x40))).toMatchObject({ ok: false, error: 'not-enc' });
    expect(decrypt(enc.encode('plain text'))).toMatchObject({ ok: false, error: 'not-enc', message: DECRYPT_ERROR_TEXT['not-enc'] });
  });

  it('a file encrypted for another key reports "different key"', () => {
    const randomKey = w.curves.x25519.publicKey(w.utils.getRandomBytes(32));
    const out = encryptContent(w, { content: 'to a stranger', recipientPublicKey: randomKey });
    const r = decryptFile(w, out.bytes, { encryptionKey: alice.xPriv });
    expect(r).toEqual({ ok: false, error: 'wrong-recipient', message: 'This file was encrypted for a different key.' });
  });

  it('a non-GCM or non-X25519 ENC is unsupported', () => {
    const out = encryptContent(w, { content: 'x', recipientPublicKey: alice.xPub });
    const t = extractTrailer(w, out.bytes);
    const bytes = Uint8Array.from(out.bytes);
    const rec = bytes.subarray(t.payload.length, bytes.length - 8);
    // Walk REC → RECORDS[0] → value ($ENC) → SYMMETRIC slot via the vtables.
    const dv = new DataView(rec.buffer, rec.byteOffset, rec.length);
    const table = (pos) => ({ pos, vt: pos - dv.getInt32(pos, true) });
    const ref = (at) => at + dv.getUint32(at, true);
    const root = table(dv.getUint32(0, true));
    const records = ref(root.pos + dv.getUint16(root.vt + 6, true));
    const record0 = table(ref(records + 4));
    const encTable = table(ref(record0.pos + dv.getUint16(record0.vt + 6, true)));
    const symAt = encTable.pos + dv.getUint16(encTable.vt + 8, true);
    expect(rec[symAt]).toBe(1);
    rec[symAt] = 0; // AES_256_CTR
    expect(decryptFile(w, bytes, { encryptionKey: alice.xPriv }))
      .toEqual({ ok: false, error: 'unsupported', message: 'Only X25519 / AES-256-GCM files are supported.' });
  });

  it('sign + encrypt with a tampered inner FIL reports the signature as not valid', () => {
    const fil = buildFileRecord(w, { content: enc.encode('inner'), name: 'inner.txt', mediaType: TEXT_MEDIA_TYPE });
    const notice = signContent(w, { content: fil, name: 'inner.txt', signingKey: alice.edPriv });
    const signed = buildRecFile(w, fil, notice);
    // Flip one byte of the FIL's NAME (outside DIGEST/CONTENT): the FIL stays self-consistent.
    const nameAt = indexOfBytes(signed, enc.encode('inner.txt\0'));
    expect(nameAt).toBeGreaterThan(0);
    expect(nameAt).toBeLessThan(fil.length);
    const tampered = flipAt(signed, nameAt, 0x20);
    const r = decryptFile(w, sealBytes(w, tampered, alice.xPub), { encryptionKey: alice.xPriv });
    expect(r.ok).toBe(true);
    expect(r.file.name).toBe('Inner.txt');
    expect(r.signature).toMatchObject({ valid: false, reason: 'changed' });

    const intact = decryptFile(w, sealBytes(w, signed, alice.xPub), { encryptionKey: alice.xPriv });
    expect(intact.signature.valid).toBe(true);
  });

  it('a FIL whose DIGEST or SIZE does not match its CONTENT is rejected', () => {
    const fil = buildFileRecord(w, { content: enc.encode('digest check'), name: 'd.txt', mediaType: TEXT_MEDIA_TYPE });
    const at = indexOfBytes(fil, enc.encode('digest check'));
    const bad = flipAt(fil, at);
    const r = decryptFile(w, sealBytes(w, bad, alice.xPub), { encryptionKey: alice.xPriv });
    expect(r).toEqual({ ok: false, error: 'file-changed', message: DECRYPT_ERROR_TEXT['file-changed'] });
  });

  it('a plaintext that is not a $FIL is offered as raw bytes', () => {
    const raw = enc.encode('module payload');
    const r = decryptFile(w, sealBytes(w, raw, alice.xPub, { rootType: 'MBL' }), { encryptionKey: alice.xPriv, fileName: 'module.wasm.enc' });
    expect(r).toMatchObject({ ok: true, isFileRecord: false, saveName: 'module.wasm', signature: null });
    expect(new TextDecoder().decode(r.bytes)).toBe('module payload');
  });

  it('zeroes the ephemeral key it creates and leaves the caller keys intact', () => {
    const spy = vi.spyOn(w.utils, 'getRandomBytes');
    const keyBefore = hex(alice.edPriv);
    try {
      encryptContent(w, { content: 'z', recipientPublicKey: bob.xPub, signingKey: alice.edPriv });
      const ephemeral = spy.mock.results.find((r) => r.value?.length === 32)?.value;
      expect(ephemeral).toBeInstanceOf(Uint8Array);
      expect(ephemeral.every((b) => b === 0)).toBe(true);
    } finally {
      spy.mockRestore();
    }
    expect(hex(alice.edPriv)).toBe(keyBefore);
  });
});

describe('limits', () => {
  it('refuses inputs over 50 MiB for sign and encrypt', () => {
    const big = new Uint8Array(MAX_INPUT_BYTES + 1);
    expect(() => signContent(w, { content: big, signingKey: alice.edPriv })).toThrow('Files up to 50 MB can be signed or encrypted here.');
    expect(() => encryptContent(w, { content: big, recipientPublicKey: alice.xPub })).toThrow(/50 MB/);
    expect(MAX_INPUT_BYTES).toBe(50 * 1024 * 1024);
  });

  it('rejects malformed keys', () => {
    expect(() => signContent(w, { content: 'x', signingKey: new Uint8Array(31) })).toThrow(/32 bytes/);
    expect(() => encryptContent(w, { content: 'x', recipientPublicKey: new Uint8Array(33) })).toThrow(/32 bytes/);
  });
});
