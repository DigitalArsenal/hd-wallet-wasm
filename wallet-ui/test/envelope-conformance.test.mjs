// Byte-exactness against space-data-module-sdk 0.9.7 (devDependency, tests only)
// and against the generated SDS 1.249.0 REC object API, which the wallet does
// not bundle (it pulls in every SDS standard). module-sdk starts its own
// hd-wallet-wasm instance; that is fine here and never happens in the bundle.
import * as flatbuffers from 'flatbuffers';
import initHDWallet from 'hd-wallet-wasm';
import {
  appendPublicationRecordCollection,
  createCidV1Raw as sdkCidV1Raw,
  createPublicationNotice,
  decodePnmRecord,
  decryptProtectedBytes,
  encodeEncRecord as sdkEncodeEncRecord,
  encodePublicationRecordCollection,
  encryptBytesForRecipient,
  extractPublicationRecordCollection,
} from 'space-data-module-sdk/transport';
import { REC, RECT } from '@sds/lib/js/REC/REC.js';
import { RecordT } from '@sds/lib/js/REC/Record.js';
import { RecordType } from '@sds/lib/js/REC/RecordType.js';
import { ENCT } from '@sds/lib/js/ENC/ENC.js';
import { PNMT } from '@sds/lib/js/PNM/PNM.js';
import { beforeAll, describe, expect, it } from 'vitest';

import {
  MESSAGE_CONTEXT,
  appendTrailer,
  buildFileRecord,
  buildPnmFile,
  buildRecFile,
  createCidV1Raw,
  decryptFile,
  encodeEncRecord,
  encodeRecordCollection,
  encryptContent,
  parseFileRecord,
  peerIdFromEd25519,
  signContent,
} from '../src/envelopes.js';

const MNEMONIC = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const enc = new TextEncoder();
const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
const base64ToBytes = (s) => Uint8Array.from(Buffer.from(s, 'base64'));

let w;
let edPriv;
let xPriv;
let xPub;
let peerId;

beforeAll(async () => {
  w = await initHDWallet();
  const seed = w.mnemonic.toSeed(MNEMONIC);
  edPriv = w.slip10.deriveEd25519Path(seed, "m/44'/0'/0'/0'/0'").privateKey;
  xPriv = w.slip10.deriveEd25519Path(seed, "m/44'/0'/0'/1'/0'").privateKey;
  seed.fill(0);
  xPub = w.curves.x25519.publicKey(xPriv);
  peerId = peerIdFromEd25519(w, w.curves.ed25519.publicKeyFromSeed(edPriv));
});

function sampleEncRecords() {
  return [
    {
      version: 1,
      keyExchange: 0,
      symmetric: 1,
      keyDerivation: 0,
      ephemeralPublicKey: w.utils.getRandomBytes(32),
      nonceStart: w.utils.getRandomBytes(12),
      recipientKeyId: w.utils.sha256(xPub),
      context: MESSAGE_CONTEXT,
      rootType: 'FIL',
      timestamp: 1760500000123,
    },
    {
      version: 1,
      keyExchange: 0,
      symmetric: 1,
      keyDerivation: 0,
      ephemeralPublicKey: w.utils.getRandomBytes(32),
      nonceStart: w.utils.getRandomBytes(12),
      context: 'space-data-module-sdk/package',
      timestamp: 0,
    },
    {
      version: 2,
      keyExchange: 1,
      symmetric: 0,
      keyDerivation: 0,
      ephemeralPublicKey: w.utils.getRandomBytes(33),
      nonceStart: w.utils.getRandomBytes(12),
      recipientKeyId: w.utils.getRandomBytes(20),
      schemaHash: w.utils.getRandomBytes(32),
      context: 'ctx',
      rootType: 'MBL',
      timestamp: 2 ** 40,
    },
  ];
}

describe('module-sdk 0.9.7 byte-exactness', () => {
  it('encodeEncRecord is byte-identical for three records', () => {
    for (const record of sampleEncRecords()) {
      const ours = encodeEncRecord(w, record);
      const theirs = sdkEncodeEncRecord({
        ...record,
        keyExchange: ['X25519', 'SECP256K1', 'P256'][record.keyExchange],
        symmetric: record.symmetric === 1 ? 'AES_256_GCM' : 'AES_256_CTR',
        keyDerivation: 'HKDF_SHA256',
      });
      expect(hex(ours)).toBe(hex(theirs));
    }
  });

  it('createCidV1Raw matches for 0 B, 1 B and 1 MiB', async () => {
    const mib = new Uint8Array(1024 * 1024);
    for (let off = 0; off < mib.length; off += 65536) mib.set(w.utils.getRandomBytes(65536), off);
    for (const payload of [new Uint8Array(0), Uint8Array.of(0x42), mib]) {
      expect(createCidV1Raw(w, payload)).toBe(await sdkCidV1Raw(payload));
    }
    expect(createCidV1Raw(w, new Uint8Array(0))).toBe('bafkreihdwdcefgh4dqkjv67uzcmw7ojee6xedzdetojuzjevtenxquvyku');
  });

  it('our PNM decodes with decodePnmRecord and equals createPublicationNotice with the same signer', async () => {
    const payload = enc.encode('hello SDN');
    const ts = '2026-10-15T12:00:00.000Z';
    const ours = signContent(w, { content: payload, signingKey: edPriv, timestamp: ts });
    const theirs = await createPublicationNotice({
      payloadBytes: payload,
      publishTimestamp: ts,
      fileName: 'message.txt',
      fileId: `${peerId}:wallet:message.txt:${ts}`,
      multiformatAddress: `/p2p/${peerId}`,
      signer: { algorithm: 'Ed25519', sign: (msg) => w.curves.ed25519.sign(msg, edPriv) },
    });
    const pnmRoot = encodeRecordCollection(w, { pnm: ours });
    const decoded = extractPublicationRecordCollection(appendTrailer(w, payload, pnmRoot)).pnm;
    expect(decoded).toEqual(theirs);
    // The size-prefixed .pnm carries the same table: strip the 4-byte prefix → root PNM.
    expect(decodePnmRecord(buildPnmFile(w, ours).subarray(4))).toEqual(theirs);
  });

  // The $REC collection is byte-identical to SDS 1.249.0 RECT(...).pack. module-sdk 0.9.7 packs it with
  // SDS 1.206.0, whose Record table has no EXTENDED_TYPE / EXTENDED_VALUE, so its Record bytes differ by
  // that (empty) vector; the records it carries, the footer framing and the ENC AAD are identical.
  it('the $REC collection equals SDS RECT.pack and carries the same records as module-sdk', () => {
    const payload = enc.encode('trailer');
    const notice = signContent(w, { content: payload, signingKey: edPriv, timestamp: '2026-10-15T12:00:00.000Z' });
    const ourPnmRec = encodeRecordCollection(w, { pnm: notice });

    const sdsPnm = new PNMT(notice.MULTIFORMAT_ADDRESS, notice.PUBLISH_TIMESTAMP, notice.CID, notice.FILE_NAME,
      notice.FILE_ID, notice.SIGNATURE, notice.TIMESTAMP_SIGNATURE, notice.SIGNATURE_TYPE, notice.TIMESTAMP_SIGNATURE_TYPE);
    const b = new flatbuffers.Builder(1024);
    REC.finishRECBuffer(b, new RECT('1.0.0', [new RecordT(RecordType.PNM, sdsPnm, 'PNM')]).pack(b));
    expect(hex(ourPnmRec)).toBe(hex(b.asUint8Array()));

    // Footer framing: payload ‖ REC ‖ u32le(len) ‖ "$REC", exactly as module-sdk appends it.
    const rec = buildRecFile(w, payload, notice);
    expect(hex(rec)).toBe(hex(appendPublicationRecordCollection(payload, ourPnmRec)));
    const footer = rec.subarray(rec.length - 8);
    expect(new DataView(footer.buffer, footer.byteOffset).getUint32(0, true)).toBe(ourPnmRec.length);
    expect(new TextDecoder().decode(footer.subarray(4))).toBe('$REC');

    const sdkPnmRec = encodePublicationRecordCollection({
      pnm: {
        multiformatAddress: notice.MULTIFORMAT_ADDRESS,
        publishTimestamp: notice.PUBLISH_TIMESTAMP,
        cid: notice.CID,
        fileName: notice.FILE_NAME,
        fileId: notice.FILE_ID,
        signature: notice.SIGNATURE,
        timestampSignature: notice.TIMESTAMP_SIGNATURE,
        signatureType: notice.SIGNATURE_TYPE,
        timestampSignatureType: notice.TIMESTAMP_SIGNATURE_TYPE,
      },
    });
    const ours = extractPublicationRecordCollection(appendTrailer(w, payload, ourPnmRec));
    const theirs = extractPublicationRecordCollection(appendPublicationRecordCollection(payload, sdkPnmRec));
    expect(ours.pnm).toEqual(theirs.pnm);
    expect(ours.records).toEqual(theirs.records);
    expect(ourPnmRec.length - sdkPnmRec.length).toBe(12); // the empty EXTENDED_VALUE vector + vtable slots

    for (const record of sampleEncRecords()) {
      const ourEncRec = encodeRecordCollection(w, { enc: record });
      const sdsEnc = new ENCT(record.version, record.keyExchange, record.symmetric, record.keyDerivation,
        Array.from(record.ephemeralPublicKey), Array.from(record.nonceStart), Array.from(record.recipientKeyId ?? []),
        record.context ?? null, Array.from(record.schemaHash ?? []), record.rootType ?? null, BigInt(record.timestamp));
      const b2 = new flatbuffers.Builder(1024);
      REC.finishRECBuffer(b2, new RECT('1.0.0', [new RecordT(RecordType.ENC, sdsEnc, 'ENC')]).pack(b2));
      expect(hex(ourEncRec)).toBe(hex(b2.asUint8Array()));
      const parsedOurs = extractPublicationRecordCollection(appendTrailer(w, new Uint8Array(16), ourEncRec));
      const parsedTheirs = extractPublicationRecordCollection(
        appendPublicationRecordCollection(new Uint8Array(16), encodePublicationRecordCollection({ enc: record })));
      expect(parsedOurs.enc).toEqual(parsedTheirs.enc);
      expect(hex(sdkEncodeEncRecord(parsedOurs.enc))).toBe(hex(encodeEncRecord(w, record)));
    }
  });

  it('extractPublicationRecordCollection parses our .rec', () => {
    const payload = w.utils.getRandomBytes(777);
    const notice = signContent(w, { content: payload, name: 'blob.bin', signingKey: edPriv });
    const parsed = extractPublicationRecordCollection(buildRecFile(w, payload, notice));
    expect(parsed).not.toBeNull();
    expect(hex(parsed.payloadBytes)).toBe(hex(payload));
    expect(parsed.pnm.cid).toBe(notice.CID);
    expect(parsed.pnm.fileName).toBe('blob.bin');
    expect(parsed.records.map((r) => r.standard)).toEqual(['PNM']);
    expect(parsed.footerBytes.length).toBe(8);
  });

  it('module-sdk decryptProtectedBytes opens our .enc (keyAgreement and private key)', async () => {
    const out = encryptContent(w, { content: 'for module-sdk', recipientPublicKey: xPub, signingKey: edPriv });
    const viaAgreement = await decryptProtectedBytes({
      protectedBytes: out.bytes,
      keyAgreement: ({ ephemeralPublicKey }) => w.curves.x25519.ecdh(xPriv, ephemeralPublicKey),
    });
    const viaKey = await decryptProtectedBytes({ protectedBytes: out.bytes, recipientPrivateKey: xPriv });
    expect(hex(viaAgreement)).toBe(hex(viaKey));
    // Signed plaintext: $FIL ‖ $REC{PNM} ‖ footer.
    const inner = extractPublicationRecordCollection(viaKey);
    expect(inner.pnm.signatureType).toBe('Ed25519');
    const file = parseFileRecord(w, inner.payloadBytes);
    expect(new TextDecoder().decode(file.content)).toBe('for module-sdk');
    expect(file.name).toBe('message.txt');

    const unsigned = encryptContent(w, { content: Uint8Array.of(9, 8, 7), name: 'a.bin', recipientPublicKey: xPub });
    const plain = await decryptProtectedBytes({ protectedBytes: unsigned.bytes, recipientPrivateKey: xPriv });
    expect(Array.from(parseFileRecord(w, plain).content)).toEqual([9, 8, 7]);
  });

  it('our decrypt opens encryptBytesForRecipient output', async () => {
    const fil = buildFileRecord(w, { content: enc.encode('from module-sdk'), name: 'sdk.txt', mediaType: 'text/plain' });
    const envelope = await encryptBytesForRecipient({
      plaintext: fil,
      recipientPublicKey: xPub,
      context: MESSAGE_CONTEXT,
      recipientKeyId: w.utils.sha256(xPub),
      rootType: 'FIL',
    });
    const r = decryptFile(w, base64ToBytes(envelope.protectedBlobBase64), { encryptionKey: xPriv });
    expect(r.ok).toBe(true);
    expect(r.file).toMatchObject({ name: 'sdk.txt', mediaType: 'text/plain' });
    expect(new TextDecoder().decode(r.file.content)).toBe('from module-sdk');

    // A module-sdk payload that is not a $FIL, with its default context and no key id.
    const raw = await encryptBytesForRecipient({ plaintext: enc.encode('raw bytes'), recipientPublicKey: xPub });
    const r2 = decryptFile(w, base64ToBytes(raw.protectedBlobBase64), { encryptionKey: xPriv, fileName: 'x.enc' });
    expect(r2).toMatchObject({ ok: true, isFileRecord: false, saveName: 'x' });
    expect(new TextDecoder().decode(r2.bytes)).toBe('raw bytes');
  });
});
