/**
 * SDS envelopes for the account view's Messages pane (spec §4).
 *
 * Every function takes `wasm` first: the wallet's ONE hd-wallet-wasm instance.
 * No DOM, no WebCrypto, no JS crypto. Hashing, signing, ECDH, HKDF and
 * AES-GCM run in WASM; randomness comes from `wasm.utils.getRandomBytes`.
 * Private keys are passed in by the caller (derived per operation, e.g. by
 * identity-keys `withEdKey` / `withXKey`) and zeroed by the caller in its
 * `finally`. Every secret this module creates itself (ephemeral X25519 key,
 * shared secret, AES key) is zeroed here before returning.
 *
 * Outputs (§4.1):
 *   .rec  content ‖ $REC{PNM} ‖ u32le(len) ‖ "$REC"              application/octet-stream
 *   .pnm  size-prefixed $PNM over the content's CID               application/vnd.sdn.pnm
 *   .enc  ct ‖ tag(16) ‖ $REC{ENC} ‖ u32le(len) ‖ "$REC"           application/octet-stream
 *         plaintext = size-prefixed $FIL, or, signed,
 *         $FILsp ‖ $REC{PNM over $FILsp} ‖ u32le(len) ‖ "$REC"
 *
 * API
 *   Constants
 *     MESSAGE_CONTEXT            "space-data-network/wallet/message/v1" (ENC CONTEXT and HKDF info)
 *     SYMMETRIC_AES_256_GCM      1 (absent from the SDS 1.249.0 SymmetricAlgo enum; written as a number)
 *     MAX_INPUT_BYTES            50 MiB, enforced by signContent / encryptContent
 *     DEFAULT_TEXT_NAME          "message.txt";  TEXT_MEDIA_TYPE "text/plain; charset=utf-8"
 *     ENVELOPE_MIME              { rec, pnm, enc, epm } MIME types from §4.1
 *     VERIFY_REASON_TEXT         { changed, signature, 'not-sds', 'not-peer-id' } → the Verify sentences
 *     DECRYPT_ERROR_TEXT         { 'not-enc', 'wrong-recipient', 'auth-failed', 'unsupported', 'file-changed' }
 *     TOO_LARGE_TEXT             "Files up to 50 MB can be signed or encrypted here."
 *   Names
 *     envelopeFileName(wasm, name, kind)      → "<name>.<kind>" ("message.txt" when name is empty)
 *     decryptedFallbackName(wasm, encName)     → encName without ".enc"
 *   Sign / verify
 *     signContent(wasm, { content, name?, signingKey, timestamp? })
 *         → notice: { MULTIFORMAT_ADDRESS, PUBLISH_TIMESTAMP, CID, FILE_NAME, FILE_ID, SIGNATURE,
 *                     TIMESTAMP_SIGNATURE, SIGNATURE_TYPE, TIMESTAMP_SIGNATURE_TYPE }
 *           plus extras the record encoders ignore: { content (Uint8Array), name, peerId, publicKey }
 *     buildRecFile(wasm, content, notice)      → Uint8Array (.rec)
 *     buildPnmFile(wasm, notice)               → Uint8Array (.pnm, size-prefixed $PNM)
 *     verifyInput(wasm, bytes, { original? })  → classification + verdict:
 *         { kind:'enc' }                                  redirect to Decrypt
 *         { kind:'unknown', valid:false, reason:'not-sds' }
 *         { kind:'pnm', needsOriginal:true, notice }      .pnm dropped without the original
 *         { kind:'rec'|'pnm', valid, reason, timestampValid, signer:{peerId,keyType,publicKey}|null,
 *           notice, content, fileName, size }
 *     verifyNotice(wasm, notice, content)      → { valid, reason, timestampValid, signer }
 *     classifyInput(wasm, bytes)               → { kind:'rec'|'pnm'|'enc'|'unknown', ... }
 *   Encrypt / decrypt
 *     encryptContent(wasm, { content, name?, mediaType?, modifiedAtMs?, recipientPublicKey, signingKey?, timestamp? })
 *         → { bytes, fileName, mime, signed, recipientKeyId, notice|null }
 *     decryptFile(wasm, bytes, { encryptionKey, fileName? })
 *         → { ok:false, error, message }
 *         | { ok:true, isFileRecord:true, file:{ name, mediaType, size, modifiedAtMs, content },
 *             signature: null | { valid, reason, timestampValid, signer, notice } }
 *         | { ok:true, isFileRecord:false, bytes, saveName, signature }
 *   Building blocks (exported for tests, fixtures and interop)
 *     createCidV1Raw(wasm, bytes)              CIDv1 raw sha2-256, base32lower, as module-sdk
 *     peerIdFromEd25519(wasm, publicKey)       libp2p peer ID string ("12D3KooW…")
 *     parsePeerId(wasm, peerId)                → { keyType:'Ed25519'|'Secp256k1', publicKey } | null
 *     encodeEncRecord(wasm, enc)               root $ENC bytes (the GCM AAD), byte-identical to module-sdk
 *     encodeRecordCollection(wasm, { enc?, pnm? }) root $REC bytes, byte-identical to RECT.pack
 *     appendTrailer(wasm, payload, recBytes)   payload ‖ rec ‖ u32le(len) ‖ "$REC"
 *     extractTrailer(wasm, bytes)              → { payload, recordCollection, enc, pnm, records } | null
 *     buildFileRecord(wasm, { content, name, mediaType, modifiedAtMs }) size-prefixed $FIL
 *     parseFileRecord(wasm, bytes)             → { name, mediaType, size, modifiedAtMs, digestAlgorithm, digest, content } | null
 *     sealBytes(wasm, plaintext, recipientPublicKey, { rootType? }) → .enc bytes for any plaintext
 *     textPreview(wasm, bytes, max = 65536)    UTF-8 text or null (fatal decode)
 *   Contact card ($EPM codec; contact-card.js builds and checks the fields)
 *     encodeEpm(wasm, epm)                     plain EPM fields → size-prefixed $EPM (.epm); refuses private keys
 *     decodeEpm(wasm, bytes)                   size-prefixed or root $EPM → plain fields; throws code 'not-epm'
 *
 * The `$REC` collection is written and read with the flatbuffers Builder /
 * ByteBuffer directly instead of the generated REC/Record classes: importing
 * `@sds/lib/js/REC/REC.js` pulls in RecordType.js, which statically imports
 * every SDS standard (+6.4 MB minified). The bytes are identical to
 * `RECT(...).pack` (pinned by envelope-conformance.test.mjs), and records are
 * selected by their `standard` string, as the Go node and module-sdk do.
 */

import * as flatbuffers from 'flatbuffers';
import { base58 } from '@scure/base';
import { PNM, PNMT } from '@sds/lib/js/PNM/PNM.js';
import { ENC, ENCT } from '@sds/lib/js/ENC/ENC.js';
import { KeyExchange } from '@sds/lib/js/ENC/KeyExchange.js';
import { KDF } from '@sds/lib/js/ENC/KDF.js';
import { FIL } from '@sds/lib/js/FIL/FIL.js';
import { filEntryKind } from '@sds/lib/js/FIL/filEntryKind.js';
import { filDigestAlgorithm } from '@sds/lib/js/FIL/filDigestAlgorithm.js';
import { EPM, EPMT } from '@sds/lib/js/EPM/EPM.js';
import { AddressT } from '@sds/lib/js/EPM/Address.js';
import { CryptoKeyT } from '@sds/lib/js/EPM/CryptoKey.js';
import { ChainProofT } from '@sds/lib/js/EPM/ChainProof.js';
import { DomainProofT } from '@sds/lib/js/EPM/DomainProof.js';
import { KeyType } from '@sds/lib/js/EPM/KeyType.js';
import { EntityType } from '@sds/lib/js/EPM/EntityType.js';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const MESSAGE_CONTEXT = 'space-data-network/wallet/message/v1';
export const SYMMETRIC_AES_256_GCM = 1;
export const MAX_INPUT_BYTES = 50 * 1024 * 1024;
export const DEFAULT_TEXT_NAME = 'message.txt';
export const TEXT_MEDIA_TYPE = 'text/plain; charset=utf-8';
export const DEFAULT_MEDIA_TYPE = 'application/octet-stream';
export const TRAILER_FOOTER_LENGTH = 8;
export const RECORD_COLLECTION_VERSION = '1.0.0';
export const GCM_TAG_LENGTH = 16;

export const ENVELOPE_MIME = Object.freeze({
  rec: 'application/octet-stream',
  pnm: 'application/vnd.sdn.pnm',
  enc: 'application/octet-stream',
  epm: 'application/octet-stream',
});

export const VERIFY_REASON_TEXT = Object.freeze({
  changed: 'The content was changed after signing.',
  signature: 'The signature does not match the signer.',
  'not-sds': 'This is not a signed SDS file.',
  'not-peer-id': 'The signer address is not an SDN peer ID.',
});

export const DECRYPT_ERROR_TEXT = Object.freeze({
  'not-enc': 'This file is not an SDS encrypted file.',
  'wrong-recipient': 'This file was encrypted for a different key.',
  'auth-failed': 'Decryption failed: the file was changed or the key is wrong.',
  unsupported: 'Only X25519 / AES-256-GCM files are supported.',
  'file-changed': 'Decryption failed: the file was changed or the key is wrong.',
});

export const TOO_LARGE_TEXT = 'Files up to 50 MB can be signed or encrypted here.';

export class EnvelopeError extends Error {
  constructor(code, message) {
    super(message || code);
    this.name = 'EnvelopeError';
    this.code = code;
  }
}

// RecordType union ordinals (SDS 1.249.0 REC/RecordType.js; frozen, ENC=39, PNM=114).
const RECORD_TYPE = Object.freeze({ ENC: 39, PNM: 114 });
const CURVE_ED25519 = 1; // hd-wallet-wasm Curve.ED25519
const SIGNATURE_TYPE_ED25519 = 'Ed25519';
const SIGNATURE_TYPE_SECP256K1 = 'Secp256k1';
const TRAILER_MAGIC = [0x24, 0x52, 0x45, 0x43]; // "$REC"
const ED25519_PEER_PREFIX = [0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
const SECP256K1_PEER_PREFIX = [0x00, 0x25, 0x08, 0x02, 0x12, 0x21];

const textEncoder = new TextEncoder();

// ---------------------------------------------------------------------------
// Small encoding helpers (no crypto)
// ---------------------------------------------------------------------------

function toBytes(value, label = 'content') {
  if (value instanceof Uint8Array) return value;
  if (value instanceof ArrayBuffer) return new Uint8Array(value);
  if (ArrayBuffer.isView(value)) return new Uint8Array(value.buffer, value.byteOffset, value.byteLength);
  if (typeof value === 'string') return textEncoder.encode(value);
  throw new EnvelopeError('invalid-input', `${label} must be bytes or text`);
}

function bytesToHex(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
  return out;
}

function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function equalBytes(a, b) {
  if (!a || !b || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function startsWith(bytes, prefix) {
  if (bytes.length < prefix.length) return false;
  for (let i = 0; i < prefix.length; i++) if (bytes[i] !== prefix[i]) return false;
  return true;
}

function concatBytes(chunks) {
  let total = 0;
  for (const c of chunks) total += c.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) {
    out.set(c, offset);
    offset += c.length;
  }
  return out;
}

function toBase32Lower(bytes) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = ((value << 8) | byte) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += alphabet[(value << (5 - bits)) & 31];
  return out;
}

function zero(...buffers) {
  for (const b of buffers) if (b instanceof Uint8Array) b.fill(0);
}

function requireKey(key, label) {
  if (!(key instanceof Uint8Array) || key.length !== 32) {
    throw new EnvelopeError('invalid-key', `${label} must be 32 bytes`);
  }
  return key;
}

function nullIfBlank(value) {
  if (value === undefined || value === null) return null;
  const s = String(value).trim();
  return s.length ? s : null;
}

function u32le(n) {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, true);
  return out;
}

// ---------------------------------------------------------------------------
// Bounds-checked FlatBuffer reading. flatbuffers' ByteBuffer reads past the
// end silently, so every table, string and vector this module reads is
// checked first; a malformed buffer throws FormatError and the caller maps it
// to "not an SDS file".
// ---------------------------------------------------------------------------

class FormatError extends Error {}

function rdU16(b, o) {
  if (o < 0 || o + 2 > b.length) throw new FormatError('u16 out of range');
  return b[o] | (b[o + 1] << 8);
}

function rdU32(b, o) {
  if (o < 0 || o + 4 > b.length) throw new FormatError('u32 out of range');
  return (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
}

function rdI32(b, o) {
  return rdU32(b, o) | 0;
}

function openTable(b, pos) {
  if (pos < 0 || pos + 4 > b.length) throw new FormatError('table out of range');
  const vt = pos - rdI32(b, pos);
  const vtLen = rdU16(b, vt);
  const tLen = rdU16(b, vt + 2);
  if (vtLen < 4 || vtLen % 2 !== 0 || vt + vtLen > b.length || tLen < 4 || pos + tLen > b.length) {
    throw new FormatError('bad vtable');
  }
  return { b, pos, vt, vtLen, tLen };
}

function fieldAt(t, vOff, size) {
  if (vOff + 2 > t.vtLen) return 0;
  const o = rdU16(t.b, t.vt + vOff);
  if (!o) return 0;
  if (o + size > t.tLen) throw new FormatError('field outside table');
  return t.pos + o;
}

function refAt(b, at) {
  const target = at + rdU32(b, at);
  if (target >= b.length) throw new FormatError('reference out of range');
  return target;
}

function checkString(t, vOff) {
  const at = fieldAt(t, vOff, 4);
  if (!at) return;
  const s = refAt(t.b, at);
  const n = rdU32(t.b, s);
  if (s + 4 + n + 1 > t.b.length || t.b[s + 4 + n] !== 0) throw new FormatError('bad string');
}

function checkByteVector(t, vOff, { min = 0, max = Infinity } = {}) {
  const at = fieldAt(t, vOff, 4);
  if (!at) return;
  const v = refAt(t.b, at);
  const n = rdU32(t.b, v);
  if (v + 4 + n > t.b.length || n < min || n > max) throw new FormatError('bad byte vector');
}

// A copy of a byte vector, or null when the field is absent or empty. SDS's
// generated *Array() accessors don't check that the field is present, so an
// absent vector would read the table's own bytes; every vector goes through here.
function readByteVector(t, vOff) {
  const at = fieldAt(t, vOff, 4);
  if (!at) return null;
  const v = refAt(t.b, at);
  const n = rdU32(t.b, v);
  if (v + 4 + n > t.b.length) throw new FormatError('bad byte vector');
  return n ? t.b.slice(v + 4, v + 4 + n) : null;
}

function readStringField(t, vOff) {
  const at = fieldAt(t, vOff, 4);
  if (!at) return null;
  const s = refAt(t.b, at);
  const n = rdU32(t.b, s);
  return new TextDecoder().decode(t.b.subarray(s + 4, s + 4 + n));
}

function subTable(t, vOff) {
  const at = fieldAt(t, vOff, 4);
  return at ? openTable(t.b, refAt(t.b, at)) : null;
}

function rootTablePos(b, sizePrefixed) {
  const base = sizePrefixed ? 4 : 0;
  if (sizePrefixed && rdU32(b, 0) + 4 !== b.length) throw new FormatError('size prefix mismatch');
  return base + rdU32(b, base);
}

function hasIdentifier(b, sizePrefixed, ident) {
  const at = sizePrefixed ? 8 : 4;
  if (b.length < at + 4) return false;
  for (let i = 0; i < 4; i++) if (b[at + i] !== ident.charCodeAt(i)) return false;
  return true;
}

function checkPnmTable(t) {
  for (let vOff = 4; vOff <= 20; vOff += 2) checkString(t, vOff);
}

function checkEncTable(t) {
  for (const [vOff, size] of [[4, 1], [6, 1], [8, 1], [10, 1], [24, 8]]) fieldAt(t, vOff, size);
  // EPHEMERAL_PUBLIC_KEY and NONCE_START are required: without them there is
  // nothing to decrypt with.
  if (!fieldAt(t, 12, 4) || !fieldAt(t, 14, 4)) throw new FormatError('ENC without key or nonce');
  checkByteVector(t, 12, { min: 1, max: 65 });
  checkByteVector(t, 14, { min: 12, max: 12 });
  checkByteVector(t, 16, { max: 32 });
  checkString(t, 18);
  checkByteVector(t, 20, { max: 32 });
  checkString(t, 22);
}

function checkFilTable(t) {
  checkString(t, 4);
  checkString(t, 6);
  fieldAt(t, 8, 1);
  checkString(t, 10);
  for (const vOff of [12, 14, 16, 26]) fieldAt(t, vOff, 8);
  fieldAt(t, 18, 1);
  checkByteVector(t, 20, { max: 64 });
  checkByteVector(t, 22);
  fieldAt(t, 24, 1);
}

function pnmFromTable(t) {
  const pnm = new PNM().__init(t.pos, new flatbuffers.ByteBuffer(t.b));
  return {
    MULTIFORMAT_ADDRESS: pnm.MULTIFORMAT_ADDRESS(),
    PUBLISH_TIMESTAMP: pnm.PUBLISH_TIMESTAMP(),
    CID: pnm.CID(),
    FILE_NAME: pnm.FILE_NAME(),
    FILE_ID: pnm.FILE_ID(),
    SIGNATURE: pnm.SIGNATURE(),
    TIMESTAMP_SIGNATURE: pnm.TIMESTAMP_SIGNATURE(),
    SIGNATURE_TYPE: pnm.SIGNATURE_TYPE(),
    TIMESTAMP_SIGNATURE_TYPE: pnm.TIMESTAMP_SIGNATURE_TYPE(),
  };
}

function encFromTable(t) {
  const enc = new ENC().__init(t.pos, new flatbuffers.ByteBuffer(t.b));
  return {
    version: enc.VERSION(),
    keyExchange: enc.KEY_EXCHANGE(),
    symmetric: enc.SYMMETRIC(),
    keyDerivation: enc.KEY_DERIVATION(),
    ephemeralPublicKey: readByteVector(t, 12),
    nonceStart: readByteVector(t, 14),
    recipientKeyId: readByteVector(t, 16),
    context: enc.CONTEXT(),
    schemaHash: readByteVector(t, 20),
    rootType: enc.ROOT_TYPE(),
    timestamp: enc.TIMESTAMP(),
  };
}

// ---------------------------------------------------------------------------
// Names
// ---------------------------------------------------------------------------

export function envelopeFileName(wasm, name, kind) {
  const base = nullIfBlank(name) ?? DEFAULT_TEXT_NAME;
  return `${base}.${kind}`;
}

export function decryptedFallbackName(wasm, encName) {
  const name = nullIfBlank(encName) ?? 'decrypted.bin';
  return /\.enc$/i.test(name) && name.length > 4 ? name.slice(0, -4) : `${name}.bin`;
}

// ---------------------------------------------------------------------------
// CID, peer IDs
// ---------------------------------------------------------------------------

export function createCidV1Raw(wasm, bytes) {
  const digest = wasm.utils.sha256(toBytes(bytes));
  return `b${toBase32Lower(concatBytes([Uint8Array.of(0x01, 0x55, 0x12, digest.length), digest]))}`;
}

export function peerIdFromEd25519(wasm, publicKey) {
  return wasm.libp2p.peerIdToString(wasm.libp2p.peerIdFromPublicKey(publicKey, CURVE_ED25519));
}

// Ed25519 peer IDs are 52 base58 characters and secp256k1 ones 53. Anything
// much longer is refused before decoding: base58 decoding is quadratic, and a
// hostile .rec could otherwise stall the page on a megabyte-long "peer ID".
const MAX_PEER_ID_LENGTH = 64;

export function parsePeerId(wasm, peerId) {
  if (typeof peerId !== 'string' || peerId.length > MAX_PEER_ID_LENGTH || !/^\w+$/.test(peerId)) return null;
  let raw;
  try {
    raw = base58.decode(peerId);
  } catch {
    return null;
  }
  if (raw.length === 38 && startsWith(raw, ED25519_PEER_PREFIX)) {
    return { keyType: SIGNATURE_TYPE_ED25519, publicKey: raw.slice(6) };
  }
  if (raw.length === 39 && startsWith(raw, SECP256K1_PEER_PREFIX) && (raw[6] === 2 || raw[6] === 3)) {
    return { keyType: SIGNATURE_TYPE_SECP256K1, publicKey: raw.slice(6) };
  }
  return null;
}

// ---------------------------------------------------------------------------
// Record encoding
// ---------------------------------------------------------------------------

function pnmT(notice) {
  return new PNMT(
    nullIfBlank(notice.MULTIFORMAT_ADDRESS),
    nullIfBlank(notice.PUBLISH_TIMESTAMP),
    nullIfBlank(notice.CID),
    nullIfBlank(notice.FILE_NAME),
    nullIfBlank(notice.FILE_ID),
    nullIfBlank(notice.SIGNATURE),
    nullIfBlank(notice.TIMESTAMP_SIGNATURE),
    nullIfBlank(notice.SIGNATURE_TYPE),
    nullIfBlank(notice.TIMESTAMP_SIGNATURE_TYPE),
  );
}

// Mirrors module-sdk records.js encTableFromObject: byte vectors always present
// (empty when absent), strings omitted when blank, enums as numbers.
function encT(enc) {
  const bytes = (v) => Array.from(v ? toBytes(v) : []);
  return new ENCT(
    Number(enc.version ?? 1),
    Number(enc.keyExchange ?? KeyExchange.X25519),
    Number(enc.symmetric ?? SYMMETRIC_AES_256_GCM),
    Number(enc.keyDerivation ?? KDF.HKDF_SHA256),
    bytes(enc.ephemeralPublicKey),
    bytes(enc.nonceStart),
    bytes(enc.recipientKeyId),
    nullIfBlank(enc.context),
    bytes(enc.schemaHash),
    nullIfBlank(enc.rootType),
    BigInt(enc.timestamp ?? 0),
  );
}

export function encodeEncRecord(wasm, enc) {
  const builder = new flatbuffers.Builder(256);
  ENC.finishENCBuffer(builder, encT(enc).pack(builder));
  return builder.asUint8Array().slice();
}

function encodePnm(notice, sizePrefixed) {
  const builder = new flatbuffers.Builder(256);
  const root = pnmT(notice).pack(builder);
  if (sizePrefixed) PNM.finishSizePrefixedPNMBuffer(builder, root);
  else PNM.finishPNMBuffer(builder, root);
  return builder.asUint8Array().slice();
}

// Same bytes as RECT(version, [RecordT(type, table, standard)]).pack + REC.finishRECBuffer.
function packRecord(builder, type, standard, valueT) {
  const value = valueT.pack(builder);
  const std = builder.createString(standard);
  builder.startVector(1, 0, 1);
  const extended = builder.endVector();
  builder.startObject(5);
  builder.addFieldInt8(0, type, 0);
  builder.addFieldOffset(1, value, 0);
  builder.addFieldOffset(2, std, 0);
  builder.addFieldInt16(3, 0, 0);
  builder.addFieldOffset(4, extended, 0);
  return builder.endObject();
}

export function encodeRecordCollection(wasm, { enc = null, pnm = null } = {}) {
  const entries = [];
  if (enc) entries.push([RECORD_TYPE.ENC, 'ENC', encT(enc)]);
  if (pnm) entries.push([RECORD_TYPE.PNM, 'PNM', pnmT(pnm)]);
  if (!entries.length) throw new EnvelopeError('invalid-input', 'a record collection needs ENC or PNM');
  const builder = new flatbuffers.Builder(1024);
  const version = builder.createString(RECORD_COLLECTION_VERSION);
  const records = entries.map(([type, standard, table]) => packRecord(builder, type, standard, table));
  builder.startVector(4, records.length, 4);
  for (let i = records.length - 1; i >= 0; i--) builder.addOffset(records[i]);
  const vector = builder.endVector();
  builder.startObject(2);
  builder.addFieldOffset(0, version, 0);
  builder.addFieldOffset(1, vector, 0);
  builder.finish(builder.endObject(), '$REC');
  return builder.asUint8Array().slice();
}

export function appendTrailer(wasm, payload, recordCollection) {
  return concatBytes([toBytes(payload), recordCollection, u32le(recordCollection.length), Uint8Array.from(TRAILER_MAGIC)]);
}

function decodeRecordCollection(rec) {
  if (!hasIdentifier(rec, false, '$REC')) throw new FormatError('not a $REC buffer');
  const root = openTable(rec, rootTablePos(rec, false));
  checkString(root, 4);
  const at = fieldAt(root, 6, 4);
  if (!at) throw new FormatError('no records');
  const vec = refAt(rec, at);
  const count = rdU32(rec, vec);
  if (count === 0 || vec + 4 + count * 4 > rec.length) throw new FormatError('bad records vector');
  const records = [];
  let enc = null;
  let pnm = null;
  for (let i = 0; i < count; i++) {
    const record = openTable(rec, refAt(rec, vec + 4 + i * 4));
    checkString(record, 8);
    const standard = (readStringField(record, 8) ?? '').trim();
    const typeAt = fieldAt(record, 4, 1);
    const type = typeAt ? rec[typeAt] : 0;
    const value = subTable(record, 6);
    if (!value) throw new FormatError('record without value');
    if (standard === 'ENC') {
      if (enc) throw new FormatError('two ENC records');
      checkEncTable(value);
      enc = encFromTable(value);
    } else if (standard === 'PNM') {
      if (pnm) throw new FormatError('two PNM records');
      checkPnmTable(value);
      pnm = pnmFromTable(value);
    }
    records.push({ standard, type });
  }
  return { enc, pnm, records };
}

export function extractTrailer(wasm, bytes) {
  const b = toBytes(bytes);
  if (b.length < TRAILER_FOOTER_LENGTH) return null;
  const footer = b.length - TRAILER_FOOTER_LENGTH;
  for (let i = 0; i < 4; i++) if (b[footer + 4 + i] !== TRAILER_MAGIC[i]) return null;
  const length = rdU32(b, footer);
  if (length > footer) return null;
  const start = footer - length;
  const recordCollection = b.subarray(start, footer);
  try {
    return { payload: b.subarray(0, start), recordCollection, ...decodeRecordCollection(recordCollection) };
  } catch {
    // FormatError, or a RangeError from a generated SDS accessor on a hostile
    // buffer: either way this is not a record collection we can read.
    return null;
  }
}

function parseSizePrefixedPnm(b) {
  if (!hasIdentifier(b, true, '$PNM')) return null;
  try {
    const t = openTable(b, rootTablePos(b, true));
    checkPnmTable(t);
    return pnmFromTable(t);
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// $FIL
// ---------------------------------------------------------------------------

export function buildFileRecord(wasm, { content, name, mediaType, modifiedAtMs = 0 }) {
  const data = toBytes(content);
  const digest = wasm.utils.sha256(data);
  const builder = new flatbuffers.Builder(data.length + 512);
  const nameOffset = builder.createString(nullIfBlank(name) ?? DEFAULT_TEXT_NAME);
  const mediaOffset = builder.createString(nullIfBlank(mediaType) ?? DEFAULT_MEDIA_TYPE);
  const digestOffset = builder.createByteVector(digest);
  const contentOffset = builder.createByteVector(data);
  FIL.startFIL(builder);
  FIL.addName(builder, nameOffset);
  FIL.addKind(builder, filEntryKind.File);
  FIL.addMediaType(builder, mediaOffset);
  FIL.addSize(builder, BigInt(data.length));
  FIL.addModifiedAtMs(builder, BigInt(Math.max(0, Math.trunc(Number(modifiedAtMs) || 0))));
  FIL.addDigestAlgorithm(builder, filDigestAlgorithm.SHA256);
  FIL.addDigest(builder, digestOffset);
  FIL.addContent(builder, contentOffset);
  FIL.finishSizePrefixedFILBuffer(builder, FIL.endFIL(builder));
  return builder.asUint8Array().slice();
}

export function parseFileRecord(wasm, bytes) {
  const b = toBytes(bytes);
  if (!hasIdentifier(b, true, '$FIL')) return null;
  try {
    const t = openTable(b, rootTablePos(b, true));
    checkFilTable(t);
    const fil = new FIL().__init(t.pos, new flatbuffers.ByteBuffer(b));
    return {
      name: fil.NAME(),
      mediaType: fil.MEDIA_TYPE(),
      size: fil.SIZE(),
      modifiedAtMs: Number(fil.MODIFIED_AT_MS()),
      digestAlgorithm: fil.DIGEST_ALGORITHM(),
      digest: readByteVector(t, 20) ?? new Uint8Array(0),
      content: readByteVector(t, 22) ?? new Uint8Array(0),
    };
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// $EPM (the contact card)
//
// contact-card.js builds and checks the card as a plain field object (the
// UPPER_SNAKE schema names, as hd-wallet-wasm signEPMContent canonicalizes
// them); these two functions are its FlatBuffer codec. The card never carries
// a private key: encodeEpm refuses PRIVATE_KEY / XPRIV, and decodeEpm drops
// them if someone else's card has them.
// ---------------------------------------------------------------------------

const EPM_MAX_LIST = 256;

const EPM_STRINGS = Object.freeze([
  [4, 'DN'], [6, 'LEGAL_NAME'], [8, 'FAMILY_NAME'], [10, 'GIVEN_NAME'], [12, 'ADDITIONAL_NAME'],
  [14, 'HONORIFIC_PREFIX'], [16, 'HONORIFIC_SUFFIX'], [18, 'JOB_TITLE'], [20, 'OCCUPATION'],
  [26, 'EMAIL'], [28, 'TELEPHONE'], [34, 'SIGNATURE'], [42, 'SIGNATURE_ALGORITHM'], [46, 'PHOTO'],
]);
const EPM_ADDRESS_STRINGS = Object.freeze([
  [4, 'COUNTRY'], [6, 'REGION'], [8, 'LOCALITY'], [10, 'POSTAL_CODE'], [12, 'STREET'], [14, 'POST_OFFICE_BOX_NUMBER'],
]);
// PRIVATE_KEY (8) and XPRIV (10) are never read.
const EPM_KEY_STRINGS = Object.freeze([
  [4, 'PUBLIC_KEY'], [6, 'XPUB'], [12, 'KEY_ADDRESS'], [14, 'ADDRESS_TYPE'], [18, 'KEY_PATH'],
  [20, 'ALGORITHM'], [22, 'ENCODING'],
]);
const EPM_PROOF_STRINGS = Object.freeze([
  [4, 'CHAIN'], [6, 'ADDRESS'], [8, 'PUBLIC_KEY'], [10, 'KEY_PATH'], [12, 'SIGNATURE'],
  [14, 'SIGNED_PAYLOAD'], [16, 'ALGORITHM'], [18, 'ENCODING'],
]);
const EPM_DOMAIN_PROOF_STRINGS = Object.freeze([
  [4, 'DOMAIN'], [6, 'PUBLIC_KEY'], [8, 'KEY_PATH'], [10, 'SIGNATURE'], [12, 'SIGNED_PAYLOAD'],
  [14, 'ALGORITHM'], [16, 'ENCODING'],
]);

function readCheckedString(t, vOff) {
  checkString(t, vOff);
  return readStringField(t, vOff);
}

function readStrings(t, fields, into = {}) {
  for (const [vOff, name] of fields) {
    const value = readCheckedString(t, vOff);
    if (value !== null) into[name] = value;
  }
  return into;
}

function readByteField(t, vOff, fallback = 0) {
  const at = fieldAt(t, vOff, 1);
  return at ? t.b[at] : fallback;
}

/** The element positions of a vector of offsets (strings or tables). */
function offsetVector(t, vOff) {
  const at = fieldAt(t, vOff, 4);
  if (!at) return [];
  const v = refAt(t.b, at);
  const n = rdU32(t.b, v);
  if (n > EPM_MAX_LIST || v + 4 + n * 4 > t.b.length) throw new FormatError('bad offset vector');
  const out = [];
  for (let i = 0; i < n; i++) out.push(refAt(t.b, v + 4 + i * 4));
  return out;
}

function readStringVector(t, vOff) {
  return offsetVector(t, vOff).map((s) => {
    const n = rdU32(t.b, s);
    if (s + 4 + n + 1 > t.b.length || t.b[s + 4 + n] !== 0) throw new FormatError('bad string');
    return new TextDecoder().decode(t.b.subarray(s + 4, s + 4 + n));
  });
}

function readTableVector(t, vOff, read) {
  return offsetVector(t, vOff).map((pos) => read(openTable(t.b, pos)));
}

function epmFromTable(t) {
  const epm = readStrings(t, EPM_STRINGS);
  const address = subTable(t, 22);
  if (address) epm.ADDRESS = readStrings(address, EPM_ADDRESS_STRINGS);
  const alternateNames = readStringVector(t, 24);
  if (alternateNames.length) epm.ALTERNATE_NAMES = alternateNames;
  epm.KEYS = readTableVector(t, 30, (key) => {
    const out = readStrings(key, EPM_KEY_STRINGS);
    out.KEY_TYPE = readByteField(key, 16, KeyType.Signing);
    return out;
  });
  epm.MULTIFORMAT_ADDRESS = readStringVector(t, 32);
  const tsAt = fieldAt(t, 36, 8);
  if (tsAt) {
    const ts = new DataView(t.b.buffer, t.b.byteOffset + tsAt, 8).getBigUint64(0, true);
    epm.SIGNATURE_TIMESTAMP = ts <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(ts) : ts.toString();
  }
  epm.CHAIN_PROOFS = readTableVector(t, 38, (proof) => readStrings(proof, EPM_PROOF_STRINGS));
  epm.ENTITY_TYPE = readByteField(t, 40, EntityType.User);
  const domainProofs = readTableVector(t, 44, (proof) => readStrings(proof, EPM_DOMAIN_PROOF_STRINGS));
  if (domainProofs.length) epm.DOMAIN_PROOFS = domainProofs;
  return epm;
}

/**
 * A contact card's bytes as a plain EPM field object. Accepts a size-prefixed
 * `$EPM` (what encodeEpm writes) or a root `$EPM`.
 * @throws {EnvelopeError} code 'not-epm' when the bytes are not a well-formed $EPM
 */
export function decodeEpm(wasm, bytes) {
  const b = toBytes(bytes);
  const sizePrefixed = hasIdentifier(b, true, '$EPM') && b.length >= 12 && rdU32(b, 0) + 4 === b.length;
  if (!sizePrefixed && !hasIdentifier(b, false, '$EPM')) throw new EnvelopeError('not-epm', 'not an $EPM buffer');
  try {
    return epmFromTable(openTable(b, rootTablePos(b, sizePrefixed)));
  } catch (error) {
    if (error instanceof FormatError || error instanceof RangeError) {
      throw new EnvelopeError('not-epm', 'not a well-formed $EPM buffer');
    }
    throw error;
  }
}

function optionalString(value) {
  if (value === undefined || value === null) return null;
  return String(value);
}

function stringList(values) {
  return Array.isArray(values) ? values.filter((v) => typeof v === 'string') : [];
}

function enumValue(value, names, fallback) {
  if (typeof value === 'number' && Number.isInteger(value)) return value;
  const index = names.indexOf(value);
  return index >= 0 ? index : fallback;
}

/**
 * A plain EPM field object (contact-card.js buildContactEpm) as a size-prefixed
 * `$EPM` (EPM.finishSizePrefixedEPMBuffer), the `.epm` contact card file.
 */
export function encodeEpm(wasm, epm) {
  if (!epm || typeof epm !== 'object') throw new EnvelopeError('invalid-input', 'an EPM needs fields');
  const keys = Array.isArray(epm.KEYS) ? epm.KEYS : [];
  for (const key of keys) {
    if (key?.PRIVATE_KEY || key?.XPRIV) throw new EnvelopeError('invalid-input', 'a contact card never carries a private key');
  }
  const address = epm.ADDRESS && typeof epm.ADDRESS === 'object'
    ? new AddressT(
      optionalString(epm.ADDRESS.COUNTRY),
      optionalString(epm.ADDRESS.REGION),
      optionalString(epm.ADDRESS.LOCALITY),
      optionalString(epm.ADDRESS.POSTAL_CODE),
      optionalString(epm.ADDRESS.STREET),
      optionalString(epm.ADDRESS.POST_OFFICE_BOX_NUMBER),
    )
    : null;
  const keyNames = ['Signing', 'Encryption'];
  const cryptoKeys = keys.map((key) => new CryptoKeyT(
    optionalString(key.PUBLIC_KEY),
    optionalString(key.XPUB),
    null,
    null,
    optionalString(key.KEY_ADDRESS),
    optionalString(key.ADDRESS_TYPE),
    enumValue(key.KEY_TYPE, keyNames, KeyType.Signing),
    optionalString(key.KEY_PATH),
    optionalString(key.ALGORITHM),
    optionalString(key.ENCODING),
  ));
  const chainProofs = (Array.isArray(epm.CHAIN_PROOFS) ? epm.CHAIN_PROOFS : []).map((proof) => new ChainProofT(
    optionalString(proof.CHAIN),
    optionalString(proof.ADDRESS),
    optionalString(proof.PUBLIC_KEY),
    optionalString(proof.KEY_PATH),
    optionalString(proof.SIGNATURE),
    optionalString(proof.SIGNED_PAYLOAD),
    optionalString(proof.ALGORITHM),
    optionalString(proof.ENCODING),
  ));
  const domainProofs = (Array.isArray(epm.DOMAIN_PROOFS) ? epm.DOMAIN_PROOFS : []).map((proof) => new DomainProofT(
    optionalString(proof.DOMAIN),
    optionalString(proof.PUBLIC_KEY),
    optionalString(proof.KEY_PATH),
    optionalString(proof.SIGNATURE),
    optionalString(proof.SIGNED_PAYLOAD),
    optionalString(proof.ALGORITHM),
    optionalString(proof.ENCODING),
  ));
  const timestamp = epm.SIGNATURE_TIMESTAMP;
  const table = new EPMT(
    optionalString(epm.DN),
    optionalString(epm.LEGAL_NAME),
    optionalString(epm.FAMILY_NAME),
    optionalString(epm.GIVEN_NAME),
    optionalString(epm.ADDITIONAL_NAME),
    optionalString(epm.HONORIFIC_PREFIX),
    optionalString(epm.HONORIFIC_SUFFIX),
    optionalString(epm.JOB_TITLE),
    optionalString(epm.OCCUPATION),
    address,
    stringList(epm.ALTERNATE_NAMES),
    optionalString(epm.EMAIL),
    optionalString(epm.TELEPHONE),
    cryptoKeys,
    stringList(epm.MULTIFORMAT_ADDRESS),
    optionalString(epm.SIGNATURE),
    BigInt(timestamp == null || timestamp === '' ? 0 : timestamp),
    chainProofs,
    enumValue(epm.ENTITY_TYPE, ['User', 'Node'], EntityType.User),
    optionalString(epm.SIGNATURE_ALGORITHM),
    domainProofs,
    optionalString(epm.PHOTO),
  );
  const builder = new flatbuffers.Builder(1024);
  EPM.finishSizePrefixedEPMBuffer(builder, table.pack(builder));
  return builder.asUint8Array().slice();
}

// ---------------------------------------------------------------------------
// Sign
// ---------------------------------------------------------------------------

function checkSize(data) {
  if (data.length > MAX_INPUT_BYTES) throw new EnvelopeError('too-large', TOO_LARGE_TEXT);
}

export function signContent(wasm, { content, name, signingKey, timestamp } = {}) {
  requireKey(signingKey, 'signingKey');
  const data = toBytes(content);
  checkSize(data);
  const fileName = nullIfBlank(name) ?? DEFAULT_TEXT_NAME;
  const publicKey = wasm.curves.ed25519.publicKeyFromSeed(signingKey);
  const peerId = peerIdFromEd25519(wasm, publicKey);
  const cid = createCidV1Raw(wasm, data);
  const ts = nullIfBlank(timestamp) ?? new Date().toISOString();
  const sig = wasm.curves.ed25519.sign(textEncoder.encode(cid), signingKey);
  const tsSig = wasm.curves.ed25519.sign(textEncoder.encode(ts), signingKey);
  return {
    MULTIFORMAT_ADDRESS: `/p2p/${peerId}`,
    PUBLISH_TIMESTAMP: ts,
    CID: cid,
    FILE_NAME: fileName,
    FILE_ID: `${peerId}:wallet:${fileName}:${ts}`,
    SIGNATURE: bytesToHex(sig),
    TIMESTAMP_SIGNATURE: bytesToHex(tsSig),
    SIGNATURE_TYPE: SIGNATURE_TYPE_ED25519,
    TIMESTAMP_SIGNATURE_TYPE: SIGNATURE_TYPE_ED25519,
    content: data,
    name: fileName,
    peerId,
    publicKey,
  };
}

export function buildRecFile(wasm, content, notice) {
  return appendTrailer(wasm, toBytes(content), encodeRecordCollection(wasm, { pnm: notice }));
}

export function buildPnmFile(wasm, notice) {
  return encodePnm(notice, true);
}

// ---------------------------------------------------------------------------
// Verify
// ---------------------------------------------------------------------------

function readDer(der) {
  // Strict DER: 30 len 02 rlen r 02 slen s, minimal lengths and integers, positive.
  if (!(der instanceof Uint8Array) || der.length < 8 || der.length > 72) return null;
  if (der[0] !== 0x30 || der[1] !== der.length - 2) return null;
  const ints = [];
  let p = 2;
  for (let k = 0; k < 2; k++) {
    if (der[p] !== 0x02) return null;
    const len = der[p + 1];
    if (len < 1 || len > 33 || p + 2 + len > der.length) return null;
    const v = der.subarray(p + 2, p + 2 + len);
    if (v[0] & 0x80) return null;
    if (len > 1 && v[0] === 0 && !(v[1] & 0x80)) return null;
    if (len === 33 && v[0] !== 0) return null;
    ints.push(len === 33 ? v.subarray(1) : v);
    p += 2 + len;
  }
  if (p !== der.length) return null;
  const compact = new Uint8Array(64);
  compact.set(ints[0], 32 - ints[0].length);
  compact.set(ints[1], 64 - ints[1].length);
  return compact;
}

function verifySignature(wasm, type, message, sigHex, signer) {
  if (type !== signer.keyType) return false;
  const sig = hexToBytes(sigHex ?? '');
  if (!sig) return false;
  try {
    if (type === SIGNATURE_TYPE_ED25519) {
      return sig.length === 64 && wasm.curves.ed25519.verify(message, sig, signer.publicKey) === true;
    }
    if (type === SIGNATURE_TYPE_SECP256K1) {
      const compact = readDer(sig);
      return !!compact && wasm.curves.secp256k1.verify(message, compact, signer.publicKey) === true;
    }
  } catch {
    return false;
  }
  return false;
}

export function verifyNotice(wasm, notice, content) {
  const data = toBytes(content);
  const result = { valid: false, reason: null, timestampValid: false, signer: null };
  const cid = createCidV1Raw(wasm, data);
  if (!notice || typeof notice.CID !== 'string' || notice.CID.trim() !== cid) {
    result.reason = 'changed';
    return result;
  }
  const address = typeof notice.MULTIFORMAT_ADDRESS === 'string' ? notice.MULTIFORMAT_ADDRESS.trim() : '';
  const match = address.length <= MAX_PEER_ID_LENGTH + 5 ? /^\/p2p\/(\w+)$/.exec(address) : null;
  const signer = match ? parsePeerId(wasm, match[1]) : null;
  if (!signer) {
    result.reason = 'not-peer-id';
    return result;
  }
  result.signer = { peerId: match[1], ...signer };
  if (!verifySignature(wasm, (notice.SIGNATURE_TYPE ?? '').trim(), textEncoder.encode(cid), notice.SIGNATURE, signer)) {
    result.reason = 'signature';
    return result;
  }
  result.valid = true;
  const ts = notice.PUBLISH_TIMESTAMP ?? '';
  result.timestampValid = ts.length > 0 && verifySignature(
    wasm,
    (notice.TIMESTAMP_SIGNATURE_TYPE ?? '').trim(),
    textEncoder.encode(ts),
    notice.TIMESTAMP_SIGNATURE,
    signer,
  );
  return result;
}

export function classifyInput(wasm, bytes) {
  const b = toBytes(bytes);
  const trailer = extractTrailer(wasm, b);
  if (trailer?.enc) return { kind: 'enc', trailer };
  if (trailer?.pnm) return { kind: 'rec', trailer, notice: trailer.pnm, content: trailer.payload };
  const notice = parseSizePrefixedPnm(b);
  if (notice) return { kind: 'pnm', notice };
  return { kind: 'unknown' };
}

export function verifyInput(wasm, bytes, { original } = {}) {
  const c = classifyInput(wasm, bytes);
  if (c.kind === 'enc') return { kind: 'enc' };
  if (c.kind === 'unknown') return { kind: 'unknown', valid: false, reason: 'not-sds', timestampValid: false, signer: null };
  if (c.kind === 'pnm' && original == null) return { kind: 'pnm', needsOriginal: true, notice: c.notice };
  const content = c.kind === 'rec' ? c.content : toBytes(original);
  return {
    kind: c.kind,
    ...verifyNotice(wasm, c.notice, content),
    notice: c.notice,
    content,
    fileName: c.notice.FILE_NAME,
    size: content.length,
  };
}

// ---------------------------------------------------------------------------
// Encrypt / decrypt
// ---------------------------------------------------------------------------

export function sealBytes(wasm, plaintext, recipientPublicKey, { rootType = 'FIL', timestamp } = {}) {
  const recipient = requireKey(recipientPublicKey, 'recipientPublicKey');
  const e = wasm.utils.getRandomBytes(32);
  let ss = null;
  let key = null;
  try {
    const ephemeralPublicKey = wasm.curves.x25519.publicKey(e);
    try {
      ss = checkedSharedSecret(wasm.curves.x25519.ecdh(e, recipient));
    } catch {
      // WASM X25519 refuses all-zero and low-order points; an all-zero
      // shared secret is refused here as well, whatever the WASM returned.
      throw new EnvelopeError('bad-recipient-key', 'This is not a valid encryption key.');
    }
    zero(e);
    key = wasm.utils.hkdf(ss, new Uint8Array(0), textEncoder.encode(MESSAGE_CONTEXT), 32);
    zero(ss);
    const enc = {
      version: 1,
      keyExchange: KeyExchange.X25519,
      symmetric: SYMMETRIC_AES_256_GCM,
      keyDerivation: KDF.HKDF_SHA256,
      ephemeralPublicKey,
      nonceStart: wasm.utils.getRandomBytes(12),
      recipientKeyId: wasm.utils.sha256(recipient),
      context: MESSAGE_CONTEXT,
      rootType,
      timestamp: BigInt(timestamp ?? Date.now()),
    };
    const aad = encodeEncRecord(wasm, enc);
    const { ciphertext, tag } = wasm.utils.aesGcm.encrypt(key, toBytes(plaintext), enc.nonceStart, aad);
    return appendTrailer(wasm, concatBytes([ciphertext, tag]), encodeRecordCollection(wasm, { enc }));
  } finally {
    zero(e, ss, key);
  }
}

export function encryptContent(wasm, {
  content,
  name,
  mediaType,
  modifiedAtMs = 0,
  recipientPublicKey,
  signingKey = null,
  timestamp,
} = {}) {
  requireKey(recipientPublicKey, 'recipientPublicKey');
  const isText = typeof content === 'string';
  const data = toBytes(content);
  checkSize(data);
  const fileName = nullIfBlank(name) ?? DEFAULT_TEXT_NAME;
  const fil = buildFileRecord(wasm, {
    content: data,
    name: fileName,
    mediaType: nullIfBlank(mediaType) ?? (isText ? TEXT_MEDIA_TYPE : DEFAULT_MEDIA_TYPE),
    modifiedAtMs,
  });
  let plaintext = fil;
  let notice = null;
  if (signingKey) {
    notice = signContent(wasm, { content: fil, name: fileName, signingKey, timestamp });
    plaintext = buildRecFile(wasm, fil, notice);
  }
  const bytes = sealBytes(wasm, plaintext, recipientPublicKey, { rootType: 'FIL' });
  // The plaintext copies hold the user's content; clear them once sealed.
  zero(plaintext, fil);
  let publicNotice = null;
  if (notice) {
    const { content: _filBytes, ...rest } = notice;
    publicNotice = rest;
  }
  return {
    bytes,
    fileName: envelopeFileName(wasm, fileName, 'enc'),
    mime: ENVELOPE_MIME.enc,
    signed: !!notice,
    recipientKeyId: wasm.utils.sha256(recipientPublicKey),
    notice: publicNotice,
  };
}

/**
 * An X25519 shared secret the page will use: exactly 32 bytes and not all
 * zero. A low-order peer key gives the all-zero secret, which an attacker can
 * predict; hd-wallet-wasm refuses those points, and this is the page's own
 * check (SEC-002 defence in depth: up to 2.1.0 some WASM ECDH failures came
 * back as success). Throws otherwise.
 */
function checkedSharedSecret(ss) {
  if (!(ss instanceof Uint8Array) || ss.length !== 32) throw new Error('bad shared secret');
  let any = 0;
  for (const byte of ss) any |= byte;
  if (any === 0) throw new Error('bad shared secret');
  return ss;
}

function decryptFailure(error) {
  return { ok: false, error, message: DECRYPT_ERROR_TEXT[error] };
}

export function decryptFile(wasm, bytes, { encryptionKey, fileName } = {}) {
  requireKey(encryptionKey, 'encryptionKey');
  const trailer = extractTrailer(wasm, toBytes(bytes));
  if (!trailer?.enc) return decryptFailure('not-enc');
  const enc = trailer.enc;
  if (enc.keyExchange !== KeyExchange.X25519 || enc.symmetric !== SYMMETRIC_AES_256_GCM
      || enc.keyDerivation !== KDF.HKDF_SHA256 || enc.ephemeralPublicKey?.length !== 32) {
    return decryptFailure('unsupported');
  }
  const myPublicKey = wasm.curves.x25519.publicKey(encryptionKey);
  if (enc.recipientKeyId && !equalBytes(enc.recipientKeyId, wasm.utils.sha256(myPublicKey))) {
    return decryptFailure('wrong-recipient');
  }
  if (trailer.payload.length < GCM_TAG_LENGTH) return decryptFailure('auth-failed');
  let ss = null;
  let key = null;
  let plaintext;
  try {
    ss = checkedSharedSecret(wasm.curves.x25519.ecdh(encryptionKey, enc.ephemeralPublicKey));
    key = wasm.utils.hkdf(ss, new Uint8Array(0), textEncoder.encode(enc.context ?? ''), 32);
    const split = trailer.payload.length - GCM_TAG_LENGTH;
    plaintext = wasm.utils.aesGcm.decrypt(
      key,
      trailer.payload.subarray(0, split),
      trailer.payload.subarray(split),
      enc.nonceStart,
      encodeEncRecord(wasm, enc),
    );
  } catch {
    return decryptFailure('auth-failed');
  } finally {
    zero(ss, key);
  }
  return openPlaintext(wasm, plaintext, fileName);
}

function openPlaintext(wasm, plaintext, fileName) {
  let body = plaintext;
  let signature = null;
  const wholeFil = hasIdentifier(plaintext, true, '$FIL') && rdU32(plaintext, 0) + 4 === plaintext.length;
  if (!wholeFil) {
    const inner = extractTrailer(wasm, plaintext);
    if (inner?.pnm && !inner.enc) {
      body = inner.payload;
      signature = { ...verifyNotice(wasm, inner.pnm, body), notice: inner.pnm };
    }
  }
  const file = parseFileRecord(wasm, body);
  if (!file) {
    return { ok: true, isFileRecord: false, bytes: plaintext, saveName: decryptedFallbackName(wasm, fileName), signature };
  }
  if (file.digestAlgorithm !== filDigestAlgorithm.SHA256
      || file.size !== BigInt(file.content.length)
      || !equalBytes(wasm.utils.sha256(file.content), file.digest)) {
    return decryptFailure('file-changed');
  }
  return {
    ok: true,
    isFileRecord: true,
    file: {
      name: file.name ?? decryptedFallbackName(wasm, fileName),
      mediaType: file.mediaType ?? DEFAULT_MEDIA_TYPE,
      size: file.content.length,
      modifiedAtMs: file.modifiedAtMs,
      content: file.content,
    },
    signature,
  };
}

export function textPreview(wasm, bytes, max = 64 * 1024) {
  const b = toBytes(bytes);
  if (b.length > max) return null;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(b);
  } catch {
    return null;
  }
}
