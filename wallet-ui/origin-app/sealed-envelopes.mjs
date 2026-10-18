/**
 * Readers for the SDS records a sealed field arrives in: the `$ENC` header
 * (spacedatastandards.org schema/ENC) and the `$KMF` key-material record
 * (schema/KMF). Every offset is bounds-checked; anything the wallet does not
 * open (another suite, a missing key id, a malformed table) is refused.
 *
 * Only the X25519 / AES-256-CTR / HKDF-SHA256 suite is accepted: the SDN
 * Unified ECIES field cipher the wallet's native code implements.
 */

const utf8 = new TextDecoder('utf-8', { fatal: true });

export class SealedEnvelopeError extends Error {
  constructor() {
    super('MALFORMED_ENVELOPE');
    this.name = 'SealedEnvelopeError';
    this.code = 'MALFORMED_ENVELOPE';
  }
}

function fail() {
  throw new SealedEnvelopeError();
}

function table(bytes, identifier) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 12) fail();
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  for (let index = 0; index < 4; index += 1) {
    if (bytes[4 + index] !== identifier.charCodeAt(index)) fail();
  }
  const root = view.getUint32(0, true);
  if (root < 8 || root + 4 > bytes.length) fail();
  const vtable = root - view.getInt32(root, true);
  if (vtable < 0 || vtable + 4 > bytes.length) fail();
  const vtableLength = view.getUint16(vtable, true);
  const objectLength = view.getUint16(vtable + 2, true);
  if (vtableLength < 4 || vtableLength % 2 !== 0 || vtable + vtableLength > bytes.length
      || objectLength < 4 || root + objectLength > bytes.length) fail();
  const slot = (index) => {
    const at = 4 + index * 2;
    if (at >= vtableLength) return 0;
    const offset = view.getUint16(vtable + at, true);
    if (offset !== 0 && (offset < 4 || offset >= objectLength)) fail();
    return offset;
  };
  return {
    scalar(index, defaultValue) {
      const offset = slot(index);
      return offset === 0 ? defaultValue : bytes[root + offset];
    },
    vector(index) {
      const offset = slot(index);
      if (offset === 0) return null;
      const at = root + offset;
      if (at + 4 > bytes.length) fail();
      const start = at + view.getUint32(at, true);
      if (start + 4 > bytes.length) fail();
      const length = view.getUint32(start, true);
      if (start + 4 + length > bytes.length) fail();
      return bytes.slice(start + 4, start + 4 + length);
    },
  };
}

/** The values of an SDS `$ENC` header the wallet opens. */
export function readEncHeader(bytes) {
  const header = table(bytes, '$ENC');
  if (header.scalar(0, 1) !== 1 // VERSION
      || header.scalar(1, 0) !== 0 // KEY_EXCHANGE = X25519
      || header.scalar(2, 0) !== 0 // SYMMETRIC = AES_256_CTR
      || header.scalar(3, 0) !== 0) fail(); // KEY_DERIVATION = HKDF_SHA256
  const ephemeralPublic = header.vector(4);
  const nonceStart = header.vector(5);
  const recipientKeyId = header.vector(6);
  const context = header.vector(7);
  if (ephemeralPublic?.length !== 32 || nonceStart?.length !== 12
      || recipientKeyId?.length !== 8 || !context || context.length === 0) fail();
  let text;
  try {
    text = utf8.decode(context);
  } catch {
    fail();
  }
  return Object.freeze({ context: text, ephemeralPublic, recipientKeyId });
}

/** KEY_BYTES of an SDS `$KMF` record: the 32-byte wrapped content key. */
export function readKmfKeyBytes(bytes) {
  const keyBytes = table(bytes, '$KMF').vector(4);
  if (keyBytes?.length !== 32) fail();
  return keyBytes;
}
