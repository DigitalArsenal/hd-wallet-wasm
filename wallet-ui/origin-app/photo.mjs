const MAX_PHOTO_BYTES = 2 * 1024 * 1024;
const MAX_DIMENSION = 2048;
const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const bufferGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'buffer').get;
const byteLengthGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteLength').get;
const byteOffsetGetter = Object.getOwnPropertyDescriptor(typedArrayPrototype, 'byteOffset').get;

export class WalletPhotoError extends Error {
  constructor(code) {
    super(code);
    this.name = 'WalletPhotoError';
    this.code = code;
  }
}

function fail(code) {
  throw new WalletPhotoError(code);
}

function bytesLength(value) {
  try { return byteLengthGetter.call(value); } catch { fail('INVALID_PHOTO_BYTES'); }
}

function requireBytes(value) {
  if (!(value instanceof Uint8Array)) fail('INVALID_PHOTO_BYTES');
  const length = bytesLength(value);
  if (length < 10 || length > MAX_PHOTO_BYTES) fail('INVALID_PHOTO_BYTES');
  try {
    const buffer = bufferGetter.call(value);
    const byteOffset = byteOffsetGetter.call(value);
    return new Uint8Array(new Uint8Array(buffer, byteOffset, length));
  } catch {
    fail('INVALID_PHOTO_BYTES');
  }
}

function ascii(bytes, offset, length) {
  let output = '';
  for (let index = 0; index < length; index += 1) output += String.fromCharCode(bytes[offset + index]);
  return output;
}

function pngDimensions(bytes) {
  if (bytes.length < 24
      || ascii(bytes, 8, 8) !== '\u0000\u0000\u0000\rIHDR') return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return { height: view.getUint32(20), width: view.getUint32(16) };
}

function gifDimensions(bytes) {
  if (bytes.length < 10 || !['GIF87a', 'GIF89a'].includes(ascii(bytes, 0, 6))) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  return { height: view.getUint16(8, true), width: view.getUint16(6, true) };
}

function webpDimensions(bytes) {
  if (bytes.length < 30 || ascii(bytes, 0, 4) !== 'RIFF' || ascii(bytes, 8, 4) !== 'WEBP') return null;
  const chunk = ascii(bytes, 12, 4);
  if (chunk === 'VP8X') {
    const width = 1 + bytes[24] + (bytes[25] << 8) + (bytes[26] << 16);
    const height = 1 + bytes[27] + (bytes[28] << 8) + (bytes[29] << 16);
    return { height, width };
  }
  if (chunk === 'VP8 ' && bytes.length >= 30
      && bytes[23] === 0x9d && bytes[24] === 0x01 && bytes[25] === 0x2a) {
    const width = (bytes[26] | (bytes[27] << 8)) & 0x3fff;
    const height = (bytes[28] | (bytes[29] << 8)) & 0x3fff;
    return { height, width };
  }
  if (chunk === 'VP8L' && bytes.length >= 25 && bytes[20] === 0x2f) {
    const bits = bytes[21] | (bytes[22] << 8) | (bytes[23] << 16) | (bytes[24] << 24);
    return {
      height: 1 + ((bits >>> 14) & 0x3fff),
      width: 1 + (bits & 0x3fff),
    };
  }
  return null;
}

function jpegDimensions(bytes) {
  if (bytes.length < 11 || bytes[0] !== 0xff || bytes[1] !== 0xd8) return null;
  let offset = 2;
  while (offset + 3 < bytes.length) {
    if (bytes[offset] !== 0xff) return null;
    while (offset < bytes.length && bytes[offset] === 0xff) offset += 1;
    const marker = bytes[offset++];
    if (marker === 0xd9 || marker === 0xda) break;
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) continue;
    if (offset + 1 >= bytes.length) return null;
    const length = (bytes[offset] << 8) | bytes[offset + 1];
    if (length < 2 || offset + length > bytes.length) return null;
    if ([0xc0, 0xc1, 0xc2, 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf].includes(marker)) {
      if (length < 7) return null;
      return {
        height: (bytes[offset + 3] << 8) | bytes[offset + 4],
        width: (bytes[offset + 5] << 8) | bytes[offset + 6],
      };
    }
    offset += length;
  }
  return null;
}

export function inspectPhotoBytes(value) {
  const bytes = requireBytes(value);
  let type;
  let dimensions;
  if (bytes.length >= 8 && bytes[0] === 137 && ascii(bytes, 1, 3) === 'PNG'
      && bytes[4] === 13 && bytes[5] === 10 && bytes[6] === 26 && bytes[7] === 10) {
    type = 'image/png';
    dimensions = pngDimensions(bytes);
  } else if (bytes[0] === 0xff && bytes[1] === 0xd8) {
    type = 'image/jpeg';
    dimensions = jpegDimensions(bytes);
  } else if (ascii(bytes, 0, 4) === 'RIFF') {
    type = 'image/webp';
    dimensions = webpDimensions(bytes);
  } else if (ascii(bytes, 0, 3) === 'GIF') {
    type = 'image/gif';
    dimensions = gifDimensions(bytes);
  }
  if (!type || !dimensions || !Number.isInteger(dimensions.width)
      || !Number.isInteger(dimensions.height) || dimensions.width < 1 || dimensions.height < 1
      || dimensions.width > MAX_DIMENSION || dimensions.height > MAX_DIMENSION) {
    fail('INVALID_PHOTO_BYTES');
  }
  return Object.freeze({
    bytes,
    height: dimensions.height,
    type,
    width: dimensions.width,
  });
}

async function defaultDecode(blob) {
  if (typeof globalThis.createImageBitmap !== 'function') fail('PHOTO_DECODER_UNAVAILABLE');
  let bitmap;
  try {
    bitmap = await globalThis.createImageBitmap(blob);
    return { height: bitmap.height, width: bitmap.width };
  } catch {
    fail('INVALID_PHOTO_BYTES');
  } finally {
    try { bitmap?.close?.(); } catch { /* decoded object is no longer needed */ }
  }
}

export class PhotoUrlController {
  #Blob;
  #URL;
  #decode;
  #destroyed = false;
  #generation = 0;
  #url = null;

  constructor({ Blob = globalThis.Blob, URL = globalThis.URL, decode = defaultDecode } = {}) {
    this.#Blob = Blob;
    this.#URL = URL;
    this.#decode = decode;
  }

  #revoke() {
    if (!this.#url) return;
    const value = this.#url;
    this.#url = null;
    try { this.#URL.revokeObjectURL(value); } catch { /* best effort */ }
  }

  async replace(value) {
    if (this.#destroyed) fail('PHOTO_CONTROLLER_DESTROYED');
    this.#generation += 1;
    const generation = this.#generation;
    const inspected = inspectPhotoBytes(value);
    const blob = new this.#Blob([inspected.bytes], { type: inspected.type });
    const decoded = await this.#decode(blob, Object.freeze({
      height: inspected.height,
      width: inspected.width,
    }));
    if (this.#destroyed || generation !== this.#generation) fail('PHOTO_REPLACED');
    if (!decoded || decoded.width !== inspected.width || decoded.height !== inspected.height
        || decoded.width > MAX_DIMENSION || decoded.height > MAX_DIMENSION) {
      fail('INVALID_PHOTO_BYTES');
    }
    let next;
    try { next = this.#URL.createObjectURL(blob); } catch { fail('PHOTO_URL_UNAVAILABLE'); }
    if (typeof next !== 'string' || !next.startsWith('blob:')) {
      try { this.#URL.revokeObjectURL(next); } catch { /* invalid URL */ }
      fail('PHOTO_URL_UNAVAILABLE');
    }
    if (this.#destroyed || generation !== this.#generation) {
      try { this.#URL.revokeObjectURL(next); } catch { /* stale URL is never exposed */ }
      fail('PHOTO_REPLACED');
    }
    this.#revoke();
    if (this.#destroyed || generation !== this.#generation) {
      try { this.#URL.revokeObjectURL(next); } catch { /* stale URL is never exposed */ }
      fail('PHOTO_REPLACED');
    }
    this.#url = next;
    return next;
  }

  imageError(value) {
    if (value !== this.#url) return;
    this.#revoke();
  }

  logout() {
    this.#generation += 1;
    this.#revoke();
  }

  destroy() {
    if (this.#destroyed) return;
    this.#destroyed = true;
    this.#generation += 1;
    this.#revoke();
  }
}
