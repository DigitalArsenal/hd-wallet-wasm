const SafeUint8Array = Uint8Array;
const SafeArrayBuffer = ArrayBuffer;
const TypedArrayPrototype = Object.getPrototypeOf(SafeUint8Array.prototype);
const bufferGetter = Object.getOwnPropertyDescriptor(TypedArrayPrototype, 'buffer').get;
const byteLengthGetter = Object.getOwnPropertyDescriptor(TypedArrayPrototype, 'byteLength').get;
const byteOffsetGetter = Object.getOwnPropertyDescriptor(TypedArrayPrototype, 'byteOffset').get;
const arrayBufferByteLengthGetter = Object.getOwnPropertyDescriptor(SafeArrayBuffer.prototype, 'byteLength').get;

export class WalletRandomError extends Error {
  constructor(code = 'RNG_FAILURE') {
    super(code);
    this.name = 'WalletRandomError';
    this.code = code;
  }
}

function fail() {
  throw new WalletRandomError();
}

function isFreshFullSpanBytes(bytes) {
  if (!(bytes instanceof SafeUint8Array)
      || Object.getPrototypeOf(bytes) !== SafeUint8Array.prototype) return null;
  let buffer;
  let byteLength;
  let byteOffset;
  try {
    buffer = Reflect.apply(bufferGetter, bytes, []);
    byteLength = Reflect.apply(byteLengthGetter, bytes, []);
    byteOffset = Reflect.apply(byteOffsetGetter, bytes, []);
  } catch {
    return null;
  }
  let bufferByteLength;
  try { bufferByteLength = Reflect.apply(arrayBufferByteLengthGetter, buffer, []); } catch { return null; }
  if (Object.getPrototypeOf(buffer) !== SafeArrayBuffer.prototype
      || byteOffset !== 0 || byteLength !== bufferByteLength
      || (byteLength !== 12 && byteLength !== 32)) return null;
  return buffer;
}

export function createRandomFiller({ getRandomValues, observedWrite } = {}) {
  if (typeof getRandomValues !== 'function') {
    return () => fail();
  }
  const consumedViews = new WeakSet();
  const consumedBuffers = new WeakSet();
  return function fillRandom(bytes) {
    const buffer = isFreshFullSpanBytes(bytes);
    if (!buffer || consumedViews.has(bytes) || consumedBuffers.has(buffer)) fail();
    consumedViews.add(bytes);
    consumedBuffers.add(buffer);
    let result;
    try {
      result = getRandomValues(bytes);
    } catch {
      fail();
    }
    if (result !== bytes) fail();
    if (observedWrite !== undefined) {
      if (typeof observedWrite !== 'function') fail();
      let written = false;
      try { written = observedWrite(bytes) === true; } catch { fail(); }
      if (!written) fail();
    }
    return bytes;
  };
}

export function randomBytes(fillRandom, length) {
  if (typeof fillRandom !== 'function' || (length !== 12 && length !== 32)) fail();
  const bytes = new SafeUint8Array(length);
  return fillRandom(bytes);
}
