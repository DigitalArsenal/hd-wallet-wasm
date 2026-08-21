import { createHash, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';

const decoder = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });

export class RelayError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = 'RelayError';
    this.status = status;
    this.code = code;
  }
}

export const ERRORS = Object.freeze({
  conflict: Object.freeze({
    status: 409,
    code: 'CONFLICT',
    message: 'The transaction has already been used.',
  }),
  gone: Object.freeze({
    status: 410,
    code: 'GONE',
    message: 'The transaction is no longer available.',
  }),
  internal: Object.freeze({
    status: 500,
    code: 'INTERNAL_ERROR',
    message: 'The relay could not complete the request.',
  }),
  invalidBinding: Object.freeze({
    status: 400,
    code: 'INVALID_BINDING',
    message: 'The transaction binding is invalid.',
  }),
  malformed: Object.freeze({
    status: 400,
    code: 'MALFORMED_REQUEST',
    message: 'The request is invalid.',
  }),
  notFound: Object.freeze({
    status: 404,
    code: 'NOT_FOUND',
    message: 'The requested relay resource was not found.',
  }),
  payloadTooLarge: Object.freeze({
    status: 413,
    code: 'PAYLOAD_TOO_LARGE',
    message: 'The request body is too large.',
  }),
  rateLimited: Object.freeze({
    status: 429,
    code: 'RATE_LIMITED',
    message: 'Too many relay requests.',
  }),
  unregistered: Object.freeze({
    status: 403,
    code: 'UNREGISTERED_CLIENT',
    message: 'The client binding is not registered.',
  }),
  unsupportedMediaType: Object.freeze({
    status: 415,
    code: 'UNSUPPORTED_MEDIA_TYPE',
    message: 'Content-Type must be application/json.',
  }),
});

export function relayError(error: Readonly<{ status: number; code: string; message: string }>): RelayError {
  return new RelayError(error.status, error.code, error.message);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function validateScalarString(value: string): string {
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    let scalar = first;
    if (first >= 0xd800 && first <= 0xdbff) {
      const second = value.charCodeAt(index + 1);
      if (!(second >= 0xdc00 && second <= 0xdfff)) throw relayError(ERRORS.malformed);
      scalar = 0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00);
      index += 1;
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      throw relayError(ERRORS.malformed);
    }
    if ((scalar & 0xffff) === 0xfffe || (scalar & 0xffff) === 0xffff
      || (scalar >= 0xfdd0 && scalar <= 0xfdef)) {
      throw relayError(ERRORS.malformed);
    }
  }
  return value;
}

export function parseStrictJson(text: string): unknown {
  if (text.length > 0 && text.charCodeAt(0) === 0xfeff) throw relayError(ERRORS.malformed);
  let offset = 0;
  let tokens = 0;

  const skipWhitespace = (): void => {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[offset] ?? '')) offset += 1;
  };

  const parseString = (): string => {
    if (text[offset] !== '"') throw relayError(ERRORS.malformed);
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        try {
          return validateScalarString(JSON.parse(text.slice(start, offset)) as string);
        } catch (error) {
          if (error instanceof RelayError) throw error;
          throw relayError(ERRORS.malformed);
        }
      }
      if (code < 0x20) throw relayError(ERRORS.malformed);
      if (code === 0x5c) {
        offset += 1;
        if (offset >= text.length) throw relayError(ERRORS.malformed);
      }
      offset += 1;
    }
    throw relayError(ERRORS.malformed);
  };

  const parseValue = (depth = 0): unknown => {
    if (depth > 32) throw relayError(ERRORS.malformed);
    tokens += 1;
    if (tokens > 4096) throw relayError(ERRORS.malformed);
    skipWhitespace();
    const character = text[offset];
    if (character === '"') return parseString();
    if (character === '{') {
      offset += 1;
      const result: Record<string, unknown> = Object.create(null) as Record<string, unknown>;
      const names = new Set<string>();
      skipWhitespace();
      if (text[offset] === '}') {
        offset += 1;
        return result;
      }
      while (offset < text.length) {
        skipWhitespace();
        const name = parseString();
        if (names.has(name)) throw relayError(ERRORS.malformed);
        names.add(name);
        skipWhitespace();
        if (text[offset] !== ':') throw relayError(ERRORS.malformed);
        offset += 1;
        result[name] = parseValue(depth + 1);
        skipWhitespace();
        if (text[offset] === '}') {
          offset += 1;
          return result;
        }
        if (text[offset] !== ',') throw relayError(ERRORS.malformed);
        offset += 1;
      }
      throw relayError(ERRORS.malformed);
    }
    if (character === '[') {
      offset += 1;
      const result: unknown[] = [];
      skipWhitespace();
      if (text[offset] === ']') {
        offset += 1;
        return result;
      }
      while (offset < text.length) {
        result.push(parseValue(depth + 1));
        skipWhitespace();
        if (text[offset] === ']') {
          offset += 1;
          return result;
        }
        if (text[offset] !== ',') throw relayError(ERRORS.malformed);
        offset += 1;
      }
      throw relayError(ERRORS.malformed);
    }
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]] as const) {
      if (text.startsWith(literal, offset)) {
        offset += literal.length;
        return value;
      }
    }
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(text.slice(offset));
    if (!match) throw relayError(ERRORS.malformed);
    offset += match[0].length;
    const number = Number(match[0]);
    if (!Number.isFinite(number)) throw relayError(ERRORS.malformed);
    return number;
  };

  skipWhitespace();
  const result = parseValue();
  skipWhitespace();
  if (offset !== text.length) throw relayError(ERRORS.malformed);
  return result;
}

export async function readJsonBody(request: IncomingMessage, maximumBytes: number): Promise<unknown> {
  if (request.headers['content-type'] !== 'application/json') {
    throw relayError(ERRORS.unsupportedMediaType);
  }
  const contentLength = request.headers['content-length'];
  if (contentLength !== undefined) {
    if (!/^(?:0|[1-9]\d*)$/u.test(contentLength)) throw relayError(ERRORS.malformed);
    if (Number(contentLength) > maximumBytes) {
      request.resume();
      throw relayError(ERRORS.payloadTooLarge);
    }
  }
  const chunks: Buffer[] = [];
  let byteLength = 0;
  let oversized = false;
  for await (const part of request) {
    const chunk = Buffer.isBuffer(part) ? part : Buffer.from(part as Uint8Array);
    byteLength += chunk.byteLength;
    if (byteLength > maximumBytes) oversized = true;
    else if (!oversized) chunks.push(chunk);
  }
  if (oversized) throw relayError(ERRORS.payloadTooLarge);
  const bytes = Buffer.concat(chunks, byteLength);
  if (bytes.byteLength >= 3 && bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) {
    throw relayError(ERRORS.malformed);
  }
  let text: string;
  try {
    text = decoder.decode(bytes);
  } catch {
    throw relayError(ERRORS.malformed);
  }
  return parseStrictJson(text);
}

export function exactObject(
  value: unknown,
  fields: readonly string[],
): Record<string, unknown> {
  if (!isRecord(value)) throw relayError(ERRORS.malformed);
  const names = Reflect.ownKeys(value);
  if (names.some((name) => typeof name !== 'string')) throw relayError(ERRORS.malformed);
  const actual = (names as string[]).sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((name, index) => name !== expected[index])) {
    throw relayError(ERRORS.malformed);
  }
  for (const name of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)
        || descriptor.value === undefined) {
      throw relayError(ERRORS.malformed);
    }
  }
  return value;
}

export function jcs(value: unknown): string {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') return JSON.stringify(validateScalarString(value));
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw relayError(ERRORS.malformed);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  if (!isRecord(value)) throw relayError(ERRORS.malformed);
  return `{${Object.keys(value).sort().map((name) => `${JSON.stringify(name)}:${jcs(value[name])}`).join(',')}}`;
}

export function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

export function sha256Base64urlAscii(value: string): string {
  return createHash('sha256').update(value, 'ascii').digest('base64url');
}

export function constantTimeEqual(left: string, right: string): boolean {
  const leftBytes = Buffer.from(left, 'utf8');
  const rightBytes = Buffer.from(right, 'utf8');
  if (leftBytes.byteLength !== rightBytes.byteLength) {
    const padded = Buffer.alloc(leftBytes.byteLength);
    const comparable = rightBytes.subarray(0, padded.byteLength);
    comparable.copy(padded);
    timingSafeEqual(leftBytes, padded);
    return false;
  }
  return timingSafeEqual(leftBytes, rightBytes);
}

export function isLowerHex64(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/u.test(value);
}

export function isBase64url32(value: unknown): value is string {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{43}$/u.test(value)) return false;
  const decoded = Buffer.from(value, 'base64url');
  return decoded.byteLength === 32 && decoded.toString('base64url') === value;
}
