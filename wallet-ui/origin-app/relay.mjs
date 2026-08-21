const TRANSACTION_ID = /^[0-9a-f]{64}$/u;
const RESULT_TOKEN = /^[A-Za-z0-9_-]{43}$/u;
const TRANSACTION_FIELDS = Object.freeze([
  'callbackUri',
  'clientDisplayName',
  'clientId',
  'expiresAt',
  'operation',
  'registryVersion',
  'request',
  'requestOrigin',
  'requestSha256',
  'resultToken',
  'schemaVersion',
  'state',
  'transactionId',
]);
const COMPLETION_FIELDS = Object.freeze(['redirectUri', 'schemaVersion', 'transactionId']);
const MAX_TRANSACTION_RESPONSE_BYTES = 64 * 1024;
const MAX_COMPLETION_RESPONSE_BYTES = 4 * 1024;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

export class WalletRelayError extends Error {
  constructor() {
    super('RELAY_FAILURE');
    this.name = 'WalletRelayError';
    this.code = 'RELAY_FAILURE';
  }
}

function fail() {
  throw new WalletRelayError();
}

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactRecord(value, fields) {
  if (!isRecord(value)) fail();
  let keys;
  try { keys = Reflect.ownKeys(value); } catch { fail(); }
  if (keys.some((key) => typeof key !== 'string')) fail();
  const actual = [...keys].sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length
      || actual.some((field, index) => field !== expected[index])) fail();
  for (const field of actual) {
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(value, field); } catch { fail(); }
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) fail();
  }
  return value;
}

function deepFreezeCopy(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(deepFreezeCopy));
  if (!isRecord(value)) return value;
  const copy = {};
  for (const key of Object.keys(value).sort()) copy[key] = deepFreezeCopy(value[key]);
  return Object.freeze(copy);
}

function parseJsonWithoutDuplicates(text, maximumBytes) {
  if (typeof text !== 'string' || encoder.encode(text).byteLength > maximumBytes
      || text.charCodeAt(0) === 0xfeff) fail();
  let offset = 0;
  let tokens = 0;

  const skipWhitespace = () => {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[offset])) offset += 1;
  };
  const parseString = () => {
    if (text[offset] !== '"') fail();
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        let value;
        try { value = JSON.parse(text.slice(start, offset)); } catch { fail(); }
        for (let index = 0; index < value.length; index += 1) {
          const first = value.charCodeAt(index);
          if (first >= 0xd800 && first <= 0xdbff) {
            const second = value.charCodeAt(index + 1);
            if (!(second >= 0xdc00 && second <= 0xdfff)) fail();
            index += 1;
          } else if (first >= 0xdc00 && first <= 0xdfff) fail();
        }
        return value;
      }
      if (code < 0x20) fail();
      if (code === 0x5c) {
        offset += 1;
        if (offset >= text.length) fail();
      }
      offset += 1;
    }
    fail();
  };
  const parseValue = (depth = 0) => {
    if (depth > 32 || ++tokens > 4096) fail();
    skipWhitespace();
    const character = text[offset];
    if (character === '"') return parseString();
    if (character === '{') {
      offset += 1;
      const output = Object.create(null);
      const names = new Set();
      skipWhitespace();
      if (text[offset] === '}') {
        offset += 1;
        return output;
      }
      while (offset < text.length) {
        skipWhitespace();
        const name = parseString();
        if (names.has(name)) fail();
        names.add(name);
        skipWhitespace();
        if (text[offset] !== ':') fail();
        offset += 1;
        output[name] = parseValue(depth + 1);
        skipWhitespace();
        if (text[offset] === '}') {
          offset += 1;
          return output;
        }
        if (text[offset] !== ',') fail();
        offset += 1;
      }
      fail();
    }
    if (character === '[') {
      offset += 1;
      const output = [];
      skipWhitespace();
      if (text[offset] === ']') {
        offset += 1;
        return output;
      }
      while (offset < text.length) {
        output.push(parseValue(depth + 1));
        skipWhitespace();
        if (text[offset] === ']') {
          offset += 1;
          return output;
        }
        if (text[offset] !== ',') fail();
        offset += 1;
      }
      fail();
    }
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(literal, offset)) {
        offset += literal.length;
        return value;
      }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(text.slice(offset));
    if (!number) fail();
    offset += number[0].length;
    const value = Number(number[0]);
    if (!Number.isFinite(value)) fail();
    return value;
  };

  skipWhitespace();
  const value = parseValue();
  skipWhitespace();
  if (offset !== text.length) fail();
  return value;
}

function suppressSettlement(value) {
  try { Promise.resolve(value).catch(() => {}); } catch { /* best-effort cleanup only */ }
}

function cancelBody(response, reader = null) {
  try {
    const cancel = reader?.cancel;
    if (typeof cancel === 'function') suppressSettlement(Reflect.apply(cancel, reader, []));
  } catch { /* best-effort bounded response teardown */ }
  if (!reader) {
    try {
      const body = response?.body;
      const cancel = body?.cancel;
      if (typeof cancel === 'function') suppressSettlement(Reflect.apply(cancel, body, []));
    } catch { /* best-effort bounded response teardown */ }
  }
}

function raceAbort(value, signal, onLateValue = null) {
  let promise;
  try { promise = Promise.resolve(value); } catch { return Promise.reject(new WalletRelayError()); }
  if (!signal) return promise;
  return new Promise((resolve, reject) => {
    let settled = false;
    const remove = () => {
      try { signal.removeEventListener?.('abort', onAbort); } catch { /* settled locally */ }
    };
    const settle = (callback, result) => {
      if (settled) return false;
      settled = true;
      remove();
      callback(result);
      return true;
    };
    const onAbort = () => settle(reject, new WalletRelayError());
    try {
      signal.addEventListener?.('abort', onAbort, { once: true });
      if (signal.aborted === true) onAbort();
    } catch {
      onAbort();
    }
    promise.then(
      (result) => {
        if (!settle(resolve, result)) {
          try { onLateValue?.(result); } catch { /* late values stay revoked */ }
        }
      },
      (error) => { settle(reject, error); },
    );
  });
}

async function readExactJsonResponse(response, expectedStatus, maximumBytes, signal) {
  let reader = null;
  try {
    if (!response || response.status !== expectedStatus || response.redirected === true
        || response.headers?.get?.('cache-control')?.trim().toLowerCase() !== 'no-store'
        || response.headers?.get?.('content-type')?.trim().toLowerCase()
          !== 'application/json; charset=utf-8'
        || typeof response.body?.getReader !== 'function') fail();
    reader = response.body.getReader();
    if (!reader || typeof reader.read !== 'function' || signal?.aborted === true) fail();
    const chunks = [];
    let total = 0;
    while (true) {
      if (signal?.aborted === true) fail();
      const { done, value } = await raceAbort(reader.read(), signal);
      if (signal?.aborted === true) fail();
      if (done) break;
      if (!(value instanceof Uint8Array)) fail();
      total += value.byteLength;
      if (total > maximumBytes) fail();
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let destination = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, destination);
      destination += chunk.byteLength;
    }
    return parseJsonWithoutDuplicates(decoder.decode(bytes), maximumBytes);
  } catch (error) {
    cancelBody(response, reader);
    if (error instanceof WalletRelayError) throw error;
    fail();
  } finally {
    try { reader?.releaseLock?.(); } catch { /* response is already rejected or consumed */ }
  }
}

function validateTransactionResponse(value, expectedTransactionId) {
  exactRecord(value, TRANSACTION_FIELDS);
  if (value.schemaVersion !== 1 || value.transactionId !== expectedTransactionId
      || !TRANSACTION_ID.test(value.transactionId) || !TRANSACTION_ID.test(value.state)
      || !TRANSACTION_ID.test(value.requestSha256) || !RESULT_TOKEN.test(value.resultToken)
      || typeof value.callbackUri !== 'string' || typeof value.clientDisplayName !== 'string'
      || typeof value.clientId !== 'string' || typeof value.expiresAt !== 'string'
      || typeof value.operation !== 'string' || typeof value.registryVersion !== 'string'
      || typeof value.requestOrigin !== 'string') fail();
  return deepFreezeCopy(value);
}

export function validateWalletRelayCompletion(transaction, value) {
  exactRecord(value, COMPLETION_FIELDS);
  if (value.schemaVersion !== 1 || value.transactionId !== transaction.transactionId
      || typeof value.redirectUri !== 'string') fail();
  const prefix = `${transaction.callbackUri}#code=`;
  const suffix = `&state=${transaction.state}`;
  if (!value.redirectUri.startsWith(prefix) || !value.redirectUri.endsWith(suffix)) fail();
  const code = value.redirectUri.slice(prefix.length, value.redirectUri.length - suffix.length);
  if (!TRANSACTION_ID.test(code)
      || value.redirectUri !== `${prefix}${code}${suffix}`) fail();
  return Object.freeze({
    redirectUri: value.redirectUri,
    schemaVersion: 1,
    transactionId: value.transactionId,
  });
}

function requestOptions(method, signal, body = undefined) {
  const options = {
    cache: 'no-store',
    credentials: 'omit',
    headers: method === 'POST'
      ? { Accept: 'application/json', 'Content-Type': 'application/json' }
      : { Accept: 'application/json' },
    method,
    mode: 'same-origin',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal,
  };
  if (body !== undefined) options.body = JSON.stringify(body);
  return options;
}

export function createSameOriginWalletRelay({ fetch, location }) {
  if (typeof fetch !== 'function' || typeof location?.replace !== 'function') fail();
  const approvedRedirects = new Set();
  const request = async (path, options, expectedStatus, maximumBytes) => {
    let response;
    try {
      response = await raceAbort(fetch(path, options), options.signal, (late) => cancelBody(late));
    } catch { fail(); }
    return readExactJsonResponse(response, expectedStatus, maximumBytes, options.signal);
  };
  return Object.freeze({
    async fetchTransaction(transactionId, { signal } = {}) {
      if (typeof transactionId !== 'string' || !TRANSACTION_ID.test(transactionId)) fail();
      const value = await request(
        `/relay/v1/transactions/${transactionId}`,
        requestOptions('GET', signal),
        200,
        MAX_TRANSACTION_RESPONSE_BYTES,
      );
      return validateTransactionResponse(value, transactionId);
    },
    async publishResult(transaction, result, { signal } = {}) {
      const validated = validateTransactionResponse(transaction, transaction?.transactionId);
      const value = await request(
        `/relay/v1/transactions/${validated.transactionId}/result`,
        requestOptions('POST', signal, {
          result,
          resultToken: validated.resultToken,
          schemaVersion: 1,
          transactionId: validated.transactionId,
        }),
        201,
        MAX_COMPLETION_RESPONSE_BYTES,
      );
      const completion = validateWalletRelayCompletion(validated, value);
      approvedRedirects.clear();
      approvedRedirects.add(completion.redirectUri);
      return completion;
    },
    navigate(redirectUri) {
      if (typeof redirectUri !== 'string' || !approvedRedirects.delete(redirectUri)) fail();
      try { Reflect.apply(location.replace, location, [redirectUri]); } catch { fail(); }
    },
    revokeNow() {
      approvedRedirects.clear();
    },
    async destroy() {
      approvedRedirects.clear();
    },
  });
}
