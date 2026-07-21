const WALLET_ORIGIN = 'https://wallet.spacedatanetwork.org';
const CALLBACK_PREFIX = 'sdn.wallet.callback.v1:';
const LOWER_HEX_32 = /^[0-9a-f]{64}$/u;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/u;
const RFC3339_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const CALLBACK_POLL_MS = 250;
const REGISTRATION_WINDOW_MS = 30_000;
const MAX_TRANSACTION_MS = 300_000;
const MAX_CONNECTION_MS = 900_000;
const MAX_CALLBACK_MS = 120_000;
const MAX_RETIRED_CLEANUPS = 8;
const MAX_REGISTRATION_RESPONSE_BYTES = 4_096;
const MAX_REDEEM_RESPONSE_BYTES = 70 * 1_024;

export const WALLET_CLIENT_ERRORS = Object.freeze({
  CALLBACK_ERROR: 'The wallet return could not be verified. Try again.',
  CRYPTO_UNAVAILABLE: 'Secure browser cryptography is unavailable.',
  DESTROYED: 'This wallet client has been destroyed.',
  DISCONNECTED: 'The wallet was disconnected.',
  EXPIRED: 'The wallet connection expired.',
  INVALID_CLIENT: 'This wallet client is not registered.',
  INVALID_REQUEST: 'The wallet request is invalid.',
  RELAY_ERROR: 'The wallet service could not complete the request. Try again.',
  REPLACED: 'A newer wallet request replaced this one.',
  WALLET_NOT_COMPLETED: 'The wallet did not complete. Check popup settings and try again.',
});

const textEncoder = new TextEncoder();
const fatalTextDecoder = new TextDecoder('utf-8', { fatal: true });

class PublicWalletError extends Error {
  constructor(code) {
    super(WALLET_CLIENT_ERRORS[code]);
    this.name = 'WalletClientError';
    Object.defineProperty(this, 'code', {
      configurable: false,
      enumerable: true,
      value: code,
      writable: false,
    });
  }
}

export function walletClientError(code) {
  if (!Object.hasOwn(WALLET_CLIENT_ERRORS, code)) return new PublicWalletError('RELAY_ERROR');
  return new PublicWalletError(code);
}

function isObjectRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function parseJsonWithoutDuplicates(text, maximumBytes) {
  if (typeof text !== 'string' || textEncoder.encode(text).byteLength > maximumBytes
      || text.charCodeAt(0) === 0xfeff) {
    throw walletClientError('RELAY_ERROR');
  }
  let offset = 0;
  let tokens = 0;

  const skipWhitespace = () => {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[offset])) offset += 1;
  };

  const parseString = () => {
    if (text[offset] !== '"') throw walletClientError('RELAY_ERROR');
    const start = offset;
    offset += 1;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        let value;
        try {
          value = JSON.parse(text.slice(start, offset));
        } catch {
          throw walletClientError('RELAY_ERROR');
        }
        for (let index = 0; index < value.length; index += 1) {
          const first = value.charCodeAt(index);
          if (first >= 0xd800 && first <= 0xdbff) {
            const second = value.charCodeAt(index + 1);
            if (!(second >= 0xdc00 && second <= 0xdfff)) throw walletClientError('RELAY_ERROR');
            index += 1;
          } else if (first >= 0xdc00 && first <= 0xdfff) {
            throw walletClientError('RELAY_ERROR');
          }
        }
        return value;
      }
      if (code < 0x20) throw walletClientError('RELAY_ERROR');
      if (code === 0x5c) {
        offset += 1;
        if (offset >= text.length) throw walletClientError('RELAY_ERROR');
      }
      offset += 1;
    }
    throw walletClientError('RELAY_ERROR');
  };

  const parseValue = (depth = 0) => {
    if (depth > 32 || ++tokens > 4096) throw walletClientError('RELAY_ERROR');
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
        if (names.has(name)) throw walletClientError('RELAY_ERROR');
        names.add(name);
        skipWhitespace();
        if (text[offset] !== ':') throw walletClientError('RELAY_ERROR');
        offset += 1;
        output[name] = parseValue(depth + 1);
        skipWhitespace();
        if (text[offset] === '}') {
          offset += 1;
          return output;
        }
        if (text[offset] !== ',') throw walletClientError('RELAY_ERROR');
        offset += 1;
      }
      throw walletClientError('RELAY_ERROR');
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
        if (text[offset] !== ',') throw walletClientError('RELAY_ERROR');
        offset += 1;
      }
      throw walletClientError('RELAY_ERROR');
    }
    for (const [literal, value] of [['true', true], ['false', false], ['null', null]]) {
      if (text.startsWith(literal, offset)) {
        offset += literal.length;
        return value;
      }
    }
    const number = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/u.exec(text.slice(offset));
    if (!number) throw walletClientError('RELAY_ERROR');
    offset += number[0].length;
    const value = Number(number[0]);
    if (!Number.isFinite(value)) throw walletClientError('RELAY_ERROR');
    return value;
  };

  skipWhitespace();
  const value = parseValue();
  skipWhitespace();
  if (offset !== text.length) throw walletClientError('RELAY_ERROR');
  return value;
}

function exactObject(value, fields, errorCode = 'RELAY_ERROR') {
  if (!isObjectRecord(value) || Object.getOwnPropertySymbols(value).length !== 0) {
    throw walletClientError(errorCode);
  }
  const names = Object.getOwnPropertyNames(value).sort();
  const expected = [...fields].sort();
  if (names.length !== expected.length || names.some((name, index) => name !== expected[index])) {
    throw walletClientError(errorCode);
  }
  for (const name of names) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      throw walletClientError(errorCode);
    }
  }
  return value;
}

function exactTimestamp(value, code = 'RELAY_ERROR') {
  if (typeof value !== 'string' || !RFC3339_MILLISECONDS.test(value)) {
    throw walletClientError(code);
  }
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) {
    throw walletClientError(code);
  }
  return milliseconds;
}

function cloneFrozen(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(cloneFrozen));
  if (value && typeof value === 'object') {
    return Object.freeze(Object.fromEntries(
      Object.entries(value).map(([name, child]) => [name, cloneFrozen(child)]),
    ));
  }
  return value;
}

function snapshotFrom(state) {
  const output = {
    identity: state.identity === null ? null : cloneFrozen(state.identity),
    status: state.status,
  };
  if (state.connectionExpiresAt !== undefined) output.connectionExpiresAt = state.connectionExpiresAt;
  if (state.error !== undefined) output.error = cloneFrozen(state.error);
  return cloneFrozen(output);
}

function publicErrorRecord(error) {
  return Object.freeze({ code: error.code, message: error.message });
}

function base64url(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  let accumulator = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 6) {
      bits -= 6;
      output += alphabet[(accumulator >>> bits) & 63];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits !== 0) output += alphabet[(accumulator << (6 - bits)) & 63];
  return output;
}

function lowercaseHex(bytes) {
  let output = '';
  for (const byte of bytes) output += byte.toString(16).padStart(2, '0');
  return output;
}

function secureBytes(cryptoObject, getRandomValues) {
  const bytes = new Uint8Array(32);
  Reflect.apply(getRandomValues, cryptoObject, [bytes]);
  return bytes;
}

function responseHasJsonMediaType(response) {
  const value = response?.headers?.get?.('content-type');
  return typeof value === 'string'
    && /^application\/json(?:\s*;\s*charset=utf-8)?$/iu.test(value.trim());
}

function suppressSettlement(value) {
  try {
    Promise.resolve(value).catch(() => {});
  } catch {
    // Best-effort transport cleanup must never delay public settlement.
  }
}

function bestEffortBodyCancel(response) {
  try {
    const body = response?.body;
    const cancel = body?.cancel;
    if (typeof cancel === 'function') suppressSettlement(Reflect.apply(cancel, body, []));
  } catch {
    // A hostile or already-locked body cannot block local cleanup.
  }
}

function bestEffortReaderCancel(reader) {
  try {
    const cancel = reader?.cancel;
    if (typeof cancel === 'function') suppressSettlement(Reflect.apply(cancel, reader, []));
  } catch {
    // Reader cancellation is deliberately non-blocking.
  }
}

function bestEffortReleaseReader(reader) {
  try {
    const releaseLock = reader?.releaseLock;
    if (typeof releaseLock === 'function') Reflect.apply(releaseLock, reader, []);
  } catch {
    // The controller abort below remains the authoritative transport teardown.
  }
}

function abortResponse(controller, response, reader = null) {
  try {
    controller.abort();
  } catch {
    // Continue through every independent cleanup attempt.
  }
  if (reader) bestEffortReaderCancel(reader);
  bestEffortBodyCancel(response);
}

function raceAbortSignal(value, signal, onLateValue = null) {
  let transport;
  try {
    transport = Promise.resolve(value);
  } catch (error) {
    return Promise.reject(error);
  }

  return new Promise((resolve, reject) => {
    let settled = false;
    const removeAbortListener = () => {
      try {
        signal.removeEventListener('abort', onAbort);
      } catch {
        // Native AbortSignal removal is best effort after settlement.
      }
    };
    const finish = (callback, result) => {
      if (settled) return false;
      settled = true;
      removeAbortListener();
      callback(result);
      return true;
    };
    const onAbort = () => {
      finish(reject, walletClientError('RELAY_ERROR'));
    };

    try {
      signal.addEventListener('abort', onAbort, { once: true });
      if (signal.aborted) onAbort();
    } catch {
      onAbort();
    }

    transport.then(
      (result) => {
        if (settled) {
          try {
            onLateValue?.(result);
          } catch {
            // A late transport value is never allowed back into client state.
          }
          return;
        }
        finish(resolve, result);
      },
      (error) => {
        if (!settled) finish(reject, error);
      },
    );
  });
}

async function readResponseText(response, maximumBytes, controller) {
  let reader = null;
  const chunks = [];
  let total = 0;
  try {
    if (!responseHasJsonMediaType(response)) throw walletClientError('RELAY_ERROR');
    if (typeof response?.body?.getReader !== 'function') {
      throw walletClientError('RELAY_ERROR');
    }
    reader = response.body.getReader();
    while (true) {
      const read = reader.read();
      const { done, value } = await raceAbortSignal(read, controller.signal);
      if (done) break;
      if (!(value instanceof Uint8Array)) throw walletClientError('RELAY_ERROR');
      total += value.byteLength;
      if (total > maximumBytes) {
        throw walletClientError('RELAY_ERROR');
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return fatalTextDecoder.decode(bytes);
  } catch {
    try {
      controller.abort();
    } catch {
      // Continue with independent reader cancellation.
    }
    if (reader) bestEffortReaderCancel(reader);
    throw walletClientError('RELAY_ERROR');
  } finally {
    if (reader) bestEffortReleaseReader(reader);
  }
}

function requestOptions(body, signal) {
  return {
    body: JSON.stringify(body),
    cache: 'no-store',
    credentials: 'omit',
    headers: { 'Content-Type': 'application/json' },
    method: 'POST',
    mode: 'cors',
    redirect: 'error',
    referrerPolicy: 'no-referrer',
    signal,
  };
}

function callbackRecord(text, expectedState, now) {
  let value;
  try {
    value = parseJsonWithoutDuplicates(text, 2_048);
    exactObject(value, ['code', 'expiresAt', 'schemaVersion', 'state'], 'CALLBACK_ERROR');
  } catch {
    throw walletClientError('CALLBACK_ERROR');
  }
  if (value.schemaVersion !== 1 || value.state !== expectedState
      || !LOWER_HEX_32.test(value.code)) {
    throw walletClientError('CALLBACK_ERROR');
  }
  const expiresAt = exactTimestamp(value.expiresAt, 'CALLBACK_ERROR');
  if (expiresAt <= now || expiresAt - now > MAX_CALLBACK_MS) {
    throw walletClientError('CALLBACK_ERROR');
  }
  return { code: value.code, expiresAt, state: value.state };
}

function makeDeferred() {
  let resolve;
  const promise = new Promise((resolvePromise) => {
    resolve = resolvePromise;
  });
  return { promise, resolve };
}

function makeOperation() {
  let reject;
  let resolve;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    reject = rejectPromise;
    resolve = resolvePromise;
  });
  return { promise, reject, resolve };
}

function browserDependencies() {
  const windowObject = globalThis.window;
  let storage = null;
  if (windowObject) {
    try {
      storage = windowObject.localStorage ?? null;
    } catch {
      storage = null;
    }
  }
  return Object.freeze({
    AbortController: globalThis.AbortController,
    clearInterval: globalThis.clearInterval.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    crypto: globalThis.crypto,
    fetch: typeof globalThis.fetch === 'function' ? globalThis.fetch.bind(globalThis) : undefined,
    now: () => Date.now(),
    setInterval: globalThis.setInterval.bind(globalThis),
    setTimeout: globalThis.setTimeout.bind(globalThis),
    storage,
    window: windowObject,
  });
}

class InternalWalletClient {
  #adapters;
  #clientId;
  #connection = null;
  #connectionTimer = null;
  #controllers = new Set();
  #dependencies;
  #destroyPromise = null;
  #destroyed = false;
  #entryEpoch = 0;
  #generation = 0;
  #listeners = new Set();
  #notificationQueue = [];
  #pending = null;
  #publishing = false;
  #retired = new Set();
  #state = Object.freeze({ identity: null, status: 'dormant' });
  #storage;
  #storageListener;
  #timers = new Set();
  #window;

  constructor({ adapters, clientId, dependencies }) {
    this.#adapters = adapters;
    this.#clientId = clientId;
    this.#dependencies = dependencies ?? browserDependencies();
    this.#window = this.#dependencies.window;
    this.#storage = this.#dependencies.storage;
    this.#removeExpiredCallbackRecords();
    this.#storageListener = (event) => {
      const pending = this.#pending;
      if (!pending || !this.#isActive(pending)) return;
      const key = `${CALLBACK_PREFIX}${pending.state}`;
      if (event?.key === key) void this.#consumeCallback(pending, true);
    };
    this.#window?.addEventListener?.('storage', this.#storageListener);
  }

  getSnapshot() {
    this.#expireConnectionIfNeeded();
    return snapshotFrom(this.#state);
  }

  subscribe(listener) {
    if (typeof listener !== 'function') throw walletClientError('INVALID_REQUEST');
    if (this.#destroyed) throw walletClientError('DESTROYED');
    this.#listeners.add(listener);
    try {
      listener(this.getSnapshot());
    } catch {
      // A failed presenter cannot suppress other presenters or client state.
    }
    let subscribed = true;
    return () => {
      if (!subscribed) return;
      subscribed = false;
      this.#listeners.delete(listener);
    };
  }

  execute(adapterName, input) {
    if (this.#destroyed) return Promise.reject(walletClientError('DESTROYED'));
    const observedEntryEpoch = this.#entryEpoch;
    const adapter = this.#adapters[adapterName];
    if (!adapter) return Promise.reject(walletClientError('INVALID_REQUEST'));
    let request;
    try {
      request = adapter.buildRequest(input);
    } catch {
      const entryFailure = this.#entryFailure(observedEntryEpoch);
      if (entryFailure) return Promise.reject(entryFailure);
      return Promise.reject(walletClientError('INVALID_REQUEST'));
    }
    let entryFailure = this.#entryFailure(observedEntryEpoch);
    if (entryFailure) return Promise.reject(entryFailure);
    const entryEpoch = ++this.#entryEpoch;

    this.#expireConnectionIfNeeded();
    entryFailure = this.#entryFailure(entryEpoch);
    if (entryFailure) return Promise.reject(entryFailure);
    const now = this.#now();
    entryFailure = this.#entryFailure(entryEpoch);
    if (entryFailure) return Promise.reject(entryFailure);
    const priorConnection = this.#connection && this.#connection.expiresAtMs > now
      ? this.#connection
      : null;
    entryFailure = this.#entryFailure(entryEpoch);
    if (entryFailure) return Promise.reject(entryFailure);
    const previous = this.#pending;
    let transactionId;
    let state;
    let verifier;
    try {
      const cryptoObject = this.#dependencies.crypto;
      const getRandomValues = cryptoObject?.getRandomValues;
      const digest = cryptoObject?.subtle?.digest;
      const open = this.#window?.open;
      entryFailure = this.#entryFailure(entryEpoch);
      if (entryFailure) throw entryFailure;
      if (typeof getRandomValues !== 'function' || typeof digest !== 'function'
          || typeof open !== 'function') {
        throw walletClientError('CRYPTO_UNAVAILABLE');
      }
      transactionId = lowercaseHex(secureBytes(cryptoObject, getRandomValues));
      entryFailure = this.#entryFailure(entryEpoch);
      if (entryFailure) throw entryFailure;
      state = lowercaseHex(secureBytes(cryptoObject, getRandomValues));
      entryFailure = this.#entryFailure(entryEpoch);
      if (entryFailure) throw entryFailure;
      verifier = base64url(secureBytes(cryptoObject, getRandomValues));
      entryFailure = this.#entryFailure(entryEpoch);
      if (entryFailure) throw entryFailure;
      if (!LOWER_HEX_32.test(transactionId) || !LOWER_HEX_32.test(state)
          || !BASE64URL_32.test(verifier)) {
        throw walletClientError('CRYPTO_UNAVAILABLE');
      }
      // The HTML Standard returns null for noopener even on success. Deliberately discard it.
      Reflect.apply(open, this.#window, [
        `${WALLET_ORIGIN}/transaction/${transactionId}`,
        '_blank',
        'noopener',
      ]);
      entryFailure = this.#entryFailure(entryEpoch);
      if (entryFailure) throw entryFailure;
    } catch (error) {
      entryFailure = this.#entryFailure(entryEpoch);
      if (entryFailure) return Promise.reject(entryFailure);
      let safe;
      try {
        safe = error instanceof PublicWalletError
          ? error
          : walletClientError('CRYPTO_UNAVAILABLE');
      } catch {
        safe = walletClientError('CRYPTO_UNAVAILABLE');
      }
      if (previous) {
        this.#retire(previous, 'REPLACED', false);
        entryFailure = this.#entryFailure(entryEpoch);
        if (entryFailure) return Promise.reject(entryFailure);
      }
      this.#publishFailure(null, safe, priorConnection, adapter.kind);
      return Promise.reject(safe);
    }

    if (previous) {
      this.#retire(previous, 'REPLACED', false);
      entryFailure = this.#entryFailure(entryEpoch);
      if (entryFailure) return Promise.reject(entryFailure);
    }

    const operation = makeOperation();
    const cleanup = makeDeferred();
    const pending = {
      active: true,
      adapter,
      callbackBusy: false,
      challenge: null,
      cleanup,
      cleanupFinished: false,
      cleanupStarted: false,
      controllers: new Set(),
      expiryTimer: null,
      generation: ++this.#generation,
      operationTimer: null,
      phase: 'hashing',
      pollTimer: null,
      priorConnection,
      promise: operation.promise,
      registrationDeadlineMs: now + REGISTRATION_WINDOW_MS,
      registrationOutcome: 'none',
      reject: operation.reject,
      request,
      resolve: operation.resolve,
      retryResolve: null,
      retryTimer: null,
      state,
      transactionExpiresAtMs: null,
      transactionId,
      verifier,
    };
    this.#pending = pending;
    this.#publish({
      ...(priorConnection ? {
        connectionExpiresAt: priorConnection.expiresAt,
        identity: priorConnection.identity,
      } : { identity: null }),
      status: 'opening',
    });
    void this.#register(pending);
    return operation.promise;
  }

  async disconnect() {
    if (this.#destroyed) throw walletClientError('DESTROYED');
    const entryEpoch = ++this.#entryEpoch;
    this.#clearConnection();
    const pending = this.#pending;
    let cleanup = Promise.resolve();
    if (pending) cleanup = this.#retire(pending, 'DISCONNECTED', false);
    let entryFailure = this.#entryFailure(entryEpoch);
    if (entryFailure) {
      await cleanup;
      throw entryFailure;
    }
    this.#publish({ identity: null, status: 'dormant' });
    await cleanup;
    entryFailure = this.#entryFailure(entryEpoch);
    if (entryFailure) throw entryFailure;
  }

  destroy() {
    if (this.#destroyPromise) return this.#destroyPromise;
    const destruction = makeOperation();
    this.#destroyPromise = destruction.promise;
    this.#entryEpoch += 1;
    try {
      this.#destroyNow();
      destruction.resolve();
    } catch {
      destruction.reject(walletClientError('RELAY_ERROR'));
    }
    return this.#destroyPromise;
  }

  #destroyNow() {
    this.#destroyed = true;
    this.#generation += 1;
    this.#clearConnection();
    const current = this.#pending;
    if (current) {
      current.active = false;
      this.#pending = null;
      this.#clearOperationTimers(current);
      current.reject(walletClientError('DESTROYED'));
      if (current.challenge && current.verifier) void this.#cancelOnce(current);
    }
    for (const retired of this.#retired) {
      if (retired.challenge && retired.verifier) void this.#cancelOnce(retired);
    }
    for (const controller of this.#controllers) controller.abort();
    this.#controllers.clear();
    for (const timer of this.#timers) {
      this.#dependencies.clearTimeout(timer);
      this.#dependencies.clearInterval(timer);
    }
    this.#timers.clear();
    this.#window?.removeEventListener?.('storage', this.#storageListener);
    this.#listeners.clear();
    if (current) this.#finishCleanup(current);
    for (const retired of [...this.#retired]) this.#finishCleanup(retired);
    this.#publish({
      error: publicErrorRecord(walletClientError('DESTROYED')),
      identity: null,
      status: 'error',
    });
  }

  async #register(pending) {
    if (!this.#isActive(pending) || pending.cleanupFinished) return;
    try {
      pending.operationTimer = this.#setTimer(() => {
        if (pending.cleanupFinished) return;
        if (pending.phase === 'hashing') {
          if (this.#isActive(pending)) {
            this.#failActive(pending, 'CRYPTO_UNAVAILABLE', false);
          }
          return;
        }
        if (pending.phase === 'registering') {
          for (const controller of pending.controllers) controller.abort();
        }
      }, Math.max(0, pending.registrationDeadlineMs - this.#now()));
      const digest = await this.#dependencies.crypto.subtle.digest(
        'SHA-256',
        textEncoder.encode(pending.verifier),
      );
      const challenge = base64url(new Uint8Array(digest));
      if (!BASE64URL_32.test(challenge)) throw walletClientError('CRYPTO_UNAVAILABLE');
      if (!this.#isActive(pending)) {
        pending.registrationOutcome = 'not-started';
        this.#finishCleanup(pending);
        return;
      }
      pending.challenge = challenge;

      pending.phase = 'registering';
      const controller = this.#newController(pending);
      let expiresAtMs;
      let response = null;
      try {
        try {
          const transport = this.#dependencies.fetch(
            `${WALLET_ORIGIN}/relay/v1/transactions`,
            requestOptions({
              clientId: this.#clientId,
              codeChallenge: pending.challenge,
              codeChallengeMethod: 'S256',
              operation: pending.adapter.operation,
              request: pending.request,
              schemaVersion: 1,
              state: pending.state,
              transactionId: pending.transactionId,
            }, controller.signal),
          );
          response = await raceAbortSignal(
            transport,
            controller.signal,
            bestEffortBodyCancel,
          );
        } catch {
          pending.registrationOutcome = 'ambiguous';
          if (pending.active) this.#failActive(pending, 'RELAY_ERROR');
          else void this.#ensureCleanup(pending);
          return;
        }

        pending.registrationOutcome = 'ambiguous';

        let status;
        try {
          status = response.status;
        } catch {
          abortResponse(controller, response);
          if (pending.active) this.#failActive(pending, 'RELAY_ERROR');
          else void this.#ensureCleanup(pending);
          return;
        }
        if (status !== 201) {
          pending.registrationOutcome = 'definitive-failure';
          abortResponse(controller, response);
          if (pending.active) this.#failActive(pending, 'RELAY_ERROR', false);
          else this.#finishCleanup(pending);
          return;
        }

        try {
          const text = await readResponseText(
            response,
            MAX_REGISTRATION_RESPONSE_BYTES,
            controller,
          );
          const value = exactObject(
            parseJsonWithoutDuplicates(text, MAX_REGISTRATION_RESPONSE_BYTES),
            ['expiresAt', 'schemaVersion', 'transactionId'],
          );
          if (value.schemaVersion !== 1 || value.transactionId !== pending.transactionId) {
            throw walletClientError('RELAY_ERROR');
          }
          expiresAtMs = exactTimestamp(value.expiresAt);
          const now = this.#now();
          if (expiresAtMs <= now || expiresAtMs - now > MAX_TRANSACTION_MS) {
            throw walletClientError('RELAY_ERROR');
          }
        } catch {
          pending.registrationOutcome = 'ambiguous';
          abortResponse(controller, response);
          if (pending.active) this.#failActive(pending, 'RELAY_ERROR');
          else void this.#ensureCleanup(pending);
          return;
        }
      } finally {
        try {
          controller.abort();
        } catch {
          // Public settlement never depends on transport abort cooperation.
        }
        this.#releaseController(pending, controller);
        this.#clearTimer(pending.operationTimer);
        pending.operationTimer = null;
      }

      pending.transactionExpiresAtMs = expiresAtMs;
      pending.registrationOutcome = 'registered';
      if (!this.#isActive(pending)) {
        void this.#ensureCleanup(pending);
        return;
      }
      pending.phase = 'waiting-callback';
      pending.expiryTimer = this.#setTimer(() => {
        if (this.#isActive(pending)) this.#failActive(pending, 'WALLET_NOT_COMPLETED');
      }, Math.max(0, pending.transactionExpiresAtMs - this.#now()));
      pending.pollTimer = this.#setInterval(() => {
        void this.#consumeCallback(pending, false);
      }, CALLBACK_POLL_MS);
      await this.#consumeCallback(pending, false);
    } catch (error) {
      if (!pending.active) {
        if (pending.registrationOutcome === 'ambiguous'
            || pending.registrationOutcome === 'registered') {
          void this.#ensureCleanup(pending);
        } else {
          this.#finishCleanup(pending);
        }
        return;
      }
      const code = error instanceof PublicWalletError
        ? error.code
        : pending.phase === 'hashing' ? 'CRYPTO_UNAVAILABLE' : 'RELAY_ERROR';
      this.#failActive(pending, code, pending.registrationOutcome !== 'none');
    }
  }

  async #consumeCallback(pending, evidence) {
    if (!this.#isActive(pending) || pending.phase !== 'waiting-callback'
        || pending.callbackBusy || !this.#storage) return;
    const key = `${CALLBACK_PREFIX}${pending.state}`;
    let text;
    try {
      text = this.#storage.getItem(key);
    } catch {
      if (evidence) this.#failActive(pending, 'CALLBACK_ERROR');
      return;
    }
    if (text === null) return;
    pending.callbackBusy = true;
    let record;
    try {
      record = callbackRecord(text, pending.state, this.#now());
      this.#storage.removeItem(key);
    } catch {
      try {
        this.#storage.removeItem(key);
      } catch {
        // A failed removal still fails closed and never redeems.
      }
      this.#failActive(pending, 'CALLBACK_ERROR');
      return;
    }
    if (!this.#isActive(pending)) return;
    pending.phase = 'redeeming';
    this.#clearTimer(pending.pollTimer, true);
    pending.pollTimer = null;

    const controller = this.#newController(pending);
    let response = null;
    try {
      const transport = this.#dependencies.fetch(
        `${WALLET_ORIGIN}/relay/v1/codes/redeem`,
        requestOptions({
          code: record.code,
          codeVerifier: pending.verifier,
          schemaVersion: 1,
          state: pending.state,
          transactionId: pending.transactionId,
        }, controller.signal),
      );
      response = await raceAbortSignal(
        transport,
        controller.signal,
        bestEffortBodyCancel,
      );
      if (response.status !== 200) throw walletClientError('RELAY_ERROR');
      const textResponse = await readResponseText(
        response,
        MAX_REDEEM_RESPONSE_BYTES,
        controller,
      );
      const value = exactObject(
        parseJsonWithoutDuplicates(textResponse, MAX_REDEEM_RESPONSE_BYTES),
        ['result', 'schemaVersion', 'transactionId'],
      );
      if (value.schemaVersion !== 1 || value.transactionId !== pending.transactionId) {
        throw walletClientError('RELAY_ERROR');
      }
      let result;
      try {
        result = pending.adapter.parseResult(value.result);
      } catch {
        throw walletClientError('RELAY_ERROR');
      }
      if (!this.#isActive(pending)) return;
      this.#complete(pending, result);
    } catch (error) {
      if (response) abortResponse(controller, response);
      if (!this.#isActive(pending)) return;
      const code = error instanceof PublicWalletError ? error.code : 'RELAY_ERROR';
      this.#failActive(pending, code);
    } finally {
      try {
        controller.abort();
      } catch {
        // Public settlement never depends on transport abort cooperation.
      }
      this.#releaseController(pending, controller);
    }
  }

  #complete(pending, result) {
    if (!this.#isActive(pending)) return;
    let connection = null;
    if (pending.adapter.kind === 'connect'
        || (pending.adapter.kind === 'account' && result.event === 'connected')) {
      connection = this.#prepareConnection(result);
    }
    pending.active = false;
    this.#pending = null;
    this.#clearOperationTimers(pending);
    let resolution = result;
    if (pending.adapter.kind === 'connect') {
      this.#installConnection(connection);
      resolution = cloneFrozen(result.identity);
    } else if (pending.adapter.kind === 'account') {
      if (result.event === 'connected') this.#installConnection(connection);
      else {
        this.#clearConnection();
        this.#publish({ identity: null, status: 'dormant' });
      }
      resolution = undefined;
    } else {
      this.#restorePriorConnection(pending, undefined);
    }
    pending.resolve(resolution);
    this.#finishCleanup(pending);
  }

  #failActive(pending, code, cleanup = true) {
    if (!this.#isActive(pending)) return;
    this.#retire(pending, code, true, cleanup);
  }

  #retire(pending, code, publishFailure, cleanup = true) {
    if (!pending.active) return pending.cleanup.promise;
    const retirementEpoch = this.#entryEpoch;
    pending.active = false;
    if (this.#pending === pending) this.#pending = null;
    this.#generation += 1;
    this.#clearOperationTimers(pending);
    for (const controller of pending.controllers) {
      if (pending.phase !== 'registering') controller.abort();
    }
    const retirementFailure = this.#entryFailure(retirementEpoch);
    const error = retirementFailure ?? walletClientError(code);
    pending.reject(error);
    if (publishFailure && !retirementFailure) {
      this.#publishFailure(pending, error, pending.priorConnection, pending.adapter.kind);
    }
    if (this.#destroyed) {
      if (pending.challenge && pending.verifier) void this.#cancelOnce(pending);
      this.#finishCleanup(pending);
      return pending.cleanup.promise;
    }
    if (!cleanup || pending.registrationOutcome === 'definitive-failure'
        || pending.registrationOutcome === 'not-started') {
      this.#finishCleanup(pending);
    } else if (pending.phase === 'hashing') {
      pending.registrationOutcome = 'not-started';
      this.#finishCleanup(pending);
    } else if (pending.phase === 'registering' && pending.registrationOutcome === 'none') {
      this.#addRetired(pending);
    } else {
      this.#addRetired(pending);
      void this.#ensureCleanup(pending);
    }
    return pending.cleanup.promise;
  }

  #publishFailure(_pending, error, priorConnection, _kind) {
    if (priorConnection?.expiresAtMs > this.#now()) {
      this.#connection = priorConnection;
      this.#publish({
        connectionExpiresAt: priorConnection.expiresAt,
        error: publicErrorRecord(error),
        identity: priorConnection.identity,
        status: 'connected',
      });
      return;
    }
    this.#clearConnection();
    this.#publish({
      error: publicErrorRecord(error),
      identity: null,
      status: 'error',
    });
  }

  #prepareConnection(result) {
    const expiresAtMs = exactTimestamp(result.connectionExpiresAt);
    const now = this.#now();
    if (expiresAtMs <= now || expiresAtMs - now > MAX_CONNECTION_MS) {
      throw walletClientError('RELAY_ERROR');
    }
    return {
      expiresAt: result.connectionExpiresAt,
      expiresAtMs,
      identity: cloneFrozen(result.identity),
    };
  }

  #installConnection(connection) {
    const now = this.#now();
    this.#clearConnection();
    this.#connection = connection;
    const captured = this.#connection;
    this.#connectionTimer = this.#setTimer(() => {
      if (this.#connection !== captured) return;
      this.#connection = null;
      this.#connectionTimer = null;
      if (this.#pending) {
        this.#publish({ identity: null, status: 'opening' });
      } else {
        this.#publish({ identity: null, status: 'dormant' });
      }
    }, Math.max(0, connection.expiresAtMs - now));
    this.#publish({
      connectionExpiresAt: connection.expiresAt,
      identity: this.#connection.identity,
      status: 'connected',
    });
  }

  #restorePriorConnection(pending, error) {
    const prior = pending.priorConnection;
    if (prior?.expiresAtMs > this.#now()) {
      this.#connection = prior;
      this.#publish({
        connectionExpiresAt: prior.expiresAt,
        ...(error ? { error: publicErrorRecord(error) } : {}),
        identity: prior.identity,
        status: 'connected',
      });
    } else if (error) {
      this.#clearConnection();
      this.#publish({ error: publicErrorRecord(error), identity: null, status: 'error' });
    } else {
      this.#clearConnection();
      this.#publish({ identity: null, status: 'dormant' });
    }
  }

  #expireConnectionIfNeeded() {
    if (!this.#connection || this.#connection.expiresAtMs > this.#now()) return;
    this.#clearConnection();
    if (this.#pending) this.#publish({ identity: null, status: 'opening' });
    else this.#publish({ identity: null, status: 'dormant' });
  }

  #clearConnection() {
    this.#connection = null;
    this.#clearTimer(this.#connectionTimer);
    this.#connectionTimer = null;
  }

  #publish(value) {
    const state = cloneFrozen(value);
    this.#state = state;
    this.#notificationQueue.push(state);
    if (this.#publishing) return;
    this.#publishing = true;
    try {
      while (this.#notificationQueue.length !== 0) {
        const published = this.#notificationQueue.shift();
        for (const listener of [...this.#listeners]) {
          try {
            listener(snapshotFrom(published));
          } catch {
            // Presenter isolation is part of the public observable contract.
          }
        }
      }
    } finally {
      this.#publishing = false;
    }
  }

  #isActive(pending) {
    return !this.#destroyed && pending.active && this.#pending === pending
      && pending.generation === this.#generation;
  }

  #entryFailure(entryEpoch) {
    if (this.#destroyed) return walletClientError('DESTROYED');
    if (entryEpoch !== this.#entryEpoch) return walletClientError('REPLACED');
    return null;
  }

  #now() {
    return this.#dependencies.now();
  }

  #newController(pending) {
    const controller = new this.#dependencies.AbortController();
    pending.controllers.add(controller);
    this.#controllers.add(controller);
    return controller;
  }

  #releaseController(pending, controller) {
    pending.controllers.delete(controller);
    this.#controllers.delete(controller);
  }

  #setTimer(callback, milliseconds) {
    let timer;
    timer = this.#dependencies.setTimeout(() => {
      this.#timers.delete(timer);
      callback();
    }, Math.max(0, milliseconds));
    this.#timers.add(timer);
    return timer;
  }

  #setInterval(callback, milliseconds) {
    const timer = this.#dependencies.setInterval(callback, milliseconds);
    this.#timers.add(timer);
    return timer;
  }

  #clearTimer(timer, interval = false) {
    if (timer === null || timer === undefined) return;
    if (interval) this.#dependencies.clearInterval(timer);
    else this.#dependencies.clearTimeout(timer);
    this.#timers.delete(timer);
  }

  #clearOperationTimers(pending) {
    this.#clearTimer(pending.expiryTimer);
    this.#clearTimer(pending.pollTimer, true);
    pending.expiryTimer = null;
    pending.pollTimer = null;
  }

  #addRetired(pending) {
    if (pending.cleanupFinished || this.#retired.has(pending)) return;
    this.#retired.add(pending);
    while (this.#retired.size > MAX_RETIRED_CLEANUPS) {
      const oldest = this.#retired.values().next().value;
      for (const controller of oldest.controllers) controller.abort();
      this.#finishCleanup(oldest);
    }
  }

  async #ensureCleanup(pending) {
    if (pending.cleanupFinished || pending.cleanupStarted || this.#destroyed) {
      return pending.cleanup.promise;
    }
    pending.cleanupStarted = true;
    this.#addRetired(pending);
    let delay = 100;
    let firstAttempt = true;
    while (!this.#destroyed && !pending.cleanupFinished
        && (firstAttempt || this.#now() <= pending.registrationDeadlineMs)) {
      firstAttempt = false;
      const outcome = await this.#cancelOnce(pending);
      if (pending.cleanupFinished) return pending.cleanup.promise;
      if (outcome === 'done') {
        this.#finishCleanup(pending);
        return pending.cleanup.promise;
      }
      const remaining = pending.registrationDeadlineMs - this.#now();
      if (remaining <= 0) break;
      await new Promise((resolve) => {
        pending.retryResolve = resolve;
        pending.retryTimer = this.#setTimer(() => {
          pending.retryResolve = null;
          resolve();
        }, Math.min(delay, remaining));
      });
      pending.retryResolve = null;
      pending.retryTimer = null;
      delay = Math.min(delay * 2, 4_000);
    }
    this.#finishCleanup(pending);
    return pending.cleanup.promise;
  }

  async #cancelOnce(pending) {
    if (!pending.verifier || !pending.challenge) return 'done';
    const controller = this.#newController(pending);
    const remaining = pending.registrationDeadlineMs - this.#now();
    const attemptTimeoutMs = remaining > 0 ? Math.min(4_000, remaining) : 1_000;
    const attemptTimer = this.#setTimer(() => controller.abort(), Math.max(1, attemptTimeoutMs));
    let response = null;
    try {
      const transport = this.#dependencies.fetch(
        `${WALLET_ORIGIN}/relay/v1/transactions/${pending.transactionId}/cancel`,
        requestOptions({
          codeVerifier: pending.verifier,
          schemaVersion: 1,
          state: pending.state,
          transactionId: pending.transactionId,
        }, controller.signal),
      );
      response = await raceAbortSignal(
        transport,
        controller.signal,
        bestEffortBodyCancel,
      );
      const status = response.status;
      abortResponse(controller, response);
      response = null;
      if (status === 204 || status === 400 || status === 403
          || status === 409 || status === 410) return 'done';
      return 'retry';
    } catch {
      if (response) abortResponse(controller, response);
      return 'retry';
    } finally {
      try {
        controller.abort();
      } catch {
        // Cleanup is locally bounded even when the transport ignores abort.
      }
      this.#clearTimer(attemptTimer);
      this.#releaseController(pending, controller);
    }
  }

  #finishCleanup(pending) {
    if (pending.cleanupFinished) return;
    pending.cleanupFinished = true;
    this.#clearTimer(pending.retryTimer);
    pending.retryResolve?.();
    pending.retryResolve = null;
    pending.retryTimer = null;
    this.#clearTimer(pending.operationTimer);
    pending.operationTimer = null;
    this.#clearOperationTimers(pending);
    for (const controller of pending.controllers) {
      controller.abort();
      this.#controllers.delete(controller);
    }
    pending.controllers.clear();
    this.#retired.delete(pending);
    pending.adapter = null;
    pending.challenge = null;
    pending.priorConnection = null;
    pending.request = null;
    pending.state = null;
    pending.transactionExpiresAtMs = null;
    pending.transactionId = null;
    pending.verifier = null;
    pending.cleanup.resolve();
  }

  #removeExpiredCallbackRecords() {
    const storage = this.#storage;
    if (!storage) return;
    let keys;
    try {
      keys = Array.from({ length: storage.length }, (_, index) => storage.key(index));
    } catch {
      return;
    }
    for (const key of keys) {
      if (typeof key !== 'string' || !key.startsWith(CALLBACK_PREFIX)) continue;
      const state = key.slice(CALLBACK_PREFIX.length);
      if (!LOWER_HEX_32.test(state)) continue;
      try {
        const text = storage.getItem(key);
        if (text === null) continue;
        const value = exactObject(
          parseJsonWithoutDuplicates(text, 2_048),
          ['code', 'expiresAt', 'schemaVersion', 'state'],
          'CALLBACK_ERROR',
        );
        if (value.schemaVersion !== 1 || value.state !== state || !LOWER_HEX_32.test(value.code)) {
          continue;
        }
        if (exactTimestamp(value.expiresAt, 'CALLBACK_ERROR') <= this.#now()) storage.removeItem(key);
      } catch {
        // Malformed records are not proven expired and are not removed at startup.
      }
    }
  }
}

export function createInternalWalletClient(configuration) {
  return new InternalWalletClient(configuration);
}

export function createPublicApi(core, methodAdapters = {}) {
  const requireNoArguments = (argumentsLength, callback) => {
    if (argumentsLength !== 0) return Promise.reject(walletClientError('INVALID_REQUEST'));
    return callback();
  };
  const api = {
    connect(...arguments_) {
      return requireNoArguments(arguments_.length, () => core.execute('connect', undefined));
    },
    destroy(...arguments_) {
      return requireNoArguments(arguments_.length, () => core.destroy());
    },
    disconnect(...arguments_) {
      return requireNoArguments(arguments_.length, () => core.disconnect());
    },
    getSnapshot(...arguments_) {
      if (arguments_.length !== 0) throw walletClientError('INVALID_REQUEST');
      return core.getSnapshot();
    },
    openAccount(...arguments_) {
      return requireNoArguments(arguments_.length, () => core.execute('account', undefined));
    },
    subscribe(listener, ...extra) {
      if (extra.length !== 0) throw walletClientError('INVALID_REQUEST');
      return core.subscribe(listener);
    },
  };
  for (const [method, adapterName] of Object.entries(methodAdapters)) {
    api[method] = function executeTyped(input, ...extra) {
      if (extra.length !== 0) return Promise.reject(walletClientError('INVALID_REQUEST'));
      return core.execute(adapterName, input);
    };
  }
  return Object.freeze(api);
}
