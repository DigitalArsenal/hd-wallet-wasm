import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { createWalletClient as createProductionWalletClient } from '../client/index.mjs';
import { createSdnWalletClient as createProductionSdnWalletClient } from '../client/sdn.mjs';
import {
  createAssetReviewWalletClient as createProductionAssetReviewWalletClient,
} from '../client/asset-review.mjs';
import * as publicModule from '../client/index.mjs';
import * as sdnModule from '../client/sdn.mjs';
import * as reviewModule from '../client/asset-review.mjs';
import {
  createInternalWalletClient,
  createPublicApi,
} from '../client/relay-client.mjs';
import {
  buildAssetReviewAuthorityActivationRequest,
  buildAssetReviewAuthorityActivationResult,
  buildAssetReviewDecisionRequest,
  buildAssetReviewDecisionResult,
  buildSdnLoginV1Request,
  buildSdnLoginV1Result,
  buildSdnLoginV2Request,
  buildSdnLoginV2Result,
  buildWalletAccountRequest,
  buildWalletAccountResult,
  buildWalletConnectRequest,
  buildWalletConnectResult,
} from '../client/wire.mjs';

const NOW = Date.parse('2026-07-21T12:00:00.000Z');
const CALLBACK_PREFIX = 'sdn.wallet.callback.v1:';
const TRANSACTION_ID = '11'.repeat(32);
const STATE = '22'.repeat(32);
const VERIFIER = 'MzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzMzM';
const CODE_CHALLENGE = 'KPlDz_s5_TfmJIOULW1xN9xQeIvZ3e0Wj3nQKHXecd8';
const CODE = 'ab'.repeat(32);
const HEX_32 = 'a'.repeat(64);
const SIGNATURE_HEX = 'b'.repeat(128);

const CLIENT_METHODS = [
  'connect',
  'destroy',
  'disconnect',
  'getSnapshot',
  'openAccount',
  'subscribe',
];

const TEST_BASE_ADAPTERS = Object.freeze({
  account: Object.freeze({
    buildRequest: () => buildWalletAccountRequest({}),
    kind: 'account',
    operation: 'sdn.wallet.account.v1',
    parseResult: buildWalletAccountResult,
  }),
  connect: Object.freeze({
    buildRequest: () => buildWalletConnectRequest({}),
    kind: 'connect',
    operation: 'sdn.wallet.connect.v1',
    parseResult: buildWalletConnectResult,
  }),
});

let injectedDependencies;

function injectedClient(adapters, clientId, methodAdapters = {}) {
  if (!injectedDependencies) throw new Error('test dependencies were not installed');
  const core = createInternalWalletClient({ adapters, clientId, dependencies: injectedDependencies });
  return createPublicApi(core, methodAdapters);
}

function createWalletClient({ clientId }) {
  return injectedClient(TEST_BASE_ADAPTERS, clientId);
}

function createSdnWalletClient() {
  return injectedClient(Object.freeze({
    ...TEST_BASE_ADAPTERS,
    sdnLoginV1: Object.freeze({
      buildRequest: buildSdnLoginV1Request,
      kind: 'typed',
      operation: 'sdn.auth.raw-challenge.v1',
      parseResult: buildSdnLoginV1Result,
    }),
    sdnLoginV2: Object.freeze({
      buildRequest: buildSdnLoginV2Request,
      kind: 'typed',
      operation: 'sdn.auth.jcs-envelope.v2',
      parseResult: buildSdnLoginV2Result,
    }),
  }), 'sdn-node-console-v1', {
    requestSdnLoginV1: 'sdnLoginV1',
    requestSdnLoginV2: 'sdnLoginV2',
  });
}

function createAssetReviewWalletClient() {
  return injectedClient(Object.freeze({
    ...TEST_BASE_ADAPTERS,
    assetReviewApproval: Object.freeze({
      buildRequest: buildAssetReviewDecisionRequest,
      kind: 'typed',
      operation: 'sdn.asset-review.decision.v1',
      parseResult: buildAssetReviewDecisionResult,
    }),
    authorityActivation: Object.freeze({
      buildRequest: buildAssetReviewAuthorityActivationRequest,
      kind: 'typed',
      operation: 'sdn.asset-review.authority-activation.v1',
      parseResult: buildAssetReviewAuthorityActivationResult,
    }),
  }), 'sdn-asset-review-v1', {
    requestAssetReviewApproval: 'assetReviewApproval',
    requestAuthorityActivation: 'authorityActivation',
  });
}

class MemoryStorage {
  #values = new Map();

  constructor(entries = []) {
    for (const [key, value] of entries) this.#values.set(key, value);
    this.getItem = vi.fn((key) => this.#values.get(String(key)) ?? null);
    this.setItem = vi.fn((key, value) => {
      this.#values.set(String(key), String(value));
    });
    this.removeItem = vi.fn((key) => {
      this.#values.delete(String(key));
    });
  }

  get length() {
    return this.#values.size;
  }

  key(index) {
    return [...this.#values.keys()][index] ?? null;
  }
}

function deferred() {
  let resolve;
  let reject;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function byteStream(bytes) {
  let complete = false;
  const cancel = vi.fn(async () => {
    complete = true;
  });
  return {
    cancel,
    getReader() {
      return {
        cancel: vi.fn(async () => {
          complete = true;
        }),
        read: vi.fn(async () => {
          if (complete) return { done: true, value: undefined };
          complete = true;
          return { done: false, value: bytes };
        }),
        releaseLock: vi.fn(),
      };
    },
  };
}

function jsonResponse(status, value, {
  contentType = 'application/json; charset=utf-8',
  raw = JSON.stringify(value),
  rawBytes = new TextEncoder().encode(raw),
} = {}) {
  return {
    body: byteStream(rawBytes),
    headers: { get: (name) => name.toLowerCase() === 'content-type' ? contentType : null },
    ok: status >= 200 && status < 300,
    status,
    text: vi.fn(async () => raw),
  };
}

function jsonResponseWithoutStream(status, value) {
  const raw = JSON.stringify(value);
  return {
    headers: { get: () => 'application/json; charset=utf-8' },
    status,
    text: vi.fn(async () => raw),
  };
}

function emptyResponse(status = 204) {
  return {
    headers: { get: () => null },
    ok: status >= 200 && status < 300,
    status,
    text: vi.fn(async () => ''),
  };
}

function approvalIdentity() {
  const descriptor = (purpose, curve, signatureProfile, path, fill) => ({
    bip32Fingerprint: null,
    curve,
    derivation: 'slip10',
    encoding: 'raw',
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    keyId: `sha256:${fill.repeat(64)}`,
    path,
    publicKeyHex: fill.repeat(64),
    purpose,
    seedProfile: 'password-scrypt-v2',
    signatureProfile,
  });
  return {
    accountFingerprint: '1234abcd',
    accountIndex: 0,
    accountLabel: null,
    accountPeerId: `16Uiu2H${'1'.repeat(40)}`,
    accountXpub: `xpub${'1'.repeat(107)}`,
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    keys: [
      descriptor(
        'asset-review-approval',
        'ed25519',
        'ed25519-over-sha256-jcs-v1',
        "m/44'/0'/0'/2'/0'",
        'a',
      ),
      descriptor('contact-encryption', 'x25519', null, "m/44'/0'/0'/1'/0'", 'b'),
      descriptor(
        'sdn-authentication',
        'ed25519',
        'ed25519-over-sha256-jcs-v1',
        "m/44'/0'/0'/0'/0'",
        'c',
      ),
    ],
    schemaVersion: 1,
    seedProfile: 'password-scrypt-v2',
  };
}

function connectedResult(expiresAt = new Date(Date.now() + 60_000).toISOString()) {
  return {
    connectionExpiresAt: expiresAt,
    event: 'connected',
    identity: approvalIdentity(),
    schemaVersion: 1,
  };
}

function disconnectedResult() {
  return {
    connectionExpiresAt: null,
    event: 'disconnected',
    identity: null,
    schemaVersion: 1,
  };
}

function rawSignature() {
  return {
    algorithm: 'ed25519',
    encoding: 'raw',
    identityScheme: 'sdn-fast-password-auth-v1-legacy',
    keyId: `sha256:${HEX_32}`,
    schemaVersion: 1,
    signatureHex: SIGNATURE_HEX,
    signatureProfile: 'ed25519-raw-32-v1',
  };
}

function base32(bytes) {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
  let accumulator = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet[(accumulator >>> bits) & 31];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits !== 0) output += alphabet[(accumulator << (5 - bits)) & 31];
  return output;
}

function rawSha256Cid(digestHex = HEX_32) {
  const digest = Uint8Array.from(digestHex.match(/../gu), (byte) => Number.parseInt(byte, 16));
  return `b${base32(Uint8Array.of(0x01, 0x55, 0x12, 0x20, ...digest))}`;
}

function activationRequest() {
  return {
    audience: 'asset-review-authority:assets.ipfs.01',
    clientId: 'sdn-asset-review-v1',
    expiresAt: '2026-07-21T12:05:00.000Z',
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    issuedAt: '2026-07-21T12:00:00.000Z',
    keyId: `sha256:${HEX_32}`,
    nonce: 'c'.repeat(64),
    protocolVersion: 1,
    publicKeyHex: HEX_32,
    purpose: 'asset-review-authority-activation',
    requestOrigin: 'https://review.spacedatanetwork.org',
    serviceInstance: 'assets.ipfs.01/asset-review-attestation',
    signatureProfile: 'ed25519-over-sha256-jcs-v1',
  };
}

function approvalRequest() {
  return {
    audience: 'asset-review:assets.ipfs.01',
    candidateKey: `asset-review:provider/model:${HEX_32}`,
    challengeId: 'd'.repeat(64),
    clientId: 'sdn-asset-review-v1',
    decision: 'approve',
    expiresAt: '2026-07-21T12:05:00.000Z',
    issuedAt: '2026-07-21T12:00:00.000Z',
    metadataSha256: 'e'.repeat(64),
    modelBytes: 4096,
    modelCid: rawSha256Cid(),
    modelSha256: HEX_32,
    nonce: 'f'.repeat(64),
    note: null,
    previousDecisionHead: null,
    protocolVersion: 1,
    requestOrigin: 'https://review.spacedatanetwork.org',
    reviewedTransform: {
      metersPerSourceUnit: 1,
      rotation: [0, 0, 0, 1],
      scale: [1, 1, 1],
      sourceUnits: 'm',
      translation: [0, 0, 0],
      upAxis: 'Z_UP',
    },
  };
}

function expectDeepFrozen(value) {
  expect(Object.isFrozen(value)).toBe(true);
  if (!value || typeof value !== 'object') return;
  for (const child of Object.values(value)) expectDeepFrozen(child);
}

async function flushAsync(rounds = 12) {
  for (let index = 0; index < rounds; index += 1) await Promise.resolve();
}

async function waitForLength(value, length) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    await flushAsync(2);
    if (value.length >= length) return;
  }
  throw new Error(`expected ${length} entries, received ${value.length}`);
}

function createHarness({
  openReturn = null,
  registrationLifetimeMs = 300_000,
  storage = new MemoryStorage(),
} = {}) {
  const eventOrder = [];
  const listeners = new Map();
  const requests = [];
  const registrations = [];
  const cancellations = [];
  const redemptions = [];
  const redeemResults = [];
  let entropyFill = 0x11;
  let customFetch;
  let registrationGate;
  let onRedeem;

  const windowValue = {
    addEventListener: vi.fn((type, listener) => {
      if (!listeners.has(type)) listeners.set(type, new Set());
      listeners.get(type).add(listener);
    }),
    open: vi.fn((..._arguments) => {
      eventOrder.push('open');
      return openReturn;
    }),
    removeEventListener: vi.fn((type, listener) => listeners.get(type)?.delete(listener)),
  };
  const cryptoValue = {
    getRandomValues: vi.fn((target) => {
      eventOrder.push(`rng:${entropyFill.toString(16)}`);
      target.fill(entropyFill);
      entropyFill = (entropyFill + 0x11) & 0xff;
      return target;
    }),
    subtle: {
      digest: vi.fn(async (algorithm, input) => {
        eventOrder.push('digest');
        expect(algorithm).toBe('SHA-256');
        const digest = createHash('sha256').update(new Uint8Array(input)).digest();
        return digest.buffer.slice(digest.byteOffset, digest.byteOffset + digest.byteLength);
      }),
    },
  };

  async function defaultFetch(url, init = {}) {
    const parsed = new URL(String(url));
    const body = typeof init.body === 'string' ? JSON.parse(init.body) : undefined;
    if (init.method === 'POST' && parsed.pathname === '/relay/v1/transactions') {
      if (registrationGate) await registrationGate;
      registrations.push(body);
      return jsonResponse(201, {
        expiresAt: new Date(Date.now() + registrationLifetimeMs).toISOString(),
        schemaVersion: 1,
        transactionId: body.transactionId,
      });
    }
    if (init.method === 'POST' && /\/cancel$/u.test(parsed.pathname)) {
      cancellations.push(body);
      return emptyResponse();
    }
    if (init.method === 'POST' && parsed.pathname === '/relay/v1/codes/redeem') {
      redemptions.push(body);
      onRedeem?.(body);
      const result = redeemResults.shift();
      if (!result) throw new Error('test did not provide a redeem result');
      return jsonResponse(200, {
        result,
        schemaVersion: 1,
        transactionId: body.transactionId,
      });
    }
    throw new Error(`unexpected local fetch ${init.method ?? 'GET'} ${parsed.pathname}`);
  }

  const fetchValue = vi.fn(async (url, init) => {
    eventOrder.push('fetch');
    const request = { init, url: String(url) };
    requests.push(request);
    return customFetch ? customFetch(url, init, defaultFetch) : defaultFetch(url, init);
  });

  const dependencies = Object.freeze({
    AbortController: globalThis.AbortController,
    clearInterval: globalThis.clearInterval.bind(globalThis),
    clearTimeout: globalThis.clearTimeout.bind(globalThis),
    crypto: cryptoValue,
    fetch: fetchValue,
    now: () => Date.now(),
    setInterval: globalThis.setInterval.bind(globalThis),
    setTimeout: globalThis.setTimeout.bind(globalThis),
    storage,
    window: windowValue,
  });
  injectedDependencies = dependencies;

  function emitCallback(registration = registrations.at(-1), {
    code = CODE,
    expiresAt = new Date(Date.now() + 120_000).toISOString(),
    recordState = registration.state,
  } = {}) {
    const key = `${CALLBACK_PREFIX}${registration.state}`;
    storage.setItem(key, JSON.stringify({
      schemaVersion: 1,
      code,
      state: recordState,
      expiresAt,
    }));
    for (const listener of listeners.get('storage') ?? []) {
      listener({ key, newValue: 'event payload is deliberately ignored', storageArea: storage });
    }
    return key;
  }

  return {
    cancellations,
    crypto: cryptoValue,
    dependencies,
    emitCallback,
    eventOrder,
    fetch: fetchValue,
    listenerCount: (type) => listeners.get(type)?.size ?? 0,
    registrations,
    redemptions,
    requests,
    setCustomFetch: (value) => { customFetch = value; },
    setOnRedeem: (value) => { onRedeem = value; },
    setRegistrationGate: (value) => { registrationGate = value; },
    storage,
    useRedeemResult: (value) => redeemResults.push(value),
    window: windowValue,
  };
}

async function beginStalledRedeem(harness, client, onAbort) {
  harness.setCustomFetch(async (url, init, fallback) => {
    if (new URL(String(url)).pathname !== '/relay/v1/codes/redeem') {
      return fallback(url, init);
    }
    init.signal.addEventListener('abort', onAbort, { once: true });
    return new Promise(() => {});
  });
  const operation = client.connect();
  operation.catch(() => {});
  await waitForLength(harness.registrations, 1);
  harness.emitCallback();
  await waitForLength(harness.requests, 2);
  expect(new URL(harness.requests[1].url).pathname).toBe('/relay/v1/codes/redeem');
  return { operation };
}

beforeEach(() => {
  vi.useFakeTimers({ now: NOW });
});

afterEach(() => {
  injectedDependencies = undefined;
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('public client factories and launch contract', () => {
  test('opens synchronously with exact noopener URL, ignores a null return, and registers PKCE after open', async () => {
    const harness = createHarness({ openReturn: null });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });

    const operation = client.connect();
    operation.catch(() => {});

    expect(harness.window.open).toHaveBeenCalledOnce();
    expect(harness.window.open).toHaveBeenCalledWith(
      `https://wallet.spacedatanetwork.org/transaction/${TRANSACTION_ID}`,
      '_blank',
      'noopener',
    );
    expect(harness.eventOrder.slice(0, 4)).toEqual(['rng:11', 'rng:22', 'rng:33', 'open']);

    await waitForLength(harness.registrations, 1);
    const transactionUrl = new URL(harness.window.open.mock.calls[0][0]);
    expect(transactionUrl.pathname).toBe(`/transaction/${TRANSACTION_ID}`);
    expect(transactionUrl.search).toBe('');
    expect(transactionUrl.hash).toBe('');
    expect(harness.eventOrder.indexOf('open')).toBeLessThan(harness.eventOrder.indexOf('digest'));
    expect(harness.eventOrder.indexOf('digest')).toBeLessThan(harness.eventOrder.indexOf('fetch'));
    expect(harness.crypto.getRandomValues).toHaveBeenCalledTimes(3);
    for (const [target] of harness.crypto.getRandomValues.mock.calls) {
      expect(target).toBeInstanceOf(Uint8Array);
      expect(target).toHaveLength(32);
    }
    expect(harness.crypto.subtle.digest).toHaveBeenCalledOnce();
    expect(harness.registrations[0]).toEqual({
      clientId: 'sdn-landing-web-v1',
      codeChallenge: CODE_CHALLENGE,
      codeChallengeMethod: 'S256',
      operation: 'sdn.wallet.connect.v1',
      request: {},
      schemaVersion: 1,
      state: STATE,
      transactionId: TRANSACTION_ID,
    });
    expect(JSON.stringify(harness.window.open.mock.calls[0])).not.toMatch(
      /code|state|verifier|challenge|credential/iu,
    );
    expect(harness.requests[0].init).toMatchObject({
      cache: 'no-store',
      credentials: 'omit',
      method: 'POST',
      redirect: 'error',
    });

    await client.destroy();
    await expect(operation).rejects.toMatchObject({ code: 'DESTROYED' });
  });

  test('never reads a returned WindowProxy and contains no popup-handle lifecycle code', async () => {
    const poison = new Proxy({}, {
      get() {
        throw new Error('the no-opener return must remain unobserved');
      },
    });
    const harness = createHarness({ openReturn: poison });
    const client = createWalletClient({ clientId: 'sdn-standards-web-v1' });

    const operation = client.connect();
    operation.catch(() => {});
    await waitForLength(harness.registrations, 1);

    const relaySource = await readFile(new URL('../client/relay-client.mjs', import.meta.url), 'utf8');
    expect(relaySource).not.toMatch(/\.closed\b|\.opener\b|popup\.close|WindowProxy/u);
    await client.destroy();
  });

  test('exports only frozen purpose-specific client surfaces and rejects every unknown client ID', async () => {
    createHarness();
    const base = createProductionWalletClient({ clientId: 'sdn-asset-models-pages-v1' });
    const sdn = createProductionSdnWalletClient();
    const review = createProductionAssetReviewWalletClient();

    expect(Object.keys(publicModule).sort()).toEqual(['WALLET_CLIENT_ERRORS', 'createWalletClient']);
    expect(Object.keys(sdnModule).sort()).toEqual(['WALLET_CLIENT_ERRORS', 'createSdnWalletClient']);
    expect(Object.keys(reviewModule).sort()).toEqual([
      'WALLET_CLIENT_ERRORS',
      'createAssetReviewWalletClient',
    ]);

    expect(Object.keys(base).sort()).toEqual(CLIENT_METHODS);
    expect(Object.keys(sdn).sort()).toEqual([
      ...CLIENT_METHODS,
      'requestSdnLoginV1',
      'requestSdnLoginV2',
    ].sort());
    expect(Object.keys(review).sort()).toEqual([
      ...CLIENT_METHODS,
      'requestAssetReviewApproval',
      'requestAuthorityActivation',
    ].sort());
    expect(Object.isFrozen(base)).toBe(true);
    expect(Object.isFrozen(sdn)).toBe(true);
    expect(Object.isFrozen(review)).toBe(true);
    expect(base).not.toHaveProperty('sign');
    expect(sdn).not.toHaveProperty('requestAssetReviewApproval');
    expect(review).not.toHaveProperty('requestSdnLoginV2');
    expect(() => createProductionWalletClient({ clientId: 'sdn-desktop-v1' })).toThrowError(
      expect.objectContaining({ code: 'INVALID_CLIENT' }),
    );
    const hostileOptions = new Proxy({}, {
      getPrototypeOf() {
        throw new Error('caller-controlled factory error');
      },
    });
    expect(() => createProductionWalletClient(hostileOptions)).toThrowError(
      expect.objectContaining({ code: 'INVALID_REQUEST' }),
    );
    try {
      createProductionWalletClient(hostileOptions);
    } catch (error) {
      expect(error.message).not.toContain('caller-controlled');
    }
    expect(() => createProductionSdnWalletClient({ clientId: 'sdn-landing-web-v1' })).toThrowError(
      expect.objectContaining({ code: 'INVALID_REQUEST' }),
    );

    await Promise.all([base.destroy(), sdn.destroy(), review.destroy()]);
  });

  test('maps the six methods one-to-one and copies typed caller values before opening', async () => {
    const harness = createHarness();
    const base = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const sdn = createSdnWalletClient();
    const review = createAssetReviewWalletClient();
    const challengeV1 = Uint8Array.from({ length: 32 }, (_, index) => index);
    const challengeV2 = Uint8Array.from({ length: 32 }, (_, index) => 31 - index);
    const decision = approvalRequest();
    const pending = [];

    pending.push(base.connect());
    pending.at(-1).catch(() => {});
    await waitForLength(harness.registrations, 1);
    pending.push(base.openAccount());
    pending.at(-1).catch(() => {});
    await waitForLength(harness.registrations, 2);
    pending.push(sdn.requestSdnLoginV1({ protocolVersion: 1, challenge: challengeV1 }));
    pending.at(-1).catch(() => {});
    challengeV1.fill(255);
    await waitForLength(harness.registrations, 3);
    pending.push(sdn.requestSdnLoginV2({
      audience: 'sdn-login:sdn.spaceaware.io',
      challenge: challengeV2,
      expiresAt: '2026-07-21T12:05:00.000Z',
      issuedAt: '2026-07-21T12:00:00.000Z',
      nonce: '1'.repeat(64),
      protocolVersion: 2,
    }));
    pending.at(-1).catch(() => {});
    challengeV2.fill(255);
    await waitForLength(harness.registrations, 4);
    pending.push(review.requestAuthorityActivation(activationRequest()));
    pending.at(-1).catch(() => {});
    await waitForLength(harness.registrations, 5);
    pending.push(review.requestAssetReviewApproval(decision));
    pending.at(-1).catch(() => {});
    decision.reviewedTransform.translation[0] = 99;
    await waitForLength(harness.registrations, 6);

    expect(harness.registrations.map(({ operation }) => operation)).toEqual([
      'sdn.wallet.connect.v1',
      'sdn.wallet.account.v1',
      'sdn.auth.raw-challenge.v1',
      'sdn.auth.jcs-envelope.v2',
      'sdn.asset-review.authority-activation.v1',
      'sdn.asset-review.decision.v1',
    ]);
    expect(harness.registrations.map(({ clientId }) => clientId)).toEqual([
      'sdn-landing-web-v1',
      'sdn-landing-web-v1',
      'sdn-node-console-v1',
      'sdn-node-console-v1',
      'sdn-asset-review-v1',
      'sdn-asset-review-v1',
    ]);
    expect(harness.registrations[2].request.challengeBase64url)
      .toBe('AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8');
    expect(harness.registrations[5].request.reviewedTransform.translation).toEqual([0, 0, 0]);

    await Promise.all([base.destroy(), sdn.destroy(), review.destroy()]);
  });

  test('rejects invalid typed requests before entropy, popup, or network work', async () => {
    const harness = createHarness();
    const sdn = createSdnWalletClient();

    await expect(sdn.requestSdnLoginV1({
      challenge: new Uint8Array(31),
      protocolVersion: 1,
    })).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    expect(harness.crypto.getRandomValues).not.toHaveBeenCalled();
    expect(harness.window.open).not.toHaveBeenCalled();
    expect(harness.fetch).not.toHaveBeenCalled();
    await sdn.destroy();
  });

  test('a request validator that destroys reentrantly cannot resurrect terminal state', async () => {
    const harness = createHarness();
    const client = createSdnWalletClient();
    let destroyPromise;
    const input = new Proxy({
      challenge: new Uint8Array(32),
      protocolVersion: 1,
    }, {
      getPrototypeOf(target) {
        destroyPromise ??= client.destroy();
        return Reflect.getPrototypeOf(target);
      },
    });

    const operation = client.requestSdnLoginV1(input);
    operation.catch(() => {});
    await destroyPromise;

    await expect(operation).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(client.getSnapshot()).toEqual({
      error: {
        code: 'DESTROYED',
        message: 'This wallet client has been destroyed.',
      },
      identity: null,
      status: 'error',
    });
    expect(harness.crypto.getRandomValues).not.toHaveBeenCalled();
    expect(harness.window.open).not.toHaveBeenCalled();
    expect(harness.fetch).not.toHaveBeenCalled();
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('a nested request during validation replaces only the older invocation', async () => {
    const harness = createHarness();
    const client = createSdnWalletClient();
    let nested;
    let reentered = false;
    const input = new Proxy({
      challenge: new Uint8Array(32),
      protocolVersion: 1,
    }, {
      getPrototypeOf(target) {
        if (!reentered) {
          reentered = true;
          nested = client.connect();
          nested.catch(() => {});
        }
        return Reflect.getPrototypeOf(target);
      },
    });

    const older = client.requestSdnLoginV1(input);
    await expect(older).rejects.toMatchObject({ code: 'REPLACED' });
    await waitForLength(harness.registrations, 1);

    expect(harness.registrations[0].operation).toBe('sdn.wallet.connect.v1');
    expect(harness.window.open).toHaveBeenCalledOnce();
    expect(client.getSnapshot()).toEqual({ identity: null, status: 'opening' });
    await client.destroy();
    await expect(nested).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('a nested invalid request cannot invalidate the outer valid invocation', async () => {
    const harness = createHarness();
    const client = createSdnWalletClient();
    let nestedInvalid;
    let reentered = false;
    const input = new Proxy({
      challenge: new Uint8Array(32),
      protocolVersion: 1,
    }, {
      getPrototypeOf(target) {
        if (!reentered) {
          reentered = true;
          nestedInvalid = client.requestSdnLoginV1({
            challenge: new Uint8Array(31),
            protocolVersion: 1,
          });
        }
        return Reflect.getPrototypeOf(target);
      },
    });

    const outer = client.requestSdnLoginV1(input);
    outer.catch(() => {});
    await expect(nestedInvalid).rejects.toMatchObject({ code: 'INVALID_REQUEST' });
    await waitForLength(harness.registrations, 1);

    expect(harness.registrations[0].operation).toBe('sdn.auth.raw-challenge.v1');
    expect(harness.window.open).toHaveBeenCalledOnce();
    await client.destroy();
    await expect(outer).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(vi.getTimerCount()).toBe(0);
  });

  test('a nested request during entropy prevents the older invocation from consuming more entropy', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    let nested;
    let reentered = false;
    let fill = 0x44;
    harness.crypto.getRandomValues.mockImplementation((target) => {
      if (!reentered) {
        reentered = true;
        nested = client.openAccount();
        nested.catch(() => {});
      }
      target.fill(fill);
      fill += 0x11;
      return target;
    });

    const older = client.connect();
    await expect(older).rejects.toMatchObject({ code: 'REPLACED' });
    await waitForLength(harness.registrations, 1);

    expect(harness.registrations[0].operation).toBe('sdn.wallet.account.v1');
    expect(harness.crypto.getRandomValues).toHaveBeenCalledTimes(4);
    expect(harness.window.open).toHaveBeenCalledOnce();
    await client.destroy();
    await expect(nested).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(vi.getTimerCount()).toBe(0);
  });

  test('a popup that launches a newer request and then throws cannot clobber the newer state', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    let nested;
    harness.window.open.mockImplementationOnce(() => {
      nested = client.openAccount();
      nested.catch(() => {});
      throw new Error('older popup failed after reentry');
    }).mockImplementation(() => null);

    const older = client.connect();
    await expect(older).rejects.toMatchObject({ code: 'REPLACED' });
    await waitForLength(harness.registrations, 1);

    expect(harness.registrations[0].operation).toBe('sdn.wallet.account.v1');
    expect(harness.window.open).toHaveBeenCalledTimes(2);
    expect(client.getSnapshot()).toEqual({ identity: null, status: 'opening' });
    await client.destroy();
    await expect(nested).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });
});

describe('state, callback, and revocation lifecycle', () => {
  test('shares one transaction across immediate subscribers and publishes fresh immutable snapshots', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const first = [];
    const second = [];
    const unsubscribeFirst = client.subscribe((snapshot) => first.push(snapshot));
    const unsubscribeThrowing = client.subscribe(() => { throw new Error('presenter failed'); });
    const unsubscribeSecond = client.subscribe((snapshot) => second.push(snapshot));

    expect(first).toHaveLength(1);
    expect(second).toHaveLength(1);
    expect(first[0]).toEqual({ identity: null, status: 'dormant' });
    expect(first[0]).not.toBe(second[0]);
    expectDeepFrozen(first[0]);

    harness.useRedeemResult(connectedResult());
    const operation = client.connect();
    await waitForLength(harness.registrations, 1);
    const callbackKey = harness.emitCallback();
    await expect(operation).resolves.toEqual(approvalIdentity());

    expect(harness.window.open).toHaveBeenCalledOnce();
    expect(harness.redemptions).toHaveLength(1);
    expect(harness.storage.getItem(callbackKey)).toBeNull();
    const left = client.getSnapshot();
    const right = client.getSnapshot();
    expect(left.status).toBe('connected');
    expect(left).not.toBe(right);
    expect(left.identity).not.toBe(right.identity);
    expectDeepFrozen(left);
    expect(first.at(-1).status).toBe('connected');
    expect(second.at(-1).status).toBe('connected');

    unsubscribeFirst();
    unsubscribeFirst();
    unsubscribeThrowing();
    await client.disconnect();
    expect(first.at(-1).status).toBe('connected');
    expect(second.at(-1)).toEqual({ identity: null, status: 'dormant' });
    unsubscribeSecond();
    await client.destroy();
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('delivers reentrant state changes to every subscriber in the same order', async () => {
    createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const first = [];
    const second = [];
    let disconnect;
    client.subscribe((snapshot) => {
      first.push(snapshot.status);
      if (snapshot.status === 'opening' && !disconnect) disconnect = client.disconnect();
    });
    client.subscribe((snapshot) => second.push(snapshot.status));

    const operation = client.connect();
    await expect(operation).rejects.toMatchObject({ code: 'DISCONNECTED' });
    await disconnect;

    expect(first).toEqual(['dormant', 'opening', 'dormant']);
    expect(second).toEqual(['dormant', 'opening', 'dormant']);
    await client.destroy();
  });

  test('removes the exact callback record before one redeem when storage event and poll race', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const redeemGate = deferred();
    harness.setOnRedeem(() => {
      expect(harness.storage.getItem(`${CALLBACK_PREFIX}${STATE}`)).toBeNull();
    });
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname === '/relay/v1/codes/redeem') {
        await redeemGate.promise;
      }
      return fallback(url, init);
    });
    harness.useRedeemResult(connectedResult());

    const operation = client.connect();
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();
    await vi.advanceTimersByTimeAsync(250);
    await flushAsync();
    expect(harness.requests.filter(({ url }) => new URL(url).pathname === '/relay/v1/codes/redeem'))
      .toHaveLength(1);
    redeemGate.resolve();
    await expect(operation).resolves.toEqual(approvalIdentity());
    expect(harness.redemptions).toHaveLength(1);
    await client.destroy();
  });

  test('does not consume an exact callback record until registration succeeds', async () => {
    const harness = createHarness();
    const registrationGate = deferred();
    harness.setRegistrationGate(registrationGate.promise);
    harness.useRedeemResult(connectedResult());
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });

    const operation = client.connect();
    await flushAsync();
    const key = harness.emitCallback({ state: STATE });
    await flushAsync();

    expect(harness.redemptions).toHaveLength(0);
    expect(harness.storage.getItem(key)).not.toBeNull();

    registrationGate.resolve();
    await expect(operation).resolves.toEqual(approvalIdentity());
    expect(harness.redemptions).toHaveLength(1);
    expect(harness.storage.getItem(key)).toBeNull();
    await client.destroy();
  });

  test('removes and rejects an exact-state malformed or overlong callback without redeeming', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    await waitForLength(harness.registrations, 1);

    const key = harness.emitCallback(undefined, {
      expiresAt: new Date(Date.now() + 120_001).toISOString(),
    });
    await expect(operation).rejects.toMatchObject({ code: 'CALLBACK_ERROR' });
    expect(harness.storage.getItem(key)).toBeNull();
    expect(harness.redemptions).toHaveLength(0);
    expect(client.getSnapshot()).toMatchObject({ status: 'error', identity: null });
    await client.destroy();
  });

  test('startup removes only structurally valid expired callback records with the exact prefix', async () => {
    const expiredState = '1'.repeat(64);
    const futureState = '2'.repeat(64);
    const expired = JSON.stringify({
      schemaVersion: 1,
      code: '3'.repeat(64),
      state: expiredState,
      expiresAt: new Date(Date.now() - 1).toISOString(),
    });
    const future = JSON.stringify({
      schemaVersion: 1,
      code: '4'.repeat(64),
      state: futureState,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
    });
    const storage = new MemoryStorage([
      [`${CALLBACK_PREFIX}${expiredState}`, expired],
      [`${CALLBACK_PREFIX}${futureState}`, future],
      [`${CALLBACK_PREFIX}malformed`, '{not-json'],
      ['other.application:key', expired],
    ]);
    createHarness({ storage });

    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });

    expect(storage.getItem(`${CALLBACK_PREFIX}${expiredState}`)).toBeNull();
    expect(storage.getItem(`${CALLBACK_PREFIX}${futureState}`)).toBe(future);
    expect(storage.getItem(`${CALLBACK_PREFIX}malformed`)).toBe('{not-json');
    expect(storage.getItem('other.application:key')).toBe(expired);
    await client.destroy();
  });

  test('restores a still-valid public connection around typed success and typed failure', async () => {
    const harness = createHarness();
    const client = createSdnWalletClient();
    harness.useRedeemResult(connectedResult());
    const connected = client.connect();
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();
    await connected;

    const challenge = Uint8Array.from({ length: 32 }, (_, index) => index);
    harness.useRedeemResult(rawSignature());
    const signed = client.requestSdnLoginV1({ challenge, protocolVersion: 1 });
    expect(client.getSnapshot()).toMatchObject({ status: 'opening', identity: approvalIdentity() });
    await waitForLength(harness.registrations, 2);
    harness.emitCallback();
    await expect(signed).resolves.toEqual(rawSignature());
    expect(client.getSnapshot()).toMatchObject({ status: 'connected', identity: approvalIdentity() });

    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname === '/relay/v1/transactions') {
        return jsonResponse(403, {
          error: { code: 'UNREGISTERED_CLIENT', message: 'must remain private' },
          schemaVersion: 1,
        });
      }
      return fallback(url, init);
    });
    const failed = client.requestSdnLoginV1({ challenge, protocolVersion: 1 });
    await expect(failed).rejects.toMatchObject({ code: 'RELAY_ERROR' });
    expect(client.getSnapshot()).toMatchObject({
      error: { code: 'RELAY_ERROR' },
      identity: approvalIdentity(),
      status: 'connected',
    });
    expect(JSON.stringify(client.getSnapshot())).not.toContain('must remain private');
    await client.destroy();
  });

  test('Account logout and matching connection expiry clear public state once', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    harness.useRedeemResult(connectedResult(new Date(Date.now() + 1_000).toISOString()));
    const connected = client.connect();
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();
    await connected;
    expect(client.getSnapshot().status).toBe('connected');

    await vi.advanceTimersByTimeAsync(1_001);
    expect(client.getSnapshot()).toEqual({ identity: null, status: 'dormant' });

    harness.useRedeemResult(disconnectedResult());
    const account = client.openAccount();
    await waitForLength(harness.registrations, 2);
    harness.emitCallback();
    await expect(account).resolves.toBeUndefined();
    expect(client.getSnapshot()).toEqual({ identity: null, status: 'dormant' });
    await client.destroy();
  });

  test('replacement rejects and cancels the old operation while ignoring its late callback', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const first = client.connect();
    first.catch(() => {});
    await waitForLength(harness.registrations, 1);
    const firstRegistration = harness.registrations[0];

    const second = client.openAccount();
    second.catch(() => {});
    await expect(first).rejects.toMatchObject({ code: 'REPLACED' });
    await waitForLength(harness.registrations, 2);
    await waitForLength(harness.cancellations, 1);
    expect(harness.cancellations[0]).toEqual({
      codeVerifier: VERIFIER,
      schemaVersion: 1,
      state: firstRegistration.state,
      transactionId: firstRegistration.transactionId,
    });

    harness.emitCallback(firstRegistration);
    await flushAsync();
    expect(harness.redemptions).toHaveLength(0);
    expect(client.getSnapshot().status).toBe('opening');
    await client.destroy();
    await expect(second).rejects.toMatchObject({ code: 'DESTROYED' });
  });

  test('destroy reentered from a redeem abort is stable and publishes one terminal lifecycle', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    let nestedDestroy;
    const { operation } = await beginStalledRedeem(harness, client, () => {
      nestedDestroy = client.destroy();
    });

    const outerDestroy = client.destroy();
    const repeatedDestroy = client.destroy();

    expect(nestedDestroy).toBe(outerDestroy);
    expect(repeatedDestroy).toBe(outerDestroy);
    await outerDestroy;
    await expect(operation).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(client.getSnapshot()).toEqual({
      error: {
        code: 'DESTROYED',
        message: 'This wallet client has been destroyed.',
      },
      identity: null,
      status: 'error',
    });
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('destroy reentered from disconnect retirement remains terminal and settles disconnect', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    let destroyPromise;
    const { operation } = await beginStalledRedeem(harness, client, () => {
      destroyPromise = client.destroy();
    });

    const disconnected = client.disconnect().then(
      () => ({ code: 'resolved' }),
      (error) => error,
    );
    await flushAsync(24);

    await destroyPromise;
    await expect(disconnected).resolves.toMatchObject({ code: 'DESTROYED' });
    await expect(operation).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(client.getSnapshot()).toEqual({
      error: {
        code: 'DESTROYED',
        message: 'This wallet client has been destroyed.',
      },
      identity: null,
      status: 'error',
    });
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('destroy reentered from replacement prevents an inactive pending operation from being installed', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    let destroyPromise;
    const { operation: first } = await beginStalledRedeem(harness, client, () => {
      destroyPromise = client.destroy();
    });

    const replacement = client.openAccount();
    replacement.catch(() => {});
    await flushAsync(24);

    await destroyPromise;
    await expect(replacement).rejects.toMatchObject({ code: 'DESTROYED' });
    await expect(first).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(harness.registrations).toHaveLength(1);
    expect(client.getSnapshot()).toMatchObject({
      error: { code: 'DESTROYED' },
      identity: null,
      status: 'error',
    });
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('a nested request claimed during replacement retirement remains the only pending operation', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    let nested;
    const { operation: first } = await beginStalledRedeem(harness, client, () => {
      nested = client.openAccount();
      nested.catch(() => {});
    });

    const olderReplacement = client.connect();
    olderReplacement.catch(() => {});
    await flushAsync(24);
    await waitForLength(harness.registrations, 2);

    await expect(olderReplacement).rejects.toMatchObject({ code: 'REPLACED' });
    await expect(first).rejects.toMatchObject({ code: 'REPLACED' });
    expect(harness.registrations.map(({ operation: name }) => name)).toEqual([
      'sdn.wallet.connect.v1',
      'sdn.wallet.account.v1',
    ]);
    expect(client.getSnapshot()).toEqual({ identity: null, status: 'opening' });
    await client.destroy();
    await expect(nested).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(vi.getTimerCount()).toBe(0);
  });

  test('a nested disconnect claimed during replacement retirement prevents stale opening state', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    let nestedDisconnect;
    const { operation: first } = await beginStalledRedeem(harness, client, () => {
      nestedDisconnect = client.disconnect();
    });

    const olderReplacement = client.openAccount();
    olderReplacement.catch(() => {});
    await flushAsync(24);

    await expect(nestedDisconnect).resolves.toBeUndefined();
    await expect(olderReplacement).rejects.toMatchObject({ code: 'REPLACED' });
    await expect(first).rejects.toMatchObject({ code: 'REPLACED' });
    expect(harness.registrations).toHaveLength(1);
    expect(client.getSnapshot()).toEqual({ identity: null, status: 'dormant' });
    await client.destroy();
    expect(vi.getTimerCount()).toBe(0);
  });

  test('a second valid call replaces the old operation even when new entropy generation fails', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const first = client.connect();
    first.catch(() => {});
    await waitForLength(harness.registrations, 1);
    harness.crypto.getRandomValues.mockImplementationOnce(() => {
      throw new Error('entropy unavailable');
    });

    const second = client.openAccount();

    await expect(second).rejects.toMatchObject({ code: 'CRYPTO_UNAVAILABLE' });
    await expect(first).rejects.toMatchObject({ code: 'REPLACED' });
    await waitForLength(harness.cancellations, 1);
    expect(client.getSnapshot()).toMatchObject({
      error: { code: 'CRYPTO_UNAVAILABLE' },
      identity: null,
      status: 'error',
    });
    await client.destroy();
  });

  test('disconnect revokes locally before an in-flight registration settles, then cancels exact 201', async () => {
    const harness = createHarness();
    const gate = deferred();
    harness.setRegistrationGate(gate.promise);
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await flushAsync();
    expect(harness.requests).toHaveLength(1);

    const disconnect = client.disconnect();
    expect(client.getSnapshot()).toEqual({ identity: null, status: 'dormant' });
    await expect(operation).rejects.toMatchObject({ code: 'DISCONNECTED' });
    expect(harness.cancellations).toHaveLength(0);

    gate.resolve();
    await disconnect;
    await waitForLength(harness.cancellations, 1);
    expect(harness.cancellations[0].transactionId).toBe(TRANSACTION_ID);
    await client.destroy();
  });

  test('disconnect aborts and cleans up one unanswered registration at the original deadline', async () => {
    const harness = createHarness();
    let registrationSignal;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/transactions') {
        return fallback(url, init);
      }
      registrationSignal = init.signal;
      return new Promise(() => {});
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await flushAsync();

    let disconnected = false;
    const disconnect = client.disconnect().then(() => { disconnected = true; });
    await expect(operation).rejects.toMatchObject({ code: 'DISCONNECTED' });
    expect(registrationSignal.aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(30_000);
    await flushAsync();
    expect(registrationSignal.aborted).toBe(true);
    expect(disconnected).toBe(true);
    await disconnect;
    expect(harness.cancellations).toHaveLength(1);
    expect(vi.getTimerCount()).toBe(0);
    await client.destroy();
  });

  test('disconnect finishes a hashing operation and ignores a late PKCE digest', async () => {
    const harness = createHarness();
    const digestGate = deferred();
    harness.crypto.subtle.digest.mockImplementationOnce(() => digestGate.promise);
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await flushAsync();

    await expect(client.disconnect()).resolves.toBeUndefined();
    await expect(operation).rejects.toMatchObject({ code: 'DISCONNECTED' });
    expect(harness.fetch).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);

    digestGate.resolve(Uint8Array.from({ length: 32 }, () => 0xaa).buffer);
    await flushAsync();
    expect(harness.fetch).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
    await client.destroy();
  });

  test('bounds an otherwise untouched PKCE digest by the original registration window', async () => {
    const harness = createHarness();
    harness.crypto.subtle.digest.mockImplementationOnce(() => new Promise(() => {}));
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await flushAsync();

    await vi.advanceTimersByTimeAsync(30_000);
    await expect(operation).rejects.toMatchObject({ code: 'CRYPTO_UNAVAILABLE' });
    expect(harness.fetch).not.toHaveBeenCalled();
    expect(vi.getTimerCount()).toBe(0);
    await client.destroy();
  });

  test('bounds a cancellation request that never settles', async () => {
    const harness = createHarness();
    let cancelSignal;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (!/\/cancel$/u.test(new URL(String(url)).pathname)) return fallback(url, init);
      cancelSignal = init.signal;
      return new Promise(() => {});
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await waitForLength(harness.registrations, 1);
    await flushAsync();
    let disconnected = false;
    const disconnect = client.disconnect().then(() => { disconnected = true; });
    await flushAsync();
    expect(cancelSignal.aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(31_000);
    await flushAsync();
    expect(cancelSignal.aborted).toBe(true);
    expect(disconnected).toBe(true);
    await disconnect;
    expect(vi.getTimerCount()).toBe(0);
    await client.destroy();
  });

  test('hard-bounds cleanup records and timers across rapid in-flight replacements', async () => {
    const harness = createHarness();
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/transactions') {
        return fallback(url, init);
      }
      return new Promise((_resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(new Error('registration aborted')), {
          once: true,
        });
      });
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operations = [];

    for (let index = 0; index < 12; index += 1) {
      const operation = client.connect();
      operation.catch(() => {});
      operations.push(operation);
      await waitForLength(harness.requests, index + 1);
      expect(vi.getTimerCount()).toBeLessThanOrEqual(9);
    }

    for (const operation of operations.slice(0, -1)) {
      await expect(operation).rejects.toMatchObject({ code: 'REPLACED' });
    }
    await client.destroy();
    await expect(operations.at(-1)).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(vi.getTimerCount()).toBe(0);
    expect(harness.listenerCount('storage')).toBe(0);
  });

  test('a failed reconnect preserves a still-valid public connection with a safe error', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    harness.useRedeemResult(connectedResult());
    const first = client.connect();
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();
    await first;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname === '/relay/v1/transactions') {
        return jsonResponse(403, {
          error: { code: 'UNREGISTERED_CLIENT', message: 'not public' },
          schemaVersion: 1,
        });
      }
      return fallback(url, init);
    });

    await expect(client.connect()).rejects.toMatchObject({ code: 'RELAY_ERROR' });
    expect(client.getSnapshot()).toMatchObject({
      error: { code: 'RELAY_ERROR' },
      identity: approvalIdentity(),
      status: 'connected',
    });
    await client.destroy();
  });

  test('bounded wallet non-completion cancels even after the 30-second registration window', async () => {
    const harness = createHarness({ registrationLifetimeMs: 31_000 });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await waitForLength(harness.registrations, 1);

    await vi.advanceTimersByTimeAsync(31_001);
    await expect(operation).rejects.toMatchObject({ code: 'WALLET_NOT_COMPLETED' });
    expect(client.getSnapshot()).toMatchObject({ status: 'error', identity: null });
    await waitForLength(harness.cancellations, 1);
    expect(JSON.stringify(client.getSnapshot())).toMatch(/popup settings/iu);

    const retry = client.connect();
    retry.catch(() => {});
    await waitForLength(harness.registrations, 2);
    expect(harness.registrations[1].transactionId).not.toBe(harness.registrations[0].transactionId);
    await client.destroy();
  });

  test('accepts the relay maximum TTL when it is issued after request latency', async () => {
    const harness = createHarness();
    const gate = deferred();
    harness.setRegistrationGate(gate.promise);
    harness.useRedeemResult(connectedResult());
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    await flushAsync();

    await vi.advanceTimersByTimeAsync(1_000);
    gate.resolve();
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();

    await expect(operation).resolves.toEqual(approvalIdentity());
    await client.destroy();
  });

  test.each([0, 300_001])(
    'rejects a relay registration with invalid receipt-relative TTL %dms',
    async (registrationLifetimeMs) => {
      const harness = createHarness({ registrationLifetimeMs });
      const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });

      await expect(client.connect()).rejects.toMatchObject({ code: 'RELAY_ERROR' });
      await waitForLength(harness.cancellations, 1);
      await client.destroy();
    },
  );

  test('accepts a public connection through the exact 15-minute maximum', async () => {
    const harness = createHarness();
    const expiresAt = new Date(Date.now() + 900_000).toISOString();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    harness.useRedeemResult(connectedResult(expiresAt));
    const operation = client.connect();
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();

    await expect(operation).resolves.toEqual(approvalIdentity());
    expect(client.getSnapshot()).toMatchObject({
      connectionExpiresAt: expiresAt,
      identity: approvalIdentity(),
      status: 'connected',
    });
    await client.destroy();
  });

  test.each([-1, 900_001])(
    'fails closed on an invalid public connection expiry offset %dms',
    async (expiryOffsetMs) => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    harness.useRedeemResult(connectedResult(new Date(Date.now() + expiryOffsetMs).toISOString()));
    const operation = client.connect();
    const failure = operation.catch((error) => error);
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();
    await expect(failure).resolves.toMatchObject({ code: 'RELAY_ERROR' });

    expect(client.getSnapshot()).toMatchObject({
      error: { code: 'RELAY_ERROR' },
      identity: null,
      status: 'error',
    });
    await client.destroy();
    },
  );

  test('destroy is terminal, cancels once, aborts requests, and removes every resource without a popup handle', async () => {
    const harness = createHarness();
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await waitForLength(harness.registrations, 1);
    await flushAsync();
    expect(harness.listenerCount('storage')).toBe(1);
    expect(vi.getTimerCount()).toBeGreaterThan(0);

    await client.destroy();
    await client.destroy();

    await expect(operation).rejects.toMatchObject({ code: 'DESTROYED' });
    expect(harness.cancellations).toHaveLength(1);
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
    const destroyCancellation = harness.requests.filter(({ url }) => /\/cancel$/u.test(new URL(url).pathname));
    expect(destroyCancellation).toHaveLength(1);
    expect(destroyCancellation[0].init.signal.aborted).toBe(true);
    await expect(client.connect()).rejects.toMatchObject({ code: 'DESTROYED' });
  });
});

describe('strict relay response handling', () => {
  test('rejects an oversized body without awaiting a reader cancellation that never settles', async () => {
    const harness = createHarness();
    const readerCancel = vi.fn(() => new Promise(() => {}));
    const releaseLock = vi.fn();
    let registrationSignal;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/transactions') {
        return fallback(url, init);
      }
      registrationSignal = init.signal;
      return {
        body: {
          cancel: vi.fn(() => new Promise(() => {})),
          getReader: () => ({
            cancel: readerCancel,
            read: vi.fn(async () => ({ done: false, value: new Uint8Array(4_097) })),
            releaseLock,
          }),
        },
        headers: { get: () => 'application/json; charset=utf-8' },
        status: 201,
      };
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    let failure;
    const operation = client.connect().catch((error) => {
      failure = error;
      throw error;
    });
    operation.catch(() => {});

    await flushAsync(24);

    expect(failure).toMatchObject({ code: 'RELAY_ERROR' });
    expect(registrationSignal.aborted).toBe(true);
    expect(readerCancel).toHaveBeenCalledOnce();
    expect(releaseLock).toHaveBeenCalledOnce();
    await waitForLength(harness.cancellations, 1);
    await client.destroy();
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('the registration deadline settles a stalled reader even when it ignores abort', async () => {
    const harness = createHarness();
    const readerCancel = vi.fn(() => new Promise(() => {}));
    const releaseLock = vi.fn();
    let registrationSignal;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/transactions') {
        return fallback(url, init);
      }
      registrationSignal = init.signal;
      return {
        body: {
          cancel: vi.fn(() => new Promise(() => {})),
          getReader: () => ({
            cancel: readerCancel,
            read: vi.fn(() => new Promise(() => {})),
            releaseLock,
          }),
        },
        headers: { get: () => 'application/json; charset=utf-8' },
        status: 201,
      };
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    let failure;
    const operation = client.connect().catch((error) => {
      failure = error;
      throw error;
    });
    operation.catch(() => {});
    await flushAsync();

    await vi.advanceTimersByTimeAsync(30_000);
    await flushAsync(24);

    expect(failure).toMatchObject({ code: 'RELAY_ERROR' });
    expect(registrationSignal.aborted).toBe(true);
    expect(readerCancel).toHaveBeenCalledOnce();
    expect(releaseLock).toHaveBeenCalledOnce();
    await client.destroy();
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('keeps the registration abort bound active through a stalled 201 response body', async () => {
    const harness = createHarness();
    let registrationSignal;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/transactions') {
        return fallback(url, init);
      }
      registrationSignal = init.signal;
      return {
        body: {
          getReader: () => ({
            cancel: vi.fn(async () => {}),
            read: () => new Promise((_resolve, reject) => {
              init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
            }),
            releaseLock: vi.fn(),
          }),
        },
        headers: { get: () => 'application/json; charset=utf-8' },
        status: 201,
      };
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await flushAsync();
    expect(registrationSignal.aborted).toBe(false);

    await vi.advanceTimersByTimeAsync(30_000);
    await expect(operation).rejects.toMatchObject({ code: 'RELAY_ERROR' });
    expect(registrationSignal.aborted).toBe(true);
    await client.destroy();
  });

  test.each([
    {
      name: 'wrong media type',
      response: () => jsonResponse(201, {}, { contentType: 'text/plain' }),
      cancellation: true,
    },
    {
      name: 'missing stream reader',
      response: () => ({
        body: { cancel: vi.fn(async () => {}) },
        headers: { get: () => 'application/json; charset=utf-8' },
        status: 201,
      }),
      cancellation: true,
    },
    {
      name: 'rejected status',
      response: () => jsonResponse(403, { error: 'rejected' }),
      cancellation: false,
    },
    {
      name: 'JSON parse rejection',
      response: (transactionId) => jsonResponse(201, null, {
        raw: `{"expiresAt":"2026-07-21T12:05:00.000Z","schemaVersion":1,"schemaVersion":1,"transactionId":"${transactionId}"}`,
      }),
      cancellation: true,
    },
  ])('aborts and cancels the registration body on $name', async ({ response, cancellation }) => {
    const harness = createHarness();
    let relayResponse;
    let registrationSignal;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/transactions') {
        return fallback(url, init);
      }
      registrationSignal = init.signal;
      relayResponse = response(JSON.parse(init.body).transactionId);
      return relayResponse;
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });

    await expect(client.connect()).rejects.toMatchObject({ code: 'RELAY_ERROR' });
    if (cancellation) await waitForLength(harness.cancellations, 1);
    await client.destroy();

    expect(registrationSignal.aborted).toBe(true);
    expect(relayResponse.body.cancel).toHaveBeenCalledOnce();
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test.each([
    {
      name: 'wrong media type',
      response: () => jsonResponse(200, {}, { contentType: 'text/plain' }),
    },
    {
      name: 'missing stream reader',
      response: () => ({
        body: { cancel: vi.fn(async () => {}) },
        headers: { get: () => 'application/json; charset=utf-8' },
        status: 200,
      }),
    },
    {
      name: 'rejected status',
      response: () => jsonResponse(403, { error: 'rejected' }),
    },
    {
      name: 'JSON parse rejection',
      response: (transactionId) => jsonResponse(200, null, {
        raw: `{"result":{},"schemaVersion":1,"schemaVersion":1,"transactionId":"${transactionId}"}`,
      }),
    },
  ])('aborts and cancels the redeem body on $name', async ({ response }) => {
    const harness = createHarness();
    let relayResponse;
    let redeemSignal;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/codes/redeem') {
        return fallback(url, init);
      }
      redeemSignal = init.signal;
      relayResponse = response(JSON.parse(init.body).transactionId);
      return relayResponse;
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();

    await expect(operation).rejects.toMatchObject({ code: 'RELAY_ERROR' });
    await waitForLength(harness.cancellations, 1);
    await client.destroy();

    expect(redeemSignal.aborted).toBe(true);
    expect(relayResponse.body.cancel).toHaveBeenCalledOnce();
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('the transaction deadline releases a stalled redeem reader that ignores abort', async () => {
    const harness = createHarness({ registrationLifetimeMs: 1_000 });
    const readerCancel = vi.fn(() => new Promise(() => {}));
    const releaseLock = vi.fn();
    let redeemSignal;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/codes/redeem') {
        return fallback(url, init);
      }
      redeemSignal = init.signal;
      return {
        body: {
          cancel: vi.fn(() => new Promise(() => {})),
          getReader: () => ({
            cancel: readerCancel,
            read: vi.fn(() => new Promise(() => {})),
            releaseLock,
          }),
        },
        headers: { get: () => 'application/json; charset=utf-8' },
        status: 200,
      };
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();
    await flushAsync();

    await vi.advanceTimersByTimeAsync(1_000);
    await expect(operation).rejects.toMatchObject({ code: 'WALLET_NOT_COMPLETED' });
    await flushAsync(24);

    expect(redeemSignal.aborted).toBe(true);
    expect(readerCancel).toHaveBeenCalledOnce();
    expect(releaseLock).toHaveBeenCalledOnce();
    await client.destroy();
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('cancels and aborts every ignored cancellation response body', async () => {
    const harness = createHarness();
    let cancellationResponse;
    let cancellationSignal;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (!/\/cancel$/u.test(new URL(String(url)).pathname)) return fallback(url, init);
      cancellationSignal = init.signal;
      cancellationResponse = jsonResponse(204, {});
      return cancellationResponse;
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    operation.catch(() => {});
    await waitForLength(harness.registrations, 1);

    await client.disconnect();
    await expect(operation).rejects.toMatchObject({ code: 'DISCONNECTED' });
    await client.destroy();

    expect(cancellationSignal.aborted).toBe(true);
    expect(cancellationResponse.body.cancel).toHaveBeenCalledOnce();
    expect(harness.listenerCount('storage')).toBe(0);
    expect(vi.getTimerCount()).toBe(0);
  });

  test('successful registration and redeem abort exact controllers without cancelling consumed bodies', async () => {
    const harness = createHarness();
    const responses = [];
    const signals = [];
    harness.setCustomFetch(async (url, init, fallback) => {
      const response = await fallback(url, init);
      const pathname = new URL(String(url)).pathname;
      if (pathname === '/relay/v1/transactions' || pathname === '/relay/v1/codes/redeem') {
        responses.push(response);
        signals.push(init.signal);
      }
      return response;
    });
    harness.useRedeemResult(connectedResult());
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();

    await operation;

    expect(signals).toHaveLength(2);
    expect(signals.every((signal) => signal.aborted)).toBe(true);
    expect(responses.every((response) => response.body.cancel.mock.calls.length === 0)).toBe(true);
    await client.destroy();
  });

  test('treats an unreadable registration status as ambiguous relay failure and cancels', async () => {
    const harness = createHarness();
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/transactions') {
        return fallback(url, init);
      }
      return Object.defineProperty({}, 'status', {
        get() {
          throw new Error('hostile response status');
        },
      });
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });

    await expect(client.connect()).rejects.toMatchObject({ code: 'RELAY_ERROR' });
    await waitForLength(harness.cancellations, 1);
    expect(JSON.stringify(client.getSnapshot())).not.toContain('hostile response');
    await client.destroy();
  });

  test('rejects a registration response without a bounded byte stream', async () => {
    const harness = createHarness();
    let registration;
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/transactions') {
        return fallback(url, init);
      }
      registration = JSON.parse(init.body);
      return jsonResponseWithoutStream(201, {
        expiresAt: new Date(Date.now() + 300_000).toISOString(),
        schemaVersion: 1,
        transactionId: registration.transactionId,
      });
    });
    harness.useRedeemResult(connectedResult());
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    await flushAsync();
    harness.emitCallback(registration);

    await expect(operation).rejects.toMatchObject({ code: 'RELAY_ERROR' });
    await waitForLength(harness.cancellations, 1);
    await client.destroy();
  });

  test.each([
    {
      name: 'one byte over the registration cap',
      response: (transactionId) => {
        const raw = JSON.stringify({
          expiresAt: new Date(Date.now() + 300_000).toISOString(),
          schemaVersion: 1,
          transactionId,
        });
        return jsonResponse(201, null, { raw: `${raw}${' '.repeat(4_097 - raw.length)}` });
      },
    },
    {
      name: 'fatal UTF-8 in registration',
      response: () => jsonResponse(201, null, { rawBytes: Uint8Array.of(0xff) }),
    },
  ])('rejects $name before parsing JSON', async ({ response }) => {
    const harness = createHarness();
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/transactions') {
        return fallback(url, init);
      }
      return response(JSON.parse(init.body).transactionId);
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });

    await expect(client.connect()).rejects.toMatchObject({ code: 'RELAY_ERROR' });
    await waitForLength(harness.cancellations, 1);
    await client.destroy();
  });

  test.each([
    {
      name: 'missing redeem stream',
      response: (transactionId) => jsonResponseWithoutStream(200, {
        result: connectedResult(),
        schemaVersion: 1,
        transactionId,
      }),
    },
    {
      name: 'one byte over the redeem cap',
      response: (transactionId) => {
        const raw = JSON.stringify({
          result: connectedResult(),
          schemaVersion: 1,
          transactionId,
        });
        return jsonResponse(200, null, { raw: `${raw}${' '.repeat((70 * 1_024) + 1 - raw.length)}` });
      },
    },
    {
      name: 'fatal UTF-8 in redeem',
      response: () => jsonResponse(200, null, { rawBytes: Uint8Array.of(0xff) }),
    },
  ])('rejects a $name response before publishing a result', async ({ response }) => {
    const harness = createHarness();
    harness.setCustomFetch(async (url, init, fallback) => {
      if (new URL(String(url)).pathname !== '/relay/v1/codes/redeem') {
        return fallback(url, init);
      }
      return response(JSON.parse(init.body).transactionId);
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });
    const operation = client.connect();
    await waitForLength(harness.registrations, 1);
    harness.emitCallback();

    await expect(operation).rejects.toMatchObject({ code: 'RELAY_ERROR' });
    await waitForLength(harness.cancellations, 1);
    expect(client.getSnapshot()).toMatchObject({ identity: null, status: 'error' });
    await client.destroy();
  });

  test.each([
    {
      name: 'duplicate keys',
      response: (transactionId) => jsonResponse(201, null, {
        raw: `{"expiresAt":"2026-07-21T12:05:00.000Z","schemaVersion":1,"schemaVersion":1,"transactionId":"${transactionId}"}`,
      }),
    },
    {
      name: 'wrong media type',
      response: (transactionId) => jsonResponse(201, {
        expiresAt: '2026-07-21T12:05:00.000Z',
        schemaVersion: 1,
        transactionId,
      }, { contentType: 'text/plain' }),
    },
    {
      name: 'unknown field',
      response: (transactionId) => jsonResponse(201, {
        expiresAt: '2026-07-21T12:05:00.000Z',
        schemaVersion: 1,
        transactionId,
        verifier: 'must not be accepted',
      }),
    },
    {
      name: 'wrong transaction binding',
      response: () => jsonResponse(201, {
        expiresAt: '2026-07-21T12:05:00.000Z',
        schemaVersion: 1,
        transactionId: '9'.repeat(64),
      }),
    },
  ])('fails closed on $name without exposing the relay body', async ({ response }) => {
    const harness = createHarness();
    harness.setCustomFetch(async (url, init, fallback) => {
      const parsed = new URL(String(url));
      if (init.method === 'POST' && parsed.pathname === '/relay/v1/transactions') {
        return response(JSON.parse(init.body).transactionId);
      }
      return fallback(url, init);
    });
    const client = createWalletClient({ clientId: 'sdn-landing-web-v1' });

    const operation = client.connect();
    await expect(operation).rejects.toMatchObject({ code: 'RELAY_ERROR' });
    expect(client.getSnapshot()).toMatchObject({
      error: { code: 'RELAY_ERROR' },
      identity: null,
      status: 'error',
    });
    expect(JSON.stringify(client.getSnapshot())).not.toContain('verifier');
    await waitForLength(harness.cancellations, 1);
    await client.destroy();
  });
});
