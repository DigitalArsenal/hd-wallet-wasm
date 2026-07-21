import { readFile } from 'node:fs/promises';

import { describe, expect, test, vi } from 'vitest';

vi.mock('hd-wallet-wasm', () => ({
  getWalletOriginCapabilities(module) {
    const descriptor = Object.getOwnPropertyDescriptor(module, 'walletOriginCapabilities');
    if (!descriptor || descriptor.value !== module.__testBinding) throw new TypeError('invalid owner');
    return descriptor.value;
  },
}));

import {
  RememberedWalletError,
  canonicalizeWalletUsername,
  createRememberedWalletCoordinator,
} from '../origin-app/remember-wallet.mjs';
import { createRandomFiller } from '../origin-app/rng.mjs';
import {
  ACTIVE_REMEMBERED_WALLET_KEY,
  PENDING_REMEMBERED_WALLET_KEY,
  parseRememberedWalletRecord,
  serializeRememberedWalletRecord,
} from '../src/wallet-storage.js';

const vectors = JSON.parse(await readFile(
  new URL('../../test/fixtures/sdn-wallet-vectors.v1.json', import.meta.url),
  'utf8',
));

function usernameInput(row) {
  if (row.inputEncoding === 'utf8-hex') {
    return Uint8Array.from(row.inputHex.match(/../gu) ?? [], (pair) => Number.parseInt(pair, 16));
  }
  if (row.inputEncoding === 'utf16-code-units-be-hex') {
    const units = row.inputHex.match(/.{4}/gu) ?? [];
    return String.fromCharCode(...units.map((unit) => Number.parseInt(unit, 16)));
  }
  throw new Error(`unsupported fixture encoding: ${row.inputEncoding}`);
}

describe('remembered wallet username contract', () => {
  test.each(vectors.validationCases.username)('$name matches the frozen native fixture', (row) => {
    const input = usernameInput(row);
    if (row.accepted) {
      expect(canonicalizeWalletUsername(input)).toBe(row.canonicalUsername);
    } else {
      expect(() => canonicalizeWalletUsername(input)).toThrowError(/INVALID_USERNAME/u);
    }
  });

  test('rejects a real 260-byte username despite own buffer and byteLength decoys', () => {
    const input = new Uint8Array(260).fill(0x61);
    Object.defineProperties(input, {
      buffer: { value: new ArrayBuffer(32) },
      byteLength: { value: 32 },
    });

    expect(() => canonicalizeWalletUsername(input)).toThrowError(/INVALID_USERNAME/u);
  });
});

describe('remembered wallet entropy contract', () => {
  test('fills one fresh full-span buffer with one platform call', () => {
    const calls = [];
    const fillRandom = createRandomFiller({
      getRandomValues(bytes) {
        calls.push(bytes);
        bytes.fill(0x5a);
        return bytes;
      },
      observedWrite(bytes) {
        return bytes.every((byte) => byte === 0x5a);
      },
    });
    const output = new Uint8Array(32);

    expect(fillRandom(output)).toBe(output);
    expect(calls).toEqual([output]);
    expect([...output]).toEqual(Array(32).fill(0x5a));
  });

  test('rejects reuse before making another platform call', () => {
    let calls = 0;
    const fillRandom = createRandomFiller({
      getRandomValues(bytes) { calls += 1; return bytes; },
    });
    const output = new Uint8Array(12);
    fillRandom(output);

    expect(() => fillRandom(output)).toThrowError(/RNG_FAILURE/u);
    expect(calls).toBe(1);
  });

  test('rejects an aliasing full-span view over a consumed backing buffer', () => {
    let calls = 0;
    const fillRandom = createRandomFiller({
      getRandomValues(bytes) { calls += 1; return bytes; },
    });
    const buffer = new ArrayBuffer(32);
    fillRandom(new Uint8Array(buffer));

    expect(() => fillRandom(new Uint8Array(buffer))).toThrowError(/RNG_FAILURE/u);
    expect(calls).toBe(1);
  });

  test('rejects alias views despite distinct own buffer decoys', () => {
    let calls = 0;
    const fillRandom = createRandomFiller({
      getRandomValues(bytes) { calls += 1; return bytes; },
    });
    const backing = new ArrayBuffer(32);
    const first = new Uint8Array(backing);
    const second = new Uint8Array(backing);
    Object.defineProperty(first, 'buffer', { value: new ArrayBuffer(32) });
    Object.defineProperty(second, 'buffer', { value: new ArrayBuffer(32) });

    fillRandom(first);

    expect(() => fillRandom(second)).toThrowError(/RNG_FAILURE/u);
    expect(calls).toBe(1);
  });

  test.each([
    ['missing platform RNG', {}, new Uint8Array(32)],
    ['throwing platform RNG', { getRandomValues() { throw new Error('fault'); } }, new Uint8Array(32)],
    ['wrong returned buffer', { getRandomValues() { return new Uint8Array(32); } }, new Uint8Array(32)],
    ['no observed write', { getRandomValues(bytes) { return bytes; }, observedWrite() { return false; } }, new Uint8Array(32)],
    ['partial-span view', { getRandomValues(bytes) { return bytes; } }, new Uint8Array(33).subarray(1)],
    ['unexpected length', { getRandomValues(bytes) { return bytes; } }, new Uint8Array(16)],
  ])('rejects %s', (_name, platform, output) => {
    expect(() => createRandomFiller(platform)(output)).toThrowError(/RNG_FAILURE/u);
  });
});

function modernIdentity(overrides = {}) {
  const descriptor = (purpose, curve, path, signatureProfile, digit) => ({
    bip32Fingerprint: null,
    curve,
    derivation: 'slip10',
    encoding: 'raw',
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    keyId: `sha256:${digit.repeat(64)}`,
    path,
    publicKeyHex: digit.repeat(64),
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
      descriptor('asset-review-approval', 'ed25519', "m/44'/0'/0'/2'/0'", 'ed25519-over-sha256-jcs-v1', '2'),
      descriptor('contact-encryption', 'x25519', "m/44'/0'/0'/1'/0'", null, '3'),
      descriptor('sdn-authentication', 'ed25519', "m/44'/0'/0'/0'/0'", 'ed25519-over-sha256-jcs-v1', '4'),
    ],
    schemaVersion: 1,
    seedProfile: 'password-scrypt-v2',
    ...overrides,
  };
}

function fakeModule(capabilities, sha256 = () => new Uint8Array(32).fill(0x66)) {
  const binding = Object.freeze({ sdn: capabilities, sha256 });
  const module = { __testBinding: binding };
  Object.defineProperty(module, 'walletOriginCapabilities', {
    configurable: false,
    enumerable: false,
    value: binding,
    writable: false,
  });
  return module;
}

class MemoryStorage {
  constructor() { this.map = new Map(); this.operations = []; }
  getItem(key) { this.operations.push(['get', key]); return this.map.get(key) ?? null; }
  setItem(key, value) { this.operations.push(['set', key]); this.map.set(key, String(value)); }
  removeItem(key) { this.operations.push(['remove', key]); this.map.delete(key); }
}

function ordinaryBuffer(bytes) {
  const copy = Uint8Array.from(bytes);
  return copy.buffer;
}

class BrowserCredential {
  #extensions;
  #rawId;

  constructor(rawId, extensions) {
    this.#rawId = rawId instanceof ArrayBuffer || (typeof SharedArrayBuffer === 'function'
      && rawId instanceof SharedArrayBuffer)
      ? rawId
      : ordinaryBuffer(rawId);
    this.#extensions = extensions;
  }

  get rawId() { return this.#rawId; }
  get type() { return 'public-key'; }
  getClientExtensionResults() { return this.#extensions; }
}

function base64url(bytes) {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
}

function storedRecord({ credentialId, prfInput, usernameSha256 = '66'.repeat(32) }) {
  const credentialIdBase64url = base64url(credentialId);
  return {
    aad: {
      credentialIdBase64url,
      identityScheme: 'sdn-bip32-slip10-purpose-v1',
      schemaVersion: 2,
      seedProfile: 'password-scrypt-v2',
      storageProfile: 'webauthn-prf-hkdf-sha256-aes256gcm-v2',
      usernameSha256,
    },
    canonicalUsername: 'alice_01',
    ciphertextBase64url: base64url(new Uint8Array(64).fill(0x7c)),
    createdAt: '2026-07-21T12:00:00.000Z',
    credentialIdBase64url,
    hkdfSaltBase64url: base64url(new Uint8Array(32).fill(0x20)),
    nonceBase64url: base64url(new Uint8Array(12).fill(0x40)),
    prfInputBase64url: base64url(prfInput),
    schemaVersion: 2,
    storageProfile: 'webauthn-prf-hkdf-sha256-aes256gcm-v2',
  };
}

function setupHarness(options = {}) {
  const identity = options.identity ?? modernIdentity();
  const credentialId = options.credentialId ?? new Uint8Array(32).fill(0xa1);
  const prfOutput = options.prfOutput ?? new Uint8Array(32).fill(0xb2);
  const storage = options.storage ?? new MemoryStorage();
  const owned = new Set(['source-handle']);
  const destroyed = [];
  const calls = [];
  const sealInputs = [];
  const openInputs = [];
  let verificationIndex = 0;
  const hasOption = (name) => Object.prototype.hasOwnProperty.call(options, name);
  const creationRawId = hasOption('creationRawId')
    ? options.creationRawId
    : ordinaryBuffer(credentialId);
  const assertionRawId = hasOption('assertionRawId')
    ? options.assertionRawId
    : ordinaryBuffer(credentialId);
  const creationExtensions = hasOption('creationExtensions')
    ? options.creationExtensions
    : { prf: { enabled: true } };
  const assertionExtensions = hasOption('assertionExtensions')
    ? options.assertionExtensions
    : { prf: { results: { first: ordinaryBuffer(prfOutput) } } };
  const capabilities = {
    sealRememberedIdentity(handle, input) {
      calls.push('seal');
      sealInputs.push(input);
      if (typeof options.seal === 'function') return options.seal(handle, input);
      return new Uint8Array(64).fill(0x7c);
    },
    importRememberedIdentity(input) {
      calls.push('open');
      openInputs.push(input);
      if (typeof options.open === 'function') return options.open(input, owned);
      verificationIndex += 1;
      return {
        handle: `verification-${verificationIndex}`,
        identity: typeof options.openIdentity === 'function'
          ? options.openIdentity()
          : options.openIdentity ?? identity,
      };
    },
  };
  const requestControllers = [];
  const coordinator = createRememberedWalletCoordinator({
    createRequestController() {
      const controller = new AbortController();
      requestControllers.push(controller);
      return controller;
    },
    credentials: {
      async create(request) {
        calls.push('create');
        if (typeof options.create === 'function') return options.create(request);
        return new BrowserCredential(creationRawId, creationExtensions);
      },
      async get(request) {
        calls.push('get');
        if (typeof options.get === 'function') return options.get(request);
        return new BrowserCredential(assertionRawId, assertionExtensions);
      },
    },
    destroyHandle(handle) {
      destroyed.push(handle);
      if (typeof options.destroyHandle === 'function'
          && options.destroyHandle(handle, destroyed.length) === false) return false;
      owned.delete(handle);
      return true;
    },
    module: fakeModule(capabilities, options.sha256),
    now: () => new Date('2026-07-21T12:00:00.000Z'),
    ownHandle(handle) { owned.add(handle); },
    ownedHandlesClean(source) { return owned.size === 1 && owned.has(source); },
    releaseRequestController: () => {},
    rng: options.rng ?? {
      getRandomValues(bytes) { bytes.fill(0x5a); return bytes; },
      observedWrite: () => true,
    },
    storage,
  });
  const setup = (passwordUtf8 = new TextEncoder().encode('Correct Horse Battery Staple!'), extra = {}) => (
    coordinator.setup({
      assertCurrent: options.assertCurrent ?? (() => {}),
      canonicalUsername: 'alice_01',
      handle: 'source-handle',
      identity,
      passwordUtf8,
      ...extra,
    })
  );
  return {
    calls,
    coordinator,
    credentialId,
    destroyed,
    identity,
    openInputs,
    owned,
    requestControllers,
    sealInputs,
    setup,
    storage,
  };
}

describe('PRF-only remembered wallet coordinator', () => {
  test('missing setup lifecycle owners fail before WebAuthn or native import', async () => {
    let platformCalls = 0;
    let importCalls = 0;
    const coordinator = createRememberedWalletCoordinator({
      createRequestController: () => new AbortController(),
      credentials: {
        create() { platformCalls += 1; },
        get() { platformCalls += 1; },
      },
      module: fakeModule({
        importRememberedIdentity() { importCalls += 1; },
        sealRememberedIdentity() { return new Uint8Array(64); },
      }),
      rng: { getRandomValues(bytes) { return bytes; } },
      releaseRequestController: () => {},
      storage: new MemoryStorage(),
    });
    const password = new TextEncoder().encode('Correct Horse Battery Staple!');

    await expect(coordinator.setup({
      assertCurrent: () => {},
      canonicalUsername: 'alice_01',
      handle: 'source-handle',
      identity: modernIdentity(),
      passwordUtf8: password,
    })).rejects.toMatchObject({ code: 'REMEMBER_UNAVAILABLE' });
    expect(platformCalls).toBe(0);
    expect(importCalls).toBe(0);
    expect(password.every((byte) => byte === 0)).toBe(true);
  });

  test('missing restore lifecycle owners fail before WebAuthn or native import', async () => {
    let platformCalls = 0;
    let importCalls = 0;
    const credentialId = new Uint8Array(32).fill(0xa1);
    const storage = new MemoryStorage();
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, serializeRememberedWalletRecord(storedRecord({
      credentialId,
      prfInput: new Uint8Array(32).fill(0x55),
    })));
    const coordinator = createRememberedWalletCoordinator({
      createRequestController: () => new AbortController(),
      credentials: {
        create() { platformCalls += 1; },
        get() { platformCalls += 1; },
      },
      module: fakeModule({
        importRememberedIdentity() { importCalls += 1; },
        sealRememberedIdentity() { return new Uint8Array(64); },
      }),
      rng: { getRandomValues(bytes) { return bytes; } },
      releaseRequestController: () => {},
      storage,
    });

    await expect(coordinator.restore({ assertCurrent: () => {} })).rejects.toMatchObject({
      code: 'REMEMBER_UNAVAILABLE',
    });
    expect(platformCalls).toBe(0);
    expect(importCalls).toBe(0);
  });

  test('uses the exact creation/assertion requests and commits only a verified identity', async () => {
    const identity = modernIdentity();
    const owned = new Set(['source-handle']);
    const destroyed = [];
    const requests = [];
    const randomRequests = [];
    let fillValue = 1;
    const credentialId = Uint8Array.from({ length: 32 }, (_unused, index) => 0xa0 + index);
    const prfOutput = Uint8Array.from({ length: 32 }, (_unused, index) => index);
    const storage = new MemoryStorage();
    const capabilities = {
      sealRememberedIdentity(handle, input) {
        expect(handle).toBe('source-handle');
        expect(Object.keys(input).sort()).toEqual([
          'canonicalAad', 'hkdfSalt', 'nonce', 'passwordUtf8', 'prfOutput',
        ]);
        return new Uint8Array(64).fill(0x7c);
      },
      importRememberedIdentity() {
        return {
          handle: 'verification-handle',
          get identity() {
            expect(owned.has('verification-handle')).toBe(true);
            return identity;
          },
        };
      },
    };
    const module = fakeModule(capabilities);
    const credentials = {
      async create(options) {
        requests.push(['create', options]);
        return new BrowserCredential(credentialId, { prf: { enabled: true } });
      },
      async get(options) {
        requests.push(['get', {
          ...options,
          publicKey: {
            ...options.publicKey,
            allowCredentials: [{
              ...options.publicKey.allowCredentials[0],
              id: options.publicKey.allowCredentials[0].id.slice(),
            }],
            extensions: {
              prf: {
                eval: { first: options.publicKey.extensions.prf.eval.first.slice() },
              },
            },
          },
        }]);
        return new BrowserCredential(credentialId, {
          prf: { results: { first: ordinaryBuffer(prfOutput) } },
        });
      },
    };
    const abortController = new AbortController();
    const coordinator = createRememberedWalletCoordinator({
      createRequestController: () => abortController,
      credentials,
      destroyHandle(handle) {
        destroyed.push(handle);
        owned.delete(handle);
        return true;
      },
      module,
      now: () => new Date('2026-07-21T12:00:00.000Z'),
      ownHandle(handle) { owned.add(handle); },
      ownedHandlesClean(source) { return owned.size === 1 && owned.has(source); },
      releaseRequestController: () => {},
      rng: {
        getRandomValues(bytes) {
          randomRequests.push(bytes);
          bytes.fill(fillValue++);
          return bytes;
        },
        observedWrite: () => true,
      },
      storage,
    });
    const passwordUtf8 = new TextEncoder().encode('Correct Horse Battery Staple!');

    const result = await coordinator.setup({
      assertCurrent: () => {},
      canonicalUsername: 'alice_01',
      handle: 'source-handle',
      identity,
      passwordUtf8,
    });

    expect(result.remembered).toBe(true);
    expect(passwordUtf8.every((byte) => byte === 0)).toBe(true);
    expect(destroyed).toEqual(['verification-handle']);
    expect(randomRequests.map((bytes) => bytes.length)).toEqual([32, 32, 32, 32, 12, 32]);
    expect(new Set(randomRequests).size).toBe(6);
    expect(requests.map(([method]) => method)).toEqual(['create', 'get']);
    const creation = requests[0][1];
    expect(Object.keys(creation).sort()).toEqual(['publicKey', 'signal']);
    expect(creation.signal).toBe(abortController.signal);
    expect(creation.publicKey).toMatchObject({
      attestation: 'none',
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      extensions: { prf: {} },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },
        { alg: -257, type: 'public-key' },
      ],
      rp: { id: 'wallet.spacedatanetwork.org', name: 'Space Data Network Wallet' },
      timeout: 120000,
      user: { displayName: 'alice_01', name: 'alice_01' },
    });
    expect(Object.keys(creation.publicKey.authenticatorSelection).sort()).toEqual([
      'residentKey', 'userVerification',
    ]);
    const assertion = requests[1][1];
    expect(Object.keys(assertion).sort()).toEqual(['publicKey', 'signal']);
    expect(assertion.signal).toBe(abortController.signal);
    expect(assertion.publicKey).toMatchObject({
      allowCredentials: [{ id: credentialId, type: 'public-key' }],
      extensions: { prf: { eval: { first: expect.any(Uint8Array) } } },
      rpId: 'wallet.spacedatanetwork.org',
      timeout: 120000,
      userVerification: 'required',
    });
    expect(Object.keys(assertion.publicKey.allowCredentials[0]).sort()).toEqual(['id', 'type']);
    const active = storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY);
    expect(parseRememberedWalletRecord(active).canonicalUsername).toBe('alice_01');
    expect(storage.map.has(PENDING_REMEMBERED_WALLET_KEY)).toBe(false);
    expect(storage.operations.at(-1)).toEqual(['set', ACTIVE_REMEMBERED_WALLET_KEY]);
  });

  test('restores only through a fresh PRF assertion and owns the imported handle immediately', async () => {
    const identity = modernIdentity();
    const credentialId = new Uint8Array(32).fill(0xa1);
    const prfInput = new Uint8Array(32).fill(0xb2);
    const prfOutput = new Uint8Array(32).fill(0xc3);
    const storage = new MemoryStorage();
    storage.map.set(
      ACTIVE_REMEMBERED_WALLET_KEY,
      serializeRememberedWalletRecord(storedRecord({ credentialId, prfInput })),
    );
    const owned = new Set();
    const calls = [];
    const module = fakeModule({
      sealRememberedIdentity() { throw new Error('not used'); },
      importRememberedIdentity(input) {
        calls.push(['import', input]);
        return {
          handle: 'restored-handle',
          get identity() {
            expect(owned.has('restored-handle')).toBe(true);
            return identity;
          },
        };
      },
    });
    const coordinator = createRememberedWalletCoordinator({
      createRequestController: () => new AbortController(),
      credentials: {
        async create() { throw new Error('not used'); },
        async get(options) {
          calls.push(['get', {
            ...options,
            publicKey: {
              ...options.publicKey,
              allowCredentials: [{
                ...options.publicKey.allowCredentials[0],
                id: options.publicKey.allowCredentials[0].id.slice(),
              }],
              extensions: {
                prf: {
                  eval: { first: options.publicKey.extensions.prf.eval.first.slice() },
                },
              },
            },
          }]);
          return {
            type: 'public-key',
            rawId: ordinaryBuffer(credentialId),
            getClientExtensionResults: () => ({
              prf: { results: { first: ordinaryBuffer(prfOutput) } },
            }),
          };
        },
      },
      destroyHandle: () => true,
      module,
      ownHandle: (handle) => owned.add(handle),
      ownedHandlesClean: () => true,
      releaseRequestController: () => {},
      rng: {
        getRandomValues(bytes) { bytes.fill(0xd4); return bytes; },
        observedWrite: () => true,
      },
      storage,
    });

    const restored = await coordinator.restore({ assertCurrent: () => {} });

    expect(restored).toEqual({ handle: 'restored-handle', identity });
    expect(owned).toEqual(new Set(['restored-handle']));
    expect(calls.map(([name]) => name)).toEqual(['get', 'import']);
    expect(calls[0][1].publicKey.allowCredentials[0].id).toEqual(credentialId);
    expect(calls[0][1].publicKey.extensions.prf.eval.first).toEqual(prfInput);
    expect(storage.map.has(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(true);
  });

  test.each([
    ['missing creation PRF result', {}],
    ['false creation PRF result', { prf: { enabled: false } }],
  ])('rejects %s before sealing or persistence', async (_name, creationExtensions) => {
    const test = setupHarness({ creationExtensions });
    const password = new TextEncoder().encode('Correct Horse Battery Staple!');

    await expect(test.setup(password)).rejects.toMatchObject({ code: 'WEBAUTHN_PRF_REQUIRED' });
    expect(test.calls).toEqual(['create']);
    expect(test.storage.map.size).toBe(0);
    expect(password.every((byte) => byte === 0)).toBe(true);
    expect(test.owned).toEqual(new Set(['source-handle']));
  });

  test('rejects an accessor-backed creation PRF result without rereading it', async () => {
    let reads = 0;
    const creationExtensions = {};
    Object.defineProperty(creationExtensions, 'prf', {
      enumerable: true,
      get() {
        reads += 1;
        return reads === 1 ? { enabled: true } : { enabled: false };
      },
    });
    const test = setupHarness({ creationExtensions });

    await expect(test.setup()).rejects.toMatchObject({ code: 'WEBAUTHN_PRF_REQUIRED' });
    expect(reads).toBe(0);
    expect(test.calls).toEqual(['create']);
    expect(test.storage.map.size).toBe(0);
  });

  test('copies rawId with the intrinsic operation instead of an own hostile slice', async () => {
    const credentialId = new Uint8Array(32).fill(0xa1);
    const creationRawId = ordinaryBuffer(credentialId);
    Object.defineProperty(creationRawId, 'slice', {
      configurable: true,
      value: () => ordinaryBuffer(new Uint8Array(32).fill(0xff)),
      writable: true,
    });
    const test = setupHarness({ creationRawId, credentialId });

    await test.setup();

    const active = parseRememberedWalletRecord(test.storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY));
    expect(active.credentialIdBase64url).toBe(base64url(credentialId));
  });

  test.each([
    ['non-ordinary rawId', new (class extends ArrayBuffer {})(32)],
    ['empty rawId', new ArrayBuffer(0)],
    ['oversized rawId', new ArrayBuffer(1025)],
    ['shared rawId', typeof SharedArrayBuffer === 'function' ? new SharedArrayBuffer(32) : 'invalid'],
  ])('rejects a %s before reading PRF results or persisting', async (_name, creationRawId) => {
    const test = setupHarness({ creationRawId });

    await expect(test.setup()).rejects.toMatchObject({ code: 'WEBAUTHN_INVALID_RESPONSE' });
    expect(test.calls).toEqual(['create']);
    expect(test.storage.map.size).toBe(0);
  });

  test('rejects an accessor-backed assertion PRF buffer without a second read', async () => {
    let reads = 0;
    const results = {};
    Object.defineProperty(results, 'first', {
      enumerable: true,
      get() {
        reads += 1;
        return reads === 1
          ? ordinaryBuffer(new Uint8Array(32).fill(0x7a))
          : typeof SharedArrayBuffer === 'function' ? new SharedArrayBuffer(32) : new ArrayBuffer(31);
      },
    });
    const test = setupHarness({ assertionExtensions: { prf: { results } } });

    await expect(test.setup()).rejects.toMatchObject({ code: 'WEBAUTHN_PRF_REQUIRED' });
    expect(reads).toBe(0);
    expect(test.calls).toEqual(['create', 'get']);
    expect(test.storage.map.size).toBe(0);
  });

  test('copies then immediately wipes the platform PRF result buffer', async () => {
    const first = ordinaryBuffer(new Uint8Array(32).fill(0x9a));
    const test = setupHarness({
      assertionExtensions: { prf: { results: { first } } },
    });

    await test.setup();

    expect([...new Uint8Array(first)]).toEqual(Array(32).fill(0));
  });

  test('compares assertion rawId before reading extension results', async () => {
    let extensionReads = 0;
    const wrong = new Uint8Array(32).fill(0xff);
    const test = setupHarness({
      get: async () => ({
        type: 'public-key',
        rawId: ordinaryBuffer(wrong),
        getClientExtensionResults() {
          extensionReads += 1;
          return { prf: { results: { first: ordinaryBuffer(new Uint8Array(32)) } } };
        },
      }),
    });

    await expect(test.setup()).rejects.toMatchObject({ code: 'WEBAUTHN_CREDENTIAL_MISMATCH' });
    expect(extensionReads).toBe(0);
    expect(test.storage.map.size).toBe(0);
  });

  test.each([
    ['typed-array PRF view', new Uint8Array(32)],
    ['short PRF buffer', new ArrayBuffer(31)],
    ['long PRF buffer', new ArrayBuffer(33)],
    ['string PRF', 'not-secret-material'],
  ])('rejects a %s', async (_name, first) => {
    const test = setupHarness({
      assertionExtensions: { prf: { results: { first } } },
    });

    await expect(test.setup()).rejects.toMatchObject({ code: 'WEBAUTHN_PRF_REQUIRED' });
    expect(test.calls).toEqual(['create', 'get']);
    expect(test.storage.map.size).toBe(0);
  });

  test.each([0, 257])('rejects a %i-byte remembered password before platform or persistence', async (length) => {
    const test = setupHarness();
    const password = new Uint8Array(length).fill(0x61);

    await expect(test.setup(password)).rejects.toMatchObject({ code: 'REMEMBER_UNAVAILABLE' });
    expect(test.calls).toEqual([]);
    expect(test.storage.map.size).toBe(0);
    expect(password.every((byte) => byte === 0)).toBe(true);
  });

  test('wipes the caller password when public identity validation fails before WebAuthn', async () => {
    const test = setupHarness({ identity: { schemaVersion: 1 } });
    const password = new TextEncoder().encode('Correct Horse Battery Staple!');

    await expect(test.setup(password)).rejects.toBeDefined();
    expect(password.every((byte) => byte === 0)).toBe(true);
    expect(test.calls).toEqual([]);
    expect(test.storage.map.size).toBe(0);
  });

  test('wipes the caller password when storage inspection quarantines setup before WebAuthn', async () => {
    const storage = new MemoryStorage();
    storage.map.set(PENDING_REMEMBERED_WALLET_KEY, '{"crash":true}');
    const test = setupHarness({ storage });
    const password = new TextEncoder().encode('Correct Horse Battery Staple!');

    await expect(test.setup(password)).rejects.toMatchObject({ code: 'STORAGE_QUARANTINED' });
    expect(password.every((byte) => byte === 0)).toBe(true);
    expect(test.calls).toEqual([]);
  });

  test('wipes the caller password when canonical username validation fails before WebAuthn', async () => {
    const test = setupHarness();
    const password = new TextEncoder().encode('Correct Horse Battery Staple!');

    await expect(test.setup(password, { canonicalUsername: 'Not Canonical' })).rejects.toBeDefined();
    expect(password.every((byte) => byte === 0)).toBe(true);
    expect(test.calls).toEqual([]);
  });

  test('native open failure leaves the prior active record authoritative and pending quarantined', async () => {
    const credentialId = new Uint8Array(32).fill(0xa1);
    const prfInput = new Uint8Array(32).fill(0x55);
    const previous = serializeRememberedWalletRecord(storedRecord({ credentialId, prfInput }));
    const storage = new MemoryStorage();
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, previous);
    const test = setupHarness({
      open() { throw new Error('authenticated open failed'); },
      storage,
    });

    await expect(test.setup()).rejects.toThrowError(/authenticated open failed/u);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(previous);
    expect(storage.map.has(PENDING_REMEMBERED_WALLET_KEY)).toBe(true);
    expect(test.owned).toEqual(new Set(['source-handle']));
    expect(test.openInputs[0].prfOutput.every((byte) => byte === 0)).toBe(true);
  });

  test('identity mismatch after open destroys the verification handle and keeps only the source', async () => {
    const test = setupHarness({
      openIdentity: () => modernIdentity({ accountXpub: `xpub${'9'.repeat(107)}` }),
    });

    await expect(test.setup()).rejects.toMatchObject({ code: 'IDENTITY_MISMATCH' });
    expect(test.destroyed).toEqual(['verification-1']);
    expect(test.owned).toEqual(new Set(['source-handle']));
    expect(test.storage.map.has(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(false);
    expect(test.storage.map.has(PENDING_REMEMBERED_WALLET_KEY)).toBe(true);
  });

  test('repeated successful replacement never leaves more than the one source handle', async () => {
    const test = setupHarness();

    await test.setup();
    await test.setup();

    expect(test.destroyed).toEqual(['verification-1', 'verification-2']);
    expect(test.owned).toEqual(new Set(['source-handle']));
    expect(test.sealInputs).toHaveLength(2);
    expect(test.openInputs).toHaveLength(2);
    for (const input of [...test.sealInputs, ...test.openInputs]) {
      expect(input.prfOutput.every((byte) => byte === 0)).toBe(true);
    }
  });

  test('a final active write fault preserves the prior active after verified open cleanup', async () => {
    const credentialId = new Uint8Array(32).fill(0xa1);
    const previous = serializeRememberedWalletRecord(storedRecord({
      credentialId,
      prfInput: new Uint8Array(32).fill(0x55),
    }));
    const storage = new MemoryStorage();
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, previous);
    const originalSet = storage.setItem.bind(storage);
    storage.setItem = (key, value) => {
      if (key === ACTIVE_REMEMBERED_WALLET_KEY) throw new Error('active write fault');
      originalSet(key, value);
    };
    const test = setupHarness({ storage });

    await expect(test.setup()).rejects.toThrowError(/active write fault/u);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(previous);
    expect(test.destroyed).toEqual(['verification-1']);
    expect(test.owned).toEqual(new Set(['source-handle']));
  });

  test('a pending write fault preserves the prior active and never opens a candidate', async () => {
    const credentialId = new Uint8Array(32).fill(0xa1);
    const previous = serializeRememberedWalletRecord(storedRecord({
      credentialId,
      prfInput: new Uint8Array(32).fill(0x55),
    }));
    const storage = new MemoryStorage();
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, previous);
    const originalSet = storage.setItem.bind(storage);
    storage.setItem = (key, value) => {
      if (key === PENDING_REMEMBERED_WALLET_KEY) throw new Error('pending write fault');
      originalSet(key, value);
    };
    const test = setupHarness({ storage });

    await expect(test.setup()).rejects.toThrowError(/pending write fault/u);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(previous);
    expect(test.calls).toEqual(['create', 'get', 'seal']);
    expect(test.openInputs).toHaveLength(0);
    expect(test.owned).toEqual(new Set(['source-handle']));
  });

  test('restore cancellation leaves the exact active record untouched', async () => {
    const credentialId = new Uint8Array(32).fill(0xa1);
    const active = serializeRememberedWalletRecord(storedRecord({
      credentialId,
      prfInput: new Uint8Array(32).fill(0x55),
    }));
    const storage = new MemoryStorage();
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, active);
    const cancellation = new Error('user cancelled');
    const test = setupHarness({ get: async () => { throw cancellation; }, storage });

    await expect(test.coordinator.restore({ assertCurrent: () => {} })).rejects.toBe(cancellation);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(active);
    expect(storage.map.size).toBe(1);
    expect(test.calls).toEqual(['get']);
  });

  test('username-hash tamper fails before WebAuthn and leaves the active record untouched', async () => {
    const credentialId = new Uint8Array(32).fill(0xa1);
    const active = serializeRememberedWalletRecord(storedRecord({
      credentialId,
      prfInput: new Uint8Array(32).fill(0x55),
      usernameSha256: '00'.repeat(32),
    }));
    const storage = new MemoryStorage();
    storage.map.set(ACTIVE_REMEMBERED_WALLET_KEY, active);
    const test = setupHarness({ storage });

    await expect(test.coordinator.restore({ assertCurrent: () => {} })).rejects.toMatchObject({
      code: 'INVALID_REMEMBERED_WALLET',
    });
    expect(test.calls).toEqual([]);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(active);
  });

  test('lifecycle abort rejects a late assertion before persistence and wipes the password', async () => {
    let stale = false;
    const test = setupHarness({
      assertCurrent() { if (stale) throw new RememberedWalletError('STALE_CONTROLLER'); },
      get(request) {
        return new Promise((_resolve, reject) => {
          request.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
        });
      },
    });
    const password = new TextEncoder().encode('Correct Horse Battery Staple!');
    const pending = test.setup(password);
    await vi.waitFor(() => expect(test.calls).toContain('get'));
    stale = true;
    test.requestControllers[0].abort();

    await expect(pending).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
    expect(test.storage.map.size).toBe(0);
    expect(password.every((byte) => byte === 0)).toBe(true);
    expect(test.owned).toEqual(new Set(['source-handle']));
  });
});
