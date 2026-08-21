import { readFile } from 'node:fs/promises';

import { describe, expect, test } from 'vitest';
import { vi } from 'vitest';

vi.mock('hd-wallet-wasm', () => ({
  getWalletOriginCapabilities(module) {
    if (module?.__rejectCapabilities === true) throw new TypeError('invalid owner');
    const descriptor = Object.getOwnPropertyDescriptor(module ?? {}, 'walletOriginCapabilities');
    if (descriptor) {
      if (descriptor.value !== module.__testBinding) throw new TypeError('invalid owner');
      return descriptor.value;
    }
    const sdn = module?.sdn ?? module;
    const hashOwner = module?.utils ?? module;
    if (!sdn || typeof hashOwner?.sha256 !== 'function') throw new TypeError('invalid owner');
    return Object.freeze({ sdn, sha256: hashOwner.sha256.bind(hashOwner) });
  },
}));

import { resolveRegistryBinding, verifyRegistry } from '../origin-app/registry.mjs';
import { ApprovalConfigurationController } from '../origin-app/account.mjs';
import { WalletOriginController } from '../origin-app/controller.mjs';
import { requestTrustedConfirmation, validateWalletTransaction } from '../origin-app/operations.mjs';
import { createPasswordCredentialPrompt, createWalletOriginApp } from '../origin-app/app.mjs';
import { createSameOriginWalletRelay } from '../origin-app/relay.mjs';
import {
  ACTIVE_REMEMBERED_WALLET_KEY,
  LEGACY_WALLET_QUARANTINE_KEYS,
  PENDING_REMEMBERED_WALLET_KEY,
  serializeRememberedWalletRecord,
} from '../src/wallet-storage.js';

const registryReleaseSha256 = verifyRegistry().registryReleaseSha256;
const sdnWalletVectors = JSON.parse(await readFile(
  new URL('../../test/fixtures/sdn-wallet-vectors.v1.json', import.meta.url),
  'utf8',
));

function digestBytes(hex) {
  return Uint8Array.from(hex.match(/../gu) ?? [], (pair) => Number.parseInt(pair, 16));
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

class FakeEventTarget {
  constructor() {
    this.listeners = new Map();
  }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(listener);
  }

  removeEventListener(type, listener) {
    this.listeners.get(type)?.delete(listener);
  }

  dispatch(type, event = {}) {
    for (const listener of [...(this.listeners.get(type) ?? [])]) listener(event);
  }
}

class FakeNode extends FakeEventTarget {
  constructor(tagName, ownerDocument) {
    super();
    this.tagName = tagName;
    this.ownerDocument = ownerDocument;
    this.children = [];
    this.parentNode = null;
    this.dataset = {};
    this.attributes = new Map();
    this.className = '';
    this.disabled = false;
    this.inert = false;
    this._textContent = '';
  }

  append(...children) {
    for (const child of children) {
      child.parentNode = this;
      this.children.push(child);
      if (this.tagName === 'form') {
        const associate = (node) => {
          if (node.tagName === 'input' || node.tagName === 'textarea') node.form = this;
          node.children.forEach(associate);
        };
        associate(child);
      }
    }
  }

  appendChild(child) {
    this.append(child);
    return child;
  }

  replaceChildren(...children) {
    for (const child of this.children) child.parentNode = null;
    this.children = [];
    this.append(...children);
  }

  remove() {
    if (!this.parentNode) return;
    this.parentNode.children = this.parentNode.children.filter((child) => child !== this);
    this.parentNode = null;
  }

  replaceWith(replacement) {
    if (!this.parentNode) return;
    const index = this.parentNode.children.indexOf(this);
    this.parentNode.children[index] = replacement;
    replacement.parentNode = this.parentNode;
    this.parentNode = null;
  }

  setAttribute(name, value) {
    this.attributes.set(name, String(value));
  }

  getAttribute(name) {
    return this.attributes.get(name) ?? null;
  }

  removeAttribute(name) {
    this.attributes.delete(name);
  }

  contains(candidate) {
    if (candidate === this) return true;
    return this.children.some((child) => child.contains?.(candidate));
  }

  focus() {
    this.ownerDocument.activeElement = this;
  }

  querySelectorAll(selector) {
    if (selector !== 'input, textarea') return [];
    const output = [];
    const visit = (node) => {
      if (node.tagName === 'input' || node.tagName === 'textarea') output.push(node);
      node.children.forEach(visit);
    };
    this.children.forEach(visit);
    return output;
  }

  set textContent(value) {
    this._textContent = String(value);
    this.replaceChildren();
  }

  get textContent() {
    return this._textContent + this.children.map((child) => child.textContent).join('');
  }
}

class FakeDocument extends FakeEventTarget {
  constructor() {
    super();
    this.visibilityState = 'visible';
    this.body = new FakeNode('body', this);
    this.activeElement = this.body;
  }

  createElement(tagName) {
    return new FakeNode(tagName.toLowerCase(), this);
  }

  createTextNode(value) {
    const node = new FakeNode('#text', this);
    node._textContent = String(value);
    return node;
  }

  hasFocus() {
    return true;
  }

  findAction(action) {
    let found = null;
    const visit = (node) => {
      if (node.dataset.walletAction === action) found = node;
      node.children.forEach(visit);
    };
    visit(this.body);
    return found;
  }

  find(predicate) {
    let found = null;
    const visit = (node) => {
      if (!found && predicate(node)) found = node;
      node.children.forEach(visit);
    };
    visit(this.body);
    return found;
  }

  findAll(predicate) {
    const found = [];
    const visit = (node) => {
      if (predicate(node)) found.push(node);
      node.children.forEach(visit);
    };
    visit(this.body);
    return found;
  }
}

function fakeWindow(document) {
  const target = new FakeEventTarget();
  target.top = target;
  target.document = document;
  target.crypto = globalThis.crypto;
  target.location = { pathname: '/', reload: () => { target.reloads += 1; } };
  target.reloads = 0;
  return target;
}

function approvalControls(username = 'alice', password = 'correct horse battery staple') {
  const form = { parentNode: { remove() {} } };
  const control = (value) => ({
    defaultValue: value,
    disabled: false,
    form,
    inert: false,
    removeAttribute() {},
    setCustomValidity() {},
    setSelectionRange() {},
    value,
  });
  return {
    passwordControl: control(password),
    usernameControl: control(username),
  };
}

function identity(seed = '1') {
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
    accountPeerId: `16Uiu2H${seed.repeat(40)}`,
    accountXpub: `xpub${seed.repeat(107)}`,
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    keys: [
      descriptor('asset-review-approval', 'ed25519', "m/44'/0'/0'/2'/0'", 'ed25519-over-sha256-jcs-v1', '2'),
      descriptor('contact-encryption', 'x25519', "m/44'/0'/0'/1'/0'", null, '3'),
      descriptor('sdn-authentication', 'ed25519', "m/44'/0'/0'/0'/0'", 'ed25519-over-sha256-jcs-v1', '4'),
    ],
    schemaVersion: 1,
    seedProfile: 'password-scrypt-v2',
  };
}

function rememberedBase64url(length, value) {
  let binary = '';
  for (const byte of new Uint8Array(length).fill(value)) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
}

function validRememberedRecord() {
  const credentialIdBase64url = rememberedBase64url(32, 0xa1);
  return serializeRememberedWalletRecord({
    aad: {
      credentialIdBase64url,
      identityScheme: 'sdn-bip32-slip10-purpose-v1',
      schemaVersion: 2,
      seedProfile: 'password-scrypt-v2',
      storageProfile: 'webauthn-prf-hkdf-sha256-aes256gcm-v2',
      usernameSha256: '66'.repeat(32),
    },
    canonicalUsername: 'alice_01',
    ciphertextBase64url: rememberedBase64url(64, 0x7c),
    createdAt: '2026-07-21T12:00:00.000Z',
    credentialIdBase64url,
    hkdfSaltBase64url: rememberedBase64url(32, 0x20),
    nonceBase64url: rememberedBase64url(12, 0x40),
    prfInputBase64url: rememberedBase64url(32, 0x60),
    schemaVersion: 2,
    storageProfile: 'webauthn-prf-hkdf-sha256-aes256gcm-v2',
  });
}

function memoryStorage(entries = []) {
  const map = new Map(entries);
  const operations = [];
  return {
    getItem(key) {
      operations.push(['getItem', key]);
      return map.get(key) ?? null;
    },
    map,
    operations,
    removeItem(key) {
      operations.push(['removeItem', key]);
      map.delete(key);
    },
    setItem(key, value) {
      operations.push(['setItem', key, String(value)]);
      map.set(key, String(value));
    },
  };
}

describe('ApprovalConfigurationController terminal ownership', () => {
  test('destroy synchronously wipes controller-owned round bytes and never prompts round 2', async () => {
    const derivation = deferred();
    const rounds = [];
    let captured = null;
    const controller = new ApprovalConfigurationController({
      credentialRound: async (round) => {
        rounds.push(round);
        return approvalControls();
      },
      expectedIdentity: identity(),
      wasm: {
        derivePasswordIdentity(input) {
          captured = input;
          return derivation.promise;
        },
        destroySdnIdentity() {},
      },
    });

    const confirmation = controller.confirm();
    await until(() => captured);
    expect([...captured.usernameUtf8]).not.toEqual(
      Array(captured.usernameUtf8.length).fill(0),
    );
    controller.destroy();
    expect([...captured.usernameUtf8]).toEqual(Array(captured.usernameUtf8.length).fill(0));
    expect([...captured.passwordUtf8]).toEqual(Array(captured.passwordUtf8.length).fill(0));
    derivation.resolve({ handle: 'late-round-1', identity: identity() });

    await expect(confirmation).rejects.toMatchObject({
      code: 'CREDENTIAL_CONFIRMATION_MISMATCH',
    });
    expect(rounds).toEqual([1]);
    await expect(controller.confirm()).rejects.toMatchObject({
      code: 'CREDENTIAL_CONFIRMATION_MISMATCH',
    });
    expect(rounds).toEqual([1]);
  });

  test('in-flight clear retains a late handle owner until persistent native cleanup succeeds', async () => {
    const derivation = deferred();
    let captured = null;
    let cleanupAllowed = false;
    let cleanupAttempts = 0;
    const controller = new ApprovalConfigurationController({
      credentialRound: async () => approvalControls(),
      expectedIdentity: identity(),
      wasm: {
        derivePasswordIdentity(input) {
          captured = input;
          return derivation.promise;
        },
        destroySdnIdentity() {
          cleanupAttempts += 1;
          if (!cleanupAllowed) throw new Error('persistent native cleanup failure');
        },
      },
    });

    const confirmation = controller.confirm();
    await until(() => captured);
    expect(controller.clear()).toBe(false);
    expect([...captured.usernameUtf8]).toEqual(Array(captured.usernameUtf8.length).fill(0));
    expect([...captured.passwordUtf8]).toEqual(Array(captured.passwordUtf8.length).fill(0));

    derivation.resolve({ handle: 'late-approval-handle', identity: identity() });
    await expect(confirmation).rejects.toMatchObject({
      code: 'CREDENTIAL_CONFIRMATION_MISMATCH',
    });
    expect(cleanupAttempts).toBeGreaterThan(0);
    expect(controller.destroy()).toBe(false);
    cleanupAllowed = true;
    expect(controller.destroy()).toBe(true);
  });

  test('round-1 teardown reentry is checked before requesting round 2', async () => {
    const rounds = [];
    let controller;
    controller = new ApprovalConfigurationController({
      credentialRound: async (round) => {
        rounds.push(round);
        return approvalControls();
      },
      expectedIdentity: identity(),
      wasm: {
        async derivePasswordIdentity() {
          return { handle: 'round-1', identity: identity() };
        },
        destroySdnIdentity() {
          controller.clear();
        },
      },
    });

    await expect(controller.confirm()).rejects.toMatchObject({
      code: 'CREDENTIAL_CONFIRMATION_MISMATCH',
    });
    expect(rounds).toEqual([1]);
  });

  test('round-2 teardown reentry is checked before confirmation is installed', async () => {
    const rounds = [];
    let controller;
    controller = new ApprovalConfigurationController({
      credentialRound: async (round) => {
        rounds.push(round);
        return approvalControls();
      },
      expectedIdentity: identity(),
      wasm: {
        async derivePasswordIdentity() {
          return { handle: `round-${rounds.length}`, identity: identity() };
        },
        destroySdnIdentity(handle) {
          if (handle === 'round-2') controller.clear();
        },
      },
    });

    await expect(controller.confirm()).rejects.toMatchObject({
      code: 'CREDENTIAL_CONFIRMATION_MISMATCH',
    });
    expect(rounds).toEqual([1, 2]);
    expect(controller.confirmed).toBeNull();
  });

  test('terminal clear and repeated destroy retry a retained handle until destruction succeeds', async () => {
    const rounds = [];
    let attempts = 0;
    let allowDestruction = false;
    const controller = new ApprovalConfigurationController({
      credentialRound: async (round) => {
        rounds.push(round);
        return approvalControls();
      },
      expectedIdentity: identity(),
      wasm: {
        async derivePasswordIdentity() {
          return { handle: 'retained-round-1', identity: identity() };
        },
        destroySdnIdentity() {
          attempts += 1;
          if (!allowDestruction) throw new Error('persistent native cleanup failure');
        },
      },
    });

    await expect(controller.confirm()).rejects.toMatchObject({
      code: 'CREDENTIAL_CONFIRMATION_MISMATCH',
    });
    const attemptsAfterConfirmation = attempts;
    controller.clear();
    controller.destroy();
    expect(attempts).toBeGreaterThan(attemptsAfterConfirmation);
    allowDestruction = true;
    controller.destroy();
    const successfulAttempt = attempts;
    controller.clear();
    expect(attempts).toBe(successfulAttempt);
    await expect(controller.confirm()).rejects.toMatchObject({
      code: 'CREDENTIAL_CONFIRMATION_MISMATCH',
    });
    expect(rounds).toEqual([1]);
  });
});

function legacyIdentity() {
  return {
    accountFingerprint: '9876abcd',
    accountIndex: 0,
    accountLabel: null,
    accountPeerId: `16Uiu2H${'9'.repeat(40)}`,
    accountXpub: `xpub${'9'.repeat(107)}`,
    identityScheme: 'sdn-fast-password-auth-v1-legacy',
    keys: [{
      bip32Fingerprint: null,
      curve: 'ed25519',
      derivation: 'bip32-scalar-as-ed25519-seed',
      encoding: 'raw',
      identityScheme: 'sdn-fast-password-auth-v1-legacy',
      keyId: `sha256:${'9'.repeat(64)}`,
      path: "m/44'/0'/0'/0/0",
      publicKeyHex: '9'.repeat(64),
      purpose: 'sdn-authentication',
      seedProfile: 'password-fast-v1-legacy',
      signatureProfile: 'ed25519-raw-32-v1',
    }],
    schemaVersion: 1,
    seedProfile: 'password-fast-v1-legacy',
  };
}

function controls(document, username, password) {
  const form = document.createElement('form');
  const usernameControl = document.createElement('input');
  const passwordControl = document.createElement('input');
  for (const [control, value] of [[usernameControl, username], [passwordControl, password]]) {
    control.value = value;
    control.defaultValue = value;
    control.setAttribute('name', 'credential');
    control.setAttribute('autocomplete', 'current-password');
    control.form = form;
    control.selectionStart = 1;
    control.selectionEnd = 2;
    control.setSelectionRange = (start, end) => {
      control.selectionStart = start;
      control.selectionEnd = end;
    };
    control.setCustomValidity = (value) => { control.validationMessage = value; };
    form.append(control);
  }
  document.body.append(form);
  return { form, passwordControl, usernameControl };
}

function transaction(now = Date.now()) {
  const issuedAt = new Date(now).toISOString();
  const expiresAt = new Date(now + 60_000).toISOString();
  return {
    callbackUri: 'https://sdn.spaceaware.io/wallet/callback',
    clientDisplayName: 'SDN Node Console',
    clientId: 'sdn-node-console-v1',
    expiresAt,
    operation: 'sdn.auth.jcs-envelope.v2',
    registryVersion: registryReleaseSha256,
    request: {
      audience: 'sdn-login:sdn.spaceaware.io',
      challengeBase64url: 'A'.repeat(43),
      expiresAt,
      issuedAt,
      nonce: 'a'.repeat(64),
      protocolVersion: 2,
    },
    requestOrigin: 'https://sdn.spaceaware.io',
    requestSha256: 'b'.repeat(64),
    resultToken: 'C'.repeat(43),
    schemaVersion: 1,
    state: 'd'.repeat(64),
    transactionId: 'e'.repeat(64),
  };
}

function publicTransaction(operation, now = Date.now()) {
  const expiresAt = new Date(now + 60_000).toISOString();
  return {
    callbackUri: 'https://spacedatanetwork.org/wallet-callback.html',
    clientDisplayName: 'Space Data Network',
    clientId: 'sdn-landing-web-v1',
    expiresAt,
    operation,
    registryVersion: registryReleaseSha256,
    request: {},
    requestOrigin: 'https://spacedatanetwork.org',
    requestSha256: 'b'.repeat(64),
    resultToken: 'C'.repeat(43),
    schemaVersion: 1,
    state: 'd'.repeat(64),
    transactionId: 'e'.repeat(64),
  };
}

function relayJsonResponse(value, { raw = null, status = 200 } = {}) {
  return new Response(raw ?? JSON.stringify(value), {
    headers: {
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
    },
    status,
  });
}

function relayCompletion(transaction, override = {}) {
  const code = override.code ?? 'f'.repeat(64);
  return {
    redirectUri: `${transaction.callbackUri}#code=${code}&state=${transaction.state}`,
    schemaVersion: 1,
    transactionId: transaction.transactionId,
    ...override,
  };
}

async function until(predicate) {
  for (let attempt = 0; attempt < 50; attempt += 1) {
    const value = predicate();
    if (value) return value;
    await Promise.resolve();
    if (attempt % 10 === 9) await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error('condition was not reached');
}

describe('same-origin production wallet relay', () => {
  test('uses the exact same-origin GET/result schemas and replaces location only on explicit navigation', async () => {
    const value = publicTransaction('sdn.wallet.connect.v1');
    const calls = [];
    const replacements = [];
    const relay = createSameOriginWalletRelay({
      async fetch(url, options) {
        calls.push({ options, url });
        if (options.method === 'GET') return relayJsonResponse(value);
        return relayJsonResponse(relayCompletion(value), { status: 201 });
      },
      location: { replace(redirectUri) { replacements.push(redirectUri); } },
    });
    const fetched = await relay.fetchTransaction(value.transactionId);
    expect(fetched).toEqual(value);
    const result = Object.freeze({ identity: { accountIndex: 0 }, schemaVersion: 1, status: 'connected' });
    const completion = await relay.publishResult(value, result);
    expect(replacements).toEqual([]);
    relay.navigate(completion.redirectUri);
    expect(replacements).toEqual([relayCompletion(value).redirectUri]);
    expect(calls).toHaveLength(2);
    expect(calls[0]).toMatchObject({
      url: `/relay/v1/transactions/${value.transactionId}`,
      options: {
        cache: 'no-store',
        credentials: 'omit',
        method: 'GET',
        mode: 'same-origin',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
      },
    });
    expect(calls[1]).toMatchObject({
      url: `/relay/v1/transactions/${value.transactionId}/result`,
      options: {
        cache: 'no-store',
        credentials: 'omit',
        method: 'POST',
        mode: 'same-origin',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
      },
    });
    expect(JSON.parse(calls[1].options.body)).toEqual({
      result,
      resultToken: value.resultToken,
      schemaVersion: 1,
      transactionId: value.transactionId,
    });
  });

  test.each([
    ['wrong status', () => relayJsonResponse({}, { status: 201 })],
    ['wrong media type', () => new Response('{}', { status: 200 })],
    ['unknown field', (value) => relayJsonResponse({ ...value, extra: true })],
    ['duplicate field', (value) => relayJsonResponse(null, {
      raw: JSON.stringify(value).replace('{', `{"schemaVersion":1,`),
    })],
  ])('rejects a malformed transaction response: %s', async (_label, responseFor) => {
    const value = publicTransaction('sdn.wallet.connect.v1');
    const relay = createSameOriginWalletRelay({
      fetch: async () => responseFor(value),
      location: { replace() { throw new Error('must not navigate'); } },
    });
    await expect(relay.fetchTransaction(value.transactionId)).rejects.toMatchObject({
      code: 'RELAY_FAILURE',
      message: 'RELAY_FAILURE',
    });
  });

  test.each([
    ['wrong transaction', (value) => ({ ...relayCompletion(value), transactionId: '0'.repeat(64) })],
    ['wrong callback', (value) => ({ ...relayCompletion(value), redirectUri: `https://attacker.invalid/#code=${'f'.repeat(64)}&state=${value.state}` })],
    ['wrong state', (value) => ({ ...relayCompletion(value), redirectUri: `${value.callbackUri}#code=${'f'.repeat(64)}&state=${'0'.repeat(64)}` })],
    ['noncanonical code', (value) => ({ ...relayCompletion(value), redirectUri: `${value.callbackUri}#code=${'F'.repeat(64)}&state=${value.state}` })],
    ['extra fragment field', (value) => ({ ...relayCompletion(value), redirectUri: `${relayCompletion(value).redirectUri}&extra=1` })],
    ['unknown response field', (value) => ({ ...relayCompletion(value), extra: true })],
  ])('rejects completion with %s before navigation', async (_label, completionFor) => {
    const value = publicTransaction('sdn.wallet.connect.v1');
    const replacements = [];
    const relay = createSameOriginWalletRelay({
      fetch: async () => relayJsonResponse(completionFor(value), { status: 201 }),
      location: { replace(redirectUri) { replacements.push(redirectUri); } },
    });
    await expect(relay.publishResult(value, { schemaVersion: 1 })).rejects.toMatchObject({
      code: 'RELAY_FAILURE',
    });
    expect(replacements).toEqual([]);
  });

  test.each(['fetch', 'reader'])('abort settles a never-resolving hostile %s and suppresses cancel rejection', async (phase) => {
    const value = publicTransaction('sdn.wallet.connect.v1');
    const abort = new AbortController();
    let cancelCalls = 0;
    const never = new Promise(() => {});
    const hostileResponse = {
      body: {
        getReader() {
          return {
            cancel() {
              cancelCalls += 1;
              return Promise.reject(new Error('hostile cancel rejection'));
            },
            read() { return never; },
            releaseLock() {},
          };
        },
      },
      headers: {
        get(name) {
          if (name === 'cache-control') return 'no-store';
          if (name === 'content-type') return 'application/json; charset=utf-8';
          return null;
        },
      },
      redirected: false,
      status: 200,
    };
    const relay = createSameOriginWalletRelay({
      fetch: () => phase === 'fetch' ? never : hostileResponse,
      location: { replace() {} },
    });
    const pending = relay.fetchTransaction(value.transactionId, { signal: abort.signal });
    await Promise.resolve();
    abort.abort();
    await expect(pending).rejects.toMatchObject({ code: 'RELAY_FAILURE' });
    await Promise.resolve();
    await Promise.resolve();
    expect(cancelCalls).toBe(phase === 'reader' ? 1 : 0);
  });
});

function fixture() {
  const document = new FakeDocument();
  const window = fakeWindow(document);
  const derives = [];
  const destroyed = [];
  const published = [];
  const sign = deferred();
  let signCalls = 0;
  const wasm = {
    derivePasswordIdentity(input) {
      const call = deferred();
      call.input = input;
      derives.push(call);
      return call.promise;
    },
    destroySdnIdentity(handle) {
      destroyed.push(handle);
    },
    signSdnLoginV2() {
      signCalls += 1;
      return sign.promise;
    },
    sha256() {
      return new Uint8Array(32).fill(0xbb);
    },
  };
  const relay = {
    async fetchTransaction(value) { return value; },
    async hashRequest() { throw new Error('relay hashing must not be used'); },
    async publishResult(_transaction, result) { published.push(result); },
  };
  const controller = new WalletOriginController({
    document,
    registry: { resolveRegistryBinding: (lookup) => {
      expect(lookup).toEqual({
        clientId: 'sdn-node-console-v1',
        operation: 'sdn.auth.jcs-envelope.v2',
        requestOrigin: 'https://sdn.spaceaware.io',
      });
      return {
        audience: 'sdn-login:sdn.spaceaware.io',
        callbackUri: 'https://sdn.spaceaware.io/wallet/callback',
        clientDisplayName: 'SDN Node Console',
        clientId: 'sdn-node-console-v1',
        maxLifetimeSeconds: 300,
        operation: 'sdn.auth.jcs-envelope.v2',
        requestOrigin: 'https://sdn.spaceaware.io',
        registryReleaseSha256,
        registryRow: 'sdn-node-console-v2',
        serviceActivationState: null,
        serviceInstance: null,
      };
    } },
    relay,
    rng: { fillRandom: () => { throw new Error('not needed'); } },
    wasm,
    window,
  });
  return {
    controller,
    derives,
    destroyed,
    document,
    get signCalls() { return signCalls; },
    identity: identity(),
    published,
    relay,
    sign,
    wasm,
    window,
  };
}

describe('modern password prompt remembered-wallet control', () => {
  test('shows Remember on this device visibly and unchecked on supported platforms', () => {
    const document = new FakeDocument();
    createPasswordCredentialPrompt({
      controller: {
        registerCredentialControls() {},
        supportsRememberedWallet: () => true,
      },
      document,
    });

    const remember = document.find((node) => node.dataset.walletRemember === 'prf-only');
    expect(remember).toBeTruthy();
    expect(remember.type).toBe('checkbox');
    expect(remember.checked).toBe(false);
    expect(remember.defaultChecked).toBe(false);
    expect(remember.disabled).toBe(false);
    expect(remember.parentNode.textContent).toContain('Remember on this device');
  });

  test('keeps the visible Remember control unselectable on unsupported platforms', () => {
    const document = new FakeDocument();
    createPasswordCredentialPrompt({
      controller: {
        registerCredentialControls() {},
        supportsRememberedWallet: () => false,
      },
      document,
    });

    const remember = document.find((node) => node.dataset.walletRemember === 'prf-only');
    expect(remember).toBeTruthy();
    expect(remember.disabled).toBe(true);
    expect(remember.checked).toBe(false);
    expect(remember.defaultChecked).toBe(false);
  });

  test('offers remembered restore only as an explicit trusted action', async () => {
    const document = new FakeDocument();
    const prompt = createPasswordCredentialPrompt({
      controller: {
        canRestoreRememberedWallet: () => true,
        registerCredentialControls() {},
        supportsRememberedWallet: () => true,
      },
      document,
    });
    const unlock = document.findAction('unlock-remembered');
    expect(unlock).toBeTruthy();
    let settled = false;
    prompt.promise.then(() => { settled = true; });

    unlock.dispatch('click', { isTrusted: false });
    await Promise.resolve();
    expect(settled).toBe(false);
    unlock.dispatch('click', { isTrusted: true });

    await expect(prompt.promise).resolves.toMatchObject({ remembered: true });
  });

  test('lists every classified quarantine and uses trusted bounded export and exact deletion', async () => {
    const document = new FakeDocument();
    const keys = [
      ACTIVE_REMEMBERED_WALLET_KEY,
      PENDING_REMEMBERED_WALLET_KEY,
      ...LEGACY_WALLET_QUARANTINE_KEYS,
    ];
    let entries = keys.map((key) => ({
      exportable: true,
      key,
      oversized: false,
      rawLength: 17,
    }));
    const deleted = [];
    const writes = [];
    const controller = {
      canRestoreRememberedWallet: () => !entries.some(({ key }) => key === PENDING_REMEMBERED_WALLET_KEY),
      deleteQuarantinedWalletRecord(key, confirmation) {
        expect(confirmation).toBe(key);
        deleted.push(key);
        entries = entries.filter((entry) => entry.key !== key);
      },
      exportQuarantinedWalletRecord: (key) => `raw:${key}:<img onerror=attack>`,
      generation: 7,
      isUiGenerationCurrent: (generation) => generation === 7,
      listQuarantinedWalletRecords: () => entries,
      registerCredentialControls() {},
      supportsRememberedWallet: () => true,
    };
    createPasswordCredentialPrompt({
      clipboard: { async writeText(value) { writes.push(value); } },
      controller,
      document,
    });

    const labels = document.findAll((node) => node.dataset.walletQuarantineLabel === 'true');
    expect(labels.map((node) => node.textContent)).toEqual(keys);
    expect(document.body.textContent).not.toContain('<img onerror=attack>');
    const pendingExport = document.find((node) => (
      node.dataset.walletAction === 'export-quarantined-wallet'
      && node.dataset.walletQuarantineKey === PENDING_REMEMBERED_WALLET_KEY
    ));
    pendingExport.dispatch('click', { isTrusted: false });
    await Promise.resolve();
    expect(writes).toEqual([]);
    pendingExport.dispatch('click', { isTrusted: true });
    await until(() => writes.length === 1);
    expect(writes[0]).toBe(`raw:${PENDING_REMEMBERED_WALLET_KEY}:<img onerror=attack>`);

    const launchDelete = document.find((node) => (
      node.dataset.walletAction === 'delete-quarantined-wallet'
      && node.dataset.walletQuarantineKey === PENDING_REMEMBERED_WALLET_KEY
    ));
    const confirmation = document.find((node) => (
      node.dataset.walletQuarantineConfirmation === PENDING_REMEMBERED_WALLET_KEY
    ));
    const confirmDelete = document.find((node) => (
      node.dataset.walletAction === 'confirm-delete-quarantined-wallet'
      && node.dataset.walletQuarantineKey === PENDING_REMEMBERED_WALLET_KEY
    ));
    expect(confirmDelete.parentNode.hidden).toBe(true);
    launchDelete.dispatch('click', { isTrusted: false });
    expect(confirmDelete.parentNode.hidden).toBe(true);
    launchDelete.dispatch('click', { isTrusted: true });
    expect(confirmDelete.parentNode.hidden).toBe(false);
    confirmation.value = 'wrong';
    confirmDelete.dispatch('click', { isTrusted: true });
    expect(deleted).toEqual([]);
    confirmation.value = PENDING_REMEMBERED_WALLET_KEY;
    confirmDelete.dispatch('click', { isTrusted: false });
    expect(deleted).toEqual([]);
    confirmDelete.dispatch('click', { isTrusted: true });
    await until(() => deleted.length === 1);
    expect(deleted).toEqual([PENDING_REMEMBERED_WALLET_KEY]);
    expect(document.findAction('unlock-remembered')).toBeTruthy();
    expect(document.findAction('login')).toBeTruthy();
  });

  test('late quarantine clipboard completion cannot mutate a removed prompt', async () => {
    const document = new FakeDocument();
    const write = deferred();
    const controller = {
      canRestoreRememberedWallet: () => false,
      exportQuarantinedWalletRecord: () => 'bounded quarantine',
      generation: 2,
      isUiGenerationCurrent: (generation) => generation === 2,
      listQuarantinedWalletRecords: () => [{
        exportable: true,
        key: PENDING_REMEMBERED_WALLET_KEY,
        oversized: false,
        rawLength: 18,
      }],
      registerCredentialControls() {},
      supportsRememberedWallet: () => true,
    };
    const prompt = createPasswordCredentialPrompt({
      clipboard: { writeText: () => write.promise },
      controller,
      document,
    });
    const exportButton = document.findAction('export-quarantined-wallet');
    const status = document.find((node) => node.dataset.walletQuarantineStatus === 'true');
    const confirmation = document.find((node) => (
      node.dataset.walletQuarantineConfirmation === PENDING_REMEMBERED_WALLET_KEY
    ));
    confirmation.value = PENDING_REMEMBERED_WALLET_KEY;
    exportButton.dispatch('click', { isTrusted: true });
    prompt.remove();
    expect(confirmation.value).toBe('');
    expect(status.textContent).toBe('');
    write.resolve();
    await Promise.resolve();
    await Promise.resolve();
    expect(status.textContent).toBe('');
    expect(document.findAction('login')).toBeNull();
  });
});

describe('WalletOriginController generation and handle ownership', () => {
  test('origin quarantine APIs exclude valid active storage from generic management', () => {
    const document = new FakeDocument();
    const window = fakeWindow(document);
    const active = validRememberedRecord();
    const storage = memoryStorage([[ACTIVE_REMEMBERED_WALLET_KEY, active]]);
    const controller = new WalletOriginController({
      document,
      registry: {},
      relay: {},
      storage,
      wasm: {
        derivePasswordIdentity() {},
        destroySdnIdentity() {},
        sha256() { return new Uint8Array(32); },
      },
      window,
    });

    expect(controller.listQuarantinedWalletRecords()).toEqual([]);
    expect(() => controller.deleteQuarantinedWalletRecord(
      ACTIVE_REMEMBERED_WALLET_KEY,
      ACTIVE_REMEMBERED_WALLET_KEY,
    )).toThrowError(/NOT_QUARANTINED/u);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(active);
  });

  test('rejects a forged cross-module capability owner before platform or raw calls', () => {
    const document = new FakeDocument();
    const window = fakeWindow(document);
    let rawCalls = 0;
    let platformCalls = 0;

    expect(() => new WalletOriginController({
      credentials: {
        create() { platformCalls += 1; },
        get() { platformCalls += 1; },
      },
      document,
      registry: {},
      relay: {},
      rng: { getRandomValues(bytes) { return bytes; } },
      storage: { getItem: () => null, removeItem() {}, setItem() {} },
      wasm: {
        __rejectCapabilities: true,
        derivePasswordIdentity() { rawCalls += 1; },
        destroySdnIdentity() { rawCalls += 1; },
        sha256() { rawCalls += 1; return new Uint8Array(32); },
      },
      window,
    })).toThrowError(/WASM_UNAVAILABLE/u);
    expect(rawCalls).toBe(0);
    expect(platformCalls).toBe(0);
  });

  test('selected Remember owns two distinct password copies and preserves the fresh source handle', async () => {
    const document = new FakeDocument();
    const window = fakeWindow(document);
    const storageMap = new Map();
    const storage = {
      getItem: (key) => storageMap.get(key) ?? null,
      removeItem: (key) => storageMap.delete(key),
      setItem: (key, value) => storageMap.set(key, String(value)),
    };
    const passwordCopies = [];
    const destroyed = [];
    const credentialId = new Uint8Array(32).fill(0xa1);
    const prfOutput = new Uint8Array(32).fill(0xb2);
    const rawId = () => credentialId.slice().buffer;
    const wasm = {
      async derivePasswordIdentity(input) {
        passwordCopies.push(input.passwordUtf8);
        return { handle: 'source-handle', identity: identity() };
      },
      destroySdnIdentity(handle) { destroyed.push(handle); },
      importRememberedIdentity() {
        return { handle: 'verification-handle', identity: identity() };
      },
      sealRememberedIdentity(_handle, input) {
        passwordCopies.push(input.passwordUtf8);
        return new Uint8Array(64).fill(0x7c);
      },
      sha256() { return new Uint8Array(32).fill(0x66); },
    };
    const credentials = {
        async create() {
          return {
            type: 'public-key',
            rawId: rawId(),
            getClientExtensionResults: () => ({ prf: { enabled: true } }),
          };
        },
        async get() {
          return {
            type: 'public-key',
            rawId: rawId(),
            getClientExtensionResults: () => ({
              prf: { results: { first: prfOutput.slice().buffer } },
            }),
          };
        },
      };
    const controllerConfiguration = {
      credentials,
      document,
      registry: {},
      relay: {},
      rng: {
        getRandomValues(bytes) { bytes.fill(0x5a); return bytes; },
        observedWrite: () => true,
      },
      storage,
      wasm,
      window,
    };
    const controller = new WalletOriginController(controllerConfiguration);
    const controls = approvalControls('  ALICE  ', 'correct horse battery staple');
    controls.rememberControl = { checked: true, disabled: false };
    controls.rememberStatus = { textContent: '' };

    await controller.unlockPassword(controls);

    expect(passwordCopies).toHaveLength(2);
    expect(passwordCopies[0]).not.toBe(passwordCopies[1]);
    expect(passwordCopies.every((bytes) => bytes.every((byte) => byte === 0))).toBe(true);
    expect(destroyed).toEqual(['verification-handle']);
    expect(storageMap.has(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(true);
    expect(controls.rememberStatus.textContent).toBe('Wallet remembered on this device.');

    controller.revokeNow('replacement');
    const restoredController = new WalletOriginController(controllerConfiguration);
    await expect(restoredController.unlockRemembered()).resolves.toEqual(identity());
    expect(restoredController.copyPublicIdentity()).toEqual(identity());
    expect(destroyed).toEqual(['verification-handle', 'source-handle']);
  });

  test('an auxiliary remembered handle cleanup failure destroys the source and grants no publication', async () => {
    const document = new FakeDocument();
    const window = fakeWindow(document);
    const storageMap = new Map();
    const destroyAttempts = [];
    let publications = 0;
    const credentialId = new Uint8Array(32).fill(0xa1);
    const controller = new WalletOriginController({
      credentials: {
        async create() {
          return {
            type: 'public-key',
            rawId: credentialId.slice().buffer,
            getClientExtensionResults: () => ({ prf: { enabled: true } }),
          };
        },
        async get() {
          return {
            type: 'public-key',
            rawId: credentialId.slice().buffer,
            getClientExtensionResults: () => ({
              prf: { results: { first: new Uint8Array(32).fill(0xb2).buffer } },
            }),
          };
        },
      },
      document,
      registry: {},
      relay: { publishResult() { publications += 1; } },
      rng: {
        getRandomValues(bytes) { bytes.fill(0x5a); return bytes; },
        observedWrite: () => true,
      },
      storage: {
        getItem: (key) => storageMap.get(key) ?? null,
        removeItem: (key) => storageMap.delete(key),
        setItem: (key, value) => storageMap.set(key, String(value)),
      },
      wasm: {
        async derivePasswordIdentity() {
          return { handle: 'source-handle', identity: identity() };
        },
        destroySdnIdentity(handle) {
          destroyAttempts.push(handle);
          if (handle === 'verification-handle') throw new Error('persistent cleanup fault');
        },
        importRememberedIdentity() {
          return { handle: 'verification-handle', identity: identity() };
        },
        sealRememberedIdentity() { return new Uint8Array(64).fill(0x7c); },
        sha256() { return new Uint8Array(32).fill(0x66); },
      },
      window,
    });
    const controls = approvalControls('alice', 'correct horse battery staple');
    controls.rememberControl = { checked: true, disabled: false };
    controls.rememberStatus = { textContent: '' };

    await expect(controller.unlockPassword(controls)).rejects.toMatchObject({
      code: 'DESTRUCTION_FAILED',
    });
    await expect(controller.execute({})).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
    expect(destroyAttempts).toContain('source-handle');
    expect(destroyAttempts.filter((handle) => handle === 'verification-handle').length).toBeGreaterThan(1);
    expect(publications).toBe(0);
    expect(storageMap.has(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(false);
  });

  test('confirmation traps keyboard focus, rejects untrusted keys, and restores prior focus', async () => {
    const document = new FakeDocument();
    const prior = document.createElement('button');
    document.body.append(prior);
    prior.focus();
    const confirmation = requestTrustedConfirmation({
      binding: {
        clientDisplayName: 'Space Data Network',
        operation: 'sdn.wallet.connect.v1',
        requestOrigin: 'https://spacedatanetwork.org',
      },
      document,
      request: {},
    });
    const confirm = document.findAction('confirm');
    const cancel = document.findAction('cancel');
    const root = confirm.parentNode.parentNode;
    const heading = root.children[0];
    expect(root.getAttribute('role')).toBe('dialog');
    expect(root.getAttribute('aria-labelledby')).toBe('wallet-confirmation-heading');
    expect(heading.id).toBe('wallet-confirmation-heading');
    expect(document.activeElement).toBe(confirm);
    cancel.focus();
    root.dispatch('keydown', { isTrusted: false, key: 'Tab', preventDefault() {} });
    expect(document.activeElement).toBe(cancel);
    root.dispatch('keydown', { isTrusted: true, key: 'Tab', preventDefault() {} });
    expect(document.activeElement).toBe(confirm);
    const outside = document.createElement('input');
    document.body.append(outside);
    outside.focus();
    document.dispatch('focusin', { target: outside });
    expect(document.activeElement).toBe(confirm);
    confirmation.destroy();
    expect(document.activeElement).toBe(prior);
  });

  test('uses the validated request snapshot even if the relay input mutates during hashing', async () => {
    const input = transaction();
    const originalNonce = input.request.nonce;
    const binding = {
      callbackUri: input.callbackUri,
      clientDisplayName: input.clientDisplayName,
      clientId: input.clientId,
      maxLifetimeSeconds: 300,
      operation: input.operation,
      requestOrigin: input.requestOrigin,
      registryReleaseSha256,
    };
    let hashedRequest = null;
    const validated = await validateWalletTransaction(input, {
      registry: { resolveRegistryBinding: () => binding },
      relay: { async hashRequest() {
        throw new Error('relay hashing must not be used');
      } },
      sha256(bytes) {
        hashedRequest = new TextDecoder().decode(bytes);
        input.request.nonce = 'f'.repeat(64);
        return new Uint8Array(32).fill(0xbb);
      },
      window: { crypto: globalThis.crypto },
    });
    expect(hashedRequest).toContain(`"nonce":"${originalNonce}"`);
    expect(validated.request.nonce).toBe(originalNonce);
    expect(validated.transaction.request.nonce).toBe(originalNonce);
  });

  test.each(['resolve', 'reject'])(
    'password B synchronously retires remembered setup A before its WebAuthn create can %s',
    async (settlement) => {
      const document = new FakeDocument();
      const window = fakeWindow(document);
      const creation = deferred();
      const destroyed = [];
      const deriveInputs = [];
      let creationRequest = null;
      let deriveCalls = 0;
      const controller = new WalletOriginController({
        credentials: {
          create(request) {
            creationRequest = request;
            return creation.promise;
          },
          get() { throw new Error('stale setup must not request an assertion'); },
        },
        document,
        registry: {},
        relay: {},
        rng: {
          getRandomValues(bytes) { bytes.fill(0x5a); return bytes; },
          observedWrite: () => true,
        },
        storage: memoryStorage(),
        wasm: {
          derivePasswordIdentity(input) {
            deriveInputs.push(input);
            deriveCalls += 1;
            return {
              handle: `password-handle-${deriveCalls}`,
              identity: identity(String(deriveCalls)),
            };
          },
          destroySdnIdentity(handle) { destroyed.push(handle); },
          importRememberedIdentity() {
            throw new Error('stale setup must not import');
          },
          sealRememberedIdentity() {
            throw new Error('stale setup must not seal');
          },
          sha256() { return new Uint8Array(32).fill(0x66); },
        },
        window,
      });
      const a = approvalControls('alice_01', 'first remembered password');
      a.rememberControl = { checked: true, defaultChecked: true, disabled: false };
      a.rememberStatus = { textContent: '' };
      const pendingA = controller.unlockPassword(a);
      await until(() => creationRequest);

      const b = approvalControls('bob_02', 'second current password');
      const pendingB = controller.unlockPassword(b);

      expect(creationRequest.signal.aborted).toBe(true);
      expect([...deriveInputs[0].passwordUtf8]).toEqual(
        Array(deriveInputs[0].passwordUtf8.length).fill(0),
      );
      expect(a.rememberStatus.textContent).toBe('');
      await expect(pendingB).resolves.toEqual(identity('2'));

      if (settlement === 'resolve') {
        creation.resolve({
          type: 'public-key',
          rawId: new Uint8Array(32).fill(0xa1).buffer,
          getClientExtensionResults: () => ({ prf: { enabled: true } }),
        });
      } else {
        creation.reject(new Error('late platform rejection'));
      }
      await expect(pendingA).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
      expect(a.rememberStatus.textContent).toBe('');
      expect(controller.copyPublicIdentity()).toEqual(identity('2'));
      expect(destroyed).toContain('password-handle-1');
      expect(destroyed).not.toContain('password-handle-2');
    },
  );

  test.each(['resolve', 'reject'])(
    'password B synchronously retires remembered restore A before its WebAuthn assertion can %s',
    async (settlement) => {
      const document = new FakeDocument();
      const window = fakeWindow(document);
      const assertion = deferred();
      const destroyed = [];
      let assertionRequest = null;
      const controller = new WalletOriginController({
        credentials: {
          create() { throw new Error('restore must not create a credential'); },
          get(request) {
            assertionRequest = request;
            return assertion.promise;
          },
        },
        document,
        registry: {},
        relay: {},
        rng: {
          getRandomValues(bytes) { bytes.fill(0x5a); return bytes; },
          observedWrite: () => true,
        },
        storage: memoryStorage([[ACTIVE_REMEMBERED_WALLET_KEY, validRememberedRecord()]]),
        wasm: {
          derivePasswordIdentity() {
            return { handle: 'current-password-handle', identity: identity('2') };
          },
          destroySdnIdentity(handle) { destroyed.push(handle); },
          importRememberedIdentity() {
            throw new Error('stale restore must not import');
          },
          sha256() { return new Uint8Array(32).fill(0x66); },
        },
        window,
      });
      const pendingA = controller.unlockRemembered();
      await until(() => assertionRequest);

      const pendingB = controller.unlockPassword(
        approvalControls('bob_02', 'second current password'),
      );

      expect(assertionRequest.signal.aborted).toBe(true);
      await expect(pendingB).resolves.toEqual(identity('2'));
      if (settlement === 'resolve') {
        assertion.resolve({
          type: 'public-key',
          rawId: new Uint8Array(32).fill(0xa1).buffer,
          getClientExtensionResults: () => ({
            prf: { results: { first: new Uint8Array(32).fill(0xb2).buffer } },
          }),
        });
      } else {
        assertion.reject(new Error('late platform rejection'));
      }
      await expect(pendingA).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
      expect(controller.copyPublicIdentity()).toEqual(identity('2'));
      expect(destroyed).not.toContain('current-password-handle');
    },
  );

  test.each(['resolve', 'reject'])(
    'password B synchronously wipes legacy derivation A and survives its late %s',
    async (settlement) => {
      const document = new FakeDocument();
      const window = fakeWindow(document);
      const legacyDerivation = deferred();
      const destroyed = [];
      let legacyInput = null;
      const controller = new WalletOriginController({
        document,
        registry: {},
        relay: {},
        wasm: {
          deriveLegacyPasswordIdentity(input) {
            legacyInput = input;
            return legacyDerivation.promise;
          },
          derivePasswordIdentity() {
            return { handle: 'current-password-handle', identity: identity('2') };
          },
          destroySdnIdentity(handle) { destroyed.push(handle); },
          sha256() { return new Uint8Array(32).fill(0x66); },
        },
        window,
      });
      const legacyControls = approvalControls('legacy-user', 'legacy password');
      const pendingA = controller.unlockLegacy({
        operation: 'sdn.auth.raw-challenge.v1',
        passwordControl: legacyControls.passwordControl,
        profile: 'password-fast-v1-legacy',
        usernameControl: legacyControls.usernameControl,
      });
      await until(() => legacyInput);

      const pendingB = controller.unlockPassword(
        approvalControls('bob_02', 'second current password'),
      );

      expect([...legacyInput.usernameUtf8]).toEqual(
        Array(legacyInput.usernameUtf8.length).fill(0),
      );
      expect([...legacyInput.passwordUtf8]).toEqual(
        Array(legacyInput.passwordUtf8.length).fill(0),
      );
      await expect(pendingB).resolves.toEqual(identity('2'));
      if (settlement === 'resolve') {
        legacyDerivation.resolve({ handle: 'late-legacy-handle', identity: legacyIdentity() });
      } else {
        legacyDerivation.reject(new Error('late native rejection'));
      }
      await expect(pendingA).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
      expect(controller.copyPublicIdentity()).toEqual(identity('2'));
      expect(destroyed).not.toContain('current-password-handle');
      if (settlement === 'resolve') expect(destroyed).toContain('late-legacy-handle');
    },
  );

  test.each(['resolve', 'reject'])(
    'remembered restore B synchronously wipes password derivation A and survives its late %s',
    async (settlement) => {
      const document = new FakeDocument();
      const window = fakeWindow(document);
      const passwordDerivation = deferred();
      const destroyed = [];
      let passwordInput = null;
      const controller = new WalletOriginController({
        credentials: {
          create() { throw new Error('restore must not create a credential'); },
          async get() {
            return {
              type: 'public-key',
              rawId: new Uint8Array(32).fill(0xa1).buffer,
              getClientExtensionResults: () => ({
                prf: { results: { first: new Uint8Array(32).fill(0xb2).buffer } },
              }),
            };
          },
        },
        document,
        registry: {},
        relay: {},
        rng: {
          getRandomValues(bytes) { bytes.fill(0x5a); return bytes; },
          observedWrite: () => true,
        },
        storage: memoryStorage([[ACTIVE_REMEMBERED_WALLET_KEY, validRememberedRecord()]]),
        wasm: {
          derivePasswordIdentity(input) {
            passwordInput = input;
            return passwordDerivation.promise;
          },
          destroySdnIdentity(handle) { destroyed.push(handle); },
          importRememberedIdentity() {
            return { handle: 'current-remembered-handle', identity: identity('2') };
          },
          sha256() { return new Uint8Array(32).fill(0x66); },
        },
        window,
      });
      const pendingA = controller.unlockPassword(
        approvalControls('alice_01', 'first password'),
      );
      await until(() => passwordInput);

      const pendingB = controller.unlockRemembered();

      expect([...passwordInput.usernameUtf8]).toEqual(
        Array(passwordInput.usernameUtf8.length).fill(0),
      );
      expect([...passwordInput.passwordUtf8]).toEqual(
        Array(passwordInput.passwordUtf8.length).fill(0),
      );
      await expect(pendingB).resolves.toEqual(identity('2'));
      if (settlement === 'resolve') {
        passwordDerivation.resolve({ handle: 'late-password-handle', identity: identity('1') });
      } else {
        passwordDerivation.reject(new Error('late native rejection'));
      }
      await expect(pendingA).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
      expect(controller.copyPublicIdentity()).toEqual(identity('2'));
      expect(destroyed).not.toContain('current-remembered-handle');
      if (settlement === 'resolve') expect(destroyed).toContain('late-password-handle');
    },
  );

  test.each(['resolve', 'reject'])(
    'legacy B synchronously retires remembered setup A before its WebAuthn create can %s',
    async (settlement) => {
      const document = new FakeDocument();
      const window = fakeWindow(document);
      const creation = deferred();
      const destroyed = [];
      const deriveInputs = [];
      let creationRequest = null;
      const controller = new WalletOriginController({
        credentials: {
          create(request) {
            creationRequest = request;
            return creation.promise;
          },
          get() { throw new Error('stale setup must not request an assertion'); },
        },
        document,
        registry: {},
        relay: {},
        rng: {
          getRandomValues(bytes) { bytes.fill(0x5a); return bytes; },
          observedWrite: () => true,
        },
        storage: memoryStorage(),
        wasm: {
          deriveLegacyPasswordIdentity() {
            return { handle: 'current-legacy-handle', identity: legacyIdentity() };
          },
          derivePasswordIdentity(input) {
            deriveInputs.push(input);
            return { handle: 'remember-source-handle', identity: identity('1') };
          },
          destroySdnIdentity(handle) { destroyed.push(handle); },
          importRememberedIdentity() {
            throw new Error('stale setup must not import');
          },
          sealRememberedIdentity() {
            throw new Error('stale setup must not seal');
          },
          sha256() { return new Uint8Array(32).fill(0x66); },
        },
        window,
      });
      const a = approvalControls('alice_01', 'first remembered password');
      a.rememberControl = { checked: true, defaultChecked: true, disabled: false };
      a.rememberStatus = { textContent: '' };
      const pendingA = controller.unlockPassword(a);
      await until(() => creationRequest);
      const legacyControls = approvalControls('legacy-user', 'legacy password');

      const pendingB = controller.unlockLegacy({
        operation: 'sdn.auth.raw-challenge.v1',
        passwordControl: legacyControls.passwordControl,
        profile: 'password-fast-v1-legacy',
        usernameControl: legacyControls.usernameControl,
      });

      expect(creationRequest.signal.aborted).toBe(true);
      expect([...deriveInputs[0].passwordUtf8]).toEqual(
        Array(deriveInputs[0].passwordUtf8.length).fill(0),
      );
      expect(a.rememberStatus.textContent).toBe('');
      await expect(pendingB).resolves.toEqual(legacyIdentity());
      if (settlement === 'resolve') {
        creation.resolve({
          type: 'public-key',
          rawId: new Uint8Array(32).fill(0xa1).buffer,
          getClientExtensionResults: () => ({ prf: { enabled: true } }),
        });
      } else {
        creation.reject(new Error('late platform rejection'));
      }
      await expect(pendingA).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
      expect(a.rememberStatus.textContent).toBe('');
      expect(destroyed).not.toContain('current-legacy-handle');
    },
  );

  test('B unlock replaces A, tears controls down before await, and destroys stale A', async () => {
    const test = fixture();
    const a = controls(test.document, 'alice', 'correct horse battery staple');
    const pendingA = test.controller.unlockPassword(a);
    expect(a.usernameControl.value).toBe('');
    expect(a.passwordControl.value).toBe('');
    expect(a.usernameControl.defaultValue).toBe('');
    expect(a.passwordControl.defaultValue).toBe('');
    expect(a.passwordControl.disabled).toBe(true);
    expect(a.passwordControl.getAttribute('name')).toBeNull();
    expect(a.passwordControl.getAttribute('autocomplete')).toBeNull();
    expect(a.passwordControl.selectionStart).toBe(0);
    expect(a.form.parentNode).toBeNull();

    const b = controls(test.document, 'alice', 'correct horse battery staple');
    const pendingB = test.controller.unlockPassword(b);
    const handleA = Object.freeze({ value: 'A' });
    const handleB = Object.freeze({ value: 'B' });
    test.derives[1].resolve({ handle: handleB, identity: test.identity });
    await expect(pendingB).resolves.toEqual(test.identity);
    test.derives[0].resolve({ handle: handleA, identity: test.identity });
    await expect(pendingA).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
    expect(test.destroyed).toContain(handleA);
    expect(test.destroyed).not.toContain(handleB);
    expect(Array.from(test.derives[0].input.passwordUtf8)).toEqual(
      Array(test.derives[0].input.passwordUtf8.length).fill(0),
    );

    await test.controller.logout();
    expect(test.destroyed).toContain(handleB);
  });

  test('does not derive B when native destruction of installed A fails and retries A on destroy', async () => {
    const test = fixture();
    const a = controls(test.document, 'alice', 'correct horse battery staple');
    const pendingA = test.controller.unlockPassword(a);
    const handleA = Object.freeze({ value: 'installed-A' });
    test.derives[0].resolve({ handle: handleA, identity: test.identity });
    await pendingA;

    const originalDestroy = test.wasm.destroySdnIdentity;
    const attempts = [];
    let failA = true;
    test.wasm.destroySdnIdentity = (handle) => {
      attempts.push(handle);
      if (handle === handleA && failA) throw new Error('native destroy failed');
      originalDestroy(handle);
    };
    let replacementDerives = 0;
    test.wasm.derivePasswordIdentity = () => {
      replacementDerives += 1;
      throw new Error('replacement must not be derived');
    };

    const b = controls(test.document, 'bob', 'different password');
    await expect(test.controller.unlockPassword(b)).rejects.toMatchObject({
      code: 'DESTRUCTION_FAILED',
    });
    expect(replacementDerives).toBe(0);
    expect(b.usernameControl.value).toBe('');
    expect(b.passwordControl.value).toBe('');
    expect(b.form.parentNode).toBeNull();
    expect(() => test.controller.copyPublicIdentity()).toThrowError(/STALE_CONTROLLER/u);

    failA = false;
    await test.controller.destroy('retry-native-owner');
    expect(attempts.filter((handle) => handle === handleA).length).toBeGreaterThan(1);
    expect(test.destroyed).toContain(handleA);
  });

  test('rechecks trusted context after destroying A and immediately before reading B controls', async () => {
    const test = fixture();
    const a = controls(test.document, 'alice', 'correct horse battery staple');
    const pendingA = test.controller.unlockPassword(a);
    const handleA = Object.freeze({ value: 'context-A' });
    test.derives[0].resolve({ handle: handleA, identity: test.identity });
    await pendingA;

    const originalDestroy = test.wasm.destroySdnIdentity;
    test.wasm.destroySdnIdentity = (handle) => {
      originalDestroy(handle);
      test.document.visibilityState = 'hidden';
    };
    let replacementDerives = 0;
    test.wasm.derivePasswordIdentity = () => {
      replacementDerives += 1;
      throw new Error('context must be checked before derivation');
    };
    const b = controls(test.document, 'bob', 'different password');
    await expect(test.controller.unlockPassword(b)).rejects.toMatchObject({
      code: 'WALLET_CONTEXT_UNTRUSTED',
    });
    expect(replacementDerives).toBe(0);
    expect(b.usernameControl.value).toBe('');
    expect(b.passwordControl.value).toBe('');
    expect(b.form.parentNode).toBeNull();
  });

  test('rejects a malformed native identity and destroys its returned handle', async () => {
    const test = fixture();
    const entry = controls(test.document, 'alice', 'correct horse battery staple');
    const pending = test.controller.unlockPassword(entry);
    const handle = Object.freeze({ value: 'malformed' });
    test.derives[0].resolve({ handle, identity: { schemaVersion: 1 } });
    await expect(pending).rejects.toMatchObject({ code: 'WASM_FAILURE' });
    expect(test.destroyed).toEqual([handle]);
    expect(Array.from(test.derives[0].input.usernameUtf8)).toEqual(
      Array(test.derives[0].input.usernameUtf8.length).fill(0),
    );
  });

  test('retains and retries a malformed derived handle when native destruction fails', async () => {
    const test = fixture();
    const originalDestroy = test.wasm.destroySdnIdentity;
    const attempts = [];
    let failCleanup = true;
    test.wasm.destroySdnIdentity = (handle) => {
      attempts.push(handle);
      if (failCleanup) throw new Error('native destroy failed');
      originalDestroy(handle);
    };
    const entry = controls(test.document, 'alice', 'correct horse battery staple');
    const pending = test.controller.unlockPassword(entry);
    const handle = Object.freeze({ value: 'malformed-cleanup-failure' });
    test.derives[0].resolve({ handle, identity: { schemaVersion: 1 } });

    await expect(pending).rejects.toMatchObject({ code: 'DESTRUCTION_FAILED' });
    expect(() => test.controller.copyPublicIdentity()).toThrowError(/STALE_CONTROLLER/u);
    failCleanup = false;
    await test.controller.destroy('retry-malformed-owner');
    expect(attempts.filter((candidate) => candidate === handle).length).toBeGreaterThan(1);
    expect(test.destroyed).toContain(handle);
  });

  test('terminally revokes and retains a stale derived handle when its destruction fails', async () => {
    const test = fixture();
    const first = controls(test.document, 'alice', 'first password');
    const staleUnlock = test.controller.unlockPassword(first);
    const second = controls(test.document, 'bob', 'second password');
    const currentUnlock = test.controller.unlockPassword(second);
    const staleHandle = Object.freeze({ value: 'stale-derived' });
    const currentHandle = Object.freeze({ value: 'current-derived' });
    test.derives[1].resolve({ handle: currentHandle, identity: test.identity });
    await currentUnlock;

    const originalDestroy = test.wasm.destroySdnIdentity;
    const attempts = [];
    let failStale = true;
    test.wasm.destroySdnIdentity = (handle) => {
      attempts.push(handle);
      if (handle === staleHandle && failStale) throw new Error('native destroy failed');
      originalDestroy(handle);
    };
    test.derives[0].resolve({ handle: staleHandle, identity: test.identity });

    await expect(staleUnlock).rejects.toMatchObject({ code: 'DESTRUCTION_FAILED' });
    expect(test.destroyed).toContain(currentHandle);
    expect(() => test.controller.copyPublicIdentity()).toThrowError(/STALE_CONTROLLER/u);
    failStale = false;
    await test.controller.destroy('retry-stale-owner');
    expect(attempts.filter((handle) => handle === staleHandle).length).toBeGreaterThan(1);
    expect(test.destroyed).toContain(staleHandle);
  });

  test('logout during signing synchronously drops the handle and stale work publishes nothing', async () => {
    const test = fixture();
    const entry = controls(test.document, 'alice', 'correct horse battery staple');
    const unlock = test.controller.unlockPassword(entry);
    const handle = Object.freeze({ value: 'signing' });
    test.derives[0].resolve({ handle, identity: test.identity });
    await unlock;

    const execution = test.controller.execute(transaction());
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: false });
    expect(test.signCalls).toBe(0);
    confirm.dispatch('click', { isTrusted: true });
    await until(() => test.signCalls === 1);

    const logout = test.controller.logout();
    expect(test.destroyed).toContain(handle);
    test.sign.resolve({ unsafe: true });
    await expect(execution).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
    await logout;
    expect(test.published).toEqual([]);
  });

  test.each([
    ['wrong registry release', { registryVersion: '0'.repeat(64) }],
    ['wrong request hash', { requestSha256: '0'.repeat(64) }],
    ['wrong exact origin', { requestOrigin: 'https://SDN.spaceaware.io' }],
  ])('fails closed on %s before confirmation or signing', async (_label, override) => {
    const test = fixture();
    const entry = controls(test.document, 'alice', 'correct horse battery staple');
    const unlock = test.controller.unlockPassword(entry);
    const handle = Object.freeze({ value: 'validation' });
    test.derives[0].resolve({ handle, identity: test.identity });
    await unlock;
    await expect(test.controller.execute({ ...transaction(), ...override })).rejects.toBeDefined();
    expect(test.signCalls).toBe(0);
    expect(test.published).toEqual([]);
    expect(test.destroyed).toContain(handle);
  });
});

function legacyIdentityFromVector(vector) {
  const account = vector.accounts[0];
  const authentication = account.authentication;
  return {
    accountFingerprint: vector.rootPublicIdentity.fingerprint,
    accountIndex: 0,
    accountLabel: null,
    accountPeerId: vector.rootPublicIdentity.peerId,
    accountXpub: vector.rootPublicIdentity.accountXpub,
    identityScheme: vector.identityScheme,
    keys: [{
      bip32Fingerprint: null,
      curve: 'ed25519',
      derivation: 'bip32-scalar-as-ed25519-seed',
      encoding: 'raw',
      identityScheme: vector.identityScheme,
      keyId: authentication.keyId,
      path: authentication.path,
      publicKeyHex: authentication.publicKeyHex,
      purpose: 'sdn-authentication',
      seedProfile: vector.seedProfile,
      signatureProfile: 'ed25519-raw-32-v1',
    }],
    schemaVersion: 1,
    seedProfile: vector.seedProfile,
  };
}

function rawTransactionFromVector(vector, now = Date.now()) {
  return {
    ...transaction(now),
    operation: 'sdn.auth.raw-challenge.v1',
    request: {
      challengeBase64url: vector.accounts[0].authentication.rawChallengeBase64url,
      protocolVersion: 1,
    },
  };
}

function submitLegacyProfile(document, profile) {
  const select = document.find((node) => node.dataset.walletLegacyProfile === 'required');
  expect(select).toBeTruthy();
  expect(select.value).toBe('');
  select.value = profile;
  const submit = document.findAction('continue-legacy-login');
  expect(submit).toBeTruthy();
  submit.parentNode.dispatch('submit', { isTrusted: true, preventDefault() {} });
}

function submitLegacyMnemonic(document, mnemonic) {
  const submit = document.findAction('confirm-legacy-mnemonic');
  expect(submit).toBeTruthy();
  const form = submit.parentNode;
  const mnemonicControl = document.find(
    (node) => node.tagName === 'textarea' && node.parentNode === form.children[0],
  );
  expect(mnemonicControl).toBeTruthy();
  mnemonicControl.value = mnemonic;
  mnemonicControl.defaultValue = mnemonic;
  form.dispatch('submit', { isTrusted: true, preventDefault() {} });
}

function rawLegacyAppFixture(vector, { derive = null } = {}) {
  const document = new FakeDocument();
  const window = fakeWindow(document);
  const value = rawTransactionFromVector(vector);
  window.location.pathname = `/transaction/${value.transactionId}`;
  const calls = [];
  const destroyed = [];
  const published = [];
  const identityValue = legacyIdentityFromVector(vector);
  const handle = Object.freeze({ profile: vector.seedProfile });
  const deriveSelected = derive ?? (async (input) => ({ handle, identity: identityValue, input }));
  const wasm = {
    derivePasswordIdentity() {
      calls.push(['modern']);
      throw new Error('modern derivation must not run for raw-v1');
    },
    deriveLegacyPasswordIdentity(input) {
      calls.push(['password-fast-v1-legacy', input]);
      return deriveSelected(input);
    },
    destroySdnIdentity(candidate) { destroyed.push(candidate); },
    importLegacyMnemonicIdentity(input) {
      calls.push(['bip39-mnemonic-v1-legacy', input]);
      return deriveSelected(input);
    },
    sha256() { return new Uint8Array(32).fill(0xbb); },
    signSdnLoginV1(candidate, challenge) {
      calls.push(['sign', candidate, challenge]);
      return {
        algorithm: 'ed25519',
        encoding: 'raw',
        identityScheme: vector.identityScheme,
        keyId: vector.accounts[0].authentication.keyId,
        schemaVersion: 1,
        signatureHex: vector.accounts[0].authentication.signatureHex,
        signatureProfile: 'ed25519-raw-32-v1',
      };
    },
  };
  const relay = {
    async fetchTransaction(id) {
      expect(id).toBe(value.transactionId);
      return value;
    },
    async publishResult(_transaction, result) {
      expect(destroyed).toContain(handle);
      published.push(result);
      return { ok: true };
    },
  };
  const app = createWalletOriginApp({
    document,
    registry: { resolveRegistryBinding },
    relay,
    wasm,
    window,
  });
  return { app, calls, destroyed, document, handle, published, transaction: value, wasm, window };
}

describe('explicit legacy raw-v1 origin flow', () => {
  test.each(sdnWalletVectors.legacyIdentities)(
    'selects, derives, signs, and retires fixture profile $seedProfile without approval authority',
    async (vector) => {
      const test = rawLegacyAppFixture(vector);
      const started = test.app.start();
      await until(() => test.document.find(
        (node) => node.dataset.walletLegacyProfile === 'required',
      ));
      submitLegacyProfile(test.document, vector.seedProfile);
      if (vector.seedProfile === 'password-fast-v1-legacy') {
        await until(() => test.document.findAction('login'));
        submitCurrentLogin(test, vector.source.rawUsername, vector.source.password);
      } else {
        await until(() => test.document.findAction('confirm-legacy-mnemonic'));
        submitLegacyMnemonic(test.document, vector.source.mnemonic);
      }
      const confirm = await until(() => test.document.findAction('confirm'));
      confirm.dispatch('click', { isTrusted: true });
      await expect(started).resolves.toEqual({ ok: true });

      const selectedCalls = test.calls.filter(([name]) => name === vector.seedProfile);
      expect(selectedCalls).toHaveLength(1);
      expect(test.calls.some(([name]) => name === 'modern')).toBe(false);
      const otherProfile = vector.seedProfile === 'password-fast-v1-legacy'
        ? 'bip39-mnemonic-v1-legacy'
        : 'password-fast-v1-legacy';
      expect(test.calls.some(([name]) => name === otherProfile)).toBe(false);
      const selectedInput = selectedCalls[0][1];
      for (const bytes of [
        selectedInput.usernameUtf8,
        selectedInput.passwordUtf8,
        selectedInput.mnemonicUtf8,
      ].filter(Boolean)) {
        expect([...bytes]).toEqual(Array(bytes.byteLength).fill(0));
      }
      const signCall = test.calls.find(([name]) => name === 'sign');
      expect(signCall[1]).toBe(test.handle);
      expect([...signCall[2]]).toEqual([
        ...Uint8Array.from(atob(
          vector.accounts[0].authentication.rawChallengeBase64url
            .replace(/-/gu, '+').replace(/_/gu, '/') + '=',
        ), (character) => character.charCodeAt(0)),
      ]);
      expect(test.destroyed).toEqual([test.handle]);
      expect(test.published).toEqual([{
        algorithm: 'ed25519',
        encoding: 'raw',
        identityScheme: vector.identityScheme,
        keyId: vector.accounts[0].authentication.keyId,
        schemaVersion: 1,
        signatureHex: vector.accounts[0].authentication.signatureHex,
        signatureProfile: 'ed25519-raw-32-v1',
      }]);
      expect(test.document.findAction('copy-approval')).toBeNull();
    },
  );

  test('pagehide during selected legacy derivation wipes credentials and destroys the late handle', async () => {
    const vector = sdnWalletVectors.legacyIdentities[0];
    const pendingDerive = deferred();
    let captured = null;
    const test = rawLegacyAppFixture(vector, {
      derive(input) {
        captured = input;
        return pendingDerive.promise;
      },
    });
    const started = test.app.start();
    await until(() => test.document.find(
      (node) => node.dataset.walletLegacyProfile === 'required',
    ));
    submitLegacyProfile(test.document, vector.seedProfile);
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test, vector.source.rawUsername, vector.source.password);
    await until(() => captured);

    test.window.dispatch('pagehide', { persisted: false });
    expect([...captured.usernameUtf8]).toEqual(Array(captured.usernameUtf8.byteLength).fill(0));
    expect([...captured.passwordUtf8]).toEqual(Array(captured.passwordUtf8.byteLength).fill(0));
    pendingDerive.resolve({ handle: test.handle, identity: legacyIdentityFromVector(vector) });
    await expect(started).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
    expect(test.destroyed).toContain(test.handle);
    expect(test.calls.some(([name]) => name === 'sign')).toBe(false);
    expect(test.published).toEqual([]);
  });

  test('a selected legacy native failure wipes credentials without fallback or retry', async () => {
    const vector = sdnWalletVectors.legacyIdentities[0];
    let captured = null;
    const nativeFailure = new Error('fixture legacy derivation failed');
    const test = rawLegacyAppFixture(vector, {
      derive(input) {
        captured = input;
        throw nativeFailure;
      },
    });
    const started = test.app.start();
    await until(() => test.document.find(
      (node) => node.dataset.walletLegacyProfile === 'required',
    ));
    submitLegacyProfile(test.document, vector.seedProfile);
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test, vector.source.rawUsername, vector.source.password);

    await expect(started).rejects.toBe(nativeFailure);
    expect([...captured.usernameUtf8]).toEqual(Array(captured.usernameUtf8.byteLength).fill(0));
    expect([...captured.passwordUtf8]).toEqual(Array(captured.passwordUtf8.byteLength).fill(0));
    expect(test.calls.filter(([name]) => name === vector.seedProfile)).toHaveLength(1);
    expect(test.calls.some(([name]) => name === 'modern')).toBe(false);
    expect(test.calls.some(([name]) => name === 'bip39-mnemonic-v1-legacy')).toBe(false);
    expect(test.calls.some(([name]) => name === 'sign')).toBe(false);
    expect(test.published).toEqual([]);
  });
});

function standaloneFixture(operation, { createRelay = null } = {}) {
  const document = new FakeDocument();
  const window = fakeWindow(document);
  const value = publicTransaction(operation);
  if (typeof createRelay === 'function') {
    value.requestSha256 = '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a';
  }
  window.location.pathname = `/transaction/${value.transactionId}`;
  const destroyed = [];
  const published = [];
  const disconnected = [];
  let derives = 0;
  const wasm = {
    async derivePasswordIdentity() {
      derives += 1;
      return { handle: `handle-${derives}`, identity: identity() };
    },
    async deriveLegacyPasswordIdentity() {
      return { handle: 'legacy-handle', identity: legacyIdentity() };
    },
    destroySdnIdentity(handle) { destroyed.push(handle); },
    sha256() { return digestBytes(value.requestSha256); },
  };
  const injectedRelay = {
    async fetchTransaction(id) {
      expect(id).toBe(value.transactionId);
      return value;
    },
    async hashRequest() { return value.requestSha256; },
    async publishResult(_transaction, result) {
      expect(destroyed).toContain('handle-1');
      published.push(result);
      return { ok: true };
    },
    async publishDisconnected(result, publicIdentity) {
      disconnected.push({ publicIdentity, result });
    },
  };
  const relay = typeof createRelay === 'function'
    ? createRelay({ destroyed, disconnected, published, transaction: value, window })
    : injectedRelay;
  const app = createWalletOriginApp({
    clipboard: { async writeText(text) { standaloneFixture.clipboardWrites.push(text); } },
    document,
    registry: { resolveRegistryBinding },
    relay,
    rng: {},
    wasm,
    window,
  });
  return {
    app,
    get derives() { return derives; },
    destroyed,
    disconnected,
    document,
    published,
    transaction: value,
    wasm,
    window,
  };
}
standaloneFixture.clipboardWrites = [];

function defaultRelayAccountFixture({ clipboard = null, publish = null, storage = undefined } = {}) {
  const document = new FakeDocument();
  const window = fakeWindow(document);
  const value = publicTransaction('sdn.wallet.account.v1');
  value.requestSha256 = '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a';
  window.location.pathname = `/transaction/${value.transactionId}`;
  const destroyed = [];
  const posts = [];
  const replacements = [];
  let derives = 0;
  window.location.replace = (redirectUri) => replacements.push(redirectUri);
  const wasm = {
    async derivePasswordIdentity() {
      derives += 1;
      return { handle: `handle-${derives}`, identity: identity() };
    },
    destroySdnIdentity(handle) { destroyed.push(handle); },
    sha256() { return digestBytes(value.requestSha256); },
  };
  const app = createWalletOriginApp({
    clipboard: clipboard ?? { async writeText() {} },
    document,
    async fetch(_url, options) {
      if (options.method === 'GET') return relayJsonResponse(value);
      posts.push(JSON.parse(options.body));
      if (publish) return publish({ options, transaction: value });
      return relayJsonResponse(relayCompletion(value), { status: 201 });
    },
    registry: { resolveRegistryBinding },
    rng: {},
    storage,
    wasm,
    window,
  });
  return {
    app,
    destroyed,
    document,
    get derives() { return derives; },
    posts,
    replacements,
    transaction: value,
    wasm,
    window,
  };
}

function submitCurrentLogin(test, username = 'alice', password = 'correct horse battery staple') {
  const button = test.document.findAction('login');
  expect(button).toBeTruthy();
  const form = button.parentNode.parentNode;
  const inputs = [];
  const collect = (node) => {
    if (node.tagName === 'input' && node.type !== 'checkbox') inputs.push(node);
    node.children.forEach(collect);
  };
  collect(form);
  expect(inputs).toHaveLength(2);
  inputs[0].value = username;
  inputs[0].defaultValue = username;
  inputs[1].value = password;
  inputs[1].defaultValue = password;
  form.dispatch('submit', { isTrusted: true, preventDefault() {} });
}

test('normal prompt remains lifecycle-owned before submit and reaches unlock with exact nonempty controls', async () => {
  const document = new FakeDocument();
  const window = fakeWindow(document);
  const transactionId = 'e'.repeat(64);
  window.location.pathname = `/transaction/${transactionId}`;
  let registered = null;
  let unlocked = null;
  const prepared = Object.freeze({
    binding: Object.freeze({ clientDisplayName: 'Space Data Network' }),
    transaction: Object.freeze({ operation: 'sdn.wallet.connect.v1' }),
  });
  const controller = {
    canRestoreRememberedWallet: () => false,
    async destroy() {},
    async executePrepared() { return { ok: true }; },
    isUiGenerationCurrent: () => true,
    listQuarantinedWalletRecords: () => [],
    async prepare() { return prepared; },
    registerCredentialControls(controls) { registered = controls; },
    supportsRememberedWallet: () => true,
    async unlockPassword(controls) {
      unlocked = {
        password: controls.passwordControl.value,
        passwordControl: controls.passwordControl,
        username: controls.usernameControl.value,
        usernameControl: controls.usernameControl,
      };
      return identity();
    },
  };
  const app = createWalletOriginApp({ controller, document, window });
  const started = app.start();
  await until(() => document.findAction('login'));

  expect(registered).toBeTruthy();
  submitCurrentLogin({ document }, 'alice_01', 'nonempty prompt password');
  await expect(started).resolves.toEqual({ ok: true });
  expect(unlocked).toMatchObject({
    password: 'nonempty prompt password',
    username: 'alice_01',
  });
  expect(unlocked.usernameControl).toBe(registered.usernameControl);
  expect(unlocked.passwordControl).toBe(registered.passwordControl);
});

test.each([
  'Wallet remembered on this device.',
  'Wallet was not remembered.',
])('origin app keeps the current bounded Remember status visible through confirmation: %s', async (status) => {
  const document = new FakeDocument();
  const window = fakeWindow(document);
  const transactionId = 'e'.repeat(64);
  window.location.pathname = `/transaction/${transactionId}`;
  const execution = deferred();
  let executeStarted = false;
  const prepared = Object.freeze({
    binding: Object.freeze({ clientDisplayName: 'Space Data Network' }),
    transaction: Object.freeze({ operation: 'sdn.wallet.connect.v1' }),
  });
  const controller = {
    canRestoreRememberedWallet: () => false,
    async destroy() {},
    executePrepared() {
      executeStarted = true;
      return execution.promise;
    },
    isUiGenerationCurrent: () => true,
    listQuarantinedWalletRecords: () => [],
    async prepare() { return prepared; },
    registerCredentialControls() {},
    supportsRememberedWallet: () => true,
    async unlockPassword(controls) {
      controls.rememberStatus.textContent = status;
      controls.usernameControl.value = '';
      controls.passwordControl.value = '';
      controls.usernameControl.disabled = true;
      controls.passwordControl.disabled = true;
      return identity();
    },
  };
  const app = createWalletOriginApp({ controller, document, window });
  const started = app.start();
  await until(() => document.findAction('login'));
  const remember = document.find((node) => node.dataset.walletRemember === 'prf-only');
  remember.checked = true;
  submitCurrentLogin({ document }, 'alice_01', 'nonempty prompt password');
  await until(() => executeStarted);

  expect(document.body.textContent).toContain(status);
  expect(document.find((node) => node.dataset.walletRememberStatus === 'true')?.textContent)
    .toBe(status);
  const credentialInputs = document.findAll(
    (node) => node.tagName === 'input' && node.type !== 'checkbox',
  );
  expect(credentialInputs.every((input) => input.value === '' && input.disabled)).toBe(true);

  execution.resolve({ ok: true });
  await expect(started).resolves.toEqual({ ok: true });
});

test.each([
  ['password Remember', 'stop', 'resolve'],
  ['password Remember', 'stop', 'reject'],
  ['password Remember', 'pagehide', 'resolve'],
  ['password Remember', 'pagehide', 'reject'],
  ['remembered restore', 'stop', 'resolve'],
  ['remembered restore', 'stop', 'reject'],
  ['remembered restore', 'pagehide', 'resolve'],
  ['remembered restore', 'pagehide', 'reject'],
])(
  'origin app suppresses late %s %s after %s',
  async (flow, termination, settlement) => {
    const document = new FakeDocument();
    const window = fakeWindow(document);
    const transactionId = 'e'.repeat(64);
    window.location.pathname = `/transaction/${transactionId}`;
    const unlock = deferred();
    const calls = [];
    const prepared = Object.freeze({
      binding: Object.freeze({ clientDisplayName: 'Space Data Network' }),
      transaction: Object.freeze({ operation: 'sdn.wallet.connect.v1' }),
    });
    const controller = {
      canRestoreRememberedWallet: () => flow === 'remembered restore',
      async destroy(reason) { calls.push(['destroy', reason]); },
      async executePrepared(value) {
        calls.push(['execute', value]);
        return { published: true };
      },
      isUiGenerationCurrent: () => true,
      listQuarantinedWalletRecords: () => [],
      async prepare(value) {
        calls.push(['prepare', value]);
        return prepared;
      },
      supportsRememberedWallet: () => true,
      unlockPassword(controls) {
        calls.push(['unlock-password', controls.rememberControl?.checked]);
        return unlock.promise;
      },
      unlockRemembered() {
        calls.push(['unlock-remembered']);
        return unlock.promise;
      },
    };
    const app = createWalletOriginApp({ controller, document, window });
    const started = app.start().then(
      (value) => ({ resolved: value }),
      (error) => ({ rejected: error }),
    );
    await until(() => document.findAction('login'));
    if (flow === 'password Remember') {
      const remember = document.find((node) => node.dataset.walletRemember === 'prf-only');
      remember.checked = true;
      submitCurrentLogin({ document });
      await until(() => calls.some(([name]) => name === 'unlock-password'));
      expect(calls.find(([name]) => name === 'unlock-password')[1]).toBe(true);
    } else {
      const restore = document.findAction('unlock-remembered');
      restore.dispatch('click', { isTrusted: true });
      await until(() => calls.some(([name]) => name === 'unlock-remembered'));
    }

    if (termination === 'stop') await app.stop('test-stop');
    else window.dispatch('pagehide', { persisted: false });

    expect(document.findAction('login')).toBeNull();
    expect(document.findAction('unlock-remembered')).toBeNull();
    expect(document.body.textContent).not.toContain('Sign in');

    if (settlement === 'resolve') unlock.resolve(identity());
    else unlock.reject(new Error('late WebAuthn failure'));
    const outcome = await started;

    expect(outcome.rejected).toBeTruthy();
    expect(calls.filter(([name]) => name === 'execute')).toHaveLength(0);
    expect(document.body.textContent).not.toContain('Wallet request stopped');
    expect(document.body.textContent).not.toContain('Complete');
  },
);

describe('standalone wallet-origin application', () => {
  test('does not render credentials for an invalid transaction', async () => {
    const test = standaloneFixture('sdn.wallet.connect.v1');
    test.transaction.clientId = 'unregistered-client';
    await expect(test.app.start()).rejects.toBeDefined();
    expect(test.document.findAction('login')).toBeNull();
    expect(test.derives).toBe(0);
    expect(test.published).toEqual([]);
  });

  test('valid connect validates, unlocks, confirms, publishes after destruction, and completes', async () => {
    const test = standaloneFixture('sdn.wallet.connect.v1');
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    expect(test.derives).toBe(0);
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await expect(started).resolves.toEqual({ ok: true });
    expect(test.published).toHaveLength(1);
    expect(test.destroyed).toEqual(['handle-1']);
    expect(test.document.body.textContent).toContain('completed successfully');
  });

  test('same-origin relay navigates only after a valid signed result is published and the handle is destroyed', async () => {
    const replacements = [];
    const test = standaloneFixture('sdn.wallet.connect.v1', {
      createRelay: ({ destroyed, published, transaction, window }) => {
        window.location.replace = (redirectUri) => replacements.push(redirectUri);
        return createSameOriginWalletRelay({
          async fetch(url, options) {
            if (options.method === 'GET') return relayJsonResponse(transaction);
            expect(destroyed).toContain('handle-1');
            const body = JSON.parse(options.body);
            published.push(body.result);
            return relayJsonResponse(relayCompletion(transaction), { status: 201 });
          },
          location: window.location,
        });
      },
    });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await expect(started).resolves.toMatchObject({
      redirectUri: relayCompletion(test.transaction).redirectUri,
      transactionId: test.transaction.transactionId,
    });
    expect(test.published).toHaveLength(1);
    expect(replacements).toEqual([relayCompletion(test.transaction).redirectUri]);
  });

  test('malformed relay completion publishes no callback navigation', async () => {
    const replacements = [];
    const test = standaloneFixture('sdn.wallet.connect.v1', {
      createRelay: ({ transaction, window }) => {
        window.location.replace = (redirectUri) => replacements.push(redirectUri);
        return createSameOriginWalletRelay({
          async fetch(_url, options) {
            if (options.method === 'GET') return relayJsonResponse(transaction);
            return relayJsonResponse({
              ...relayCompletion(transaction),
              redirectUri: `${transaction.callbackUri}#code=${'f'.repeat(64)}&state=${'0'.repeat(64)}`,
            }, { status: 201 });
          },
          location: window.location,
        });
      },
    });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await expect(started).rejects.toMatchObject({ code: 'RELAY_FAILURE' });
    expect(test.destroyed).toEqual(['handle-1']);
    expect(replacements).toEqual([]);
  });

  test('controller independently rejects an injected relay callback mismatch before navigation', async () => {
    const replacements = [];
    const test = standaloneFixture('sdn.wallet.connect.v1', {
      createRelay: ({ transaction }) => ({
        async fetchTransaction() { return transaction; },
        async hashRequest() { return transaction.requestSha256; },
        async publishResult() {
          return {
            ...relayCompletion(transaction),
            redirectUri: `${transaction.callbackUri}#code=${'f'.repeat(64)}&state=${'0'.repeat(64)}`,
          };
        },
        navigate(redirectUri) { replacements.push(redirectUri); },
      }),
    });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await expect(started).rejects.toMatchObject({ code: 'RELAY_FAILURE' });
    expect(replacements).toEqual([]);
  });

  test('one-shot abort cleanup cannot reenter revocation and regain publication authority', async () => {
    let test;
    let publishCalls = 0;
    test = standaloneFixture('sdn.wallet.connect.v1', {
      createRelay: ({ transaction }) => ({
        async fetchTransaction(_transactionId, { signal }) {
          signal.addEventListener('abort', () => {
            test.app.controller.revokeNow('finish-abort-reentry');
          }, { once: true });
          return transaction;
        },
        async hashRequest() { return transaction.requestSha256; },
        async publishResult() { publishCalls += 1; },
      }),
    });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });

    await expect(started).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
    expect(test.destroyed).toEqual(['handle-1']);
    expect(publishCalls).toBe(0);
  });

  test('pagehide while result publication is pending prevents later callback navigation', async () => {
    const completion = deferred();
    const replacements = [];
    let postStarted = false;
    const test = standaloneFixture('sdn.wallet.connect.v1', {
      createRelay: ({ transaction, window }) => {
        window.location.replace = (redirectUri) => replacements.push(redirectUri);
        return createSameOriginWalletRelay({
          async fetch(_url, options) {
            if (options.method === 'GET') return relayJsonResponse(transaction);
            postStarted = true;
            return completion.promise;
          },
          location: window.location,
        });
      },
    });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await until(() => postStarted);
    test.window.dispatch('pagehide', { persisted: false });
    await expect(started).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
    expect(replacements).toEqual([]);
  });

  test('destroy while result publication is pending prevents later callback navigation', async () => {
    const completion = deferred();
    const replacements = [];
    let postStarted = false;
    const test = standaloneFixture('sdn.wallet.connect.v1', {
      createRelay: ({ transaction, window }) => {
        window.location.replace = (redirectUri) => replacements.push(redirectUri);
        return createSameOriginWalletRelay({
          async fetch(_url, options) {
            if (options.method === 'GET') return relayJsonResponse(transaction);
            postStarted = true;
            return completion.promise;
          },
          location: window.location,
        });
      },
    });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await until(() => postStarted);
    await test.app.stop('destroyed-during-publication');
    await expect(started).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
    expect(replacements).toEqual([]);
  });

  test('context loss after prepare clears credentials before native unlock and publishes nothing', async () => {
    const test = standaloneFixture('sdn.wallet.connect.v1');
    const started = test.app.start();
    const login = await until(() => test.document.findAction('login'));
    const form = login.parentNode.parentNode;
    const inputs = [];
    const collect = (node) => {
      if (node.tagName === 'input') inputs.push(node);
      node.children.forEach(collect);
    };
    collect(form);
    inputs[0].value = 'alice';
    inputs[0].defaultValue = 'alice';
    inputs[1].value = 'correct horse battery staple';
    inputs[1].defaultValue = 'correct horse battery staple';
    test.document.visibilityState = 'hidden';
    form.dispatch('submit', { isTrusted: true, preventDefault() {} });
    await expect(started).rejects.toMatchObject({ code: 'WALLET_CONTEXT_UNTRUSTED' });
    expect(inputs[0].value).toBe('');
    expect(inputs[1].value).toBe('');
    expect(inputs[1].disabled).toBe(true);
    expect(form.parentNode).toBeNull();
    expect(test.derives).toBe(0);
    expect(test.published).toEqual([]);
  });

  test('native destruction failure cancels public result publication', async () => {
    const test = standaloneFixture('sdn.wallet.connect.v1');
    test.wasm.destroySdnIdentity = () => { throw new Error('native destroy failed'); };
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await expect(started).rejects.toMatchObject({ code: 'DESTRUCTION_FAILED' });
    expect(test.published).toEqual([]);
  });

  test('default relay Account renders before POST and Return publishes connected exactly once', async () => {
    const test = defaultRelayAccountFixture();
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });

    await until(() => test.document.findAction('copy-approval'));
    const returnToSite = test.document.findAction('return-to-site');
    const logout = test.document.findAction('logout');
    expect(returnToSite).toBeTruthy();
    expect(logout).toBeTruthy();
    expect(test.posts).toEqual([]);
    expect(test.replacements).toEqual([]);
    expect(test.destroyed).toEqual(['handle-1']);
    await started;

    returnToSite.dispatch('click', { isTrusted: false });
    expect(test.posts).toEqual([]);
    returnToSite.dispatch('click', { isTrusted: true });
    logout.dispatch('click', { isTrusted: true });
    await until(() => test.replacements.length === 1);
    expect(test.posts).toHaveLength(1);
    expect(test.posts[0].result).toMatchObject({ event: 'connected', schemaVersion: 1 });
    expect(test.posts[0].transactionId).toBe(test.transaction.transactionId);
    expect(test.replacements).toEqual([relayCompletion(test.transaction).redirectUri]);
  });

  test('default relay Account Logout publishes disconnected on the pending transaction', async () => {
    const test = defaultRelayAccountFixture();
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    const logout = await until(() => test.document.findAction('logout'));
    expect(test.posts).toEqual([]);
    expect(test.replacements).toEqual([]);
    await started;

    logout.dispatch('click', { isTrusted: true });
    await until(() => test.replacements.length === 1);
    expect(test.posts).toHaveLength(1);
    expect(test.posts[0].result).toEqual({
      connectionExpiresAt: null,
      event: 'disconnected',
      identity: null,
      schemaVersion: 1,
    });
    expect(test.posts[0].transactionId).toBe(test.transaction.transactionId);
  });

  test('Account forget uses a separate trusted exact confirmation and preserves the live session', async () => {
    const active = validRememberedRecord();
    const pending = '{"crash":"left"}';
    const legacyKey = 'wallet_storage_encrypted';
    const storage = memoryStorage([
      [ACTIVE_REMEMBERED_WALLET_KEY, active],
      [PENDING_REMEMBERED_WALLET_KEY, pending],
      [legacyKey, 'legacy-ciphertext'],
    ]);
    const test = defaultRelayAccountFixture({ storage });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const operationConfirm = await until(() => test.document.findAction('confirm'));
    operationConfirm.dispatch('click', { isTrusted: true });
    await started;

    const launch = test.document.findAction('forget-stored-wallet');
    expect(launch).toBeTruthy();
    const confirmForget = test.document.findAction('confirm-forget-stored-wallet');
    expect(confirmForget.parentNode.hidden).toBe(true);
    launch.dispatch('click', { isTrusted: false });
    expect(confirmForget.parentNode.hidden).toBe(true);
    launch.dispatch('click', { isTrusted: true });

    expect(confirmForget.parentNode.hidden).toBe(false);
    const confirmation = test.document.find(
      (node) => node.dataset.walletForgetConfirmation === 'exact-storage-key',
    );
    const status = test.document.find(
      (node) => node.dataset.walletForgetStatus === 'true',
    );
    expect(confirmForget).toBeTruthy();
    expect(confirmation).toBeTruthy();
    confirmation.value = 'forget';
    confirmForget.dispatch('click', { isTrusted: true });
    await until(() => status.textContent.includes('Type the exact storage key'));
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(active);

    confirmation.value = ACTIVE_REMEMBERED_WALLET_KEY;
    confirmForget.dispatch('click', { isTrusted: false });
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(active);
    confirmForget.dispatch('click', { isTrusted: true });
    await until(() => !storage.map.has(ACTIVE_REMEMBERED_WALLET_KEY));

    expect(storage.map.get(PENDING_REMEMBERED_WALLET_KEY)).toBe(pending);
    expect(storage.map.get(legacyKey)).toBe('legacy-ciphertext');
    expect(status.textContent).toBe('Stored wallet forgotten. This account remains signed in.');
    expect(test.document.findAction('copy-approval')).toBeTruthy();
    expect(test.document.findAction('logout')).toBeTruthy();
    const removal = storage.operations.findLastIndex(
      ([operation, key]) => operation === 'removeItem' && key === ACTIVE_REMEMBERED_WALLET_KEY,
    );
    expect(storage.operations.slice(removal, removal + 2)).toEqual([
      ['removeItem', ACTIVE_REMEMBERED_WALLET_KEY],
      ['getItem', ACTIVE_REMEMBERED_WALLET_KEY],
    ]);
    expect(test.posts).toEqual([]);
    expect(test.replacements).toEqual([]);
  });

  test('Account logout never deletes a valid remembered wallet', async () => {
    const active = validRememberedRecord();
    const storage = memoryStorage([[ACTIVE_REMEMBERED_WALLET_KEY, active]]);
    const test = defaultRelayAccountFixture({ storage });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    const logout = await until(() => test.document.findAction('logout'));
    await started;

    logout.dispatch('click', { isTrusted: true });
    await until(() => test.replacements.length === 1);

    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe(active);
    expect(storage.operations.some(
      ([operation, key]) => operation === 'removeItem' && key === ACTIVE_REMEMBERED_WALLET_KEY,
    )).toBe(false);
  });

  test('wallet-origin exposes quarantine before login and in Account, then Return clears it without deletion', async () => {
    const initialEntries = [
      [ACTIVE_REMEMBERED_WALLET_KEY, '{"broken":true}'],
      [PENDING_REMEMBERED_WALLET_KEY, '{"crash":"left"}'],
      ...LEGACY_WALLET_QUARANTINE_KEYS.map((key) => [key, `legacy:${key}`]),
    ];
    const storage = memoryStorage(initialEntries);
    const test = defaultRelayAccountFixture({ storage });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    expect(test.document.findAll(
      (node) => node.dataset.walletQuarantineLabel === 'true',
    ).map((node) => node.textContent)).toEqual(initialEntries.map(([key]) => key));

    submitCurrentLogin(test);
    const confirmOperation = await until(() => test.document.findAction('confirm'));
    confirmOperation.dispatch('click', { isTrusted: true });
    await started;

    const accountLabels = test.document.findAll(
      (node) => node.dataset.walletQuarantineLabel === 'true',
    );
    expect(accountLabels.map((node) => node.textContent)).toEqual(initialEntries.map(([key]) => key));
    const launchDelete = test.document.find((node) => (
      node.dataset.walletAction === 'delete-quarantined-wallet'
      && node.dataset.walletQuarantineKey === ACTIVE_REMEMBERED_WALLET_KEY
    ));
    launchDelete.dispatch('click', { isTrusted: true });
    const confirmation = test.document.find((node) => (
      node.dataset.walletQuarantineConfirmation === ACTIVE_REMEMBERED_WALLET_KEY
    ));
    const status = test.document.find((node) => node.dataset.walletQuarantineStatus === 'true');
    confirmation.value = ACTIVE_REMEMBERED_WALLET_KEY;
    const returnToSite = test.document.findAction('return-to-site');
    returnToSite.dispatch('click', { isTrusted: true });
    await until(() => test.replacements.length === 1);

    expect(confirmation.value).toBe('');
    expect(status.textContent).toBe('');
    expect([...storage.map.entries()]).toEqual(initialEntries);
    expect(storage.operations.some(([operation]) => operation === 'removeItem')).toBe(false);
  });

  test('Account quarantine export/delete require trusted events and exact confirmation', async () => {
    const storage = memoryStorage([
      [ACTIVE_REMEMBERED_WALLET_KEY, '{"broken":true}'],
      [PENDING_REMEMBERED_WALLET_KEY, '{"crash":"left"}'],
    ]);
    const writes = [];
    const test = defaultRelayAccountFixture({
      clipboard: { async writeText(value) { writes.push(value); } },
      storage,
    });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const operationConfirm = await until(() => test.document.findAction('confirm'));
    operationConfirm.dispatch('click', { isTrusted: true });
    await started;

    const exportPending = test.document.find((node) => (
      node.dataset.walletAction === 'export-quarantined-wallet'
      && node.dataset.walletQuarantineKey === PENDING_REMEMBERED_WALLET_KEY
    ));
    exportPending.dispatch('click', { isTrusted: false });
    await Promise.resolve();
    expect(writes).toEqual([]);
    exportPending.dispatch('click', { isTrusted: true });
    await until(() => writes.length === 1);
    expect(writes).toEqual(['{"crash":"left"}']);

    const launchDelete = test.document.find((node) => (
      node.dataset.walletAction === 'delete-quarantined-wallet'
      && node.dataset.walletQuarantineKey === PENDING_REMEMBERED_WALLET_KEY
    ));
    const confirmation = test.document.find((node) => (
      node.dataset.walletQuarantineConfirmation === PENDING_REMEMBERED_WALLET_KEY
    ));
    const confirmDelete = test.document.find((node) => (
      node.dataset.walletAction === 'confirm-delete-quarantined-wallet'
      && node.dataset.walletQuarantineKey === PENDING_REMEMBERED_WALLET_KEY
    ));
    launchDelete.dispatch('click', { isTrusted: true });
    confirmation.value = PENDING_REMEMBERED_WALLET_KEY;
    confirmDelete.dispatch('click', { isTrusted: false });
    expect(storage.map.has(PENDING_REMEMBERED_WALLET_KEY)).toBe(true);
    confirmation.value = 'wrong';
    confirmDelete.dispatch('click', { isTrusted: true });
    expect(storage.map.has(PENDING_REMEMBERED_WALLET_KEY)).toBe(true);
    confirmation.value = PENDING_REMEMBERED_WALLET_KEY;
    confirmDelete.dispatch('click', { isTrusted: true });
    expect(storage.map.has(PENDING_REMEMBERED_WALLET_KEY)).toBe(false);
    expect(storage.map.get(ACTIVE_REMEMBERED_WALLET_KEY)).toBe('{"broken":true}');
    expect(test.document.findAction('logout')).toBeTruthy();
  });

  test.each(['Return', 'Logout', 'pagehide'])(
    'Account %s clears quarantine confirmation and ignores late clipboard completion',
    async (termination) => {
      const storage = memoryStorage([[PENDING_REMEMBERED_WALLET_KEY, '{"crash":"left"}']]);
      const write = deferred();
      const test = defaultRelayAccountFixture({
        clipboard: { writeText: () => write.promise },
        storage,
      });
      const started = test.app.start();
      await until(() => test.document.findAction('login'));
      submitCurrentLogin(test);
      const operationConfirm = await until(() => test.document.findAction('confirm'));
      operationConfirm.dispatch('click', { isTrusted: true });
      await started;
      const exportPending = test.document.findAction('export-quarantined-wallet');
      const launchDelete = test.document.findAction('delete-quarantined-wallet');
      const confirmation = test.document.find((node) => (
        node.dataset.walletQuarantineConfirmation === PENDING_REMEMBERED_WALLET_KEY
      ));
      const status = test.document.find((node) => node.dataset.walletQuarantineStatus === 'true');
      exportPending.dispatch('click', { isTrusted: true });
      launchDelete.dispatch('click', { isTrusted: true });
      confirmation.value = PENDING_REMEMBERED_WALLET_KEY;

      if (termination === 'Return') {
        test.document.findAction('return-to-site').dispatch('click', { isTrusted: true });
        await until(() => test.replacements.length === 1);
      } else if (termination === 'Logout') {
        test.document.findAction('logout').dispatch('click', { isTrusted: true });
        await until(() => test.replacements.length === 1);
      } else {
        test.window.dispatch('pagehide', { persisted: false });
      }
      expect(confirmation.value).toBe('');
      expect(status.textContent).toBe('');
      write.resolve();
      await Promise.resolve();
      await Promise.resolve();
      expect(status.textContent).toBe('');
      expect(storage.map.get(PENDING_REMEMBERED_WALLET_KEY)).toBe('{"crash":"left"}');
      expect(storage.operations.some(([operation]) => operation === 'removeItem')).toBe(false);
    },
  );

  test('a failed Account publication consumes the action and cannot POST or navigate again', async () => {
    const test = defaultRelayAccountFixture({
      async publish() { throw new Error('ambiguous relay failure'); },
    });
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    const returnToSite = await until(() => test.document.findAction('return-to-site'));
    const logout = test.document.findAction('logout');
    await started;

    returnToSite.dispatch('click', { isTrusted: true });
    await until(() => test.document.body.textContent.includes('Wallet request stopped'));
    returnToSite.dispatch('click', { isTrusted: true });
    logout.dispatch('click', { isTrusted: true });
    await Promise.resolve();
    await Promise.resolve();
    expect(test.posts).toHaveLength(1);
    expect(test.replacements).toEqual([]);
  });

  test.each([
    ['Return', 'pagehide'],
    ['Return', 'stop'],
    ['Logout', 'pagehide'],
    ['Logout', 'stop'],
  ])(
    'Account %s pending publication cannot resurrect UI after %s and a late relay rejection',
    async (action, termination) => {
      const publication = deferred();
      const test = defaultRelayAccountFixture({
        publish: () => publication.promise,
      });
      const started = test.app.start();
      await until(() => test.document.findAction('login'));
      submitCurrentLogin(test);
      const confirm = await until(() => test.document.findAction('confirm'));
      confirm.dispatch('click', { isTrusted: true });
      await started;
      const actionControl = test.document.findAction(
        action === 'Return' ? 'return-to-site' : 'logout',
      );

      actionControl.dispatch('click', { isTrusted: true });
      await until(() => test.posts.length === 1);
      expect(test.document.body.textContent).toContain(
        action === 'Return' ? 'Returning to the requesting site.' : 'Logged out.',
      );

      if (termination === 'pagehide') {
        test.window.dispatch('pagehide', { persisted: false });
      } else {
        await test.app.stop('pending-account-publication');
      }
      expect(test.document.body.textContent).toBe('');
      expect(test.replacements).toEqual([]);

      publication.reject(new Error('late ignored relay rejection'));
      await Promise.resolve();
      await Promise.resolve();
      expect(test.document.body.textContent).toBe('');
      expect(test.document.body.textContent).not.toContain('Wallet request stopped');
      expect(test.posts).toHaveLength(1);
      expect(test.replacements).toEqual([]);
    },
  );

  test.each(['pagehide', 'destroy'])(
    'default relay Account %s clears its permit without POST or navigation',
    async (termination) => {
      const test = defaultRelayAccountFixture();
      const started = test.app.start();
      await until(() => test.document.findAction('login'));
      submitCurrentLogin(test);
      const confirm = await until(() => test.document.findAction('confirm'));
      confirm.dispatch('click', { isTrusted: true });
      const returnToSite = await until(() => test.document.findAction('return-to-site'));
      const logout = test.document.findAction('logout');
      await started;

      if (termination === 'pagehide') test.window.dispatch('pagehide', { persisted: false });
      else await test.app.stop('account-destroy');
      returnToSite.dispatch('click', { isTrusted: true });
      logout.dispatch('click', { isTrusted: true });
      await Promise.resolve();
      await Promise.resolve();
      expect(test.posts).toEqual([]);
      expect(test.replacements).toEqual([]);
    },
  );

  test('Account destroys the login handle, supports two-entry approval copy, and has separate Logout', async () => {
    standaloneFixture.clipboardWrites = [];
    const test = standaloneFixture('sdn.wallet.account.v1');
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await expect(started).resolves.toEqual({ accountReady: true });
    expect(test.destroyed).toEqual(['handle-1']);
    expect(test.published).toEqual([]);
    expect(test.document.body.textContent).toContain('Account');
    const copy = test.document.findAction('copy-approval');
    const returnToSite = test.document.findAction('return-to-site');
    const logout = test.document.findAction('logout');
    expect(copy).toBeTruthy();
    expect(returnToSite).toBeTruthy();
    expect(logout).toBeTruthy();
    expect(copy).not.toBe(logout);

    copy.dispatch('click', { isTrusted: true });
    const firstApprovalLogin = await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    await until(() => {
      const candidate = test.document.findAction('login');
      return candidate && candidate !== firstApprovalLogin ? candidate : null;
    });
    submitCurrentLogin(test);
    await until(() => standaloneFixture.clipboardWrites.length === 1);
    expect(test.destroyed).toEqual(['handle-1', 'handle-2', 'handle-3']);
    expect(JSON.parse(standaloneFixture.clipboardWrites[0])).toMatchObject({
      purpose: 'asset-review-approval',
      publicKeyHex: '2'.repeat(64),
      schemaVersion: 1,
    });

    await until(() => test.document.body.textContent.includes('configuration copied'));
    copy.dispatch('click', { isTrusted: true });
    await until(() => standaloneFixture.clipboardWrites.length === 2);
    await until(() => copy.disabled === false);
    expect(test.derives).toBe(3);

    const launchLegacy = test.document.findAction('launch-legacy-migration');
    expect(launchLegacy).toBeTruthy();
    launchLegacy.dispatch('click', { isTrusted: false });
    expect(test.document.findAction('login')).toBeNull();
    launchLegacy.dispatch('click', { isTrusted: true });
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test, 'legacy-user', 'legacy password');
    await until(() => test.document.body.textContent.includes('Legacy account xpub'));
    expect(test.document.body.textContent).toContain(`xpub${'9'.repeat(107)}`);
    expect(test.document.body.textContent).toContain('9'.repeat(64));
    expect(test.destroyed).toContain('legacy-handle');

    logout.dispatch('click', { isTrusted: true });
    await until(() => test.published.length === 1);
    expect(test.published[0]).toEqual({
      connectionExpiresAt: null,
      event: 'disconnected',
      identity: null,
      schemaVersion: 1,
    });
    expect(test.disconnected).toEqual([]);
    await until(() => test.document.body.textContent.includes('Logged out'));
    expect(test.document.body.textContent).toContain('Logged out');
  });

  test('closing an Account transaction removes its retained public surface', async () => {
    const test = standaloneFixture('sdn.wallet.account.v1');
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await started;
    expect(test.document.findAction('copy-approval')).toBeTruthy();
    await test.app.stop('close');
    expect(test.document.findAction('copy-approval')).toBeNull();
    expect(() => test.app.controller.copyPublicIdentity()).toThrowError(/STALE_CONTROLLER/u);
  });

  test('legacy comparison renders nothing until its native handle is destroyed and retries cleanup', async () => {
    const test = standaloneFixture('sdn.wallet.account.v1');
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await started;

    const originalDestroy = test.wasm.destroySdnIdentity;
    let legacyDestroyAttempts = 0;
    test.wasm.destroySdnIdentity = (handle) => {
      if (handle === 'legacy-handle') {
        legacyDestroyAttempts += 1;
        if (legacyDestroyAttempts === 1) throw new Error('native destroy failed');
      }
      originalDestroy(handle);
    };
    const launchLegacy = test.document.findAction('launch-legacy-migration');
    launchLegacy.dispatch('click', { isTrusted: true });
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test, 'legacy-user', 'legacy password');
    await until(() => test.document.body.textContent.includes(
      'Legacy account comparison could not be completed.',
    ));
    expect(test.document.body.textContent).not.toContain('Legacy account xpub');
    expect(legacyDestroyAttempts).toBe(2);
    expect(test.destroyed).toContain('legacy-handle');
    await test.app.stop('test-complete');
  });

  test('repeated Account teardown retries a persistently retained legacy handle', async () => {
    const test = standaloneFixture('sdn.wallet.account.v1');
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await started;

    const originalDestroy = test.wasm.destroySdnIdentity;
    let allowLegacyDestruction = false;
    let legacyDestroyAttempts = 0;
    test.wasm.destroySdnIdentity = (handle) => {
      if (handle === 'legacy-handle') {
        legacyDestroyAttempts += 1;
        if (!allowLegacyDestruction) throw new Error('persistent native destroy failure');
      }
      originalDestroy(handle);
    };
    test.document.findAction('launch-legacy-migration').dispatch('click', { isTrusted: true });
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test, 'legacy-user', 'legacy password');
    await until(() => test.document.body.textContent.includes(
      'Legacy account comparison could not be completed.',
    ));
    const attemptsBeforeStop = legacyDestroyAttempts;
    await test.app.stop('first-account-stop');
    expect(legacyDestroyAttempts).toBeGreaterThan(attemptsBeforeStop);

    allowLegacyDestruction = true;
    await test.app.stop('retry-account-stop');
    expect(test.destroyed).toContain('legacy-handle');
  });

  test.each(['pagehide', 'stop', 'return', 'logout'])(
    '%s during deferred legacy migration wipes bytes and permits no publication or stale rendering',
    async (termination) => {
      const test = defaultRelayAccountFixture();
      const started = test.app.start();
      await until(() => test.document.findAction('login'));
      submitCurrentLogin(test);
      const confirm = await until(() => test.document.findAction('confirm'));
      confirm.dispatch('click', { isTrusted: true });
      await started;

      const migration = deferred();
      let captured = null;
      test.wasm.deriveLegacyPasswordIdentity = (input) => {
        captured = input;
        return migration.promise;
      };
      const returnToSite = test.document.findAction('return-to-site');
      const logout = test.document.findAction('logout');
      test.document.findAction('launch-legacy-migration').dispatch('click', { isTrusted: true });
      await until(() => test.document.findAction('login'));
      submitCurrentLogin(test, 'legacy-user', 'legacy password');
      await until(() => captured);

      let stopping = null;
      if (termination === 'pagehide') test.window.dispatch('pagehide', { persisted: false });
      if (termination === 'stop') stopping = test.app.stop('migration-stop');
      if (termination === 'return') returnToSite.dispatch('click', { isTrusted: true });
      if (termination === 'logout') logout.dispatch('click', { isTrusted: true });

      expect([...captured.usernameUtf8]).toEqual(Array(captured.usernameUtf8.length).fill(0));
      expect([...captured.passwordUtf8]).toEqual(Array(captured.passwordUtf8.length).fill(0));
      expect(test.posts).toEqual([]);
      expect(test.replacements).toEqual([]);

      migration.resolve({ handle: 'late-legacy-handle', identity: legacyIdentity() });
      await until(() => test.destroyed.includes('late-legacy-handle'));
      if (stopping) await stopping;
      expect(test.document.body.textContent).not.toContain(`xpub${'9'.repeat(107)}`);
      expect(test.document.body.textContent).not.toContain('Legacy account comparison could not be completed.');
      expect(test.posts).toEqual([]);
      expect(test.replacements).toEqual([]);
    },
  );

  test.each(['return', 'logout'])(
    '%s during deferred approval copy wipes bytes and permits no publication',
    async (termination) => {
      const test = defaultRelayAccountFixture();
      const started = test.app.start();
      await until(() => test.document.findAction('login'));
      submitCurrentLogin(test);
      const initialConfirm = await until(() => test.document.findAction('confirm'));
      initialConfirm.dispatch('click', { isTrusted: true });
      await started;

      const approvalDerivation = deferred();
      let captured = null;
      test.wasm.derivePasswordIdentity = (input) => {
        captured = input;
        return approvalDerivation.promise;
      };
      const returnToSite = test.document.findAction('return-to-site');
      const logout = test.document.findAction('logout');
      test.document.findAction('copy-approval').dispatch('click', { isTrusted: true });
      await until(() => test.document.findAction('login'));
      submitCurrentLogin(test);
      await until(() => captured);

      (termination === 'return' ? returnToSite : logout).dispatch('click', { isTrusted: true });
      expect([...captured.usernameUtf8]).toEqual(Array(captured.usernameUtf8.length).fill(0));
      expect([...captured.passwordUtf8]).toEqual(Array(captured.passwordUtf8.length).fill(0));
      expect(test.posts).toEqual([]);
      expect(test.replacements).toEqual([]);

      approvalDerivation.resolve({ handle: 'late-approval-copy', identity: identity() });
      await until(() => test.destroyed.includes('late-approval-copy'));
      expect(test.posts).toEqual([]);
      expect(test.replacements).toEqual([]);
      expect(test.document.body.textContent).not.toContain('configuration copied');
    },
  );

  test('public Account logout retains an approval owner until cleanup succeeds, then publishes once', async () => {
    const test = defaultRelayAccountFixture();
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const initialConfirm = await until(() => test.document.findAction('confirm'));
    initialConfirm.dispatch('click', { isTrusted: true });
    await started;

    const approvalDerivation = deferred();
    let captured = null;
    let cleanupAllowed = false;
    let cleanupAttempts = 0;
    const originalDestroy = test.wasm.destroySdnIdentity;
    test.wasm.derivePasswordIdentity = (input) => {
      captured = input;
      return approvalDerivation.promise;
    };
    test.wasm.destroySdnIdentity = (handle) => {
      if (handle === 'late-persistent-approval') {
        cleanupAttempts += 1;
        if (!cleanupAllowed) throw new Error('persistent approval cleanup failure');
      }
      originalDestroy(handle);
    };

    test.document.findAction('copy-approval').dispatch('click', { isTrusted: true });
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    await until(() => captured);

    await expect(test.app.logout()).rejects.toMatchObject({ code: 'DESTRUCTION_FAILED' });
    expect([...captured.usernameUtf8]).toEqual(Array(captured.usernameUtf8.length).fill(0));
    expect([...captured.passwordUtf8]).toEqual(Array(captured.passwordUtf8.length).fill(0));
    expect(test.document.findAction('copy-approval')).toBeNull();
    expect(test.document.findAction('launch-legacy-migration')).toBeNull();
    expect(test.document.findAction('return-to-site')).toBeTruthy();
    expect(test.document.findAction('logout')).toBeTruthy();
    expect(test.document.body.textContent).not.toContain('Complete');
    expect(test.posts).toEqual([]);
    expect(test.replacements).toEqual([]);

    approvalDerivation.resolve({ handle: 'late-persistent-approval', identity: identity() });
    await until(() => cleanupAttempts > 0);
    await expect(test.app.logout()).rejects.toMatchObject({ code: 'DESTRUCTION_FAILED' });
    expect(test.document.findAction('return-to-site')).toBeTruthy();
    expect(test.document.findAction('logout')).toBeTruthy();
    expect(test.posts).toEqual([]);
    expect(test.replacements).toEqual([]);

    cleanupAllowed = true;
    await test.app.logout();
    await until(() => test.replacements.length === 1);
    expect(test.posts).toHaveLength(1);
    expect(test.posts[0].result).toMatchObject({ event: 'disconnected', schemaVersion: 1 });
    await test.app.logout();
    expect(test.posts).toHaveLength(1);
    expect(test.replacements).toHaveLength(1);
  });

  test('Account Return retains a legacy owner and exit-only retry surface until cleanup succeeds', async () => {
    const test = defaultRelayAccountFixture();
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const initialConfirm = await until(() => test.document.findAction('confirm'));
    initialConfirm.dispatch('click', { isTrusted: true });
    await started;

    const migration = deferred();
    let captured = null;
    let cleanupAllowed = false;
    let cleanupAttempts = 0;
    const originalDestroy = test.wasm.destroySdnIdentity;
    test.wasm.deriveLegacyPasswordIdentity = (input) => {
      captured = input;
      return migration.promise;
    };
    test.wasm.destroySdnIdentity = (handle) => {
      if (handle === 'late-persistent-exit-legacy') {
        cleanupAttempts += 1;
        if (!cleanupAllowed) throw new Error('persistent legacy cleanup failure');
      }
      originalDestroy(handle);
    };

    test.document.findAction('launch-legacy-migration').dispatch('click', { isTrusted: true });
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test, 'legacy-user', 'legacy password');
    await until(() => captured);
    const returnToSite = test.document.findAction('return-to-site');
    returnToSite.dispatch('click', { isTrusted: true });

    expect([...captured.usernameUtf8]).toEqual(Array(captured.usernameUtf8.length).fill(0));
    expect([...captured.passwordUtf8]).toEqual(Array(captured.passwordUtf8.length).fill(0));
    expect(test.document.findAction('copy-approval')).toBeNull();
    expect(test.document.findAction('launch-legacy-migration')).toBeNull();
    expect(test.document.findAction('return-to-site')).toBeTruthy();
    expect(test.document.findAction('logout')).toBeTruthy();
    expect(test.document.body.textContent).not.toContain('Complete');
    expect(test.posts).toEqual([]);
    expect(test.replacements).toEqual([]);

    migration.resolve({ handle: 'late-persistent-exit-legacy', identity: legacyIdentity() });
    await until(() => cleanupAttempts > 0);
    returnToSite.dispatch('click', { isTrusted: true });
    await Promise.resolve();
    expect(test.document.findAction('return-to-site')).toBeTruthy();
    expect(test.document.findAction('logout')).toBeTruthy();
    expect(test.posts).toEqual([]);
    expect(test.replacements).toEqual([]);

    cleanupAllowed = true;
    const retryLogout = test.document.findAction('logout');
    returnToSite.dispatch('click', { isTrusted: true });
    retryLogout.dispatch('click', { isTrusted: true });
    await until(() => test.replacements.length === 1);
    expect(test.posts).toHaveLength(1);
    expect(test.posts[0].result).toMatchObject({ event: 'connected', schemaVersion: 1 });
    expect(test.replacements).toHaveLength(1);
  });

  test('late legacy handle remains surface-owned across repeated stop cleanup failures', async () => {
    const test = standaloneFixture('sdn.wallet.account.v1');
    const started = test.app.start();
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test);
    const confirm = await until(() => test.document.findAction('confirm'));
    confirm.dispatch('click', { isTrusted: true });
    await started;

    const migration = deferred();
    let captured = null;
    let cleanupAllowed = false;
    let cleanupAttempts = 0;
    const originalDestroy = test.wasm.destroySdnIdentity;
    test.wasm.deriveLegacyPasswordIdentity = (input) => {
      captured = input;
      return migration.promise;
    };
    test.wasm.destroySdnIdentity = (handle) => {
      if (handle === 'late-persistent-legacy') {
        cleanupAttempts += 1;
        if (!cleanupAllowed) throw new Error('persistent late cleanup failure');
      }
      originalDestroy(handle);
    };

    test.document.findAction('launch-legacy-migration').dispatch('click', { isTrusted: true });
    await until(() => test.document.findAction('login'));
    submitCurrentLogin(test, 'legacy-user', 'legacy password');
    await until(() => captured);
    const firstStop = test.app.stop('first-late-stop');
    expect([...captured.passwordUtf8]).toEqual(Array(captured.passwordUtf8.length).fill(0));
    migration.resolve({ handle: 'late-persistent-legacy', identity: legacyIdentity() });
    await until(() => cleanupAttempts > 0);
    await firstStop;

    const attemptsBeforeRetry = cleanupAttempts;
    await test.app.stop('second-late-stop');
    expect(cleanupAttempts).toBeGreaterThan(attemptsBeforeRetry);
    cleanupAllowed = true;
    await test.app.stop('successful-late-stop');
    expect(test.destroyed).toContain('late-persistent-legacy');
  });
});
