import { readFile } from 'node:fs/promises';

import { describe, expect, test, vi } from 'vitest';

vi.mock('hd-wallet-wasm', () => ({
  getWalletOriginCapabilities(module) {
    const sdn = module?.sdn ?? module;
    const hashOwner = module?.utils ?? module;
    if (!sdn || typeof hashOwner?.sha256 !== 'function') throw new TypeError('invalid owner');
    return Object.freeze({ sdn, sha256: hashOwner.sha256.bind(hashOwner) });
  },
}));

import { createWalletOriginApp, transactionIdFromLocation } from '../origin-app/app.mjs';
import { WalletOriginController } from '../origin-app/controller.mjs';
import { deriveExplicitLegacyIdentity } from '../origin-app/account.mjs';
import { resolveRegistryBinding } from '../origin-app/registry.mjs';

class Events {
  constructor() { this.listeners = new Map(); }
  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, new Set());
    this.listeners.get(type).add(listener);
  }
  removeEventListener(type, listener) { this.listeners.get(type)?.delete(listener); }
  dispatch(type, event = {}) {
    for (const listener of [...(this.listeners.get(type) ?? [])]) listener(event);
  }
  count() { return [...this.listeners.values()].reduce((sum, set) => sum + set.size, 0); }
}

function publicIdentity() {
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
  };
}

function lifecycleFixture() {
  const document = new Events();
  document.visibilityState = 'visible';
  document.hasFocus = () => true;
  document.body = { append() {} };
  document.createElement = () => ({
    addEventListener() {}, append() {}, dataset: {}, remove() {}, set textContent(_value) {},
  });
  document.createTextNode = (value) => ({ textContent: String(value) });
  const window = new Events();
  window.top = window;
  window.location = { reloads: 0, reload() { this.reloads += 1; } };
  const destroyed = [];
  const relay = {
    aborts: 0,
    destroyCalls: 0,
    async destroy() { this.destroyCalls += 1; },
    revokeNow() { this.aborts += 1; },
  };
  const wasm = {
    async derivePasswordIdentity() { return { handle: 'handle-1', identity: publicIdentity() }; },
    destroySdnIdentity(handle) { destroyed.push(handle); },
    sha256() { return new Uint8Array(32); },
  };
  const controller = new WalletOriginController({
    document,
    registry: {},
    relay,
    rng: {},
    wasm,
    window,
  });
  return { controller, destroyed, document, relay, wasm, window };
}

function simpleControl(value) {
  return {
    defaultValue: value,
    disabled: false,
    form: null,
    removeAttribute() {},
    setCustomValidity() {},
    setSelectionRange() {},
    value,
  };
}

describe('synchronous lifecycle revocation', () => {
  test.each(['pagehide', 'freeze', 'beforeunload'])(
    '%s drops the native handle before the handler returns',
    async (eventName) => {
      const test = lifecycleFixture();
      await test.controller.unlockPassword({
        passwordControl: simpleControl('correct horse battery staple'),
        usernameControl: simpleControl('alice'),
      });
      const before = test.controller.generation;
      const target = eventName === 'freeze' ? test.document : test.window;
      target.dispatch(eventName);
      expect(test.destroyed).toEqual(['handle-1']);
      expect(test.controller.generation).toBe(before + 1);
      target.dispatch(eventName);
      expect(test.destroyed).toEqual(['handle-1']);
    },
  );

  test('BFCache restore remains logged out and reloads a fresh application', async () => {
    const test = lifecycleFixture();
    await test.controller.unlockPassword({
      passwordControl: simpleControl('correct horse battery staple'),
      usernameControl: simpleControl('alice'),
    });
    test.window.dispatch('pageshow', { persisted: true });
    expect(test.destroyed).toEqual(['handle-1']);
    expect(test.window.location.reloads).toBe(1);
  });

  test('destroy is idempotent and removes every listener/request/timer owner', async () => {
    const test = lifecycleFixture();
    expect(test.window.count() + test.document.count()).toBe(4);
    await Promise.all([test.controller.destroy('close'), test.controller.destroy('close-again')]);
    expect(test.window.count() + test.document.count()).toBe(0);
    expect(test.relay.aborts).toBe(1);
    expect(test.relay.destroyCalls).toBe(1);
  });

  test('destroy publishes one stable promise before an abort listener can reenter it', async () => {
    const test = lifecycleFixture();
    let reenteredDestroy = null;
    let signalReady;
    const ready = new Promise((resolve) => { signalReady = resolve; });
    test.relay.fetchTransaction = (_transactionId, { signal }) => new Promise((_resolve, reject) => {
      signal.addEventListener('abort', () => {
        reenteredDestroy = test.controller.destroy('abort-reentry');
        reject(new Error('hostile relay aborted'));
      }, { once: true });
      signalReady();
    });

    const preparing = test.controller.prepare('a'.repeat(64));
    await ready;
    const destroying = test.controller.destroy('outer-destroy');
    expect(reenteredDestroy).toBe(destroying);
    await destroying;
    await expect(preparing).rejects.toMatchObject({ code: 'STALE_CONTROLLER' });
    expect(test.relay.destroyCalls).toBe(1);
  });

  test('pagehide clears a tracked credential form even before submit', () => {
    const test = lifecycleFixture();
    const removed = [];
    const form = {
      inert: false,
      querySelectorAll: () => [usernameControl, passwordControl],
      remove() { removed.push(true); },
      replaceChildren() {},
      replaceWith() { removed.push(true); },
      setAttribute() {},
    };
    const usernameControl = simpleControl('alice');
    const passwordControl = simpleControl('secret');
    usernameControl.form = form;
    passwordControl.form = form;
    test.controller.registerCredentialControls({ passwordControl, usernameControl });
    test.window.dispatch('pagehide', { persisted: true });
    expect(usernameControl.value).toBe('');
    expect(passwordControl.value).toBe('');
    expect(passwordControl.disabled).toBe(true);
    expect(removed).toHaveLength(1);
  });

  test('credential subtree teardown observes an already-terminal controller', () => {
    const test = lifecycleFixture();
    const usernameControl = simpleControl('alice');
    const passwordControl = simpleControl('secret');
    let observedCode = null;
    const form = {
      querySelectorAll: () => [usernameControl, passwordControl],
      replaceChildren() {},
      replaceWith() {
        try {
          test.controller.registerCredentialControls({
            passwordControl: simpleControl('replacement-secret'),
            usernameControl: simpleControl('mallory'),
          });
        } catch (error) {
          observedCode = error?.code;
        }
      },
      setAttribute() {},
    };
    usernameControl.form = form;
    passwordControl.form = form;
    test.controller.registerCredentialControls({ passwordControl, usernameControl });

    test.controller.revokeNow('credential-teardown-reentry');

    expect(observedCode).toBe('STALE_CONTROLLER');
  });
});

describe('explicit-only legacy migration', () => {
  test.each([
    ['password-fast-v1-legacy', 'deriveLegacyPasswordIdentity', { usernameUtf8: new Uint8Array([1]), passwordUtf8: new Uint8Array([2]) }],
    ['bip39-mnemonic-v1-legacy', 'importLegacyMnemonicIdentity', { mnemonicUtf8: new Uint8Array([3]) }],
  ])('runs only the selected %s capability and permits raw-v1 only', async (profile, method, credentials) => {
    const calls = [];
    const wasm = {
      async [method](input) { calls.push(input); return { handle: 'legacy', identity: { identityScheme: profile, seedProfile: profile } }; },
      destroySdnIdentity() {},
    };
    const result = await deriveExplicitLegacyIdentity({
      accountIndex: 0,
      credentials,
      operation: 'sdn.auth.raw-challenge.v1',
      profile,
      wasm,
    });
    expect(result.legacy).toBe(true);
    expect(result.approval).toBeNull();
    expect(calls).toHaveLength(1);
    await expect(deriveExplicitLegacyIdentity({
      accountIndex: 0,
      credentials,
      operation: 'sdn.auth.jcs-envelope.v2',
      profile,
      wasm,
    })).rejects.toMatchObject({ code: 'OPERATION_NOT_ALLOWED' });
  });

  test('does not infer a legacy profile or retry from a failed v2 derivation', async () => {
    await expect(deriveExplicitLegacyIdentity({
      accountIndex: 0,
      credentials: {},
      operation: 'sdn.auth.raw-challenge.v1',
      profile: undefined,
      wasm: {},
    })).rejects.toMatchObject({ code: 'INVALID_LEGACY_PROFILE' });
  });
});

test('origin app accepts only an exact transaction pathname and destroys on startup failure', async () => {
  const destroyed = [];
  const controller = {
    async destroy(reason) { destroyed.push(reason); },
    async execute() { throw new Error('relay failed'); },
  };
  const app = createWalletOriginApp({
    controller,
    window: { location: { pathname: `/transaction/${'a'.repeat(64)}` } },
  });
  await expect(app.start()).rejects.toThrow('relay failed');
  expect(destroyed).toEqual(['startup-failure']);

  const invalid = createWalletOriginApp({
    controller,
    window: { location: { pathname: `/transaction/${'A'.repeat(64)}?request=secret` } },
  });
  await expect(invalid.start()).rejects.toMatchObject({ code: 'INVALID_TRANSACTION' });
});

test.each([
  ['search', { hash: '', search: '?request=secret' }],
  ['hash', { hash: '#request=secret', search: '' }],
  ['search and hash', { hash: '#fragment', search: '?query=1' }],
])('transaction location rejects a real nonempty %s component', (_label, components) => {
  const location = {
    pathname: `/transaction/${'a'.repeat(64)}`,
    ...components,
  };
  expect(() => transactionIdFromLocation(location)).toThrowError(/INVALID_TRANSACTION/u);
});

test('origin app factory installs the strict same-origin relay when none is injected', async () => {
  const test = lifecycleFixture();
  const transactionId = 'a'.repeat(64);
  const calls = [];
  test.window.location.pathname = `/transaction/${transactionId}`;
  test.window.location.replace = () => { throw new Error('malformed relay data must not navigate'); };
  const app = createWalletOriginApp({
    document: test.document,
    fetch: async (url, options) => {
      calls.push({ options, url });
      return new Response('{}', {
        headers: {
          'Cache-Control': 'no-store',
          'Content-Type': 'application/json; charset=utf-8',
        },
        status: 200,
      });
    },
    registry: {},
    rng: {},
    wasm: test.wasm,
    window: test.window,
  });

  await expect(app.start()).rejects.toMatchObject({ code: 'RELAY_FAILURE' });
  expect(calls).toHaveLength(1);
  expect(calls[0]).toMatchObject({
    url: `/relay/v1/transactions/${transactionId}`,
    options: {
      cache: 'no-store',
      credentials: 'omit',
      method: 'GET',
      mode: 'same-origin',
      redirect: 'error',
      referrerPolicy: 'no-referrer',
    },
  });
});

test('origin app validates before prompting, then unlocks and consumes the prepared transaction', async () => {
  const calls = [];
  const prepared = Object.freeze({
    binding: Object.freeze({ clientDisplayName: 'Space Data Network' }),
    transaction: Object.freeze({ operation: 'sdn.wallet.connect.v1' }),
  });
  const usernameControl = { value: 'alice' };
  const passwordControl = { value: 'secret' };
  const controller = {
    async prepare(transactionId) {
      calls.push(['prepare', transactionId]);
      return prepared;
    },
    async unlockPassword(controls) {
      calls.push(['unlock', controls]);
      return Object.freeze({ accountIndex: 0 });
    },
    async executePrepared(value) {
      calls.push(['execute', value]);
      return Object.freeze({ ok: true });
    },
    async destroy(reason) { calls.push(['destroy', reason]); },
  };
  const credentialPrompt = async ({ transaction }) => {
    calls.push(['prompt', transaction]);
    return { passwordControl, usernameControl };
  };
  const transactionId = 'a'.repeat(64);
  const app = createWalletOriginApp({
    controller,
    credentialPrompt,
    window: { location: { pathname: `/transaction/${transactionId}` } },
  });
  await expect(app.start()).resolves.toEqual({ ok: true });
  expect(calls).toEqual([
    ['prepare', transactionId],
    ['prompt', prepared],
    ['unlock', { passwordControl, usernameControl }],
    ['execute', prepared],
  ]);
});

test('legacy UI repairs both createWalletUI forms, rejects WASM init failure, and wipes the session seed', async () => {
  const app = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
  expect(app).toContain('normalizeCreateWalletUIArguments');
  expect(app).toMatch(/createWalletUI\(rootElementOrOptions, options/u);
  expect(app).toMatch(/throw err/u);
  expect(app).toMatch(/state\.masterSeed\?\.fill\?\.\(0\)/u);
  expect(app).toMatch(/state\.hdRoot\?\.wipe\?\.\(\)/u);
  expect(app).toMatch(/state\.addresses\s*=\s*\{\s*btc:\s*null,\s*eth:\s*null,\s*sol:\s*null/su);
  expect(app).not.toMatch(/async sign\(message\)/u);
  expect(app).not.toMatch(/getSigningKey\(state\.hdRoot, 0, 0, 0\)/u);
  expect(app).not.toContain("$('account-logout')?.addEventListener('click', logout)");
  expect(app).toContain('logout: () => app.logout()');
  expect(app).toContain('forget-stored-wallet');
});

function sourceBetween(source, start, end) {
  const from = source.indexOf(start);
  expect(from, start).toBeGreaterThanOrEqual(0);
  const to = source.indexOf(end, from + start.length);
  expect(to, end).toBeGreaterThan(from);
  return source.slice(from, to);
}

test('session work is bound to a login generation and logout tears every surface down', async () => {
  const app = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
  const balances = await readFile(new URL('../src/balances.js', import.meta.url), 'utf8');
  const balanceSource = sourceBetween(balances, 'async function fetchBalance(', '\n  /**\n   * Scan every target once.');
  const refreshSource = sourceBetween(app, 'async function refreshBalances', '\nfunction assetsState');
  const logoutSource = sourceBetween(app, 'function logout()', '\n// =============================================================================\n// Grid Canvas Animation');

  expect(app).toContain('legacySessionGuard.begin();');
  expect(app).toContain('legacySessionGuard.invalidate();');
  expect(balanceSource.match(/isCurrent\(\)/gu)?.length ?? 0).toBeGreaterThanOrEqual(4);
  expect(refreshSource).toMatch(/balanceScanner\.scan\(targets, current, \{ force \}\)/u);
  expect(refreshSource).toContain('const current = () => isCurrentLegacySession(sessionGeneration) && account === state.account;');

  expect(logoutSource).toContain('wipeSession();');
  expect(logoutSource).toContain('clearTrustState();');
  expect(logoutSource).toContain('_shell?.close();');
  expect(logoutSource).toMatch(/for \(const pane of Object\.values\(_panes \?\? \{\}\)\)[\s\S]*pane\.reset\(\)/u);
  expect(logoutSource).toContain('state.balances = {};');
  expect(logoutSource).toContain('balanceScanner.reset();');
  expect(logoutSource).toContain('state.storage = null;');
  expect(logoutSource).toContain('_barPhoto.logout();');
  expect(logoutSource).toContain('clearSeedPhrase();');
});

test('the trust scan is session-bound, per account, and never polls in the background', async () => {
  const app = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
  const scanSource = sourceBetween(app, 'async function runTrustScan', '\nfunction clearTrustState');
  const publishSource = sourceBetween(app, 'async function publishTrustRecord', '\nfunction trustEthRpc');

  expect(scanSource).toContain('runTrustScan(sessionGeneration = currentLegacySession()');
  expect(scanSource.match(/isCurrentLegacySession\(sessionGeneration\)/gu)?.length ?? 0).toBeGreaterThanOrEqual(5);
  expect(scanSource).toContain('addressesSnapshot');
  expect(scanSource).toContain('TRUST_SCAN_MIN_INTERVAL_MS');
  expect(app).not.toMatch(/setInterval\(/u);
  // Publishing and revoking sign with the CURRENT account's chain keys (B10).
  expect(publishSource).toContain('const paths = chainPaths(state.account);');
  for (const chain of ['btc', 'eth', 'sol']) expect(publishSource).toContain(`scopedChainKey(paths.${chain}`);
  expect(publishSource).not.toMatch(/buildSigningPath\(coinType, 0, 0\)/u);
});

test('profile photo and camera continuations are session-bound and a section switch stops the camera', async () => {
  const profile = await readFile(new URL('../src/profile-ui.js', import.meta.url), 'utf8');
  const resetSource = sourceBetween(profile, '    reset() {', '    destroy() {');

  expect(profile).toContain('readFileBytesForSession');
  expect(profile).toContain('acquireMediaStreamForSession');
  expect(profile).toContain('stopMediaStream');
  expect(profile).toContain('inspectPhotoBytes');
  expect(profile).toContain('PhotoUrlController');
  expect(profile.match(/stale\(token\)/gu)?.length ?? 0).toBeGreaterThanOrEqual(8);
  expect(resetSource).toContain('stopCamera();');
  expect(resetSource).toContain('photoUrls.logout();');
  expect(profile).not.toMatch(/readAsDataURL|innerHTML/u);
});

test('no 2.x account-modal runtime survives: no wallets layer, $EME, vCard, PKI demo or name resolution', async () => {
  const app = await readFile(new URL('../src/app.js', import.meta.url), 'utf8');
  for (const gone of [
    'DEFAULT_WALLET_COUNT', 'normalizeWallets', 'ensureWalletAccounts', 'createNewWallet', 'renderWalletList',
    'renderWalletSelector', 'updateWalletBondDisplay', 'showWalletsView', 'showWalletMainView', 'addCustomPathAccount',
    'toggleAccountActive', 'handleAccountAction', 'EMET', 'emeToJSON', 'ecies-x25519-aes256gcm', 'generateVCard',
    'verifyVCardSignature', 'parseAndDisplayVCF', 'generatePKIKeyPairs', 'loadPKIKeys', 'wallet-pki-keys',
    'api.hiro.so', 'bonfida', 'resolveENSName', 'autoOpenWallet', 'deriveAndDisplayAddress', 'updatePathDisplay',
    'applyTrustRules', 'buildSdsTrustExport', 'importTrustData', "'keys-modal'", 'vcard-cryptoperson',
  ]) {
    expect(app, gone).not.toContain(gone);
  }
  // Private keys are derived per operation, never kept in session state.
  expect(app).not.toMatch(/state\.wallet\b/u);
  expect(app).not.toMatch(/privateKey:\s*[a-zA-Z]+\.privateKey/u);
});

test('both createWalletUI forms hide signer authority and repeated public destroy retries late cleanup', async () => {
  const originalDocument = globalThis.document;
  const originalNode = globalThis.Node;
  const originalWindow = globalThis.window;
  class TestNode extends Events {
    constructor(ownerDocument = null) {
      super();
      this.children = [];
      this.dataset = {};
      this.ownerDocument = ownerDocument;
      this.parentNode = null;
    }
    append(...children) {
      for (const child of children) {
        child.parentNode = this;
        this.children.push(child);
      }
    }
    remove() {
      if (!this.parentNode) return;
      this.parentNode.children = this.parentNode.children.filter((child) => child !== this);
      this.parentNode = null;
    }
    replaceChildren(...children) {
      for (const child of this.children) child.parentNode = null;
      this.children = [];
      this.append(...children);
    }
    set textContent(value) {
      this.value = String(value);
      this.replaceChildren();
    }
    get textContent() {
      return this.value ?? this.children.map((child) => child.textContent).join('');
    }
  }
  const testDocument = new Events();
  testDocument.visibilityState = 'visible';
  testDocument.hasFocus = () => true;
  testDocument.body = new TestNode(testDocument);
  testDocument.createElement = () => new TestNode(testDocument);
  testDocument.createTextNode = (value) => {
    const node = new TestNode(testDocument);
    node.textContent = value;
    return node;
  };
  const testWindow = new Events();
  testWindow.document = testDocument;
  testWindow.location = { pathname: '/' };
  testWindow.top = testWindow;
  const wasm = {
    async derivePasswordIdentity() { throw new Error('invalid path must fail first'); },
    destroySdnIdentity() {},
    sha256() { return new Uint8Array(32); },
  };
  const dependencies = {
    document: testDocument,
    registry: { resolveRegistryBinding() { throw new Error('invalid path must fail first'); } },
    relay: {},
    rng: {},
    wasm,
    window: testWindow,
  };
  try {
    globalThis.document = testDocument;
    globalThis.Node = TestNode;
    globalThis.window = testWindow;
    const { createWalletUI } = await import('../src/app.js');
    const positionalMount = new TestNode(testDocument);
    const objectMount = new TestNode(testDocument);
    const positional = await createWalletUI(positionalMount, dependencies);
    const object = await createWalletUI({ element: objectMount, ...dependencies });

    expect(Object.keys(positional).sort()).toEqual(['destroy', 'logout', 'openAccount', 'openLogin']);
    expect('controller' in positional).toBe(false);
    expect('sign' in positional).toBe(false);
    await expect(positional.openLogin()).rejects.toMatchObject({ code: 'INVALID_TRANSACTION' });
    await expect(object.openAccount()).rejects.toMatchObject({ code: 'INVALID_TRANSACTION' });
    expect(positionalMount.children).toHaveLength(1);
    expect(objectMount.children).toHaveLength(1);
    await positional.destroy();
    await object.destroy();

    const defaultRelayCalls = [];
    const { relay: _injectedRelay, ...defaultDependencies } = dependencies;
    testWindow.location.pathname = `/transaction/${'a'.repeat(64)}`;
    testWindow.location.replace = () => { throw new Error('invalid response must not navigate'); };
    const defaultUi = await createWalletUI({
      element: new TestNode(testDocument),
      ...defaultDependencies,
      fetch: async (url, requestOptions) => {
        defaultRelayCalls.push({ requestOptions, url });
        return new Response('{}', {
          headers: {
            'Cache-Control': 'no-store',
            'Content-Type': 'application/json; charset=utf-8',
          },
          status: 200,
        });
      },
      location: testWindow.location,
    });
    await expect(defaultUi.openLogin()).rejects.toMatchObject({ code: 'RELAY_FAILURE' });
    expect(defaultRelayCalls).toHaveLength(1);
    expect(defaultRelayCalls[0].url).toBe(`/relay/v1/transactions/${'a'.repeat(64)}`);
    expect(defaultRelayCalls[0].requestOptions.credentials).toBe('omit');
    await defaultUi.destroy();

    const binding = resolveRegistryBinding({
      clientId: 'sdn-landing-web-v1',
      operation: 'sdn.wallet.connect.v1',
      requestOrigin: 'https://spacedatanetwork.org',
    });
    const transactionId = 'e'.repeat(64);
    const requestSha256 = '44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a';
    const lateTransaction = {
      callbackUri: binding.callbackUri,
      clientDisplayName: binding.clientDisplayName,
      clientId: binding.clientId,
      expiresAt: new Date(Date.now() + 60_000).toISOString(),
      operation: binding.operation,
      registryVersion: binding.registryReleaseSha256,
      request: {},
      requestOrigin: binding.requestOrigin,
      requestSha256,
      resultToken: 'C'.repeat(43),
      schemaVersion: 1,
      state: 'd'.repeat(64),
      transactionId,
    };
    let capturedCredentials = null;
    let resolveDerivation;
    let signalDerivationStarted;
    let cleanupAllowed = false;
    let cleanupAttempts = 0;
    const derivationStarted = new Promise((resolve) => { signalDerivationStarted = resolve; });
    const lateDerivation = new Promise((resolve) => { resolveDerivation = resolve; });
    const lateWasm = {
      derivePasswordIdentity(input) {
        capturedCredentials = input;
        signalDerivationStarted();
        return lateDerivation;
      },
      destroySdnIdentity(handle) {
        if (handle !== 'late-public-handle') return;
        cleanupAttempts += 1;
        if (!cleanupAllowed) throw new Error('late native cleanup failed');
      },
      sha256() {
        return Uint8Array.from(
          requestSha256.match(/../gu),
          (pair) => Number.parseInt(pair, 16),
        );
      },
    };
    testWindow.location = { hash: '', pathname: `/transaction/${transactionId}`, search: '' };
    const lateUi = await createWalletUI({
      credentialPrompt: () => ({
        passwordControl: simpleControl('correct horse battery staple'),
        usernameControl: simpleControl('alice'),
      }),
      document: testDocument,
      element: new TestNode(testDocument),
      registry: { resolveRegistryBinding },
      relay: {
        destroy() {},
        fetchTransaction() { return lateTransaction; },
        hashRequest() { return requestSha256; },
        revokeNow() {},
      },
      rng: {},
      wasm: lateWasm,
      window: testWindow,
    });
    const openingLateUi = lateUi.openLogin();
    await derivationStarted;
    const firstPublicDestroy = lateUi.destroy();
    expect([...capturedCredentials.usernameUtf8])
      .toEqual(Array(capturedCredentials.usernameUtf8.length).fill(0));
    expect([...capturedCredentials.passwordUtf8])
      .toEqual(Array(capturedCredentials.passwordUtf8.length).fill(0));
    resolveDerivation({ handle: 'late-public-handle', identity: publicIdentity() });
    await expect(openingLateUi).rejects.toMatchObject({ code: 'DESTRUCTION_FAILED' });
    await firstPublicDestroy;

    const attemptsBeforePublicRetry = cleanupAttempts;
    expect(lateUi.destroy()).toBe(firstPublicDestroy);
    expect(cleanupAttempts).toBeGreaterThan(attemptsBeforePublicRetry);
    cleanupAllowed = true;
    const attemptsBeforeSuccess = cleanupAttempts;
    expect(lateUi.destroy()).toBe(firstPublicDestroy);
    expect(cleanupAttempts).toBeGreaterThan(attemptsBeforeSuccess);

    const initializationFailure = new Error('WASM initialization failed');
    await expect(createWalletUI({
      element: new TestNode(testDocument),
      ...dependencies,
      wasm: Promise.reject(initializationFailure),
    })).rejects.toBe(initializationFailure);
  } finally {
    globalThis.document = originalDocument;
    globalThis.Node = originalNode;
    globalThis.window = originalWindow;
  }
});
