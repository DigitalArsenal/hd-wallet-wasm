import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

import { describe, expect, test } from 'vitest';

const publicGlobalUrl = new URL('../dist/browser/sdn-wallet-public-client.js', import.meta.url);
const callbackGlobalUrl = new URL('../dist/browser/sdn-wallet-callback.js', import.meta.url);

const CLIENT_IDS = Object.freeze([
  'orbpro-pages-v1',
  'sdn-asset-models-pages-v1',
  'sdn-asset-review-v1',
  'sdn-flatbuffers-pages-v1',
  'sdn-flatsql-pages-v1',
  'sdn-landing-web-v1',
  'sdn-module-sdk-pages-v1',
  'sdn-node-console-v1',
  'sdn-standards-web-v1',
  'spaceaware-web-v1',
]);

function instrumentedContext() {
  const counts = {
    close: 0,
    fetch: 0,
    listeners: 0,
    open: 0,
    storage: 0,
    timers: 0,
  };
  const window = {
    addEventListener() { counts.listeners += 1; },
    open() { counts.open += 1; return null; },
    removeEventListener() {},
  };
  Object.defineProperty(window, 'localStorage', {
    configurable: false,
    enumerable: true,
    get() {
      counts.storage += 1;
      throw new Error('localStorage must remain lazy');
    },
  });
  const context = vm.createContext({
    AbortController,
    TextDecoder,
    TextEncoder,
    Uint8Array,
    clearInterval() {},
    clearTimeout() {},
    console: Object.freeze({ error() {}, log() {}, warn() {} }),
    crypto: Object.freeze({
      getRandomValues() { throw new Error('entropy must remain inert'); },
      subtle: Object.freeze({ digest() { throw new Error('digest must remain inert'); } }),
    }),
    fetch() { counts.fetch += 1; throw new Error('fetch must remain inert'); },
    setInterval() { counts.timers += 1; return 1; },
    setTimeout() { counts.timers += 1; return 1; },
    window,
  });
  return { context, counts };
}

async function publicSource() {
  return readFile(publicGlobalUrl, 'utf8');
}

describe('classic public-client global', () => {
  test('defines one immutable frozen namespace and is inert through all ten factories', async () => {
    const source = await publicSource();
    const { context, counts } = instrumentedContext();
    const before = Reflect.ownKeys(context);

    vm.runInContext(source, context, { filename: 'sdn-wallet-public-client.js' });

    expect(Reflect.ownKeys(context).filter((name) => !before.includes(name)))
      .toEqual(['SDNWalletPublicClient']);
    const descriptor = Object.getOwnPropertyDescriptor(context, 'SDNWalletPublicClient');
    expect(descriptor).toMatchObject({ configurable: false, enumerable: false, writable: false });
    expect(Object.isFrozen(context.SDNWalletPublicClient)).toBe(true);
    expect(Object.keys(context.SDNWalletPublicClient)).toEqual(['create']);
    expect(context.SDNWalletPublicClient.create).toHaveLength(1);
    expect(counts).toEqual({ close: 0, fetch: 0, listeners: 0, open: 0, storage: 0, timers: 0 });

    for (const clientId of CLIENT_IDS) {
      context.__clientId = clientId;
      const methods = vm.runInContext(
        'Object.keys(SDNWalletPublicClient.create({ clientId: __clientId })).sort()',
        context,
      );
      expect(Array.from(methods)).toEqual([
        'connect',
        'destroy',
        'disconnect',
        'getSnapshot',
        'openAccount',
        'subscribe',
      ]);
    }
    expect(counts).toEqual({ close: 0, fetch: 0, listeners: 0, open: 0, storage: 0, timers: 0 });
  });

  test.each([
    'SDNWalletPublicClient.create()',
    'SDNWalletPublicClient.create({ clientId: "sdn-landing-web-v1" }, 1)',
    'SDNWalletPublicClient.create(null)',
    'SDNWalletPublicClient.create([])',
    'SDNWalletPublicClient.create(Object.create(null, { clientId: { value: "sdn-landing-web-v1", enumerable: true } }))',
    'SDNWalletPublicClient.create({ clientId: "sdn-landing-web-v1", extra: true })',
    'SDNWalletPublicClient.create(Object.defineProperty({}, "clientId", { get() { throw new Error("secret getter"); }, enumerable: true }))',
    'SDNWalletPublicClient.create(Object.defineProperty({}, "clientId", { value: "sdn-landing-web-v1", enumerable: false }))',
    'SDNWalletPublicClient.create(Object.assign({ clientId: "sdn-landing-web-v1" }, { [Symbol("extra")]: true }))',
  ])('rejects a non-exact factory record without observable work: %s', async (expression) => {
    const { context, counts } = instrumentedContext();
    vm.runInContext(await publicSource(), context);
    let error;
    try {
      vm.runInContext(expression, context);
    } catch (caught) {
      error = caught;
    }
    expect(error).toMatchObject({ code: 'INVALID_REQUEST' });
    expect(String(error?.message)).not.toContain('secret getter');
    expect(counts).toEqual({ close: 0, fetch: 0, listeners: 0, open: 0, storage: 0, timers: 0 });
  });

  test.each(['data', 'accessor'])('fails closed on a nonconfigurable preexisting %s global', async (kind) => {
    const { context, counts } = instrumentedContext();
    const source = await publicSource();
    const existing = Object.freeze({ owned: true });
    let getterCalls = 0;
    Object.defineProperty(context, 'SDNWalletPublicClient', kind === 'data' ? {
      configurable: false,
      enumerable: true,
      value: existing,
      writable: false,
    } : {
      configurable: false,
      enumerable: true,
      get() {
        getterCalls += 1;
        return existing;
      },
    });
    expect(() => vm.runInContext(source, context)).toThrow();
    const descriptor = Object.getOwnPropertyDescriptor(context, 'SDNWalletPublicClient');
    expect(descriptor.configurable).toBe(false);
    if (kind === 'data') expect(descriptor.value).toBe(existing);
    expect(getterCalls).toBe(0);
    expect(counts).toEqual({ close: 0, fetch: 0, listeners: 0, open: 0, storage: 0, timers: 0 });
  });
});

describe('classic callback helper', () => {
  function callbackContext({ framed = false, hash = `#code=${'a'.repeat(64)}&state=${'b'.repeat(64)}` } = {}) {
    const records = [];
    const replacements = [];
    const body = { textContent: '' };
    const window = {
      close() { window.closed = true; },
      closed: false,
      document: { body },
      history: { replaceState: (...values) => replacements.push(values) },
      localStorage: { setItem: (...values) => records.push(values) },
      location: { hash, pathname: '/wallet-callback.html', search: '' },
    };
    window.top = framed ? {} : window;
    return {
      body,
      context: vm.createContext({ Date, Error, JSON, window }),
      records,
      replacements,
      window,
    };
  }

  test('self-runs once, clears the fragment, writes one bounded record, and closes', async () => {
    const fixture = callbackContext();
    vm.runInContext(await readFile(callbackGlobalUrl, 'utf8'), fixture.context);
    expect(fixture.replacements).toEqual([[null, '', '/wallet-callback.html']]);
    expect(fixture.records).toHaveLength(1);
    expect(fixture.records[0][0]).toBe(`sdn.wallet.callback.v1:${'b'.repeat(64)}`);
    expect(new TextEncoder().encode(fixture.records[0][1]).byteLength).toBeLessThanOrEqual(2_048);
    expect(JSON.parse(fixture.records[0][1])).toMatchObject({
      code: 'a'.repeat(64),
      schemaVersion: 1,
      state: 'b'.repeat(64),
    });
    expect(fixture.window.closed).toBe(true);
    expect(fixture.body.textContent).toBe('');
  });

  test('refuses framing, clears the fragment, writes nothing, and renders only a safe error', async () => {
    const fixture = callbackContext({ framed: true });
    vm.runInContext(await readFile(callbackGlobalUrl, 'utf8'), fixture.context);
    expect(fixture.replacements).toEqual([[null, '', '/wallet-callback.html']]);
    expect(fixture.records).toHaveLength(0);
    expect(fixture.window.closed).toBe(false);
    expect(fixture.body.textContent).toBe(
      'Wallet return could not be completed. Close this page and try Login again.',
    );
  });

  test.each(['invalid-fragment', 'storage-getter', 'storage-write'])('%s fails closed after fragment clearing', async (mode) => {
    const fixture = callbackContext({
      hash: mode === 'invalid-fragment' ? '#code=bad&state=bad' : undefined,
    });
    if (mode === 'storage-getter') {
      Object.defineProperty(fixture.window, 'localStorage', {
        configurable: true,
        get() { throw new Error('hostile storage getter'); },
      });
    } else if (mode === 'storage-write') {
      fixture.window.localStorage.setItem = () => { throw new Error('quota'); };
    }
    vm.runInContext(await readFile(callbackGlobalUrl, 'utf8'), fixture.context);
    expect(fixture.replacements).toEqual([[null, '', '/wallet-callback.html']]);
    expect(fixture.records).toHaveLength(0);
    expect(fixture.window.closed).toBe(false);
    expect(fixture.body.textContent).toBe(
      'Wallet return could not be completed. Close this page and try Login again.',
    );
  });

  test('a denied close leaves the completed bounded record and no error content', async () => {
    const fixture = callbackContext();
    fixture.window.close = () => { throw new Error('close denied'); };
    vm.runInContext(await readFile(callbackGlobalUrl, 'utf8'), fixture.context);
    expect(fixture.records).toHaveLength(1);
    expect(fixture.replacements).toEqual([[null, '', '/wallet-callback.html']]);
    expect(fixture.body.textContent).toBe('');
  });
});
