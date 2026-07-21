import { afterEach, beforeEach, describe, expect, test, vi } from 'vitest';

import { completeWalletCallbackV1 } from '../client/callback.mjs';

const SAFE_RETRY = 'Wallet return could not be completed. Close this page and try Login again.';
const CODE = 'a'.repeat(64);
const STATE = 'b'.repeat(64);
const NOW = Date.parse('2026-07-21T12:00:00.000Z');

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

function callbackFixture({
  hash = `#code=${CODE}&state=${STATE}`,
  storage = new MemoryStorage(),
} = {}) {
  const order = [];
  const location = {
    hash,
    pathname: '/wallet/callback',
    search: '?source=wallet',
  };
  const history = {
    replaceState: vi.fn((..._arguments) => {
      order.push('clear');
      location.hash = '';
    }),
  };
  const originalSetItem = storage.setItem;
  storage.setItem = vi.fn((...arguments_) => {
    order.push('store');
    return originalSetItem(...arguments_);
  });
  const close = vi.fn(() => order.push('close'));
  return { close, history, location, order, storage };
}

async function loadCallbackEntry(windowValue, _caseName) {
  vi.stubGlobal('window', windowValue);
  vi.resetModules();
  await import('../client/callback-entry.mjs');
}

beforeEach(() => {
  vi.useFakeTimers({ now: NOW });
});

afterEach(() => {
  vi.useRealTimers();
  vi.unstubAllGlobals();
});

describe('completeWalletCallbackV1', () => {
  test('clears the exact fragment before writing one bounded public record and closing once', () => {
    const fixture = callbackFixture();

    completeWalletCallbackV1(
      fixture.location,
      fixture.storage,
      fixture.history,
      fixture.close,
    );

    const expiresAt = '2026-07-21T12:02:00.000Z';
    const key = `sdn.wallet.callback.v1:${STATE}`;
    expect(fixture.order).toEqual(['clear', 'store', 'close']);
    expect(fixture.history.replaceState).toHaveBeenCalledOnce();
    expect(fixture.history.replaceState).toHaveBeenCalledWith(
      null,
      '',
      '/wallet/callback?source=wallet',
    );
    expect(fixture.storage.setItem).toHaveBeenCalledOnce();
    expect(fixture.storage.setItem).toHaveBeenCalledWith(
      key,
      JSON.stringify({ schemaVersion: 1, code: CODE, state: STATE, expiresAt }),
    );
    expect(Date.parse(expiresAt) - Date.now()).toBeLessThanOrEqual(120_000);
    expect(fixture.close).toHaveBeenCalledOnce();
  });

  test.each([
    '',
    `#state=${STATE}&code=${CODE}`,
    `#code=${CODE.toUpperCase()}&state=${STATE}`,
    `#code=${CODE}&state=${STATE.toUpperCase()}`,
    `#code=${CODE}%00&state=${STATE}`,
    `#code=${CODE}&state=${STATE}&extra=1`,
    `#code=${CODE}&code=${CODE}&state=${STATE}`,
    `#code=${CODE}`,
  ])('clears then rejects every non-exact callback fragment without storing: %s', (hash) => {
    const fixture = callbackFixture({ hash });

    expect(() => completeWalletCallbackV1(
      fixture.location,
      fixture.storage,
      fixture.history,
      fixture.close,
    )).toThrow(SAFE_RETRY);

    expect(fixture.order).toEqual(['clear']);
    expect(fixture.storage.setItem).not.toHaveBeenCalled();
    expect(fixture.close).not.toHaveBeenCalled();
  });

  test('never closes or exposes callback values when storage fails', () => {
    const storage = new MemoryStorage();
    storage.setItem = vi.fn(() => {
      throw new Error(`do not expose ${CODE} or ${STATE}`);
    });
    const fixture = callbackFixture({ storage });

    expect(() => completeWalletCallbackV1(
      fixture.location,
      fixture.storage,
      fixture.history,
      fixture.close,
    )).toThrow(SAFE_RETRY);

    expect(fixture.location.hash).toBe('');
    expect(fixture.history.replaceState).toHaveBeenCalledOnce();
    expect(fixture.close).not.toHaveBeenCalled();
  });

  test('stores nothing when the fragment cannot be cleared first', () => {
    const fixture = callbackFixture();
    fixture.history.replaceState = vi.fn(() => {
      throw new Error('history unavailable');
    });

    expect(() => completeWalletCallbackV1(
      fixture.location,
      fixture.storage,
      fixture.history,
      fixture.close,
    )).toThrow(SAFE_RETRY);
    expect(fixture.storage.setItem).not.toHaveBeenCalled();
    expect(fixture.close).not.toHaveBeenCalled();
  });
});

describe('callback-entry', () => {
  function entryWindow({ framed = false, storage = new MemoryStorage() } = {}) {
    const order = [];
    const location = {
      hash: `#code=${CODE}&state=${STATE}`,
      pathname: '/wallet/callback',
      search: '',
    };
    const history = {
      replaceState: vi.fn(() => {
        order.push('clear');
        location.hash = '';
      }),
    };
    const originalSetItem = storage.setItem;
    storage.setItem = vi.fn((...arguments_) => {
      order.push('store');
      return originalSetItem(...arguments_);
    });
    const body = { textContent: '' };
    const document = { body };
    const close = vi.fn(() => order.push('close'));
    const value = { close, document, history, localStorage: storage, location };
    value.top = framed ? {} : value;
    return { order, storage, value };
  }

  test('self-runs exactly once, clears, stores, and closes with no setup export', async () => {
    const fixture = entryWindow();

    const loaded = await loadCallbackEntry(fixture.value, 'success');

    expect(loaded).toBeUndefined();
    expect(fixture.order).toEqual(['clear', 'store', 'close']);
    expect(fixture.value.close).toHaveBeenCalledOnce();
    expect(fixture.value.document.body.textContent).toBe('');
  });

  test('clears first and renders only the safe retry message when storage fails', async () => {
    const storage = new MemoryStorage();
    storage.setItem = vi.fn(() => {
      throw new Error(`hostile ${CODE} ${STATE}`);
    });
    const fixture = entryWindow({ storage });

    await loadCallbackEntry(fixture.value, 'storage-failure');

    expect(fixture.order[0]).toBe('clear');
    expect(fixture.value.close).not.toHaveBeenCalled();
    expect(fixture.value.document.body.textContent).toBe(SAFE_RETRY);
    expect(fixture.value.document.body.textContent).not.toContain(CODE);
    expect(fixture.value.document.body.textContent).not.toContain(STATE);
  });

  test('clears first when merely accessing localStorage throws', async () => {
    const fixture = entryWindow();
    delete fixture.value.localStorage;
    Object.defineProperty(fixture.value, 'localStorage', {
      get() {
        throw new Error(`storage denied ${CODE} ${STATE}`);
      },
    });

    await loadCallbackEntry(fixture.value, 'storage-getter-failure');

    expect(fixture.order).toEqual(['clear']);
    expect(fixture.value.location.hash).toBe('');
    expect(fixture.value.close).not.toHaveBeenCalled();
    expect(fixture.value.document.body.textContent).toBe(SAFE_RETRY);
  });

  test('rejects framing after clearing and performs no storage write or close', async () => {
    const fixture = entryWindow({ framed: true });

    await loadCallbackEntry(fixture.value, 'framed');

    expect(fixture.order).toEqual(['clear']);
    expect(fixture.storage.setItem).not.toHaveBeenCalled();
    expect(fixture.value.close).not.toHaveBeenCalled();
    expect(fixture.value.document.body.textContent).toBe(SAFE_RETRY);
  });
});
