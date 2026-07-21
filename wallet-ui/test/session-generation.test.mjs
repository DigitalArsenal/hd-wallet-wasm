import { describe, expect, test, vi } from 'vitest';

import { SessionGenerationGuard } from '../src/session-generation.js';

function deferred() {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
}

describe('legacy wallet session generation', () => {
  test('a delayed balance cannot commit after logout invalidates its session', async () => {
    const guard = new SessionGenerationGuard();
    const session = guard.begin();
    const balance = deferred();
    const commit = vi.fn();

    const pending = guard.commitIfCurrent(session, balance.promise, commit);
    guard.invalidate();
    balance.resolve({ balance: '42' });

    await expect(pending).resolves.toBe(false);
    expect(commit).not.toHaveBeenCalled();
  });

  test('the current session may commit exactly once', async () => {
    const guard = new SessionGenerationGuard();
    const session = guard.begin();
    const commit = vi.fn();

    await expect(guard.commitIfCurrent(session, Promise.resolve('ready'), commit)).resolves.toBe(true);
    expect(commit).toHaveBeenCalledOnce();
    expect(commit).toHaveBeenCalledWith('ready');
  });

  test('a delayed trust scan from a logged-out session cannot repopulate a relogged session', async () => {
    const guard = new SessionGenerationGuard();
    const oldSession = guard.begin();
    const oldScan = deferred();
    const trustState = { relationships: [], transactions: [] };
    const rendered = [];
    const oldCommit = guard.commitIfCurrent(oldSession, oldScan.promise, (result) => {
      trustState.relationships = result.relationships;
      trustState.transactions = result.transactions;
      rendered.push(...result.relationships);
    });

    guard.invalidate();
    trustState.relationships = [];
    trustState.transactions = [];
    const newSession = guard.begin();
    oldScan.resolve({ relationships: ['stale-address'], transactions: ['stale-tx'] });

    await expect(oldCommit).resolves.toBe(false);
    expect(trustState).toEqual({ relationships: [], transactions: [] });
    expect(rendered).toEqual([]);

    await expect(guard.commitIfCurrent(newSession, Promise.resolve({
      relationships: ['current-address'],
      transactions: ['current-tx'],
    }), (result) => {
      trustState.relationships = result.relationships;
      trustState.transactions = result.transactions;
      rendered.push(...result.relationships);
    })).resolves.toBe(true);
    expect(trustState.relationships).toEqual(['current-address']);
    expect(rendered).toEqual(['current-address']);
  });

});
