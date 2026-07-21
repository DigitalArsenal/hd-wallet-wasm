import { describe, expect, it } from 'vitest';

async function loadScopeHelpers() {
  const helpers = await import('../src/derived-key-scope.js').catch(() => null);
  expect(helpers?.withDerivedHandle).toBeTypeOf('function');
  expect(helpers?.withDerivedPrivateKey).toBeTypeOf('function');
  return helpers;
}

function fakeDerived(privateKey = new Uint8Array([1, 2, 3, 4])) {
  const wipeSnapshots = [];
  const derived = {
    privateKey: () => privateKey,
    wipe: () => wipeSnapshots.push(Array.from(privateKey)),
  };
  return { derived, privateKey, wipeSnapshots };
}

describe('derived key scopes', () => {
  it('rejects a derived handle without mandatory wipe support before the operation runs', async () => {
    const { withDerivedHandle } = await loadScopeHelpers();
    let operationCount = 0;

    expect(() => withDerivedHandle(
      () => ({ privateKey: () => new Uint8Array([1]) }),
      () => { operationCount += 1; },
    )).toThrow('callable wipe');
    expect(operationCount).toBe(0);
  });

  it('preserves derivation errors without running the operation', async () => {
    const { withDerivedHandle } = await loadScopeHelpers();
    let operationCount = 0;

    expect(() => withDerivedHandle(
      () => { throw new Error('derivation failed'); },
      () => { operationCount += 1; },
    )).toThrow('derivation failed');
    expect(operationCount).toBe(0);
  });

  it('zeroes private key bytes and wipes the native handle after success', async () => {
    const { withDerivedPrivateKey } = await loadScopeHelpers();
    const fixture = fakeDerived();

    const result = withDerivedPrivateKey(
      () => fixture.derived,
      (privateKey) => {
        expect(Array.from(privateKey)).toEqual([1, 2, 3, 4]);
        return 'signed';
      },
    );

    expect(result).toBe('signed');
    expect(Array.from(fixture.privateKey)).toEqual([0, 0, 0, 0]);
    expect(fixture.wipeSnapshots).toEqual([[0, 0, 0, 0]]);
  });

  it('zeroes private key bytes and wipes the native handle when signing throws', async () => {
    const { withDerivedPrivateKey } = await loadScopeHelpers();
    const fixture = fakeDerived();

    expect(() => withDerivedPrivateKey(
      () => fixture.derived,
      () => { throw new Error('signing failed'); },
    )).toThrow('signing failed');

    expect(Array.from(fixture.privateKey)).toEqual([0, 0, 0, 0]);
    expect(fixture.wipeSnapshots).toEqual([[0, 0, 0, 0]]);
  });

  it('wipes the native handle when private key extraction throws', async () => {
    const { withDerivedPrivateKey } = await loadScopeHelpers();
    let wipeCount = 0;
    const derived = {
      privateKey: () => { throw new Error('extraction failed'); },
      wipe: () => { wipeCount += 1; },
    };

    expect(() => withDerivedPrivateKey(
      () => derived,
      () => { throw new Error('operation must not run'); },
    )).toThrow('extraction failed');
    expect(wipeCount).toBe(1);
  });

  it('rejects non-byte private key material and still wipes the native handle', async () => {
    const { withDerivedPrivateKey } = await loadScopeHelpers();
    let wipeCount = 0;
    let operationCount = 0;
    const derived = {
      privateKey: () => ({ fill() {} }),
      wipe: () => { wipeCount += 1; },
    };

    expect(() => withDerivedPrivateKey(
      () => derived,
      () => { operationCount += 1; },
    )).toThrow('Uint8Array');
    expect(operationCount).toBe(0);
    expect(wipeCount).toBe(1);
  });

  it('wipes the native handle even if zeroing private key bytes throws', async () => {
    const { withDerivedPrivateKey } = await loadScopeHelpers();
    let wipeCount = 0;
    let fillCount = 0;
    class ThrowingFillKey extends Uint8Array {
      fill() {
        fillCount += 1;
        throw new Error('zeroing failed');
      }
    }
    const derived = {
      privateKey: () => new ThrowingFillKey([1, 2, 3, 4]),
      wipe: () => { wipeCount += 1; },
    };

    expect(() => withDerivedPrivateKey(
      () => derived,
      () => 'signed',
    )).toThrow('zeroing failed');
    expect(fillCount).toBe(1);
    expect(wipeCount).toBe(1);
  });

  it('rejects asynchronous private key callbacks before deriving a handle', async () => {
    const { withDerivedPrivateKey } = await loadScopeHelpers();
    let deriveCount = 0;

    expect(() => withDerivedPrivateKey(
      () => {
        deriveCount += 1;
        return fakeDerived().derived;
      },
      async () => 'not allowed',
    )).toThrow('must be synchronous');
    expect(deriveCount).toBe(0);
  });

  it('wipes identity handles after public strings are copied and on callback errors', async () => {
    const { withDerivedHandle } = await loadScopeHelpers();
    let successWipes = 0;
    const identity = withDerivedHandle(
      () => ({ wipe: () => { successWipes += 1; } }),
      () => ({ xpub: `${'xpub'}-copy`, peerId: `${'peer'}-copy` }),
    );

    expect(identity).toEqual({ xpub: 'xpub-copy', peerId: 'peer-copy' });
    expect(successWipes).toBe(1);

    let errorWipes = 0;
    expect(() => withDerivedHandle(
      () => ({ wipe: () => { errorWipes += 1; } }),
      () => { throw new Error('copy failed'); },
    )).toThrow('copy failed');
    expect(errorWipes).toBe(1);
  });
});
