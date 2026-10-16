// SEC-020: in 2.x the account list and the Receive address were read back from
// plaintext localStorage that was not keyed by seed, so a second wallet on the
// same browser showed the first wallet's address until a slow scan fixed it.
// In 3.0 every address the page shows or sends from is derived from the
// session's BIP-32 root when the account is opened; storage holds no address
// the page trusts. This pins both halves: the derivation (two seeds, two sets
// of addresses, nothing shared through storage) and the wiring.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import initHDWallet from 'hd-wallet-wasm';
import { describe, expect, it } from 'vitest';

import { createAccountStorage } from '../src/account-storage.js';
import { deriveAccountAddresses, namespaceFingerprint } from '../src/identity-keys.js';
import { memoryStorage } from './helpers/stub-dom.mjs';

const wallet = await initHDWallet();
const app = readFileSync(resolve(import.meta.dirname, '..', 'src', 'app.js'), 'utf8');

function session(mnemonic, storage) {
  const root = wallet.hdkey.fromSeed(wallet.mnemonic.toSeed(mnemonic));
  const fp = namespaceFingerprint(wallet, root.toXpub());
  const accountStorage = createAccountStorage({ fp, storage });
  return { addresses: deriveAccountAddresses(wallet, root, accountStorage.readAccount()), accountStorage };
}

describe('addresses come from the seed, never from storage', () => {
  it('a second seed on the same browser gets its own addresses at once', () => {
    const storage = memoryStorage();
    const a = session('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about', storage);
    a.accountStorage.write(0, 'scan-cache', { [`btc:${a.addresses.btc.address}`]: { balance: '1', at: 1 } });
    const b = session('legal winner thank year wave sausage worth useful legal winner thank yellow', storage);
    for (const chain of ['btc', 'eth', 'sol']) {
      expect(b.addresses[chain].address).not.toBe(a.addresses[chain].address);
    }
    // B's namespace holds nothing of A's.
    expect(b.accountStorage.read(0, 'scan-cache', {})).toEqual({});
    // No stored record anywhere carries an address the page would read back.
    expect(storage.entries().length).toBeGreaterThan(0);
    for (const [key] of storage.entries()) expect(key).not.toMatch(/active-accounts|hd-wallet-wallets/u);
  });

  it('app.js sets the session addresses only from the derivation (or the connected external account)', () => {
    const assignments = [...app.matchAll(/state\.(addresses|chainAccounts) = ([^;]+);/gu)].map((m) => `${m[1]} = ${m[2].split('\n')[0]}`);
    expect(assignments).toEqual([
      'chainAccounts = deriveAccountAddresses(wasm, state.hdRoot, n)',
      'addresses = {',
      'addresses = { ...emptyAddresses(), [chain]: account.address }',
      'chainAccounts = null',
      'chainAccounts = null',
      'addresses = { btc: null, eth: null, sol: null }',
    ]);
    expect(app).toMatch(/state\.addresses = \{\s*btc: state\.chainAccounts\.btc\.address,\s*eth: state\.chainAccounts\.eth\.address,\s*sol: state\.chainAccounts\.sol\.address,\s*\};/u);
    // Storage is read for profile, contacts and the balance cache only.
    const reads = [...app.matchAll(/state\.storage\.read\(state\.account, '([^']+)'/gu)].map((m) => m[1]).sort();
    expect(reads).toEqual(['contacts', 'profile', 'scan-cache']);
  });
});
