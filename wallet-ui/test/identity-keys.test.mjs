// Per-account SDN identity keys (identity-keys.js) against fixed vectors and
// an independent SLIP-10 implementation, plus key hygiene: every private key
// is zeroed when its scope ends.

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import initHDWallet from 'hd-wallet-wasm';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { hmac } from '@noble/hashes/hmac';
import { sha512 } from '@noble/hashes/sha512';
import { beforeAll, describe, expect, it, vi } from 'vitest';

import {
  accountXpub,
  buildLoginPayload,
  chainPaths,
  deriveAccountAddresses,
  deriveIdentity,
  encryptionKeyPath,
  namespaceFingerprint,
  normalizeAccount,
  runScoped,
  shortPeerId,
  signingKeyPath,
  toHex,
  withChainKey,
  withEdKey,
  withXKey,
} from '../src/identity-keys.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, 'fixtures', 'sdn-identity.json'), 'utf8'));
const OTHER = `${'zoo '.repeat(11)}wrong`;

// SLIP-10 for Ed25519, written out independently of the WASM build.
function slip10(seed, path) {
  let I = hmac(sha512, new TextEncoder().encode('ed25519 seed'), seed);
  let key = I.slice(0, 32);
  let chain = I.slice(32);
  for (const segment of path.split('/').slice(1)) {
    const index = (Number.parseInt(segment, 10) + 0x80000000) >>> 0;
    const data = new Uint8Array(37);
    data.set(key, 1);
    new DataView(data.buffer).setUint32(33, index);
    I = hmac(sha512, chain, data);
    key = I.slice(0, 32);
    chain = I.slice(32);
  }
  return key;
}

let wallet;
let seed;
let otherSeed;

beforeAll(async () => {
  wallet = await initHDWallet();
  seed = wallet.mnemonic.toSeed(vectors.mnemonic);
  otherSeed = wallet.mnemonic.toSeed(OTHER);
});

describe('paths', () => {
  it('uses the SDN identity paths and the 2.x address paths for account N', () => {
    expect(signingKeyPath(3)).toBe("m/44'/0'/3'/0'/0'");
    expect(encryptionKeyPath(3)).toBe("m/44'/0'/3'/1'/0'");
    expect(chainPaths(3)).toEqual({ btc: "m/44'/0'/3'/0/0", eth: "m/44'/60'/0'/0/3", sol: "m/44'/501'/3'/0/0" });
    expect(normalizeAccount(99)).toBe(99);
    expect(normalizeAccount(100)).toBe(0);
    expect(normalizeAccount(-1)).toBe(0);
    expect(normalizeAccount(1.5)).toBe(0);
  });
});

describe('identity vectors (test seed)', () => {
  for (const account of [0, 1]) {
    it(`account ${account}: Ed25519, X25519 and peer ID`, () => {
      const id = deriveIdentity(wallet, seed, account);
      const expected = vectors.accounts[String(account)];
      expect(toHex(id.edPub)).toBe(expected.ed25519);
      expect(toHex(id.xPub)).toBe(expected.x25519);
      expect(id.peerId).toBe(expected.peerId);
      expect(id.account).toBe(account);
    });

    it(`account ${account}: matches an independent SLIP-10 + noble derivation`, () => {
      const edPriv = slip10(seed, `m/44'/0'/${account}'/0'/0'`.replace(/'/gu, ''));
      const xPriv = slip10(seed, `m/44'/0'/${account}'/1'/0'`.replace(/'/gu, ''));
      const expected = vectors.accounts[String(account)];
      expect(toHex(ed25519.getPublicKey(edPriv))).toBe(expected.ed25519);
      expect(toHex(x25519.getPublicKey(xPriv))).toBe(expected.x25519);
    });

    it(`account ${account}: the three addresses`, () => {
      const root = wallet.hdkey.fromSeed(seed);
      const addresses = deriveAccountAddresses(wallet, root, account);
      const expected = vectors.accounts[String(account)];
      expect(addresses.btc.address).toBe(expected.btc);
      expect(addresses.eth.address.toLowerCase()).toBe(expected.eth);
      expect(addresses.sol.address).toBe(expected.sol);
      expect(addresses.btc.path).toBe(chainPaths(account).btc);
    });
  }

  it('the two accounts are different identities', () => {
    const a = deriveIdentity(wallet, seed, 0);
    const b = deriveIdentity(wallet, seed, 1);
    expect(a.peerId).not.toBe(b.peerId);
    expect(toHex(a.xPub)).not.toBe(toHex(b.xPub));
  });

  it('shortens a peer ID to the first 8 and last 4 characters', () => {
    expect(shortPeerId(vectors.accounts['0'].peerId)).toBe('12D3KooW…kmWZ');
  });
});

describe('storage fingerprint', () => {
  it('is the first 16 hex of sha256(root xpub), stable, and differs between seeds', () => {
    const root = wallet.hdkey.fromSeed(seed);
    const fp = namespaceFingerprint(wallet, root.toXpub());
    expect(fp).toBe(vectors.fingerprint);
    expect(namespaceFingerprint(wallet, wallet.hdkey.fromSeed(seed).toXpub())).toBe(fp);
    const other = namespaceFingerprint(wallet, wallet.hdkey.fromSeed(otherSeed).toXpub());
    expect(other).toMatch(/^[0-9a-f]{16}$/u);
    expect(other).not.toBe(fp);
  });
});

describe('key hygiene', () => {
  it('zeroes the Ed25519 key after withEdKey, also when the callback throws', () => {
    let seen = null;
    const signature = withEdKey(wallet, seed, 0, (key) => {
      seen = key;
      expect(key.some((byte) => byte !== 0)).toBe(true);
      return wallet.curves.ed25519.sign(new Uint8Array([1, 2, 3]), key);
    });
    expect(signature).toHaveLength(64);
    expect([...seen].every((byte) => byte === 0)).toBe(true);
    let thrown = null;
    expect(() => withEdKey(wallet, seed, 0, (key) => { thrown = key; throw new Error('boom'); })).toThrow('boom');
    expect([...thrown].every((byte) => byte === 0)).toBe(true);
  });

  it('zeroes the X25519 key after withXKey', () => {
    let seen = null;
    const fill = vi.spyOn(Uint8Array.prototype, 'fill');
    try {
      withXKey(wallet, seed, 1, (key) => { seen = key; });
      expect(fill).toHaveBeenCalled();
    } finally {
      fill.mockRestore();
    }
    expect([...seen].every((byte) => byte === 0)).toBe(true);
  });

  it('keeps an async scope open until the promise settles, then zeroes', async () => {
    let seen = null;
    const result = await runScoped(new Uint8Array([7, 7, 7]), async (key) => {
      seen = key;
      await Promise.resolve();
      expect([...key]).toEqual([7, 7, 7]);
      return 'done';
    });
    expect(result).toBe('done');
    expect([...seen]).toEqual([0, 0, 0]);
  });

  it('zeroes chain keys after withChainKey', () => {
    const root = wallet.hdkey.fromSeed(seed);
    let seen = null;
    withChainKey(root, chainPaths(0).btc, (key) => { seen = key; });
    expect(seen).toHaveLength(32);
    expect([...seen].every((byte) => byte === 0)).toBe(true);
  });

  it('refuses to run without a seed-phrase session', () => {
    expect(() => withEdKey(wallet, null, 0, () => {})).toThrow(/seed-phrase session/u);
  });
});

describe('onLogin payload', () => {
  it('carries the Ed25519 identity peer ID, Ed25519 and X25519 keys of the current account, and copies', () => {
    const root = wallet.hdkey.fromSeed(seed);
    for (const account of [0, 1]) {
      const identity = deriveIdentity(wallet, seed, account);
      const payload = buildLoginPayload({ rootXpub: root.toXpub(), identity });
      expect(Object.isFrozen(payload)).toBe(true);
      expect(payload.peerId).toBe(vectors.accounts[String(account)].peerId);
      expect(toHex(payload.signingPublicKey)).toBe(vectors.accounts[String(account)].ed25519);
      expect(toHex(payload.encryptionPublicKey)).toBe(vectors.accounts[String(account)].x25519);
      expect(payload.signingPublicKey).not.toBe(identity.edPub);
      expect(payload.account).toBe(account);
      expect(Object.keys(payload).sort()).toEqual(['account', 'encryptionPublicKey', 'peerId', 'signingPublicKey', 'xpub']);
    }
    expect(accountXpub(root, 0)).toMatch(/^xpub/u);
  });
});
