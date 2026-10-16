// The onLogin host contract (3.0, breaking): the payload carries the SDN
// Ed25519 identity of the CURRENT account — its peer ID, Ed25519 signing key
// (m/44'/0'/N'/0'/0') and X25519 encryption key (m/44'/0'/N'/1'/0') — and an
// account switch calls the callback again with the new identity.

import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

import initHDWallet from 'hd-wallet-wasm';
import { ed25519, x25519 } from '@noble/curves/ed25519';
import { describe, expect, it } from 'vitest';

import { buildLoginPayload, deriveIdentity, peerIdFromEd25519, toHex, withEdKey, withXKey } from '../src/identity-keys.js';

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(join(here, 'fixtures', 'sdn-identity.json'), 'utf8'));
const app = readFileSync(resolve(here, '..', 'src', 'app.js'), 'utf8');
const wallet = await initHDWallet();
const seed = wallet.mnemonic.toSeed(vectors.mnemonic);
const root = wallet.hdkey.fromSeed(seed);

describe('onLogin payload', () => {
  it('peerId is the Ed25519 identity peer ID, not the root secp256k1 key', () => {
    const payload = buildLoginPayload({ rootXpub: root.toXpub(), identity: deriveIdentity(wallet, seed, 0) });
    expect(payload.peerId).toBe(vectors.accounts['0'].peerId);
    expect(payload.peerId.startsWith('12D3KooW')).toBe(true);
    expect(payload.peerId).not.toBe(root.peerIdString());
    expect(payload.peerId).toBe(peerIdFromEd25519(wallet, payload.signingPublicKey));
  });

  it('signingPublicKey is the account Ed25519 key and verifies its signatures', () => {
    const payload = buildLoginPayload({ rootXpub: root.toXpub(), identity: deriveIdentity(wallet, seed, 0) });
    expect(toHex(payload.signingPublicKey)).toBe(vectors.accounts['0'].ed25519);
    const message = new TextEncoder().encode('authenticate me');
    const signature = withEdKey(wallet, seed, 0, (key) => wallet.curves.ed25519.sign(message, key));
    expect(ed25519.verify(signature, message, payload.signingPublicKey)).toBe(true);
  });

  it('encryptionPublicKey is the account X25519 key: ECDH with it matches the private side', () => {
    const payload = buildLoginPayload({ rootXpub: root.toXpub(), identity: deriveIdentity(wallet, seed, 0) });
    expect(toHex(payload.encryptionPublicKey)).toBe(vectors.accounts['0'].x25519);
    const other = new Uint8Array(32).fill(9);
    const theirs = x25519.getSharedSecret(other, payload.encryptionPublicKey);
    const mine = withXKey(wallet, seed, 0, (key) => wallet.curves.x25519.ecdh(key, x25519.getPublicKey(other)));
    expect(toHex(mine)).toBe(toHex(theirs));
  });

  it('a different account is a different identity', () => {
    const one = buildLoginPayload({ rootXpub: root.toXpub(), identity: deriveIdentity(wallet, seed, 1) });
    expect(one.peerId).toBe(vectors.accounts['1'].peerId);
    expect(one.account).toBe(1);
  });
});

describe('app wiring', () => {
  function body(name) {
    const start = app.indexOf(name);
    expect(start).toBeGreaterThanOrEqual(0);
    const next = app.indexOf('\nfunction ', start + name.length);
    const nextAsync = app.indexOf('\nasync function ', start + name.length);
    const ends = [next, nextAsync].filter((index) => index > start);
    return app.slice(start, Math.min(...ends));
  }

  it('login and every account switch call onLogin with the new identity', () => {
    expect(body('function notifyLogin()')).toContain('buildLoginPayload({ rootXpub: state.hdRoot.toXpub(), identity: state.identity })');
    expect(body('function login(')).toContain('notifyLogin();');
    const switchBody = body('async function switchAccount(');
    expect(switchBody).toContain('deriveAccountSession(n);');
    expect(switchBody).toContain('state.storage?.writeAccount(n);');
    expect(switchBody).toContain('notifyLogin();');
  });

  it('never hands a host a private key or a signer', () => {
    expect(body('function notifyLogin()')).not.toMatch(/privateKey|sign\(/u);
  });
});
