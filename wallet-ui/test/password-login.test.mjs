// SEC-015: password sign-in is no longer a fast brain wallet. New password
// wallets derive through the memory-hard scrypt profile (password-scrypt-v2),
// cross-checked against the native profile; sign-in is gated on a zxcvbn
// estimate (10^20 guesses), never on character classes or length alone;
// wallets made with the old fast method open read-only so they can be swept.

import { createHash, hkdfSync, scryptSync } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import initHDWallet from 'hd-wallet-wasm';
import { describe, expect, it } from 'vitest';

import {
  MIN_GUESSES_LOG10,
  assessNewPassword,
  canonicalizeUsername,
  deriveLegacyPasswordSeed,
  derivePasswordSeed,
  loadStrengthEstimator,
  passwordPolicyProblem,
} from '../src/password-login.js';
import { getModalHTML } from '../src/template.js';

const wallet = await initHDWallet();
const estimator = await loadStrengthEstimator();
const ROOT = resolve(import.meta.dirname, '..');
const read = (path) => readFileSync(resolve(ROOT, path), 'utf8');

const STRONG = 'quiver lantern basalt orchid pemmican tundra';

/** password-scrypt-v2, computed independently with node:crypto. */
function nodeScryptSeed(canonical, password) {
  const salt = Buffer.concat([Buffer.from('sdn-hd-wallet/password-scrypt-v2'), Buffer.from([0]), Buffer.from(canonical, 'utf8')]);
  return new Uint8Array(scryptSync(Buffer.from(password, 'utf8'), salt, 64, { N: 65536, r: 8, p: 1, maxmem: 256 * 1024 * 1024 }));
}

/** The retired 2.x method, computed independently with node:crypto. */
function nodeLegacySeed(username, password) {
  const user = Buffer.from(username, 'utf8');
  const initial = createHash('sha256').update(Buffer.concat([user, Buffer.from(password, 'utf8')])).digest();
  const master = Buffer.from(hkdfSync('sha256', initial, user, Buffer.from('master-key'), 32));
  return new Uint8Array(hkdfSync('sha256', master, Buffer.alloc(0), Buffer.from('hd-wallet-seed'), 64));
}

const hex = (bytes) => Buffer.from(bytes).toString('hex');

async function code(promise) {
  try {
    await promise;
  } catch (error) {
    return error.code;
  }
  return 'RESOLVED';
}

describe('scrypt profile (new password wallets)', () => {
  it('derives exactly scrypt(N=2^16, r=8, p=1) over the canonical username, as the native profile does', async () => {
    const seed = await derivePasswordSeed(wallet, { username: '  Alice.Example ', password: STRONG });
    expect(hex(seed)).toBe(hex(nodeScryptSeed('alice.example', STRONG)));
    const native = await wallet.sdn.derivePasswordIdentity({
      usernameUtf8: new TextEncoder().encode('alice.example'),
      passwordUtf8: new TextEncoder().encode(STRONG),
      accountIndex: 0,
    });
    const account = wallet.hdkey.fromSeed(seed).derivePath("m/44'/0'/0'");
    expect(account.toXpub()).toBe(native.identity.accountXpub);
    expect(native.identity.seedProfile).toBe('password-scrypt-v2');
    wallet.sdn.destroySdnIdentity(native.handle);
  });

  it('is not the fast method: the same credentials give a different wallet', async () => {
    const seed = await derivePasswordSeed(wallet, { username: 'alice.example', password: STRONG });
    expect(hex(seed)).not.toBe(hex(nodeLegacySeed('alice.example', STRONG)));
  });

  it('canonicalizes usernames like the native profile', () => {
    expect(canonicalizeUsername('  Alice.Example ')).toBe('alice.example');
    // Only ASCII capitals fold; other characters are kept as typed.
    expect(canonicalizeUsername('ÉLAN user')).toBe('Élan user');
    expect(() => canonicalizeUsername('ab')).toThrow();
    expect(() => canonicalizeUsername(`a${'b'.repeat(64)}`)).toThrow();
    expect(() => canonicalizeUsername('bad\u0007name')).toThrow();
    expect(() => canonicalizeUsername('lone\ud800surrogate')).toThrow();
  });

  it('applies the native policy: 12..128 characters, no control characters, not common', async () => {
    expect(passwordPolicyProblem('short')).toBe('INVALID_PASSWORD');
    expect(passwordPolicyProblem(' '.repeat(20))).toBe('INVALID_PASSWORD');
    expect(passwordPolicyProblem(`${STRONG}\u0000`)).toBe('INVALID_PASSWORD');
    expect(passwordPolicyProblem('x'.repeat(129))).toBe('INVALID_PASSWORD');
    expect(passwordPolicyProblem(STRONG)).toBeNull();
    // The native common-password list refuses it even past the page.
    expect(await code(derivePasswordSeed(wallet, { username: 'alice', password: 'Unbelievable' }))).toBe('COMMON_PASSWORD');
    expect(await code(derivePasswordSeed(wallet, { username: 'alice', password: 'short' }))).toBe('INVALID_PASSWORD');
  });

  it('fails closed when the WASM scrypt result does not match the native profile', async () => {
    const broken = { ...wallet, utils: { ...wallet.utils, scrypt: () => new Uint8Array(64).fill(7) } };
    expect(await code(derivePasswordSeed(broken, { username: 'alice', password: STRONG }))).toBe('PROFILE_MISMATCH');
    const silent = { ...wallet, utils: { ...wallet.utils, scrypt: () => new Uint8Array(64) } };
    expect(await code(derivePasswordSeed(silent, { username: 'alice', password: STRONG }))).toBe('KDF_FAILURE');
    const noNative = { ...wallet, sdn: {} };
    expect(await code(derivePasswordSeed(noNative, { username: 'alice', password: STRONG }))).toBe('KDF_FAILURE');
  });
});

describe('strength gate (a real estimate, not character classes)', () => {
  it('refuses the passwords the old meter called "strong"', () => {
    for (const password of [
      'passwordpasswordpassword',
      'a'.repeat(24),
      '123456789012345678901234',
      'iloveyouiloveyouiloveyou',
      'correct horse battery staple',
      'Tr0ub4dor&3Tr0ub4dor&3',
      'alice.example2026!!summer',
    ]) {
      const result = assessNewPassword({ username: 'alice.example', password, estimator });
      expect([password, result.ok]).toEqual([password, false]);
      expect(result.guessesLog10).toBeLessThan(MIN_GUESSES_LOG10);
    }
  });

  it('accepts a long passphrase of uncommon random words', () => {
    const result = assessNewPassword({ username: 'alice.example', password: STRONG, estimator });
    expect(result.ok).toBe(true);
    expect(result.guessesLog10).toBeGreaterThanOrEqual(MIN_GUESSES_LOG10);
  });

  it('penalizes the username inside the password and refuses without an estimator', () => {
    const withName = assessNewPassword({ username: 'quiverlanternbasalt', password: 'quiverlanternbasalt', estimator });
    expect(withName.ok).toBe(false);
    expect(assessNewPassword({ username: 'alice', password: STRONG, estimator: null }).ok).toBe(false);
  });
});

describe('old password method (read-only, for sweeping)', () => {
  it('derives exactly the 2.x seed, cross-checked with the native legacy profile', async () => {
    for (const [username, password] of [['bob', 'passwordpasswordpassword'], ['Bob Smith ', 'pw'], ['ünï', 'ç'.repeat(30)]]) {
      const seed = await deriveLegacyPasswordSeed(wallet, { username, password });
      expect(hex(seed)).toBe(hex(nodeLegacySeed(username, password)));
    }
  });

  it('fails closed when the derivation does not match the native legacy profile', async () => {
    const broken = { ...wallet, utils: { ...wallet.utils, hkdf: () => new Uint8Array(64).fill(1) } };
    expect(await code(deriveLegacyPasswordSeed(broken, { username: 'bob', password: 'pw' }))).toBe('PROFILE_MISMATCH');
  });
});

describe('page wiring', () => {
  const app = read('src/app.js');
  const template = getModalHTML();

  it('no character-class meter and no length-only gate remain', () => {
    expect(app).not.toContain('calculateEntropy');
    expect(app).not.toMatch(/password\.length\s*<\s*24/u);
    expect(app).not.toMatch(/sha256\(new Uint8Array\(\[\.\.\.usernameSalt/u);
  });

  it('sign-in re-checks the estimate and derives through the scrypt profile', () => {
    const handler = app.slice(app.indexOf("$('derive-from-password')?.addEventListener"), app.indexOf("$('derive-from-legacy-password')?.addEventListener"));
    expect(handler).toContain('assessNewPassword({ username, password, estimator: _strengthEstimator })');
    expect(handler).toContain('if (!assessment.ok)');
    expect(handler).toContain('await deriveKeysFromPassword(username, password)');
    expect(app).toContain('const seed = await derivePasswordSeed(hdWallet(), { username, password });');
  });

  it('the old method opens a read-only session that signs nothing but the sweep', () => {
    expect(app).toContain("login('password-legacy')");
    expect(app).toMatch(/function scopedEdKey\(fn\) \{[\s\S]*?if \(isLegacyPasswordSession\(\)\) throw new Error\(LEGACY_READ_ONLY_MESSAGE\);/u);
    expect(app).toMatch(/function scopedChainKey\(path, fn\) \{[\s\S]*?if \(isLegacyPasswordSession\(\) && !_sweepSigning\) throw/u);
    expect(app).toMatch(/canSend: \(chain\) => isHdSession\(\) && !isLegacyPasswordSession\(\)/u);
    // A sweep may only pay the new wallet the migration derived.
    expect(app).toContain("String(to) !== state.migrationDestination[chain]");
  });

  it('the form does not ask the browser to save the password and documents the migration', () => {
    expect(template).toContain('id="wallet-password" class="glass-input" placeholder="Password" autocomplete="off"');
    expect(template).not.toContain('new-password');
    expect(template).toContain('id="derive-from-legacy-password"');
    expect(template).toContain('Sign in with old password method');
    expect(template).toContain('read-only');
    expect(template).toContain('scrypt');
  });
});
