import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const repoRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const productionFiles = [
  'wallet-ui/src/app.js',
  'wallet-ui/src/lib.js',
  'wallet-ui/src/wallet-storage.js',
  'wallet-ui/origin-app/app.mjs',
  'wallet-ui/origin-app/controller.mjs',
  'wallet-ui/origin-app/remember-wallet.mjs',
  'wallet-ui/origin-app/rng.mjs',
];

const forbidden = [
  /\bcrypto\.subtle\b/,
  /\bderiveBits\b/,
  /\bderiveKey\b/,
  /\bimportKey\b/,
  /\bgenerateKey\b/
];

const pureFiles = [
  'wallet-ui/src/lib.js',
  'wallet-ui/src/wallet-storage.js',
  'wallet-ui/origin-app/remember-wallet.mjs',
  'wallet-ui/origin-app/rng.mjs',
];

const forbiddenLegacyStorage = [
  /\bstoreWithPIN\b/,
  /\bretrieveWithPIN\b/,
  /\bstoreWithPasskey\b/,
  /\bretrieveWithPasskey\b/,
  /\bregisterPasskey\b/,
  /\bauthenticatePasskey\b/,
  /\bderiveKeyFromPIN\b/,
  /\bcredid-fallback\b/,
  /\bmigrateStorage\b/,
  /credentialId.*(?:key|hkdf)/iu,
  /remember-method/u,
  /Math\.random/u,
];

const forbiddenPureCryptoRuntime = [
  /\bcrypto\.subtle\b/,
  /\bderiveKey\b/,
  /\.encrypt\s*\(/u,
  /\.decrypt\s*\(/u,
  /\binitWasm\b/,
  /\bcreateHDWallet\b/,
];

describe('production WebCrypto surface', () => {
  it('does not use WebCrypto runtime APIs', () => {
    const failures = [];
    for (const file of productionFiles) {
      const source = readFileSync(resolve(repoRoot, file), 'utf8');
      for (const pattern of forbidden) {
        if (pattern.test(source)) failures.push(`${file} matches ${pattern}`);
      }
    }

    expect(failures).toEqual([]);
  });

  it('contains no retired PIN, passkey fallback, or migration runtime', () => {
    const failures = [];
    for (const file of productionFiles) {
      const source = readFileSync(resolve(repoRoot, file), 'utf8');
      for (const pattern of forbiddenLegacyStorage) {
        if (pattern.test(source)) failures.push(`${file} matches ${pattern}`);
      }
    }

    expect(failures).toEqual([]);
  });

  it('keeps pure remembered-storage modules free of crypto implementation', () => {
    const failures = [];
    for (const file of pureFiles) {
      const source = readFileSync(resolve(repoRoot, file), 'utf8');
      for (const pattern of forbiddenPureCryptoRuntime) {
        if (pattern.test(source)) failures.push(`${file} matches ${pattern}`);
      }
    }

    expect(failures).toEqual([]);
  });
});
