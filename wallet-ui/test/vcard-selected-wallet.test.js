import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');

function read(relativePath) {
  return readFileSync(resolve(ROOT, relativePath), 'utf8');
}

describe('selected wallet vCard identity', () => {
  it('exports keys from the currently selected wallet', () => {
    const app = read('src/app.js');

    expect(app).toContain('getCurrentWalletIdentity()');
    expect(app).toContain('getCurrentWalletSigningAccounts()');
    expect(app).toContain('identity.xpub');
    expect(app).not.toContain('state.activeAccounts\n        .filter(a => a.active && isSigningAccount(a))');
  });

  it('signs vCards with the selected wallet Solana signing key path', () => {
    const app = read('src/app.js');

    expect(app).toContain('getCurrentWalletSignatureKey()');
    expect(app).toContain('signatureKey.accountIndex');
    expect(app).not.toContain('const sigValue = `${sigB64}:501:0:0`;');
  });
});
