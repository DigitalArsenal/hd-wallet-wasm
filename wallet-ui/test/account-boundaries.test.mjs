// The 3.0 account view's bundle boundaries (spec §0 and §8.1): one runtime
// dependency, module-sdk for conformance tests only, and none of the removed
// 2.x surfaces (vCard, $EME, name resolution) left in the shipped sources.

import { readFile, readdir } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import { describe, expect, it } from 'vitest';

const walletUi = dirname(fileURLToPath(new URL('../package.json', import.meta.url)));
const manifest = JSON.parse(await readFile(join(walletUi, 'package.json'), 'utf8'));

async function sources(directory) {
  const out = [];
  for (const entry of await readdir(join(walletUi, directory), { withFileTypes: true })) {
    if (entry.isFile() && /\.(?:m?js|html)$/u.test(entry.name)) {
      out.push([`${directory}/${entry.name}`, await readFile(join(walletUi, directory, entry.name), 'utf8')]);
    }
  }
  return out;
}

const shipped = [
  ...await sources('src'),
  ...await sources('account'),
  ['index.html', await readFile(join(walletUi, 'index.html'), 'utf8')],
];

describe('account view bundle boundaries', () => {
  it('keeps hd-wallet-wasm as the only runtime dependency; module-sdk is dev-only', () => {
    expect(Object.keys(manifest.dependencies)).toEqual(['hd-wallet-wasm']);
    expect(manifest.devDependencies['space-data-module-sdk']).toBe('0.9.7');
    expect(manifest.devDependencies['spacedatastandards.org']).toBe('1.249.0');
    expect(manifest.dependencies['space-data-module-sdk']).toBeUndefined();
    expect(JSON.stringify(manifest)).not.toContain('vcard-cryptoperson');
  });

  it('ships no module-sdk, vCard, $EME or name-resolution code', () => {
    for (const [path, text] of shipped) {
      expect(text, path).not.toMatch(/from\s+['"]space-data-module-sdk|import\(\s*['"]space-data-module-sdk/u);
      expect(text, path).not.toMatch(/vcard-cryptoperson|vcard-signing/u);
      expect(text, path).not.toMatch(/\bEMET\b|\/EME\/EME\.js|\.eme\.(?:json|fbs)/u);
      expect(text, path).not.toMatch(/api\.hiro\.so|bonfida/u);
    }
  });

  it('envelopes.js reads $REC without the generated REC classes (they pull in every SDS standard)', () => {
    const [, envelopes] = shipped.find(([path]) => path === 'src/envelopes.js');
    expect(envelopes).not.toMatch(/(?:from|import\()\s*['"]@sds\/lib\/js\/REC\//u);
    expect(envelopes).not.toMatch(/crypto\.subtle|Math\.random/u);
  });
});
