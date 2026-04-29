import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const repoRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const productionFiles = [
  'wallet-ui/src/app.js',
  'wallet-ui/src/wallet-storage.js'
];

const forbidden = [
  /\bcrypto\.subtle\b/,
  /\bderiveBits\b/,
  /\bderiveKey\b/,
  /\bimportKey\b/,
  /\bgenerateKey\b/
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
});
