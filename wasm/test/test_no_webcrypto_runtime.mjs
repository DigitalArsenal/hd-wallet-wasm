import { readFileSync } from 'node:fs';
import { relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = resolve(fileURLToPath(new URL('../..', import.meta.url)));
const productionFiles = [
  'wasm/src/index.mjs',
  'wasm/src/sdn-plugin.mjs'
];

const forbidden = [
  /\bcrypto\.subtle\b/,
  /\bsubtle\(\)\./,
  /\bderiveBits\b/,
  /\bderiveKey\b/,
  /\bimportKey\b/,
  /\bgenerateKey\b/
];

const failures = [];
for (const file of productionFiles) {
  const absolute = resolve(repoRoot, file);
  const source = readFileSync(absolute, 'utf8');
  for (const pattern of forbidden) {
    if (pattern.test(source)) {
      failures.push(`${relative(repoRoot, absolute)} matches ${pattern}`);
    }
  }
}

if (failures.length > 0) {
  throw new Error(`WebCrypto runtime APIs are not allowed in hd-wallet-wasm production code:\n${failures.join('\n')}`);
}

console.log('No WebCrypto runtime APIs found in hd-wallet-wasm production code');
