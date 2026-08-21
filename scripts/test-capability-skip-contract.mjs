import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const bip39 = readFileSync(path.join(repositoryRoot, 'wasm/test/test_bip39.mjs'), 'utf8');
const x509 = readFileSync(path.join(repositoryRoot, 'wasm/test/test_x509.mjs'), 'utf8');

assert.match(bip39, /import init, \{ ErrorCode, Language \}/);
assert.match(
  bip39,
  /if \(error\?\.name === 'HDWalletError' && error\.code === ErrorCode\.NOT_SUPPORTED\) \{[\s\S]{0,240}?skip\(japaneseTestName,[\s\S]{0,240}?\} else \{\s*throw error;\s*\}/,
  'Japanese capability handling must rethrow every error except HDWalletError NOT_SUPPORTED',
);

assert.match(x509, /assert\(wallet\.x509, 'X\.509 API object must exist'\);/);
assert.match(
  x509,
  /assertEqual\(typeof wallet\.x509\.isAvailable, 'function', 'X\.509 capability probe must exist'\);/,
);
assert.match(x509, /const x509Available = wallet\.x509\.isAvailable\(\);/);
assert.match(x509, /if \(!x509Available\) \{[\s\S]{0,500}?skip\([\s\S]{0,500}?skip\(/);

console.log('PASS: optional wallet capabilities skip only through explicit probes');
