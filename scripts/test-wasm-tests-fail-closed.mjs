import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const testRoot = path.join(repositoryRoot, 'wasm/test');
const testFiles = readdirSync(testRoot)
  .filter((name) => name.endsWith('.mjs'))
  .sort();
const violations = [];

for (const name of testFiles) {
  const body = readFileSync(path.join(testRoot, name), 'utf8');
  if (/process\.exit\(0\)/.test(body)) {
    violations.push(`${name}: exits successfully without running expected tests`);
  }
  if (/Skipping[^\n]*WASM module not available/.test(body)) {
    violations.push(`${name}: treats an expected WASM load failure as a skip`);
  }
}

assert.deepEqual(
  violations,
  [],
  `WASM tests must fail closed:\n${violations.join('\n')}`,
);

const suite = readFileSync(path.join(testRoot, 'test_all.mjs'), 'utf8');
assert.match(
  suite,
  /if \(!existsSync\(jsPath\)\) \{\s*throw new Error\(/,
  'the full suite must fail when its expected package entrypoint is absent',
);
assert.match(
  suite,
  /let skippedTests = 0;/,
  'legitimate capability skips must be counted separately',
);
assert.match(
  suite,
  /Skipped: \$\{skippedTests\}/,
  'the full-suite summary must report its exact skip count',
);

console.log(`PASS: ${testFiles.length} WASM test modules fail closed on required artifact errors`);
