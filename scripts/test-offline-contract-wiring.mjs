import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const packageJson = JSON.parse(readFileSync(path.join(repositoryRoot, 'package.json'), 'utf8'));
const localCi = readFileSync(path.join(repositoryRoot, 'scripts/ci-local.sh'), 'utf8');
const hostedCi = readFileSync(path.join(repositoryRoot, '.github/workflows/build.yml'), 'utf8');

const offlineScript = packageJson.scripts?.['test:offline-contracts'];
assert.equal(typeof offlineScript, 'string', 'root package must define test:offline-contracts');
for (const command of [
  'node scripts/verify-fixtures.mjs',
  'node --test scripts/test-no-live-test-fetches.test.mjs',
  'node scripts/test-no-live-test-fetches.mjs',
  'node scripts/test-wasm-package-copy-contract.mjs',
  'node scripts/test-wasm-tests-fail-closed.mjs',
  'node scripts/test-capability-skip-contract.mjs',
  'node scripts/test-offline-contract-wiring.mjs',
]) {
  assert(offlineScript.includes(command), `offline contract script is missing: ${command}`);
}

assert(
  (packageJson.scripts?.test ?? '').startsWith('npm run test:offline-contracts'),
  'root npm test must start with offline contracts',
);

const install = localCi.indexOf('npm ci');
const contracts = localCi.indexOf('npm run test:offline-contracts');
const build = localCi.indexOf('npm run build:release');
const docs = localCi.indexOf('npm run build:docs');
assert(install !== -1 && install < contracts && contracts < build && build < docs);
assert.match(localCi, /set -euo pipefail/u);
assert.doesNotMatch(localCi.replaceAll('--skip-tag', ''), /\bskip(?:ped)?\b|\bquick\b|\bMODE\b/iu);
assert.doesNotMatch(localCi, /npm install[^\n]*\|\|\s*true/u);

assert.match(hostedCi, /^  verify:\s*$/mu, 'hosted CI must have one full verification job');
assert.match(
  hostedCi,
  /name: Run complete local gate[\s\S]{0,120}?run: \.\/scripts\/ci-local\.sh/u,
  'hosted CI must invoke the same fail-closed local gate',
);
assert.doesNotMatch(hostedCi, /^  (?:native|wasm|matrix|npm|contracts):\s*$/mu);

console.log('PASS: root, local CI, and hosted CI always run offline contracts first');
