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

const rootTest = packageJson.scripts?.test ?? '';
assert(
  rootTest.indexOf('npm run test:offline-contracts') !== -1 &&
    rootTest.indexOf('npm run test:offline-contracts') < rootTest.indexOf('npm run test:artifact'),
  'root npm test must run offline contracts before artifact-dependent suites',
);

const preflightCall = localCi.indexOf('if ! run_offline_contracts; then');
const dispatch = localCi.indexOf('case "$MODE" in');
assert(preflightCall !== -1 && preflightCall < dispatch, 'local CI must run offline contracts before dispatch');
assert.doesNotMatch(
  localCi,
  /npm install --ignore-scripts[^\n]*\|\|\s*true/,
  'local CI must not ignore dependency installation failures',
);
assert.match(
  localCi,
  /if \(cd "\$ROOT\/wasm" && npm install --ignore-scripts 2>&1\); then[\s\S]{0,160}?pass "npm dependencies"[\s\S]{0,160}?fail "npm dependencies"/,
  'local CI must explicitly pass or fail dependency installation',
);

assert.match(
  hostedCi,
  /contracts:\s*\n\s+name: Offline Contract Gates[\s\S]{0,500}?run: npm run test:offline-contracts/,
  'hosted CI must define the offline contract gate job',
);
for (const job of ['native', 'wasm', 'matrix']) {
  assert.match(
    hostedCi,
    new RegExp(`\\n  ${job}:[\\s\\S]{0,180}?\\n    needs: contracts`),
    `${job} job must depend on offline contracts`,
  );
}

console.log('PASS: root, local CI, and hosted CI always run offline contracts first');
