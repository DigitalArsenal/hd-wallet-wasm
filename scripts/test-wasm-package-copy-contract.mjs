import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const localCi = readFileSync(path.join(repositoryRoot, 'scripts/ci-local.sh'), 'utf8');
const hostedCi = readFileSync(path.join(repositoryRoot, '.github/workflows/build.yml'), 'utf8');

assert.match(
  localCi,
  /cmake --build "\$ROOT\/build-wasi"[\s\S]{0,200}--target hd_wallet_wasm_npm/,
  'local npm testing must stage the package through the canonical CMake target',
);
assert.doesNotMatch(
  localCi,
  /cp "\$ROOT\/build-wasi\/wasm\/hd-wallet\.js" "\$ROOT\/wasm\/dist/,
  'local npm testing must not package the split-loader JavaScript artifact',
);
assert.match(
  localCi,
  /cp "\$ROOT\/build-wasi\/wasm\/hd-wallet-inline\.js" "\$ROOT\/wasm\/dist\/hd-wallet-inline\.js"/,
  'local npm testing must preserve the explicit inline artifact filename',
);

assert.match(
  hostedCi,
  /cmake --build build[^\n]*--target hd_wallet_wasm_npm/,
  'hosted CI must run the canonical CMake package target',
);
assert.match(
  hostedCi,
  /name: Upload WASM artifacts[\s\S]{0,300}?path:\s*\|\s*\n\s+wasm\/dist\//,
  'hosted CI must upload CMake-staged package files',
);
assert.doesNotMatch(
  hostedCi,
  /name: Upload WASM artifacts[\s\S]{0,500}?build\/wasm\/hd-wallet\.js/,
  'hosted CI must not upload the split-loader JavaScript artifact for packaging',
);
assert.match(
  hostedCi,
  /name: Verify packaged WASM entrypoint[\s\S]{0,200}?node test\/test_bundle_browser_artifact\.mjs/,
  'the hosted npm job must execute the package entrypoint regression',
);

console.log('PASS: local and hosted CI use the canonical inline package entrypoint');
