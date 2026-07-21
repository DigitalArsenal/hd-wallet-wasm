import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const localCi = readFileSync(path.join(repositoryRoot, 'scripts/ci-local.sh'), 'utf8');
const hostedCi = readFileSync(path.join(repositoryRoot, '.github/workflows/build.yml'), 'utf8');
const publishCi = readFileSync(
  path.join(repositoryRoot, '.github/workflows/npm-publish.yml'),
  'utf8',
);
const cmake = readFileSync(path.join(repositoryRoot, 'CMakeLists.txt'), 'utf8');

function workflowJob(source, name, nextName = null) {
  const startMarker = `  ${name}:\n`;
  const start = source.indexOf(startMarker);
  assert.notEqual(start, -1, `workflow must contain the ${name} job`);
  const end = nextName === null ? source.length : source.indexOf(`  ${nextName}:\n`, start + 1);
  assert.notEqual(end, -1, `workflow must contain the ${nextName} job after ${name}`);
  return source.slice(start, end);
}

const hostedWasmJob = workflowJob(hostedCi, 'wasm', 'npm');
const publishBuildJob = workflowJob(publishCi, 'build', 'test');
const publishUiJob = workflowJob(publishCi, 'publish-ui');

assert.match(
  cmake,
  /add_custom_command\(TARGET hd_wallet_wasm_npm POST_BUILD[\s\S]{0,300}?scripts\/stage-core-package\.mjs/,
  'the canonical CMake package target must finish with deterministic typed staging',
);

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
  hostedWasmJob,
  /cmake --build build[^\n]*--target hd_wallet_wasm_npm/,
  'hosted CI must run the canonical CMake package target',
);
assert.match(
  hostedWasmJob,
  /name: Upload WASM artifacts[\s\S]{0,300}?path:\s*\|\s*\n\s+wasm\/dist\//,
  'hosted CI must upload CMake-staged package files',
);
assert.doesNotMatch(
  hostedWasmJob,
  /name: Upload WASM artifacts[\s\S]{0,500}?build\/wasm\/hd-wallet\.js/,
  'hosted CI must not upload the split-loader JavaScript artifact for packaging',
);
assert.match(
  hostedCi,
  /name: Verify packaged WASM entrypoint[\s\S]{0,200}?node test\/test_bundle_browser_artifact\.mjs/,
  'the hosted npm job must execute the package entrypoint regression',
);
assert.doesNotMatch(
  hostedCi,
  /cp wasm\/src\/index\.d\.ts wasm\/dist/,
  'hosted CI must consume the canonical staged declaration graph',
);
for (const path of [
  'wasm/dist/wasm-loader.d.ts',
  'wasm/dist/runtime/index.mjs',
  'wasm/dist/runtime/index.d.ts',
]) assert.ok(hostedCi.includes(path), `hosted CI must verify ${path}`);

for (const [label, job] of [
  ['hosted WASM', hostedWasmJob],
  ['publish build', publishBuildJob],
]) {
  assert.match(
    job,
    /name: Setup Node\.js[\s\S]{0,160}?uses: actions\/setup-node@v4[\s\S]{0,160}?node-version: "24"/,
    `${label} job must declare Node 24 before CMake invokes package staging`,
  );
  assert.ok(
    job.indexOf('name: Setup Node.js') < job.indexOf('cmake --build'),
    `${label} job must set up Node before the CMake package target`,
  );
}
assert.match(
  publishBuildJob,
  /cmake --build build-wasm[^\n]*--target hd_wallet_wasm_npm/,
  'publish build must run the canonical package target in the UI release build directory',
);
assert.match(
  publishBuildJob,
  /name: Build UI release package[\s\S]{0,160}?npm --workspace hd-wallet-ui run build:release/,
  'publish build must create the dist-only UI package',
);
assert.match(
  publishBuildJob,
  /name: Upload UI package artifacts[\s\S]{0,200}?name: ui-package[\s\S]{0,100}?path: wallet-ui\/dist\//,
  'publish build must upload the completed UI dist directory',
);
assert.match(
  publishUiJob,
  /name: Download UI package artifacts[\s\S]{0,200}?name: ui-package[\s\S]{0,100}?path: wallet-ui\/dist\//,
  'publish-ui must download the completed dist directory in its fresh checkout',
);
assert.ok(
  publishUiJob.indexOf('name: Download UI package artifacts')
    < publishUiJob.indexOf('name: Verify package'),
  'publish-ui must restore dist before packing',
);
assert.match(
  publishUiJob,
  /pkg\.dependencies\['hd-wallet-wasm'\] = '\$\{WASM_VERSION\}';/,
  'publish-ui must retain an exact core dependency version',
);
assert.doesNotMatch(
  publishUiJob,
  /pkg\.dependencies\['hd-wallet-wasm'\]\s*=\s*['"]\^/,
  'publish-ui must not widen the reviewed core/UI release pair',
);

console.log('PASS: local and hosted CI use the canonical typed package staging target');
