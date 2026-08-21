import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFile, readdir } from 'node:fs/promises';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = resolve(scriptDirectory, '..');
const wasmDirectory = join(repositoryDirectory, 'wasm');
const runtimeDirectory = join(wasmDirectory, 'dist/runtime');

const expectedRuntimeFiles = Object.freeze([
  'aligned.d.ts',
  'aligned.mjs',
  'epm-attestation.d.ts',
  'epm-attestation.mjs',
  'generated/aligned/hd_wallet_aligned.mjs',
  'generated/sdn_plugin_manifest.mjs',
  'index.d.ts',
  'index.mjs',
  'sdn-plugin-manifest-codec.mjs',
  'sdn-plugin-manifest-source.mjs',
  'sdn-plugin.mjs',
  'sdn-typed.mjs',
]);

async function walk(directory, base = directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(path, base));
    else output.push(relative(base, path).replaceAll('\\', '/'));
  }
  return output.sort();
}

execFileSync(process.execPath, [join(scriptDirectory, 'stage-core-package.mjs')], {
  cwd: repositoryDirectory,
  env: { ...process.env, npm_config_offline: 'true' },
  stdio: 'pipe',
});

assert.deepEqual(await walk(runtimeDirectory), expectedRuntimeFiles);
assert.equal(
  await readFile(join(runtimeDirectory, 'index.mjs'), 'utf8')
    .then((source) => source.includes("import('../hd-wallet.js')")),
  true,
);
const stagedTypes = await readFile(join(runtimeDirectory, 'index.d.ts'), 'utf8');
assert.match(stagedTypes, /from '\.\/aligned\.js';/u);
assert.doesNotMatch(stagedTypes, /from '\.\/aligned';/u);
assert.match(stagedTypes, /export \* from '\.\/epm-attestation\.js';/u);
assert.deepEqual(
  await readFile(join(wasmDirectory, 'dist/wasm-loader.d.ts')),
  await readFile(join(wasmDirectory, 'src/wasm-loader.d.ts')),
);
for (const path of ['dist/hd-wallet.js', 'dist/hd-wallet-wasi.wasm']) {
  const bytes = await readFile(join(wasmDirectory, path));
  assert.ok(bytes.byteLength > 8, path);
}
assert.deepEqual(
  (await readFile(join(wasmDirectory, 'dist/hd-wallet-wasi.wasm'))).subarray(0, 8),
  Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]),
);

assert.throws(() => execFileSync(
  process.execPath,
  [join(scriptDirectory, 'stage-core-package.mjs'), '/tmp/attacker-output'],
  { cwd: repositoryDirectory, stdio: 'pipe' },
));

console.log('PASS: core package staging is exact, typed, bounded, and path-fixed');
