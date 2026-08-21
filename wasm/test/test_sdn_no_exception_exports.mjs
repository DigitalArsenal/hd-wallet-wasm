import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import test from 'node:test';

const buildDirectory = process.env.HD_WALLET_WASM_BUILD_DIR;

test('standalone and WASI modules contain no reserved typed SDN entrypoints', async () => {
  assert.ok(buildDirectory, 'HD_WALLET_WASM_BUILD_DIR is required');
  for (const filename of ['hd-wallet.wasm', 'hd-wallet-wasi.wasm']) {
    const path = join(buildDirectory, filename);
    const bytes = await readFile(path);
    const module = new WebAssembly.Module(bytes);
    const reserved = WebAssembly.Module.exports(module)
      .map(({ name }) => name)
      .filter((name) => /^_?hd_sdn_/.test(name));
    assert.deepEqual(reserved, [], `${filename} leaked ${reserved.join(', ')}`);
  }
});
