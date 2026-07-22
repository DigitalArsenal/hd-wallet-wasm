import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { dirname, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

import {
  assertPortableBuildBytes,
  decodeInlineWasm,
} from '../../scripts/verify-build-paths.mjs';

const CANONICAL_PREFIX = '/hd-wallet-build/openssl-3.0.9';
const verifierPath = resolve(
  dirname(fileURLToPath(import.meta.url)),
  '../../scripts/verify-build-paths.mjs',
);

test('portable build scanner recognizes only the exact canonical inert OpenSSL prefix', () => {
  const bytes = Buffer.from([
    `OPENSSLDIR: "${CANONICAL_PREFIX}/ssl"`,
    `MODULESDIR: "${CANONICAL_PREFIX}/lib/ossl-modules"`,
    '/dev/random',
    '/etc/localtime',
    '/providers/implementations/ciphers/cipher_aes.c',
    'server=http%s://%s%s%s',
  ].join('\0'));
  assert.doesNotThrow(() => assertPortableBuildBytes(bytes, 'fixture'));

  for (const path of [
    `${CANONICAL_PREFIX}evil/ssl`,
    `${CANONICAL_PREFIX}/../foreign/ssl`,
    `${CANONICAL_PREFIX}/./ssl`,
    `${CANONICAL_PREFIX}//ssl`,
    `${CANONICAL_PREFIX}\\ssl`,
    `${CANONICAL_PREFIX}:evil`,
    `${CANONICAL_PREFIX}%2fssl`,
    `${CANONICAL_PREFIX}?ssl`,
    `${CANONICAL_PREFIX}/ssl\\evil`,
    `${CANONICAL_PREFIX}/ssl:evil`,
    `${CANONICAL_PREFIX}/ssl%2fevil`,
    `${CANONICAL_PREFIX}/ssl?evil`,
  ]) {
    assert.throws(
      () => assertPortableBuildBytes(Buffer.from(path), 'fixture'),
      /non-portable build path/u,
      path,
    );
  }
});

test('portable build scanner rejects ephemeral and host build paths', () => {
  for (const path of [
    '/tmp/hd-wallet-openssl.ABC123/dist/ssl',
    '/private/tmp/hd-wallet-openssl.ABC123/source',
    '/var/folders/ab/random/T/hd-wallet-openssl.ABC123/dist',
    '/Users/alice/source/hd-wallet-wasm',
    '/home/runner/work/hd-wallet-wasm/hd-wallet-wasm',
    '/__w/hd-wallet-wasm/hd-wallet-wasm',
    '/workspaces/hd-wallet-wasm/build',
    '/workspace/hd-wallet-wasm/build',
    '/builds/hd-wallet-wasm/output',
    '/mnt/agent/hd-wallet-wasm',
    'x/Users/alice/source/hd-wallet-wasm',
    'x/workspaces/hd-wallet-wasm/build',
    '/opt/hd-wallet-openssl/3.0.9/ssl',
    '/hd-wallet-build/openssl-3.0.8/ssl',
    'C:\\Users\\alice\\source\\hd-wallet-wasm',
    'C:/workspaces/hd-wallet-wasm/build',
    'D:\\a\\hd-wallet-wasm\\hd-wallet-wasm',
    'C:\\Windows\\Temp\\hd-wallet-wasm',
    '\\\\runner\\builds\\hd-wallet-wasm',
  ]) {
    assert.throws(
      () => assertPortableBuildBytes(Buffer.from(`prefix\0${path}\0suffix`), 'fixture'),
      /non-portable build path/u,
      path,
    );
  }
  assert.throws(
    () => assertPortableBuildBytes(
      Buffer.from(`${CANONICAL_PREFIX}/ssl\0/workspaces/team/hd-wallet-wasm`),
      'fixture',
    ),
    /non-portable build path/u,
  );
});

test('inline Emscripten scanner decodes the single embedded WebAssembly module', () => {
  const wasm = Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0, ...Buffer.from(CANONICAL_PREFIX)]);
  const source = `const empty = "data:application/octet-stream;base64,";\n`
    + `const wasm = "data:application/octet-stream;base64,${wasm.toString('base64')}";\n`;
  assert.deepEqual(decodeInlineWasm(source), wasm);
  assert.throws(
    () => decodeInlineWasm(`${source}${source}`),
    /exactly one embedded WebAssembly/u,
  );
});

test('build path verifier CLI rejects every argument before reading artifacts', () => {
  const result = spawnSync(process.execPath, [verifierPath, '--bogus'], { encoding: 'utf8' });
  assert.notEqual(result.status, 0);
  assert.match(`${result.stdout}${result.stderr}`, /takes no arguments/u);
});
