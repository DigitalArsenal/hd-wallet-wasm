import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  access,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const packageDirectory = dirname(fileURLToPath(new URL('../package.json', import.meta.url)));
const repositoryDirectory = resolve(packageDirectory, '..');
const typescriptExecutable = join(repositoryDirectory, 'node_modules/.bin/tsc');

const EXPECTED_EXPORTS = Object.freeze({
  '.': {
    types: './dist/runtime/index.d.ts',
    import: './dist/runtime/index.mjs',
  },
  './aligned': {
    types: './dist/runtime/aligned.d.ts',
    import: './dist/runtime/aligned.mjs',
  },
  './attestation': {
    types: './dist/runtime/epm-attestation.d.ts',
    import: './dist/runtime/epm-attestation.mjs',
  },
  './wasm': {
    types: './dist/wasm-loader.d.ts',
    import: './dist/hd-wallet.js',
  },
  './wasi.wasm': './dist/hd-wallet-wasi.wasm',
  './dist/hd-wallet-wasi.wasm': './dist/hd-wallet-wasi.wasm',
});

const EXPECTED_FILES = Object.freeze([
  'dist/runtime/',
  'dist/hd-wallet.js',
  'dist/hd-wallet-wasi.wasm',
  'dist/wasm-loader.d.ts',
  'README.md',
  'LICENSE',
]);

const PACKED_FILE_ALLOWLIST = Object.freeze([
  'LICENSE',
  'README.md',
  'dist/hd-wallet-wasi.wasm',
  'dist/hd-wallet.js',
  'dist/runtime/aligned.d.ts',
  'dist/runtime/aligned.mjs',
  'dist/runtime/epm-attestation.d.ts',
  'dist/runtime/epm-attestation.mjs',
  'dist/runtime/generated/aligned/hd_wallet_aligned.mjs',
  'dist/runtime/generated/sdn_plugin_manifest.mjs',
  'dist/runtime/index.d.ts',
  'dist/runtime/index.mjs',
  'dist/runtime/sdn-plugin-manifest-codec.mjs',
  'dist/runtime/sdn-plugin-manifest-source.mjs',
  'dist/runtime/sdn-plugin.mjs',
  'dist/runtime/sdn-typed.mjs',
  'dist/wasm-loader.d.ts',
  'package.json',
]);

test('core package exposes only the synchronized built runtime contract', async () => {
  const manifest = JSON.parse(await readFile(join(packageDirectory, 'package.json'), 'utf8'));

  assert.equal(manifest.version, '2.0.27');
  assert.equal(manifest.main, './dist/runtime/index.mjs');
  assert.equal(manifest.module, './dist/runtime/index.mjs');
  assert.equal(manifest.types, './dist/runtime/index.d.ts');
  assert.deepEqual(manifest.exports, EXPECTED_EXPORTS);
  assert.deepEqual(manifest.files, EXPECTED_FILES);
  assert.equal(JSON.stringify(manifest).includes('hd-wallet-inline'), false);
});

test('npm dry-run inventory contains no inline, duplicate, source, test, or archive file', async () => {
  const before = (await readdir(packageDirectory)).filter((name) => name.endsWith('.tgz'));
  const output = execFileSync('npm', [
    'pack', '--dry-run', '--json', '--ignore-scripts',
  ], {
    cwd: packageDirectory,
    encoding: 'utf8',
    env: {
      ...process.env,
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_offline: 'true',
      npm_config_update_notifier: 'false',
    },
  });
  const packed = JSON.parse(output);
  assert.equal(packed.length, 1);
  const actual = packed[0].files.map(({ path }) => path).sort();
  const presentAllowlist = [];
  for (const path of PACKED_FILE_ALLOWLIST) {
    if (path === 'package.json') {
      presentAllowlist.push(path);
      continue;
    }
    try {
      await access(join(packageDirectory, path));
      presentAllowlist.push(path);
    } catch {
      // Release staging owns required-output presence; this test owns package inclusion boundaries.
    }
  }
  assert.deepEqual(actual, presentAllowlist.sort());
  assert.equal(actual.some((path) => path.endsWith('.tgz')), false);
  assert.equal(actual.some((path) => path.startsWith('src/')), false);
  assert.equal(actual.some((path) => path.startsWith('test/')), false);

  const after = (await readdir(packageDirectory)).filter((name) => name.endsWith('.tgz'));
  assert.deepEqual(after, before);
});

test('core workspace carries the root license and no nested package archive', async () => {
  assert.deepEqual(
    await readFile(join(packageDirectory, 'LICENSE')),
    await readFile(join(repositoryDirectory, 'LICENSE')),
  );
  assert.deepEqual(
    (await readdir(packageDirectory)).filter((name) => name.endsWith('.tgz')),
    [],
  );
});

test('all typed core subpaths compile together under NodeNext', async () => {
  const temporaryDirectory = await mkdtemp(join(tmpdir(), 'hd-wallet-core-types-'));
  const installedPackage = join(temporaryDirectory, 'node_modules/hd-wallet-wasm');
  const runtimeDirectory = join(installedPackage, 'dist/runtime');

  try {
    await mkdir(runtimeDirectory, { recursive: true });
    const manifest = JSON.parse(await readFile(join(packageDirectory, 'package.json'), 'utf8'));
    await writeFile(
      join(installedPackage, 'package.json'),
      `${JSON.stringify({
        name: manifest.name,
        version: manifest.version,
        type: 'module',
        exports: EXPECTED_EXPORTS,
      }, null, 2)}\n`,
    );

    const highLevelDeclaration = (
      await readFile(join(packageDirectory, 'src/index.d.ts'), 'utf8')
    ).replace("from './aligned';", "from './aligned.js';");
    await writeFile(join(runtimeDirectory, 'index.d.ts'), highLevelDeclaration);
    await copyFile(
      join(packageDirectory, 'src/aligned.d.ts'),
      join(runtimeDirectory, 'aligned.d.ts'),
    );
    await copyFile(
      join(packageDirectory, 'src/epm-attestation.d.ts'),
      join(runtimeDirectory, 'epm-attestation.d.ts'),
    );
    await copyFile(
      join(packageDirectory, 'src/wasm-loader.d.ts'),
      join(installedPackage, 'dist/wasm-loader.d.ts'),
    );

    await writeFile(join(temporaryDirectory, 'package.json'), '{"type":"module"}\n');
    await writeFile(join(temporaryDirectory, 'consumer.mts'), `
import initializeWallet, {
  createHDWallet,
  signEPMContent as signEPMContentFromRoot,
  type HDWalletModule,
} from 'hd-wallet-wasm';
import { type AlignedAPI } from 'hd-wallet-wasm/aligned';
import {
  buildCanonicalPayload,
  signEPMContent,
  type EpmSignatureOptions,
} from 'hd-wallet-wasm/attestation';
import initializeRawWasm, {
  type HDWalletWasmModule,
  type HDWalletWasmModuleOptions,
} from 'hd-wallet-wasm/wasm';

const walletPromise: Promise<HDWalletModule> = initializeWallet();
const alternateWalletPromise: Promise<HDWalletModule> = createHDWallet();
// @ts-expect-error The high-level runtime has no caller-selected WASM path seam.
void initializeWallet('https://attacker.invalid/hd-wallet.wasm');
// @ts-expect-error The alternate initializer has the same sealed zero-argument contract.
void createHDWallet('https://attacker.invalid/hd-wallet.wasm');
void alternateWalletPromise;
declare const aligned: AlignedAPI;
void aligned;

const options: HDWalletWasmModuleOptions = {
  locateFile: (path, prefix) => new URL(path, prefix).href,
  wasmBinary: new Uint8Array(8),
  print: (message) => void message,
  printErr: (message) => void message,
};
const rawPromise: Promise<HDWalletWasmModule> = initializeRawWasm(options);
rawPromise.then((raw) => {
  const heap: Uint8Array = raw.HEAPU8;
  const pointer: number = raw._malloc(heap.byteLength);
  const version: number = raw.ccall<number>('hd_get_version', 'number', [], []);
  const asyncVersion: Promise<number> = raw.ccall<number>(
    'hd_get_version',
    'number',
    [],
    [],
    { async: true },
  );
  const wrappedAsync: () => Promise<number> = raw.cwrap<[], number>(
    'hd_get_version',
    'number',
    [],
    { async: true },
  );
  raw._free(pointer);
  void version;
  void asyncVersion;
  void wrappedAsync;
  // @ts-expect-error The raw loader must not masquerade as the high-level API.
  void raw.mnemonic;
});

walletPromise.then((wallet) => {
  const payload: string = buildCanonicalPayload({
    xpub: 'xpub',
    signingPubKeyHex: '00',
    encryptionPubKeyHex: '00',
    issuedAt: 1,
  });
  const signatureOptions: EpmSignatureOptions = { curve: 'secp256k1' };
  const result: { signature: string; timestamp: number } = signEPMContent(
    wallet,
    { payload },
    new Uint8Array(32),
    signatureOptions,
  );
  const rootResult: { signature: string; timestamp: number } = signEPMContentFromRoot(
    wallet,
    { payload },
    new Uint8Array(32),
    signatureOptions,
  );
  void result;
  void rootResult;
});
`);

    execFileSync(typescriptExecutable, [
      '--noEmit',
      '--strict',
      '--skipLibCheck', 'false',
      '--module', 'NodeNext',
      '--moduleResolution', 'NodeNext',
      '--target', 'ES2022',
      join(temporaryDirectory, 'consumer.mts'),
    ], {
      cwd: temporaryDirectory,
      encoding: 'utf8',
      stdio: 'pipe',
    });
  } finally {
    await rm(temporaryDirectory, { recursive: true, force: true });
  }
});
