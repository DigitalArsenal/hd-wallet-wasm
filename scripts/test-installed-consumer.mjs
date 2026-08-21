import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { dirname, isAbsolute, join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = resolve(scriptDirectory, '..');
const typescriptExecutable = join(repositoryDirectory, 'node_modules/.bin/tsc');
const esbuildExecutable = join(repositoryDirectory, 'node_modules/esbuild/bin/esbuild');

if (!process.execArgv.includes('--experimental-import-meta-resolve')) {
  const result = execFileSync(process.execPath, [
    '--experimental-import-meta-resolve',
    fileURLToPath(import.meta.url),
    ...process.argv.slice(2),
  ], { env: { ...process.env, npm_config_offline: 'true' }, stdio: 'inherit' });
  void result;
  process.exit(0);
}

function parseProjectArgument() {
  if (process.argv.length !== 4 || process.argv[2] !== '--project'
      || !isAbsolute(process.argv[3])) {
    throw new Error('usage: test-installed-consumer.mjs --project /absolute/project');
  }
  return process.argv[3];
}

async function resolveInstalled(specifier, parentUrl, projectDirectory) {
  const resolvedUrl = import.meta.resolve(specifier, parentUrl);
  assert.equal(resolvedUrl.startsWith('file:'), true, `${specifier} must resolve to a file`);
  const resolvedPath = await realpath(fileURLToPath(resolvedUrl));
  const installedRoot = `${await realpath(join(projectDirectory, 'node_modules'))}/`;
  assert.equal(
    resolvedPath.startsWith(installedRoot),
    true,
    `${specifier} escaped installed node_modules: ${resolvedPath}`,
  );
  assert.equal(resolvedPath.startsWith(`${await realpath(repositoryDirectory)}/`), false);
  return { resolvedPath, resolvedUrl };
}

function exactExports(module, expected, label) {
  for (const name of expected) {
    assert.equal(name in module, true, `${label} is missing ${name}`);
  }
}

function instrumentGlobals() {
  const records = [];
  const names = ['document', 'localStorage', 'window'];
  const prior = new Map(names.map((name) => [name, Object.getOwnPropertyDescriptor(globalThis, name)]));
  for (const name of names) {
    Object.defineProperty(globalThis, name, {
      configurable: true,
      get() {
        records.push(name);
        throw new Error(`installed module touched ${name}`);
      },
    });
  }
  return {
    records,
    restore() {
      for (const name of names) {
        const descriptor = prior.get(name);
        if (descriptor) Object.defineProperty(globalThis, name, descriptor);
        else delete globalThis[name];
      }
    },
  };
}

const projectDirectory = parseProjectArgument();
const projectRealpath = await realpath(projectDirectory);
const parentUrl = pathToFileURL(join(projectRealpath, 'installed-consumer.mjs')).href;
const temporaryDirectory = await mkdtemp(join(projectRealpath, '.sdn-installed-consumer-'));

try {
  const resolved = new Map();
  for (const specifier of [
    'hd-wallet-wasm',
    'hd-wallet-wasm/aligned',
    'hd-wallet-wasm/attestation',
    'hd-wallet-wasm/wasm',
    'hd-wallet-wasm/wasi.wasm',
    'hd-wallet-wasm/dist/hd-wallet-wasi.wasm',
    'hd-wallet-ui',
    'hd-wallet-ui/client',
    'hd-wallet-ui/client/sdn',
    'hd-wallet-ui/client/asset-review',
    'hd-wallet-ui/client/callback',
    'hd-wallet-ui/wallet-origin',
    'hd-wallet-ui/styles',
  ]) resolved.set(specifier, await resolveInstalled(specifier, parentUrl, projectRealpath));

  assert.throws(
    () => import.meta.resolve(
      'hd-wallet-wasm',
      pathToFileURL(join(tmpdir(), 'sdn-wallet-resolution-negative/consumer.mjs')).href,
    ),
    /Cannot find package/u,
    'the supplied parent URL must control package resolution',
  );

  const instrumentation = instrumentGlobals();
  let uiModules;
  try {
    uiModules = await Promise.all([
      import(resolved.get('hd-wallet-ui').resolvedUrl),
      import(resolved.get('hd-wallet-ui/client').resolvedUrl),
      import(resolved.get('hd-wallet-ui/client/sdn').resolvedUrl),
      import(resolved.get('hd-wallet-ui/client/asset-review').resolvedUrl),
      import(resolved.get('hd-wallet-ui/client/callback').resolvedUrl),
      import(resolved.get('hd-wallet-ui/wallet-origin').resolvedUrl),
    ]);
  } finally {
    instrumentation.restore();
  }
  assert.deepEqual(instrumentation.records, [], 'every UI export must be browser-global inert');
  const [compat, client, sdn, review, callback, origin] = uiModules;
  exactExports(compat, [
    'createWalletUI',
    'init',
    'normalizeCreateWalletUIArguments',
    'normalizeTabHash',
  ], 'hd-wallet-ui');

  const [core, aligned, attestation, raw] = await Promise.all([
    import(resolved.get('hd-wallet-wasm').resolvedUrl),
    import(resolved.get('hd-wallet-wasm/aligned').resolvedUrl),
    import(resolved.get('hd-wallet-wasm/attestation').resolvedUrl),
    import(resolved.get('hd-wallet-wasm/wasm').resolvedUrl),
  ]);
  exactExports(core, ['createHDWallet', 'default', 'getWalletOriginCapabilities'], 'core root');
  exactExports(aligned, ['AlignedAPI', 'default'], 'core aligned');
  exactExports(attestation, ['buildCanonicalPayload', 'signEPMContent'], 'core attestation');
  exactExports(raw, ['default'], 'core raw WASM');
  exactExports(client, ['WALLET_CLIENT_ERRORS', 'createWalletClient'], 'UI client');
  exactExports(sdn, ['createSdnWalletClient'], 'UI SDN client');
  exactExports(review, ['createAssetReviewWalletClient'], 'UI review client');
  exactExports(callback, ['completeWalletCallbackV1'], 'UI callback');
  exactExports(origin, ['createWalletOriginApp', 'mountWalletOriginApp'], 'UI wallet origin');

  const publicClient = client.createWalletClient({ clientId: 'sdn-landing-web-v1' });
  assert.deepEqual(publicClient.getSnapshot(), { identity: null, status: 'dormant' });
  await publicClient.destroy();
  const sdnClient = sdn.createSdnWalletClient();
  const reviewClient = review.createAssetReviewWalletClient();
  await Promise.all([sdnClient.destroy(), reviewClient.destroy()]);

  const wasi = await readFile(resolved.get('hd-wallet-wasm/wasi.wasm').resolvedPath);
  const documentedWasi = await readFile(
    resolved.get('hd-wallet-wasm/dist/hd-wallet-wasi.wasm').resolvedPath,
  );
  assert.deepEqual(wasi, documentedWasi);
  assert.deepEqual(wasi.subarray(0, 8), Buffer.from([0, 0x61, 0x73, 0x6d, 1, 0, 0, 0]));
  assert.match(await readFile(resolved.get('hd-wallet-ui/styles').resolvedPath, 'utf8'), /\.sdn-wallet/u);

  const typeConsumer = join(temporaryDirectory, 'consumer.mts');
  await writeFile(typeConsumer, `
import initializeWallet, { createHDWallet, type HDWalletModule } from 'hd-wallet-wasm';
import { AlignedAPI } from 'hd-wallet-wasm/aligned';
import { buildCanonicalPayload, type EpmSignatureOptions } from 'hd-wallet-wasm/attestation';
import initializeRaw, { type HDWalletWasmModule } from 'hd-wallet-wasm/wasm';
import { createWalletUI } from 'hd-wallet-ui';
import { createWalletClient } from 'hd-wallet-ui/client';
import { createSdnWalletClient } from 'hd-wallet-ui/client/sdn';
import { createAssetReviewWalletClient } from 'hd-wallet-ui/client/asset-review';
import { completeWalletCallbackV1 } from 'hd-wallet-ui/client/callback';
import { createWalletOriginApp } from 'hd-wallet-ui/wallet-origin';

const wallet: Promise<HDWalletModule> = initializeWallet();
const second: Promise<HDWalletModule> = createHDWallet();
const raw: Promise<HDWalletWasmModule> = initializeRaw({ wasmBinary: new Uint8Array(8) });
const publicClient = createWalletClient({ clientId: 'sdn-landing-web-v1' });
const sdn = createSdnWalletClient();
const review = createAssetReviewWalletClient();
const compatibilityController = createWalletUI({ wasm: {} });
const originApplication = createWalletOriginApp({ wasm: {} });
completeWalletCallbackV1(
  { hash: '', pathname: '/wallet-callback.html', search: '' },
  { setItem(_key: string, _value: string) {} },
  { replaceState(_data: unknown, _unused: string, _url: string) {} },
  () => {},
);
const options: EpmSignatureOptions = { curve: 'secp256k1' };
const payload: string = buildCanonicalPayload({
  encryptionPubKeyHex: '00', issuedAt: 1, signingPubKeyHex: '00', xpub: 'xpub',
});
wallet.then((value) => { const aligned: AlignedAPI = value.aligned; void aligned; });
compatibilityController.then(async (controller) => {
  await controller.openLogin();
  await controller.openAccount();
  await controller.logout();
  await controller.destroy();
});
void originApplication.start();
void originApplication.stop('consumer-typecheck');
void originApplication.logout();
void second; void raw; void publicClient; void sdn; void review; void options; void payload;
`);
  execFileSync(typescriptExecutable, [
    '--noEmit',
    '--strict',
    '--skipLibCheck', 'false',
    '--module', 'NodeNext',
    '--moduleResolution', 'NodeNext',
    '--target', 'ES2022',
    typeConsumer,
  ], { cwd: projectRealpath, env: { ...process.env, npm_config_offline: 'true' }, stdio: 'pipe' });

  const bundleEntry = join(temporaryDirectory, 'public-entry.mjs');
  const bundleOutput = join(temporaryDirectory, 'public-bundle.js');
  await writeFile(bundleEntry, `
import { createWalletClient } from 'hd-wallet-ui/client';
import { createSdnWalletClient } from 'hd-wallet-ui/client/sdn';
import { createAssetReviewWalletClient } from 'hd-wallet-ui/client/asset-review';
export { createWalletClient, createSdnWalletClient, createAssetReviewWalletClient };
`);
  execFileSync(esbuildExecutable, [
    bundleEntry,
    '--bundle',
    '--format=esm',
    '--legal-comments=none',
    '--minify',
    '--platform=browser',
    '--target=es2022',
    `--outfile=${bundleOutput}`,
  ], { cwd: projectRealpath, env: { ...process.env, npm_config_offline: 'true' }, stdio: 'pipe' });
  let bundle = await readFile(bundleOutput, 'utf8');
  for (const literal of [
    'password-scrypt-v2',
    'sdn-fast-password-auth-v1-legacy',
    'sdn-bip39-auth-v1-legacy',
  ]) bundle = bundle.replaceAll(`"${literal}"`, '"<allowed-protocol-literal>"');
  assert.doesNotMatch(bundle, /(?:\0asm|\.wasm\b|\b(?:argon2|hkdf|pbkdf2|scrypt)\b)/iu);
  assert.doesNotMatch(bundle, /\b(?:deriveBits|deriveKey|importKey|privateKey|secretHandle)\b/u);
  assert.doesNotMatch(bundle, /\bimport\s*\(/u);
  assert.doesNotMatch(bundle, /(?:origin-app|@wallet|@sds|node_modules|file:\/\/|\.worktrees)/u);
  assert.doesNotMatch(bundle, /[A-Za-z0-9+/]{1024,}={0,2}/u);
} finally {
  await rm(temporaryDirectory, { force: true, recursive: true });
}

console.log(`PASS: installed consumer imports, types, and bundles resolve inside ${projectRealpath}`);
