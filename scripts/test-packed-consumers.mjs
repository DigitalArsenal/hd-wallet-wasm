import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = resolve(scriptDirectory, '..');
const coreDirectory = join(repositoryDirectory, 'wasm');
const uiDirectory = join(repositoryDirectory, 'wallet-ui');
const flatbuffersDirectory = join(repositoryDirectory, 'node_modules', 'flatbuffers');
const npmExecutable = process.env.npm_execpath;
let isolatedNpmCacheDirectory;

const npmVersion = typeof npmExecutable === 'string'
  ? JSON.parse(await readFile(resolve(dirname(npmExecutable), '..', 'package.json'), 'utf8')).version
  : null;
if (Number(process.versions.node.split('.')[0]) !== 24 || npmVersion !== '11.16.0') {
  throw new Error('test:packed requires Node 24.x and exact npm 11.16.0');
}

const CORE_FILES = Object.freeze([
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

const UI_FIXED_FILES = Object.freeze([
  'LICENSE',
  'README.md',
  'data/common-passwords-sdn-v1.source.json',
  'data/common-passwords-sdn-v1.txt',
  'dist/browser/sdn-wallet-callback.js',
  'dist/browser/sdn-wallet-public-client.js',
  'dist/browser/wallet-callback.html',
  'dist/client/asset-review.d.ts',
  'dist/client/asset-review.js',
  'dist/client/callback.d.ts',
  'dist/client/callback.js',
  'dist/client/index.d.ts',
  'dist/client/index.js',
  'dist/client/sdn.d.ts',
  'dist/client/sdn.js',
  'dist/client/style.css',
  'dist/client/types.d.ts',
  'dist/compat/index.d.ts',
  'dist/compat/index.js',
  'dist/wallet-origin-host/index.html',
  'dist/wallet-origin-host/integrity.json',
  'dist/wallet-origin/index.d.ts',
  'dist/wallet-origin/index.js',
  'package.json',
]);

async function walk(directory, base = directory) {
  const output = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) output.push(...await walk(path, base));
    else if (entry.isFile()) output.push(relative(base, path).replaceAll('\\', '/'));
    else throw new Error(`unsupported package entry: ${path}`);
  }
  return output.sort();
}

function runNpm(arguments_, options = {}) {
  return execFileSync(process.execPath, [npmExecutable, ...arguments_], {
    encoding: 'utf8',
    env: {
      ...process.env,
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_offline: 'true',
      npm_config_update_notifier: 'false',
      ...(isolatedNpmCacheDirectory
        ? { npm_config_cache: isolatedNpmCacheDirectory }
        : {}),
    },
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  });
}

async function workspaceArchives(directory) {
  return (await readdir(directory)).filter((name) => name.endsWith('.tgz')).sort();
}

function pack(directory, destination) {
  const output = runNpm([
    'pack',
    '--ignore-scripts',
    '--json',
    '--pack-destination', destination,
  ], { cwd: directory });
  const records = JSON.parse(output);
  assert.equal(records.length, 1);
  return {
    files: records[0].files.map(({ path }) => path).sort(),
    tarball: join(destination, records[0].filename),
  };
}

function assertPackageInventory(files, expected, label) {
  assert.deepEqual(files, [...expected].sort(), `${label} package inventory drift`);
  assert.equal(files.some((path) => path.endsWith('.tgz')), false);
  assert.equal(files.some((path) => path.endsWith('.map')), false);
  assert.equal(files.some((path) => /(?:^|\/)node_modules\//u.test(path)), false);
  assert.equal(files.some((path) => /^(?:src|test)\//u.test(path)), false);
}

const beforeCoreArchives = await workspaceArchives(coreDirectory);
const beforeUiArchives = await workspaceArchives(uiDirectory);
assert.deepEqual(beforeCoreArchives, []);
assert.deepEqual(beforeUiArchives, []);

execFileSync(process.execPath, [join(scriptDirectory, 'stage-core-package.mjs')], {
  cwd: repositoryDirectory,
  env: { ...process.env, npm_config_offline: 'true' },
  stdio: 'pipe',
});

const temporaryDirectory = await mkdtemp(join(tmpdir(), 'hd-wallet-packed-consumer-'));
try {
  const packDirectory = join(temporaryDirectory, 'packs');
  const projectDirectory = join(temporaryDirectory, 'project');
  isolatedNpmCacheDirectory = join(temporaryDirectory, 'npm-cache');
  await Promise.all([
    mkdir(packDirectory, { recursive: true }),
    mkdir(projectDirectory, { recursive: true }),
    mkdir(isolatedNpmCacheDirectory, { recursive: true }),
  ]);

  const uiDistFiles = (await walk(join(uiDirectory, 'dist')))
    .map((path) => `dist/${path}`);
  const uiHostAssets = uiDistFiles
    .filter((path) => path.startsWith('dist/wallet-origin-host/assets/'))
    .sort();
  assert.equal(uiHostAssets.length, 3, 'UI package must contain exactly three hosted assets');
  const uiHostExtensions = [];
  for (const path of uiHostAssets) {
    const match = /^dist\/wallet-origin-host\/assets\/wallet-origin\.([0-9a-f]{64})\.(css|js|wasm)$/u
      .exec(path);
    assert(match, `unexpected wallet-origin host asset: ${path}`);
    uiHostExtensions.push(match[2]);
  }
  assert.deepEqual(uiHostExtensions.sort(), ['css', 'js', 'wasm']);
  const expectedUiFiles = [...UI_FIXED_FILES, ...uiHostAssets].sort();
  const corePack = pack(coreDirectory, packDirectory);
  const uiPack = pack(uiDirectory, packDirectory);
  const flatbuffersPack = pack(flatbuffersDirectory, packDirectory);
  assertPackageInventory(corePack.files, CORE_FILES, 'core');
  assertPackageInventory(uiPack.files, expectedUiFiles, 'UI');
  const [sourceCoreManifest, sourceFlatbuffersManifest] = await Promise.all([
    readFile(join(coreDirectory, 'package.json'), 'utf8').then(JSON.parse),
    readFile(join(flatbuffersDirectory, 'package.json'), 'utf8').then(JSON.parse),
  ]);
  assert.equal(sourceFlatbuffersManifest.name, 'flatbuffers');
  assert.equal(sourceFlatbuffersManifest.version, sourceCoreManifest.dependencies.flatbuffers);

  await writeFile(join(projectDirectory, 'package.json'), JSON.stringify({
    name: 'sdn-wallet-packed-consumer',
    private: true,
    type: 'module',
  }, null, 2));
  runNpm([
    'install',
    '--ignore-scripts',
    '--no-audit',
    '--no-fund',
    '--offline',
    '--omit=dev',
    flatbuffersPack.tarball,
    corePack.tarball,
    uiPack.tarball,
  ], { cwd: projectDirectory });

  const installedCore = join(projectDirectory, 'node_modules/hd-wallet-wasm');
  const installedUi = join(projectDirectory, 'node_modules/hd-wallet-ui');
  await Promise.all([access(installedCore), access(installedUi)]);
  assert.equal((await realpath(installedCore)).startsWith(`${await realpath(projectDirectory)}/`), true);
  assert.equal((await realpath(installedUi)).startsWith(`${await realpath(projectDirectory)}/`), true);
  assert.deepEqual(
    await readFile(join(installedCore, 'LICENSE')),
    await readFile(join(repositoryDirectory, 'LICENSE')),
  );
  assert.deepEqual(
    await readFile(join(installedUi, 'LICENSE')),
    await readFile(join(repositoryDirectory, 'LICENSE')),
  );

  const coreManifest = JSON.parse(await readFile(join(installedCore, 'package.json'), 'utf8'));
  const uiManifest = JSON.parse(await readFile(join(installedUi, 'package.json'), 'utf8'));
  assert.equal(JSON.stringify(coreManifest).includes('workspace:'), false);
  assert.equal(JSON.stringify(uiManifest).includes('workspace:'), false);
  assert.deepEqual(uiManifest.dependencies, { 'hd-wallet-wasm': '2.0.30' });
  assert.equal(uiManifest.scripts?.prepack, undefined);

  const [coreReadme, uiReadme] = await Promise.all([
    readFile(join(installedCore, 'README.md'), 'utf8'),
    readFile(join(installedUi, 'README.md'), 'utf8'),
  ]);
  for (const surface of [
    'hd-wallet-wasm',
    'hd-wallet-wasm/aligned',
    'hd-wallet-wasm/attestation',
    'hd-wallet-wasm/wasm',
    'hd-wallet-wasm/wasi.wasm',
    'hd-wallet-wasm/dist/hd-wallet-wasi.wasm',
  ]) assert.equal(coreReadme.includes(surface), true, `core README omits ${surface}`);
  assert.doesNotMatch(
    coreReadme,
    /(?:\bunpkg\b|\bjsdelivr\b|hd-wallet-wasm\/src\/|\blocateFile\b|runtime path override)/iu,
    'core README must not recommend unpackaged or caller-rebound runtime paths',
  );
  for (const surface of [
    'hd-wallet-ui',
    'hd-wallet-ui/client',
    'hd-wallet-ui/client/asset-review',
    'hd-wallet-ui/client/callback',
    'hd-wallet-ui/client/sdn',
    'hd-wallet-ui/styles',
    'hd-wallet-ui/wallet-origin',
  ]) assert.equal(uiReadme.includes(surface), true, `UI README omits ${surface}`);
  assert.doesNotMatch(
    uiReadme,
    /(?:styles\/demo|(?:^|[('"`])\.?\.?\/?src\/|\bPIN\b|\bPBKDF2\b|\bmnemonic\b|stored[- ]seed|\bbalance(?:s)?\b|provider APIs?)/imu,
    'UI README must not advertise removed public surfaces or credential flows',
  );
  assert.doesNotMatch(
    uiReadme,
    /(?:@noble\/|@peculiar\/|@scure\/|\bbip39\b|\bflatc-wasm\b|\bqrcode\b|\bvcard-cryptoperson\b)/iu,
    'UI README must not advertise development-only packages as runtime dependencies',
  );

  const topLevelModules = await readdir(join(projectDirectory, 'node_modules'));
  for (const forbidden of [
    '@noble',
    '@peculiar',
    '@scure',
    'bip39',
    'buffer',
    'flatc-wasm',
    'qrcode',
    'spacedatastandards.org',
    'vcard-cryptoperson',
  ]) assert.equal(topLevelModules.includes(forbidden), false, `forbidden production dependency ${forbidden}`);

  for (const packageDirectory of [installedCore, installedUi]) {
    for (const path of await walk(packageDirectory)) {
      if (!/\.(?:css|d\.ts|html|js|json|mjs|md)$/u.test(path)) continue;
      const source = await readFile(join(packageDirectory, path), 'utf8');
      assert.equal(source.includes(repositoryDirectory), false, path);
      assert.doesNotMatch(source, /(?:file:\/\/|\/Users\/|\.worktrees\/|sdn-wallet-rollout)/u, path);
    }
  }

  execFileSync(process.execPath, [
    join(scriptDirectory, 'test-installed-consumer.mjs'),
    '--project', projectDirectory,
  ], {
    cwd: repositoryDirectory,
    env: { ...process.env, npm_config_offline: 'true' },
    stdio: 'inherit',
  });
} finally {
  await rm(temporaryDirectory, { force: true, recursive: true });
}

assert.deepEqual(await workspaceArchives(coreDirectory), beforeCoreArchives);
assert.deepEqual(await workspaceArchives(uiDirectory), beforeUiArchives);
console.log('PASS: packed packages install, import, typecheck, and bundle from an external project');
