import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  cp,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  realpath,
  rename,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import vm from 'node:vm';
import test from 'node:test';

import { buildWalletAssets } from '../../scripts/build-wallet-assets.mjs';
import { verifyWalletAssets } from '../../scripts/verify-wallet-assets.mjs';

const repositoryDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '../..');
const releaseDirectory = join(repositoryDirectory, 'release');
const staticVersionDirectory = join(
  releaseDirectory,
  'static/assets/hd-wallet-ui/2.0.28',
);
const manifestPath = join(releaseDirectory, 'wallet-assets.v1.json');
const staticUrlPrefix = 'https://static.spacedatanetwork.org/assets/hd-wallet-ui/2.0.28/';
const clientIds = Object.freeze([
  'orbpro-pages-v1',
  'sdn-asset-models-pages-v1',
  'sdn-asset-review-v1',
  'sdn-flatbuffers-pages-v1',
  'sdn-flatsql-pages-v1',
  'sdn-landing-web-v1',
  'sdn-module-sdk-pages-v1',
  'sdn-node-console-v1',
  'sdn-standards-web-v1',
  'spaceaware-web-v1',
]);

let canonicalTemporaryRootPromise;

async function makeTemporaryDirectory(prefix) {
  canonicalTemporaryRootPromise ??= realpath(tmpdir());
  return mkdtemp(join(await canonicalTemporaryRootPromise, prefix));
}

function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    assert.equal(Number.isFinite(value), true, 'JCS numbers must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  assert(value && typeof value === 'object', 'JCS values must be JSON values');
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${jcs(value[key])}`
  )).join(',')}}`;
}

function digest(algorithm, bytes, encoding = 'hex') {
  return createHash(algorithm).update(bytes).digest(encoding);
}

function assetValues(manifest) {
  return [
    manifest.assets.publicClientScript,
    manifest.assets.publicClientStyle,
    manifest.callbackHelper.asset,
  ];
}

function localAssetPath(asset, root = staticVersionDirectory) {
  return join(root, basename(new URL(asset.url).pathname));
}

async function walk(directory, base = directory) {
  const paths = [];
  for (const entry of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) paths.push(...await walk(path, base));
    else paths.push(relative(base, path).replaceAll('\\', '/'));
  }
  return paths.sort();
}

function instrumentedPublicContext() {
  const counts = {
    close: 0,
    fetch: 0,
    listeners: 0,
    open: 0,
    storage: 0,
    timers: 0,
  };
  const window = {
    addEventListener() { counts.listeners += 1; },
    close() { counts.close += 1; },
    open() { counts.open += 1; return null; },
    removeEventListener() {},
  };
  Object.defineProperty(window, 'localStorage', {
    configurable: false,
    enumerable: true,
    get() {
      counts.storage += 1;
      throw new Error('localStorage must remain lazy');
    },
  });
  const context = vm.createContext({
    AbortController,
    TextDecoder,
    TextEncoder,
    Uint8Array,
    clearInterval() {},
    clearTimeout() {},
    console: Object.freeze({ error() {}, log() {}, warn() {} }),
    crypto: Object.freeze({
      getRandomValues() { throw new Error('entropy must remain inert'); },
      subtle: Object.freeze({ digest() { throw new Error('digest must remain inert'); } }),
    }),
    fetch() { counts.fetch += 1; throw new Error('fetch must remain inert'); },
    setInterval() { counts.timers += 1; return 1; },
    setTimeout() { counts.timers += 1; return 1; },
    window,
  });
  return { context, counts };
}

function assertPublicClientIife(source) {
  const { context, counts } = instrumentedPublicContext();
  const before = Reflect.ownKeys(context);
  vm.runInContext(source, context, {
    filename: 'sdn-wallet-public-client.js',
    timeout: 1_000,
  });
  assert.deepEqual(
    Reflect.ownKeys(context).filter((name) => !before.includes(name)),
    ['SDNWalletPublicClient'],
  );
  const descriptor = Object.getOwnPropertyDescriptor(context, 'SDNWalletPublicClient');
  assert.deepEqual(
    {
      configurable: descriptor.configurable,
      enumerable: descriptor.enumerable,
      writable: descriptor.writable,
    },
    { configurable: false, enumerable: false, writable: false },
  );
  assert.equal(Object.isFrozen(context.SDNWalletPublicClient), true);
  assert.deepEqual(Object.keys(context.SDNWalletPublicClient), ['create']);
  assert.equal(context.SDNWalletPublicClient.create.length, 1);
  assert.deepEqual(counts, {
    close: 0,
    fetch: 0,
    listeners: 0,
    open: 0,
    storage: 0,
    timers: 0,
  });

  for (const clientId of clientIds) {
    context.__clientId = clientId;
    const methods = vm.runInContext(
      'Object.keys(SDNWalletPublicClient.create({ clientId: __clientId })).sort()',
      context,
      { timeout: 1_000 },
    );
    assert.deepEqual(Array.from(methods), [
      'connect',
      'destroy',
      'disconnect',
      'getSnapshot',
      'openAccount',
      'subscribe',
    ]);
  }

  for (const expression of [
    'SDNWalletPublicClient.create()',
    'SDNWalletPublicClient.create({ clientId: "sdn-landing-web-v1" }, 1)',
    'SDNWalletPublicClient.create(null)',
    'SDNWalletPublicClient.create([])',
    'SDNWalletPublicClient.create(Object.create(null, { clientId: { value: "sdn-landing-web-v1", enumerable: true } }))',
    'SDNWalletPublicClient.create({ clientId: "sdn-landing-web-v1", extra: true })',
    'SDNWalletPublicClient.create(Object.defineProperty({}, "clientId", { get() { throw new Error("secret getter"); }, enumerable: true }))',
    'SDNWalletPublicClient.create(Object.defineProperty({}, "clientId", { value: "sdn-landing-web-v1", enumerable: false }))',
    'SDNWalletPublicClient.create(Object.assign({ clientId: "sdn-landing-web-v1" }, { [Symbol("extra")]: true }))',
  ]) {
    assert.throws(
      () => vm.runInContext(expression, context, { timeout: 1_000 }),
      (error) => error?.code === 'INVALID_REQUEST',
      expression,
    );
  }
  assert.deepEqual(counts, {
    close: 0,
    fetch: 0,
    listeners: 0,
    open: 0,
    storage: 0,
    timers: 0,
  });
}
function assertCallbackHelper(source) {
  const records = [];
  const replacements = [];
  const body = { textContent: '' };
  const window = {
    close() { window.closed = true; },
    closed: false,
    document: { body },
    history: { replaceState: (...values) => replacements.push(values) },
    localStorage: { setItem: (...values) => records.push(values) },
    location: {
      hash: `#code=${'a'.repeat(64)}&state=${'b'.repeat(64)}`,
      pathname: '/wallet-callback.html',
      search: '',
    },
  };
  window.top = window;
  const context = vm.createContext({ Date, Error, JSON, window });
  const before = Reflect.ownKeys(context);
  vm.runInContext(source, context, {
    filename: 'sdn-wallet-callback.js',
    timeout: 1_000,
  });
  assert.deepEqual(Reflect.ownKeys(context), before);
  assert.deepEqual(replacements, [[null, '', '/wallet-callback.html']]);
  assert.equal(records.length, 1);
  assert.equal(records[0][0], `sdn.wallet.callback.v1:${'b'.repeat(64)}`);
  assert.equal(JSON.parse(records[0][1]).schemaVersion, 1);
  assert.equal(window.closed, true);
  assert.equal(body.textContent, '');
}

async function readManifest(root = releaseDirectory) {
  const bytes = await readFile(join(root, 'wallet-assets.v1.json'));
  return { bytes, manifest: JSON.parse(bytes) };
}

async function makeReleaseFixture() {
  const directory = await makeTemporaryDirectory('sdn-wallet-assets-test-');
  const fixtureRelease = join(directory, 'release');
  await mkdir(fixtureRelease, { recursive: true });
  await cp(manifestPath, join(fixtureRelease, 'wallet-assets.v1.json'));
  await cp(join(releaseDirectory, 'static'), join(fixtureRelease, 'static'), {
    recursive: true,
  });
  return { directory, fixtureRelease };
}

async function replaceAsset(fixtureRelease, selector, bytes, { filename } = {}) {
  const { manifest } = await readManifest(fixtureRelease);
  const asset = selector === 'callbackHelper'
    ? manifest.callbackHelper.asset
    : manifest.assets[selector];
  const oldPath = localAssetPath(asset, join(
    fixtureRelease,
    'static/assets/hd-wallet-ui/2.0.28',
  ));
  const sha256 = digest('sha256', bytes);
  const originalName = basename(new URL(asset.url).pathname);
  const match = /^(.+)\.[0-9a-f]{64}\.(css|js)$/u.exec(originalName);
  assert(match, `unexpected fixture asset name: ${originalName}`);
  const nextName = filename ?? `${match[1]}.${sha256}.${match[2]}`;
  const nextPath = join(dirname(oldPath), nextName);
  if (nextPath !== oldPath) await rename(oldPath, nextPath);
  await writeFile(nextPath, bytes);
  const nextAsset = {
    bytes: bytes.byteLength,
    sha256,
    sha384: `sha384-${digest('sha384', bytes, 'base64')}`,
    url: `${staticUrlPrefix}${nextName}`,
  };
  if (selector === 'callbackHelper') manifest.callbackHelper.asset = nextAsset;
  else manifest.assets[selector] = nextAsset;
  await writeFile(join(fixtureRelease, 'wallet-assets.v1.json'), `${jcs(manifest)}\n`);
}

test('wallet fragment has the exact JCS schema and three content-addressed local assets', async () => {
  const { bytes, manifest } = await readManifest();
  assert.equal(bytes.toString('utf8'), `${jcs(manifest)}\n`);
  assert.deepEqual(Object.keys(manifest).sort(), [
    'assets',
    'callbackHelper',
    'registryReleaseSha256',
    'schemaVersion',
    'walletVersion',
  ]);
  assert.deepEqual(Object.keys(manifest.assets).sort(), [
    'publicClientScript',
    'publicClientStyle',
  ]);
  assert.deepEqual(Object.keys(manifest.callbackHelper).sort(), ['asset', 'identity']);
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.walletVersion, '2.0.28');
  assert.match(manifest.registryReleaseSha256, /^[0-9a-f]{64}$/u);
  assert.equal(manifest.callbackHelper.identity, 'sdn.wallet.callback.v1');
  assert.notEqual(
    manifest.callbackHelper.asset.url,
    manifest.assets.publicClientScript.url,
  );
  assert.equal(JSON.stringify(manifest).includes('nav'), false);

  for (const asset of assetValues(manifest)) {
    assert.deepEqual(Object.keys(asset).sort(), ['bytes', 'sha256', 'sha384', 'url']);
    assert.equal(Number.isSafeInteger(asset.bytes) && asset.bytes > 0, true);
    assert.match(asset.sha256, /^[0-9a-f]{64}$/u);
    assert.match(asset.sha384, /^sha384-[A-Za-z0-9+/]{64}$/u);
    assert.equal(Buffer.from(asset.sha384.slice('sha384-'.length), 'base64').byteLength, 48);
    assert.match(asset.url, new RegExp(`^${staticUrlPrefix.replaceAll('.', '\\.')}`));
    assert.match(basename(new URL(asset.url).pathname), new RegExp(`\\.${asset.sha256}\\.(?:css|js)$`, 'u'));
    const localBytes = await readFile(localAssetPath(asset));
    assert.equal(localBytes.byteLength, asset.bytes);
    assert.equal(digest('sha256', localBytes), asset.sha256);
    assert.equal(`sha384-${digest('sha384', localBytes, 'base64')}`, asset.sha384);
    assert.equal(localBytes.includes(Buffer.from('sdn-stack-nav')), false);
  }

  const registry = JSON.parse(await readFile(
    join(repositoryDirectory, 'wallet-ui/relay/config/client-registry.v1.json'),
  ));
  assert.equal(manifest.registryReleaseSha256, registry.registryReleaseSha256);
  assert.deepEqual(await walk(staticVersionDirectory), assetValues(manifest)
    .map((asset) => basename(new URL(asset.url).pathname))
    .sort());
});

test('manifested public bytes are the exact inert Task 11 classic IIFE and external CSS', async () => {
  const { manifest } = await readManifest();
  const publicBytes = await readFile(localAssetPath(manifest.assets.publicClientScript));
  const styleBytes = await readFile(localAssetPath(manifest.assets.publicClientStyle));
  assert.deepEqual(
    publicBytes,
    await readFile(join(repositoryDirectory, 'wallet-ui/dist/browser/sdn-wallet-public-client.js')),
  );
  assert.deepEqual(
    styleBytes,
    await readFile(join(repositoryDirectory, 'wallet-ui/dist/client/style.css')),
  );
  assert.doesNotMatch(publicBytes.toString('utf8'), /\b(?:import|export)\b/u);
  assertPublicClientIife(publicBytes.toString('utf8'));
});

test('callback helper is independently addressed and is the exact self-running Task 11 IIFE', async () => {
  const { manifest } = await readManifest();
  const callbackBytes = await readFile(localAssetPath(manifest.callbackHelper.asset));
  assert.deepEqual(
    callbackBytes,
    await readFile(join(repositoryDirectory, 'wallet-ui/dist/browser/sdn-wallet-callback.js')),
  );
  assert.notDeepEqual(
    callbackBytes,
    await readFile(localAssetPath(manifest.assets.publicClientScript)),
  );
  assert.doesNotMatch(callbackBytes.toString('utf8'), /\b(?:import|export)\b/u);
  assertCallbackHelper(callbackBytes.toString('utf8'));
});

test('wallet asset generation is deterministic and the verifier does not mutate the release', async (t) => {
  const firstRoot = await makeTemporaryDirectory('sdn-wallet-assets-first-');
  const secondRoot = await makeTemporaryDirectory('sdn-wallet-assets-second-');
  t.after(async () => {
    await Promise.all([
      rm(firstRoot, { force: true, recursive: true }),
      rm(secondRoot, { force: true, recursive: true }),
    ]);
  });
  const firstRelease = join(firstRoot, 'release');
  const secondRelease = join(secondRoot, 'release');
  await buildWalletAssets({ repositoryDirectory, releaseDirectory: firstRelease, version: '2.0.28' });
  await buildWalletAssets({ repositoryDirectory, releaseDirectory: secondRelease, version: '2.0.28' });
  const firstFiles = [
    'wallet-assets.v1.json',
    ...(await walk(join(firstRelease, 'static'))).map((path) => `static/${path}`),
  ];
  const secondFiles = [
    'wallet-assets.v1.json',
    ...(await walk(join(secondRelease, 'static'))).map((path) => `static/${path}`),
  ];
  assert.deepEqual(firstFiles, secondFiles);
  for (const path of firstFiles) {
    assert.deepEqual(await readFile(join(firstRelease, path)), await readFile(join(secondRelease, path)));
  }
  const before = new Map();
  for (const path of firstFiles) before.set(path, await readFile(join(firstRelease, path)));
  await verifyWalletAssets({ repositoryDirectory, releaseDirectory: firstRelease, version: '2.0.28' });
  for (const [path, bytes] of before) assert.deepEqual(await readFile(join(firstRelease, path)), bytes);
});

test('wallet asset generation rejects a symlinked static output root', async (t) => {
  const directory = await makeTemporaryDirectory('sdn-wallet-assets-build-link-');
  t.after(() => rm(directory, { force: true, recursive: true }));
  const fixtureRelease = join(directory, 'release');
  const externalStatic = join(directory, 'external-static');
  await mkdir(fixtureRelease, { recursive: true });
  await mkdir(externalStatic, { recursive: true });
  await symlink(externalStatic, join(fixtureRelease, 'static'), 'dir');
  await assert.rejects(
    buildWalletAssets({
      repositoryDirectory,
      releaseDirectory: fixtureRelease,
      version: '2.0.28',
    }),
    /static.*symlink|symlink.*static/iu,
  );
  assert.deepEqual(await readdir(externalStatic), []);
});

test('wallet asset generation rejects a symlinked ancestor before creating output', async (t) => {
  const directory = await makeTemporaryDirectory('sdn-wallet-assets-build-ancestor-link-');
  t.after(() => rm(directory, { force: true, recursive: true }));
  const externalDirectory = join(directory, 'external');
  const stagingDirectory = join(directory, 'staging');
  await mkdir(externalDirectory, { recursive: true });
  await mkdir(stagingDirectory, { recursive: true });
  await symlink(externalDirectory, join(stagingDirectory, 'redirect'), 'dir');
  await assert.rejects(
    buildWalletAssets({
      repositoryDirectory,
      releaseDirectory: join(stagingDirectory, 'redirect/release'),
      version: '2.0.28',
    }),
    /ancestor|path component|symlink/iu,
  );
  assert.deepEqual(await readdir(externalDirectory), []);
});

test('wallet asset verification rejects a symlinked static staging root', async (t) => {
  const fixture = await makeReleaseFixture();
  t.after(() => rm(fixture.directory, { force: true, recursive: true }));
  const staticPath = join(fixture.fixtureRelease, 'static');
  const externalStatic = join(fixture.directory, 'external-static');
  await rename(staticPath, externalStatic);
  await symlink(externalStatic, staticPath, 'dir');
  await assert.rejects(
    verifyWalletAssets({
      repositoryDirectory,
      releaseDirectory: fixture.fixtureRelease,
      version: '2.0.28',
    }),
    /static.*symlink|symlink.*static/iu,
  );
});

test('wallet asset verification rejects a symlinked release root', async (t) => {
  const fixture = await makeReleaseFixture();
  t.after(() => rm(fixture.directory, { force: true, recursive: true }));
  const externalRelease = join(fixture.directory, 'external-release');
  await rename(fixture.fixtureRelease, externalRelease);
  await symlink(externalRelease, fixture.fixtureRelease, 'dir');
  await assert.rejects(
    verifyWalletAssets({
      repositoryDirectory,
      releaseDirectory: fixture.fixtureRelease,
      version: '2.0.28',
    }),
    /release.*symlink|symlink.*release|path component/iu,
  );
});

for (const [name, mutate, pattern] of [
  [
    'extra file',
    async (fixtureRelease) => writeFile(
      join(fixtureRelease, 'static/assets/hd-wallet-ui/2.0.28/extra.js'),
      'extra',
    ),
    /extra|allowlist|inventory/iu,
  ],
  [
    'unhashed filename',
    async (fixtureRelease) => {
      const { manifest } = await readManifest(fixtureRelease);
      const bytes = await readFile(localAssetPath(
        manifest.assets.publicClientStyle,
        join(fixtureRelease, 'static/assets/hd-wallet-ui/2.0.28'),
      ));
      await replaceAsset(fixtureRelease, 'publicClientStyle', bytes, {
        filename: 'sdn-wallet-public-client.css',
      });
    },
    /filename|content-addressed|SHA-256/iu,
  ],
  [
    'wallet-origin bytes',
    async (fixtureRelease) => {
      const originAssets = join(repositoryDirectory, 'wallet-ui/dist/wallet-origin-host/assets');
      const originScript = (await readdir(originAssets)).find((name) => name.endsWith('.js'));
      assert(originScript);
      await replaceAsset(
        fixtureRelease,
        'publicClientScript',
        await readFile(join(originAssets, originScript)),
      );
    },
    /publicClientScript differs from the exact built Task 11 public output/iu,
  ],
  [
    'executable public substitution before evaluation',
    async (fixtureRelease) => replaceAsset(
      fixtureRelease,
      'publicClientScript',
      Buffer.from('(function(){throw new Error("tampered-executed");})();\n'),
    ),
    /publicClientScript differs from the exact built Task 11 public output/iu,
  ],
  [
    'WASM bytes',
    async (fixtureRelease) => {
      const originAssets = join(repositoryDirectory, 'wallet-ui/dist/wallet-origin-host/assets');
      const originWasm = (await readdir(originAssets)).find((name) => name.endsWith('.wasm'));
      assert(originWasm);
      await replaceAsset(
        fixtureRelease,
        'publicClientStyle',
        await readFile(join(originAssets, originWasm)),
      );
    },
    /WASM|public client style|rebuild/iu,
  ],
  [
    'callback export mismatch',
    async (fixtureRelease) => {
      await replaceAsset(
        fixtureRelease,
        'callbackHelper',
        await readFile(join(repositoryDirectory, 'wallet-ui/dist/browser/sdn-wallet-public-client.js')),
      );
    },
    /callbackHelper differs from the exact built Task 11 public output/iu,
  ],
  [
    'version drift',
    async (fixtureRelease) => {
      const { manifest } = await readManifest(fixtureRelease);
      manifest.walletVersion = '999.0.0';
      await writeFile(join(fixtureRelease, 'wallet-assets.v1.json'), `${jcs(manifest)}\n`);
    },
    /version/iu,
  ],
  [
    'sdn-stack-nav content',
    async (fixtureRelease) => {
      const { manifest } = await readManifest(fixtureRelease);
      const stylePath = localAssetPath(
        manifest.assets.publicClientStyle,
        join(fixtureRelease, 'static/assets/hd-wallet-ui/2.0.28'),
      );
      const bytes = Buffer.concat([
        await readFile(stylePath),
        Buffer.from('\n.sdn-stack-nav { display: block; }\n'),
      ]);
      await replaceAsset(fixtureRelease, 'publicClientStyle', bytes);
    },
    /sdn-stack-nav|navigation/iu,
  ],
]) {
  test(`wallet asset verification rejects ${name}`, async (t) => {
    const fixture = await makeReleaseFixture();
    t.after(() => rm(fixture.directory, { force: true, recursive: true }));
    await mutate(fixture.fixtureRelease);
    await assert.rejects(
      verifyWalletAssets({
        repositoryDirectory,
        releaseDirectory: fixture.fixtureRelease,
        version: '2.0.28',
      }),
      pattern,
    );
  });
}
