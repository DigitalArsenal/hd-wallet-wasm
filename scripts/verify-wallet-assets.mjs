import { createHash } from 'node:crypto';
import {
  lstat,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import {
  basename,
  dirname,
  join,
  parse,
  relative,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import vm from 'node:vm';

import { buildWalletAssets } from './build-wallet-assets.mjs';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const defaultRepositoryDirectory = resolve(scriptDirectory, '..');
const RELEASE_VERSION = '2.0.27';
const STATIC_ORIGIN = 'https://static.spacedatanetwork.org';
const STATIC_PATH_PREFIX = `/assets/hd-wallet-ui/${RELEASE_VERSION}/`;
const STATIC_URL_PREFIX = `${STATIC_ORIGIN}${STATIC_PATH_PREFIX}`;
const CALLBACK_IDENTITY = 'sdn.wallet.callback.v1';
const SHA256 = /^[0-9a-f]{64}$/u;
const SHA384 = /^sha384-([A-Za-z0-9+/]{64})$/u;
const wasmMagic = Buffer.from([0x00, 0x61, 0x73, 0x6d]);
const assetDefinitions = Object.freeze({
  callbackHelper: Object.freeze({
    extension: 'js',
    relativeSource: 'wallet-ui/dist/browser/sdn-wallet-callback.js',
    stem: 'sdn-wallet-callback',
  }),
  publicClientScript: Object.freeze({
    extension: 'js',
    relativeSource: 'wallet-ui/dist/browser/sdn-wallet-public-client.js',
    stem: 'sdn-wallet-public-client',
  }),
  publicClientStyle: Object.freeze({
    extension: 'css',
    relativeSource: 'wallet-ui/dist/client/style.css',
    stem: 'sdn-wallet-public-client',
  }),
});

function fail(message) {
  throw new Error(`wallet asset verification: ${message}`);
}

function isRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected, label) {
  if (!isRecord(value)) fail(`${label} must be an object`);
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (actual.length !== sortedExpected.length
      || actual.some((key, index) => key !== sortedExpected[index])) {
    fail(`${label} has missing or unknown fields`);
  }
}

function assertUnicodeScalarString(value, label) {
  for (let index = 0; index < value.length; index += 1) {
    const unit = value.charCodeAt(index);
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) fail(`${label} contains an unpaired surrogate`);
      index += 1;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) {
      fail(`${label} contains an unpaired surrogate`);
    }
  }
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    assertUnicodeScalarString(value, 'JCS string');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('JCS number is not finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!isRecord(value)) fail('JCS input contains a non-JSON value');
  return `{${Object.keys(value).sort().map((key) => {
    assertUnicodeScalarString(key, 'JCS object key');
    if (value[key] === undefined) fail(`JCS field ${key} is undefined`);
    return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
  }).join(',')}}`;
}

function digest(algorithm, bytes, encoding = 'hex') {
  return createHash(algorithm).update(bytes).digest(encoding);
}

async function assertSafePathComponents(path, label, {
  leafType,
  mustExist,
}) {
  const absolutePath = resolve(path);
  const { root } = parse(absolutePath);
  const names = absolutePath.slice(root.length).split(sep).filter(Boolean);
  let current = root;
  let missingAncestor = false;
  for (let index = -1; index < names.length; index += 1) {
    if (index >= 0) current = join(current, names[index]);
    const isLeaf = index === names.length - 1;
    let status;
    try {
      status = await lstat(current);
    } catch (error) {
      if (error.code !== 'ENOENT') {
        fail(`${label} path component cannot be inspected: ${error.code ?? error.message}`);
      }
      if (mustExist && isLeaf) fail(`${label} is unavailable`);
      missingAncestor = true;
      continue;
    }
    if (missingAncestor) fail(`${label} exists below a missing path component`);
    if (status.isSymbolicLink()) fail(`${label} path component is a symlink: ${current}`);
    if (!isLeaf || leafType === 'directory') {
      if (!status.isDirectory()) fail(`${label} path component is not a directory: ${current}`);
    } else if (leafType === 'file' && !status.isFile()) {
      fail(`${label} must be a regular file`);
    }
  }
}

async function readRegularFile(path, label) {
  await assertSafePathComponents(path, label, { leafType: 'file', mustExist: true });
  return readFile(path);
}

function parseJson(bytes, label) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    fail(`${label} must be valid UTF-8`);
  }
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail(`${label} must be valid JSON`);
  }
  return { text, value };
}

async function verifyVersionFiles(repositoryDirectory, version) {
  if (version !== RELEASE_VERSION) fail(`requested version must be exactly ${RELEASE_VERSION}`);
  for (const relativePath of [
    'package.json',
    'wallet-ui/package.json',
    'wallet-ui/relay/package.json',
    'wasm/package.json',
  ]) {
    const bytes = await readRegularFile(join(repositoryDirectory, relativePath), relativePath);
    const { value } = parseJson(bytes, relativePath);
    if (!isRecord(value) || value.version !== version) {
      fail(`${relativePath} version differs from ${version}`);
    }
  }
}

async function verifiedRegistryHash(repositoryDirectory) {
  const bytes = await readRegularFile(
    join(repositoryDirectory, 'wallet-ui/relay/config/client-registry.v1.json'),
    'wallet client registry',
  );
  const { text, value } = parseJson(bytes, 'wallet client registry');
  if (text !== `${canonicalJson(value)}\n`) {
    fail('wallet client registry is not RFC 8785 JCS plus one LF');
  }
  if (!isRecord(value) || !SHA256.test(value.registryReleaseSha256 ?? '')) {
    fail('wallet client registry release hash is invalid');
  }
  const { registryReleaseSha256, ...unsignedRegistry } = value;
  if (digest('sha256', Buffer.from(canonicalJson(unsignedRegistry))) !== registryReleaseSha256) {
    fail('wallet client registry release hash mismatch');
  }
  return registryReleaseSha256;
}

function publicClientContext() {
  const counts = { fetch: 0, listeners: 0, open: 0, storage: 0, timers: 0 };
  const window = {
    addEventListener() { counts.listeners += 1; },
    open() { counts.open += 1; return null; },
    removeEventListener() {},
  };
  Object.defineProperty(window, 'localStorage', {
    configurable: false,
    get() {
      counts.storage += 1;
      throw new Error('storage must remain inert');
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

function verifyPublicClientIife(bytes) {
  if (bytes.includes(wasmMagic)) fail('public client contains WASM bytes');
  const source = bytes.toString('utf8');
  if (source.includes('sdn-stack-nav')) fail('public client contains sdn-stack-nav navigation bytes');
  if (/\.wasm\b/iu.test(source)) fail('public client contains a WASM reference');
  if (/\b(?:import|export)\b/u.test(source)) fail('public client is not a classic IIFE');
  const { context, counts } = publicClientContext();
  const before = Reflect.ownKeys(context);
  try {
    vm.runInContext(source, context, { filename: 'sdn-wallet-public-client.js', timeout: 1_000 });
  } catch (error) {
    fail(`public client IIFE failed: ${error.message}`);
  }
  const added = Reflect.ownKeys(context).filter((key) => !before.includes(key));
  const descriptor = Object.getOwnPropertyDescriptor(context, 'SDNWalletPublicClient');
  const namespace = context.SDNWalletPublicClient;
  if (added.length !== 1 || added[0] !== 'SDNWalletPublicClient'
      || !descriptor || descriptor.configurable || descriptor.enumerable || descriptor.writable
      || !Object.isFrozen(namespace) || Object.keys(namespace).join(',') !== 'create'
      || namespace.create.length !== 1) {
    fail('public client does not expose the frozen Task 11 namespace');
  }
  try {
    context.__clientId = 'sdn-landing-web-v1';
    const methods = vm.runInContext(
      'Object.keys(SDNWalletPublicClient.create({ clientId: __clientId })).sort()',
      context,
      { timeout: 1_000 },
    );
    if (Array.from(methods).join(',')
        !== 'connect,destroy,disconnect,getSnapshot,openAccount,subscribe') {
      fail('public client factory surface differs from Task 11');
    }
    let rejected = false;
    try {
      vm.runInContext(
        'SDNWalletPublicClient.create({ clientId: __clientId, extra: true })',
        context,
        { timeout: 1_000 },
      );
    } catch (error) {
      rejected = error?.code === 'INVALID_REQUEST';
    }
    if (!rejected) fail('public client factory accepts non-exact options');
  } catch (error) {
    fail(`public client factory failed: ${error.message}`);
  }
  if (Object.values(counts).some((count) => count !== 0)) {
    fail('public client performs work at load or factory time');
  }
}

function verifyCallbackIife(bytes) {
  if (bytes.includes(wasmMagic)) fail('callback helper contains WASM bytes');
  const source = bytes.toString('utf8');
  if (source.includes('sdn-stack-nav')) fail('callback helper contains sdn-stack-nav navigation bytes');
  if (/\.wasm\b/iu.test(source)) fail('callback helper contains a WASM reference');
  if (/\b(?:import|export)\b/u.test(source)) fail('callback helper is not a classic IIFE');
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
  try {
    vm.runInContext(source, context, { filename: 'sdn-wallet-callback.js', timeout: 1_000 });
  } catch (error) {
    fail(`callback helper IIFE failed: ${error.message}`);
  }
  if (Reflect.ownKeys(context).length !== before.length
      || records.length !== 1
      || records[0][0] !== `${CALLBACK_IDENTITY}:${'b'.repeat(64)}`
      || replacements.length !== 1
      || replacements[0][0] !== null
      || replacements[0][1] !== ''
      || replacements[0][2] !== '/wallet-callback.html'
      || !window.closed || body.textContent !== '') {
    fail('callback helper identity or self-running export does not match sdn.wallet.callback.v1');
  }
}

function assetFromManifest(manifest, name) {
  return name === 'callbackHelper'
    ? manifest.callbackHelper.asset
    : manifest.assets[name];
}

function validateAssetRecord(asset, definition, version, label) {
  exactKeys(asset, ['bytes', 'sha256', 'sha384', 'url'], label);
  if (!Number.isSafeInteger(asset.bytes) || asset.bytes < 1) fail(`${label} byte count is invalid`);
  if (!SHA256.test(asset.sha256)) fail(`${label} SHA-256 is invalid`);
  const integrity = SHA384.exec(asset.sha384);
  if (!integrity || Buffer.from(integrity[1], 'base64').byteLength !== 48) {
    fail(`${label} SHA-384 integrity is invalid`);
  }
  let url;
  try {
    url = new URL(asset.url);
  } catch {
    fail(`${label} URL is invalid`);
  }
  const expectedFilename = `${definition.stem}.${asset.sha256}.${definition.extension}`;
  if (url.origin !== STATIC_ORIGIN || url.username || url.password || url.port
      || url.search || url.hash || url.pathname !== `${STATIC_PATH_PREFIX}${expectedFilename}`
      || url.href !== `${STATIC_URL_PREFIX}${expectedFilename}`) {
    fail(`${label} filename is not the exact content-addressed ${version} URL`);
  }
  return expectedFilename;
}

async function strictStaticInventory(staticDirectory, expectedFiles, version) {
  let rootStatus;
  try {
    rootStatus = await lstat(staticDirectory);
  } catch (error) {
    fail(`static asset directory is unavailable: ${error.code ?? error.message}`);
  }
  if (rootStatus.isSymbolicLink()) fail('static asset directory must not be a symlink');
  if (!rootStatus.isDirectory()) fail('static asset directory must be a directory');
  const files = [];
  const directories = [];
  async function walk(directory, prefix = '') {
    let entries;
    try {
      entries = await readdir(directory, { withFileTypes: true });
    } catch (error) {
      fail(`static asset directory is unavailable: ${error.code ?? error.message}`);
    }
    for (const entry of entries) {
      const path = join(directory, entry.name);
      const relativePath = prefix ? `${prefix}/${entry.name}` : entry.name;
      if (entry.isSymbolicLink()) fail(`static inventory contains a symlink: ${relativePath}`);
      if (entry.isDirectory()) {
        directories.push(relativePath);
        await walk(path, relativePath);
      } else if (entry.isFile()) {
        files.push(relativePath);
      } else {
        fail(`static inventory contains a non-regular entry: ${relativePath}`);
      }
    }
  }
  await walk(staticDirectory);
  const expectedDirectories = [
    'assets',
    'assets/hd-wallet-ui',
    `assets/hd-wallet-ui/${version}`,
  ];
  const sortedExpectedFiles = [...expectedFiles].sort();
  if (directories.sort().join('\n') !== expectedDirectories.sort().join('\n')
      || files.sort().join('\n') !== sortedExpectedFiles.join('\n')) {
    fail('static asset inventory contains an extra or missing file/directory outside the allowlist');
  }
}

async function verifyManifestAndAssets({ repositoryDirectory, releaseDirectory, version }) {
  await verifyVersionFiles(repositoryDirectory, version);
  const manifestBytes = await readRegularFile(
    join(releaseDirectory, 'wallet-assets.v1.json'),
    'wallet asset manifest',
  );
  const { text, value: manifest } = parseJson(manifestBytes, 'wallet asset manifest');
  if (text !== `${canonicalJson(manifest)}\n`) {
    fail('wallet asset manifest must be RFC 8785 JCS plus one LF');
  }
  exactKeys(manifest, [
    'assets',
    'callbackHelper',
    'registryReleaseSha256',
    'schemaVersion',
    'walletVersion',
  ], 'wallet asset manifest');
  exactKeys(manifest.assets, ['publicClientScript', 'publicClientStyle'], 'manifest assets');
  exactKeys(manifest.callbackHelper, ['asset', 'identity'], 'callback helper');
  if (manifest.schemaVersion !== 1) fail('manifest schemaVersion must be 1');
  if (manifest.walletVersion !== version) fail('manifest wallet version drifted');
  if (manifest.callbackHelper.identity !== CALLBACK_IDENTITY) fail('callback helper identity drifted');
  if (JSON.stringify(manifest).includes('nav')) fail('manifest contains navigation data');
  const registryReleaseSha256 = await verifiedRegistryHash(repositoryDirectory);
  if (manifest.registryReleaseSha256 !== registryReleaseSha256) {
    fail('manifest registry release hash differs from the verified registry');
  }

  const versionDirectory = join(
    releaseDirectory,
    'static/assets/hd-wallet-ui',
    version,
  );
  const filenames = {};
  const bytesByName = {};
  for (const [name, definition] of Object.entries(assetDefinitions)) {
    const asset = assetFromManifest(manifest, name);
    const filename = validateAssetRecord(asset, definition, version, name);
    filenames[name] = filename;
    const bytes = await readRegularFile(join(versionDirectory, filename), `${name} asset`);
    bytesByName[name] = bytes;
    if (bytes.byteLength !== asset.bytes
        || digest('sha256', bytes) !== asset.sha256
        || `sha384-${digest('sha384', bytes, 'base64')}` !== asset.sha384) {
      fail(`${name} asset digest or byte count mismatch`);
    }
    if (bytes.includes(Buffer.from('sdn-stack-nav'))) {
      fail(`${name} contains forbidden sdn-stack-nav navigation bytes`);
    }
    if (bytes.includes(wasmMagic)) fail(`${name} contains WASM bytes`);
    const builtBytes = await readRegularFile(
      join(repositoryDirectory, definition.relativeSource),
      definition.relativeSource,
    );
    if (!bytes.equals(builtBytes)) {
      fail(`${name} differs from the exact built Task 11 public output`);
    }
  }
  if (new Set(Object.values(filenames)).size !== 3) fail('wallet assets are not independently addressed');
  if (bytesByName.publicClientScript.equals(bytesByName.callbackHelper)) {
    fail('callback helper is not independent from the public client');
  }
  verifyPublicClientIife(bytesByName.publicClientScript);
  verifyCallbackIife(bytesByName.callbackHelper);
  let styleText;
  try {
    styleText = new TextDecoder('utf-8', { fatal: true }).decode(bytesByName.publicClientStyle);
  } catch {
    fail('public client style is not valid UTF-8');
  }
  if (styleText.includes('sdn-stack-nav')) fail('public client style contains navigation data');
  if (/\.wasm\b/iu.test(styleText)) fail('public client style contains a WASM reference');

  const expectedFiles = Object.values(filenames).map((filename) => (
    `assets/hd-wallet-ui/${version}/${filename}`
  ));
  await strictStaticInventory(join(releaseDirectory, 'static'), expectedFiles, version);
  return { manifest, manifestBytes, filenames };
}

async function compareRegeneration(actualRelease, rebuiltRelease) {
  const rebuiltManifest = await readRegularFile(
    join(rebuiltRelease, 'wallet-assets.v1.json'),
    'rebuilt wallet asset manifest',
  );
  const actualManifest = await readRegularFile(
    join(actualRelease, 'wallet-assets.v1.json'),
    'wallet asset manifest',
  );
  if (!actualManifest.equals(rebuiltManifest)) fail('manifest differs from a deterministic rebuild');

  async function files(directory, base = directory) {
    const output = [];
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) fail('static rebuild comparison encountered a symlink');
      if (entry.isDirectory()) output.push(...await files(path, base));
      else if (entry.isFile()) output.push(relative(base, path).replaceAll('\\', '/'));
      else fail('static rebuild comparison encountered a non-file');
    }
    return output.sort();
  }
  const actualFiles = await files(join(actualRelease, 'static'));
  const rebuiltFiles = await files(join(rebuiltRelease, 'static'));
  if (actualFiles.join('\n') !== rebuiltFiles.join('\n')) {
    fail('static inventory differs from a deterministic rebuild');
  }
  for (const path of actualFiles) {
    const [actual, rebuilt] = await Promise.all([
      readRegularFile(join(actualRelease, 'static', path), `wallet static asset ${path}`),
      readRegularFile(join(rebuiltRelease, 'static', path), `rebuilt wallet static asset ${path}`),
    ]);
    if (!actual.equals(rebuilt)) fail(`${path} differs from a deterministic rebuild`);
  }
}

export async function verifyWalletAssets({
  repositoryDirectory = defaultRepositoryDirectory,
  releaseDirectory = join(repositoryDirectory, 'release'),
  version,
} = {}) {
  const repositoryRoot = resolve(repositoryDirectory);
  const releaseRoot = resolve(releaseDirectory);
  const verified = await verifyManifestAndAssets({
    repositoryDirectory: repositoryRoot,
    releaseDirectory: releaseRoot,
    version,
  });
  const canonicalTemporaryRoot = await realpath(tmpdir());
  const temporaryDirectory = await mkdtemp(join(
    canonicalTemporaryRoot,
    'sdn-wallet-assets-verify-',
  ));
  try {
    const rebuiltRelease = join(temporaryDirectory, 'release');
    await buildWalletAssets({
      repositoryDirectory: repositoryRoot,
      releaseDirectory: rebuiltRelease,
      version,
    });
    await compareRegeneration(releaseRoot, rebuiltRelease);
  } finally {
    await rm(temporaryDirectory, { force: true, recursive: true });
  }
  return Object.freeze(verified);
}

function parseArguments(argv) {
  if (argv.length !== 2 || argv[0] !== '--version' || argv[1].length === 0) {
    fail(`usage: node scripts/verify-wallet-assets.mjs --version ${RELEASE_VERSION}`);
  }
  return { version: argv[1] };
}

function isMainModule() {
  return typeof process.argv[1] === 'string'
    && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
}

if (isMainModule()) {
  await verifyWalletAssets(parseArguments(process.argv.slice(2)));
}
