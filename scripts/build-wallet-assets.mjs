import { createHash } from 'node:crypto';
import {
  lstat,
  mkdir,
  readFile,
  rm,
  writeFile,
} from 'node:fs/promises';
import {
  dirname,
  join,
  parse,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import vm from 'node:vm';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const defaultRepositoryDirectory = resolve(scriptDirectory, '..');
const RELEASE_VERSION = '2.0.26';
const STATIC_URL_PREFIX = `https://static.spacedatanetwork.org/assets/hd-wallet-ui/${RELEASE_VERSION}/`;
const CALLBACK_IDENTITY = 'sdn.wallet.callback.v1';
const SHA256 = /^[0-9a-f]{64}$/u;
const wasmMagic = Buffer.from([0x00, 0x61, 0x73, 0x6d]);

const sourceAssets = Object.freeze({
  callbackHelper: Object.freeze({
    extension: 'js',
    relativePath: 'wallet-ui/dist/browser/sdn-wallet-callback.js',
    stem: 'sdn-wallet-callback',
  }),
  publicClientScript: Object.freeze({
    extension: 'js',
    relativePath: 'wallet-ui/dist/browser/sdn-wallet-public-client.js',
    stem: 'sdn-wallet-public-client',
  }),
  publicClientStyle: Object.freeze({
    extension: 'css',
    relativePath: 'wallet-ui/dist/client/style.css',
    stem: 'sdn-wallet-public-client',
  }),
});

function fail(message) {
  throw new Error(`wallet asset build: ${message}`);
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

function isRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function canonicalizeWalletAssetJson(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    assertUnicodeScalarString(value, 'JCS string');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('JCS numbers must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizeWalletAssetJson).join(',')}]`;
  }
  if (!isRecord(value)) fail('JCS input contains a non-JSON value');
  const fields = [];
  for (const key of Object.keys(value).sort()) {
    assertUnicodeScalarString(key, 'JCS object key');
    if (value[key] === undefined) fail(`JCS field ${key} is undefined`);
    fields.push(`${JSON.stringify(key)}:${canonicalizeWalletAssetJson(value[key])}`);
  }
  return `{${fields.join(',')}}`;
}

function digest(algorithm, bytes, encoding = 'hex') {
  return createHash(algorithm).update(bytes).digest(encoding);
}

function assetRecord(bytes, definition) {
  const sha256 = digest('sha256', bytes);
  const filename = `${definition.stem}.${sha256}.${definition.extension}`;
  return {
    asset: {
      bytes: bytes.byteLength,
      sha256,
      sha384: `sha384-${digest('sha384', bytes, 'base64')}`,
      url: `${STATIC_URL_PREFIX}${filename}`,
    },
    filename,
  };
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

async function verifyRegistry(repositoryDirectory) {
  const path = join(repositoryDirectory, 'wallet-ui/relay/config/client-registry.v1.json');
  const bytes = await readRegularFile(path, 'wallet client registry');
  const { text, value } = parseJson(bytes, 'wallet client registry');
  if (text !== `${canonicalizeWalletAssetJson(value)}\n`) {
    fail('wallet client registry must be RFC 8785 JCS plus one LF');
  }
  if (!isRecord(value) || !SHA256.test(value.registryReleaseSha256 ?? '')) {
    fail('wallet client registry release hash is invalid');
  }
  const { registryReleaseSha256, ...unsignedRegistry } = value;
  const computed = digest('sha256', Buffer.from(canonicalizeWalletAssetJson(unsignedRegistry)));
  if (computed !== registryReleaseSha256) fail('wallet client registry release hash mismatch');
  return registryReleaseSha256;
}

async function verifyVersion(repositoryDirectory, version) {
  if (version !== RELEASE_VERSION) fail(`version must be exactly ${RELEASE_VERSION}`);
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

function assertNoNavigationOrWasm(bytes, label) {
  if (bytes.includes(Buffer.from('sdn-stack-nav'))) fail(`${label} contains sdn-stack-nav`);
  if (bytes.includes(wasmMagic)) fail(`${label} contains WASM bytes`);
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

function verifyPublicClient(bytes) {
  const source = bytes.toString('utf8');
  if (/\b(?:import|export)\b/u.test(source)) fail('public client is not a classic IIFE');
  if (/\.wasm\b/iu.test(source)) fail('public client contains a WASM reference');
  const { context, counts } = publicClientContext();
  const before = Reflect.ownKeys(context);
  try {
    vm.runInContext(source, context, { filename: 'sdn-wallet-public-client.js', timeout: 1_000 });
  } catch (error) {
    fail(`public client IIFE failed validation: ${error.message}`);
  }
  const added = Reflect.ownKeys(context).filter((key) => !before.includes(key));
  if (added.length !== 1 || added[0] !== 'SDNWalletPublicClient') {
    fail('public client IIFE defines an unexpected global');
  }
  const namespace = context.SDNWalletPublicClient;
  const descriptor = Object.getOwnPropertyDescriptor(context, 'SDNWalletPublicClient');
  if (!descriptor || descriptor.configurable || descriptor.enumerable || descriptor.writable
      || !Object.isFrozen(namespace) || Object.keys(namespace).join(',') !== 'create'
      || namespace.create.length !== 1) {
    fail('public client namespace is not the frozen Task 11 contract');
  }
  try {
    context.__clientId = 'sdn-landing-web-v1';
    vm.runInContext('SDNWalletPublicClient.create({ clientId: __clientId })', context, {
      timeout: 1_000,
    });
  } catch (error) {
    fail(`public client factory failed validation: ${error.message}`);
  }
  if (Object.values(counts).some((count) => count !== 0)) {
    fail('public client has load-time or factory side effects');
  }
}

function verifyCallbackHelper(bytes) {
  const source = bytes.toString('utf8');
  if (/\b(?:import|export)\b/u.test(source)) fail('callback helper is not a classic IIFE');
  if (/\.wasm\b/iu.test(source)) fail('callback helper contains a WASM reference');
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
    fail(`callback helper IIFE failed validation: ${error.message}`);
  }
  const expectedKey = `${CALLBACK_IDENTITY}:${'b'.repeat(64)}`;
  if (Reflect.ownKeys(context).length !== before.length
      || records.length !== 1 || records[0][0] !== expectedKey
      || replacements.length !== 1 || replacements[0].join('\0') !== [null, '', '/wallet-callback.html'].join('\0')
      || !window.closed || body.textContent !== '') {
    fail('callback helper does not implement the sdn.wallet.callback.v1 contract');
  }
}

export async function buildWalletAssets({
  repositoryDirectory = defaultRepositoryDirectory,
  releaseDirectory = join(repositoryDirectory, 'release'),
  version,
} = {}) {
  const repositoryRoot = resolve(repositoryDirectory);
  const releaseRoot = resolve(releaseDirectory);
  await verifyVersion(repositoryRoot, version);
  const versionDirectory = join(
    releaseRoot,
    'static',
    'assets',
    'hd-wallet-ui',
    version,
  );
  await assertSafePathComponents(versionDirectory, 'wallet asset output', {
    leafType: 'directory',
    mustExist: false,
  });
  await assertSafePathComponents(
    join(releaseRoot, 'wallet-assets.v1.json'),
    'wallet asset manifest output',
    { leafType: 'file', mustExist: false },
  );
  const registryReleaseSha256 = await verifyRegistry(repositoryRoot);

  const sourceBytes = {};
  for (const [name, definition] of Object.entries(sourceAssets)) {
    const bytes = await readRegularFile(
      join(repositoryRoot, definition.relativePath),
      definition.relativePath,
    );
    if (bytes.byteLength < 1) fail(`${definition.relativePath} is empty`);
    assertNoNavigationOrWasm(bytes, definition.relativePath);
    sourceBytes[name] = bytes;
  }
  if (sourceBytes.publicClientScript.equals(sourceBytes.callbackHelper)) {
    fail('public client and callback helper must be independent assets');
  }
  verifyPublicClient(sourceBytes.publicClientScript);
  verifyCallbackHelper(sourceBytes.callbackHelper);

  const records = Object.fromEntries(Object.entries(sourceAssets).map(([name, definition]) => [
    name,
    assetRecord(sourceBytes[name], definition),
  ]));
  const manifest = {
    assets: {
      publicClientScript: records.publicClientScript.asset,
      publicClientStyle: records.publicClientStyle.asset,
    },
    callbackHelper: {
      asset: records.callbackHelper.asset,
      identity: CALLBACK_IDENTITY,
    },
    registryReleaseSha256,
    schemaVersion: 1,
    walletVersion: version,
  };
  const manifestBytes = Buffer.from(`${canonicalizeWalletAssetJson(manifest)}\n`);
  if (manifestBytes.includes(Buffer.from('sdn-stack-nav'))) fail('manifest contains navigation data');

  await mkdir(releaseRoot, { recursive: true });
  await rm(versionDirectory, { force: true, recursive: true });
  await mkdir(versionDirectory, { recursive: true });
  for (const [name, record] of Object.entries(records)) {
    await writeFile(join(versionDirectory, record.filename), sourceBytes[name], { mode: 0o644 });
  }
  await writeFile(join(releaseRoot, 'wallet-assets.v1.json'), manifestBytes, { mode: 0o644 });
  return Object.freeze({ manifest, manifestBytes, releaseDirectory: releaseRoot });
}

function parseArguments(argv) {
  if (argv.length !== 2 || argv[0] !== '--version' || argv[1].length === 0) {
    fail(`usage: node scripts/build-wallet-assets.mjs --version ${RELEASE_VERSION}`);
  }
  return { version: argv[1] };
}

function isMainModule() {
  return typeof process.argv[1] === 'string'
    && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
}

if (isMainModule()) {
  await buildWalletAssets(parseArguments(process.argv.slice(2)));
}
