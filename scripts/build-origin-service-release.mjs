import { createHash } from 'node:crypto';
import { constants as filesystemConstants } from 'node:fs';
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  readFile,
  readdir,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve, sep } from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { gzipSync } from 'node:zlib';

import {
  acquireBetterSqlite3Prebuild,
  selectBetterSqlite3Prebuild,
} from './acquire-better-sqlite3-prebuild.mjs';

export const ORIGIN_SERVICE_VERSION = '2.0.22';
export const ARCHIVE_BASENAME = 'sdn-wallet-origin-2.0.22-node24-linux-x64.tar.gz';
export const ADDON_PATH = 'node_modules/better-sqlite3/build/Release/better_sqlite3.node';
export const REQUIRED_RUNTIME = Object.freeze({
  architecture: 'x64',
  modulesAbi: '137',
  napiVersion: '10',
  nodeVersion: '24.18.0',
  platform: 'linux',
});

const BETTER_SQLITE_FILES = [
  'LICENSE',
  'build/Release/better_sqlite3.node',
  'lib/database.js',
  'lib/index.js',
  'lib/methods/aggregate.js',
  'lib/methods/backup.js',
  'lib/methods/function.js',
  'lib/methods/inspect.js',
  'lib/methods/pragma.js',
  'lib/methods/serialize.js',
  'lib/methods/table.js',
  'lib/methods/transaction.js',
  'lib/methods/wrappers.js',
  'lib/sqlite-error.js',
  'lib/util.js',
  'package.json',
].map((path) => `node_modules/better-sqlite3/${path}`);

export const RUNTIME_DEPENDENCY_FILES = Object.freeze([
  ...BETTER_SQLITE_FILES,
  'node_modules/bindings/LICENSE.md',
  'node_modules/bindings/bindings.js',
  'node_modules/bindings/package.json',
  'node_modules/file-uri-to-path/LICENSE',
  'node_modules/file-uri-to-path/index.js',
  'node_modules/file-uri-to-path/package.json',
].sort());

const FIXED_PAYLOAD_FILES = Object.freeze([
  'LICENSE',
  'package.json',
  'registry/client-registry.v1.json',
  'service/server.mjs',
  'wallet-origin/index.html',
  ...RUNTIME_DEPENDENCY_FILES,
].sort());
const ASSET_NAME = /^wallet-origin\.([0-9a-f]{64})\.(css|js|wasm)$/u;
const SAFE_VERSION = /^\d+\.\d+$/u;
const MAX_FILE_BYTES = 32 * 1024 * 1024;
const MAX_PAYLOAD_BYTES = 64 * 1024 * 1024;
const NORMALIZED_MODE = 0o644;
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_DIRECTORY = resolve(SCRIPT_DIRECTORY, '..');

const RUNTIME_PACKAGE_METADATA = Object.freeze({
  'node_modules/better-sqlite3/package.json': Object.freeze({
    dependencies: Object.freeze({ bindings: '1.5.0' }),
    license: 'MIT',
    main: 'lib/index.js',
    name: 'better-sqlite3',
    version: '12.2.0',
  }),
  'node_modules/bindings/package.json': Object.freeze({
    dependencies: Object.freeze({ 'file-uri-to-path': '1.0.0' }),
    license: 'MIT',
    main: 'bindings.js',
    name: 'bindings',
    version: '1.5.0',
  }),
  'node_modules/file-uri-to-path/package.json': Object.freeze({
    license: 'MIT',
    main: 'index.js',
    name: 'file-uri-to-path',
    version: '1.0.0',
  }),
});

function fail(message) {
  throw new Error(message);
}

function assertValidUnicode(value, label) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) fail(`${label} contains invalid Unicode`);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail(`${label} contains invalid Unicode`);
    }
  }
}

export function canonicalize(value) {
  if (value === null || typeof value === 'boolean') return JSON.stringify(value);
  if (typeof value === 'string') {
    assertValidUnicode(value, 'JCS string');
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('JCS number must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map((item) => canonicalize(item)).join(',')}]`;
  if (typeof value !== 'object' || value === undefined) fail('value cannot be encoded as JCS');
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) fail('JCS objects must be plain');
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => {
    assertValidUnicode(key, 'JCS key');
    if (value[key] === undefined) fail('JCS object contains undefined');
    return `${JSON.stringify(key)}:${canonicalize(value[key])}`;
  }).join(',')}}`;
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha384(bytes) {
  return `sha384-${createHash('sha384').update(bytes).digest('base64')}`;
}

function parseJcs(bytes, label) {
  let value;
  const text = bytes.toString('utf8');
  try {
    value = JSON.parse(text);
  } catch {
    fail(`${label} is not valid JSON`);
  }
  const canonicalBytes = Buffer.from(`${canonicalize(value)}\n`);
  if (!Buffer.from(bytes).equals(canonicalBytes)) fail(`${label} must be JCS plus one LF`);
  return value;
}

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype;
}

function exactObject(value, keys, label) {
  if (!isPlainObject(value)
      || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...keys].sort())) {
    fail(`${label} has an invalid shape`);
  }
  return value;
}

function expectedServicePackage(version) {
  return {
    dependencies: { 'better-sqlite3': '12.2.0' },
    engines: { node: '24.18.0' },
    name: '@sdn/wallet-origin-service',
    private: true,
    type: 'module',
    version,
  };
}

function validateRuntime(runtime) {
  exactObject(runtime, [
    'architecture', 'minimumGlibc', 'modulesAbi', 'napiVersion', 'nodeVersion', 'platform',
  ], 'origin-service runtime');
  for (const [key, expected] of Object.entries(REQUIRED_RUNTIME)) {
    if (runtime[key] !== expected) fail(`origin-service runtime ${key} must be ${expected}`);
  }
  if (typeof runtime.minimumGlibc !== 'string' || !SAFE_VERSION.test(runtime.minimumGlibc)) {
    fail('origin-service runtime minimumGlibc is invalid');
  }
  return { ...runtime };
}

function validateRelativePath(path) {
  if (typeof path !== 'string' || path.length === 0 || path.length > 240
      || path.startsWith('/') || path.includes('\\') || path.includes('\0')) {
    fail(`unsafe origin-service payload path: ${path}`);
  }
  const parts = path.split('/');
  if (parts.some((part) => part.length === 0 || part === '.' || part === '..')) {
    fail(`unsafe origin-service payload path: ${path}`);
  }
}

async function collectRegularFiles(root) {
  const rootStatus = await lstat(root).catch(() => null);
  if (!rootStatus?.isDirectory() || rootStatus.isSymbolicLink()) {
    fail('origin-service source must be a real directory');
  }
  const files = [];
  async function visit(directory, prefix) {
    const entries = await readdir(directory, { withFileTypes: true });
    entries.sort((left, right) => (left.name < right.name ? -1 : left.name > right.name ? 1 : 0));
    for (const entry of entries) {
      const path = prefix ? `${prefix}/${entry.name}` : entry.name;
      validateRelativePath(path);
      const absolute = resolve(directory, entry.name);
      const status = await lstat(absolute);
      if (status.isSymbolicLink()) fail(`origin-service payload contains a symlink: ${path}`);
      if (status.isDirectory()) {
        await visit(absolute, path);
      } else if (status.isFile()) {
        if (status.size <= 0 || status.size > MAX_FILE_BYTES) {
          fail(`origin-service payload file size is invalid: ${path}`);
        }
        files.push({ absolute, path, size: status.size });
      } else {
        fail(`origin-service payload must contain only regular files: ${path}`);
      }
    }
  }
  await visit(root, '');
  return files.sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
}

function validateInventory(paths) {
  const fixed = new Set(FIXED_PAYLOAD_FILES);
  const assets = { css: [], js: [], wasm: [] };
  for (const path of paths) {
    if (fixed.has(path)) continue;
    if (path.startsWith('wallet-origin/assets/')) {
      const name = path.slice('wallet-origin/assets/'.length);
      const match = ASSET_NAME.exec(name);
      if (match) {
        assets[match[2]].push(path);
        continue;
      }
    }
    fail(`unexpected origin-service payload path: ${path}`);
  }
  for (const path of FIXED_PAYLOAD_FILES) {
    if (!paths.includes(path)) fail(`origin-service payload inventory is missing ${path}`);
  }
  for (const extension of ['css', 'js', 'wasm']) {
    if (assets[extension].length !== 1) {
      fail(`origin-service payload inventory requires exactly one hashed ${extension} asset`);
    }
  }
  const expectedCount = FIXED_PAYLOAD_FILES.length + 3;
  if (paths.length !== expectedCount) fail('origin-service payload inventory has extra files');
  return assets;
}

function assertSameJson(actual, expected, label) {
  if (canonicalize(actual) !== canonicalize(expected)) fail(`${label} is invalid`);
}

function validateRuntimePackageMetadata(fileMap) {
  for (const [path, expected] of Object.entries(RUNTIME_PACKAGE_METADATA)) {
    const value = parseJcs(fileMap.get(path), path);
    assertSameJson(value, expected, `${path} runtime package metadata`);
  }
}

function parseHtmlTagAttributes(tag, tagName, label) {
  const prefix = `<${tagName}`;
  if (!tag.startsWith(prefix) || !tag.endsWith('>')) fail(`${label} tag is invalid`);
  const source = tag.slice(prefix.length, -1);
  const attributes = {};
  let offset = 0;
  while (offset < source.length) {
    if (/^\s*$/u.test(source.slice(offset))) break;
    const match = /^\s+([a-z][a-z0-9-]*)="([^"]*)"/u.exec(source.slice(offset));
    if (!match || Object.hasOwn(attributes, match[1])) fail(`${label} attributes are invalid`);
    attributes[match[1]] = match[2];
    offset += match[0].length;
  }
  if (!/^\s*$/u.test(source.slice(offset))) fail(`${label} attributes are invalid`);
  return attributes;
}

function assertExactAttributes(actual, expected, label) {
  if (canonicalize(actual) !== canonicalize(expected)) fail(`${label} attributes are invalid`);
}

function javascriptResourceAnalysis(source) {
  const isIdentifierCharacter = (character) => /[0-9A-Z_$]/iu.test(character ?? '');
  const skipLiteral = (start) => {
    const quote = source[start];
    let cursor = start + 1;
    while (cursor < source.length) {
      if (source[cursor] === '\\') {
        cursor += 2;
      } else if (source[cursor] === quote) {
        return cursor + 1;
      } else {
        cursor += 1;
      }
    }
    return source.length;
  };
  const skipTrivia = (start) => {
    let cursor = start;
    while (cursor < source.length) {
      if (/\s/u.test(source[cursor])) {
        cursor += 1;
      } else if (source.startsWith('//', cursor)) {
        const newline = source.indexOf('\n', cursor + 2);
        cursor = newline === -1 ? source.length : newline + 1;
      } else if (source.startsWith('/*', cursor)) {
        const end = source.indexOf('*/', cursor + 2);
        cursor = end === -1 ? source.length : end + 2;
      } else {
        break;
      }
    }
    return cursor;
  };
  const consumeWord = (start, word) => {
    if (!source.startsWith(word, start)
        || isIdentifierCharacter(source[start - 1])
        || isIdentifierCharacter(source[start + word.length])) return null;
    return start + word.length;
  };
  const consumeCharacter = (start, character) => {
    const cursor = skipTrivia(start);
    return source[cursor] === character ? cursor + 1 : null;
  };
  const consumeString = (start) => {
    const cursor = skipTrivia(start);
    const quote = source[cursor];
    if (quote !== '"' && quote !== "'") return null;
    let end = cursor + 1;
    while (end < source.length && source[end] !== quote) {
      if (source[end] === '\\' || source[end] === '\n' || source[end] === '\r') return null;
      end += 1;
    }
    if (source[end] !== quote) return null;
    return { next: end + 1, value: source.slice(cursor + 1, end) };
  };
  const references = [];
  let dynamicImport = false;
  let staticExport = false;
  let staticImport = false;
  let cursor = 0;
  while (cursor < source.length) {
    if (source.startsWith('//', cursor) || source.startsWith('/*', cursor)
        || /\s/u.test(source[cursor])) {
      cursor = skipTrivia(cursor);
      continue;
    }
    if (source[cursor] === '"' || source[cursor] === "'" || source[cursor] === '`') {
      cursor = skipLiteral(cursor);
      continue;
    }
    const afterImport = consumeWord(cursor, 'import');
    if (afterImport !== null) {
      const nextToken = source[skipTrivia(afterImport)];
      if (nextToken === '(') dynamicImport = true;
      else if (nextToken !== '.') staticImport = true;
    }
    if (consumeWord(cursor, 'export') !== null) staticExport = true;
    let next = consumeWord(cursor, 'new');
    if (next !== null) {
      next = skipTrivia(next);
      next = consumeWord(next, 'URL');
      next = next === null ? null : consumeCharacter(next, '(');
      const string = next === null ? null : consumeString(next);
      next = string === null ? null : consumeCharacter(string.next, ',');
      next = next === null ? null : skipTrivia(next);
      next = next === null ? null : consumeWord(next, 'import');
      next = next === null ? null : consumeCharacter(next, '.');
      next = next === null ? null : skipTrivia(next);
      next = next === null ? null : consumeWord(next, 'meta');
      next = next === null ? null : consumeCharacter(next, '.');
      next = next === null ? null : skipTrivia(next);
      next = next === null ? null : consumeWord(next, 'url');
      next = next === null ? null : consumeCharacter(next, ')');
      if (next !== null) references.push(string.value);
    }
    cursor += 1;
  }
  return {
    dynamicImport,
    references,
    staticExport,
    staticImport,
  };
}

export function validateWalletOriginAssetClosure(fileMap, assets) {
  const records = {};
  for (const extension of ['css', 'js', 'wasm']) {
    const path = assets[extension][0];
    const bytes = fileMap.get(path);
    const name = path.slice('wallet-origin/assets/'.length);
    const match = ASSET_NAME.exec(name);
    if (!match || match[1] !== sha256(bytes)) fail(`hashed ${extension} asset name is invalid`);
    records[extension] = { bytes, name, path };
  }
  if (records.wasm.bytes.length < 8
      || !records.wasm.bytes.subarray(0, 8).equals(Buffer.from([0, 97, 115, 109, 1, 0, 0, 0]))) {
    fail('wallet-origin WASM asset is invalid');
  }
  const html = fileMap.get('wallet-origin/index.html').toString('utf8');
  const linkTokens = html.match(/<link(?=[\s>])/giu) ?? [];
  const linkTags = html.match(/<link(?=[\s>])[^<>]*>/giu) ?? [];
  const scriptTokens = html.match(/<script(?=[\s>])/giu) ?? [];
  const scriptTags = html.match(/<script(?=[\s>])[^<>]*>/giu) ?? [];
  const scriptClosings = html.match(/<\/script\s*>/giu) ?? [];
  const emptyScripts = html.match(/<script(?=[\s>])[^<>]*>\s*<\/script\s*>/giu) ?? [];
  const resourceAttributes = html.match(/\b(?:href|src)\s*=/giu) ?? [];
  if (/<!--|-->/u.test(html) || linkTokens.length !== 1 || linkTags.length !== 1
      || scriptTokens.length !== 1 || scriptTags.length !== 1 || scriptClosings.length !== 1
      || emptyScripts.length !== 1 || resourceAttributes.length !== 2) {
    fail('wallet-origin HTML asset closure is invalid');
  }
  const linkAttributes = parseHtmlTagAttributes(linkTags[0], 'link', 'wallet-origin link');
  const scriptAttributes = parseHtmlTagAttributes(scriptTags[0], 'script', 'wallet-origin script');
  assertExactAttributes(linkAttributes, {
    crossorigin: 'anonymous',
    href: `/assets/${records.css.name}`,
    integrity: sha384(records.css.bytes),
    rel: 'stylesheet',
  }, 'wallet-origin link');
  assertExactAttributes(scriptAttributes, {
    crossorigin: 'anonymous',
    integrity: sha384(records.js.bytes),
    src: `/assets/${records.js.name}`,
    type: 'module',
  }, 'wallet-origin script');

  const stylesheet = records.css.bytes.toString('utf8');
  if (/@import|url\s*\(|sourceMappingURL/iu.test(stylesheet)) {
    fail('wallet-origin CSS asset closure is invalid');
  }
  const javascript = records.js.bytes.toString('utf8');
  const expectedWasmReference = `./${records.wasm.name}`;
  const rawWasmReferenceCount = javascript.split(expectedWasmReference).length - 1;
  const analysis = javascriptResourceAnalysis(javascript);
  if (rawWasmReferenceCount !== 1
      || analysis.references.length !== 1 || analysis.references[0] !== expectedWasmReference
      || analysis.dynamicImport || analysis.staticExport || analysis.staticImport
      || javascript.includes('wallet-origin.wasm')
      || /sourceMappingURL/iu.test(javascript)) {
    fail('wallet-origin JavaScript asset closure is invalid');
  }
}

function writeOctal(header, offset, length, value) {
  if (!Number.isSafeInteger(value) || value < 0) fail('tar numeric value is invalid');
  const encoded = value.toString(8);
  if (encoded.length > length - 1) fail('tar numeric value is too large');
  header.write(`${encoded.padStart(length - 1, '0')}\0`, offset, length, 'ascii');
}

function splitTarPath(path) {
  if (Buffer.byteLength(path) <= 100) return { name: path, prefix: '' };
  let separatorIndex = path.lastIndexOf('/');
  while (separatorIndex > 0) {
    const prefix = path.slice(0, separatorIndex);
    const name = path.slice(separatorIndex + 1);
    if (Buffer.byteLength(prefix) <= 155 && Buffer.byteLength(name) <= 100) {
      return { name, prefix };
    }
    separatorIndex = path.lastIndexOf('/', separatorIndex - 1);
  }
  fail(`tar path cannot be represented safely: ${path}`);
}

function tarHeader(path, size) {
  const { name, prefix } = splitTarPath(path);
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, 'ascii');
  writeOctal(header, 100, 8, NORMALIZED_MODE);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = '0'.charCodeAt(0);
  header.write('ustar\0', 257, 6, 'ascii');
  header.write('00', 263, 2, 'ascii');
  writeOctal(header, 329, 8, 0);
  writeOctal(header, 337, 8, 0);
  header.write(prefix, 345, 155, 'ascii');
  let checksum = 0;
  for (const byte of header) checksum += byte;
  const encodedChecksum = checksum.toString(8);
  if (encodedChecksum.length > 6) fail('tar checksum overflow');
  header.write(encodedChecksum.padStart(6, '0'), 148, 6, 'ascii');
  header[154] = 0;
  header[155] = 0x20;
  return header;
}

function createTar(entries) {
  const chunks = [];
  for (const { bytes, path } of entries) {
    chunks.push(tarHeader(path, bytes.length), bytes);
    const remainder = bytes.length % 512;
    if (remainder !== 0) chunks.push(Buffer.alloc(512 - remainder));
  }
  chunks.push(Buffer.alloc(1024));
  return Buffer.concat(chunks);
}

function ensureVersion(version) {
  if (version !== ORIGIN_SERVICE_VERSION) {
    fail(`origin-service version must be ${ORIGIN_SERVICE_VERSION}`);
  }
}

async function ensureOutputTargetAbsent(path) {
  const status = await lstat(path).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (status) fail(`origin-service output already exists: ${path}`);
}

export async function buildOriginServiceArchive({
  outputDirectory,
  runtime,
  sourceDirectory,
  version = ORIGIN_SERVICE_VERSION,
}) {
  ensureVersion(version);
  if (typeof sourceDirectory !== 'string' || typeof outputDirectory !== 'string') {
    fail('origin-service sourceDirectory and outputDirectory are required');
  }
  const normalizedRuntime = validateRuntime(runtime);
  const sourceRoot = resolve(sourceDirectory);
  const outputRoot = resolve(outputDirectory);
  if (sourceRoot === outputRoot || outputRoot.startsWith(`${sourceRoot}${sep}`)) {
    fail('origin-service output must be outside the payload tree');
  }
  const sourceFiles = await collectRegularFiles(sourceRoot);
  const paths = sourceFiles.map(({ path }) => path);
  const assets = validateInventory(paths);
  const totalBytes = sourceFiles.reduce((sum, file) => sum + file.size, 0);
  if (totalBytes > MAX_PAYLOAD_BYTES) fail('origin-service payload is too large');
  const fileMap = new Map();
  for (const { absolute, path, size } of sourceFiles) {
    const bytes = await readRegularFileSnapshot(absolute, path);
    if (bytes.length !== size) fail(`origin-service payload changed while reading: ${path}`);
    fileMap.set(path, bytes);
  }

  const servicePackage = parseJcs(fileMap.get('package.json'), 'package.json');
  assertSameJson(servicePackage, expectedServicePackage(version), 'origin-service package metadata');
  const registry = parseJcs(
    fileMap.get('registry/client-registry.v1.json'),
    'registry/client-registry.v1.json',
  );
  exactObject(registry, ['clients', 'registryReleaseSha256', 'schemaVersion'], 'relay registry');
  if (!Array.isArray(registry.clients) || registry.schemaVersion !== 1
      || typeof registry.registryReleaseSha256 !== 'string'
      || !/^[0-9a-f]{64}$/u.test(registry.registryReleaseSha256)) {
    fail('relay registry metadata is invalid');
  }
  const unsignedRegistry = {
    clients: registry.clients,
    schemaVersion: registry.schemaVersion,
  };
  if (sha256(Buffer.from(canonicalize(unsignedRegistry))) !== registry.registryReleaseSha256) {
    fail('relay registry release digest mismatch');
  }
  validateRuntimePackageMetadata(fileMap);
  validateWalletOriginAssetClosure(fileMap, assets);

  const addonBytes = fileMap.get(ADDON_PATH);
  if (glibcVersionFromAddon(addonBytes) !== normalizedRuntime.minimumGlibc) {
    fail('better-sqlite3 addon glibc runtime binding is invalid');
  }
  const fileRecords = paths.map((path) => {
    const bytes = fileMap.get(path);
    return {
      bytes: bytes.length,
      mode: NORMALIZED_MODE,
      path,
      sha256: sha256(bytes),
    };
  });
  const manifest = {
    files: fileRecords,
    routes: {
      root: '/',
      transactionPattern: '^/transaction/[0-9a-f]{64}$',
    },
    runtime: {
      architecture: normalizedRuntime.architecture,
      betterSqlite3Addon: {
        path: ADDON_PATH,
        sha256: sha256(addonBytes),
      },
      minimumGlibc: normalizedRuntime.minimumGlibc,
      modulesAbi: normalizedRuntime.modulesAbi,
      napiVersion: normalizedRuntime.napiVersion,
      nodeVersion: normalizedRuntime.nodeVersion,
      platform: normalizedRuntime.platform,
    },
    schemaVersion: 1,
    serviceVersion: version,
  };
  const archiveEntries = [
    ...paths.map((path) => ({ bytes: fileMap.get(path), path })),
    { bytes: Buffer.from(`${canonicalize(manifest)}\n`), path: 'manifest.v1.json' },
  ].sort((left, right) => (left.path < right.path ? -1 : left.path > right.path ? 1 : 0));
  const tar = createTar(archiveEntries);
  const archiveBytes = gzipSync(tar, { level: 9, mtime: 0 });
  const archiveSha256 = sha256(archiveBytes);

  await mkdir(outputRoot, { recursive: true, mode: 0o755 });
  const outputStatus = await lstat(outputRoot);
  if (!outputStatus.isDirectory() || outputStatus.isSymbolicLink()) {
    fail('origin-service output must be a real directory');
  }
  const archivePath = resolve(outputRoot, ARCHIVE_BASENAME);
  const checksumPath = `${archivePath}.sha256`;
  await ensureOutputTargetAbsent(archivePath);
  await ensureOutputTargetAbsent(checksumPath);
  await writeFile(archivePath, archiveBytes, { flag: 'wx', mode: NORMALIZED_MODE });
  try {
    await writeFile(
      checksumPath,
      `${archiveSha256}  ${ARCHIVE_BASENAME}\n`,
      { flag: 'wx', mode: NORMALIZED_MODE },
    );
  } catch (error) {
    await rm(archivePath, { force: true });
    throw error;
  }
  return {
    archiveName: ARCHIVE_BASENAME,
    archivePath,
    checksumPath,
    manifest,
    sha256: archiveSha256,
  };
}

function runChecked(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd,
    encoding: 'utf8',
    env: options.env ?? process.env,
    maxBuffer: 16 * 1024 * 1024,
    stdio: options.capture === false ? 'inherit' : ['ignore', 'pipe', 'pipe'],
  });
  if (result.error) throw result.error;
  if (result.status !== 0) {
    const detail = `${result.stdout ?? ''}${result.stderr ?? ''}`.trim().slice(-4000);
    fail(`${command} ${args.join(' ')} failed${detail ? `: ${detail}` : ''}`);
  }
  return typeof result.stdout === 'string' ? result.stdout.trim() : '';
}

async function readJsonFile(path, label) {
  let value;
  try {
    value = JSON.parse(await readFile(path, 'utf8'));
  } catch {
    fail(`${label} is missing or invalid`);
  }
  return value;
}

async function validateCleanDependencyInstall(repositoryDirectory) {
  const rootLock = await readJsonFile(resolve(repositoryDirectory, 'package-lock.json'), 'package lock');
  const installedLock = await readJsonFile(
    resolve(repositoryDirectory, 'node_modules/.package-lock.json'),
    'npm ci installation lock',
  );
  if (rootLock.lockfileVersion !== 3 || installedLock.lockfileVersion !== 3
      || rootLock.version !== ORIGIN_SERVICE_VERSION) {
    fail('npm ci lock metadata is invalid');
  }
  const expectedVersions = {
    'node_modules/better-sqlite3': '12.2.0',
    'node_modules/bindings': '1.5.0',
    'node_modules/file-uri-to-path': '1.0.0',
  };
  for (const [path, version] of Object.entries(expectedVersions)) {
    if (rootLock.packages?.[path]?.version !== version
        || installedLock.packages?.[path]?.version !== version) {
      fail(`clean npm ci dependency is missing or drifted: ${path}`);
    }
  }
  const relay = rootLock.packages?.['wallet-ui/relay'];
  if (relay?.version !== ORIGIN_SERVICE_VERSION
      || canonicalize(relay.dependencies) !== canonicalize({ 'better-sqlite3': '12.2.0' })) {
    fail('relay production dependency contract is invalid');
  }
  const npmVersion = runChecked('npm', ['--version'], { cwd: repositoryDirectory });
  if (npmVersion !== '11.16.0') fail('production archive requires npm 11.16.0');
  runChecked('npm', [
    'ls', '--all', '--omit=dev', '--workspace', '@sdn/wallet-relay', '--json',
  ], { cwd: repositoryDirectory });
}

function validateProductionProcessRuntime() {
  const actual = {
    architecture: process.arch,
    modulesAbi: process.versions.modules,
    napiVersion: process.versions.napi,
    nodeVersion: process.versions.node,
    platform: process.platform,
  };
  for (const [key, expected] of Object.entries(REQUIRED_RUNTIME)) {
    if (actual[key] !== expected) {
      fail(`production archive requires ${key} ${expected}; observed ${actual[key] ?? 'missing'}`);
    }
  }
}

export function glibcVersionFromAddon(bytes) {
  if (bytes.length < 64 || !bytes.subarray(0, 4).equals(Buffer.from([0x7f, 0x45, 0x4c, 0x46]))
      || bytes[4] !== 2 || bytes[5] !== 1 || bytes.readUInt16LE(18) !== 62) {
    fail('better-sqlite3 addon must be a Linux x86-64 ELF binary');
  }
  const matches = [...bytes.toString('latin1').matchAll(/GLIBC_(\d+)\.(\d+)/gu)];
  if (matches.length === 0) fail('better-sqlite3 addon has no glibc version contract');
  matches.sort((left, right) => Number(left[1]) - Number(right[1]) || Number(left[2]) - Number(right[2]));
  const latest = matches.at(-1);
  return `${Number(latest[1])}.${Number(latest[2])}`;
}

async function copyRegularFile(source, target, label) {
  const bytes = await readRegularFileSnapshot(source, label);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, bytes, { flag: 'wx', mode: NORMALIZED_MODE });
}

async function readRegularFileSnapshot(source, label) {
  const before = await lstat(source).catch(() => null);
  if (!before?.isFile() || before.isSymbolicLink()
      || before.size <= 0 || before.size > MAX_FILE_BYTES) {
    fail(`${label} is missing or not a bounded regular file`);
  }
  let handle;
  try {
    handle = await open(
      source,
      filesystemConstants.O_RDONLY | (filesystemConstants.O_NOFOLLOW ?? 0),
    );
  } catch {
    fail(`${label} is missing or not a bounded regular file`);
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size
        || opened.dev !== before.dev || opened.ino !== before.ino) {
      fail(`${label} changed before it could be snapshotted`);
    }
    const buffer = Buffer.alloc(opened.size + 1);
    let bytesRead = 0;
    while (bytesRead < buffer.length) {
      const result = await handle.read(buffer, bytesRead, buffer.length - bytesRead, bytesRead);
      if (result.bytesRead === 0) break;
      bytesRead += result.bytesRead;
    }
    const after = await handle.stat();
    if (bytesRead !== opened.size || after.size !== opened.size
        || after.dev !== opened.dev || after.ino !== opened.ino) {
      fail(`${label} changed while it was being snapshotted`);
    }
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

async function validateBuiltOrigin(originDirectory) {
  const names = (await readdir(originDirectory)).sort();
  if (JSON.stringify(names) !== JSON.stringify(['assets', 'index.html', 'integrity.json'])) {
    fail('wallet-origin build inventory is invalid');
  }
  const assetNames = (await readdir(resolve(originDirectory, 'assets'))).sort();
  if (assetNames.length !== 3) fail('wallet-origin build must contain exactly three assets');
  const integrityBytes = await readFile(resolve(originDirectory, 'integrity.json'));
  let integrity;
  const integrityText = integrityBytes.toString('utf8');
  try {
    integrity = JSON.parse(integrityText);
  } catch {
    fail('wallet-origin integrity is not valid JSON');
  }
  if (!integrityBytes.equals(Buffer.from(`${JSON.stringify(integrity)}\n`))) {
    fail('wallet-origin integrity must be compact JSON plus one LF');
  }
  exactObject(integrity, ['files', 'schemaVersion'], 'wallet-origin integrity');
  if (integrity.schemaVersion !== 1 || !isPlainObject(integrity.files)) {
    fail('wallet-origin integrity metadata is invalid');
  }
  const expectedPaths = ['index.html', ...assetNames.map((name) => `assets/${name}`)].sort();
  if (JSON.stringify(Object.keys(integrity.files).sort()) !== JSON.stringify(expectedPaths)) {
    fail('wallet-origin integrity file list is invalid');
  }
  for (const path of expectedPaths) {
    const record = exactObject(integrity.files[path], ['bytes', 'sha256', 'sha384'], `${path} integrity`);
    const bytes = await readFile(resolve(originDirectory, path));
    const expectedSha384 = `sha384-${createHash('sha384').update(bytes).digest('base64')}`;
    if (record.bytes !== bytes.length || record.sha256 !== sha256(bytes)
        || record.sha384 !== expectedSha384) {
      fail(`wallet-origin integrity mismatch: ${path}`);
    }
  }
  return assetNames;
}

function productionServerEntry(relaySourcePath, assetNames) {
  const contentTypes = Object.fromEntries(assetNames.map((name) => {
    const extension = name.slice(name.lastIndexOf('.') + 1);
    const type = extension === 'css' ? 'text/css; charset=utf-8'
      : extension === 'js' ? 'text/javascript; charset=utf-8'
        : 'application/wasm';
    return [`/assets/${name}`, type];
  }));
  return `import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRelayServer } from ${JSON.stringify(relaySourcePath)};
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const contentTypes = Object.freeze(${JSON.stringify(contentTypes)});
const shellPattern = /^\\/transaction\\/[0-9a-f]{64}$/u;
const csp = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; worker-src 'none'; manifest-src 'self'";
const databasePath = process.env.SDN_WALLET_RELAY_DATABASE_PATH ?? '/run/sdn-wallet-relay/relay.sqlite';
const host = process.env.SDN_WALLET_RELAY_HOST ?? '127.0.0.1';
const portText = process.env.SDN_WALLET_RELAY_PORT ?? '8787';
const trustText = process.env.SDN_WALLET_RELAY_TRUST_LOOPBACK_X_REAL_IP ?? '0';
if (!/^(?:[1-9]\\d{0,4})$/u.test(portText) || Number(portText) > 65535) throw new Error('relay port is invalid');
if (trustText !== '0' && trustText !== '1') throw new Error('relay loopback proxy trust setting is invalid');
const index = await readFile(resolve(root, 'wallet-origin/index.html'));
const server = createRelayServer({
  databasePath,
  registryPath: resolve(root, 'registry/client-registry.v1.json'),
  trustLoopbackProxy: trustText === '1',
});
const relayRequest = server.listeners('request')[0];
if (typeof relayRequest !== 'function' || server.listeners('request').length !== 1) throw new Error('relay handler contract is invalid');
server.removeListener('request', relayRequest);
server.on('request', (request, response) => {
  const target = request.url;
  if (request.method === 'GET' && (target === '/' || shellPattern.test(target))) {
    response.writeHead(200, {
      'cache-control': 'no-store',
      'content-length': index.length,
      'content-security-policy': csp,
      'content-type': 'text/html; charset=utf-8',
      'cross-origin-opener-policy': 'same-origin',
      'referrer-policy': 'no-referrer',
      'x-content-type-options': 'nosniff',
      'x-frame-options': 'DENY',
    });
    response.end(index);
    return;
  }
  const contentType = contentTypes[target];
  if (request.method === 'GET' && contentType) {
    void readFile(resolve(root, 'wallet-origin', target.slice(1))).then((bytes) => {
      response.writeHead(200, {
        'cache-control': 'public, max-age=31536000, immutable',
        'content-length': bytes.length,
        'content-type': contentType,
        'cross-origin-opener-policy': 'same-origin',
        'referrer-policy': 'no-referrer',
        'x-content-type-options': 'nosniff',
        'x-frame-options': 'DENY',
      });
      response.end(bytes);
    }, () => {
      if (!response.headersSent) response.writeHead(500, {'content-length': 0});
      response.end();
    });
    return;
  }
  void relayRequest.call(server, request, response);
});
server.listen(Number(portText), host);
const stop = () => server.close();
process.once('SIGINT', stop);
process.once('SIGTERM', stop);
`;
}

export async function compileOriginServiceServer({
  assetNames,
  relaySourcePath,
  target,
  wireSourcePath,
}) {
  if (!Array.isArray(assetNames) || assetNames.length !== 3
      || typeof relaySourcePath !== 'string' || typeof target !== 'string'
      || typeof wireSourcePath !== 'string') {
    fail('origin-service compiler arguments are invalid');
  }
  const assetKinds = assetNames.map((name) => ASSET_NAME.exec(name)?.[2]).sort();
  if (JSON.stringify(assetKinds) !== JSON.stringify(['css', 'js', 'wasm'])) {
    fail('origin-service compiler requires exact hashed JS/CSS/WASM names');
  }
  const relaySource = await realpath(resolve(relaySourcePath));
  const wireSource = await realpath(resolve(wireSourcePath));
  const source = await readFile(relaySource, 'utf8');
  const footer = /\nif \(process\.argv\[1\][\s\S]*?\n\}\n$/u;
  if ((source.match(footer) ?? []).length !== 1) fail('relay executable footer contract drifted');
  const computedWireImport = "await import(new URL('../../../client/wire.mjs', import.meta.url).href)";
  if (source.split(computedWireImport).length !== 2) {
    fail('relay wire import contract drifted');
  }
  const librarySource = source
    .replace(computedWireImport, `await import(${JSON.stringify(wireSource)})`)
    .replace(footer, '\n');
  const { build } = await import('esbuild');
  await mkdir(dirname(target), { recursive: true });
  let transformedRelay = false;
  await build({
    bundle: true,
    charset: 'utf8',
    external: ['better-sqlite3'],
    format: 'esm',
    legalComments: 'none',
    minify: true,
    outfile: target,
    platform: 'node',
    plugins: [{
      name: 'relay-library-entry',
      setup(buildApi) {
        buildApi.onLoad({ filter: /server\.ts$/u }, async (args) => {
          if (resolve(args.path) !== relaySource) return null;
          transformedRelay = true;
          return { contents: librarySource, loader: 'ts', resolveDir: dirname(relaySource) };
        });
      },
    }],
    sourcemap: false,
    stdin: {
      contents: productionServerEntry(relaySource, assetNames),
      loader: 'js',
      resolveDir: dirname(relaySource),
      sourcefile: 'sdn-wallet-origin-service-entry.mjs',
    },
    target: ['node24'],
    treeShaking: true,
    write: true,
  });
  if (!transformedRelay) fail('relay compiler did not transform its library entry');
  const output = await readFile(target, 'utf8');
  const violations = [];
  if (output.length === 0) violations.push('empty output');
  if (/sourceMappingURL/iu.test(output)) violations.push('source map reference');
  if (output.includes(relaySource)) violations.push('relay source path');
  if (output.includes(wireSource)) violations.push('wire source path');
  if (output.includes('../../../client/wire.mjs')) violations.push('runtime wire traversal');
  if (output.includes('new URL("../../../client/wire.mjs"')) violations.push('computed wire import');
  if (violations.length > 0) {
    fail(`compiled relay output is invalid: ${violations.join(', ')}`);
  }
}

async function snapshotRuntimeDependencies(repositoryDirectory) {
  const snapshot = new Map();
  for (const path of RUNTIME_DEPENDENCY_FILES) {
    if (path in RUNTIME_PACKAGE_METADATA) {
      snapshot.set(path, Buffer.from(`${canonicalize(RUNTIME_PACKAGE_METADATA[path])}\n`));
      continue;
    }
    snapshot.set(path, await readRegularFileSnapshot(resolve(repositoryDirectory, path), path));
  }
  return snapshot;
}

async function stageRuntimeDependencies(snapshot, stagingDirectory) {
  for (const path of RUNTIME_DEPENDENCY_FILES) {
    const target = resolve(stagingDirectory, path);
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, snapshot.get(path), { flag: 'wx', mode: NORMALIZED_MODE });
  }
}

export async function buildProductionOriginServiceRelease({
  outputDirectory = resolve(REPOSITORY_DIRECTORY, 'release/origin-service'),
  repositoryDirectory = REPOSITORY_DIRECTORY,
  version = ORIGIN_SERVICE_VERSION,
} = {}) {
  ensureVersion(version);
  validateProductionProcessRuntime();
  const repositoryRoot = resolve(repositoryDirectory);
  const npmVersion = runChecked('npm', ['--version'], { cwd: repositoryRoot });
  if (npmVersion !== '11.16.0') fail('production archive requires npm 11.16.0');
  runChecked('npm', ['ci', '--include=dev', '--ignore-scripts', '--no-audit', '--no-fund'], {
    cwd: repositoryRoot,
  });
  await validateCleanDependencyInstall(repositoryRoot);
  const toolchain = await readJsonFile(
    resolve(repositoryRoot, 'release/toolchain.v1.json'),
    'release toolchain',
  );
  const prebuildPin = selectBetterSqlite3Prebuild(toolchain, REQUIRED_RUNTIME);
  await acquireBetterSqlite3Prebuild({
    destinationPath: resolve(repositoryRoot, ADDON_PATH),
    pin: prebuildPin,
  });
  const dependencySnapshot = await snapshotRuntimeDependencies(repositoryRoot);
  const addonBytes = dependencySnapshot.get(ADDON_PATH);
  const minimumGlibc = glibcVersionFromAddon(addonBytes);
  const originDirectory = resolve(repositoryRoot, 'wallet-ui/dist/wallet-origin-host');
  const assetNames = await validateBuiltOrigin(originDirectory);
  const stagingDirectory = await mkdtemp(join(tmpdir(), 'sdn-wallet-origin-service-stage-'));
  try {
    await copyRegularFile(
      resolve(repositoryRoot, 'LICENSE'),
      resolve(stagingDirectory, 'LICENSE'),
      'repository LICENSE',
    );
    await writeFile(
      resolve(stagingDirectory, 'package.json'),
      `${canonicalize(expectedServicePackage(version))}\n`,
    );
    await copyRegularFile(
      resolve(repositoryRoot, 'wallet-ui/relay/config/client-registry.v1.json'),
      resolve(stagingDirectory, 'registry/client-registry.v1.json'),
      'relay registry',
    );
    await compileOriginServiceServer({
      assetNames,
      relaySourcePath: resolve(repositoryRoot, 'wallet-ui/relay/src/server.ts'),
      target: resolve(stagingDirectory, 'service/server.mjs'),
      wireSourcePath: resolve(repositoryRoot, 'wallet-ui/client/wire.mjs'),
    });
    await copyRegularFile(
      resolve(originDirectory, 'index.html'),
      resolve(stagingDirectory, 'wallet-origin/index.html'),
      'wallet-origin index',
    );
    for (const name of assetNames) {
      await copyRegularFile(
        resolve(originDirectory, 'assets', name),
        resolve(stagingDirectory, 'wallet-origin/assets', name),
        `wallet-origin asset ${name}`,
      );
    }
    await stageRuntimeDependencies(dependencySnapshot, stagingDirectory);
    return await buildOriginServiceArchive({
      outputDirectory,
      runtime: {
        ...REQUIRED_RUNTIME,
        minimumGlibc,
      },
      sourceDirectory: stagingDirectory,
      version,
    });
  } finally {
    await rm(stagingDirectory, { force: true, recursive: true });
  }
}

function parseArguments(argv) {
  const options = {};
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (name !== '--output' && name !== '--version') fail(`unknown argument: ${name}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) fail(`missing value for ${name}`);
    if (options[name]) fail(`duplicate argument: ${name}`);
    options[name] = value;
    index += 1;
  }
  return {
    outputDirectory: options['--output']
      ? resolve(process.cwd(), options['--output'])
      : resolve(REPOSITORY_DIRECTORY, 'release/origin-service'),
    version: options['--version'] ?? ORIGIN_SERVICE_VERSION,
  };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const options = parseArguments(process.argv.slice(2));
  const result = await buildProductionOriginServiceRelease(options);
  process.stdout.write(`${canonicalize({
    archive: result.archivePath,
    archiveSha256: result.sha256,
    checksum: result.checksumPath,
    schemaVersion: 1,
  })}\n`);
}
