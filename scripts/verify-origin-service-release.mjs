import { createHash } from 'node:crypto';
import { constants as filesystemConstants } from 'node:fs';
import {
  lstat,
  mkdir,
  mkdtemp,
  open,
  rm,
  writeFile,
} from 'node:fs/promises';
import { request as httpRequest } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve, sep } from 'node:path';
import { spawn } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { gunzipSync, gzipSync } from 'node:zlib';

import {
  ADDON_PATH,
  ARCHIVE_BASENAME,
  ORIGIN_SERVICE_VERSION,
  REQUIRED_RUNTIME,
  RUNTIME_DEPENDENCY_FILES,
  canonicalize,
  glibcVersionFromAddon,
  validateWalletOriginAssetClosure,
} from './build-origin-service-release.mjs';

const MAX_ARCHIVE_BYTES = 32 * 1024 * 1024;
const MAX_UNCOMPRESSED_BYTES = 128 * 1024 * 1024;
const NORMALIZED_MODE = 0o644;
const HASHED_ASSET = /^wallet-origin\.([0-9a-f]{64})\.(css|js|wasm)$/u;
const SAFE_VERSION = /^\d+\.\d+$/u;
const FIXED_PAYLOAD_FILES = Object.freeze([
  'LICENSE',
  'package.json',
  'registry/client-registry.v1.json',
  'service/server.mjs',
  'wallet-origin/index.html',
  ...RUNTIME_DEPENDENCY_FILES,
].sort());

function fail(message) {
  throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

async function readBoundedRegularFile(path, maximumBytes, label) {
  const before = await lstat(path).catch(() => null);
  if (!before?.isFile() || before.isSymbolicLink()
      || before.size <= 0 || before.size > maximumBytes) {
    fail(`${label} must be a bounded regular file`);
  }
  let handle;
  try {
    handle = await open(
      path,
      filesystemConstants.O_RDONLY | (filesystemConstants.O_NOFOLLOW ?? 0),
    );
  } catch {
    fail(`${label} must be a bounded regular file`);
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || opened.size !== before.size
        || opened.dev !== before.dev || opened.ino !== before.ino) {
      fail(`${label} changed before it could be read`);
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
      fail(`${label} changed while it was being read`);
    }
    return buffer.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
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

function validateArchivePath(path) {
  if (typeof path !== 'string' || path.length === 0 || path.length > 240
      || path.startsWith('/') || path.includes('\\') || path.includes('\0')) {
    fail(`unsafe archive path: ${path}`);
  }
  const parts = path.split('/');
  if (parts.some((part) => part.length === 0 || part === '.' || part === '..')) {
    fail(`unsafe archive path: ${path}`);
  }
}

function readTextField(header, offset, length, label) {
  const bytes = header.subarray(offset, offset + length);
  const zero = bytes.indexOf(0);
  const content = zero === -1 ? bytes : bytes.subarray(0, zero);
  if (content.some((byte) => byte < 0x20 || byte > 0x7e)) fail(`tar ${label} is not ASCII`);
  if (zero !== -1 && bytes.subarray(zero).some((byte) => byte !== 0)) {
    fail(`tar ${label} has nonzero padding`);
  }
  return content.toString('ascii');
}

function readOctalField(header, offset, length, label) {
  const bytes = header.subarray(offset, offset + length);
  let digits = '';
  let terminated = false;
  for (const byte of bytes) {
    if (!terminated && byte >= 0x30 && byte <= 0x37) {
      digits += String.fromCharCode(byte);
    } else if (byte === 0 || byte === 0x20) {
      terminated = true;
    } else {
      fail(`tar ${label} is not canonical octal`);
    }
  }
  if (digits.length === 0) fail(`tar ${label} is not canonical octal`);
  const value = Number.parseInt(digits, 8);
  if (!Number.isSafeInteger(value) || value < 0) fail(`tar ${label} is invalid`);
  return value;
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

function canonicalTarHeader(path, size) {
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

function validateHeaderChecksum(header) {
  const recorded = readOctalField(header, 148, 8, 'checksum');
  let calculated = 0;
  for (let index = 0; index < header.length; index += 1) {
    calculated += index >= 148 && index < 156 ? 0x20 : header[index];
  }
  if (recorded !== calculated) fail('tar header checksum mismatch');
}

function parseTar(tar) {
  if (tar.length < 1536 || tar.length % 512 !== 0) fail('tar byte length is invalid');
  const entries = [];
  let offset = 0;
  let payloadBytes = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) {
      if (offset + 1024 !== tar.length
          || !tar.subarray(offset + 512, offset + 1024).every((byte) => byte === 0)) {
        fail('tar must end with exactly two zero blocks');
      }
      break;
    }
    validateHeaderChecksum(header);
    if (header.subarray(257, 263).toString('latin1') !== 'ustar\0'
        || header.subarray(263, 265).toString('ascii') !== '00') {
      fail('tar must use the exact USTAR format');
    }
    const name = readTextField(header, 0, 100, 'name');
    const prefix = readTextField(header, 345, 155, 'prefix');
    const path = prefix ? `${prefix}/${name}` : name;
    validateArchivePath(path);
    const type = header[156];
    if (type !== '0'.charCodeAt(0)) fail('archive must contain only regular files');
    if (readTextField(header, 157, 100, 'link name') !== '') {
      fail('archive must not contain links');
    }
    const mode = readOctalField(header, 100, 8, 'mode');
    const uid = readOctalField(header, 108, 8, 'uid');
    const gid = readOctalField(header, 116, 8, 'gid');
    const size = readOctalField(header, 124, 12, 'size');
    const mtime = readOctalField(header, 136, 12, 'mtime');
    const deviceMajor = readOctalField(header, 329, 8, 'device major');
    const deviceMinor = readOctalField(header, 337, 8, 'device minor');
    if (mode !== NORMALIZED_MODE || uid !== 0 || gid !== 0 || mtime !== 0
        || deviceMajor !== 0 || deviceMinor !== 0
        || readTextField(header, 265, 32, 'user name') !== ''
        || readTextField(header, 297, 32, 'group name') !== '') {
      fail(`archive header metadata is not normalized: ${path}`);
    }
    if (!header.equals(canonicalTarHeader(path, size))) {
      fail(`tar header is not canonical: ${path}`);
    }
    if (size <= 0 || size > 32 * 1024 * 1024) fail(`archive file size is invalid: ${path}`);
    const dataOffset = offset + 512;
    const nextOffset = dataOffset + Math.ceil(size / 512) * 512;
    if (nextOffset > tar.length - 1024) fail(`archive file is truncated: ${path}`);
    const bytes = Buffer.from(tar.subarray(dataOffset, dataOffset + size));
    const padding = tar.subarray(dataOffset + size, nextOffset);
    if (!padding.every((byte) => byte === 0)) fail(`archive file padding is not zero: ${path}`);
    payloadBytes += size;
    if (payloadBytes > 64 * 1024 * 1024) fail('archive payload is too large');
    entries.push({ bytes, mode, path });
    offset = nextOffset;
  }
  if (offset + 1024 !== tar.length) fail('tar terminator is missing');
  const paths = entries.map(({ path }) => path);
  if (JSON.stringify(paths) !== JSON.stringify([...paths].sort())) {
    fail('archive entries are not sorted');
  }
  if (new Set(paths).size !== paths.length) fail('archive contains duplicate paths');
  return entries;
}

function decompressArchive(archiveBytes) {
  if (!Buffer.isBuffer(archiveBytes) || archiveBytes.length <= 18
      || archiveBytes.length > MAX_ARCHIVE_BYTES) {
    fail('origin-service archive size is invalid');
  }
  if (archiveBytes[0] !== 0x1f || archiveBytes[1] !== 0x8b || archiveBytes[2] !== 8
      || archiveBytes[3] !== 0 || archiveBytes.readUInt32LE(4) !== 0) {
    fail('origin-service archive gzip header is not deterministic');
  }
  let tar;
  try {
    tar = gunzipSync(archiveBytes, { maxOutputLength: MAX_UNCOMPRESSED_BYTES });
  } catch {
    fail('origin-service archive gzip payload is invalid');
  }
  const canonicalArchive = gzipSync(tar, { level: 9, mtime: 0 });
  if (!canonicalArchive.equals(archiveBytes)) {
    fail('origin-service archive gzip encoding is not canonical');
  }
  return tar;
}

function compareVersion(left, right) {
  const parse = (value) => {
    if (typeof value !== 'string' || !SAFE_VERSION.test(value)) fail('runtime glibc version is invalid');
    return value.split('.').map(Number);
  };
  const [leftMajor, leftMinor] = parse(left);
  const [rightMajor, rightMinor] = parse(right);
  return leftMajor - rightMajor || leftMinor - rightMinor;
}

function validateRuntime(runtime, observedRuntime) {
  exactObject(runtime, [
    'architecture', 'betterSqlite3Addon', 'minimumGlibc', 'modulesAbi',
    'napiVersion', 'nodeVersion', 'platform',
  ], 'origin-service runtime metadata');
  exactObject(runtime.betterSqlite3Addon, ['path', 'sha256'], 'better-sqlite3 addon metadata');
  for (const [key, expected] of Object.entries(REQUIRED_RUNTIME)) {
    if (runtime[key] !== expected) fail(`archive runtime ${key} is invalid`);
    if (observedRuntime[key] !== expected) fail(`observed runtime ${key} is invalid`);
  }
  if (!SAFE_VERSION.test(runtime.minimumGlibc)
      || compareVersion(observedRuntime.glibcVersion, runtime.minimumGlibc) < 0) {
    fail('observed runtime glibc is below the archive minimum runtime');
  }
  if (runtime.betterSqlite3Addon.path !== ADDON_PATH
      || !/^[0-9a-f]{64}$/u.test(runtime.betterSqlite3Addon.sha256)) {
    fail('better-sqlite3 addon runtime binding is invalid');
  }
}

function validateInventory(paths) {
  const fixed = new Set(FIXED_PAYLOAD_FILES);
  const assets = { css: [], js: [], wasm: [] };
  for (const path of paths) {
    if (fixed.has(path)) continue;
    if (path.startsWith('wallet-origin/assets/')) {
      const name = path.slice('wallet-origin/assets/'.length);
      const match = HASHED_ASSET.exec(name);
      if (match) {
        assets[match[2]].push(path);
        continue;
      }
    }
    fail(`unexpected archive path: ${path}`);
  }
  for (const expected of FIXED_PAYLOAD_FILES) {
    if (!paths.includes(expected)) fail(`archive payload inventory is missing ${expected}`);
  }
  for (const extension of ['css', 'js', 'wasm']) {
    if (assets[extension].length !== 1) {
      fail(`archive payload inventory requires one hashed ${extension} asset`);
    }
  }
  if (paths.length !== FIXED_PAYLOAD_FILES.length + 3) {
    fail('archive payload inventory has extra files');
  }
  return assets;
}

function validatePackageMetadata(fileMap) {
  const expectedService = {
    dependencies: { 'better-sqlite3': '12.2.0' },
    engines: { node: '24.18.0' },
    name: '@sdn/wallet-origin-service',
    private: true,
    type: 'module',
    version: ORIGIN_SERVICE_VERSION,
  };
  const expectedDependencies = {
    'node_modules/better-sqlite3/package.json': {
      dependencies: { bindings: '1.5.0' },
      license: 'MIT',
      main: 'lib/index.js',
      name: 'better-sqlite3',
      version: '12.2.0',
    },
    'node_modules/bindings/package.json': {
      dependencies: { 'file-uri-to-path': '1.0.0' },
      license: 'MIT',
      main: 'bindings.js',
      name: 'bindings',
      version: '1.5.0',
    },
    'node_modules/file-uri-to-path/package.json': {
      license: 'MIT',
      main: 'index.js',
      name: 'file-uri-to-path',
      version: '1.0.0',
    },
  };
  const service = parseJcs(fileMap.get('package.json'), 'package.json');
  if (canonicalize(service) !== canonicalize(expectedService)) {
    fail('origin-service package metadata is invalid');
  }
  for (const [path, expected] of Object.entries(expectedDependencies)) {
    const value = parseJcs(fileMap.get(path), path);
    if (canonicalize(value) !== canonicalize(expected)) {
      fail(`runtime dependency package metadata is invalid: ${path}`);
    }
  }
}

function validateRegistry(fileMap) {
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
}

function defaultObservedRuntime() {
  const report = typeof process.report?.getReport === 'function' ? process.report.getReport() : null;
  return {
    architecture: process.arch,
    glibcVersion: report?.header?.glibcVersionRuntime ?? '',
    modulesAbi: process.versions.modules,
    napiVersion: process.versions.napi,
    nodeVersion: process.versions.node,
    platform: process.platform,
  };
}

function inspectArchiveInternal(archiveBytes, observedRuntime) {
  const tar = decompressArchive(archiveBytes);
  const entries = parseTar(tar);
  const manifestEntries = entries.filter(({ path }) => path === 'manifest.v1.json');
  if (manifestEntries.length !== 1) fail('archive must contain exactly one manifest.v1.json');
  const payloadEntries = entries.filter(({ path }) => path !== 'manifest.v1.json');
  const paths = payloadEntries.map(({ path }) => path);
  const assets = validateInventory(paths);
  const fileMap = new Map(payloadEntries.map(({ bytes, path }) => [path, bytes]));
  const manifest = parseJcs(manifestEntries[0].bytes, 'manifest.v1.json');
  exactObject(manifest, [
    'files', 'routes', 'runtime', 'schemaVersion', 'serviceVersion',
  ], 'origin-service manifest');
  exactObject(manifest.routes, ['root', 'transactionPattern'], 'origin-service routes');
  if (manifest.schemaVersion !== 1 || manifest.serviceVersion !== ORIGIN_SERVICE_VERSION
      || manifest.routes.root !== '/'
      || manifest.routes.transactionPattern !== '^/transaction/[0-9a-f]{64}$') {
    fail('origin-service manifest contract is invalid');
  }
  validateRuntime(manifest.runtime, observedRuntime);
  if (!Array.isArray(manifest.files) || manifest.files.length !== payloadEntries.length) {
    fail('origin-service manifest file list is invalid');
  }
  for (let index = 0; index < payloadEntries.length; index += 1) {
    const entry = payloadEntries[index];
    const record = exactObject(
      manifest.files[index],
      ['bytes', 'mode', 'path', 'sha256'],
      'origin-service file record',
    );
    if (record.path !== entry.path || record.bytes !== entry.bytes.length
        || record.mode !== NORMALIZED_MODE || record.sha256 !== sha256(entry.bytes)) {
      fail(`file digest mismatch: ${entry.path}`);
    }
  }
  const addon = fileMap.get(ADDON_PATH);
  if (sha256(addon) !== manifest.runtime.betterSqlite3Addon.sha256) {
    fail('better-sqlite3 addon binding hash mismatch');
  }
  if (glibcVersionFromAddon(addon) !== manifest.runtime.minimumGlibc) {
    fail('better-sqlite3 addon glibc runtime binding is invalid');
  }
  validatePackageMetadata(fileMap);
  validateRegistry(fileMap);
  validateWalletOriginAssetClosure(fileMap, assets);
  return { archiveBytes, entries, fileMap, manifest, paths };
}

function publicInspection(internal) {
  const files = Object.fromEntries(internal.manifest.files.map((record) => [record.path, {
    bytes: record.bytes,
    mode: record.mode,
    sha256: record.sha256,
  }]));
  return {
    fileCount: internal.paths.length,
    files,
    paths: [...internal.paths],
    routes: { ...internal.manifest.routes },
    runtime: JSON.parse(JSON.stringify(internal.manifest.runtime)),
    schemaVersion: internal.manifest.schemaVersion,
    serviceVersion: internal.manifest.serviceVersion,
  };
}

export async function inspectOriginServiceArchive(archiveBytes, {
  observedRuntime = defaultObservedRuntime(),
} = {}) {
  return publicInspection(inspectArchiveInternal(archiveBytes, observedRuntime));
}

async function verifyChecksum(archivePath, checksumPath, archiveBytes) {
  const archiveName = basename(archivePath);
  if (archiveName !== ARCHIVE_BASENAME) fail(`origin-service archive name must be ${ARCHIVE_BASENAME}`);
  const expectedText = `${sha256(archiveBytes)}  ${archiveName}\n`;
  const actualText = (await readBoundedRegularFile(
    checksumPath,
    256,
    'origin-service archive checksum',
  )).toString('utf8');
  if (actualText !== expectedText) fail('origin-service archive checksum mismatch');
}

async function extractToTemporaryDirectory(entries, directory) {
  for (const entry of entries) {
    validateArchivePath(entry.path);
    const target = resolve(directory, entry.path);
    if (!target.startsWith(`${directory}${sep}`)) fail(`unsafe extraction target: ${entry.path}`);
    await mkdir(dirname(target), { recursive: true, mode: 0o755 });
    const status = await lstat(target).catch((error) => {
      if (error?.code === 'ENOENT') return null;
      throw error;
    });
    if (status) fail(`temporary extraction target already exists: ${entry.path}`);
    await writeFile(target, entry.bytes, { flag: 'wx', mode: NORMALIZED_MODE });
  }
}

async function availablePort() {
  const server = createNetServer();
  await new Promise((accept, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', accept);
  });
  const address = server.address();
  if (!address || typeof address === 'string') fail('could not reserve a health-check port');
  await new Promise((accept, reject) => server.close((error) => (error ? reject(error) : accept())));
  return address.port;
}

function delay(milliseconds) {
  return new Promise((accept) => setTimeout(accept, milliseconds));
}

function localGet(port, path) {
  return new Promise((accept, reject) => {
    const request = httpRequest({
      headers: { connection: 'close' },
      host: '127.0.0.1',
      method: 'GET',
      path,
      port,
    }, (response) => {
      const chunks = [];
      let size = 0;
      response.on('data', (chunk) => {
        size += chunk.length;
        if (size > 4 * 1024 * 1024) {
          request.destroy(new Error('health response is too large'));
          return;
        }
        chunks.push(chunk);
      });
      response.once('end', () => accept({
        body: Buffer.concat(chunks),
        headers: response.headers,
        status: response.statusCode,
      }));
    });
    request.setTimeout(750, () => request.destroy(new Error('health request timed out')));
    request.once('error', reject);
    request.end();
  });
}

async function stopChild(child) {
  if (child.exitCode !== null || child.signalCode !== null) return;
  const waitForExit = (timeoutMilliseconds) => new Promise((accept) => {
    let timer;
    const onExit = () => {
      clearTimeout(timer);
      child.removeListener('exit', onExit);
      accept(true);
    };
    timer = setTimeout(() => {
      child.removeListener('exit', onExit);
      accept(false);
    }, timeoutMilliseconds);
    child.once('exit', onExit);
    if (child.exitCode !== null || child.signalCode !== null) onExit();
  });
  const exitPromise = waitForExit(3000);
  child.kill('SIGTERM');
  const exited = await exitPromise;
  if (!exited && child.exitCode === null && child.signalCode === null) {
    const forcedExitPromise = waitForExit(3000);
    child.kill('SIGKILL');
    await forcedExitPromise;
  }
}

async function runHealthCheck(directory, indexBytes, executable) {
  const runtimeDirectory = resolve(directory, '.runtime');
  const databasePath = resolve(runtimeDirectory, 'relay.sqlite');
  const temporaryHome = resolve(runtimeDirectory, 'home');
  const temporaryFiles = resolve(runtimeDirectory, 'tmp');
  await mkdir(temporaryHome, { recursive: true, mode: 0o700 });
  await mkdir(temporaryFiles, { recursive: true, mode: 0o700 });
  const port = await availablePort();
  const child = spawn(executable, [resolve(directory, 'service/server.mjs')], {
    cwd: directory,
    env: {
      HOME: temporaryHome,
      NODE_ENV: 'production',
      PATH: process.env.PATH ?? '',
      SDN_WALLET_RELAY_DATABASE_PATH: databasePath,
      SDN_WALLET_RELAY_HOST: '127.0.0.1',
      SDN_WALLET_RELAY_PORT: String(port),
      SDN_WALLET_RELAY_TRUST_LOOPBACK_X_REAL_IP: '0',
      TMPDIR: temporaryFiles,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  const stdout = [];
  const stderr = [];
  const capture = (target) => (chunk) => {
    if (target.reduce((sum, item) => sum + item.length, 0) < 32 * 1024) target.push(chunk);
  };
  child.stdout.on('data', capture(stdout));
  child.stderr.on('data', capture(stderr));
  try {
    const deadline = Date.now() + 8000;
    let health;
    while (Date.now() < deadline) {
      if (child.exitCode !== null || child.signalCode !== null) break;
      try {
        health = await localGet(port, '/healthz');
        break;
      } catch {
        await delay(50);
      }
    }
    if (!health) {
      const detail = Buffer.concat([...stdout, ...stderr]).toString('utf8').slice(-4000);
      fail(`archived service did not become healthy${detail ? `: ${detail}` : ''}`);
    }
    if (health.status !== 200
        || health.headers['content-type'] !== 'application/json; charset=utf-8'
        || health.body.toString('utf8') !== '{"schemaVersion":1,"status":"ok"}') {
      fail('archived service health contract is invalid');
    }
    const transactionId = 'a'.repeat(64);
    const [rootShell, transactionShell] = await Promise.all([
      localGet(port, '/'),
      localGet(port, `/transaction/${transactionId}`),
    ]);
    for (const response of [rootShell, transactionShell]) {
      if (response.status !== 200
          || response.headers['content-type'] !== 'text/html; charset=utf-8'
          || !response.body.equals(indexBytes)) {
        fail('archived service shell route contract is invalid');
      }
    }
    if (!databasePath.startsWith(`${runtimeDirectory}${sep}`)) {
      fail('archived service did not use its temporary database path');
    }
    const databaseBytes = await readBoundedRegularFile(
      databasePath,
      16 * 1024 * 1024,
      'archived service database',
    );
    if (databaseBytes.length < 100
        || !databaseBytes.subarray(0, 16).equals(Buffer.from('SQLite format 3\0'))) {
      fail('archived service database is not SQLite');
    }
  } finally {
    await stopChild(child);
  }
}

export async function verifyOriginServiceRelease({
  archivePath,
  checksumPath = typeof archivePath === 'string' ? `${archivePath}.sha256` : undefined,
  healthExecutable = process.execPath,
  observedRuntime = defaultObservedRuntime(),
  requireChecksum = true,
  runHealthCheck: shouldRunHealthCheck = true,
} = {}) {
  if (typeof archivePath !== 'string' || archivePath.length === 0) {
    fail('origin-service archivePath is required');
  }
  if (typeof requireChecksum !== 'boolean' || typeof shouldRunHealthCheck !== 'boolean') {
    fail('origin-service verifier options are invalid');
  }
  const archiveBytes = await readBoundedRegularFile(
    archivePath,
    MAX_ARCHIVE_BYTES,
    'origin-service archive',
  );
  if (requireChecksum) {
    if (typeof checksumPath !== 'string' || checksumPath.length === 0) fail('checksumPath is required');
    await verifyChecksum(archivePath, checksumPath, archiveBytes);
  }
  const internal = inspectArchiveInternal(archiveBytes, observedRuntime);
  if (shouldRunHealthCheck) {
    const extractionDirectory = await mkdtemp(join(tmpdir(), 'sdn-wallet-origin-verify-'));
    try {
      await extractToTemporaryDirectory(internal.entries, extractionDirectory);
      await runHealthCheck(
        extractionDirectory,
        internal.fileMap.get('wallet-origin/index.html'),
        healthExecutable,
      );
    } finally {
      await rm(extractionDirectory, { force: true, recursive: true });
    }
  }
  return {
    ...publicInspection(internal),
    archiveSha256: sha256(archiveBytes),
    healthChecked: shouldRunHealthCheck,
    shellChecked: shouldRunHealthCheck,
  };
}

function parseArguments(argv) {
  const values = {};
  for (let index = 0; index < argv.length; index += 1) {
    const name = argv[index];
    if (name !== '--archive' && name !== '--sha256') fail(`unknown argument: ${name}`);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) fail(`missing value for ${name}`);
    if (values[name]) fail(`duplicate argument: ${name}`);
    values[name] = value;
    index += 1;
  }
  if (!values['--archive']) fail('--archive is required');
  const archivePath = resolve(process.cwd(), values['--archive']);
  return {
    archivePath,
    checksumPath: values['--sha256']
      ? resolve(process.cwd(), values['--sha256'])
      : `${archivePath}.sha256`,
  };
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  const result = await verifyOriginServiceRelease(parseArguments(process.argv.slice(2)));
  process.stdout.write(`${canonicalize({
    archiveSha256: result.archiveSha256,
    fileCount: result.fileCount,
    healthChecked: result.healthChecked,
    schemaVersion: 1,
    serviceVersion: result.serviceVersion,
    shellChecked: result.shellChecked,
  })}\n`);
}
