import { createHash, randomBytes } from 'node:crypto';
import {
  link,
  lstat,
  mkdir,
  open,
  readFile,
  unlink,
} from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { inflateRawSync } from 'node:zlib';

const ADDON_ENTRY = 'build/Release/better_sqlite3.node';
const MAX_ARCHIVE_BYTES = 4 * 1024 * 1024;
const MAX_ADDON_BYTES = 16 * 1024 * 1024;
const MAX_TAR_BYTES = MAX_ADDON_BYTES + 2048;
const HEX_64 = /^[0-9a-f]{64}$/u;
const SAFE_ARCHIVE = /^[A-Za-z0-9][A-Za-z0-9._-]*\.tar\.gz$/u;
const FROZEN_DARWIN_PIN = Object.freeze({
  architecture: 'arm64',
  archive: 'better-sqlite3-v12.2.0-node-v137-darwin-arm64.tar.gz',
  archiveBytes: 944001,
  archiveSha256: '50ec0aa2c44c9e4b2d93308b5e43f7dd5b11409dd72464f1b44acf5e692bccab',
  modulesAbi: '137',
  platform: 'darwin',
  url: 'https://github.com/WiseLibs/better-sqlite3/releases/download/v12.2.0/better-sqlite3-v12.2.0-node-v137-darwin-arm64.tar.gz',
  version: '12.2.0',
});
const FROZEN_LINUX_PIN = Object.freeze({
  architecture: 'x64',
  archive: 'better-sqlite3-v12.2.0-node-v137-linux-x64.tar.gz',
  archiveBytes: 1067842,
  archiveSha256: '69f8bdfb23f3381df6c0867eddf5980773d04fb8619ffd9090ac724c1e95457b',
  modulesAbi: '137',
  platform: 'linux',
  url: 'https://github.com/WiseLibs/better-sqlite3/releases/download/v12.2.0/better-sqlite3-v12.2.0-node-v137-linux-x64.tar.gz',
  version: '12.2.0',
});
const FROZEN_CONFIGURATION = Object.freeze({
  prebuilds: Object.freeze([FROZEN_DARWIN_PIN, FROZEN_LINUX_PIN]),
  version: '12.2.0',
});
const PIN_KEYS = Object.freeze(Object.keys(FROZEN_LINUX_PIN).sort());
const SCRIPT_DIRECTORY = dirname(fileURLToPath(import.meta.url));
const REPOSITORY_DIRECTORY = resolve(SCRIPT_DIRECTORY, '..');

function fail(message) {
  throw new Error(message);
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function canonical(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) =>
    `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}

function validatePin(pin) {
  if (!pin || typeof pin !== 'object' || Array.isArray(pin)
      || canonical(Object.keys(pin).sort()) !== canonical(PIN_KEYS)) {
    fail('better-sqlite3 prebuild pin has an invalid shape');
  }
  const supportedPlatform = (pin.architecture === 'x64' && pin.platform === 'linux')
    || (pin.architecture === 'arm64' && pin.platform === 'darwin');
  if (!supportedPlatform || pin.modulesAbi !== '137' || pin.version !== '12.2.0') {
    fail('better-sqlite3 prebuild pin has an invalid runtime binding');
  }
  if (!SAFE_ARCHIVE.test(pin.archive)
      || !Number.isSafeInteger(pin.archiveBytes)
      || pin.archiveBytes <= 0 || pin.archiveBytes > MAX_ARCHIVE_BYTES
      || !HEX_64.test(pin.archiveSha256)) {
    fail('better-sqlite3 prebuild pin has invalid archive metadata');
  }
  let url;
  try {
    url = new URL(pin.url);
  } catch {
    fail('better-sqlite3 prebuild pin URL is invalid');
  }
  if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash
      || url.pathname.split('/').at(-1) !== pin.archive) {
    fail('better-sqlite3 prebuild pin URL is invalid');
  }
  return { ...pin };
}

export function selectBetterSqlite3Prebuild(toolchain, runtime) {
  if (canonical(toolchain?.betterSqlite3) !== canonical(FROZEN_CONFIGURATION)) {
    fail('better-sqlite3 prebuilds do not match the frozen pins');
  }
  const pin = FROZEN_CONFIGURATION.prebuilds.find((candidate) =>
    runtime?.architecture === candidate.architecture
      && runtime?.modulesAbi === candidate.modulesAbi
      && runtime?.platform === candidate.platform);
  if (!pin) {
    fail('better-sqlite3 prebuild does not match the release runtime');
  }
  validatePin(pin);
  return { ...pin };
}

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let index = 0; index < table.length; index += 1) {
    let value = index;
    for (let bit = 0; bit < 8; bit += 1) {
      value = (value & 1) === 1 ? 0xedb88320 ^ (value >>> 1) : value >>> 1;
    }
    table[index] = value >>> 0;
  }
  return table;
})();

function crc32(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) value = CRC_TABLE[(value ^ byte) & 0xff] ^ (value >>> 8);
  return (value ^ 0xffffffff) >>> 0;
}

function inflateSingleGzipMember(archive) {
  if (archive.length < 18 || archive[0] !== 0x1f || archive[1] !== 0x8b
      || archive[2] !== 8 || archive[3] !== 0) {
    fail('better-sqlite3 prebuild gzip header is invalid or ambiguous');
  }
  let result;
  try {
    result = inflateRawSync(archive.subarray(10), {
      info: true,
      maxOutputLength: MAX_TAR_BYTES,
    });
  } catch {
    fail('better-sqlite3 prebuild gzip payload is invalid or too large');
  }
  const compressedBytes = result.engine?.bytesWritten;
  if (!Number.isSafeInteger(compressedBytes) || compressedBytes <= 0) {
    fail('better-sqlite3 prebuild gzip boundary is unavailable');
  }
  const trailerOffset = 10 + compressedBytes;
  if (trailerOffset + 8 !== archive.length) {
    fail('better-sqlite3 prebuild gzip has a trailing or concatenated member');
  }
  const tar = Buffer.from(result.buffer);
  if (archive.readUInt32LE(trailerOffset) !== crc32(tar)
      || archive.readUInt32LE(trailerOffset + 4) !== (tar.length >>> 0)) {
    fail('better-sqlite3 prebuild gzip trailer is invalid');
  }
  return tar;
}

function tarString(header, offset, length, label) {
  const field = header.subarray(offset, offset + length);
  const end = field.indexOf(0);
  const used = end === -1 ? field : field.subarray(0, end);
  if (end !== -1 && !field.subarray(end).every((byte) => byte === 0)) {
    fail(`better-sqlite3 prebuild tar ${label} is ambiguous`);
  }
  if (used.some((byte) => byte < 0x20 || byte > 0x7e)) {
    fail(`better-sqlite3 prebuild tar ${label} is invalid`);
  }
  return used.toString('ascii');
}

function tarOctal(header, offset, length, label) {
  const field = header.subarray(offset, offset + length);
  if ((field[0] & 0x80) !== 0) fail(`better-sqlite3 prebuild tar ${label} is not octal`);
  const text = field.toString('ascii').replace(/[\0 ]+$/u, '');
  if (!/^[0-7]+$/u.test(text)) fail(`better-sqlite3 prebuild tar ${label} is invalid`);
  const value = Number.parseInt(text, 8);
  if (!Number.isSafeInteger(value)) fail(`better-sqlite3 prebuild tar ${label} is too large`);
  return value;
}

function verifyTarChecksum(header) {
  const expected = tarOctal(header, 148, 8, 'checksum');
  let actual = 0;
  for (let offset = 0; offset < header.length; offset += 1) {
    actual += offset >= 148 && offset < 156 ? 0x20 : header[offset];
  }
  if (actual !== expected) fail('better-sqlite3 prebuild tar checksum is invalid');
}

function extractSingleAddon(tar) {
  if (tar.length < 1536 || tar.length % 512 !== 0) {
    fail('better-sqlite3 prebuild tar ending is invalid');
  }
  const header = tar.subarray(0, 512);
  if (header.every((byte) => byte === 0)) fail('better-sqlite3 prebuild tar has no addon entry');
  verifyTarChecksum(header);
  const name = tarString(header, 0, 100, 'name');
  const prefix = tarString(header, 345, 155, 'prefix');
  const path = prefix ? `${prefix}/${name}` : name;
  if (path !== ADDON_ENTRY) fail('better-sqlite3 prebuild tar entry path is invalid');
  if (header[156] !== 0x30 || tarString(header, 157, 100, 'link name') !== '') {
    fail('better-sqlite3 prebuild tar addon must be a regular file');
  }
  const size = tarOctal(header, 124, 12, 'size');
  if (size <= 0 || size > MAX_ADDON_BYTES) {
    fail('better-sqlite3 prebuild tar addon size is not bounded');
  }
  const dataEnd = 512 + size;
  const paddedEnd = 512 + Math.ceil(size / 512) * 512;
  if (paddedEnd + 1024 !== tar.length) {
    if (paddedEnd + 512 <= tar.length
        && !tar.subarray(paddedEnd, paddedEnd + 512).every((byte) => byte === 0)) {
      fail('better-sqlite3 prebuild tar must contain exactly one entry');
    }
    fail('better-sqlite3 prebuild tar ending has trailing ambiguity');
  }
  if (!tar.subarray(dataEnd, paddedEnd).every((byte) => byte === 0)) {
    fail('better-sqlite3 prebuild tar data padding is invalid');
  }
  if (!tar.subarray(paddedEnd).every((byte) => byte === 0)) {
    fail('better-sqlite3 prebuild tar end blocks are invalid');
  }
  return Buffer.from(tar.subarray(512, dataEnd));
}

export function inspectBetterSqlite3PrebuildArchive(archiveBytes, inputPin) {
  const pin = validatePin(inputPin);
  if (!(archiveBytes instanceof Uint8Array)) {
    fail('better-sqlite3 prebuild archive must be bytes');
  }
  const archive = Buffer.from(archiveBytes);
  if (archive.length !== pin.archiveBytes) {
    fail('better-sqlite3 prebuild archive size does not match the pin');
  }
  if (sha256(archive) !== pin.archiveSha256) {
    fail('better-sqlite3 prebuild archive SHA-256 does not match the pin');
  }
  return extractSingleAddon(inflateSingleGzipMember(archive));
}

async function downloadPinnedArchive(pin, fetchImpl) {
  let response;
  try {
    response = await fetchImpl(pin.url, {
      headers: { accept: 'application/octet-stream' },
      redirect: 'follow',
    });
  } catch {
    fail('better-sqlite3 prebuild download failed');
  }
  if (!response || response.ok !== true || response.status !== 200 || !response.body) {
    fail('better-sqlite3 prebuild download response is invalid');
  }
  const contentLength = response.headers?.get?.('content-length');
  if (contentLength !== null && contentLength !== undefined
      && contentLength !== String(pin.archiveBytes)) {
    fail('better-sqlite3 prebuild download content length does not match the pin');
  }
  const chunks = [];
  let total = 0;
  try {
    for await (const inputChunk of response.body) {
      const chunk = Buffer.from(inputChunk);
      total += chunk.length;
      if (total > pin.archiveBytes) fail('better-sqlite3 prebuild download is too large');
      chunks.push(chunk);
    }
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('better-sqlite3')) throw error;
    fail('better-sqlite3 prebuild download body failed');
  }
  if (total !== pin.archiveBytes) fail('better-sqlite3 prebuild download is truncated');
  return Buffer.concat(chunks, total);
}

async function stageAddonAtomically(addon, destinationPath) {
  const parent = dirname(destinationPath);
  await mkdir(parent, { recursive: true, mode: 0o755 });
  const parentStatus = await lstat(parent);
  if (!parentStatus.isDirectory() || parentStatus.isSymbolicLink()) {
    fail('better-sqlite3 addon destination parent must be a real directory');
  }
  const existing = await lstat(destinationPath).catch((error) => {
    if (error?.code === 'ENOENT') return null;
    throw error;
  });
  if (existing) fail('better-sqlite3 addon destination already exists');
  const temporary = `${destinationPath}.verified-${process.pid}-${randomBytes(12).toString('hex')}`;
  let handle;
  let linked = false;
  try {
    handle = await open(temporary, 'wx', 0o644);
    await handle.writeFile(addon);
    await handle.sync();
    await handle.close();
    handle = null;
    await link(temporary, destinationPath);
    linked = true;
  } finally {
    if (handle) await handle.close().catch(() => {});
    await unlink(temporary).catch((error) => {
      if (error?.code !== 'ENOENT') throw error;
    });
  }
  if (!linked) fail('better-sqlite3 addon could not be staged atomically');
  const status = await lstat(destinationPath);
  if (!status.isFile() || status.isSymbolicLink() || status.size !== addon.length) {
    fail('staged better-sqlite3 addon is invalid');
  }
}

export async function acquireBetterSqlite3Prebuild({
  destinationPath,
  fetchImpl = globalThis.fetch,
  pin: inputPin,
}) {
  const pin = validatePin(inputPin);
  if (typeof destinationPath !== 'string' || destinationPath.length === 0
      || typeof fetchImpl !== 'function') {
    fail('better-sqlite3 prebuild acquisition arguments are invalid');
  }
  const archive = await downloadPinnedArchive(pin, fetchImpl);
  const addon = inspectBetterSqlite3PrebuildArchive(archive, pin);
  await stageAddonAtomically(addon, destinationPath);
  return {
    addonBytes: addon.length,
    addonSha256: sha256(addon),
    archiveSha256: sha256(archive),
    path: destinationPath,
  };
}

export const BETTER_SQLITE3_ADDON_ENTRY = ADDON_ENTRY;
export const FROZEN_BETTER_SQLITE3_PREBUILDS = FROZEN_CONFIGURATION;

async function runCli() {
  if (process.argv.length !== 2) fail('better-sqlite3 prebuild acquisition accepts no arguments');
  const toolchain = JSON.parse(await readFile(
    resolve(REPOSITORY_DIRECTORY, 'release/toolchain.v1.json'),
    'utf8',
  ));
  const pin = selectBetterSqlite3Prebuild(toolchain, {
    architecture: process.arch,
    modulesAbi: process.versions.modules,
    platform: process.platform,
  });
  const result = await acquireBetterSqlite3Prebuild({
    destinationPath: resolve(REPOSITORY_DIRECTORY, 'node_modules/better-sqlite3', ADDON_ENTRY),
    pin,
  });
  process.stdout.write(`${JSON.stringify({ ...result, path: ADDON_ENTRY })}\n`);
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  runCli().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
