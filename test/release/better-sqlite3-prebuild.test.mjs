import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  lstat,
  mkdtemp,
  readFile,
  rm,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { gzipSync } from 'node:zlib';

const moduleUrl = new URL('../../scripts/acquire-better-sqlite3-prebuild.mjs', import.meta.url);
const acquisition = await import(moduleUrl).catch((loadError) => ({ loadError }));
const EXPECTED_PIN = Object.freeze({
  architecture: 'x64',
  archive: 'better-sqlite3-v12.2.0-node-v137-linux-x64.tar.gz',
  archiveBytes: 1067842,
  archiveSha256: '69f8bdfb23f3381df6c0867eddf5980773d04fb8619ffd9090ac724c1e95457b',
  modulesAbi: '137',
  platform: 'linux',
  url: 'https://github.com/WiseLibs/better-sqlite3/releases/download/v12.2.0/better-sqlite3-v12.2.0-node-v137-linux-x64.tar.gz',
  version: '12.2.0',
});
const EXPECTED_DARWIN_PIN = Object.freeze({
  architecture: 'arm64',
  archive: 'better-sqlite3-v12.2.0-node-v137-darwin-arm64.tar.gz',
  archiveBytes: 944001,
  archiveSha256: '50ec0aa2c44c9e4b2d93308b5e43f7dd5b11409dd72464f1b44acf5e692bccab',
  modulesAbi: '137',
  platform: 'darwin',
  url: 'https://github.com/WiseLibs/better-sqlite3/releases/download/v12.2.0/better-sqlite3-v12.2.0-node-v137-darwin-arm64.tar.gz',
  version: '12.2.0',
});
const EXPECTED_RUNTIME = Object.freeze({
  architecture: 'x64',
  modulesAbi: '137',
  platform: 'linux',
});
const ADDON_PATH = 'build/Release/better_sqlite3.node';

function requireFunction(name) {
  assert.equal(
    typeof acquisition[name],
    'function',
    acquisition.loadError?.message ?? `${name} must be exported`,
  );
  return acquisition[name];
}

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function writeField(header, offset, length, value) {
  const bytes = Buffer.from(value, 'ascii');
  assert.ok(bytes.length <= length);
  bytes.copy(header, offset);
}

function writeOctal(header, offset, length, value) {
  writeField(header, offset, length, `${value.toString(8).padStart(length - 2, '0')} \0`);
}

function tarHeader({ bytes, link = '', path, size = bytes.length, type = '0' }) {
  const header = Buffer.alloc(512);
  writeField(header, 0, 100, path);
  writeOctal(header, 100, 8, 0o755);
  writeOctal(header, 108, 8, 0);
  writeOctal(header, 116, 8, 0);
  writeOctal(header, 124, 12, size);
  writeOctal(header, 136, 12, 0);
  header.fill(0x20, 148, 156);
  header[156] = type.charCodeAt(0);
  writeField(header, 157, 100, link);
  writeField(header, 257, 6, 'ustar\0');
  writeField(header, 263, 2, '00');
  let checksum = 0;
  for (const byte of header) checksum += byte;
  writeField(header, 148, 8, `${checksum.toString(8).padStart(6, '0')}\0 `);
  return header;
}

function prebuild(entries, { endBlocks = 2, trailing = Buffer.alloc(0) } = {}) {
  const parts = [];
  for (const entry of entries) {
    parts.push(tarHeader(entry), entry.bytes);
    const padding = (512 - (entry.bytes.length % 512)) % 512;
    if (padding > 0) parts.push(Buffer.alloc(padding));
  }
  parts.push(Buffer.alloc(endBlocks * 512), trailing);
  return gzipSync(Buffer.concat(parts), { level: 9, mtime: 0 });
}

function fixtureArchive(overrides = {}, options) {
  const entry = {
    bytes: Buffer.from('verified fixture native addon bytes\n'),
    path: ADDON_PATH,
    type: '0',
    ...overrides,
  };
  return { addon: entry.bytes, archive: prebuild([entry], options) };
}

function fixturePin(archive) {
  return {
    ...EXPECTED_PIN,
    archive: 'fixture-node-v137-linux-x64.tar.gz',
    archiveBytes: archive.length,
    archiveSha256: sha256(archive),
    url: 'https://fixtures.invalid/fixture-node-v137-linux-x64.tar.gz',
  };
}

function responseFor(bytes, duringRead = () => {}) {
  return {
    body: (async function* body() {
      duringRead();
      yield bytes.subarray(0, Math.ceil(bytes.length / 2));
      duringRead();
      yield bytes.subarray(Math.ceil(bytes.length / 2));
    }()),
    headers: new Map([['content-length', String(bytes.length)]]),
    ok: true,
    status: 200,
  };
}

test('freezes exact better-sqlite3 URL, name, size, digest, ABI, and platform selection', async () => {
  const select = requireFunction('selectBetterSqlite3Prebuild');
  const toolchain = JSON.parse(await readFile(
    new URL('../../release/toolchain.v1.json', import.meta.url),
  ));
  assert.deepEqual(select(toolchain, EXPECTED_RUNTIME), EXPECTED_PIN);
  assert.deepEqual(select(toolchain, {
    architecture: 'arm64', modulesAbi: '137', platform: 'darwin',
  }), EXPECTED_DARWIN_PIN);

  for (const [field, value] of [
    ['architecture', 'arm64'],
    ['archive', 'other.tar.gz'],
    ['archiveBytes', EXPECTED_PIN.archiveBytes + 1],
    ['archiveSha256', '0'.repeat(64)],
    ['modulesAbi', '136'],
    ['platform', 'darwin'],
    ['url', 'https://example.invalid/prebuild.tar.gz'],
    ['version', '12.2.1'],
  ]) {
    const changed = structuredClone(toolchain);
    changed.betterSqlite3.prebuilds[1][field] = value;
    assert.throws(() => select(changed, EXPECTED_RUNTIME), /frozen|pin|prebuild/u, field);
  }
  const reordered = structuredClone(toolchain);
  reordered.betterSqlite3.prebuilds.reverse();
  assert.throws(() => select(reordered, EXPECTED_RUNTIME), /frozen|pin|prebuild/u);
  for (const [field, value] of [
    ['architecture', 'arm64'],
    ['modulesAbi', '136'],
    ['platform', 'darwin'],
  ]) {
    assert.throws(
      () => select(toolchain, { ...EXPECTED_RUNTIME, [field]: value }),
      /runtime|prebuild/u,
      field,
    );
  }
});

test('accepts only one bounded regular addon entry with an unambiguous gzip/tar ending', () => {
  const inspect = requireFunction('inspectBetterSqlite3PrebuildArchive');
  const fixture = fixtureArchive();
  assert.deepEqual(inspect(fixture.archive, fixturePin(fixture.archive)), fixture.addon);

  const invalid = [
    [fixtureArchive({ type: '2', link: ADDON_PATH }), /regular/u],
    [fixtureArchive({ path: '../better_sqlite3.node' }), /path|entry/u],
    [{
      archive: prebuild([
        { bytes: fixture.addon, path: ADDON_PATH, type: '0' },
        { bytes: Buffer.from('extra'), path: 'extra', type: '0' },
      ]),
    }, /exactly one|extra/u],
    [fixtureArchive({ bytes: Buffer.alloc(0) }), /bounded|size/u],
    [fixtureArchive({}, { endBlocks: 1 }), /end|trailing/u],
    [fixtureArchive({}, { endBlocks: 2, trailing: Buffer.alloc(512) }), /end|trailing/u],
  ];
  for (const [{ archive }, expected] of invalid) {
    assert.throws(() => inspect(archive, fixturePin(archive)), expected);
  }

  const secondMember = gzipSync(Buffer.alloc(1024), { mtime: 0 });
  const concatenated = Buffer.concat([fixture.archive, secondMember]);
  assert.throws(
    () => inspect(concatenated, fixturePin(concatenated)),
    /gzip|trailing|member/u,
  );
});

test('rejects archive tampering before staging any downloaded addon bytes', async (t) => {
  const acquire = requireFunction('acquireBetterSqlite3Prebuild');
  const parent = await mkdtemp(join(tmpdir(), 'sdn-sqlite-prebuild-tamper-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const destinationPath = join(parent, ADDON_PATH);
  const fixture = fixtureArchive();
  const pin = fixturePin(fixture.archive);
  const tampered = Buffer.from(fixture.archive);
  tampered[Math.floor(tampered.length / 2)] ^= 0x01;
  let requestedUrl = null;
  const stagingObservations = [];
  await assert.rejects(
    acquire({
      destinationPath,
      fetchImpl: async (url) => {
        requestedUrl = url;
        return responseFor(tampered, () => {
          stagingObservations.push(assert.rejects(lstat(destinationPath), { code: 'ENOENT' }));
        });
      },
      pin,
    }),
    /SHA-256|digest/u,
  );
  await Promise.all(stagingObservations);
  assert.equal(requestedUrl, pin.url);
  await assert.rejects(lstat(destinationPath), { code: 'ENOENT' });
});

test('stages the fully verified addon atomically and never runs a downloaded program', async (t) => {
  const acquire = requireFunction('acquireBetterSqlite3Prebuild');
  const parent = await mkdtemp(join(tmpdir(), 'sdn-sqlite-prebuild-stage-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const destinationPath = join(parent, ADDON_PATH);
  const fixture = fixtureArchive();
  const pin = fixturePin(fixture.archive);
  const originalDlopen = process.dlopen;
  let dlopenCalls = 0;
  process.dlopen = (...arguments_) => {
    dlopenCalls += 1;
    return originalDlopen(...arguments_);
  };
  t.after(() => { process.dlopen = originalDlopen; });
  const result = await acquire({
    destinationPath,
    fetchImpl: async () => responseFor(fixture.archive),
    pin,
  });
  assert.deepEqual(await readFile(destinationPath), fixture.addon);
  assert.equal(dlopenCalls, 0);
  assert.equal((await lstat(destinationPath)).mode & 0o111, 0);
  assert.equal(result.addonBytes, fixture.addon.length);
  assert.equal(result.addonSha256, sha256(fixture.addon));
  assert.equal(result.archiveSha256, pin.archiveSha256);
  assert.equal(result.path, destinationPath);
});
