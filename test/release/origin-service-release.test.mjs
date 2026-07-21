import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import {
  chmod,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  utimes,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { gunzipSync, gzipSync } from 'node:zlib';

import {
  ARCHIVE_BASENAME,
  ORIGIN_SERVICE_VERSION,
  RUNTIME_DEPENDENCY_FILES,
  buildOriginServiceArchive,
  canonicalize,
  compileOriginServiceServer,
} from '../../scripts/build-origin-service-release.mjs';
import {
  inspectOriginServiceArchive,
  verifyOriginServiceRelease,
} from '../../scripts/verify-origin-service-release.mjs';

const FIXTURE_RUNTIME = Object.freeze({
  architecture: 'x64',
  minimumGlibc: '2.28',
  modulesAbi: '137',
  napiVersion: '10',
  nodeVersion: '24.18.0',
  platform: 'linux',
});
const OBSERVED_RUNTIME = Object.freeze({
  ...FIXTURE_RUNTIME,
  glibcVersion: '2.39',
});
const EXPECTED_RUNTIME_DEPENDENCY_FILES = Object.freeze([
  'node_modules/better-sqlite3/LICENSE',
  'node_modules/better-sqlite3/build/Release/better_sqlite3.node',
  'node_modules/better-sqlite3/lib/database.js',
  'node_modules/better-sqlite3/lib/index.js',
  'node_modules/better-sqlite3/lib/methods/aggregate.js',
  'node_modules/better-sqlite3/lib/methods/backup.js',
  'node_modules/better-sqlite3/lib/methods/function.js',
  'node_modules/better-sqlite3/lib/methods/inspect.js',
  'node_modules/better-sqlite3/lib/methods/pragma.js',
  'node_modules/better-sqlite3/lib/methods/serialize.js',
  'node_modules/better-sqlite3/lib/methods/table.js',
  'node_modules/better-sqlite3/lib/methods/transaction.js',
  'node_modules/better-sqlite3/lib/methods/wrappers.js',
  'node_modules/better-sqlite3/lib/sqlite-error.js',
  'node_modules/better-sqlite3/lib/util.js',
  'node_modules/better-sqlite3/package.json',
  'node_modules/bindings/LICENSE.md',
  'node_modules/bindings/bindings.js',
  'node_modules/bindings/package.json',
  'node_modules/file-uri-to-path/LICENSE',
  'node_modules/file-uri-to-path/index.js',
  'node_modules/file-uri-to-path/package.json',
].sort());
const HASHED_ASSET = /^wallet-origin\.([0-9a-f]{64})\.(css|js|wasm)$/u;

function sha256(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function sha384(bytes) {
  return `sha384-${createHash('sha384').update(bytes).digest('base64')}`;
}

function fixtureLinuxAddon() {
  const bytes = Buffer.alloc(256);
  bytes.set([0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01], 0);
  bytes.writeUInt16LE(62, 18);
  bytes.write('GLIBC_2.28\0', 64, 'ascii');
  bytes.write('fixture-better-sqlite3-node-abi-137', 96, 'ascii');
  return bytes;
}

async function writeFixtureFile(root, path, bytes) {
  const target = resolve(root, path);
  await mkdir(dirname(target), { recursive: true });
  await writeFile(target, bytes);
}

async function createFixtureTree(parent, suffix = '') {
  const root = join(parent, `source${suffix}`);
  await mkdir(root, { recursive: true });
  const css = Buffer.from(':root{--fixture:1}\n');
  const wasm = Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00, 0x0b]);
  const wasmName = `wallet-origin.${sha256(wasm)}.wasm`;
  const javascript = Buffer.from(`const wasm = new URL("./${wasmName}", import.meta.url);\nvoid wasm;\n`);
  const cssName = `wallet-origin.${sha256(css)}.css`;
  const javascriptName = `wallet-origin.${sha256(javascript)}.js`;
  const html = Buffer.from('<!doctype html>\n<html><head>'
    + `<link rel="stylesheet" href="/assets/${cssName}" integrity="${sha384(css)}" crossorigin="anonymous">`
    + '</head><body><main data-wallet-origin-root></main>'
    + `<script type="module" src="/assets/${javascriptName}" integrity="${sha384(javascript)}" crossorigin="anonymous"></script>`
    + '</body></html>\n');
  const packageMetadata = {
    dependencies: { 'better-sqlite3': '12.2.0' },
    engines: { node: '24.18.0' },
    name: '@sdn/wallet-origin-service',
    private: true,
    type: 'module',
    version: ORIGIN_SERVICE_VERSION,
  };
  const unsignedRegistry = {
    clients: [],
    schemaVersion: 1,
  };
  const registry = {
    clients: unsignedRegistry.clients,
    registryReleaseSha256: sha256(Buffer.from(canonicalize(unsignedRegistry))),
    schemaVersion: unsignedRegistry.schemaVersion,
  };

  await writeFixtureFile(root, 'LICENSE', 'fixture license\n');
  await writeFixtureFile(root, 'package.json', `${canonicalize(packageMetadata)}\n`);
  await writeFixtureFile(root, 'registry/client-registry.v1.json', `${canonicalize(registry)}\n`);
  await writeFixtureFile(root, 'wallet-origin/index.html', html);
  await writeFixtureFile(root, `wallet-origin/assets/${cssName}`, css);
  await writeFixtureFile(root, `wallet-origin/assets/${javascriptName}`, javascript);
  await writeFixtureFile(root, `wallet-origin/assets/${wasmName}`, wasm);

  const compileRoot = join(parent, `compile${suffix}`);
  const relaySourcePath = resolve(compileRoot, 'wallet-ui/relay/src/server.ts');
  const wireSourcePath = resolve(compileRoot, 'wallet-ui/client/wire.mjs');
  await writeFixtureFile(compileRoot, 'wallet-ui/client/wire.mjs', `export function healthBody() {
  return '{"schemaVersion":1,"status":"ok"}';
}
`);
  await writeFixtureFile(compileRoot, 'wallet-ui/relay/src/server.ts', `import { createServer, type Server } from 'node:http';
import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
interface WireModule { healthBody(): string; }
const wire = await import(new URL('../../../client/wire.mjs', import.meta.url).href) as WireModule;
export function createRelayServer(options: {databasePath: string}): Server {
  mkdirSync(dirname(options.databasePath), { recursive: true });
  const database = Buffer.alloc(4096);
  database.write('SQLite format 3\\0', 0, 'binary');
  writeFileSync(options.databasePath, database);
  return createServer((request, response) => {
    if (request.method === 'GET' && request.url === '/healthz') {
      const body = Buffer.from(wire.healthBody());
      response.writeHead(200, {'content-length': body.length, 'content-type': 'application/json; charset=utf-8'});
      response.end(body);
      return;
    }
    response.writeHead(404, {'content-length': 0});
    response.end();
  });
}
function startFromEnvironment(): void {}
if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  startFromEnvironment();
}
`);
  await compileOriginServiceServer({
    assetNames: [cssName, javascriptName, wasmName],
    relaySourcePath,
    target: resolve(root, 'service/server.mjs'),
    wireSourcePath,
  });
  const compiledServer = await readFile(resolve(root, 'service/server.mjs'), 'utf8');
  assert.equal(compiledServer.includes('../../../client/wire.mjs'), false);
  assert.equal(compiledServer.includes('new URL("../../../client/wire.mjs"'), false);

  for (const path of EXPECTED_RUNTIME_DEPENDENCY_FILES) {
    let bytes;
    if (path.endsWith('better_sqlite3.node')) {
      bytes = fixtureLinuxAddon();
    } else if (path === 'node_modules/better-sqlite3/package.json') {
      bytes = Buffer.from(`${canonicalize({
        dependencies: { bindings: '1.5.0' },
        license: 'MIT',
        main: 'lib/index.js',
        name: 'better-sqlite3',
        version: '12.2.0',
      })}\n`);
    } else if (path === 'node_modules/bindings/package.json') {
      bytes = Buffer.from(`${canonicalize({
        dependencies: { 'file-uri-to-path': '1.0.0' },
        license: 'MIT',
        main: 'bindings.js',
        name: 'bindings',
        version: '1.5.0',
      })}\n`);
    } else if (path === 'node_modules/file-uri-to-path/package.json') {
      bytes = Buffer.from(`${canonicalize({
        license: 'MIT',
        main: 'index.js',
        name: 'file-uri-to-path',
        version: '1.0.0',
      })}\n`);
    } else {
      bytes = Buffer.from(`fixture:${path}\n`);
    }
    await writeFixtureFile(root, path, bytes);
  }
  return { cssName, html, javascriptName, root, wasmName };
}

async function buildFixture(parent, suffix = '') {
  const fixture = await createFixtureTree(parent, suffix);
  const outputDirectory = join(parent, `output${suffix}`);
  const result = await buildOriginServiceArchive({
    outputDirectory,
    runtime: FIXTURE_RUNTIME,
    sourceDirectory: fixture.root,
    version: ORIGIN_SERVICE_VERSION,
  });
  return { ...fixture, ...result, outputDirectory };
}

async function replaceFixtureJavascript(fixture, javascript) {
  const bytes = Buffer.from(javascript);
  const oldPath = resolve(fixture.root, `wallet-origin/assets/${fixture.javascriptName}`);
  const oldBytes = await readFile(oldPath);
  const nextName = `wallet-origin.${sha256(bytes)}.js`;
  const htmlPath = resolve(fixture.root, 'wallet-origin/index.html');
  const oldHtml = await readFile(htmlPath, 'utf8');
  const nextHtml = oldHtml
    .replace(fixture.javascriptName, nextName)
    .replace(sha384(oldBytes), sha384(bytes));
  await rm(oldPath);
  await writeFixtureFile(fixture.root, `wallet-origin/assets/${nextName}`, bytes);
  await writeFile(htmlPath, nextHtml);
  fixture.javascriptName = nextName;
}

function readTarEntries(archiveBytes) {
  const tar = gunzipSync(archiveBytes);
  const entries = [];
  let offset = 0;
  while (offset + 512 <= tar.length) {
    const header = tar.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const text = (start, length) => header.subarray(start, start + length)
      .toString('utf8').replace(/\0.*$/su, '');
    const name = text(0, 100);
    const prefix = text(345, 155);
    const path = prefix ? `${prefix}/${name}` : name;
    const octal = (start, length) => Number.parseInt(text(start, length).trim() || '0', 8);
    const size = octal(124, 12);
    entries.push({
      bytes: Buffer.from(tar.subarray(offset + 512, offset + 512 + size)),
      headerOffset: offset,
      mode: octal(100, 8),
      mtime: octal(136, 12),
      path,
      type: String.fromCharCode(header[156] || 0),
    });
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return { entries, tar };
}

function writeTarChecksum(header) {
  header.fill(0x20, 148, 156);
  let checksum = 0;
  for (const byte of header) checksum += byte;
  const value = checksum.toString(8).padStart(6, '0');
  header.write(value, 148, 6, 'ascii');
  header[154] = 0;
  header[155] = 0x20;
}

function forgedArchive(archiveBytes, mutate) {
  const { entries, tar } = readTarEntries(archiveBytes);
  mutate({ entries, tar });
  return gzipSync(tar, { level: 9, mtime: 0 });
}

async function assertRejectsArchive(parent, archiveBytes, pattern) {
  const archivePath = join(parent, `forged-${createHash('sha1').update(archiveBytes).digest('hex')}.tar.gz`);
  await writeFile(archivePath, archiveBytes);
  await assert.rejects(
    verifyOriginServiceRelease({
      archivePath,
      observedRuntime: OBSERVED_RUNTIME,
      requireChecksum: false,
      runHealthCheck: false,
    }),
    pattern,
  );
}

test('builds a byte-identical sorted archive with normalized headers and JCS metadata', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-origin-release-test-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const first = await buildFixture(parent, '-one');
  assert.deepEqual(RUNTIME_DEPENDENCY_FILES, EXPECTED_RUNTIME_DEPENDENCY_FILES);
  for (const path of [
    resolve(first.root, 'service/server.mjs'),
    resolve(first.root, 'wallet-origin/index.html'),
  ]) {
    await chmod(path, 0o777);
    await utimes(path, new Date('2037-01-01T00:00:00Z'), new Date('2037-01-01T00:00:00Z'));
  }
  const secondOutput = join(parent, 'output-two');
  const second = await buildOriginServiceArchive({
    outputDirectory: secondOutput,
    runtime: FIXTURE_RUNTIME,
    sourceDirectory: first.root,
    version: ORIGIN_SERVICE_VERSION,
  });
  const firstBytes = await readFile(first.archivePath);
  const secondBytes = await readFile(second.archivePath);
  assert.deepEqual(secondBytes, firstBytes);
  assert.equal(first.archiveName, ARCHIVE_BASENAME);
  assert.match(first.sha256, /^[0-9a-f]{64}$/u);
  assert.equal(
    await readFile(first.checksumPath, 'utf8'),
    `${first.sha256}  ${ARCHIVE_BASENAME}\n`,
  );

  const { entries } = readTarEntries(firstBytes);
  const paths = entries.map(({ path }) => path);
  assert.deepEqual(paths, [...paths].sort());
  assert.equal(new Set(paths).size, paths.length);
  assert.ok(entries.every(({ mode }) => mode === 0o644));
  assert.ok(entries.every(({ mtime }) => mtime === 0));
  assert.ok(entries.every(({ type }) => type === '0'));

  const manifestBytes = entries.find(({ path }) => path === 'manifest.v1.json')?.bytes;
  assert.ok(manifestBytes);
  const manifest = JSON.parse(manifestBytes);
  assert.equal(manifestBytes.toString('utf8'), `${canonicalize(manifest)}\n`);
  assert.deepEqual(Object.keys(manifest), [
    'files', 'routes', 'runtime', 'schemaVersion', 'serviceVersion',
  ]);
  assert.deepEqual(manifest.runtime, {
    architecture: 'x64',
    betterSqlite3Addon: {
      path: 'node_modules/better-sqlite3/build/Release/better_sqlite3.node',
      sha256: sha256(fixtureLinuxAddon()),
    },
    minimumGlibc: '2.28',
    modulesAbi: '137',
    napiVersion: '10',
    nodeVersion: '24.18.0',
    platform: 'linux',
  });
  assert.deepEqual(manifest.routes, {
    root: '/',
    transactionPattern: '^/transaction/[0-9a-f]{64}$',
  });
  assert.equal(manifest.schemaVersion, 1);
  assert.equal(manifest.serviceVersion, ORIGIN_SERVICE_VERSION);
  assert.deepEqual(
    manifest.files.map(({ path }) => path),
    paths.filter((path) => path !== 'manifest.v1.json'),
  );
  for (const record of manifest.files) {
    assert.deepEqual(Object.keys(record), ['bytes', 'mode', 'path', 'sha256']);
    const archived = entries.find(({ path }) => path === record.path);
    assert.equal(record.bytes, archived.bytes.length);
    assert.equal(record.mode, 0o644);
    assert.equal(record.sha256, sha256(archived.bytes));
  }
});

test('verifies exact bytes and starts the archived service against only a temporary database', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-origin-release-health-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const fixture = await buildFixture(parent);
  const result = await verifyOriginServiceRelease({
    archivePath: fixture.archivePath,
    observedRuntime: OBSERVED_RUNTIME,
  });
  assert.equal(result.archiveSha256, fixture.sha256);
  assert.equal(result.fileCount, EXPECTED_RUNTIME_DEPENDENCY_FILES.length + 8);
  assert.equal(result.healthChecked, true);
  assert.equal(result.shellChecked, true);
  assert.equal(await lstat(fixture.root).then(() => true), true);
  for (const forbidden of ['relay.sqlite', 'relay.sqlite-shm', 'relay.sqlite-wal']) {
    await assert.rejects(lstat(resolve(fixture.root, forbidden)), { code: 'ENOENT' });
  }
});

test('requires an exact hashed HTML-to-JS/CSS-to-WASM closure and both shell routes', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-origin-release-closure-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const fixture = await buildFixture(parent);
  const report = await inspectOriginServiceArchive(await readFile(fixture.archivePath), {
    observedRuntime: OBSERVED_RUNTIME,
  });
  const assetPaths = report.paths.filter((path) => path.startsWith('wallet-origin/assets/'));
  assert.equal(assetPaths.length, 3);
  for (const path of assetPaths) {
    const match = HASHED_ASSET.exec(path.slice('wallet-origin/assets/'.length));
    assert.ok(match);
    assert.equal(match[1], report.files[path].sha256);
  }
  assert.deepEqual(report.routes, {
    root: '/',
    transactionPattern: '^/transaction/[0-9a-f]{64}$',
  });
});

test('rejects extra, secret, database, source-map, cache, and development payload files', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-origin-release-forbidden-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  for (const [index, path] of [
    '.env',
    'credentials.json',
    'relay.sqlite',
    'service/server.mjs.map',
    'node_modules/.cache/probe',
    'node_modules/typescript/package.json',
    'unexpected.txt',
  ].entries()) {
    const fixture = await createFixtureTree(parent, `-${index}`);
    await writeFixtureFile(fixture.root, path, 'forbidden\n');
    await assert.rejects(
      buildOriginServiceArchive({
        outputDirectory: join(parent, `bad-output-${index}`),
        runtime: FIXTURE_RUNTIME,
        sourceDirectory: fixture.root,
        version: ORIGIN_SERVICE_VERSION,
      }),
      /unexpected origin-service payload path/u,
    );
  }
});

test('rejects source symlinks and archived links or traversal before extraction', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-origin-release-links-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const linked = await createFixtureTree(parent, '-source-link');
  await rm(resolve(linked.root, 'LICENSE'));
  await symlink(resolve(linked.root, 'package.json'), resolve(linked.root, 'LICENSE'));
  await assert.rejects(
    buildOriginServiceArchive({
      outputDirectory: join(parent, 'link-output'),
      runtime: FIXTURE_RUNTIME,
      sourceDirectory: linked.root,
      version: ORIGIN_SERVICE_VERSION,
    }),
    /symlink/u,
  );

  const fixture = await buildFixture(parent, '-archive');
  const original = await readFile(fixture.archivePath);
  const traversal = forgedArchive(original, ({ entries, tar }) => {
    const header = tar.subarray(entries[0].headerOffset, entries[0].headerOffset + 512);
    header.fill(0, 0, 100);
    header.write('../escape', 0, 'ascii');
    writeTarChecksum(header);
  });
  await assertRejectsArchive(parent, traversal, /unsafe archive path/u);

  const link = forgedArchive(original, ({ entries, tar }) => {
    const header = tar.subarray(entries[0].headerOffset, entries[0].headerOffset + 512);
    header[156] = '2'.charCodeAt(0);
    header.write('package.json', 157, 'ascii');
    writeTarChecksum(header);
  });
  await assertRejectsArchive(parent, link, /regular files/u);

  const archiveLink = resolve(parent, 'linked-archive.tar.gz');
  await symlink(fixture.archivePath, archiveLink);
  await assert.rejects(
    verifyOriginServiceRelease({
      archivePath: archiveLink,
      observedRuntime: OBSERVED_RUNTIME,
      requireChecksum: false,
      runHealthCheck: false,
    }),
    /regular file/u,
  );
});

test('rejects byte tampering, checksum tampering, and an unexpected archived path', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-origin-release-tamper-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const fixture = await buildFixture(parent);
  const original = await readFile(fixture.archivePath);

  await assertRejectsArchive(
    parent,
    Buffer.concat([original, Buffer.from([0x00])]),
    /gzip encoding is not canonical/u,
  );

  const payloadTamper = forgedArchive(original, ({ entries, tar }) => {
    const target = entries.find(({ path }) => path === 'service/server.mjs');
    tar[target.headerOffset + 512 + 1] ^= 0x01;
  });
  await assertRejectsArchive(parent, payloadTamper, /file digest mismatch/u);

  const unexpected = forgedArchive(original, ({ entries, tar }) => {
    const target = entries.find(({ path }) => path === 'LICENSE');
    const header = tar.subarray(target.headerOffset, target.headerOffset + 512);
    header.fill(0, 0, 100);
    header.write('.env', 0, 'ascii');
    writeTarChecksum(header);
  });
  await assertRejectsArchive(parent, unexpected, /unexpected archive path/u);

  const noncanonicalHeader = forgedArchive(original, ({ entries, tar }) => {
    const header = tar.subarray(entries[0].headerOffset, entries[0].headerOffset + 512);
    header[500] = 0x01;
    writeTarChecksum(header);
  });
  await assertRejectsArchive(parent, noncanonicalHeader, /tar header is not canonical/u);

  const highBitMode = forgedArchive(original, ({ entries, tar }) => {
    const header = tar.subarray(entries[0].headerOffset, entries[0].headerOffset + 512);
    header[100] |= 0x80;
    writeTarChecksum(header);
  });
  await assertRejectsArchive(parent, highBitMode, /tar mode is not canonical octal/u);

  await writeFile(fixture.checksumPath, `${'0'.repeat(64)}  ${ARCHIVE_BASENAME}\n`);
  await assert.rejects(
    verifyOriginServiceRelease({
      archivePath: fixture.archivePath,
      observedRuntime: OBSERVED_RUNTIME,
      runHealthCheck: false,
    }),
    /archive checksum mismatch/u,
  );
});

test('rejects wrong runtime ABI, platform, architecture, glibc, and addon binding', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-origin-release-runtime-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const fixture = await buildFixture(parent);
  for (const observedRuntime of [
    { ...OBSERVED_RUNTIME, nodeVersion: '24.17.0' },
    { ...OBSERVED_RUNTIME, modulesAbi: '136' },
    { ...OBSERVED_RUNTIME, napiVersion: '9' },
    { ...OBSERVED_RUNTIME, platform: 'darwin' },
    { ...OBSERVED_RUNTIME, architecture: 'arm64' },
    { ...OBSERVED_RUNTIME, glibcVersion: '2.27' },
  ]) {
    await assert.rejects(
      verifyOriginServiceRelease({
        archivePath: fixture.archivePath,
        observedRuntime,
        runHealthCheck: false,
      }),
      /runtime/u,
    );
  }

  const original = await readFile(fixture.archivePath);
  const addonTamper = forgedArchive(original, ({ entries, tar }) => {
    const target = entries.find(({ path }) => path.endsWith('/better_sqlite3.node'));
    tar[target.headerOffset + 512] ^= 0x01;
  });
  await assertRejectsArchive(parent, addonTamper, /file digest mismatch/u);

  const nonElf = await createFixtureTree(parent, '-non-elf');
  await writeFixtureFile(nonElf.root, 'node_modules/better-sqlite3/build/Release/better_sqlite3.node', 'not-elf\n');
  await assert.rejects(
    buildOriginServiceArchive({
      outputDirectory: join(parent, 'non-elf-output'),
      runtime: FIXTURE_RUNTIME,
      sourceDirectory: nonElf.root,
      version: ORIGIN_SERVICE_VERSION,
    }),
    /Linux x86-64 ELF/u,
  );
});

test('rejects malformed HTML references, unhashed names, missing asset kinds, and package drift', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-origin-release-structure-'));
  t.after(() => rm(parent, { force: true, recursive: true }));

  const badHtml = await createFixtureTree(parent, '-html');
  await writeFixtureFile(
    badHtml.root,
    'wallet-origin/index.html',
    '<!doctype html><script type="module" src="/assets/unhashed-wallet.js"></script>\n',
  );
  await assert.rejects(
    buildOriginServiceArchive({
      outputDirectory: join(parent, 'html-output'),
      runtime: FIXTURE_RUNTIME,
      sourceDirectory: badHtml.root,
      version: ORIGIN_SERVICE_VERSION,
    }),
    /wallet-origin HTML/u,
  );

  const commentedHtml = await createFixtureTree(parent, '-commented-html');
  const commentedCss = await readFile(
    resolve(commentedHtml.root, `wallet-origin/assets/${commentedHtml.cssName}`),
  );
  const commentedJavascript = await readFile(
    resolve(commentedHtml.root, `wallet-origin/assets/${commentedHtml.javascriptName}`),
  );
  await writeFixtureFile(
    commentedHtml.root,
    'wallet-origin/index.html',
    `<!doctype html><!-- <link rel="stylesheet" href="/assets/${commentedHtml.cssName}" integrity="${sha384(commentedCss)}" crossorigin="anonymous"><script type="module" src="/assets/${commentedHtml.javascriptName}" integrity="${sha384(commentedJavascript)}" crossorigin="anonymous"></script> -->\n`,
  );
  await assert.rejects(
    buildOriginServiceArchive({
      outputDirectory: join(parent, 'commented-html-output'),
      runtime: FIXTURE_RUNTIME,
      sourceDirectory: commentedHtml.root,
      version: ORIGIN_SERVICE_VERSION,
    }),
    /wallet-origin HTML/u,
  );

  const missingWasm = await createFixtureTree(parent, '-missing-wasm');
  await rm(resolve(missingWasm.root, `wallet-origin/assets/${missingWasm.wasmName}`));
  await assert.rejects(
    buildOriginServiceArchive({
      outputDirectory: join(parent, 'missing-output'),
      runtime: FIXTURE_RUNTIME,
      sourceDirectory: missingWasm.root,
      version: ORIGIN_SERVICE_VERSION,
    }),
    /payload inventory/u,
  );

  const packageDrift = await createFixtureTree(parent, '-package');
  const wrongPackage = {
    dependencies: { 'better-sqlite3': '^12.2.0' },
    engines: { node: '>=24' },
    name: '@sdn/wallet-origin-service',
    private: true,
    type: 'module',
    version: ORIGIN_SERVICE_VERSION,
  };
  await writeFixtureFile(packageDrift.root, 'package.json', `${canonicalize(wrongPackage)}\n`);
  await assert.rejects(
    buildOriginServiceArchive({
      outputDirectory: join(parent, 'package-output'),
      runtime: FIXTURE_RUNTIME,
      sourceDirectory: packageDrift.root,
      version: ORIGIN_SERVICE_VERSION,
    }),
    /package metadata/u,
  );

  const registryDrift = await createFixtureTree(parent, '-registry');
  await writeFixtureFile(registryDrift.root, 'registry/client-registry.v1.json', `${canonicalize({
    clients: [],
    registryReleaseSha256: '0'.repeat(64),
    schemaVersion: 1,
  })}\n`);
  await assert.rejects(
    buildOriginServiceArchive({
      outputDirectory: join(parent, 'registry-output'),
      runtime: FIXTURE_RUNTIME,
      sourceDirectory: registryDrift.root,
      version: ORIGIN_SERVICE_VERSION,
    }),
    /registry release digest/u,
  );
});

test('rejects JavaScript resources and module imports outside the hashed asset closure', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-origin-release-js-closure-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const cases = [
    (wasmName) => `const wasm = new URL("./${wasmName}", import.meta.url);\nconst extra = new URL("./missing.wasm", import.meta.url);\nvoid wasm; void extra;\n`,
    (wasmName) => `import "./missing.js";\nconst wasm = new URL("./${wasmName}", import.meta.url);\nvoid wasm;\n`,
    (wasmName) => `export { missing } from "./missing.js";\nconst wasm = new URL("./${wasmName}", import.meta.url);\nvoid wasm;\n`,
  ];
  for (const [index, makeJavascript] of cases.entries()) {
    await t.test(`unclosed resource ${index + 1}`, async () => {
      const fixture = await createFixtureTree(parent, `-${index}`);
      await replaceFixtureJavascript(fixture, makeJavascript(fixture.wasmName));
      await assert.rejects(
        buildOriginServiceArchive({
          outputDirectory: join(parent, `output-${index}`),
          runtime: FIXTURE_RUNTIME,
          sourceDirectory: fixture.root,
          version: ORIGIN_SERVICE_VERSION,
        }),
        /JavaScript asset closure/u,
      );
    });
  }
});

test('rejects non-UTF-8 JSON even when replacement decoding would be canonical', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-origin-release-utf8-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const fixture = await createFixtureTree(parent);
  const unsignedRegistry = { clients: ['\ufffd'], schemaVersion: 1 };
  const registry = {
    clients: unsignedRegistry.clients,
    registryReleaseSha256: sha256(Buffer.from(canonicalize(unsignedRegistry))),
    schemaVersion: unsignedRegistry.schemaVersion,
  };
  const validBytes = Buffer.from(`${canonicalize(registry)}\n`);
  const replacementOffset = validBytes.indexOf(Buffer.from('\ufffd'));
  assert.notEqual(replacementOffset, -1);
  const invalidBytes = Buffer.concat([
    validBytes.subarray(0, replacementOffset),
    Buffer.from([0xff]),
    validBytes.subarray(replacementOffset + Buffer.byteLength('\ufffd')),
  ]);
  await writeFixtureFile(fixture.root, 'registry/client-registry.v1.json', invalidBytes);
  await assert.rejects(
    buildOriginServiceArchive({
      outputDirectory: join(parent, 'output'),
      runtime: FIXTURE_RUNTIME,
      sourceDirectory: fixture.root,
      version: ORIGIN_SERVICE_VERSION,
    }),
    /JCS/u,
  );
});
