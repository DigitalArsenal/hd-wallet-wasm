import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import test from 'node:test';

import { packWorkspaceReleaseSubject } from '../../scripts/pack-release-subject.mjs';

const SOURCE_COMMIT = '0123456789abcdef0123456789abcdef01234567';

async function fixtureWorkspace(parent, suffix = '') {
  const root = join(parent, `workspace${suffix}`);
  await mkdir(root);
  const manifest = {
    files: ['index.js'],
    name: `fixture-release-subject${suffix}`,
    type: 'module',
    version: '1.0.0',
  };
  await writeFile(join(root, 'index.js'), 'export const fixture = true;\n');
  await writeFile(join(root, 'package.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  return { manifest, root };
}

function loadPinnedPacote() {
  const npmCli = process.env.npm_execpath;
  assert.equal(typeof npmCli, 'string', 'test must run through exact npm 11.16.0');
  const npmPackage = resolve(dirname(npmCli), '..', 'package.json');
  const npmManifest = createRequire(import.meta.url)(npmPackage);
  assert.equal(npmManifest.version, '11.16.0');
  return createRequire(npmPackage)('pacote');
}

test('packs one commit-bound tarball without mutating its source workspace', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-release-githead-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const fixture = await fixtureWorkspace(parent);
  const before = await readFile(join(fixture.root, 'package.json'));
  const output = join(parent, 'output');
  await mkdir(output);

  const subject = await packWorkspaceReleaseSubject({
    destination: output,
    sourceCommit: SOURCE_COMMIT,
    workspaceDirectory: fixture.root,
  });

  assert.deepEqual(await readFile(join(fixture.root, 'package.json')), before);
  assert.equal(subject.manifest.gitHead, SOURCE_COMMIT);
  assert.deepEqual(subject.files, ['index.js', 'package.json']);
  const pacote = loadPinnedPacote();
  const manifest = await pacote.manifest(`file:${subject.archivePath}`, {
    fullMetadata: true,
    offline: true,
  });
  assert.equal(manifest.gitHead, SOURCE_COMMIT);
  assert.equal(manifest.name, fixture.manifest.name);
  assert.equal(manifest.version, fixture.manifest.version);
});

test('rejects invalid commit bindings and symlinks in the packed file set', async (t) => {
  const parent = await mkdtemp(join(tmpdir(), 'sdn-release-githead-reject-'));
  t.after(() => rm(parent, { force: true, recursive: true }));
  const fixture = await fixtureWorkspace(parent, '-reject');
  const output = join(parent, 'output');
  await mkdir(output);

  await assert.rejects(
    packWorkspaceReleaseSubject({
      destination: output,
      sourceCommit: 'A'.repeat(40),
      workspaceDirectory: fixture.root,
    }),
    /source commit/u,
  );

  await rm(join(fixture.root, 'index.js'));
  await symlink(join(fixture.root, 'package.json'), join(fixture.root, 'index.js'));
  await assert.rejects(
    packWorkspaceReleaseSubject({
      destination: output,
      sourceCommit: SOURCE_COMMIT,
      workspaceDirectory: fixture.root,
    }),
    /symlink/u,
  );
});
