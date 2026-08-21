import { execFileSync } from 'node:child_process';
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
import { basename, join, relative, resolve, sep } from 'node:path';

const LOWERCASE_COMMIT = /^[0-9a-f]{40}$/u;
const SAFE_SEGMENT = /^[0-9A-Za-z@+._-]+$/u;

function fail(message) {
  throw new Error(message);
}

function assertInside(root, candidate, label) {
  const path = relative(root, candidate);
  if (path === '' || path === '..' || path.startsWith(`..${sep}`) || resolve(root, path) !== candidate) {
    fail(`${label} escapes its release root`);
  }
}

function snapshotMatches(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs;
}

async function readRegularSnapshot(path, label) {
  const before = await lstat(path).catch((error) => {
    if (error?.code === 'ENOENT') fail(`${label} is missing`);
    throw error;
  });
  if (before.isSymbolicLink()) fail(`${label} is a symlink`);
  if (!before.isFile()) fail(`${label} is not a regular file`);

  let handle;
  try {
    handle = await open(
      path,
      filesystemConstants.O_RDONLY | (filesystemConstants.O_NOFOLLOW ?? 0),
    );
  } catch (error) {
    if (error?.code === 'ELOOP') fail(`${label} is a symlink`);
    throw error;
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !snapshotMatches(before, opened)) {
      fail(`${label} changed while it was opened`);
    }
    const bytes = await handle.readFile();
    const afterRead = await handle.stat();
    if (!snapshotMatches(opened, afterRead) || bytes.length !== opened.size) {
      fail(`${label} changed while it was read`);
    }
    const after = await lstat(path);
    if (!snapshotMatches(opened, after)) fail(`${label} changed while it was copied`);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function assertRealDirectory(path, label) {
  const absolute = resolve(path);
  const status = await lstat(absolute).catch((error) => {
    if (error?.code === 'ENOENT') fail(`${label} does not exist`);
    throw error;
  });
  if (status.isSymbolicLink()) fail(`${label} is a symlink`);
  if (!status.isDirectory()) fail(`${label} is not a directory`);
  return realpath(absolute);
}

function parseFilesAllowlist(manifest) {
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) {
    fail('release package requires a non-empty literal files allowlist');
  }
  const entries = manifest.files.map((entry) => {
    if (typeof entry !== 'string' || entry.length === 0 || entry.includes('\\')
        || entry.includes('\0') || entry.startsWith('/') || /[*?{}[\]!]/u.test(entry)) {
      fail('release package files allowlist contains an unsafe entry');
    }
    const directory = entry.endsWith('/');
    const trimmed = directory ? entry.slice(0, -1) : entry;
    const segments = trimmed.split('/');
    if (trimmed.length === 0 || segments.some((segment) => !SAFE_SEGMENT.test(segment)
        || segment === '.' || segment === '..')) {
      fail('release package files allowlist contains an unsafe entry');
    }
    const normalized = segments.join('/');
    if (normalized === 'package.json') {
      fail('package.json must not appear in the release files allowlist');
    }
    return { directory, path: normalized };
  });
  entries.sort((left, right) => left.path.localeCompare(right.path, 'en'));
  for (let index = 0; index < entries.length; index += 1) {
    const current = entries[index];
    if (index > 0) {
      const previous = entries[index - 1];
      if (current.path === previous.path || current.path.startsWith(`${previous.path}/`)) {
        fail('release package files allowlist contains duplicate or overlapping entries');
      }
    }
  }
  return entries;
}

async function copyRegularTree(source, destination, sourceRoot) {
  assertInside(sourceRoot, source, 'release source');
  const before = await lstat(source);
  if (before.isSymbolicLink()) fail(`release source contains a symlink: ${source}`);
  if (!before.isDirectory()) fail(`release source is not a directory: ${source}`);
  await mkdir(destination, { mode: 0o700 });
  const entries = await readdir(source, { withFileTypes: true });
  entries.sort((left, right) => left.name.localeCompare(right.name, 'en'));
  for (const entry of entries) {
    const sourcePath = join(source, entry.name);
    const destinationPath = join(destination, entry.name);
    assertInside(sourceRoot, sourcePath, 'release source');
    const status = await lstat(sourcePath);
    if (status.isSymbolicLink()) fail(`release source contains a symlink: ${sourcePath}`);
    if (status.isDirectory()) {
      await copyRegularTree(sourcePath, destinationPath, sourceRoot);
    } else if (status.isFile()) {
      const bytes = await readRegularSnapshot(sourcePath, `release source file ${sourcePath}`);
      await writeFile(destinationPath, bytes, { flag: 'wx', mode: 0o600 });
    } else {
      fail(`release source contains an unsupported entry: ${sourcePath}`);
    }
  }
  const after = await lstat(source);
  if (!snapshotMatches(before, after)) fail(`release source directory changed while copied: ${source}`);
}

function npmExecutable() {
  const executable = process.env.npm_execpath;
  if (typeof executable !== 'string' || executable.length === 0) {
    fail('release packing must be invoked through the pinned npm executable');
  }
  return executable;
}

function archiveFiles(archivePath) {
  let listing;
  let verbose;
  try {
    listing = execFileSync('tar', ['-tf', archivePath], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    verbose = execFileSync('tar', ['-tvf', archivePath], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    fail('cannot inspect the packed release subject');
  }
  for (const line of verbose.split('\n').filter(Boolean)) {
    if (line[0] !== '-' && line[0] !== 'd') {
      fail('packed release subject contains a link or special entry');
    }
  }
  const entries = listing.split('\n').filter(Boolean);
  if (entries.some((path) => path !== 'package/' && !path.startsWith('package/'))) {
    fail('packed release subject contains an entry outside package/');
  }
  return entries
    .filter((path) => path.startsWith('package/') && !path.endsWith('/'))
    .map((path) => path.slice('package/'.length))
    .sort();
}

function packedManifest(archivePath) {
  let text;
  try {
    text = execFileSync('tar', ['-xOf', archivePath, 'package/package.json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    fail('cannot read the packed release subject manifest');
  }
  try {
    return JSON.parse(text);
  } catch {
    fail('packed release subject manifest is invalid JSON');
  }
}

export async function packWorkspaceReleaseSubject({
  destination,
  sourceCommit,
  workspaceDirectory,
}) {
  if (typeof sourceCommit !== 'string' || !LOWERCASE_COMMIT.test(sourceCommit)) {
    fail('source commit must be exactly 40 lowercase hexadecimal characters');
  }
  const workspace = await assertRealDirectory(workspaceDirectory, 'release workspace');
  const output = await assertRealDirectory(destination, 'release destination');
  const manifestBytes = await readRegularSnapshot(
    join(workspace, 'package.json'),
    'release package.json',
  );
  let sourceManifest;
  try {
    sourceManifest = JSON.parse(manifestBytes.toString('utf8'));
  } catch {
    fail('release package.json is invalid JSON');
  }
  if (!sourceManifest || typeof sourceManifest !== 'object' || Array.isArray(sourceManifest)) {
    fail('release package.json must contain an object');
  }
  if (Object.hasOwn(sourceManifest, 'gitHead')) {
    fail('source release package.json must not contain gitHead');
  }
  const allowlist = parseFilesAllowlist(sourceManifest);
  const temporaryRoot = await mkdtemp(join(await realpath(tmpdir()), 'sdn-npm-subject-'));
  try {
    const staging = join(temporaryRoot, 'package');
    await mkdir(staging, { mode: 0o700 });
    for (const entry of allowlist) {
      const source = resolve(workspace, entry.path);
      const target = resolve(staging, entry.path);
      assertInside(workspace, source, 'release source');
      assertInside(staging, target, 'release staging target');
      const status = await lstat(source).catch((error) => {
        if (error?.code === 'ENOENT') fail(`release allowlisted path is missing: ${entry.path}`);
        throw error;
      });
      if (status.isSymbolicLink()) fail(`release allowlisted path is a symlink: ${entry.path}`);
      if (entry.directory !== status.isDirectory()) {
        fail(`release allowlisted path type does not match its literal entry: ${entry.path}`);
      }
      if (status.isDirectory()) {
        await copyRegularTree(source, target, workspace);
      } else if (status.isFile()) {
        await mkdir(resolve(target, '..'), { recursive: true, mode: 0o700 });
        const bytes = await readRegularSnapshot(source, `release source file ${source}`);
        await writeFile(target, bytes, { flag: 'wx', mode: 0o600 });
      } else {
        fail(`release allowlisted path is unsupported: ${entry.path}`);
      }
    }
    const stagedManifest = { ...sourceManifest, gitHead: sourceCommit };
    await writeFile(
      join(staging, 'package.json'),
      `${JSON.stringify(stagedManifest, null, 2)}\n`,
      { flag: 'wx', mode: 0o600 },
    );

    let records;
    try {
      const result = execFileSync(process.execPath, [
        npmExecutable(),
        'pack',
        '--ignore-scripts',
        '--json',
        '--pack-destination', output,
      ], {
        cwd: staging,
        encoding: 'utf8',
        env: {
          ...process.env,
          npm_config_audit: 'false',
          npm_config_fund: 'false',
          npm_config_offline: 'true',
          npm_config_update_notifier: 'false',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      records = JSON.parse(result);
    } catch {
      fail('pinned npm failed to pack the release subject');
    }
    if (!Array.isArray(records) || records.length !== 1
        || typeof records[0]?.filename !== 'string'
        || basename(records[0].filename) !== records[0].filename) {
      fail('pinned npm returned an invalid release subject record');
    }
    const archivePath = join(output, records[0].filename);
    const archiveStatus = await lstat(archivePath);
    if (archiveStatus.isSymbolicLink() || !archiveStatus.isFile()) {
      fail('pinned npm did not produce a regular release subject archive');
    }
    const files = archiveFiles(archivePath);
    const reportedFiles = (records[0].files ?? []).map(({ path }) => path).sort();
    if (JSON.stringify(files) !== JSON.stringify(reportedFiles)) {
      fail('packed release subject inventory disagrees with npm output');
    }
    const manifest = packedManifest(archivePath);
    if (manifest.gitHead !== sourceCommit) fail('packed release subject lost its source commit');
    return { archivePath, files, manifest };
  } finally {
    await rm(temporaryRoot, { force: true, recursive: true });
  }
}
