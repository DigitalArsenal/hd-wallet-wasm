import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { scanRepository } from './test-no-live-test-fetches.mjs';

function makeRepository(t) {
  const root = mkdtempSync(path.join(os.tmpdir(), 'wallet-no-live-fetches-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  for (const directory of ['scripts', 'test', 'wasm/test', 'wallet-ui/test']) {
    mkdirSync(path.join(root, directory), { recursive: true });
  }
  writeFileSync(
    path.join(root, 'CMakeLists.txt'),
    '# Tests (native only)\nconfigure_file(local local COPYONLY)\n# Documentation\n',
  );
  writeFileSync(path.join(root, 'package.json'), '{"scripts":{"test":"node test.mjs"}}\n');
  return root;
}

function write(root, relativePath, body) {
  const target = path.join(root, relativePath);
  mkdirSync(path.dirname(target), { recursive: true });
  writeFileSync(target, body);
}

test('scans every existing test-helper language for network acquisition', (t) => {
  const root = makeRepository(t);
  const cases = new Map([
    ['test/fetch.go', 'http.Get("https://fixtures.invalid/vectors.json")\n'],
    ['test/fetch.rs', 'reqwest::blocking::get("https://fixtures.invalid/vectors.json");\n'],
    ['test/fetch.dart', 'client.getUrl(Uri.parse("https://fixtures.invalid/vectors.json"));\n'],
    ['test/fetch.py', 'requests.get("https://fixtures.invalid/vectors.json")\n'],
    ['test/fetch.html', '<script>fetch("https://fixtures.invalid/vectors.json")</script>\n'],
  ]);

  for (const [file, body] of cases) write(root, file, body);
  const failures = scanRepository(root);

  for (const file of cases.keys()) {
    assert(failures.some((failure) => failure.startsWith(`${file}:`)), file);
  }
});

test('detects indented and shell-prefixed curl and wget invocations', (t) => {
  const root = makeRepository(t);
  const cases = new Map([
    ['scripts/indented-curl.sh', '    curl https://fixtures.invalid/vectors.json\n'],
    ['scripts/command-curl.sh', 'command curl https://fixtures.invalid/vectors.json\n'],
    ['scripts/then-curl.sh', 'if true; then curl https://fixtures.invalid/vectors.json; fi\n'],
    ['scripts/indented-wget.sh', '    wget https://fixtures.invalid/vectors.json\n'],
    ['scripts/command-wget.sh', 'command wget https://fixtures.invalid/vectors.json\n'],
    ['scripts/then-wget.sh', 'if true; then wget https://fixtures.invalid/vectors.json; fi\n'],
  ]);

  for (const [file, body] of cases) write(root, file, body);
  const failures = scanRepository(root);

  for (const file of cases.keys()) {
    assert(failures.some((failure) => failure.startsWith(`${file}:`)), file);
  }
});

test('parses test commands from package manifests', (t) => {
  const root = makeRepository(t);
  write(
    root,
    'wasm/package.json',
    JSON.stringify({ scripts: { build: 'vite build', 'test:vectors': 'command curl https://fixtures.invalid/vectors.json' } }),
  );

  assert(
    scanRepository(root).some((failure) =>
      failure.startsWith('wasm/package.json#scripts.test:vectors:'),
    ),
  );
});

test('scans hosted workflow helpers for live test-data acquisition', (t) => {
  const root = makeRepository(t);
  write(
    root,
    '.github/workflows/test.yml',
    'jobs:\n  test:\n    steps:\n      - run: command curl https://fixtures.invalid/vectors.json\n',
  );

  assert(
    scanRepository(root).some((failure) =>
      failure.startsWith('.github/workflows/test.yml:'),
    ),
  );
});

test('allows only the digest-bound CMake release acquisition in release workflows', (t) => {
  const root = makeRepository(t);
  const approved = [
    'name: Release',
    'jobs:',
    '  verify:',
    '    steps:',
    '      - run: |',
    '          archive="$RUNNER_TEMP/cmake-4.0.0-linux-x86_64.tar.gz"',
    "          curl --fail --location --proto '=https' --tlsv1.2 \\",
    '            --output "$archive" \\',
    '            https://github.com/Kitware/CMake/releases/download/v4.0.0/cmake-4.0.0-linux-x86_64.tar.gz',
    "          printf '%s  %s\\n' \\",
    "            'a06e6e32da747e569162bc0442a3fd400fadd9db7d4f185c9e4464ab299a294b' \\",
    '            "$archive" | sha256sum --check --strict',
    '',
  ].join('\n');
  write(root, '.github/workflows/build.yml', approved);
  assert.deepEqual(scanRepository(root), []);

  write(
    root,
    '.github/workflows/build.yml',
    approved.replace(
      'https://github.com/Kitware/CMake/releases/download/v4.0.0/cmake-4.0.0-linux-x86_64.tar.gz',
      'https://github.com/Kitware/CMake/releases/download/v4.0.0/other.tar.gz',
    ),
  );
  assert(
    scanRepository(root).some((failure) =>
      failure.startsWith('.github/workflows/build.yml: contains curl invocation'),
    ),
  );

  write(root, '.github/workflows/build.yml', `${approved}      - run: curl https://fixtures.invalid/data\n`);
  assert(
    scanRepository(root).some((failure) =>
      failure.startsWith('.github/workflows/build.yml: contains curl invocation'),
    ),
  );
});

test('allows only the size- and digest-bound GitHub CLI acquisition in the publish workflow', (t) => {
  const root = makeRepository(t);
  const approved = [
    'name: Release',
    'jobs:',
    '  publish:',
    '    steps:',
    '      - run: |',
    '          archive="$RUNNER_TEMP/gh_2.96.0_linux_amd64.tar.gz"',
    "          curl --fail --location --proto '=https' --tlsv1.2 \\",
    '            --output "$archive" \\',
    '            https://github.com/cli/cli/releases/download/v2.96.0/gh_2.96.0_linux_amd64.tar.gz',
    '          test "$(wc -c < "$archive" | tr -d \'[:space:]\')" = 14652560',
    "          printf '%s  %s\\n' \\",
    "            '83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60' \\",
    '            "$archive" | sha256sum --check --strict',
    '',
  ].join('\n');
  write(root, '.github/workflows/npm-publish.yml', approved);
  assert.deepEqual(scanRepository(root), []);

  for (const [from, to] of [
    ['14652560', '14652561'],
    [
      '83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60',
      '0'.repeat(64),
    ],
    ['gh_2.96.0_linux_amd64.tar.gz', 'other.tar.gz'],
  ]) {
    write(root, '.github/workflows/npm-publish.yml', approved.replaceAll(from, to));
    assert(
      scanRepository(root).some((failure) =>
        failure.startsWith('.github/workflows/npm-publish.yml: contains curl invocation'),
      ),
      from,
    );
  }

  write(root, '.github/workflows/build.yml', approved);
  rmSync(path.join(root, '.github/workflows/npm-publish.yml'));
  assert(
    scanRepository(root).some((failure) =>
      failure.startsWith('.github/workflows/build.yml: contains curl invocation'),
    ),
  );
});

test('does not execute-match its own checks or fixture source metadata', (t) => {
  const root = makeRepository(t);
  write(root, 'scripts/test-no-live-test-fetches.mjs', 'raw.githubusercontent.com curl wget\n');
  write(root, 'scripts/test-no-live-test-fetches.test.mjs', 'raw.githubusercontent.com curl wget\n');
  write(root, 'scripts/verify-fixtures.mjs', 'raw.githubusercontent.com curl wget\n');
  write(
    root,
    'test/fixtures/trezor-bip39-vectors.source.json',
    '{"sourceUrl":"https://raw.githubusercontent.com/example/repository/commit/vectors.json"}\n',
  );

  assert.deepEqual(scanRepository(root), []);
});
