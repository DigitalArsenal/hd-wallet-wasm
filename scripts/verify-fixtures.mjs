import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
);

const fixturePath = 'test/fixtures/trezor-bip39-vectors.json';
const sourcePath = 'test/fixtures/trezor-bip39-vectors.source.json';
const expectedBytes = 152400;
const expectedSha256 =
  'fa3b937b7cff9c9b8ecd3aa011faeb8d6dd67993174b72326e83f4de8fdb30f8';
const expectedSource = {
  schemaVersion: 1,
  name: 'Trezor BIP-39 test vectors',
  upstreamRepository: 'https://github.com/trezor/python-mnemonic',
  upstreamCommit: 'b57a5ad77a981e743f4167ab2f7927a55c1e82a8',
  sourcePath: 'vectors.json',
  sourceUrl:
    'https://raw.githubusercontent.com/trezor/python-mnemonic/b57a5ad77a981e743f4167ab2f7927a55c1e82a8/vectors.json',
  license: 'MIT',
  bytes: expectedBytes,
  sha256: expectedSha256,
};

try {
  const fixture = readFileSync(path.join(repositoryRoot, fixturePath));
  assert.equal(fixture.length, expectedBytes, `${fixturePath} byte length`);
  assert.equal(fixture.at(-1), 0x0a, `${fixturePath} LF termination`);
  assert.equal(
    createHash('sha256').update(fixture).digest('hex'),
    expectedSha256,
    `${fixturePath} SHA-256`,
  );

  const source = JSON.parse(
    readFileSync(path.join(repositoryRoot, sourcePath), 'utf8'),
  );
  assert.deepEqual(source, expectedSource, `${sourcePath} metadata`);

  console.log('PASS: committed fixture bytes and source metadata are immutable');
} catch (error) {
  console.error(`FAIL: ${error.message}`);
  process.exitCode = 1;
}
