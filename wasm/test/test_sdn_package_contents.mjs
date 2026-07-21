import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readdir, readFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const packageDirectory = dirname(fileURLToPath(new URL('../package.json', import.meta.url)));

test('npm dry-run package includes the internal typed factory from the explicit allowlist', async () => {
  const before = (await readdir(packageDirectory)).filter((name) => name.endsWith('.tgz'));
  const packageJson = JSON.parse(await readFile(new URL('../package.json', import.meta.url), 'utf8'));
  const declarations = await readFile(new URL('../src/index.d.ts', import.meta.url), 'utf8');
  assert.ok(packageJson.files.includes('src/index.mjs'));
  assert.ok(packageJson.files.includes('src/sdn-typed.mjs'));
  assert.match(
    declarations,
    /identityScheme: 'sdn-fast-password-auth-v1-legacy' \| 'sdn-bip39-auth-v1-legacy';/,
  );

  const output = execFileSync('npm', [
    'pack', '--dry-run', '--json', '--ignore-scripts',
  ], {
    cwd: packageDirectory,
    encoding: 'utf8',
    env: {
      ...process.env,
      npm_config_offline: 'true',
      npm_config_audit: 'false',
      npm_config_fund: 'false',
      npm_config_update_notifier: 'false',
    },
  });
  const packed = JSON.parse(output);
  assert.equal(packed.length, 1);
  const files = new Set(packed[0].files.map(({ path }) => path));
  assert.equal(files.has('src/index.mjs'), true);
  assert.equal(files.has('src/sdn-typed.mjs'), true);
  assert.equal([...files].some((path) => path.startsWith('test/')), false);
  assert.equal([...files].some((path) => path.includes('sdn_identity_secrets')), false);

  const after = (await readdir(packageDirectory)).filter((name) => name.endsWith('.tgz'));
  assert.deepEqual(after, before);
});
