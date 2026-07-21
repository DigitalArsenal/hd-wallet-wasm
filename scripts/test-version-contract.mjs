import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const expectedVersion = '2.0.22';
const expectedWorkspaces = ['wasm', 'wallet-ui', 'wallet-ui/relay'];

function parseJson(relativePath) {
  const absolutePath = path.join(repositoryRoot, relativePath);
  assert(existsSync(absolutePath), `${relativePath} must exist`);
  return JSON.parse(readFileSync(absolutePath, 'utf8'));
}

const rootPackage = parseJson('package.json');
const wasmPackage = parseJson('wasm/package.json');
const uiPackage = parseJson('wallet-ui/package.json');
const relayPackage = parseJson('wallet-ui/relay/package.json');
const rootLock = parseJson('package-lock.json');
const lineage = parseJson('release/lineage.v1.json');
const cmakeLists = readFileSync(path.join(repositoryRoot, 'CMakeLists.txt'), 'utf8');

for (const [label, packageVersion] of [
  ['root', rootPackage.version],
  ['core', wasmPackage.version],
  ['UI', uiPackage.version],
  ['relay', relayPackage.version],
]) {
  assert.equal(packageVersion, expectedVersion, `${label} package version must be ${expectedVersion}`);
}

assert.equal(
  uiPackage.dependencies?.['hd-wallet-wasm'],
  expectedVersion,
  'UI must depend on the exact workspace version of hd-wallet-wasm',
);
assert.deepEqual(rootPackage.workspaces, expectedWorkspaces);
assert.equal(rootPackage.packageManager, 'npm@11.16.0');
assert.deepEqual(rootPackage.engines, { node: '>=24.0.0 <25', npm: '11.16.0' });
assert.deepEqual(relayPackage.engines, { node: '>=24.0.0 <25' });

function readCmakeVersionComponent(component) {
  const match = cmakeLists.match(
    new RegExp(`set\\(HD_WALLET_VERSION_${component}\\s+(\\d+)\\)`),
  );
  assert(match, `CMakeLists.txt must define HD_WALLET_VERSION_${component}`);
  return Number(match[1]);
}

assert.equal(readCmakeVersionComponent('MAJOR'), 2);
assert.equal(readCmakeVersionComponent('MINOR'), 0);
assert.equal(readCmakeVersionComponent('PATCH'), 22);

for (const nestedLock of [
  'wasm/package-lock.json',
  'wallet-ui/package-lock.json',
  'wallet-ui/relay/package-lock.json',
]) {
  assert.equal(existsSync(path.join(repositoryRoot, nestedLock)), false, `${nestedLock} must not exist`);
}

assert.equal(rootLock.lockfileVersion, 3);
assert.equal(rootLock.name, 'hd-wallet-wasm-workspace');
assert.equal(rootLock.version, expectedVersion);
assert.equal(rootLock.packages?.['']?.name, 'hd-wallet-wasm-workspace');
assert.equal(rootLock.packages?.['']?.version, expectedVersion);
assert.deepEqual(rootLock.packages?.['']?.workspaces, expectedWorkspaces);
assert.equal(rootLock.packages?.wasm?.version, expectedVersion);
assert.equal(rootLock.packages?.['wallet-ui']?.version, expectedVersion);
assert.equal(rootLock.packages?.['wallet-ui/relay']?.version, expectedVersion);
assert.equal(
  rootLock.packages?.['wallet-ui']?.dependencies?.['hd-wallet-wasm'],
  expectedVersion,
);
for (const [packagePath, resolved] of [
  ['node_modules/hd-wallet-wasm', 'wasm'],
  ['node_modules/hd-wallet-ui', 'wallet-ui'],
  ['node_modules/@sdn/wallet-relay', 'wallet-ui/relay'],
]) {
  assert.deepEqual(rootLock.packages?.[packagePath], { resolved, link: true });
}

const extraneousPackagePaths = Object.entries(rootLock.packages ?? {})
  .filter(([, metadata]) => metadata?.extraneous === true)
  .map(([packagePath]) => packagePath)
  .sort();
assert.deepEqual(
  extraneousPackagePaths,
  [],
  `root lock must not contain extraneous packages: ${extraneousPackagePaths.join(', ')}`,
);

const incompleteRegistryPackagePaths = Object.entries(rootLock.packages ?? {})
  .filter(
    ([packagePath, metadata]) =>
      packagePath.includes('node_modules/') &&
      metadata?.link !== true &&
      typeof metadata?.version === 'string' &&
      (typeof metadata.resolved !== 'string' ||
        metadata.resolved.length === 0 ||
        typeof metadata.integrity !== 'string' ||
        metadata.integrity.length === 0),
  )
  .map(([packagePath]) => packagePath)
  .sort();
assert.deepEqual(
  incompleteRegistryPackagePaths,
  [],
  `root lock registry packages must include resolved and integrity metadata: ${incompleteRegistryPackagePaths.join(', ')}`,
);

assert.deepEqual(lineage, {
  requiredAncestors: {
    uiLifecycleV2019: '537ac9a08c12fb62a7152007bce9898efb6f9204',
    walletCoreV2021: '3c4258a8fa3ef9bc5a86c786231bf5f3c5c568c9',
  },
  schemaVersion: 1,
});

console.log('PASS: wallet workspace version, lock, runtime, and lineage contracts are frozen');
