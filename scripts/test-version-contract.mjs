import assert from 'node:assert/strict';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const expectedVersion = '2.0.27';
const [expectedVersionMajor, expectedVersionMinor, expectedVersionPatch] = expectedVersion
  .split('.')
  .map(Number);
const expectedVersionComponents = {
  major: expectedVersionMajor,
  minor: expectedVersionMinor,
  patch: expectedVersionPatch,
};
const expectedWorkspaces = ['wasm', 'wallet-ui', 'wallet-ui/relay'];
const expectedRelayPackage = {
  name: '@sdn/wallet-relay',
  version: expectedVersion,
  private: true,
  type: 'module',
  scripts: {
    build: 'tsc -p tsconfig.json',
    test: 'node --test test/*.test.mjs',
  },
  dependencies: {
    'better-sqlite3': '12.2.0',
  },
  devDependencies: {
    '@types/node': '24.1.0',
    typescript: '5.9.2',
  },
  engines: {
    node: '>=24.0.0 <25',
  },
};
const expectedWorkspaceLockMetadata = {
  '': {
    name: 'hd-wallet-wasm-workspace',
    version: expectedVersion,
    license: 'Apache-2.0',
    workspaces: expectedWorkspaces,
    devDependencies: {
      esbuild: '0.21.5',
      flatbuffers: '^25.9.23',
      husky: '^9.1.7',
      typescript: '5.9.2',
    },
    engines: {
      node: '>=24.0.0 <25',
      npm: '11.16.0',
    },
  },
  wasm: {
    name: 'hd-wallet-wasm',
    version: expectedVersion,
    license: 'Apache-2.0',
    dependencies: {
      flatbuffers: '25.9.23',
    },
    devDependencies: {
      '@types/node': '^20.0.0',
    },
    engines: {
      node: '>=18.0.0',
    },
  },
  'wallet-ui': {
    name: 'hd-wallet-ui',
    version: expectedVersion,
    license: 'Apache-2.0',
    dependencies: {
      'hd-wallet-wasm': expectedVersion,
    },
    devDependencies: {
      '@noble/curves': '^1.9.7',
      '@noble/hashes': '^1.7.2',
      '@peculiar/x509': '^1.14.3',
      '@playwright/test': '1.61.1',
      '@scure/base': '^1.2.4',
      '@scure/bip32': '^2.0.1',
      bip39: '^3.1.0',
      buffer: '^6.0.3',
      flatbuffers: '^25.9.23',
      'flatc-wasm': '^26.1.32',
      qrcode: '^1.5.3',
      'spacedatastandards.org': '^1.93.3',
      'vcard-cryptoperson': '^1.1.11',
      vite: '^5.0.0',
      vitest: '^4.0.18',
    },
  },
  'wallet-ui/relay': {
    name: expectedRelayPackage.name,
    version: expectedRelayPackage.version,
    dependencies: expectedRelayPackage.dependencies,
    devDependencies: expectedRelayPackage.devDependencies,
    engines: expectedRelayPackage.engines,
  },
};

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
const configHeader = readFileSync(path.join(repositoryRoot, 'include/hd_wallet/config.h'), 'utf8');
const wasmIndex = readFileSync(path.join(repositoryRoot, 'wasm/src/index.mjs'), 'utf8');

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
assert.deepEqual(uiPackage.dependencies, { 'hd-wallet-wasm': expectedVersion });
assert.equal(
  uiPackage.scripts?.test,
  'vitest run --no-file-parallelism',
  'UI tests that rebuild shared dist output must run files serially',
);
assert.equal(uiPackage.devDependencies?.['@playwright/test'], '1.61.1');
assert.equal(rootPackage.devDependencies?.esbuild, '0.21.5');
assert.equal(rootPackage.devDependencies?.typescript, '5.9.2');
assert.deepEqual(rootPackage.workspaces, expectedWorkspaces);
assert.equal(rootPackage.packageManager, 'npm@11.16.0');
assert.deepEqual(rootPackage.engines, { node: '>=24.0.0 <25', npm: '11.16.0' });
assert.deepEqual(relayPackage, expectedRelayPackage);

function readCmakeVersionComponent(component) {
  const match = cmakeLists.match(
    new RegExp(`^\\s*set\\(HD_WALLET_VERSION_${component}\\s+(\\d+)\\s*\\)\\s*$`, 'm'),
  );
  assert(match, `CMakeLists.txt must define HD_WALLET_VERSION_${component}`);
  return Number(match[1]);
}

function readConfigVersionComponent(component) {
  const match = configHeader.match(
    new RegExp(`^#define\\s+HD_WALLET_VERSION_${component}\\s+(\\d+)\\s*$`, 'm'),
  );
  assert(match, `include/hd_wallet/config.h must define HD_WALLET_VERSION_${component}`);
  return Number(match[1]);
}

const configVersionStringMatch = configHeader.match(
  /^#define\s+HD_WALLET_VERSION_STRING\s+"([^"]+)"\s*$/m,
);
assert(configVersionStringMatch, 'include/hd_wallet/config.h must define HD_WALLET_VERSION_STRING');
const wasmJSDocVersionMatch = wasmIndex.match(/^\s*\*\s+@version\s+(\S+)\s*$/m);
assert(wasmJSDocVersionMatch, 'wasm/src/index.mjs must declare an @version JSDoc value');

assert.deepEqual(
  {
    cmake: {
      major: readCmakeVersionComponent('MAJOR'),
      minor: readCmakeVersionComponent('MINOR'),
      patch: readCmakeVersionComponent('PATCH'),
    },
    publicConfig: {
      major: readConfigVersionComponent('MAJOR'),
      minor: readConfigVersionComponent('MINOR'),
      patch: readConfigVersionComponent('PATCH'),
      string: configVersionStringMatch[1],
    },
    wasmJSDoc: wasmJSDocVersionMatch[1],
  },
  {
    cmake: expectedVersionComponents,
    publicConfig: { ...expectedVersionComponents, string: expectedVersion },
    wasmJSDoc: expectedVersion,
  },
  'CMake, public runtime config, and WASM wrapper versions must stay synchronized',
);

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
for (const [workspacePath, expectedMetadata] of Object.entries(expectedWorkspaceLockMetadata)) {
  assert.deepEqual(
    rootLock.packages?.[workspacePath],
    expectedMetadata,
    `root lock workspace metadata must match exactly: ${workspacePath || '<root>'}`,
  );
}
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
      (typeof metadata?.version !== 'string' ||
        metadata.version.length === 0 ||
        typeof metadata.resolved !== 'string' ||
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
