import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import {
  copyFile,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

import { validateReleaseRecord } from './write-release-record.mjs';
import { packWorkspaceReleaseSubject } from './pack-release-subject.mjs';
import { verifyGithubArtifactAttestation } from './verify-workflow-artifact-attestation.mjs';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = resolve(scriptDirectory, '..');
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const HEX_128 = /^[0-9a-f]{128}$/u;
const VERSION = /^\d+\.\d+\.\d+$/u;
const CORRELATION = /^[0-9a-f]{32}$/u;
const CORE_FILES = Object.freeze([
  'LICENSE',
  'README.md',
  'dist/hd-wallet-wasi.wasm',
  'dist/hd-wallet.js',
  'dist/runtime/aligned.d.ts',
  'dist/runtime/aligned.mjs',
  'dist/runtime/epm-attestation.d.ts',
  'dist/runtime/epm-attestation.mjs',
  'dist/runtime/generated/aligned/hd_wallet_aligned.mjs',
  'dist/runtime/generated/sdn_plugin_manifest.mjs',
  'dist/runtime/index.d.ts',
  'dist/runtime/index.mjs',
  'dist/runtime/sdn-plugin-manifest-codec.mjs',
  'dist/runtime/sdn-plugin-manifest-source.mjs',
  'dist/runtime/sdn-plugin.mjs',
  'dist/runtime/sdn-typed.mjs',
  'dist/wasm-loader.d.ts',
  'package.json',
].sort());
const UI_FIXED_FILES = Object.freeze([
  'LICENSE',
  'README.md',
  'data/common-passwords-sdn-v1.source.json',
  'data/common-passwords-sdn-v1.txt',
  'dist/browser/sdn-wallet-callback.js',
  'dist/browser/sdn-wallet-public-client.js',
  'dist/browser/wallet-callback.html',
  'dist/client/asset-review.d.ts',
  'dist/client/asset-review.js',
  'dist/client/callback.d.ts',
  'dist/client/callback.js',
  'dist/client/index.d.ts',
  'dist/client/index.js',
  'dist/client/sdn.d.ts',
  'dist/client/sdn.js',
  'dist/client/style.css',
  'dist/client/types.d.ts',
  'dist/compat/index.d.ts',
  'dist/compat/index.js',
  'dist/wallet-origin-host/index.html',
  'dist/wallet-origin-host/integrity.json',
  'dist/wallet-origin/index.d.ts',
  'dist/wallet-origin/index.js',
  'package.json',
].sort());

const FROZEN_TOOLCHAIN = Object.freeze({
  schemaVersion: 1,
  platform: { architecture: 'x64', glibc: '2.39', os: 'linux' },
  betterSqlite3: {
    prebuilds: [
      {
        architecture: 'arm64',
        archive: 'better-sqlite3-v12.2.0-node-v137-darwin-arm64.tar.gz',
        archiveBytes: 944001,
        archiveSha256: '50ec0aa2c44c9e4b2d93308b5e43f7dd5b11409dd72464f1b44acf5e692bccab',
        modulesAbi: '137',
        platform: 'darwin',
        url: 'https://github.com/WiseLibs/better-sqlite3/releases/download/v12.2.0/better-sqlite3-v12.2.0-node-v137-darwin-arm64.tar.gz',
        version: '12.2.0',
      },
      {
        architecture: 'x64',
        archive: 'better-sqlite3-v12.2.0-node-v137-linux-x64.tar.gz',
        archiveBytes: 1067842,
        archiveSha256: '69f8bdfb23f3381df6c0867eddf5980773d04fb8619ffd9090ac724c1e95457b',
        modulesAbi: '137',
        platform: 'linux',
        url: 'https://github.com/WiseLibs/better-sqlite3/releases/download/v12.2.0/better-sqlite3-v12.2.0-node-v137-linux-x64.tar.gz',
        version: '12.2.0',
      },
    ],
    version: '12.2.0',
  },
  node: {
    archive: 'node-v24.18.0-linux-x64.tar.xz',
    archiveSha256: '55aa7153f9d88f28d765fcdad5ae6945b5c0f98a36881703817e4c450fa76742',
    version: '24.18.0',
  },
  npm: { version: '11.16.0' },
  emscripten: { version: '3.1.51' },
  githubCli: {
    archive: 'gh_2.96.0_linux_amd64.tar.gz',
    archiveBytes: 14652560,
    archiveSha256: '83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60',
    executableBytes: 40722594,
    executableSha256: '56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40',
    url: 'https://github.com/cli/cli/releases/download/v2.96.0/gh_2.96.0_linux_amd64.tar.gz',
    version: '2.96.0',
  },
  cmake: {
    archive: 'cmake-4.0.0-linux-x86_64.tar.gz',
    archiveSha256: 'a06e6e32da747e569162bc0442a3fd400fadd9db7d4f185c9e4464ab299a294b',
    version: '4.0.0',
  },
  openssl: {
    sourceArchive: 'openssl-3.0.9.tar.gz',
    sourceSha256: 'eb1ab04781474360f77c318ab89d8c5a03abc38e63d65a603cabbf1b00a1dc90',
    version: '3.0.9',
  },
  cryptopp: {
    commit: '843d74c7c97f9e19a615b8ff3c0ca06599ca501b',
    repository: 'https://github.com/weidai11/cryptopp.git',
  },
  cryptoppCmake: {
    sourceArchive: 'cryptopp-cmake-f815f6284684be6ab03af4b6c273359331c61241.tar.gz',
    sourceCommit: 'f815f6284684be6ab03af4b6c273359331c61241',
    sourceSha256: '6ac4e8002b1167bb5393744e1f97a1207c39c9073fcff0efc1a43c0f0255edbe',
  },
  secp256k1: { commit: '1a53f4961f337b4d166c25fce72ef0dc88806618' },
});

const APPROVED_ACTIONS = Object.freeze({
  'actions/attest': 'f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6',
  'actions/checkout': 'fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09',
  'actions/setup-node': 'a0853c24544627f65ddf259abe73b1d18a591444',
  'actions/upload-artifact': 'ea165f8d65b6e75b540449e92b4886f43607fa02',
  'mymindstorm/setup-emsdk': '6ab9eb1bda2574c4ddb79809fc9247783eaf9021',
});

const REQUIRED_ACTIONS = Object.freeze({
  build: Object.freeze([
    'actions/checkout',
    'actions/setup-node',
    'actions/upload-artifact',
    'mymindstorm/setup-emsdk',
  ]),
  publish: Object.freeze([
    'actions/attest',
    'actions/checkout',
    'actions/setup-node',
    'actions/upload-artifact',
    'mymindstorm/setup-emsdk',
  ]),
});

function fail(message) {
  throw new Error(message);
}

export function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('canonical JSON numbers must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      fail('unsupported JSON value prototype');
    }
    return `{${Object.keys(value).sort().map((key) => {
      if (value[key] === undefined) fail('unsupported JSON value');
      return `${JSON.stringify(key)}:${canonicalJson(value[key])}`;
    }).join(',')}}`;
  }
  fail('unsupported JSON value');
}

export function assertExactToolchain(value) {
  if (canonicalJson(value) !== canonicalJson(FROZEN_TOOLCHAIN)) {
    fail('release toolchain does not match the frozen toolchain');
  }
  return true;
}

function nextValue(arguments_, index, name) {
  const value = arguments_[index + 1];
  if (value === undefined || value.startsWith('--')) fail(`missing value for ${name}`);
  return value;
}

export function parseArguments(arguments_) {
  const parsed = {
    emitArtifacts: null,
    evidenceRecord: null,
    expectedCorrelation: null,
    expectedRunAttempt: null,
    expectedRunId: null,
    postEvidenceCommit: null,
    provenanceEvidence: null,
    skipTag: false,
    sourceRef: 'HEAD',
    tag: null,
    version: null,
    workflowArtifacts: null,
    workflowArtifactAttestation: null,
  };
  const valueOptions = new Map([
    ['--version', 'version'],
    ['--source-ref', 'sourceRef'],
    ['--tag', 'tag'],
    ['--emit-artifacts', 'emitArtifacts'],
    ['--evidence-record', 'evidenceRecord'],
    ['--provenance-evidence', 'provenanceEvidence'],
    ['--post-evidence-commit', 'postEvidenceCommit'],
    ['--workflow-artifacts', 'workflowArtifacts'],
    ['--workflow-artifact-attestation', 'workflowArtifactAttestation'],
    ['--expected-run-id', 'expectedRunId'],
    ['--expected-run-attempt', 'expectedRunAttempt'],
    ['--expected-correlation', 'expectedCorrelation'],
  ]);
  const seen = new Set();
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === '--skip-tag') {
      if (seen.has(argument)) fail('duplicate argument: --skip-tag');
      parsed.skipTag = true;
      seen.add(argument);
      continue;
    }
    const field = valueOptions.get(argument);
    if (!field) fail(`unknown argument: ${argument}`);
    if (seen.has(argument)) fail(`duplicate argument: ${argument}`);
    parsed[field] = nextValue(arguments_, index, argument);
    seen.add(argument);
    index += 1;
  }
  if (typeof parsed.version !== 'string' || !VERSION.test(parsed.version)) {
    fail('--version must be a semantic version');
  }
  if (parsed.workflowArtifacts) {
    if (!parsed.expectedRunId) fail('--expected-run-id is required with --workflow-artifacts');
    if (!parsed.expectedRunAttempt) {
      fail('--expected-run-attempt is required with --workflow-artifacts');
    }
    if (!parsed.expectedCorrelation) {
      fail('--expected-correlation is required with --workflow-artifacts');
    }
  }
  if (Boolean(parsed.workflowArtifacts) !== Boolean(parsed.workflowArtifactAttestation)) {
    fail('--workflow-artifacts and --workflow-artifact-attestation must be provided together');
  }
  if (parsed.skipTag && parsed.tag) fail('--skip-tag and --tag are mutually exclusive');
  if (!parsed.skipTag && !parsed.tag && !parsed.postEvidenceCommit) {
    fail('exactly one of --skip-tag, --tag, or --post-evidence-commit is required');
  }
  if (parsed.tag && parsed.tag !== `v${parsed.version}`) fail('--tag must match --version');
  if (parsed.postEvidenceCommit && parsed.skipTag) {
    fail('--post-evidence-commit and --skip-tag are mutually exclusive');
  }
  if (parsed.expectedCorrelation && !CORRELATION.test(parsed.expectedCorrelation)) {
    fail('--expected-correlation must be 32 lowercase hexadecimal characters');
  }
  if (parsed.evidenceRecord && parsed.provenanceEvidence && !parsed.postEvidenceCommit) {
    const record = resolve(parsed.evidenceRecord);
    const canonicalRecord = join(repositoryDirectory, 'release/release-record.v1.json');
    if (record === canonicalRecord) {
      fail('installed evidence mode forbids --provenance-evidence override');
    }
  }
  if (parsed.provenanceEvidence && !parsed.evidenceRecord) {
    fail('--provenance-evidence requires --evidence-record');
  }
  if (parsed.emitArtifacts && (parsed.workflowArtifacts || parsed.workflowArtifactAttestation)) {
    fail('--emit-artifacts and workflow artifact inputs are mutually exclusive');
  }
  if (parsed.postEvidenceCommit) {
    if (parsed.sourceRef !== `v${parsed.version}`) {
      fail('--post-evidence-commit requires --source-ref to be the exact source tag');
    }
    if (!parsed.evidenceRecord) fail('--post-evidence-commit requires --evidence-record');
  }
  return parsed;
}

function exactDependency(manifest, expectedVersion, label) {
  const dependencies = manifest?.dependencies;
  if (!dependencies || Object.keys(dependencies).length !== 1
      || dependencies['hd-wallet-wasm'] !== expectedVersion) {
    fail(`${label} hd-wallet-wasm dependency must be exact ${expectedVersion}`);
  }
}

function exactCoreRuntimeDependency(manifest, label) {
  const dependencies = manifest?.dependencies;
  if (!dependencies || Object.keys(dependencies).length !== 1
      || dependencies.flatbuffers !== '25.9.23') {
    fail(`${label} flatbuffers dependency must be exact 25.9.23`);
  }
}

export function validateVersionContract(contract, expectedVersion) {
  if (typeof expectedVersion !== 'string' || !VERSION.test(expectedVersion)) {
    fail('expected version is invalid');
  }
  const versionValues = [
    ['CMake', contract.cmakeVersion],
    ['root package', contract.rootPackage?.version],
    ['root lock', contract.lockRootVersion],
    ['core package', contract.corePackage?.version],
    ['core lock', contract.lockCoreVersion],
    ['UI package', contract.uiPackage?.version],
    ['UI lock', contract.lockUiVersion],
    ['relay package', contract.relayPackage?.version],
    ['packed core package', contract.packedCorePackage?.version],
    ['packed UI package', contract.packedUiPackage?.version],
  ];
  for (const [label, value] of versionValues) {
    if (value !== expectedVersion) fail(`${label} version must be ${expectedVersion}`);
  }
  if (contract.corePackage?.name !== 'hd-wallet-wasm'
      || contract.packedCorePackage?.name !== 'hd-wallet-wasm') {
    fail('core package name mismatch');
  }
  if (contract.uiPackage?.name !== 'hd-wallet-ui'
      || contract.packedUiPackage?.name !== 'hd-wallet-ui') {
    fail('UI package name mismatch');
  }
  if (contract.relayPackage?.name !== '@sdn/wallet-relay') fail('relay package name mismatch');
  exactDependency(contract.uiPackage, expectedVersion, 'source UI');
  exactDependency(contract.packedUiPackage, expectedVersion, 'packed UI');
  exactCoreRuntimeDependency(contract.corePackage, 'source core');
  exactCoreRuntimeDependency(contract.packedCorePackage, 'packed core');
  if (contract.lockCoreFlatbuffers !== '25.9.23') {
    fail('core lock flatbuffers dependency must be exact 25.9.23');
  }
  return true;
}

export function assertCleanStatus(statusOutput) {
  if (typeof statusOutput !== 'string' || statusOutput.trim().length !== 0) {
    fail('release verification requires a clean repository; source is dirty');
  }
  return true;
}

export function assertOutputOutsideSource(sourceDirectory, outputDirectory) {
  const source = resolve(sourceDirectory);
  const output = resolve(outputDirectory);
  const pathFromSource = relative(source, output);
  if (pathFromSource === ''
      || (!pathFromSource.startsWith(`..${sep}`) && pathFromSource !== '..' && !isAbsolute(pathFromSource))) {
    fail('release output must not be written under the tagged tree');
  }
  return true;
}

function normalizeArtifactEntry(entry) {
  if (typeof entry !== 'string' || entry.length === 0 || entry.startsWith('/')
      || entry.includes('\\') || entry.split('/').some((part) => part === '..' || part === '.')) {
    fail(`unexpected artifact path: ${entry}`);
  }
  return entry.replace(/^\.\//u, '');
}

export function validateWorkflowArtifactEntries(inputEntries, version) {
  if (!Array.isArray(inputEntries) || !VERSION.test(version)) fail('artifact input is invalid');
  const entries = inputEntries.map(normalizeArtifactEntry).sort();
  if (new Set(entries).size !== entries.length) fail('duplicate artifact entry');
  const allowedRoots = new Set(['npm-tarballs', 'origin-service', 'wallet-release-report']);
  for (const entry of entries) {
    const [root, ...rest] = entry.split('/');
    if (!allowedRoots.has(root)) fail(`unexpected artifact root: ${entry}`);
    if (root === 'npm-tarballs' && rest.length !== 1) fail(`nested npm artifact is forbidden: ${entry}`);
    if (root === 'origin-service' && rest.length !== 1) {
      fail(`nested origin-service artifact is forbidden: ${entry}`);
    }
    if (root === 'wallet-release-report') {
      const allowed = entry === 'wallet-release-report/release-report.v1.json'
        || entry === 'wallet-release-report/provenance-trust.v1.json'
        || entry === 'wallet-release-report/release/wallet-assets.v1.json'
        || entry.startsWith('wallet-release-report/release/static/assets/hd-wallet-ui/');
      if (!allowed) fail(`unexpected artifact entry: ${entry}`);
    }
  }
  const required = [
    `npm-tarballs/hd-wallet-ui-${version}.tgz`,
    `npm-tarballs/hd-wallet-wasm-${version}.tgz`,
    `origin-service/sdn-wallet-origin-${version}-node24-linux-x64.tar.gz`,
    `origin-service/sdn-wallet-origin-${version}-node24-linux-x64.tar.gz.sha256`,
    'wallet-release-report/release-report.v1.json',
    'wallet-release-report/provenance-trust.v1.json',
    'wallet-release-report/release/wallet-assets.v1.json',
  ];
  for (const path of required) {
    if (!entries.includes(path)) fail(`missing workflow artifact: ${path}`);
  }
  if (!entries.some((path) => path.startsWith(
    `wallet-release-report/release/static/assets/hd-wallet-ui/${version}/`,
  ))) fail('missing workflow wallet static artifact');
  return true;
}

function requireHash(value, pattern, label) {
  if (typeof value !== 'string' || !pattern.test(value)) fail(`${label} hash is invalid`);
}

export function validateWorkflowArtifactReport(report, expected) {
  if (!report || typeof report !== 'object' || Array.isArray(report)) fail('artifact report is invalid');
  if (report.schemaVersion !== 1) fail('artifact report schemaVersion must be 1');
  if (report.version !== expected.version) fail('artifact report version mismatch');
  if (report.sourceTag !== expected.sourceTag) fail('artifact report source tag mismatch');
  if (report.commit !== expected.commit || !HEX_40.test(report.commit)) {
    fail('artifact report commit mismatch');
  }
  if (String(report.runId) !== String(expected.runId)) fail('artifact report run ID mismatch');
  if (String(report.runAttempt) !== String(expected.runAttempt)) {
    fail('artifact report run attempt mismatch');
  }
  if (report.correlationId !== expected.correlationId || !CORRELATION.test(report.correlationId)) {
    fail('artifact report correlation mismatch');
  }
  if (report.eventName !== 'workflow_dispatch'
      || report.workflow !== '.github/workflows/npm-publish.yml') {
    fail('artifact report workflow identity mismatch');
  }
  if (canonicalJson(report.platform) !== canonicalJson(FROZEN_TOOLCHAIN.platform)) {
    fail('artifact report platform mismatch');
  }
  requireHash(report.provenanceTrustPolicySha256, HEX_64,
    'artifact report provenance trust policy SHA-256');
  if (expected.provenanceTrustPolicySha256
      && report.provenanceTrustPolicySha256 !== expected.provenanceTrustPolicySha256) {
    fail('artifact report provenance trust policy mismatch');
  }
  assertExactToolchain(report.toolchain);
  const expectedPaths = {
    coreTarball: `npm-tarballs/hd-wallet-wasm-${expected.version}.tgz`,
    originService: `origin-service/sdn-wallet-origin-${expected.version}-node24-linux-x64.tar.gz`,
    uiTarball: `npm-tarballs/hd-wallet-ui-${expected.version}.tgz`,
  };
  for (const [name, path] of Object.entries(expectedPaths)) {
    const artifact = report.artifacts?.[name];
    if (!artifact || artifact.path !== path) fail(`artifact report ${name} path mismatch`);
    requireHash(artifact.sha256, HEX_64, `${name} SHA-256`);
    requireHash(artifact.sha512, HEX_128, `${name} SHA-512`);
  }
  return true;
}

export function validateOpenSslBuildScript(script) {
  if (typeof script !== 'string') fail('OpenSSL build script must be text');
  if (!script.includes(
    "OPENSSL_SHA256='eb1ab04781474360f77c318ab89d8c5a03abc38e63d65a603cabbf1b00a1dc90'",
  )) fail('OpenSSL SHA-256 is not frozen');
  for (const text of [
    'mktemp -d',
    'mktemp',
    'compute_sha256',
    'sha256sum -- "${file}"',
    'shasum -a 256 -- "${file}"',
    '[[ "${actual_sha256}" == "${OPENSSL_SHA256}" ]]',
    'reject_unsafe_archive',
    'trap cleanup EXIT',
    'curl --fail --location',
    '--no-same-owner',
    '--no-same-permissions',
    'rm -rf -- "${BUILD_DIR}" "${DIST_DIR}"',
  ]) if (!script.includes(text)) fail(`OpenSSL archive safety contract is missing ${text}`);
  if (/already downloaded|cache-hit|reuse/u.test(script)) {
    fail('OpenSSL build script may not reuse an unverified directory');
  }
  return true;
}

export function validateCiLocalScript(script) {
  if (typeof script !== 'string') fail('local CI script must be text');
  if (!script.includes('set -euo pipefail')) fail('local CI must use strict shell mode');
  const modeScan = script.replaceAll('--skip-tag', '');
  if (/\bskip(?:ped)?\b|\bquick\b|\bMODE\b|case\s+"?\$/iu.test(modeScan)) {
    fail('local CI must not contain a skip or partial mode');
  }
  const commands = [
    'npm ci --ignore-scripts',
    'node scripts/acquire-better-sqlite3-prebuild.mjs',
    'npm run test:offline-contracts',
    'npm run build:release',
    'npm run test:release',
    'npm run test:native',
    'npm run test:wasm',
    'npm run test:wallet-ui',
    'npm run test:relay',
    'npm run test:browser',
    'npm run test:packed',
    'npm run verify:release -- --version 2.0.26 --source-ref HEAD --skip-tag',
    'git diff --exit-code',
  ];
  let prior = -1;
  for (const command of commands) {
    const index = script.indexOf(command);
    if (index === -1) fail(`local CI is missing ${command}`);
    if (index <= prior) fail(`local CI command order is invalid at ${command}`);
    prior = index;
  }
  if ((script.match(/git status --porcelain=v1 --untracked-files=all/gu) ?? []).length !== 2
      || script.lastIndexOf('git status --porcelain=v1 --untracked-files=all') <= prior) {
    fail('local CI must check clean status before and after all gates');
  }
  return true;
}

export function validateReleaseInstallPolicy({ localCi, originBuilder, publishWorkflow }) {
  for (const [label, source] of [
    ['origin builder', originBuilder],
    ['local CI', localCi],
    ['publish workflow', publishWorkflow],
  ]) {
    if (typeof source !== 'string' || source.includes('--ignore-scripts=false')) {
      fail(`${label} enables npm lifecycle scripts`);
    }
  }
  const builderInstalls = originBuilder.match(/runChecked\('npm', \['ci',[^\n]*/gu) ?? [];
  if (builderInstalls.length !== 1 || !builderInstalls[0].includes("'--ignore-scripts'")) {
    fail('origin builder npm ci must disable lifecycle scripts exactly once');
  }
  for (const [label, source] of [
    ['local CI', localCi],
    ['publish workflow', publishWorkflow],
  ]) {
    const installs = source.match(/^\s*(?:run:\s*)?npm ci[^\n]*$/gmu) ?? [];
    if (installs.length === 0 || installs.some((line) => !line.includes('--ignore-scripts'))) {
      fail(`${label} npm ci must disable lifecycle scripts`);
    }
  }
  const localInstall = localCi.indexOf('npm ci --ignore-scripts');
  const localAcquisition = localCi.indexOf('node scripts/acquire-better-sqlite3-prebuild.mjs');
  const localTests = localCi.indexOf('npm run test:offline-contracts');
  if (localInstall === -1 || localAcquisition <= localInstall || localTests <= localAcquisition) {
    fail('local CI must stage the verified addon before any release tests');
  }
  return true;
}

function assertPinnedActions(yaml, label) {
  const uses = [...yaml.matchAll(/^\s*-?\s*uses:\s*([^\s#]+)\s*$/gmu)].map((match) => match[1]);
  if (uses.length === 0) fail(`${label} workflow has no actions`);
  for (const value of uses) {
    const match = /^([^@]+)@([0-9a-f]{40})$/u.exec(value);
    if (!match) fail(`${label} workflow contains an unpinned action: ${value}`);
    const expected = APPROVED_ACTIONS[match[1]];
    if (!expected || expected !== match[2]) fail(`${label} workflow action is not approved: ${value}`);
  }
  const requiredActions = REQUIRED_ACTIONS[label];
  if (!requiredActions) fail(`unknown release workflow: ${label}`);
  for (const action of requiredActions) {
    const commit = APPROVED_ACTIONS[action];
    if (!uses.includes(`${action}@${commit}`)) fail(`${label} workflow omits pinned ${action}`);
  }
}

function assertNoCaches(yaml, label) {
  if (/actions\/cache|^\s*cache\s*:/mu.test(yaml)) fail(`${label} workflow may not use caches`);
  if (/actions\/download-artifact/u.test(yaml)) {
    fail(`${label} workflow may not consume downloaded build artifacts`);
  }
}

function assertExactNpm(yaml, label) {
  if (!yaml.includes('npm@11.16.0')) fail(`${label} workflow must install exact npm 11.16.0`);
  const mentions = [...yaml.matchAll(/npm@([^\s'"\\]+)/gu)].map((match) => match[1]);
  if (mentions.some((version) => version !== '11.16.0')) {
    fail(`${label} workflow contains a non-frozen npm version`);
  }
}

export function validateBuildWorkflow(yaml) {
  if (typeof yaml !== 'string') fail('build workflow must be text');
  if (!/^\s*runs-on:\s*ubuntu-24\.04\s*$/mu.test(yaml) || /ubuntu-latest/u.test(yaml)) {
    fail('build workflow runner must be ubuntu-24.04');
  }
  assertPinnedActions(yaml, 'build');
  assertExactNpm(yaml, 'build');
  for (const text of [
    'node-version: "24.18.0"',
    'version: "3.1.51"',
    './scripts/ci-local.sh',
    '--emit-artifacts',
    'release/toolchain.v1.json',
  ]) if (!yaml.includes(text)) fail(`build workflow is missing ${text}`);
  return true;
}

export function validatePublishWorkflow(yaml) {
  if (typeof yaml !== 'string') fail('publish workflow must be text');
  if (/^\s*push\s*:/mu.test(yaml)) fail('publish workflow must not be reachable from push');
  if (!/^\s*workflow_dispatch\s*:/mu.test(yaml)) fail('publish workflow must use workflow_dispatch');
  for (const input of ['source_tag', 'dist_tag', 'correlation_id']) {
    if (!new RegExp(`^\\s{6}${input}:\\s*$`, 'mu').test(yaml)) {
      fail(`publish workflow is missing dispatch input ${input}`);
    }
  }
  if (/^\s{6}(?:dry_run|token):\s*$/mu.test(yaml)) {
    fail('publish workflow contains a forbidden input');
  }
  const jobsText = yaml.slice(yaml.search(/^jobs:\s*$/mu));
  const jobs = [...jobsText.matchAll(/^ {2}([a-zA-Z0-9_-]+):\s*$/gmu)].map((match) => match[1]);
  if (jobs.length !== 1 || jobs[0] !== 'publish') fail('publish workflow must contain one publish job');
  if (!/^\s*runs-on:\s*ubuntu-24\.04\s*$/mu.test(yaml) || /ubuntu-latest/u.test(yaml)) {
    fail('publish workflow runner must be ubuntu-24.04');
  }
  if (!/^\s*environment:\s*npm-publish\s*$/mu.test(yaml)) {
    fail('publish workflow must use the protected npm-publish environment');
  }
  if (!/^permissions:[ \t]*\n  contents: read[ \t]*\n  id-token: write[ \t]*\n  attestations: write[ \t]*\n[ \t]*\njobs:[ \t]*$/mu.test(yaml)) {
    fail('publish workflow must have exact least-privilege permissions');
  }
  assertPinnedActions(yaml, 'publish');
  assertNoCaches(yaml, 'publish');
  assertExactNpm(yaml, 'publish');
  if (!yaml.includes('test "$GITHUB_REF" = "refs/tags/$SOURCE_TAG"')
      || !yaml.includes('test "$GITHUB_REF_TYPE" = tag')
      || !yaml.includes('test "$GITHUB_REF_NAME" = "$SOURCE_TAG"')) {
    fail('publish workflow dispatch ref must be bound to the exact source tag');
  }
  if (!yaml.includes('test "$GITHUB_SHA" = "$tag_commit"')) {
    fail('publish workflow dispatch commit must equal the signed tag commit');
  }
  for (const text of [
    'run-name: sdn-wallet-stage-${{ inputs.correlation_id }}',
    'node-version: "24.18.0"',
    'version: "3.1.51"',
    'fetch-depth: 0',
    'ref: refs/tags/${{ inputs.source_tag }}',
    'WALLET_RELEASE_GPG_PUBLIC_KEY_BASE64',
    'WALLET_RELEASE_GPG_FINGERPRINT',
    'GNUPGHOME',
    'git verify-tag --raw',
    'VALIDSIG',
    'uname -m',
    'getconf GNU_LIBC_VERSION',
    'glibc 2.39',
    '--emit-artifacts',
    'release/provenance-trust.v1.json',
    'npm publish --provenance --tag',
    'npm view',
    "grep -Fq 'E404'",
    'github.run_attempt',
    'Verify final registry subjects match signed workflow artifacts',
    'record?.gitHead !== commit',
    'run: npm ci --ignore-scripts',
    'gh_2.96.0_linux_amd64.tar.gz',
    '14652560',
    '83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60',
    '40722594',
    '56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40',
    'gh version 2\\.96\\.0',
    'id: attest-origin-release',
    'workflow-artifacts.sigstore.json',
    '${{ steps.attest-origin-release.outputs.bundle-path }}',
    '--workflow-artifact-attestation',
  ]) if (!yaml.includes(text)) fail(`publish workflow is missing ${text}`);
  const exactSubjects = `subject-path: |
            \${{ runner.temp }}/sdn-wallet-artifacts/origin-service/sdn-wallet-origin-2.0.26-node24-linux-x64.tar.gz
            \${{ runner.temp }}/sdn-wallet-artifacts/wallet-release-report/release-report.v1.json`;
  if (!yaml.includes(exactSubjects)
      || (yaml.match(/actions\/attest@/gu) ?? []).length !== 1) {
    fail('publish workflow attestation subjects are not the exact origin archive and release report');
  }
  const evidenceIndex = yaml.indexOf('> "$provenance_root/npm-provenance-evidence.v1.json"');
  const attestIndex = yaml.indexOf('id: attest-origin-release');
  const copyIndex = yaml.indexOf('steps.attest-origin-release.outputs.bundle-path');
  const verifyIndex = yaml.lastIndexOf('--workflow-artifact-attestation');
  if (evidenceIndex === -1 || attestIndex <= evidenceIndex || copyIndex <= attestIndex
      || verifyIndex <= copyIndex) {
    fail('publish workflow must attest only after finalized provenance and verify the copied bundle');
  }
  if ((yaml.match(/--npm-cli "\$npm_cli"/gu) ?? []).length !== 2) {
    fail('publish workflow must pass the exact npm CLI once per provenance collection');
  }
  if (/npm\s+version/u.test(yaml)) fail('publish workflow must not run npm version');
  if (/--tag\s+["']?latest\b/u.test(yaml)) fail('publish workflow must not publish to latest');
  return true;
}

function runGit(arguments_, options = {}) {
  return execFileSync('git', arguments_, {
    cwd: repositoryDirectory,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  }).trim();
}

async function sha(path, algorithm) {
  return createHash(algorithm).update(await readFile(path)).digest('hex');
}

async function readJson(path) {
  return JSON.parse(await readFile(path, 'utf8'));
}

function cmakeVersion(text) {
  const major = /^set\(HD_WALLET_VERSION_MAJOR\s+(\d+)\)$/mu.exec(text)?.[1];
  const minor = /^set\(HD_WALLET_VERSION_MINOR\s+(\d+)\)$/mu.exec(text)?.[1];
  const patch = /^set\(HD_WALLET_VERSION_PATCH\s+(\d+)\)$/mu.exec(text)?.[1];
  if ([major, minor, patch].some((part) => part === undefined)) fail('CMake version is missing');
  return `${major}.${minor}.${patch}`;
}

async function collectVersionContract(packedCorePackage, packedUiPackage) {
  const [rootPackage, lock, corePackage, uiPackage, relayPackage, cmake] = await Promise.all([
    readJson(join(repositoryDirectory, 'package.json')),
    readJson(join(repositoryDirectory, 'package-lock.json')),
    readJson(join(repositoryDirectory, 'wasm/package.json')),
    readJson(join(repositoryDirectory, 'wallet-ui/package.json')),
    readJson(join(repositoryDirectory, 'wallet-ui/relay/package.json')),
    readFile(join(repositoryDirectory, 'CMakeLists.txt'), 'utf8'),
  ]);
  return {
    cmakeVersion: cmakeVersion(cmake),
    corePackage,
    lockCoreFlatbuffers: lock.packages?.wasm?.dependencies?.flatbuffers,
    lockCoreVersion: lock.packages?.wasm?.version,
    lockRootVersion: lock.packages?.['']?.version,
    lockUiVersion: lock.packages?.['wallet-ui']?.version,
    packedCorePackage: packedCorePackage ?? corePackage,
    packedUiPackage: packedUiPackage ?? uiPackage,
    relayPackage,
    rootPackage,
    uiPackage,
  };
}

async function assertLineage(sourceRef) {
  const lineage = await readJson(join(repositoryDirectory, 'release/lineage.v1.json'));
  if (lineage.schemaVersion !== 1) fail('release lineage schema is invalid');
  const expected = {
    uiLifecycleV2019: '537ac9a08c12fb62a7152007bce9898efb6f9204',
    walletCoreV2021: '3c4258a8fa3ef9bc5a86c786231bf5f3c5c568c9',
  };
  if (canonicalJson(lineage.requiredAncestors) !== canonicalJson(expected)) {
    fail('release lineage frozen ancestors mismatch');
  }
  for (const commit of Object.values(expected)) {
    try {
      execFileSync('git', ['merge-base', '--is-ancestor', commit, sourceRef], {
        cwd: repositoryDirectory,
        stdio: 'pipe',
      });
    } catch {
      fail(`required lineage ancestor is absent: ${commit}`);
    }
  }
}

async function assertRegistry() {
  const registry = await readJson(join(
    repositoryDirectory,
    'wallet-ui/relay/config/client-registry.v1.json',
  ));
  const claimed = registry.registryReleaseSha256;
  requireHash(claimed, HEX_64, 'registry release');
  const unsigned = { clients: registry.clients, schemaVersion: registry.schemaVersion };
  const computed = createHash('sha256').update(canonicalJson(unsigned)).digest('hex');
  if (computed !== claimed) fail('registry release hash mismatch');
  return claimed;
}

async function assertFixtureHashes() {
  const manifestPath = join(repositoryDirectory, 'test/fixtures/fixture-integrity.json');
  const manifest = await readJson(manifestPath);
  for (const entry of manifest.entries ?? []) {
    const path = join(repositoryDirectory, entry.path);
    const metadata = await stat(path);
    if (metadata.size !== entry.bytes || await sha(path, 'sha256') !== entry.sha256) {
      fail(`fixture integrity mismatch: ${entry.path}`);
    }
  }
  return sha(manifestPath, 'sha256');
}

async function walk(directory, base = directory) {
  const entries = [];
  for (const item of await readdir(directory, { withFileTypes: true })) {
    const path = join(directory, item.name);
    if (item.isSymbolicLink()) fail(`release tree contains a symlink: ${path}`);
    if (item.isDirectory()) entries.push(...await walk(path, base));
    else if (item.isFile()) entries.push(relative(base, path).replaceAll('\\', '/'));
    else fail(`release tree contains an unsupported entry: ${path}`);
  }
  return entries.sort();
}

function npmExecutable() {
  const executable = process.env.npm_execpath;
  if (typeof executable !== 'string' || executable.length === 0) {
    fail('release verification must be invoked through npm run verify:release');
  }
  return executable;
}

function assertPackageInventory(files, expected, label) {
  const actual = [...files].sort();
  if (canonicalJson(actual) !== canonicalJson([...expected].sort())) {
    fail(`${label} package file inventory mismatch`);
  }
  for (const path of actual) {
    if (path.endsWith('.tgz') || path.endsWith('.map')
        || /(?:^|\/)node_modules\//u.test(path) || /^(?:src|test)\//u.test(path)) {
      fail(`${label} package contains forbidden file: ${path}`);
    }
  }
}

function parsePackedManifest(archivePath) {
  let text;
  try {
    text = execFileSync('tar', ['-xOf', archivePath, 'package/package.json'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  } catch {
    fail(`cannot read packed package manifest: ${archivePath}`);
  }
  try {
    return JSON.parse(text);
  } catch {
    fail(`packed package manifest is invalid: ${archivePath}`);
  }
}

function packedArchiveFiles(archivePath) {
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
    fail(`cannot inspect packed package archive: ${archivePath}`);
  }
  for (const line of verbose.split('\n').filter(Boolean)) {
    const kind = line[0];
    if (kind !== '-' && kind !== 'd') fail(`packed package contains a link or special entry: ${archivePath}`);
  }
  return listing.split('\n').filter((path) => path.startsWith('package/') && !path.endsWith('/'))
    .map((path) => path.slice('package/'.length)).sort();
}

function assertPackedArchiveInventories(corePath, uiPath) {
  const coreFiles = packedArchiveFiles(corePath);
  const uiFiles = packedArchiveFiles(uiPath);
  const uiHostAssets = uiFiles.filter((path) => path.startsWith(
    'dist/wallet-origin-host/assets/',
  ));
  const extensions = uiHostAssets.map((path) => {
    const match = /^dist\/wallet-origin-host\/assets\/wallet-origin\.([0-9a-f]{64})\.(css|js|wasm)$/u
      .exec(path);
    if (!match) fail(`unexpected packed UI wallet-origin asset: ${path}`);
    return match[2];
  }).sort();
  if (canonicalJson(extensions) !== canonicalJson(['css', 'js', 'wasm'])) {
    fail('packed UI archive must contain one hashed CSS, JS, and WASM origin asset');
  }
  assertPackageInventory(coreFiles, CORE_FILES, 'core archive');
  assertPackageInventory(uiFiles, [...UI_FIXED_FILES, ...uiHostAssets], 'UI archive');
  return { coreFiles, uiFiles };
}

async function packageDigestRecord(path, artifactPath) {
  const bytes = await readFile(path);
  return {
    bytes: bytes.length,
    path: artifactPath,
    sha256: createHash('sha256').update(bytes).digest('hex'),
    sha512: createHash('sha512').update(bytes).digest('hex'),
  };
}

function assertManifestContracts(core, ui, version, sourceCommit) {
  if (!HEX_40.test(sourceCommit) || core.gitHead !== sourceCommit || ui.gitHead !== sourceCommit) {
    fail('packed package manifests must bind the exact source commit');
  }
  if (core.type !== 'module' || core.license !== 'Apache-2.0'
      || core.types !== './dist/runtime/index.d.ts') {
    fail('core package entrypoint/type/license contract drifted');
  }
  if (canonicalJson(Object.keys(core.exports ?? {}).sort()) !== canonicalJson([
    '.', './aligned', './attestation', './dist/hd-wallet-wasi.wasm', './wasi.wasm', './wasm',
  ].sort())) fail('core package exports drifted');
  if (ui.type !== 'module' || ui.license !== 'Apache-2.0'
      || ui.types !== './dist/compat/index.d.ts') {
    fail('UI package entrypoint/type/license contract drifted');
  }
  if (canonicalJson(Object.keys(ui.exports ?? {}).sort()) !== canonicalJson([
    '.', './client', './client/asset-review', './client/callback', './client/sdn',
    './styles', './wallet-origin',
  ].sort())) fail('UI package exports drifted');
  exactDependency(ui, version, 'packed UI');
}

async function packAndVerifyPackages(version, sourceCommit) {
  const temporaryDirectory = await mkdtemp(join(tmpdir(), 'hd-wallet-release-pack-'));
  try {
    execFileSync(process.execPath, [join(scriptDirectory, 'stage-core-package.mjs')], {
      cwd: repositoryDirectory,
      env: { ...process.env, npm_config_offline: 'true' },
      stdio: 'pipe',
    });
    const core = await packWorkspaceReleaseSubject({
      destination: temporaryDirectory,
      sourceCommit,
      workspaceDirectory: join(repositoryDirectory, 'wasm'),
    });
    const ui = await packWorkspaceReleaseSubject({
      destination: temporaryDirectory,
      sourceCommit,
      workspaceDirectory: join(repositoryDirectory, 'wallet-ui'),
    });
    const uiHostAssets = ui.files.filter((path) => path.startsWith(
      'dist/wallet-origin-host/assets/',
    ));
    const extensions = [];
    for (const path of uiHostAssets) {
      const match = /^dist\/wallet-origin-host\/assets\/wallet-origin\.([0-9a-f]{64})\.(css|js|wasm)$/u
        .exec(path);
      if (!match) fail(`unexpected UI wallet-origin asset: ${path}`);
      extensions.push(match[2]);
    }
    if (canonicalJson(extensions.sort()) !== canonicalJson(['css', 'js', 'wasm'])) {
      fail('UI package must contain one hashed CSS, JS, and WASM origin asset');
    }
    assertPackageInventory(core.files, CORE_FILES, 'core');
    assertPackageInventory(ui.files, [...UI_FIXED_FILES, ...uiHostAssets], 'UI');
    const coreManifest = parsePackedManifest(core.archivePath);
    const uiManifest = parsePackedManifest(ui.archivePath);
    assertManifestContracts(coreManifest, uiManifest, version, sourceCommit);
    validateVersionContract(
      await collectVersionContract(coreManifest, uiManifest),
      version,
    );

    execFileSync(process.execPath, [join(scriptDirectory, 'test-packed-consumers.mjs')], {
      cwd: repositoryDirectory,
      env: { ...process.env, npm_config_offline: 'true' },
      stdio: 'inherit',
    });

    const retainedDirectory = await mkdtemp(join(tmpdir(), 'hd-wallet-release-subjects-'));
    const retainedCore = join(retainedDirectory, basename(core.archivePath));
    const retainedUi = join(retainedDirectory, basename(ui.archivePath));
    await Promise.all([
      copyFile(core.archivePath, retainedCore),
      copyFile(ui.archivePath, retainedUi),
    ]);
    return {
      cleanupDirectory: retainedDirectory,
      core: {
        archivePath: retainedCore,
        files: core.files,
        manifest: coreManifest,
      },
      ui: {
        archivePath: retainedUi,
        files: ui.files,
        manifest: uiManifest,
      },
    };
  } finally {
    await rm(temporaryDirectory, { force: true, recursive: true });
  }
}

async function copyRegularTree(source, destination) {
  const sourceStatus = await lstat(source);
  if (!sourceStatus.isDirectory() || sourceStatus.isSymbolicLink()) {
    fail(`release copy source is not a real directory: ${source}`);
  }
  await mkdir(destination, { recursive: false });
  for (const item of await readdir(source, { withFileTypes: true })) {
    const sourcePath = join(source, item.name);
    const destinationPath = join(destination, item.name);
    const status = await lstat(sourcePath);
    if (status.isSymbolicLink()) fail(`release copy source contains a symlink: ${sourcePath}`);
    if (status.isDirectory()) await copyRegularTree(sourcePath, destinationPath);
    else if (status.isFile()) await copyFile(sourcePath, destinationPath);
    else fail(`release copy source contains an unsupported entry: ${sourcePath}`);
  }
}

function observedNpmVersion() {
  return execFileSync(process.execPath, [npmExecutable(), '--version'], {
    cwd: repositoryDirectory,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim();
}

async function assertPublishableToolchain(toolchain) {
  assertExactToolchain(toolchain);
  const glibc = process.report?.getReport?.().header?.glibcVersionRuntime;
  const actualPlatform = { architecture: process.arch, glibc, os: process.platform };
  if (canonicalJson(actualPlatform) !== canonicalJson(toolchain.platform)) {
    fail('publishable artifacts require exact Linux x64 glibc 2.39');
  }
  if (process.versions.node !== toolchain.node.version) {
    fail(`publishable artifacts require Node ${toolchain.node.version}`);
  }
  if (observedNpmVersion() !== toolchain.npm.version) {
    fail(`publishable artifacts require npm ${toolchain.npm.version}`);
  }
  const emcc = execFileSync('emcc', ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (!emcc.split('\n')[0].includes(toolchain.emscripten.version)) {
    fail(`publishable artifacts require Emscripten ${toolchain.emscripten.version}`);
  }
  const cmake = execFileSync('cmake', ['--version'], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  if (cmake.split('\n')[0] !== `cmake version ${toolchain.cmake.version}`) {
    fail(`publishable artifacts require CMake ${toolchain.cmake.version}`);
  }
  const cmakeSource = await readFile(join(repositoryDirectory, 'CMakeLists.txt'), 'utf8');
  const cryptoppWrapperUrl = `https://github.com/abdes/cryptopp-cmake/archive/${toolchain.cryptoppCmake.sourceCommit}.tar.gz`;
  if (!cmakeSource.includes(toolchain.cryptopp.commit)
      || !cmakeSource.includes(toolchain.cryptopp.repository)
      || !cmakeSource.includes(cryptoppWrapperUrl)
      || !cmakeSource.includes(`SHA256=${toolchain.cryptoppCmake.sourceSha256}`)
      || !cmakeSource.includes(toolchain.secp256k1.commit)) {
    fail('publishable dependency commits do not match the frozen toolchain');
  }
  const cryptoppSource = join(
    repositoryDirectory,
    'build-wasm/_deps/cryptopp-cmake-build/cryptopp',
  );
  const cryptoppStatus = await lstat(cryptoppSource).catch(() => null);
  if (!cryptoppStatus?.isDirectory() || cryptoppStatus.isSymbolicLink()) {
    fail('publishable Crypto++ source checkout is missing');
  }
  let cryptoppCommit;
  let cryptoppRepository;
  try {
    cryptoppCommit = execFileSync('git', ['rev-parse', 'HEAD'], {
      cwd: cryptoppSource,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
    cryptoppRepository = execFileSync('git', ['remote', 'get-url', 'origin'], {
      cwd: cryptoppSource,
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    }).trim();
  } catch {
    fail('cannot inspect the publishable Crypto++ source checkout');
  }
  if (cryptoppCommit !== toolchain.cryptopp.commit
      || cryptoppRepository !== toolchain.cryptopp.repository) {
    fail('publishable Crypto++ source checkout does not match the frozen toolchain');
  }
  validateOpenSslBuildScript(await readFile(join(repositoryDirectory, 'openssl-fips/build.sh'), 'utf8'));
  const cryptoArchive = join(repositoryDirectory, 'openssl-fips/dist/lib/libcrypto.a');
  const cryptoStatus = await lstat(cryptoArchive).catch(() => null);
  if (!cryptoStatus?.isFile() || cryptoStatus.isSymbolicLink() || cryptoStatus.size <= 0) {
    fail('verified OpenSSL FIPS output is missing');
  }
  return {
    cmake: toolchain.cmake.version,
    emscripten: toolchain.emscripten.version,
    node: process.versions.node,
    npm: observedNpmVersion(),
    openssl: toolchain.openssl.version,
  };
}

async function passwordCorpusRecord() {
  const metadata = await readJson(join(
    repositoryDirectory,
    'wallet-ui/data/common-passwords-sdn-v1.source.json',
  ));
  const path = join(repositoryDirectory, 'wallet-ui/data/common-passwords-sdn-v1.txt');
  const bytes = await readFile(path);
  const entries = bytes.toString('utf8').split('\n').filter((line) => line.length > 0).length;
  if (metadata.bytes !== bytes.length || metadata.sha256 !== createHash('sha256').update(bytes).digest('hex')) {
    fail('password corpus metadata mismatch');
  }
  return {
    bytes: bytes.length,
    entries,
    sha256: metadata.sha256,
    sourceCommit: metadata.upstreamCommit,
    sourcePath: metadata.sourcePath,
    sourceRelease: metadata.upstreamRelease,
  };
}

async function readCanonicalJsonFile(path, label) {
  const status = await lstat(path).catch(() => null);
  if (!status?.isFile() || status.isSymbolicLink() || status.size <= 0) {
    fail(`${label} must be a non-empty regular file`);
  }
  const bytes = await readFile(path);
  let value;
  try {
    value = JSON.parse(bytes.toString('utf8'));
  } catch {
    fail(`${label} is not valid JSON`);
  }
  if (bytes.toString('utf8') !== `${canonicalJson(value)}\n`) {
    fail(`${label} must be JCS plus one LF`);
  }
  return { bytes, value };
}

async function verifyEvidenceRecord({
  baseReport,
  options,
  packageResult,
  workflowReport,
}) {
  if (!options.evidenceRecord) return;
  const recordPath = resolve(options.evidenceRecord);
  const evidencePath = options.provenanceEvidence
    ? resolve(options.provenanceEvidence)
    : join(dirname(recordPath), 'npm-provenance-evidence.v1.json');
  const [{ bytes: evidenceBytes, value: evidence }, { value: record }] = await Promise.all([
    readCanonicalJsonFile(evidencePath, 'npm provenance evidence'),
    readCanonicalJsonFile(recordPath, 'release record'),
  ]);
  validateReleaseRecord(record);
  const sourceTag = `v${options.version}`;
  let trustPolicyBytes;
  try {
    trustPolicyBytes = execFileSync(
      'git', ['show', `${sourceTag}:release/provenance-trust.v1.json`],
      { cwd: repositoryDirectory, encoding: null, stdio: ['ignore', 'pipe', 'pipe'] },
    );
  } catch {
    fail('signed tag does not contain the provenance trust policy');
  }
  let trustPolicy;
  try {
    trustPolicy = JSON.parse(trustPolicyBytes.toString('utf8'));
  } catch {
    fail('signed-tag provenance trust policy is not valid JSON');
  }
  if (trustPolicyBytes.toString('utf8') !== `${canonicalJson(trustPolicy)}\n`) {
    fail('signed-tag provenance trust policy must be JCS plus one LF');
  }
  const {
    serializeProvenanceEvidence,
    validateProvenanceTrustPolicy,
    verifyProvenanceEvidence,
  } = await import('./verify-provenance-evidence.mjs');
  validateProvenanceTrustPolicy(trustPolicy);
  const verifiedEvidence = verifyProvenanceEvidence(evidence, trustPolicy);
  if (serializeProvenanceEvidence(verifiedEvidence, trustPolicy)
      !== evidenceBytes.toString('utf8')) {
    fail('npm provenance evidence serialization mismatch');
  }
  const evidenceSha256 = createHash('sha256').update(evidenceBytes).digest('hex');
  const trustPolicySha256 = createHash('sha256').update(trustPolicyBytes).digest('hex');
  if (record.npmProvenanceEvidenceSha256 !== evidenceSha256) {
    fail('release record npm provenance evidence hash mismatch');
  }
  for (const [field, expected] of [
    ['version', options.version],
    ['sourceTag', `v${options.version}`],
    ['gitCommit', baseReport.commit],
    ['assetReviewProtocolSha256', baseReport.assetReviewProtocolSha256],
    ['provenanceTrustPolicySha256', trustPolicySha256],
    ['registryReleaseSha256', baseReport.registryReleaseSha256],
    ['walletAssetsManifestSha256', baseReport.walletAssetsManifestSha256],
  ]) if (record[field] !== expected) fail(`release record ${field} mismatch`);
  if (evidence.commit !== baseReport.commit || evidence.sourceTag !== `v${options.version}`
      || evidence.repository !== 'https://github.com/DigitalArsenal/hd-wallet-wasm') {
    fail('npm provenance evidence source binding mismatch');
  }
  if (evidence.workflow?.name !== 'npm-publish.yml'
      || evidence.workflow?.path !== '.github/workflows/npm-publish.yml') {
    fail('npm provenance evidence workflow binding mismatch');
  }
  if (canonicalJson(record.passwordCorpus) !== canonicalJson(await passwordCorpusRecord())) {
    fail('release record password corpus mismatch');
  }

  const packageBindings = [
    ['corePackage', 'hd-wallet-wasm', 'coreTarball'],
    ['uiPackage', 'hd-wallet-ui', 'uiTarball'],
  ];
  for (const [recordField, packageName, artifactName] of packageBindings) {
    const packageEvidence = evidence.packages?.find((entry) => entry.name === packageName);
    if (!packageEvidence || packageEvidence.version !== options.version) {
      fail(`npm provenance evidence package is missing: ${packageName}`);
    }
    const packageRecord = record[recordField];
    const evidenceObjectSha256 = createHash('sha256')
      .update(canonicalJson(packageEvidence)).digest('hex');
    if (packageRecord.provenanceSha256 !== evidenceObjectSha256
        || packageRecord.integrity !== packageEvidence.integrity
        || packageRecord.tarballSha512 !== packageEvidence.tarball?.sha512
        || packageEvidence.subject?.digest?.sha512 !== packageEvidence.tarball?.sha512) {
      fail(`release record package evidence mismatch: ${packageName}`);
    }
    let localSha512;
    if (workflowReport) localSha512 = workflowReport.artifacts?.[artifactName]?.sha512;
    else if (packageResult) {
      const packagePath = packageName === 'hd-wallet-wasm'
        ? packageResult.core.archivePath : packageResult.ui.archivePath;
      localSha512 = await sha(packagePath, 'sha512');
    }
    if (localSha512 && localSha512 !== packageRecord.tarballSha512) {
      fail(`release record tarball differs from verified artifact: ${packageName}`);
    }
  }
  if (workflowReport
      && record.originServiceArtifactSha256 !== workflowReport.artifacts?.originService?.sha256) {
    fail('release record origin-service artifact hash mismatch');
  }
}

async function ensureEmptyArtifactDirectory(path) {
  assertOutputOutsideSource(repositoryDirectory, path);
  const status = await lstat(path).catch(() => null);
  if (!status?.isDirectory() || status.isSymbolicLink()) {
    fail('--emit-artifacts must name an existing real directory');
  }
  const [actualOutput, actualSource] = await Promise.all([
    realpath(path),
    realpath(repositoryDirectory),
  ]);
  assertOutputOutsideSource(actualSource, actualOutput);
  if ((await readdir(actualOutput)).length !== 0) fail('--emit-artifacts directory must be empty');
  return actualOutput;
}

async function emitArtifacts({
  baseReport,
  options,
  packageResult,
  toolchain,
}) {
  const output = await ensureEmptyArtifactDirectory(resolve(options.emitArtifacts));
  const observedVersions = await assertPublishableToolchain(toolchain);
  const npmDirectory = join(output, 'npm-tarballs');
  const originDirectory = join(output, 'origin-service');
  const reportDirectory = join(output, 'wallet-release-report');
  await Promise.all([
    mkdir(npmDirectory),
    mkdir(originDirectory),
    mkdir(reportDirectory),
  ]);
  const coreTarget = join(npmDirectory, `hd-wallet-wasm-${options.version}.tgz`);
  const uiTarget = join(npmDirectory, `hd-wallet-ui-${options.version}.tgz`);
  await Promise.all([
    copyFile(packageResult.core.archivePath, coreTarget),
    copyFile(packageResult.ui.archivePath, uiTarget),
  ]);

  const { buildProductionOriginServiceRelease } = await import('./build-origin-service-release.mjs');
  const { verifyOriginServiceRelease } = await import('./verify-origin-service-release.mjs');
  const origin = await buildProductionOriginServiceRelease({
    outputDirectory: originDirectory,
    repositoryDirectory,
    version: options.version,
  });
  await verifyOriginServiceRelease({
    archivePath: origin.archivePath,
    checksumPath: origin.checksumPath,
  });

  const releaseTarget = join(reportDirectory, 'release');
  await mkdir(releaseTarget);
  await copyFile(
    join(repositoryDirectory, 'release/wallet-assets.v1.json'),
    join(releaseTarget, 'wallet-assets.v1.json'),
  );
  await copyFile(
    join(repositoryDirectory, 'release/provenance-trust.v1.json'),
    join(reportDirectory, 'provenance-trust.v1.json'),
  );
  await copyRegularTree(
    join(repositoryDirectory, 'release/static'),
    join(releaseTarget, 'static'),
  );

  const [coreArtifact, uiArtifact, originArtifact] = await Promise.all([
    packageDigestRecord(coreTarget, `npm-tarballs/${basename(coreTarget)}`),
    packageDigestRecord(uiTarget, `npm-tarballs/${basename(uiTarget)}`),
    packageDigestRecord(origin.archivePath, `origin-service/${basename(origin.archivePath)}`),
  ]);
  const report = {
    ...baseReport,
    artifacts: {
      coreTarball: coreArtifact,
      originService: originArtifact,
      uiTarball: uiArtifact,
    },
    correlationId: process.env.SDN_RELEASE_CORRELATION_ID ?? '0'.repeat(32),
    eventName: process.env.SDN_RELEASE_EVENT_NAME ?? 'local',
    observedVersions,
    packages: {
      core: {
        files: packageResult.core.files,
        name: 'hd-wallet-wasm',
        version: options.version,
      },
      ui: {
        dependency: { 'hd-wallet-wasm': options.version },
        files: packageResult.ui.files,
        name: 'hd-wallet-ui',
        version: options.version,
      },
    },
    passwordCorpus: await passwordCorpusRecord(),
    platform: { ...toolchain.platform },
    runAttempt: process.env.SDN_RELEASE_RUN_ATTEMPT ?? '1',
    runId: process.env.SDN_RELEASE_RUN_ID ?? 'local',
    runner: {
      architecture: process.arch,
      imageVersion: process.env.ImageVersion ?? 'local',
      osRelease: process.env.ImageOS ?? process.platform,
    },
    sourceTag: options.tag ?? process.env.SDN_RELEASE_SOURCE_TAG ?? null,
    toolchain,
    workflow: process.env.SDN_RELEASE_WORKFLOW ?? 'local',
  };
  await writeFile(
    join(reportDirectory, 'release-report.v1.json'),
    `${canonicalJson(report)}\n`,
    { encoding: 'utf8', flag: 'wx' },
  );
  validateWorkflowArtifactEntries(await walk(output), options.version);
  return report;
}

export async function verifyWorkflowArtifactsDirectory(rootPath, options, sourceCommit) {
  if (typeof options?.workflowArtifactAttestation !== 'string') {
    fail('workflow artifact attestation sidecar is required');
  }
  const inputRoot = resolve(rootPath);
  const originName = `sdn-wallet-origin-${options.version}-node24-linux-x64.tar.gz`;
  const inputOriginPath = join(inputRoot, 'origin-service', originName);
  const inputReportPath = join(
    inputRoot,
    'wallet-release-report/release-report.v1.json',
  );
  const verified = await verifyGithubArtifactAttestation({
    artifactPaths: [inputOriginPath, inputReportPath],
    bundlePath: options.workflowArtifactAttestation,
    runAttempt: String(options.expectedRunAttempt),
    runId: String(options.expectedRunId),
    sourceCommit,
    sourceTag: options.tag ?? `v${options.version}`,
    consumeVerifiedSnapshots: async ({ artifactPaths }) => {
      const root = await realpath(inputRoot);
      const entries = await walk(root);
      validateWorkflowArtifactEntries(entries, options.version);
      const reportPath = artifactPaths['release-report.v1.json'];
      const authenticatedOriginPath = artifactPaths[originName];
      if (!reportPath || !authenticatedOriginPath) {
        fail('authenticated workflow artifact snapshots are incomplete');
      }
      const reportText = await readFile(reportPath, 'utf8');
      let report;
      try {
        report = JSON.parse(reportText);
      } catch {
        fail('authenticated workflow artifact report is invalid JSON');
      }
      if (reportText !== `${canonicalJson(report)}\n`) {
        fail('workflow artifact report must be JCS plus one LF');
      }
      validateWorkflowArtifactReport(report, {
        commit: sourceCommit,
        correlationId: options.expectedCorrelation,
        runAttempt: options.expectedRunAttempt,
        runId: options.expectedRunId,
        sourceTag: options.tag ?? `v${options.version}`,
        version: options.version,
        provenanceTrustPolicySha256: options.expectedProvenanceTrustPolicySha256 ?? await sha(
          join(repositoryDirectory, 'release/provenance-trust.v1.json'), 'sha256',
        ),
      });
      for (const [name, artifact] of Object.entries(report.artifacts)) {
        const path = name === 'originService'
          ? authenticatedOriginPath
          : join(root, artifact.path);
        if (await sha(path, 'sha256') !== artifact.sha256
            || await sha(path, 'sha512') !== artifact.sha512) {
          fail(`workflow artifact hash mismatch: ${artifact.path}`);
        }
      }
      const checksumPath = join(root, `origin-service/${originName}.sha256`);
      const checksum = await readFile(checksumPath, 'utf8');
      if (checksum !== `${report.artifacts.originService.sha256}  ${originName}\n`) {
        fail('workflow origin-service checksum does not match the authenticated archive');
      }
      const corePath = join(root, `npm-tarballs/hd-wallet-wasm-${options.version}.tgz`);
      const uiPath = join(root, `npm-tarballs/hd-wallet-ui-${options.version}.tgz`);
      const inventories = assertPackedArchiveInventories(corePath, uiPath);
      const core = parsePackedManifest(corePath);
      const ui = parsePackedManifest(uiPath);
      assertManifestContracts(core, ui, options.version, sourceCommit);
      validateVersionContract(await collectVersionContract(core, ui), options.version);
      if (canonicalJson(report.packages?.core?.files) !== canonicalJson(inventories.coreFiles)
          || canonicalJson(report.packages?.ui?.files) !== canonicalJson(inventories.uiFiles)) {
        fail('workflow artifact report package inventory mismatch');
      }
      const copiedManifest = join(root, 'wallet-release-report/release/wallet-assets.v1.json');
      if (await sha(copiedManifest, 'sha256') !== report.walletAssetsManifestSha256) {
        fail('workflow wallet asset manifest hash mismatch');
      }
      const copiedTrustPolicy = join(root, 'wallet-release-report/provenance-trust.v1.json');
      if (await sha(copiedTrustPolicy, 'sha256') !== report.provenanceTrustPolicySha256) {
        fail('workflow provenance trust policy hash mismatch');
      }
      const { validateProvenanceTrustPolicy } = await import('./verify-provenance-evidence.mjs');
      validateProvenanceTrustPolicy(await readJson(copiedTrustPolicy));
      const { verifyWalletAssets } = await import('./verify-wallet-assets.mjs');
      await verifyWalletAssets({
        releaseDirectory: join(root, 'wallet-release-report/release'),
        repositoryDirectory,
        version: options.version,
      });
      const { verifyOriginServiceRelease } = await import('./verify-origin-service-release.mjs');
      const structural = await verifyOriginServiceRelease({
        archivePath: authenticatedOriginPath,
        requireChecksum: false,
        runHealthCheck: false,
      });
      if (structural.archiveSha256 !== report.artifacts.originService.sha256
          || structural.healthChecked || structural.shellChecked) {
        fail('authenticated origin-service structural verification mismatch');
      }
      const health = await verifyOriginServiceRelease({
        archivePath: authenticatedOriginPath,
        requireChecksum: false,
      });
      if (health.archiveSha256 !== structural.archiveSha256
          || !health.healthChecked || !health.shellChecked) {
        fail('authenticated origin-service health verification mismatch');
      }
      return report;
    },
  });
  return verified.consumed;
}

function assertPostEvidenceCommit(options) {
  if (!options.postEvidenceCommit) return;
  const tag = `v${options.version}`;
  if (runGit(['cat-file', '-t', tag]) !== 'tag') fail('source tag must be annotated');
  const tagCommit = runGit(['rev-parse', `${tag}^{commit}`]);
  const postCommit = runGit(['rev-parse', `${options.postEvidenceCommit}^{commit}`]);
  if (runGit(['rev-parse', 'HEAD']) !== postCommit) {
    fail('post-evidence commit mode requires HEAD to equal --post-evidence-commit');
  }
  const parents = runGit(['rev-list', '--parents', '-n', '1', postCommit]).split(/\s+/u);
  if (parents.length !== 2 || parents[1] !== tagCommit) {
    fail('post-evidence commit must have exactly the signed tag as its parent');
  }
  const changedPaths = runGit(['diff', '--name-only', `${tagCommit}..${postCommit}`])
    .split('\n').filter(Boolean).sort();
  const expected = [
    'release/npm-provenance-evidence.v1.json',
    'release/release-record.v1.json',
  ];
  if (canonicalJson(changedPaths) !== canonicalJson(expected)) {
    fail('post-evidence commit diff must contain exactly the two release evidence files');
  }
}

async function main() {
  const options = parseArguments(process.argv.slice(2));
  const before = runGit(['status', '--short', '--untracked-files=all']);
  assertCleanStatus(before);
  const sourceCommit = runGit(['rev-parse', `${options.sourceRef}^{commit}`]);
  if (!HEX_40.test(sourceCommit)) fail('source ref did not resolve to a commit');
  if (options.tag) {
    if (runGit(['cat-file', '-t', options.tag]) !== 'tag') {
      fail('release tag must be an annotated tag object');
    }
    const tagCommit = runGit(['rev-parse', `${options.tag}^{commit}`]);
    if (sourceCommit !== tagCommit) fail('source ref does not equal the signed tag commit');
  }
  assertPostEvidenceCommit(options);
  await assertLineage(options.sourceRef);
  validateVersionContract(await collectVersionContract(), options.version);
  const toolchainPath = join(repositoryDirectory, 'release/toolchain.v1.json');
  const toolchain = await readJson(toolchainPath);
  assertExactToolchain(toolchain);
  const [buildWorkflow, publishWorkflow, openSslBuild, localCi, originBuilder] = await Promise.all([
    readFile(join(repositoryDirectory, '.github/workflows/build.yml'), 'utf8'),
    readFile(join(repositoryDirectory, '.github/workflows/npm-publish.yml'), 'utf8'),
    readFile(join(repositoryDirectory, 'openssl-fips/build.sh'), 'utf8'),
    readFile(join(repositoryDirectory, 'scripts/ci-local.sh'), 'utf8'),
    readFile(join(repositoryDirectory, 'scripts/build-origin-service-release.mjs'), 'utf8'),
  ]);
  validateBuildWorkflow(buildWorkflow);
  validatePublishWorkflow(publishWorkflow);
  validateOpenSslBuildScript(openSslBuild);
  validateCiLocalScript(localCi);
  validateReleaseInstallPolicy({ localCi, originBuilder, publishWorkflow });
  const registryReleaseSha256 = await assertRegistry();
  const fixtureIntegritySha256 = await assertFixtureHashes();
  const provenanceTrustPolicyPath = join(repositoryDirectory, 'release/provenance-trust.v1.json');
  const [assetReviewProtocolSha256, provenanceTrustPolicySha256,
    walletAssetsManifestSha256] = await Promise.all([
    sha(join(repositoryDirectory, 'release/protocol/asset-review-v1.json'), 'sha256'),
    sha(provenanceTrustPolicyPath, 'sha256'),
    sha(join(repositoryDirectory, 'release/wallet-assets.v1.json'), 'sha256'),
  ]);
  const { validateProvenanceTrustPolicy } = await import('./verify-provenance-evidence.mjs');
  validateProvenanceTrustPolicy(await readJson(provenanceTrustPolicyPath));

  execFileSync(process.execPath, [join(scriptDirectory, 'verify-wallet-assets.mjs'),
    '--version', options.version], {
    cwd: repositoryDirectory,
    env: { ...process.env, npm_config_offline: 'true' },
    stdio: 'inherit',
  });

  let report = {
    assetReviewProtocolSha256,
    commit: sourceCommit,
    fixtureIntegritySha256,
    registryReleaseSha256,
    schemaVersion: 1,
    toolchainManifestSha256: await sha(toolchainPath, 'sha256'),
    version: options.version,
    provenanceTrustPolicySha256,
    walletAssetsManifestSha256,
  };

  let packageResult;
  let workflowReport;
  try {
    if (options.workflowArtifacts) {
    const artifactReport = await verifyWorkflowArtifactsDirectory(
      options.workflowArtifacts,
      options,
      sourceCommit,
    );
    for (const [name, expected] of [
      ['assetReviewProtocolSha256', assetReviewProtocolSha256],
      ['fixtureIntegritySha256', fixtureIntegritySha256],
      ['registryReleaseSha256', registryReleaseSha256],
      ['provenanceTrustPolicySha256', provenanceTrustPolicySha256],
      ['walletAssetsManifestSha256', walletAssetsManifestSha256],
    ]) if (artifactReport[name] !== expected) fail(`workflow artifact report ${name} mismatch`);
    workflowReport = artifactReport;
    report = artifactReport;
    } else {
      packageResult = await packAndVerifyPackages(options.version, sourceCommit);
    const [coreArtifact, uiArtifact] = await Promise.all([
      packageDigestRecord(packageResult.core.archivePath, basename(packageResult.core.archivePath)),
      packageDigestRecord(packageResult.ui.archivePath, basename(packageResult.ui.archivePath)),
    ]);
    report = {
      ...report,
      packages: {
        core: {
          files: packageResult.core.files,
          name: 'hd-wallet-wasm',
          sha512: coreArtifact.sha512,
          version: options.version,
        },
        ui: {
          dependency: { 'hd-wallet-wasm': options.version },
          files: packageResult.ui.files,
          name: 'hd-wallet-ui',
          sha512: uiArtifact.sha512,
          version: options.version,
        },
      },
    };
    }

    await verifyEvidenceRecord({
      baseReport: report,
      options,
      packageResult,
      workflowReport,
    });

    if (options.emitArtifacts) {
      if (!packageResult) fail('--emit-artifacts requires locally built package subjects');
      report = await emitArtifacts({ baseReport: report, options, packageResult, toolchain });
    }

    assertCleanStatus(runGit(['status', '--short', '--untracked-files=all']));
    process.stdout.write(`${canonicalJson(report)}\n`);
  } finally {
    if (packageResult?.cleanupDirectory) {
      await rm(packageResult.cleanupDirectory, { force: true, recursive: true });
    }
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.stack ?? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
