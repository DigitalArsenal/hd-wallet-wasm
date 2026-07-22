import assert from 'node:assert/strict';
import { readFile, stat } from 'node:fs/promises';
import test from 'node:test';

import {
  assertCleanStatus,
  assertExactToolchain,
  assertOutputOutsideSource,
  canonicalJson,
  parseArguments,
  validateBuildWorkflow,
  validateCiLocalScript,
  validateOpenSslBuildScript,
  validatePublishWorkflow,
  validateReleaseInstallPolicy,
  validateVersionContract,
  validateWorkflowArtifactEntries,
  validateWorkflowArtifactReport,
} from '../../scripts/verify-release.mjs';
import {
  buildReleaseRecord,
  validateReleaseRecord,
} from '../../scripts/write-release-record.mjs';
import { validateProvenanceTrustPolicy } from '../../scripts/verify-provenance-evidence.mjs';

const SHA_A = 'a'.repeat(64);
const SHA_B = 'b'.repeat(64);
const SHA_C = 'c'.repeat(64);
const SHA_D = 'd'.repeat(64);
const SHA_E = 'e'.repeat(64);
const SHA_F = 'f'.repeat(64);
const SHA512_A = 'a'.repeat(128);
const SHA512_B = 'b'.repeat(128);
const COMMIT = '0123456789abcdef0123456789abcdef01234567';

const EXPECTED_TOOLCHAIN = {
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
};

function samplePackage(name, tarballSha512, provenanceSha256) {
  return {
    gitHead: COMMIT,
    integrity: `sha512-${Buffer.from(tarballSha512, 'hex').toString('base64')}`,
    name,
    provenanceSha256,
    tarballSha512,
    version: '2.0.25',
  };
}

function sampleRecordInput() {
  return {
    assetReviewProtocolSha256: SHA_A,
    corePackage: samplePackage('hd-wallet-wasm', SHA512_A, SHA_B),
    gitCommit: COMMIT,
    npmProvenanceEvidenceSha256: SHA_C,
    originServiceArtifactSha256: SHA_D,
    provenanceTrustPolicySha256: SHA_F,
    passwordCorpus: {
      bytes: 73017,
      entries: 10000,
      sha256: '4adb3f0afb4a10cf19ebe48d8c69a46f934bbc8d77c694c210564f9583e7f4ba',
      sourceCommit: '190c6f7bd58c847ceadfe57d9853592737f059e8',
      sourcePath: 'Passwords/Common-Credentials/10k-most-common.txt',
      sourceRelease: '2026.1',
    },
    registryReleaseSha256: SHA_E,
    registryTag: 'sdn-candidate-2.0.25',
    sourceTag: 'v2.0.25',
    uiPackage: samplePackage('hd-wallet-ui', SHA512_B, SHA_F),
    uiDependencyVersion: '2.0.25',
    version: '2.0.25',
    walletAssetsManifestSha256: SHA_B,
  };
}

test('canonicalJson is deterministic RFC 8785-compatible JSON plus no whitespace', () => {
  assert.equal(canonicalJson({ z: 1, a: ['x', true, null] }), '{"a":["x",true,null],"z":1}');
  assert.throws(() => canonicalJson({ value: undefined }), /unsupported JSON value/u);
  assert.throws(() => canonicalJson(Number.NaN), /finite/u);
});

test('release CLI modes are strict and mutually exclusive', () => {
  assert.deepEqual(parseArguments([
    '--version', '2.0.25', '--source-ref', 'HEAD', '--skip-tag',
  ]), {
    emitArtifacts: null,
    evidenceRecord: null,
    expectedCorrelation: null,
    expectedRunAttempt: null,
    expectedRunId: null,
    postEvidenceCommit: null,
    provenanceEvidence: null,
    skipTag: true,
    sourceRef: 'HEAD',
    tag: null,
    version: '2.0.25',
    workflowArtifactAttestation: null,
    workflowArtifacts: null,
  });
  assert.throws(
    () => parseArguments(['--version', '2.0.25', '--tag', 'v2.0.25', '--skip-tag']),
    /mutually exclusive/u,
  );
  assert.throws(() => parseArguments(['--version', '2.0.25', '--tag', 'v2.0.26']), /tag/u);
  assert.throws(() => parseArguments(['--version', '2.0.25', '--surprise']), /unknown/u);
  assert.throws(
    () => parseArguments(['--version', '2.0.25', '--workflow-artifacts', '/tmp/a']),
    /expected-run-id/u,
  );
});

test('the release toolchain is frozen exactly', async () => {
  const actual = JSON.parse(await readFile(new URL('../../release/toolchain.v1.json', import.meta.url)));
  assert.deepEqual(actual, EXPECTED_TOOLCHAIN);
  assert.equal(assertExactToolchain(actual), true);
  assert.throws(
    () => assertExactToolchain({ ...actual, node: { ...actual.node, version: '24.18.1' } }),
    /toolchain/u,
  );
  assert.throws(
    () => assertExactToolchain({ ...actual, extra: true }),
    /toolchain/u,
  );
  assert.throws(
    () => assertExactToolchain({
      ...actual,
      githubCli: { ...actual.githubCli, archiveSha256: SHA_A },
    }),
    /toolchain/u,
  );
});

test('the signed-tag provenance trust policy is canonical and fully frozen', async () => {
  const text = await readFile(
    new URL('../../release/provenance-trust.v1.json', import.meta.url), 'utf8',
  );
  const policy = JSON.parse(text);
  assert.deepEqual(validateProvenanceTrustPolicy(policy), policy);
  assert.equal(text, `${canonicalJson(policy)}\n`);

  for (const [expected, mutate] of [
    [/release binding/iu, (value) => { value.release.repository = 'https://example.invalid/repo'; }],
    [/source is not frozen/iu, (value) => { value.source.tufMirror = 'https://example.invalid'; }],
    [/npm keys must be sorted/iu, (value) => { value.npmRegistryKeys.reverse(); }],
    [/transparency log (?:identities|.*duplicates)/iu, (value) => { value.sigstoreTransparencyLogs[1] = structuredClone(value.sigstoreTransparencyLogs[0]); }],
    [/transparency log identities/iu, (value) => {
      value.sigstoreTransparencyLogs[1] = {
        ...structuredClone(value.sigstoreTransparencyLogs[0]),
        publicKeySha256: '0'.repeat(64),
      };
      value.sigstoreTransparencyLogs.sort(
        (left, right) => canonicalJson(left).localeCompare(canonicalJson(right)),
      );
    }],
    [/canonical UTC RFC3339/iu, (value) => { value.sigstoreCertificateAuthorities[0].validFor.start = '2022-04-13T20:06:15Z'; }],
    [/details are invalid/iu, (value) => { value.npmRegistryKeys[0].keyDetails = 'unknown'; }],
  ]) {
    const changed = structuredClone(policy);
    mutate(changed);
    assert.throws(() => validateProvenanceTrustPolicy(changed), expected);
  }
});

test('all source and packed versions must be the reviewed pair', () => {
  const contract = {
    cmakeVersion: '2.0.25',
    corePackage: {
      dependencies: { flatbuffers: '25.9.23' },
      name: 'hd-wallet-wasm',
      version: '2.0.25',
    },
    lockCoreFlatbuffers: '25.9.23',
    lockCoreVersion: '2.0.25',
    lockRootVersion: '2.0.25',
    lockUiVersion: '2.0.25',
    packedCorePackage: {
      dependencies: { flatbuffers: '25.9.23' },
      name: 'hd-wallet-wasm',
      version: '2.0.25',
    },
    packedUiPackage: {
      dependencies: { 'hd-wallet-wasm': '2.0.25' },
      name: 'hd-wallet-ui',
      version: '2.0.25',
    },
    relayPackage: { name: '@sdn/wallet-relay', version: '2.0.25' },
    rootPackage: { version: '2.0.25' },
    uiPackage: {
      dependencies: { 'hd-wallet-wasm': '2.0.25' },
      name: 'hd-wallet-ui',
      version: '2.0.25',
    },
  };
  assert.equal(validateVersionContract(contract, '2.0.25'), true);
  assert.throws(
    () => validateVersionContract({
      ...contract,
      packedUiPackage: { ...contract.packedUiPackage, dependencies: { 'hd-wallet-wasm': '^2.0.25' } },
    }, '2.0.25'),
    /dependency/u,
  );
  assert.throws(
    () => validateVersionContract({
      ...contract,
      packedCorePackage: {
        ...contract.packedCorePackage,
        dependencies: { flatbuffers: '^25.9.23' },
      },
    }, '2.0.25'),
    /flatbuffers dependency/u,
  );
  assert.throws(
    () => validateVersionContract({ ...contract, cmakeVersion: '2.0.21' }, '2.0.25'),
    /version/u,
  );
});

test('clean-tree and output-boundary checks fail closed', () => {
  assert.equal(assertCleanStatus(''), true);
  assert.throws(() => assertCleanStatus(' M package.json\n'), /dirty/u);
  assert.equal(assertOutputOutsideSource('/repo', '/tmp/release'), true);
  assert.throws(() => assertOutputOutsideSource('/repo', '/repo/release/out'), /tagged tree/u);
  assert.throws(() => assertOutputOutsideSource('/repo', '/repo'), /tagged tree/u);
});

test('release record has only the immutable post-publication fields', () => {
  const record = buildReleaseRecord(sampleRecordInput());
  assert.deepEqual(validateReleaseRecord(record), record);
  assert.deepEqual(Object.keys(record).sort(), [
    'assetReviewProtocolSha256',
    'corePackage',
    'gitCommit',
    'npmProvenanceEvidenceSha256',
    'originServiceArtifactSha256',
    'passwordCorpus',
    'provenanceTrustPolicySha256',
    'registryReleaseSha256',
    'registryTag',
    'schemaVersion',
    'sourceTag',
    'uiPackage',
    'version',
    'walletAssetsManifestSha256',
  ]);
  assert.deepEqual(Object.keys(record.corePackage).sort(), [
    'integrity', 'name', 'provenanceSha256', 'tarballSha512',
  ]);
  assert.deepEqual(Object.keys(record.passwordCorpus).sort(), [
    'bytes', 'entries', 'sha256', 'sourceCommit', 'sourcePath', 'sourceRelease',
  ]);
  assert.equal(canonicalJson(record).includes('\n'), false);

  for (const [label, mutate] of [
    ['version', (value) => { value.version = '2.0.21'; }],
    ['tag', (value) => { value.sourceTag = 'v2.0.21'; }],
    ['package', (value) => { value.uiPackage.name = 'hd-wallet-wasm'; }],
    ['integrity', (value) => { value.corePackage.integrity = 'sha512-bad'; }],
    ['hash', (value) => { value.walletAssetsManifestSha256 = 'BAD'; }],
    ['provenance trust policy', (value) => { value.provenanceTrustPolicySha256 = 'BAD'; }],
    ['gitHead', (value) => { value.corePackage.gitHead = 'f'.repeat(40); }],
    ['version', (value) => { value.uiPackage.version = '2.0.21'; }],
    ['dependency', (value) => { value.uiDependencyVersion = '^2.0.25'; }],
  ]) {
    const input = structuredClone(sampleRecordInput());
    mutate(input);
    assert.throws(() => buildReleaseRecord(input), new RegExp(label, 'u'));
  }
  assert.throws(
    () => validateReleaseRecord({ ...record, schemaVersion: 2 }),
    /schemaVersion/u,
  );
});

test('workflow artifact layout is an exact three-directory allowlist', () => {
  const entries = [
    'npm-tarballs/hd-wallet-ui-2.0.25.tgz',
    'npm-tarballs/hd-wallet-wasm-2.0.25.tgz',
    'origin-service/sdn-wallet-origin-2.0.25-node24-linux-x64.tar.gz',
    'origin-service/sdn-wallet-origin-2.0.25-node24-linux-x64.tar.gz.sha256',
    'wallet-release-report/provenance-trust.v1.json',
    'wallet-release-report/release-report.v1.json',
    'wallet-release-report/release/wallet-assets.v1.json',
    'wallet-release-report/release/static/assets/hd-wallet-ui/2.0.25/client.js',
  ];
  assert.equal(validateWorkflowArtifactEntries(entries, '2.0.25'), true);
  assert.throws(
    () => validateWorkflowArtifactEntries([...entries, 'surprise/file'], '2.0.25'),
    /unexpected artifact/u,
  );
  assert.throws(
    () => validateWorkflowArtifactEntries([...entries, 'npm-tarballs/nested/evil.tgz'], '2.0.25'),
    /nested/u,
  );
  assert.throws(
    () => validateWorkflowArtifactEntries(entries.filter((path) => !path.includes('hd-wallet-ui')), '2.0.25'),
    /missing/u,
  );
});

test('workflow artifact report binds run, tag, commit, platform, toolchain, and hashes', () => {
  const report = {
    artifacts: {
      coreTarball: { path: 'npm-tarballs/hd-wallet-wasm-2.0.25.tgz', sha256: SHA_A, sha512: SHA512_A },
      originService: { path: 'origin-service/sdn-wallet-origin-2.0.25-node24-linux-x64.tar.gz', sha256: SHA_B, sha512: SHA512_B },
      uiTarball: { path: 'npm-tarballs/hd-wallet-ui-2.0.25.tgz', sha256: SHA_C, sha512: SHA512_B },
    },
    commit: COMMIT,
    correlationId: '0123456789abcdef0123456789abcdef',
    eventName: 'workflow_dispatch',
    platform: { architecture: 'x64', glibc: '2.39', os: 'linux' },
    provenanceTrustPolicySha256: SHA_C,
    runAttempt: '2',
    runId: '12345',
    schemaVersion: 1,
    sourceTag: 'v2.0.25',
    toolchain: EXPECTED_TOOLCHAIN,
    version: '2.0.25',
    workflow: '.github/workflows/npm-publish.yml',
  };
  assert.equal(validateWorkflowArtifactReport(report, {
    commit: COMMIT,
    correlationId: report.correlationId,
    runAttempt: '2',
    runId: '12345',
    sourceTag: 'v2.0.25',
    version: '2.0.25',
    provenanceTrustPolicySha256: SHA_C,
  }), true);
  assert.throws(
    () => validateWorkflowArtifactReport({ ...report, runId: '999' }, {
      commit: COMMIT,
      correlationId: report.correlationId,
      runAttempt: '2',
      runId: '12345',
      sourceTag: 'v2.0.25',
      version: '2.0.25',
    }),
    /run ID/u,
  );
  assert.throws(
    () => validateWorkflowArtifactReport({ ...report, platform: { ...report.platform, glibc: '2.40' } }, {
      commit: COMMIT,
      correlationId: report.correlationId,
      runAttempt: '2',
      runId: '12345',
      sourceTag: 'v2.0.25',
      version: '2.0.25',
    }),
    /platform/u,
  );
});

test('OpenSSL acquisition is digest-bound and extracted from a fresh safe tree', async () => {
  const path = new URL('../../openssl-fips/build.sh', import.meta.url);
  const [script, metadata] = await Promise.all([readFile(path, 'utf8'), stat(path)]);
  assert.notEqual(metadata.mode & 0o111, 0, 'OpenSSL build entrypoint must be executable');
  assert.match(script, /compute_sha256/u);
  assert.match(script, /shasum -a 256/u);
  assert.equal(validateOpenSslBuildScript(script), true);
  assert.throws(
    () => validateOpenSslBuildScript(script.replace(
      'eb1ab04781474360f77c318ab89d8c5a03abc38e63d65a603cabbf1b00a1dc90',
      SHA_A,
    )),
    /OpenSSL SHA-256/u,
  );
  assert.throws(
    () => validateOpenSslBuildScript(script.replaceAll('reject_unsafe_archive', 'trust_archive')),
    /archive safety/u,
  );
});

test('local CI has one full fail-closed path and no skip modes', async () => {
  const path = new URL('../../scripts/ci-local.sh', import.meta.url);
  const [script, metadata] = await Promise.all([readFile(path, 'utf8'), stat(path)]);
  assert.notEqual(metadata.mode & 0o111, 0, 'local CI entrypoint must be executable');
  assert.equal(validateCiLocalScript(script), true);
  assert.throws(
    () => validateCiLocalScript(script.replace('npm run test:browser', ': # browser omitted')),
    /test:browser/u,
  );
  assert.throws(
    () => validateCiLocalScript(`${script}\nskip optional\n`),
    /skip/u,
  );
});

test('every release-path npm ci disables lifecycle scripts', async () => {
  const [builder, localCi, publishYaml] = await Promise.all([
    readFile(new URL('../../scripts/build-origin-service-release.mjs', import.meta.url), 'utf8'),
    readFile(new URL('../../scripts/ci-local.sh', import.meta.url), 'utf8'),
    readFile(new URL('../../.github/workflows/npm-publish.yml', import.meta.url), 'utf8'),
  ]);
  assert.equal(validateReleaseInstallPolicy({
    localCi,
    originBuilder: builder,
    publishWorkflow: publishYaml,
  }), true);
  assert.throws(() => validateReleaseInstallPolicy({
    localCi: localCi.replace('npm ci --ignore-scripts', 'npm ci'),
    originBuilder: builder,
    publishWorkflow: publishYaml,
  }), /lifecycle|ignore-scripts/u);
  assert.throws(() => validateReleaseInstallPolicy({
    localCi,
    originBuilder: builder.replace("'--ignore-scripts'", "'--ignore-scripts=false'"),
    publishWorkflow: publishYaml,
  }), /lifecycle/u);
  const install = localCi.indexOf('npm ci --ignore-scripts');
  const acquisition = localCi.indexOf('node scripts/acquire-better-sqlite3-prebuild.mjs');
  const tests = localCi.indexOf('npm run test:offline-contracts');
  assert.ok(install !== -1 && install < acquisition && acquisition < tests);
});

test('release-critical workflows are dispatch-safe and fully pinned', async () => {
  const [buildYaml, publishYaml] = await Promise.all([
    readFile(new URL('../../.github/workflows/build.yml', import.meta.url), 'utf8'),
    readFile(new URL('../../.github/workflows/npm-publish.yml', import.meta.url), 'utf8'),
  ]);
  assert.equal(validateBuildWorkflow(buildYaml), true);
  assert.equal(validatePublishWorkflow(publishYaml), true);
  assert.throws(
    () => validatePublishWorkflow(publishYaml.replace('workflow_dispatch:', 'push:\n    tags: ["v*"]\n  workflow_dispatch:')),
    /push/u,
  );
  assert.throws(
    () => validatePublishWorkflow(publishYaml.replace('npm@11.16.0', 'npm@latest')),
    /npm/u,
  );
  assert.throws(
    () => validatePublishWorkflow(publishYaml.replaceAll(
      'release/provenance-trust.v1.json', 'release/untrusted-policy.json',
    )),
    /provenance-trust/u,
  );
  assert.throws(
    () => validatePublishWorkflow(publishYaml.replace(
      'Verify final registry subjects match signed workflow artifacts',
      'Skip final registry subject verification',
    )),
    /final registry subjects/u,
  );
  assert.throws(
    () => validatePublishWorkflow(publishYaml.replace(
      'actions/attest@f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6',
      'actions/attest@0000000000000000000000000000000000000000',
    )),
    /action/u,
  );
  assert.throws(
    () => validatePublishWorkflow(publishYaml.replace('  attestations: write\n', '')),
    /permissions/u,
  );
  assert.throws(
    () => validatePublishWorkflow(publishYaml.replace(
      '  attestations: write\n',
      '  attestations: write\n  packages: write\n',
    )),
    /permissions/u,
  );
  assert.throws(
    () => validatePublishWorkflow(publishYaml.replace(
      'test "$GITHUB_REF" = "refs/tags/$SOURCE_TAG"',
      ': # dispatch ref binding removed',
    )),
    /dispatch ref/u,
  );
  assert.throws(
    () => validatePublishWorkflow(publishYaml.replace(
      'test "$GITHUB_SHA" = "$tag_commit"',
      ': # dispatch commit binding removed',
    )),
    /dispatch commit/u,
  );
  assert.throws(
    () => validatePublishWorkflow(publishYaml.replace(
      '${{ runner.temp }}/sdn-wallet-artifacts/origin-service/sdn-wallet-origin-2.0.25-node24-linux-x64.tar.gz',
      '${{ runner.temp }}/sdn-wallet-artifacts/origin-service/*.tar.gz',
    )),
    /attestation subjects/u,
  );
  for (const required of [
    'scripts/collect-provenance-inputs.mjs',
    'scripts/verify-provenance-evidence.mjs',
    'npm audit signatures --json --include-attestations',
    '--registry-attestations',
    '--core-attestations',
    '--ui-attestations',
    'gh run rerun <same-run-id> --failed',
    'gh_2.96.0_linux_amd64.tar.gz',
    '83d5c2ccad5498f58bf6368acb1ab32588cf43ab3a4b1c301bf36328b1c8bd60',
    'workflow-artifacts.sigstore.json',
    '--workflow-artifact-attestation',
  ]) assert.ok(publishYaml.includes(required), required);
  assert.match(publishYaml, /id: attest-origin-release/u);
  assert.match(publishYaml, /\$\{\{ steps\.attest-origin-release\.outputs\.bundle-path \}\}/u);
  assert.doesNotMatch(buildYaml, /actions\/attest|attestations:\s*write/u);
  assert.doesNotMatch(
    publishYaml,
    /sdn-wallet-artifacts\/wallet-release-report\/evidence/u,
  );
});
