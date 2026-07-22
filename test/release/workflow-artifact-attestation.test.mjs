import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, join } from 'node:path';
import test from 'node:test';

import {
  validatePinnedGithubCli,
  validateGithubArtifactAttestationResult,
  verifyGithubArtifactAttestation,
} from '../../scripts/verify-workflow-artifact-attestation.mjs';

const COMMIT = '0123456789abcdef0123456789abcdef01234567';
const RUN_ID = '123456789';
const RUN_ATTEMPT = '2';
const SOURCE_TAG = 'v2.0.28';
const REPOSITORY = 'DigitalArsenal/hd-wallet-wasm';
const REPOSITORY_URL = `https://github.com/${REPOSITORY}`;
const REF = `refs/tags/${SOURCE_TAG}`;
const WORKFLOW = '.github/workflows/npm-publish.yml';
const IDENTITY = `${REPOSITORY_URL}/${WORKFLOW}@${REF}`;
const INVOCATION = `${REPOSITORY_URL}/actions/runs/${RUN_ID}/attempts/${RUN_ATTEMPT}`;

test('accepts only the exact pinned GitHub CLI executable digest', () => {
  assert.equal(validatePinnedGithubCli({
    architecture: 'x64',
    bytes: 40_722_594,
    platform: 'linux',
    sha256: '56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40',
  }), true);
  assert.equal(validatePinnedGithubCli({
    architecture: 'arm64',
    bytes: 38_817_216,
    platform: 'darwin',
    sha256: 'b1d6c442fde99ca27c04e1e74d624895abe37785f4a3e9e9b684bf7586ce4bc8',
  }), true);
  for (const changed of [
    { architecture: 'x64', bytes: 40_722_593, platform: 'linux', sha256: '56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40' },
    { architecture: 'x64', bytes: 40_722_594, platform: 'linux', sha256: '0'.repeat(64) },
    { architecture: 'arm64', bytes: 38_817_216, platform: 'linux', sha256: 'b1d6c442fde99ca27c04e1e74d624895abe37785f4a3e9e9b684bf7586ce4bc8' },
  ]) {
    assert.throws(() => validatePinnedGithubCli(changed), /pinned GitHub CLI/iu);
  }
});

function digest(bytes) {
  return createHash('sha256').update(bytes).digest('hex');
}

function verificationResult(subjects) {
  return [{
    attestation: { bundle: { mediaType: 'application/vnd.dev.sigstore.bundle.v0.3+json' } },
    verificationResult: {
      mediaType: 'application/vnd.dev.sigstore.verificationresult+json;version=0.1',
      signature: {
        certificate: {
          buildConfigDigest: COMMIT,
          buildConfigURI: IDENTITY,
          buildSignerDigest: COMMIT,
          buildSignerURI: IDENTITY,
          buildTrigger: 'workflow_dispatch',
          githubWorkflowRef: REF,
          githubWorkflowRepository: REPOSITORY,
          githubWorkflowSHA: COMMIT,
          githubWorkflowTrigger: 'workflow_dispatch',
          issuer: 'https://token.actions.githubusercontent.com',
          runInvocationURI: INVOCATION,
          runnerEnvironment: 'github-hosted',
          sourceRepositoryDigest: COMMIT,
          sourceRepositoryIdentifier: '1142529413',
          sourceRepositoryOwnerIdentifier: '29587475',
          sourceRepositoryOwnerURI: 'https://github.com/DigitalArsenal',
          sourceRepositoryRef: REF,
          sourceRepositoryURI: REPOSITORY_URL,
          sourceRepositoryVisibilityAtSigning: 'public',
          subjectAlternativeName: IDENTITY,
        },
      },
      statement: {
        _type: 'https://in-toto.io/Statement/v1',
        predicate: {
          buildDefinition: {
            buildType: 'https://actions.github.io/buildtypes/workflow/v1',
            externalParameters: {
              workflow: { path: WORKFLOW, ref: REF, repository: REPOSITORY_URL },
            },
            internalParameters: {
              github: {
                event_name: 'workflow_dispatch',
                repository_id: '1142529413',
                repository_owner_id: '29587475',
                runner_environment: 'github-hosted',
              },
            },
            resolvedDependencies: [{
              digest: { gitCommit: COMMIT },
              uri: `git+${REPOSITORY_URL}@${REF}`,
            }],
          },
          runDetails: {
            builder: { id: IDENTITY },
            metadata: { invocationId: INVOCATION },
          },
        },
        predicateType: 'https://slsa.dev/provenance/v1',
        subject: subjects,
      },
      verifiedTimestamps: [{
        timestamp: '2026-07-20T12:00:00Z',
        type: 'Tlog',
        uri: 'https://rekor.sigstore.dev',
      }],
    },
  }];
}

function expected(subjects) {
  return {
    runAttempt: RUN_ATTEMPT,
    runId: RUN_ID,
    sourceCommit: COMMIT,
    sourceTag: SOURCE_TAG,
    subjects,
  };
}

test('accepts only an exact GitHub-hosted workflow attestation identity and subject set', () => {
  const subjects = [
    { digest: { sha256: 'a'.repeat(64) }, name: 'release-report.v1.json' },
    { digest: { sha256: 'b'.repeat(64) }, name: 'sdn-wallet-origin.tgz' },
  ];
  assert.equal(
    validateGithubArtifactAttestationResult(verificationResult(subjects), expected(subjects)),
    true,
  );
  for (const [pattern, mutate] of [
    [/invocation/iu, (value) => { value[0].verificationResult.signature.certificate.runInvocationURI = `${REPOSITORY_URL}/actions/runs/999/attempts/1`; }],
    [/repository identifier/iu, (value) => { value[0].verificationResult.signature.certificate.sourceRepositoryIdentifier = '999'; }],
    [/OIDC issuer/iu, (value) => { value[0].verificationResult.signature.certificate.issuer = 'https://example.invalid'; }],
    [/Rekor/iu, (value) => { value[0].verificationResult.verifiedTimestamps[0].uri = 'https://rekor.example.invalid'; }],
    [/subject/iu, (value) => { value[0].verificationResult.statement.subject[0].digest.sha256 = 'c'.repeat(64); }],
    [/builder/iu, (value) => { value[0].verificationResult.statement.predicate.runDetails.builder.id = 'https://example.invalid/builder'; }],
  ]) {
    const changed = structuredClone(verificationResult(subjects));
    mutate(changed);
    assert.throws(
      () => validateGithubArtifactAttestationResult(changed, expected(subjects)),
      pattern,
    );
  }
});

test('verifies both immutable snapshots with exact gh identity flags before returning', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'sdn-workflow-attestation-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const origin = join(root, 'sdn-wallet-origin-2.0.28-node24-linux-x64.tar.gz');
  const report = join(root, 'release-report.v1.json');
  const bundle = join(root, 'workflow-artifacts.sigstore.json');
  const originBytes = Buffer.from('origin fixture');
  const reportBytes = Buffer.from('{"fixture":true}\n');
  await Promise.all([
    writeFile(origin, originBytes),
    writeFile(report, reportBytes),
    writeFile(bundle, '{}\n'),
  ]);
  const subjects = [
    { digest: { sha256: digest(reportBytes) }, name: basename(report) },
    { digest: { sha256: digest(originBytes) }, name: basename(origin) },
  ].sort((left, right) => left.name.localeCompare(right.name, 'en'));
  const calls = [];
  const callOptions = [];
  const runCommand = (executable, arguments_, options) => {
    calls.push([executable, ...arguments_]);
    callOptions.push(options);
    if (arguments_[0] === '--version') return 'gh version 2.96.0 (fixture)\n';
    if (calls.length === 2) {
      writeFileSync(origin, Buffer.alloc(originBytes.length, 0x78));
      writeFileSync(report, Buffer.alloc(reportBytes.length, 0x79));
    }
    return JSON.stringify(verificationResult(subjects));
  };

  const result = await verifyGithubArtifactAttestation({
    artifactPaths: [origin, report],
    bundlePath: bundle,
    consumeVerifiedSnapshots: async ({ artifactPaths }) => ({
      origin: await readFile(artifactPaths[basename(origin)]),
      report: await readFile(artifactPaths[basename(report)]),
    }),
    runAttempt: RUN_ATTEMPT,
    runCommand,
    runId: RUN_ID,
    sourceCommit: COMMIT,
    sourceTag: SOURCE_TAG,
  });
  assert.deepEqual(result.subjects, subjects);
  assert.deepEqual(result.consumed.origin, originBytes);
  assert.deepEqual(result.consumed.report, reportBytes);
  assert.notDeepEqual(await readFile(origin), originBytes);
  assert.notDeepEqual(await readFile(report), reportBytes);
  assert.equal(calls.length, 3);
  const expectedEnvironmentKeys = [
    'GH_CONFIG_DIR',
    'GH_HOST',
    'GH_NO_UPDATE_NOTIFIER',
    'GH_PROMPT_DISABLED',
    'HOME',
    'LANG',
    'LC_ALL',
    'NO_COLOR',
    'PATH',
    'TMPDIR',
    'TZ',
    'XDG_CACHE_HOME',
    'XDG_CONFIG_HOME',
    'XDG_DATA_HOME',
  ];
  for (const options of callOptions) {
    assert.deepEqual(Object.keys(options.env).sort(), expectedEnvironmentKeys);
    assert.equal('LD_PRELOAD' in options.env, false);
    assert.equal('DYLD_INSERT_LIBRARIES' in options.env, false);
    assert.equal('GH_TOKEN' in options.env, false);
  }
  for (const call of calls.slice(1)) {
    assert.equal(call[0], 'gh');
    for (const required of [
      '--bundle',
      '--cert-identity', IDENTITY,
      '--cert-oidc-issuer', 'https://token.actions.githubusercontent.com',
      '--custom-trusted-root',
      '--deny-self-hosted-runners',
      '--repo', REPOSITORY,
      '--signer-digest', COMMIT,
      '--source-digest', COMMIT,
      '--source-ref', REF,
    ]) assert.ok(call.includes(required), `missing exact gh argument: ${required}`);
    assert.equal(call.includes('--signer-workflow'), false,
      'gh rejects --signer-workflow when exact --cert-identity is present');
    assert.equal(basename(call[call.indexOf('--bundle') + 1]), 'workflow-artifacts.sigstore.json');
    assert.equal(basename(call[call.indexOf('--custom-trusted-root') + 1]),
      'public-good-trusted-root.json');
  }
});

test('fails closed when gh verification fails and never accepts partial results', async (t) => {
  const root = await mkdtemp(join(tmpdir(), 'sdn-workflow-attestation-fail-'));
  t.after(() => rm(root, { force: true, recursive: true }));
  const origin = join(root, 'origin.tgz');
  const report = join(root, 'release-report.v1.json');
  const bundle = join(root, 'bundle.json');
  await Promise.all([
    writeFile(origin, 'origin'),
    writeFile(report, '{}\n'),
    writeFile(bundle, '{}\n'),
  ]);
  let calls = 0;
  await assert.rejects(
    verifyGithubArtifactAttestation({
      artifactPaths: [origin, report],
      bundlePath: bundle,
      runAttempt: RUN_ATTEMPT,
      runCommand: (_executable, arguments_) => {
        calls += 1;
        if (arguments_[0] === '--version') return 'gh version 2.96.0 (fixture)\n';
        throw new Error('bad signature');
      },
      runId: RUN_ID,
      sourceCommit: COMMIT,
      sourceTag: SOURCE_TAG,
    }),
    /GitHub artifact attestation verification failed/u,
  );
  assert.equal(calls, 2);
});

test('authenticated snapshots are the only path to report parsing and service execution', async () => {
  const verifierSource = await readFile(
    new URL('../../scripts/verify-release.mjs', import.meta.url),
    'utf8',
  );
  const verifierStart = verifierSource.indexOf(
    'export async function verifyWorkflowArtifactsDirectory',
  );
  const verifierEnd = verifierSource.indexOf('\nfunction assertPostEvidenceCommit', verifierStart);
  assert.ok(verifierStart >= 0 && verifierEnd > verifierStart);
  const verifier = verifierSource.slice(verifierStart, verifierEnd);
  const attestation = verifier.indexOf('const verified = await verifyGithubArtifactAttestation');
  const callback = verifier.indexOf('consumeVerifiedSnapshots: async');
  const inventory = verifier.indexOf('const entries = await walk(root);');
  const reportRead = verifier.indexOf("const reportText = await readFile(reportPath, 'utf8');");
  const structural = verifier.indexOf('const structural = await verifyOriginServiceRelease');
  const health = verifier.indexOf('const health = await verifyOriginServiceRelease');
  assert.ok(attestation >= 0);
  assert.ok(attestation < callback);
  assert.ok(callback < inventory);
  assert.ok(inventory < reportRead);
  assert.ok(reportRead < structural);
  assert.ok(structural < health);
  assert.equal(verifier.includes('readFile(inputReportPath'), false);
  assert.equal(verifier.includes('verifyOriginServiceRelease({\n        archivePath: inputOriginPath'), false);

  const recordSource = await readFile(
    new URL('../../scripts/write-release-record.mjs', import.meta.url),
    'utf8',
  );
  const recordMain = recordSource.slice(recordSource.indexOf('async function main()'));
  assert.match(
    recordMain,
    /const report = await verifyWorkflowArtifactsDirectory\(options\.workflowArtifacts,/u,
  );
  assert.equal(recordMain.includes('wallet-release-report/release-report.v1.json'), false);
  assert.equal(recordMain.includes('JSON.parse(await readFile(report'), false);
});
