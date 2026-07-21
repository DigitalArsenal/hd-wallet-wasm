import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { constants as filesystemConstants } from 'node:fs';
import {
  lstat,
  mkdtemp,
  open,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { basename, delimiter, dirname, isAbsolute, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const repositoryDirectory = resolve(scriptDirectory, '..');
const TRUSTED_ROOT_PATH = resolve(
  repositoryDirectory,
  'release/github-attestation-trusted-root.json',
);
const TRUSTED_ROOT_SHA256 = '3c2cc7f357dc064ec527fdcd78da6e9245c21a381e1abaa0f2b62b186bcac1a1';
const EXPECTED_GH_VERSION = '2.96.0';
const REPOSITORY = 'DigitalArsenal/hd-wallet-wasm';
const REPOSITORY_ID = '1142529413';
const REPOSITORY_OWNER_ID = '29587475';
const REPOSITORY_URL = `https://github.com/${REPOSITORY}`;
const REPOSITORY_OWNER_URL = 'https://github.com/DigitalArsenal';
const WORKFLOW = '.github/workflows/npm-publish.yml';
const OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
const SLSA_PREDICATE = 'https://slsa.dev/provenance/v1';
const HEX_40 = /^[0-9a-f]{40}$/u;
const DECIMAL = /^[1-9][0-9]{0,19}$/u;
const VERSION_TAG = /^v\d+\.\d+\.\d+$/u;
const MAX_BUNDLE_BYTES = 16 * 1024 * 1024;
const MAX_SUBJECT_BYTES = 96 * 1024 * 1024;
const MAX_GH_BYTES = 48 * 1024 * 1024;
const PUBLIC_GOOD_REKOR_LOGS = new Set([
  'https://log2025-1.rekor.sigstore.dev',
  'https://rekor.sigstore.dev',
]);
const GITHUB_CLI_EXECUTABLE_PINS = Object.freeze({
  'darwin-arm64': Object.freeze({
    bytes: 38_817_216,
    sha256: 'b1d6c442fde99ca27c04e1e74d624895abe37785f4a3e9e9b684bf7586ce4bc8',
  }),
  'linux-x64': Object.freeze({
    bytes: 40_722_594,
    sha256: '56b8bbbb27b066ecb33dbef9a256dc9d1314adaeff0908a752feba6c34053b40',
  }),
});

function fail(message) {
  throw new Error(message);
}

function canonical(value) {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonical(value[key])}`,
    ).join(',')}}`;
  }
  return JSON.stringify(value);
}

function exact(value, expected, label) {
  if (canonical(value) !== canonical(expected)) fail(`${label} is not exact`);
}

export function validatePinnedGithubCli({ architecture, bytes, platform, sha256 } = {}) {
  const expected = GITHUB_CLI_EXECUTABLE_PINS[`${platform}-${architecture}`];
  if (!expected || bytes !== expected.bytes || sha256 !== expected.sha256) {
    fail('executable does not match the pinned GitHub CLI');
  }
  return true;
}

function expectedIdentity(sourceTag) {
  return `${REPOSITORY_URL}/${WORKFLOW}@refs/tags/${sourceTag}`;
}

function validateExpected(expected) {
  if (!expected || !HEX_40.test(expected.sourceCommit)
      || !VERSION_TAG.test(expected.sourceTag)
      || !DECIMAL.test(String(expected.runId))
      || !DECIMAL.test(String(expected.runAttempt))) {
    fail('GitHub artifact attestation expectations are invalid');
  }
  if (!Array.isArray(expected.subjects) || expected.subjects.length !== 2) {
    fail('GitHub artifact attestation must have exactly two expected subjects');
  }
  const subjects = expected.subjects.map((subject) => ({
    digest: { sha256: subject?.digest?.sha256 },
    name: subject?.name,
  })).sort((left, right) => left.name?.localeCompare(right.name, 'en'));
  for (const subject of subjects) {
    if (typeof subject.name !== 'string' || basename(subject.name) !== subject.name
        || !/^[0-9A-Za-z._-]+$/u.test(subject.name)
        || !/^[0-9a-f]{64}$/u.test(subject.digest.sha256)) {
      fail('GitHub artifact attestation expected subject is invalid');
    }
  }
  if (subjects[0].name === subjects[1].name) {
    fail('GitHub artifact attestation expected subjects are duplicated');
  }
  return { ...expected, subjects };
}

export function validateGithubArtifactAttestationResult(value, inputExpected) {
  const expected = validateExpected(inputExpected);
  if (!Array.isArray(value) || value.length !== 1) {
    fail('GitHub artifact attestation verification must return exactly one result');
  }
  const result = value[0]?.verificationResult;
  if (result?.mediaType !== 'application/vnd.dev.sigstore.verificationresult+json;version=0.1') {
    fail('GitHub artifact attestation verification result media type is wrong');
  }
  if (!Array.isArray(result.verifiedTimestamps)
      || !result.verifiedTimestamps.some((timestamp) => (
        timestamp?.type === 'Tlog'
        && PUBLIC_GOOD_REKOR_LOGS.has(timestamp.uri)
        && typeof timestamp.timestamp === 'string'
        && Number.isFinite(Date.parse(timestamp.timestamp))
      ))) {
    fail('GitHub artifact attestation has no verified public-good Rekor timestamp');
  }
  const ref = `refs/tags/${expected.sourceTag}`;
  const identity = expectedIdentity(expected.sourceTag);
  const invocation = `${REPOSITORY_URL}/actions/runs/${expected.runId}/attempts/${expected.runAttempt}`;
  const certificate = result.signature?.certificate;
  if (certificate?.issuer !== OIDC_ISSUER) fail('GitHub artifact attestation OIDC issuer is wrong');
  if (certificate?.subjectAlternativeName !== identity
      || certificate?.buildSignerURI !== identity
      || certificate?.buildConfigURI !== identity) {
    fail('GitHub artifact attestation workflow identity is wrong');
  }
  if (certificate?.githubWorkflowRepository !== REPOSITORY
      || certificate?.sourceRepositoryURI !== REPOSITORY_URL
      || certificate?.sourceRepositoryOwnerURI !== REPOSITORY_OWNER_URL) {
    fail('GitHub artifact attestation repository identity is wrong');
  }
  if (certificate?.sourceRepositoryIdentifier !== REPOSITORY_ID
      || certificate?.sourceRepositoryOwnerIdentifier !== REPOSITORY_OWNER_ID) {
    fail('GitHub artifact attestation repository identifier is wrong');
  }
  if (certificate?.githubWorkflowSHA !== expected.sourceCommit
      || certificate?.buildSignerDigest !== expected.sourceCommit
      || certificate?.buildConfigDigest !== expected.sourceCommit
      || certificate?.sourceRepositoryDigest !== expected.sourceCommit) {
    fail('GitHub artifact attestation source commit is wrong');
  }
  if (certificate?.githubWorkflowRef !== ref || certificate?.sourceRepositoryRef !== ref) {
    fail('GitHub artifact attestation source ref is wrong');
  }
  if (certificate?.runInvocationURI !== invocation) {
    fail('GitHub artifact attestation run invocation is wrong');
  }
  if (certificate?.runnerEnvironment !== 'github-hosted') {
    fail('GitHub artifact attestation runner is not GitHub-hosted');
  }
  if (certificate?.githubWorkflowTrigger !== 'workflow_dispatch'
      || certificate?.buildTrigger !== 'workflow_dispatch') {
    fail('GitHub artifact attestation trigger is wrong');
  }
  if (certificate?.sourceRepositoryVisibilityAtSigning !== 'public') {
    fail('GitHub artifact attestation repository visibility is wrong');
  }

  const statement = result.statement;
  if (statement?._type !== 'https://in-toto.io/Statement/v1'
      || statement?.predicateType !== SLSA_PREDICATE) {
    fail('GitHub artifact attestation statement type is wrong');
  }
  const observedSubjects = (statement.subject ?? []).map((subject) => ({
    digest: { sha256: subject?.digest?.sha256 },
    name: subject?.name,
  })).sort((left, right) => left.name?.localeCompare(right.name, 'en'));
  exact(observedSubjects, expected.subjects, 'GitHub artifact attestation subject set');
  const definition = statement.predicate?.buildDefinition;
  if (definition?.buildType
      !== 'https://actions.github.io/buildtypes/workflow/v1') {
    fail('GitHub artifact attestation builder type is wrong');
  }
  exact(definition?.externalParameters?.workflow, {
    path: WORKFLOW,
    ref,
    repository: REPOSITORY_URL,
  }, 'GitHub artifact attestation workflow parameters');
  exact(definition?.internalParameters?.github, {
    event_name: 'workflow_dispatch',
    repository_id: REPOSITORY_ID,
    repository_owner_id: REPOSITORY_OWNER_ID,
    runner_environment: 'github-hosted',
  }, 'GitHub artifact attestation immutable repository parameters');
  exact(definition?.resolvedDependencies, [{
    digest: { gitCommit: expected.sourceCommit },
    uri: `git+${REPOSITORY_URL}@${ref}`,
  }], 'GitHub artifact attestation resolved source');
  if (statement.predicate?.runDetails?.builder?.id
      !== identity) {
    fail('GitHub artifact attestation builder is wrong');
  }
  if (statement.predicate?.runDetails?.metadata?.invocationId !== invocation) {
    fail('GitHub artifact attestation predicate invocation is wrong');
  }
  return true;
}

function sameSnapshot(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs;
}

async function readBoundedRegular(path, maximum, label) {
  const input = resolve(path);
  const inputStatus = await lstat(input).catch(() => null);
  if (!inputStatus || inputStatus.isSymbolicLink() || !inputStatus.isFile()
      || inputStatus.size <= 0 || inputStatus.size > maximum) {
    fail(`${label} must be a bounded regular file`);
  }
  const resolved = await realpath(input);
  const before = await lstat(resolved);
  if (!sameSnapshot(inputStatus, before)) fail(`${label} changed before it was opened`);
  let handle;
  try {
    handle = await open(
      resolved,
      filesystemConstants.O_RDONLY | (filesystemConstants.O_NOFOLLOW ?? 0),
    );
  } catch (error) {
    if (error?.code === 'ELOOP') fail(`${label} is a symlink`);
    throw error;
  }
  try {
    const opened = await handle.stat();
    if (!opened.isFile() || !sameSnapshot(before, opened)) {
      fail(`${label} changed while it was opened`);
    }
    const bytes = await handle.readFile();
    const afterRead = await handle.stat();
    const afterPath = await lstat(resolved);
    if (bytes.length !== opened.size || !sameSnapshot(opened, afterRead)
        || !sameSnapshot(opened, afterPath)) {
      fail(`${label} changed while it was read`);
    }
    return { bytes, mode: opened.mode, name: basename(resolved), path: resolved };
  } finally {
    await handle.close();
  }
}

async function resolvePinnedGithubCli() {
  const pathValue = process.env.PATH;
  if (typeof pathValue !== 'string' || pathValue.length === 0) {
    fail('PATH is required to resolve the pinned GitHub CLI');
  }
  for (const directory of pathValue.split(delimiter)) {
    if (!directory || !isAbsolute(directory)) {
      fail('PATH must contain only absolute non-empty entries for release verification');
    }
    const candidate = join(directory, 'gh');
    const status = await lstat(candidate).catch((error) => {
      if (error?.code === 'ENOENT' || error?.code === 'ENOTDIR') return null;
      throw error;
    });
    if (!status) continue;
    if (status.isSymbolicLink() || !status.isFile() || (status.mode & 0o111) === 0) {
      fail('resolved GitHub CLI must be an executable regular file, not a symlink');
    }
    const input = await readBoundedRegular(candidate, MAX_GH_BYTES, 'GitHub CLI executable');
    validatePinnedGithubCli({
      architecture: process.arch,
      bytes: input.bytes.length,
      platform: process.platform,
      sha256: createHash('sha256').update(input.bytes).digest('hex'),
    });
    return input;
  }
  fail(`GitHub CLI ${EXPECTED_GH_VERSION} is required for artifact attestation verification`);
}

function defaultRunCommand(executable, arguments_, options) {
  return execFileSync(executable, arguments_, options);
}

function githubCliEnvironment(snapshotDirectory) {
  return {
    GH_CONFIG_DIR: join(snapshotDirectory, 'gh-config'),
    GH_HOST: 'github.com',
    GH_NO_UPDATE_NOTIFIER: '1',
    GH_PROMPT_DISABLED: '1',
    HOME: snapshotDirectory,
    LANG: 'C',
    LC_ALL: 'C',
    NO_COLOR: '1',
    PATH: '/usr/bin:/bin',
    TMPDIR: snapshotDirectory,
    TZ: 'UTC',
    XDG_CACHE_HOME: join(snapshotDirectory, 'cache'),
    XDG_CONFIG_HOME: join(snapshotDirectory, 'config'),
    XDG_DATA_HOME: join(snapshotDirectory, 'data'),
  };
}

function ghArguments({ artifactPath, bundlePath, sourceCommit, sourceTag, trustedRootPath }) {
  const ref = `refs/tags/${sourceTag}`;
  return [
    'attestation', 'verify', artifactPath,
    '--bundle', bundlePath,
    '--cert-identity', expectedIdentity(sourceTag),
    '--cert-oidc-issuer', OIDC_ISSUER,
    '--custom-trusted-root', trustedRootPath,
    '--deny-self-hosted-runners',
    '--format', 'json',
    '--hostname', 'github.com',
    '--predicate-type', SLSA_PREDICATE,
    '--repo', REPOSITORY,
    '--signer-digest', sourceCommit,
    '--signer-workflow', `${REPOSITORY}/${WORKFLOW}`,
    '--source-digest', sourceCommit,
    '--source-ref', ref,
  ];
}

export async function verifyGithubArtifactAttestation({
  artifactPaths,
  bundlePath,
  consumeVerifiedSnapshots = async () => undefined,
  runAttempt,
  runCommand = defaultRunCommand,
  runId,
  sourceCommit,
  sourceTag,
  trustedRootPath = TRUSTED_ROOT_PATH,
} = {}) {
  if (!Array.isArray(artifactPaths) || artifactPaths.length !== 2
      || typeof bundlePath !== 'string' || typeof runCommand !== 'function'
      || typeof consumeVerifiedSnapshots !== 'function') {
    fail('GitHub artifact attestation verifier inputs are invalid');
  }
  const githubCliInput = runCommand === defaultRunCommand
    ? await resolvePinnedGithubCli()
    : null;
  const [bundleInput, trustedRootInput, ...artifactInputs] = await Promise.all([
    readBoundedRegular(bundlePath, MAX_BUNDLE_BYTES, 'GitHub artifact attestation bundle'),
    readBoundedRegular(trustedRootPath, MAX_BUNDLE_BYTES, 'GitHub attestation trusted root'),
    ...artifactPaths.map((path) => readBoundedRegular(
      path,
      MAX_SUBJECT_BYTES,
      `GitHub attestation subject ${basename(path)}`,
    )),
  ]);
  if (createHash('sha256').update(trustedRootInput.bytes).digest('hex') !== TRUSTED_ROOT_SHA256) {
    fail('GitHub attestation trusted root does not match the frozen release root');
  }
  const subjects = artifactInputs.map(({ bytes, name }) => ({
    digest: { sha256: createHash('sha256').update(bytes).digest('hex') },
    name,
  })).sort((left, right) => left.name.localeCompare(right.name, 'en'));
  const expected = validateExpected({ runAttempt, runId, sourceCommit, sourceTag, subjects });
  const snapshotDirectory = await mkdtemp(join(
    await realpath(tmpdir()),
    'sdn-verified-workflow-artifacts-',
  ));
  try {
    const bundle = {
      ...bundleInput,
      path: join(snapshotDirectory, 'workflow-artifacts.sigstore.json'),
    };
    const trustedRoot = {
      ...trustedRootInput,
      path: join(snapshotDirectory, 'public-good-trusted-root.json'),
    };
    const artifacts = artifactInputs.map((artifact) => ({
      ...artifact,
      path: join(snapshotDirectory, artifact.name),
    }));
    const githubCli = githubCliInput && {
      ...githubCliInput,
      path: join(snapshotDirectory, `gh-${EXPECTED_GH_VERSION}`),
    };
    await Promise.all([
      writeFile(bundle.path, bundle.bytes, { flag: 'wx', mode: 0o400 }),
      writeFile(trustedRoot.path, trustedRoot.bytes, { flag: 'wx', mode: 0o400 }),
      ...(githubCli ? [writeFile(
        githubCli.path,
        githubCli.bytes,
        { flag: 'wx', mode: 0o500 },
      )] : []),
      ...artifacts.map((artifact) => writeFile(
        artifact.path,
        artifact.bytes,
        { flag: 'wx', mode: 0o400 },
      )),
    ]);
    const githubCliExecutable = githubCli?.path ?? 'gh';
    const commandEnvironment = githubCliEnvironment(snapshotDirectory);
    let version;
    try {
      version = String(runCommand(githubCliExecutable, ['--version'], {
        encoding: 'utf8',
        env: commandEnvironment,
        stdio: ['ignore', 'pipe', 'pipe'],
      })).split('\n')[0];
    } catch {
      fail(`GitHub CLI ${EXPECTED_GH_VERSION} is required for artifact attestation verification`);
    }
    if (!version.startsWith(`gh version ${EXPECTED_GH_VERSION} `)) {
      fail(`GitHub CLI ${EXPECTED_GH_VERSION} is required for artifact attestation verification`);
    }
    const results = [];
    for (const artifact of artifacts) {
      let output;
      try {
        output = runCommand(githubCliExecutable, ghArguments({
          artifactPath: artifact.path,
          bundlePath: bundle.path,
          sourceCommit,
          sourceTag,
          trustedRootPath: trustedRoot.path,
        }), {
          encoding: 'utf8',
          env: commandEnvironment,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch {
        fail('GitHub artifact attestation verification failed');
      }
      let parsed;
      try {
        parsed = JSON.parse(String(output));
      } catch {
        fail('GitHub artifact attestation verifier returned invalid JSON');
      }
      validateGithubArtifactAttestationResult(parsed, expected);
      results.push(parsed);
    }
    if (canonical(results[0]) !== canonical(results[1])) {
      fail('GitHub artifact attestation results disagree across signed subjects');
    }
    for (const [snapshot, maximum, label] of [
      [bundle, MAX_BUNDLE_BYTES, 'GitHub artifact attestation bundle snapshot'],
      [trustedRoot, MAX_BUNDLE_BYTES, 'GitHub attestation trusted root snapshot'],
      ...(githubCli ? [[githubCli, MAX_GH_BYTES, 'GitHub CLI executable snapshot']] : []),
      ...artifacts.map((artifact) => [
        artifact,
        MAX_SUBJECT_BYTES,
        `GitHub attestation subject snapshot ${artifact.name}`,
      ]),
    ]) {
      const afterVerification = await readBoundedRegular(snapshot.path, maximum, label);
      if (!afterVerification.bytes.equals(snapshot.bytes)) {
        fail(`${label} changed during verification`);
      }
    }
    const consumed = await consumeVerifiedSnapshots({
      artifactPaths: Object.fromEntries(artifacts.map((artifact) => [artifact.name, artifact.path])),
      bundlePath: bundle.path,
      subjects,
    });
    return {
      bundleSha256: createHash('sha256').update(bundle.bytes).digest('hex'),
      consumed,
      subjects,
    };
  } finally {
    await rm(snapshotDirectory, { force: true, recursive: true });
  }
}
