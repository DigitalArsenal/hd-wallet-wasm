import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { lstat, readFile, realpath, writeFile } from 'node:fs/promises';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const repositoryDirectory = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const HEX_40 = /^[0-9a-f]{40}$/u;
const HEX_64 = /^[0-9a-f]{64}$/u;
const HEX_128 = /^[0-9a-f]{128}$/u;
const VERSION = /^\d+\.\d+\.\d+$/u;

function exactKeys(value, expected, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (JSON.stringify(actual) !== JSON.stringify(wanted)) {
    throw new Error(`${label} keys are invalid`);
  }
}

function requireHex(value, pattern, label) {
  if (typeof value !== 'string' || !pattern.test(value)) {
    throw new Error(`${label} hash is invalid`);
  }
  return value;
}

function validatePackage(value, expectedName, version, gitCommit) {
  exactKeys(
    value,
    ['gitHead', 'integrity', 'name', 'provenanceSha256', 'tarballSha512', 'version'],
    'package',
  );
  if (value.name !== expectedName) throw new Error(`package name must be ${expectedName}`);
  if (value.version !== version) throw new Error(`package version must be ${version}`);
  if (value.gitHead !== gitCommit) throw new Error('package gitHead must match the source tag');
  requireHex(value.provenanceSha256, HEX_64, 'package provenance');
  requireHex(value.tarballSha512, HEX_128, 'package tarball');
  const expectedIntegrity = `sha512-${Buffer.from(value.tarballSha512, 'hex').toString('base64')}`;
  if (value.integrity !== expectedIntegrity) throw new Error('package integrity mismatch');
  return {
    integrity: value.integrity,
    name: value.name,
    provenanceSha256: value.provenanceSha256,
    tarballSha512: value.tarballSha512,
  };
}

function validatePasswordCorpus(value) {
  exactKeys(
    value,
    ['bytes', 'entries', 'sha256', 'sourceCommit', 'sourcePath', 'sourceRelease'],
    'password corpus',
  );
  if (!Number.isSafeInteger(value.bytes) || value.bytes <= 0) {
    throw new Error('password corpus bytes are invalid');
  }
  if (!Number.isSafeInteger(value.entries) || value.entries <= 0) {
    throw new Error('password corpus entries are invalid');
  }
  requireHex(value.sha256, HEX_64, 'password corpus');
  requireHex(value.sourceCommit, HEX_40, 'password corpus source commit');
  if (typeof value.sourcePath !== 'string' || value.sourcePath.length === 0
      || value.sourcePath.startsWith('/') || value.sourcePath.includes('..')) {
    throw new Error('password corpus sourcePath is invalid');
  }
  if (typeof value.sourceRelease !== 'string' || value.sourceRelease.length === 0) {
    throw new Error('password corpus sourceRelease is invalid');
  }
  return {
    bytes: value.bytes,
    entries: value.entries,
    sha256: value.sha256,
    sourceCommit: value.sourceCommit,
    sourcePath: value.sourcePath,
    sourceRelease: value.sourceRelease,
  };
}

export function buildReleaseRecord(input) {
  exactKeys(input, [
    'assetReviewProtocolSha256',
    'corePackage',
    'gitCommit',
    'npmProvenanceEvidenceSha256',
    'originServiceArtifactSha256',
    'passwordCorpus',
    'provenanceTrustPolicySha256',
    'registryReleaseSha256',
    'registryTag',
    'sourceTag',
    'uiPackage',
    'uiDependencyVersion',
    'version',
    'walletAssetsManifestSha256',
  ], 'release record input');
  if (typeof input.version !== 'string' || !VERSION.test(input.version)) {
    throw new Error('version is invalid');
  }
  if (input.sourceTag !== `v${input.version}`) throw new Error('source tag/version mismatch');
  if (input.uiDependencyVersion !== input.version) {
    throw new Error('UI dependency must be the exact release version');
  }
  if (typeof input.registryTag !== 'string' || input.registryTag.length === 0
      || input.registryTag === 'latest') {
    throw new Error('registry tag is invalid');
  }
  requireHex(input.gitCommit, HEX_40, 'git commit');
  for (const [label, value] of [
    ['asset review protocol', input.assetReviewProtocolSha256],
    ['npm provenance evidence', input.npmProvenanceEvidenceSha256],
    ['origin service artifact', input.originServiceArtifactSha256],
    ['provenance trust policy', input.provenanceTrustPolicySha256],
    ['registry release', input.registryReleaseSha256],
    ['wallet assets manifest', input.walletAssetsManifestSha256],
  ]) requireHex(value, HEX_64, label);

  return {
    assetReviewProtocolSha256: input.assetReviewProtocolSha256,
    corePackage: validatePackage(input.corePackage, 'hd-wallet-wasm', input.version, input.gitCommit),
    gitCommit: input.gitCommit,
    npmProvenanceEvidenceSha256: input.npmProvenanceEvidenceSha256,
    originServiceArtifactSha256: input.originServiceArtifactSha256,
    passwordCorpus: validatePasswordCorpus(input.passwordCorpus),
    provenanceTrustPolicySha256: input.provenanceTrustPolicySha256,
    registryReleaseSha256: input.registryReleaseSha256,
    registryTag: input.registryTag,
    schemaVersion: 1,
    sourceTag: input.sourceTag,
    uiPackage: validatePackage(input.uiPackage, 'hd-wallet-ui', input.version, input.gitCommit),
    version: input.version,
    walletAssetsManifestSha256: input.walletAssetsManifestSha256,
  };
}

export function validateReleaseRecord(record) {
  exactKeys(record, [
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
  ], 'release record');
  if (record.schemaVersion !== 1) throw new Error('release record schemaVersion must be 1');
  const rebuilt = buildReleaseRecord({
    assetReviewProtocolSha256: record.assetReviewProtocolSha256,
    corePackage: {
      ...record.corePackage,
      gitHead: record.gitCommit,
      version: record.version,
    },
    gitCommit: record.gitCommit,
    npmProvenanceEvidenceSha256: record.npmProvenanceEvidenceSha256,
    originServiceArtifactSha256: record.originServiceArtifactSha256,
    passwordCorpus: record.passwordCorpus,
    provenanceTrustPolicySha256: record.provenanceTrustPolicySha256,
    registryReleaseSha256: record.registryReleaseSha256,
    registryTag: record.registryTag,
    sourceTag: record.sourceTag,
    uiDependencyVersion: record.version,
    uiPackage: {
      ...record.uiPackage,
      gitHead: record.gitCommit,
      version: record.version,
    },
    version: record.version,
    walletAssetsManifestSha256: record.walletAssetsManifestSha256,
  });
  if (JSON.stringify(rebuilt) !== JSON.stringify(record)) {
    throw new Error('release record field order or value contract is invalid');
  }
  return structuredClone(record);
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('release record number must be finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value).sort().map(
      (key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`,
    ).join(',')}}`;
  }
  throw new Error('unsupported release record value');
}

function parseCli(arguments_) {
  const allowed = new Set([
    '--expected-correlation',
    '--expected-run-attempt',
    '--expected-run-id',
    '--out',
    '--provenance-evidence',
    '--registry-tag',
    '--source-tag',
    '--workflow-artifacts',
    '--workflow-artifact-attestation',
  ]);
  const values = new Map();
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index];
    const value = arguments_[index + 1];
    if (!allowed.has(name)) throw new Error(`unknown argument: ${name}`);
    if (value === undefined || value.startsWith('--')) throw new Error(`missing value for ${name}`);
    if (values.has(name)) throw new Error(`duplicate argument: ${name}`);
    values.set(name, value);
  }
  for (const required of [
    '--expected-correlation',
    '--expected-run-attempt',
    '--expected-run-id',
    '--out',
    '--provenance-evidence',
    '--registry-tag',
    '--source-tag',
    '--workflow-artifacts',
    '--workflow-artifact-attestation',
  ]) if (!values.has(required)) throw new Error(`missing required argument: ${required}`);
  const sourceTag = values.get('--source-tag');
  if (sourceTag !== 'v2.0.28') throw new Error('source tag must be v2.0.28');
  const correlation = values.get('--expected-correlation');
  if (!/^[0-9a-f]{32}$/u.test(correlation)) throw new Error('expected correlation is invalid');
  const runId = values.get('--expected-run-id');
  if (!/^[1-9][0-9]{0,19}$/u.test(runId)) throw new Error('expected run ID is invalid');
  const runAttempt = values.get('--expected-run-attempt');
  if (!/^[1-9][0-9]{0,8}$/u.test(runAttempt)) {
    throw new Error('expected run attempt is invalid');
  }
  const registryTag = values.get('--registry-tag');
  if (!/^sdn-candidate-[0-9a-f]{32}$/u.test(registryTag) || registryTag === 'latest') {
    throw new Error('registry tag is invalid');
  }
  return {
    correlation,
    output: resolve(values.get('--out')),
    provenanceEvidence: resolve(values.get('--provenance-evidence')),
    registryTag,
    runAttempt,
    runId,
    sourceTag,
    workflowArtifactAttestation: resolve(values.get('--workflow-artifact-attestation')),
    workflowArtifacts: resolve(values.get('--workflow-artifacts')),
  };
}

function runGit(arguments_, options = {}) {
  return execFileSync('git', arguments_, {
    cwd: repositoryDirectory,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    ...options,
  }).trim();
}

function gitFile(tag, path) {
  return execFileSync('git', ['show', `${tag}:${path}`], {
    cwd: repositoryDirectory,
    encoding: null,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

function parseJsonBytes(bytes, label) {
  try {
    return JSON.parse(bytes.toString('utf8'));
  } catch {
    throw new Error(`${label} is not valid JSON`);
  }
}

function shaHex(bytes, algorithm) {
  return createHash(algorithm).update(bytes).digest('hex');
}

function npmView(packageName, version) {
  let record;
  try {
    record = JSON.parse(execFileSync('npm', ['view', `${packageName}@${version}`, '--json'], {
      cwd: repositoryDirectory,
      encoding: 'utf8',
      env: {
        ...process.env,
        npm_config_audit: 'false',
        npm_config_fund: 'false',
        npm_config_update_notifier: 'false',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    }));
  } catch {
    throw new Error(`registry metadata query failed for ${packageName}@${version}`);
  }
  return record;
}

async function requireOutputOutsideRepository(output) {
  const outputStatus = await lstat(output).catch(() => null);
  if (outputStatus) throw new Error('release record output already exists');
  const [parent, source] = await Promise.all([
    realpath(dirname(output)),
    realpath(repositoryDirectory),
  ]);
  const pathFromSource = relative(source, parent);
  if (pathFromSource === ''
      || (!pathFromSource.startsWith(`..${sep}`) && pathFromSource !== '..'
        && !isAbsolute(pathFromSource))) {
    throw new Error('release record output must be outside the tagged tree');
  }
}

async function main() {
  const options = parseCli(process.argv.slice(2));
  if (runGit(['status', '--short', '--untracked-files=all']) !== '') {
    throw new Error('release record requires a clean feature branch');
  }
  if (runGit(['cat-file', '-t', options.sourceTag]) !== 'tag') {
    throw new Error('source tag must be annotated');
  }
  const commit = runGit(['rev-parse', `${options.sourceTag}^{commit}`]);
  if (runGit(['rev-parse', 'HEAD']) === commit) {
    throw new Error('release record must not be written at the tagged commit');
  }
  await requireOutputOutsideRepository(options.output);

  const trustPolicyBytes = gitFile(options.sourceTag, 'release/provenance-trust.v1.json');
  const trustPolicy = parseJsonBytes(trustPolicyBytes, 'tagged provenance trust policy');
  const trustPolicySha256 = shaHex(trustPolicyBytes, 'sha256');
  if (trustPolicyBytes.toString('utf8') !== `${canonicalJson(trustPolicy)}\n`) {
    throw new Error('tagged provenance trust policy must be JCS plus one LF');
  }
  const {
    serializeProvenanceEvidence,
    validateProvenanceTrustPolicy,
    verifyProvenanceEvidence,
  } = await import('./verify-provenance-evidence.mjs');
  validateProvenanceTrustPolicy(trustPolicy);

  const runAttempt = options.runAttempt;
  const { verifyWorkflowArtifactsDirectory } = await import('./verify-release.mjs');
  const report = await verifyWorkflowArtifactsDirectory(options.workflowArtifacts, {
    expectedCorrelation: options.correlation,
    expectedProvenanceTrustPolicySha256: trustPolicySha256,
    expectedRunAttempt: runAttempt,
    expectedRunId: options.runId,
    tag: options.sourceTag,
    version: '2.0.28',
    workflowArtifactAttestation: options.workflowArtifactAttestation,
  }, commit);
  if (report.provenanceTrustPolicySha256 !== trustPolicySha256) {
    throw new Error('workflow artifacts do not contain the signed-tag provenance trust policy');
  }

  const evidenceStatus = await lstat(options.provenanceEvidence).catch(() => null);
  if (!evidenceStatus?.isFile() || evidenceStatus.isSymbolicLink()) {
    throw new Error('provenance evidence must be a regular file');
  }
  const evidenceBytes = await readFile(options.provenanceEvidence);
  const evidence = JSON.parse(evidenceBytes.toString('utf8'));
  const verifiedEvidence = verifyProvenanceEvidence(evidence, trustPolicy);
  if (serializeProvenanceEvidence(verifiedEvidence, trustPolicy)
      !== evidenceBytes.toString('utf8')) {
    throw new Error('provenance evidence must be canonical verified evidence');
  }
  if (evidence.commit !== commit || evidence.sourceTag !== options.sourceTag
      || evidence.run.id !== options.runId || String(evidence.run.finalAttempt) !== runAttempt
      || evidence.run.correlation !== options.correlation) {
    throw new Error('provenance evidence run/source binding mismatch');
  }

  const registryRecords = {
    'hd-wallet-ui': npmView('hd-wallet-ui', '2.0.28'),
    'hd-wallet-wasm': npmView('hd-wallet-wasm', '2.0.28'),
  };
  const packageInput = (name, artifactName) => {
    const registry = registryRecords[name];
    const packageEvidence = evidence.packages.find((entry) => entry.name === name);
    const artifact = report.artifacts?.[artifactName];
    if (!packageEvidence || !artifact || registry.version !== '2.0.28'
        || registry.gitHead !== commit || registry.dist?.integrity !== packageEvidence.integrity
        || artifact.sha512 !== packageEvidence.tarball?.sha512) {
      throw new Error(`registry/artifact/provenance mismatch for ${name}`);
    }
    return {
      gitHead: registry.gitHead,
      integrity: registry.dist.integrity,
      name,
      provenanceSha256: shaHex(Buffer.from(canonicalJson(packageEvidence)), 'sha256'),
      tarballSha512: artifact.sha512,
      version: registry.version,
    };
  };

  const protocolBytes = gitFile(options.sourceTag, 'release/protocol/asset-review-v1.json');
  const registryBytes = gitFile(
    options.sourceTag,
    'wallet-ui/relay/config/client-registry.v1.json',
  );
  const walletAssetsBytes = gitFile(options.sourceTag, 'release/wallet-assets.v1.json');
  const corpusBytes = gitFile(
    options.sourceTag,
    'wallet-ui/data/common-passwords-sdn-v1.txt',
  );
  const corpusSource = parseJsonBytes(gitFile(
    options.sourceTag,
    'wallet-ui/data/common-passwords-sdn-v1.source.json',
  ), 'tagged password corpus source');
  const taggedRegistry = parseJsonBytes(registryBytes, 'tagged registry');
  if (corpusSource.bytes !== corpusBytes.length
      || corpusSource.sha256 !== shaHex(corpusBytes, 'sha256')) {
    throw new Error('tagged password corpus metadata mismatch');
  }

  const record = buildReleaseRecord({
    assetReviewProtocolSha256: shaHex(protocolBytes, 'sha256'),
    corePackage: packageInput('hd-wallet-wasm', 'coreTarball'),
    gitCommit: commit,
    npmProvenanceEvidenceSha256: shaHex(evidenceBytes, 'sha256'),
    originServiceArtifactSha256: report.artifacts.originService.sha256,
    passwordCorpus: {
      bytes: corpusBytes.length,
      entries: corpusBytes.toString('utf8').split('\n').filter(Boolean).length,
      sha256: corpusSource.sha256,
      sourceCommit: corpusSource.upstreamCommit,
      sourcePath: corpusSource.sourcePath,
      sourceRelease: corpusSource.upstreamRelease,
    },
    provenanceTrustPolicySha256: trustPolicySha256,
    registryReleaseSha256: taggedRegistry.registryReleaseSha256,
    registryTag: options.registryTag,
    sourceTag: options.sourceTag,
    uiDependencyVersion: report.packages?.ui?.dependency?.['hd-wallet-wasm'],
    uiPackage: packageInput('hd-wallet-ui', 'uiTarball'),
    version: '2.0.28',
    walletAssetsManifestSha256: shaHex(walletAssetsBytes, 'sha256'),
  });
  const bytes = `${canonicalJson(record)}\n`;
  await writeFile(options.output, bytes, { encoding: 'utf8', flag: 'wx', mode: 0o644 });
  if (runGit(['status', '--short', '--untracked-files=all']) !== '') {
    throw new Error('release record generation changed the source tree');
  }
  process.stdout.write(`${shaHex(Buffer.from(bytes), 'sha256')}  ${options.output}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
