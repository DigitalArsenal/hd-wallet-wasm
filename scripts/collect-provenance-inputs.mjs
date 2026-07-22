#!/usr/bin/env node

import {
  X509Certificate,
  createHash,
  createPublicKey,
} from 'node:crypto';
import { constants as fsConstants } from 'node:fs';
import {
  lstat,
  mkdtemp,
  open,
  rename,
  rm,
  writeFile,
} from 'node:fs/promises';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import {
  basename,
  dirname,
  join,
  parse,
  resolve,
  sep,
} from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import {
  canonicalizeJson,
  validateProvenanceTrustPolicy,
  verifyRegistryEvidenceTrust,
} from './verify-provenance-evidence.mjs';

const PACKAGE_NAMES = Object.freeze(['hd-wallet-ui', 'hd-wallet-wasm']);
const RELEASE_VERSION = '2.0.23';
const NPM_VERSION = '11.16.0';
const NPM_REGISTRY = 'https://registry.npmjs.org/';
const TUF_BOOTSTRAP_ROOT_VERSION = 14;
const TUF_IMPLEMENTATION_VERSION = '4.0.2';
const TUF_MIRROR = 'https://tuf-repo-cdn.sigstore.dev';
const PROVENANCE_PREDICATE = 'https://slsa.dev/provenance/v1';
const PUBLISH_PREDICATE = 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
const P256_KEY_DETAILS = 'PKIX_ECDSA_P256_SHA_256';
const OUTPUT_FILES = Object.freeze({
  'hd-wallet-ui': 'hd-wallet-ui.registry-evidence.v1.json',
  'hd-wallet-wasm': 'hd-wallet-wasm.registry-evidence.v1.json',
});

function fail(message) {
  throw new Error(`PROVENANCE_INPUTS: ${message}`);
}

function isRecord(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function requireRecord(value, label) {
  if (!isRecord(value)) fail(`${label} must be an object`);
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  return value;
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) fail(`${label} must be a nonempty string`);
  return value;
}

function requireCanonicalBase64(value, label) {
  requireString(value, label);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    fail(`${label} must be canonical base64`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) fail(`${label} must be canonical base64`);
  return bytes;
}

function p256PublicKeyEvidence(rawBytes, label) {
  const der = requireCanonicalBase64(rawBytes, label);
  let key;
  try {
    key = createPublicKey({ key: der, format: 'der', type: 'spki' });
  } catch {
    fail(`${label} must encode a DER SPKI public key`);
  }
  if (key.asymmetricKeyType !== 'ec'
      || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    fail(`${label} must encode a P-256 public key`);
  }
  return {
    publicKeyPem: key.export({ format: 'pem', type: 'spki' }).toString(),
    publicKeySha256: createHash('sha256').update(der).digest('hex'),
  };
}

function parseSha512Integrity(value, label) {
  requireString(value, label);
  if (!value.startsWith('sha512-')) fail(`${label} must use SHA-512`);
  const digest = requireCanonicalBase64(value.slice('sha512-'.length), `${label} digest`);
  if (digest.length !== 64) fail(`${label} must contain a 64-byte digest`);
  return digest.toString('hex');
}

function requireSha512Hex(value, label) {
  requireString(value, label);
  if (!/^[0-9a-f]{128}$/u.test(value)) fail(`${label} must be lowercase SHA-512 hex`);
  return value;
}

function parseIntegratedTime(bundle, name) {
  const material = requireRecord(bundle.verificationMaterial, `${name} verification material`);
  const entries = requireArray(material.tlogEntries, `${name} transparency log entries`);
  if (entries.length !== 1) fail(`${name} must have exactly one transparency log entry`);
  const entry = requireRecord(entries[0], `${name} transparency log entry`);
  const value = requireString(entry.integratedTime, `${name} transparency integrated time`);
  if (!/^[1-9][0-9]*$/u.test(value)) fail(`${name} transparency integrated time is invalid`);
  const seconds = Number(value);
  if (!Number.isSafeInteger(seconds)) fail(`${name} transparency integrated time is too large`);
  const when = new Date(seconds * 1000);
  if (Number.isNaN(when.getTime())) fail(`${name} transparency integrated time is invalid`);
  return { entry, seconds, when };
}

function parseValidity(value, label) {
  requireRecord(value, label);
  const startText = requireString(value.start, `${label}.start`);
  const start = Date.parse(startText);
  if (!Number.isFinite(start)) fail(`${label}.start is invalid`);
  let end = Number.POSITIVE_INFINITY;
  if (value.end !== undefined && value.end !== null) {
    const endText = requireString(value.end, `${label}.end`);
    end = Date.parse(endText);
    if (!Number.isFinite(end)) fail(`${label}.end is invalid`);
  }
  if (end <= start) fail(`${label} is empty or reversed`);
  return {
    end,
    normalized: {
      end: Number.isFinite(end) ? new Date(end).toISOString() : null,
      start: new Date(start).toISOString(),
    },
    start,
  };
}

function isValidAt(value, when, label) {
  const validity = parseValidity(value, label);
  const instant = when.getTime();
  return validity.start <= instant && instant < validity.end;
}

function requireExactPolicyAuthorization(rows, normalized, label) {
  const serialized = canonicalizeJson(normalized);
  const matches = rows.filter((row) => canonicalizeJson(row) === serialized);
  if (matches.length !== 1) fail(`${label} does not exactly match the signed trust policy`);
}

function requireCertificate(rawBytes, label) {
  const der = requireCanonicalBase64(rawBytes, label);
  let certificate;
  try {
    certificate = new X509Certificate(der);
  } catch {
    fail(`${label} must encode an X.509 certificate`);
  }
  if (!certificate.raw.equals(der)) fail(`${label} must contain canonical DER`);
  return { certificate, rawBytes };
}

function issuedBy(certificate, issuer) {
  try {
    return certificate.checkIssued(issuer) && certificate.verify(issuer.publicKey);
  } catch {
    return false;
  }
}

function authorityPath(leaf, authority, label) {
  const chain = requireRecord(authority.certChain, `${label}.certChain`);
  const rows = requireArray(chain.certificates, `${label}.certChain.certificates`);
  if (rows.length === 0 || rows.length > 8) fail(`${label} has an invalid certificate chain length`);
  const remaining = rows.map((row, index) => {
    requireRecord(row, `${label}.certChain.certificates[${index}]`);
    return requireCertificate(row.rawBytes, `${label}.certChain.certificates[${index}].rawBytes`);
  });
  const result = [];
  let current = leaf;
  while (remaining.length > 0) {
    const issuers = remaining
      .map((candidate, index) => ({ ...candidate, index }))
      .filter(({ certificate }) => issuedBy(current, certificate));
    if (issuers.length !== 1) fail(`${label} does not provide one unambiguous issuer path`);
    const issuer = issuers[0];
    result.push({ rawBytes: issuer.rawBytes });
    current = issuer.certificate;
    remaining.splice(issuer.index, 1);
  }
  if (!issuedBy(current, current)) fail(`${label} certificate path does not end at a self-signed root`);
  return result;
}

function exactAuditRow(audit, name) {
  requireRecord(audit, 'audit');
  if (requireArray(audit.invalid, 'audit.invalid').length !== 0) fail('audit invalid list must be empty');
  if (requireArray(audit.missing, 'audit.missing').length !== 0) fail('audit missing list must be empty');
  const verified = requireArray(audit.verified, 'audit.verified');
  const rows = verified.filter((row) => row?.name === name && row?.version === RELEASE_VERSION);
  if (rows.length !== 1) fail(`${name} must have exactly one audit row`);
  return rows[0];
}

function attestationBundles(row, name) {
  const attestations = requireArray(row.attestationBundles, `${name} audit attestation bundles`);
  const predicates = attestations.map((entry) => entry?.predicateType).sort();
  const current = [PROVENANCE_PREDICATE, PUBLISH_PREDICATE].sort();
  if (canonicalizeJson(predicates) !== canonicalizeJson(current)) {
    fail(`${name} attestation bundle set must contain exactly one provenance and one frozen npm publish attestation`);
  }
  attestations.forEach((entry, index) => requireRecord(entry?.bundle,
    `${name} audit attestation bundle ${index}`));
  return {
    provenance: requireRecord(attestations.find(
      ({ predicateType }) => predicateType === PROVENANCE_PREDICATE,
    ).bundle, `${name} provenance bundle`),
    publish: requireRecord(attestations.find(
      ({ predicateType }) => predicateType === PUBLISH_PREDICATE,
    ).bundle, `${name} npm publish bundle`),
  };
}

function publishSignature(bundle, name) {
  const envelope = requireRecord(bundle.dsseEnvelope, `${name} npm publish DSSE envelope`);
  const signatures = requireArray(envelope.signatures, `${name} npm publish DSSE signatures`);
  if (signatures.length !== 1) fail(`${name} must have exactly one npm publish DSSE signature`);
  const signature = requireRecord(signatures[0], `${name} npm publish DSSE signature`);
  return { keyid: requireString(signature.keyid, `${name} npm publish DSSE signature.keyid`) };
}

function registryKeyEvidence(target, selectors, name, trustPolicy) {
  const keys = requireArray(requireRecord(target, 'registry keys target').keys,
    'registry keys target.keys');
  const result = [];
  for (const selector of selectors) {
    const matches = keys.filter((key, index) => key?.keyId === selector.keyid
      && key.keyUsage === selector.keyUsage
      && isValidAt(
        requireRecord(key.publicKey, `registry keys target.keys[${index}].publicKey`).validFor,
        selector.when,
        `registry keys target.keys[${index}].publicKey.validFor`,
      ));
    if (matches.length !== 1) {
      fail(`${name} ${selector.keyUsage} key selection is ambiguous or missing`);
    }
    const match = requireRecord(matches[0], `${name} ${selector.keyUsage} key`);
    const publicKey = requireRecord(match.publicKey, `${name} ${selector.keyUsage} publicKey`);
    const details = match.keyDetails ?? P256_KEY_DETAILS;
    if (details !== P256_KEY_DETAILS) fail(`${name} ${selector.keyUsage} key details are wrong`);
    const key = p256PublicKeyEvidence(
      publicKey.rawBytes, `${name} ${selector.keyUsage} rawBytes`,
    );
    requireExactPolicyAuthorization(trustPolicy.npmRegistryKeys, {
      keyDetails: details,
      keyUsage: selector.keyUsage,
      keyid: selector.keyid,
      publicKeySha256: key.publicKeySha256,
      validFor: parseValidity(
        publicKey.validFor, `${name} ${selector.keyUsage} validFor`,
      ).normalized,
    }, `${name} ${selector.keyUsage} authorization`);
    const normalized = {
      keyid: selector.keyid,
      publicKeyPem: key.publicKeyPem,
    };
    const existing = result.find(({ keyid }) => keyid === normalized.keyid);
    if (existing && canonicalizeJson(existing) !== canonicalizeJson(normalized)) {
      fail(`${name} registry key usages disagree on public key material`);
    }
    if (!existing) result.push(normalized);
  }
  return result;
}

function transparencyLogEvidence(trustedRoot, entry, when, name, trustPolicy) {
  const entryLogId = requireString(requireRecord(entry.logId,
    `${name} transparency entry log ID`).keyId, `${name} transparency entry log ID.keyId`);
  const logs = requireArray(requireRecord(trustedRoot, 'trusted root').tlogs, 'trusted root.tlogs');
  const matches = logs.filter((log, index) => {
    requireRecord(log, `trusted root.tlogs[${index}]`);
    const effectiveLogId = log.checkpointKeyId?.keyId ?? log.logId?.keyId;
    if (effectiveLogId !== entryLogId) return false;
    if (log.hashAlgorithm !== 'SHA2_256') return false;
    const publicKey = requireRecord(log.publicKey, `trusted root.tlogs[${index}].publicKey`);
    return isValidAt(publicKey.validFor, when, `trusted root.tlogs[${index}].publicKey.validFor`);
  });
  if (matches.length !== 1) fail(`${name} transparency log selection is ambiguous or missing`);
  const match = matches[0];
  const details = match.keyDetails ?? P256_KEY_DETAILS;
  if (details !== P256_KEY_DETAILS) fail(`${name} transparency log key details are wrong`);
  const publicKey = p256PublicKeyEvidence(
    match.publicKey.rawBytes, `${name} transparency log publicKey.rawBytes`,
  );
  const baseUrl = requireString(match.baseUrl, `${name} transparency log baseUrl`);
  requireExactPolicyAuthorization(trustPolicy.sigstoreTransparencyLogs, {
    baseUrl,
    effectiveLogId: entryLogId,
    hashAlgorithm: match.hashAlgorithm,
    keyDetails: details,
    publicKeySha256: publicKey.publicKeySha256,
    validFor: parseValidity(
      match.publicKey.validFor, `${name} transparency log publicKey.validFor`,
    ).normalized,
  }, `${name} transparency log authorization`);
  return {
    baseUrl,
    logId: entryLogId,
    publicKeyPem: publicKey.publicKeyPem,
  };
}

function certificateChainEvidence(trustedRoot, bundle, when, name, trustPolicy) {
  const material = requireRecord(bundle.verificationMaterial, `${name} verification material`);
  const leafRow = requireRecord(material.certificate, `${name} signing certificate`);
  const leaf = requireCertificate(leafRow.rawBytes, `${name} signing certificate.rawBytes`).certificate;
  const authorities = requireArray(requireRecord(trustedRoot, 'trusted root').certificateAuthorities,
    'trusted root.certificateAuthorities');
  const paths = [];
  authorities.forEach((authority, index) => {
    requireRecord(authority, `trusted root.certificateAuthorities[${index}]`);
    if (authority.uri !== 'https://fulcio.sigstore.dev') return;
    if (!isValidAt(authority.validFor, when,
      `trusted root.certificateAuthorities[${index}].validFor`)) return;
    try {
      paths.push({
        authority,
        certificates: authorityPath(leaf, authority,
          `trusted root.certificateAuthorities[${index}]`),
      });
    } catch (error) {
      if (!(error instanceof Error) || !error.message.startsWith('PROVENANCE_INPUTS:')) throw error;
    }
  });
  if (paths.length !== 1) fail(`${name} certificate chain selection is ambiguous or missing`);
  const selected = paths[0];
  const root = requireCertificate(
    selected.certificates.at(-1).rawBytes, `${name} certificate authority root`,
  );
  requireExactPolicyAuthorization(trustPolicy.sigstoreCertificateAuthorities, {
    rootCertificateSha256: createHash('sha256').update(root.certificate.raw).digest('hex'),
    uri: selected.authority.uri,
    validFor: parseValidity(
      selected.authority.validFor, `${name} certificate authority validFor`,
    ).normalized,
  }, `${name} certificate authority authorization`);
  return { certificates: selected.certificates };
}

function selectDistRecord(distRecords, name) {
  const dist = requireRecord(requireRecord(distRecords, 'dist records')[name], `${name} dist`);
  return normalizeDistRecord(dist, name);
}

function normalizeDistRecord(value, name) {
  const dist = requireRecord(value, `${name} dist`);
  const signatures = requireArray(dist.signatures, `${name} dist.signatures`);
  if (signatures.length !== 1) fail(`${name} must have exactly one registry signature`);
  const signature = requireRecord(signatures[0], `${name} registry signature`);
  requireString(signature.keyid, `${name} registry signature.keyid`);
  requireString(signature.sig, `${name} registry signature.sig`);
  const expectedTarball = `${NPM_REGISTRY}${name}/-/${name}-${RELEASE_VERSION}.tgz`;
  if (dist.tarball !== expectedTarball) fail(`${name} registry tarball URL is wrong`);
  requireRecord(dist.attestations, `${name} dist.attestations`);
  return {
    attestations: structuredClone(dist.attestations),
    integrity: requireString(dist.integrity, `${name} dist.integrity`),
    signatures: [{ keyid: signature.keyid, sig: signature.sig }],
    tarball: dist.tarball,
  };
}

export function buildRegistryEvidenceEnvelope(input) {
  requireRecord(input, 'single-package input');
  const name = requireString(input.packageName, 'package name');
  if (!PACKAGE_NAMES.includes(name)) fail('package name is not an exact release package');
  const auditRow = requireRecord(input.auditRow, `${name} audit row`);
  if (auditRow.name !== name || auditRow.version !== RELEASE_VERSION) {
    fail(`${name} audit row does not match the exact package version`);
  }
  const trustPolicy = validateProvenanceTrustPolicy(input.trustPolicy);
  const bundles = attestationBundles(auditRow, name);
  const provenanceTime = parseIntegratedTime(bundles.provenance, name);
  const publishTime = parseIntegratedTime(bundles.publish, `${name} npm publish attestation`);
  const dist = normalizeDistRecord(input.distRecord, name);
  const integritySha512 = parseSha512Integrity(dist.integrity, `${name} dist.integrity`);
  const workflowSha512 = requireSha512Hex(input.workflowTarballSha512,
    `${name} workflow tarball SHA-512`);
  if (workflowSha512 !== integritySha512) {
    fail(`${name} workflow tarball digest does not match registry integrity`);
  }
  const provenanceLog = transparencyLogEvidence(
    input.trustedRoot, provenanceTime.entry, provenanceTime.when, name, trustPolicy,
  );
  const publishLog = transparencyLogEvidence(
    input.trustedRoot, publishTime.entry, publishTime.when,
    `${name} npm publish attestation`, trustPolicy,
  );
  if (canonicalizeJson(provenanceLog) !== canonicalizeJson(publishLog)) {
    fail(`${name} provenance and npm publish attestations require different transparency logs`);
  }
  const result = {
    dist,
    registryKeys: registryKeyEvidence(input.registryKeysTarget, [
      {
        keyUsage: 'npm:signatures',
        keyid: dist.signatures[0].keyid,
        when: provenanceTime.when,
      },
      {
        keyUsage: 'npm:attestations',
        keyid: publishSignature(bundles.publish, name).keyid,
        when: publishTime.when,
      },
    ], name, trustPolicy),
    sigstoreTrust: {
      certificateChain: certificateChainEvidence(
        input.trustedRoot, bundles.provenance, provenanceTime.when, name, trustPolicy,
      ),
      transparencyLog: provenanceLog,
    },
    workflowTarball: { sha512: workflowSha512 },
  };
  verifyRegistryEvidenceTrust({
    auditRow,
    packageName: name,
    registryEvidence: result,
    trustPolicy,
  });
  return structuredClone(result);
}

export function buildRegistryEvidenceEnvelopes(input) {
  requireRecord(input, 'input');
  const workflowDigests = requireRecord(input.workflowTarballSha512,
    'workflow tarball SHA-512 map');
  const evidence = {};
  for (const name of PACKAGE_NAMES) {
    const auditRow = exactAuditRow(input.audit, name);
    evidence[name] = buildRegistryEvidenceEnvelope({
      auditRow,
      distRecord: selectDistRecord(input.distRecords, name),
      packageName: name,
      registryKeysTarget: input.registryKeysTarget,
      trustedRoot: input.trustedRoot,
      trustPolicy: input.trustPolicy,
      workflowTarballSha512: workflowDigests[name],
    });
  }
  const verified = requireArray(input.audit.verified, 'audit.verified');
  if (verified.length !== PACKAGE_NAMES.length) fail('audit contains an unexpected verified row');
  return structuredClone(evidence);
}

export function parseProvenanceInputArguments(argv) {
  const allowed = new Set([
    '--audit', '--core-dist', '--core-tarball', '--dist', '--npm-cli', '--output-directory',
    '--package', '--tarball', '--trust-policy', '--ui-dist', '--ui-tarball',
  ]);
  const result = {};
  if (argv.length % 2 !== 0) fail('CLI flags must each have one value');
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!allowed.has(key) || result[key] !== undefined || typeof value !== 'string' || value.length === 0) {
      fail('CLI flags are missing, duplicated, or unknown');
    }
    result[key] = value;
  }
  const common = ['--audit', '--npm-cli', '--output-directory', '--trust-policy'];
  for (const flag of common) if (result[flag] === undefined) fail(`missing required flag ${flag}`);
  const singleFlags = ['--dist', '--package', '--tarball'];
  const finalFlags = ['--core-dist', '--core-tarball', '--ui-dist', '--ui-tarball'];
  const singleMode = singleFlags.some((flag) => result[flag] !== undefined);
  const finalMode = finalFlags.some((flag) => result[flag] !== undefined);
  if (singleMode === finalMode) fail('CLI must select exactly one provenance input mode');
  const required = singleMode ? singleFlags : finalFlags;
  const forbidden = singleMode ? finalFlags : singleFlags;
  for (const flag of required) if (result[flag] === undefined) fail(`missing required flag ${flag}`);
  for (const flag of forbidden) if (result[flag] !== undefined) fail('CLI modes use disjoint flags');
  if (singleMode && !PACKAGE_NAMES.includes(result['--package'])) {
    fail('package name is not an exact release package');
  }
  return { args: result, mode: singleMode ? 'single' : 'final' };
}

function sameFilesystemObject(left, right) {
  return left.dev === right.dev
    && left.ino === right.ino
    && left.mode === right.mode;
}

function sameFileState(left, right) {
  return sameFilesystemObject(left, right)
    && left.size === right.size
    && left.mtimeMs === right.mtimeMs
    && left.ctimeMs === right.ctimeMs;
}

async function inspectSafePath(path, label, { leafType, leafMayBeMissing = false }) {
  const absolutePath = resolve(path);
  const { root } = parse(absolutePath);
  const names = absolutePath.slice(root.length).split(sep).filter(Boolean);
  const snapshots = [];
  let current = root;
  for (let index = -1; index < names.length; index += 1) {
    if (index >= 0) current = join(current, names[index]);
    const isLeaf = index === names.length - 1;
    let stats;
    try {
      stats = await lstat(current);
    } catch (error) {
      if (error?.code === 'ENOENT' && isLeaf && leafMayBeMissing) {
        return { absolutePath, leafMissing: true, snapshots };
      }
      fail(`${label} path component cannot be inspected: ${current}`);
    }
    if (stats.isSymbolicLink()) fail(`${label} path component is a symlink: ${current}`);
    if (!isLeaf || leafType === 'directory') {
      if (!stats.isDirectory()) fail(`${label} path component is not a directory: ${current}`);
    } else if (leafType === 'file' && !stats.isFile()) {
      fail(`${label} must be a regular file`);
    }
    snapshots.push({ path: current, stats });
  }
  return { absolutePath, leafMissing: false, snapshots };
}

async function assertPathSnapshotsUnchanged(snapshots, label) {
  for (const snapshot of snapshots) {
    let current;
    try {
      current = await lstat(snapshot.path);
    } catch {
      fail(`${label} path changed while it was in use`);
    }
    if (current.isSymbolicLink() || !sameFilesystemObject(current, snapshot.stats)) {
      fail(`${label} path changed while it was in use`);
    }
  }
}

async function readRegularFileSnapshot(path, label) {
  const inspected = await inspectSafePath(path, label, { leafType: 'file' });
  const leaf = inspected.snapshots.at(-1)?.stats;
  let handle;
  try {
    handle = await open(
      inspected.absolutePath,
      fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0),
    );
  } catch {
    fail(`${label} must be a readable regular non-symlink file`);
  }
  try {
    const opened = await handle.stat();
    if (!leaf || !opened.isFile() || !sameFileState(opened, leaf)) {
      fail(`${label} changed before it could be read`);
    }
    await assertPathSnapshotsUnchanged(inspected.snapshots, label);
    const bytes = await handle.readFile();
    const after = await handle.stat();
    if (!sameFileState(opened, after)) fail(`${label} changed while it was being read`);
    await assertPathSnapshotsUnchanged(inspected.snapshots, label);
    return bytes;
  } finally {
    await handle.close();
  }
}

async function readJson(path, label) {
  let value;
  try {
    value = JSON.parse((await readRegularFileSnapshot(path, label)).toString('utf8'));
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('PROVENANCE_INPUTS:')) throw error;
    fail(`${label} is not readable JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
  return value;
}

async function sha512File(path, label) {
  const bytes = await readRegularFileSnapshot(path, label);
  return createHash('sha512').update(bytes).digest('hex');
}

async function assertRegularFile(path, label) {
  await readRegularFileSnapshot(path, label);
}

async function inspectUnusedOutputDirectory(path) {
  const inspected = await inspectSafePath(path, 'output directory', {
    leafMayBeMissing: true,
    leafType: 'directory',
  });
  if (!inspected.leafMissing) fail('output directory must not already exist');
  return inspected;
}

async function publishEvidenceDirectory(output, evidence, outputNames) {
  await assertPathSnapshotsUnchanged(output.snapshots, 'output directory');
  const parent = dirname(output.absolutePath);
  const stagingDirectory = await mkdtemp(join(parent, `.${basename(output.absolutePath)}.stage-`));
  let handedOff = false;
  try {
    const files = {};
    for (const name of outputNames) {
      const filename = OUTPUT_FILES[name];
      await writeFile(
        join(stagingDirectory, filename),
        `${canonicalizeJson(evidence[name])}\n`,
        { encoding: 'utf8', flag: 'wx', mode: 0o600 },
      );
      files[name] = filename;
    }
    const refreshed = await inspectUnusedOutputDirectory(output.absolutePath);
    await assertPathSnapshotsUnchanged(output.snapshots, 'output directory');
    await assertPathSnapshotsUnchanged(refreshed.snapshots, 'output directory');
    await rename(stagingDirectory, output.absolutePath);
    handedOff = true;
    return files;
  } finally {
    if (!handedOff) await rm(stagingDirectory, { force: true, recursive: true });
  }
}

async function loadTufMaterial(npmCli, trustPolicy) {
  await assertRegularFile(npmCli, 'npm CLI');
  const npmPackagePath = resolve(dirname(npmCli), '..', 'package.json');
  const npmPackage = await readJson(npmPackagePath, 'npm package metadata');
  if (npmPackage.name !== 'npm' || npmPackage.version !== NPM_VERSION) {
    fail(`npm CLI must belong to exact npm ${NPM_VERSION}`);
  }
  const policy = validateProvenanceTrustPolicy(trustPolicy);
  if (policy.source.tufBootstrapRootVersion !== TUF_BOOTSTRAP_ROOT_VERSION
      || policy.source.tufImplementationVersion !== TUF_IMPLEMENTATION_VERSION
      || policy.source.tufMirror !== TUF_MIRROR) {
    fail('signed trust policy TUF source is not the collector source');
  }
  const requireFromNpm = createRequire(pathToFileURL(npmCli));
  let tuf;
  let seeds;
  try {
    const tufPath = requireFromNpm.resolve('@sigstore/tuf');
    const tufPackagePath = requireFromNpm.resolve('@sigstore/tuf/package.json');
    const seedsPath = requireFromNpm.resolve('@sigstore/tuf/seeds.json');
    await assertRegularFile(tufPath, 'npm Sigstore TUF implementation');
    const tufPackage = await readJson(tufPackagePath, 'npm Sigstore TUF package metadata');
    if (tufPackage.name !== '@sigstore/tuf'
        || tufPackage.version !== policy.source.tufImplementationVersion) {
      fail(`npm must bundle exact @sigstore/tuf ${policy.source.tufImplementationVersion}`);
    }
    seeds = await readJson(seedsPath, 'npm Sigstore TUF seeds');
    tuf = requireFromNpm(tufPath);
  } catch (error) {
    if (error instanceof Error && error.message.startsWith('PROVENANCE_INPUTS:')) throw error;
    fail(`npm CLI does not provide the required Sigstore TUF implementation: ${error.message}`);
  }
  if (tuf.DEFAULT_MIRROR_URL !== policy.source.tufMirror) {
    fail('npm Sigstore TUF default mirror does not match the signed trust policy');
  }
  const seed = seeds[policy.source.tufMirror]?.['root.json'];
  const rootBytes = typeof seed === 'string' ? Buffer.from(seed, 'base64') : undefined;
  if (!rootBytes || rootBytes.toString('base64') !== seed
      || createHash('sha256').update(rootBytes).digest('hex')
        !== policy.source.tufBootstrapRootSha256) {
    fail('npm Sigstore TUF bootstrap root does not match the signed trust policy');
  }
  let rootMetadata;
  try {
    rootMetadata = JSON.parse(rootBytes.toString('utf8'));
  } catch {
    fail('npm Sigstore TUF bootstrap root is not JSON');
  }
  if (!isRecord(rootMetadata.signed)
      || rootMetadata.signed.version !== policy.source.tufBootstrapRootVersion) {
    fail(`npm Sigstore TUF bootstrap root must be exact version ${policy.source.tufBootstrapRootVersion}`);
  }
  const privateCache = await mkdtemp(join(tmpdir(), 'sdn-provenance-tuf-'));
  try {
    const cachePath = join(privateCache, 'cache');
    const rootPath = join(privateCache, `root.v${policy.source.tufBootstrapRootVersion}.json`);
    await writeFile(rootPath, rootBytes, { flag: 'wx', mode: 0o600 });
    const client = await tuf.initTUF({
      cachePath,
      forceCache: false,
      forceInit: true,
      mirrorURL: policy.source.tufMirror,
      rootPath,
    });
    const [registryKeysText, trustedRootText] = await Promise.all([
      client.getTarget(policy.source.registryKeysTarget),
      client.getTarget(policy.source.sigstoreTrustedRootTarget),
    ]);
    return {
      registryKeysTarget: JSON.parse(registryKeysText),
      trustedRoot: JSON.parse(trustedRootText),
    };
  } finally {
    await rm(privateCache, { force: true, recursive: true });
  }
}

async function main(argv) {
  const { args, mode } = parseProvenanceInputArguments(argv);
  const output = await inspectUnusedOutputDirectory(args['--output-directory']);
  const paths = mode === 'single'
    ? [
      args['--audit'], args['--dist'], args['--npm-cli'], args['--tarball'],
      args['--trust-policy'],
    ]
    : [
      args['--audit'], args['--core-dist'], args['--core-tarball'], args['--npm-cli'],
      args['--trust-policy'], args['--ui-dist'], args['--ui-tarball'],
    ];
  await Promise.all(paths.map((path, index) => assertRegularFile(path, `input file ${index + 1}`)));
  const audit = await readJson(args['--audit'], 'audit');
  const trustPolicy = await readJson(args['--trust-policy'], 'signed-tag provenance trust policy');
  validateProvenanceTrustPolicy(trustPolicy);
  const tuf = await loadTufMaterial(args['--npm-cli'], trustPolicy);
  let evidence;
  let outputNames;
  if (mode === 'single') {
    const name = args['--package'];
    const [distRecord, workflowTarballSha512] = await Promise.all([
      readJson(args['--dist'], `${name} dist`),
      sha512File(args['--tarball'], `${name} tarball`),
    ]);
    evidence = {
      [name]: buildRegistryEvidenceEnvelope({
        auditRow: exactAuditRow(audit, name),
        distRecord,
        packageName: name,
        registryKeysTarget: tuf.registryKeysTarget,
        trustedRoot: tuf.trustedRoot,
        trustPolicy,
        workflowTarballSha512,
      }),
    };
    outputNames = [name];
  } else {
    const [coreDist, uiDist, coreSha512, uiSha512] = await Promise.all([
      readJson(args['--core-dist'], 'core dist'),
      readJson(args['--ui-dist'], 'UI dist'),
      sha512File(args['--core-tarball'], 'core tarball'),
      sha512File(args['--ui-tarball'], 'UI tarball'),
    ]);
    evidence = buildRegistryEvidenceEnvelopes({
      audit,
      distRecords: { 'hd-wallet-ui': uiDist, 'hd-wallet-wasm': coreDist },
      registryKeysTarget: tuf.registryKeysTarget,
      trustedRoot: tuf.trustedRoot,
      trustPolicy,
      workflowTarballSha512: { 'hd-wallet-ui': uiSha512, 'hd-wallet-wasm': coreSha512 },
    });
    outputNames = PACKAGE_NAMES;
  }
  const files = await publishEvidenceDirectory(output, evidence, outputNames);
  process.stdout.write(`${canonicalizeJson({ files, status: 'verified' })}\n`);
}

const isMain = process.argv[1]
  && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  main(process.argv.slice(2)).catch((error) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
