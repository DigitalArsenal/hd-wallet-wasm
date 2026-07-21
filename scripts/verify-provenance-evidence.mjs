#!/usr/bin/env node

import {
  X509Certificate,
  createHash,
  createPublicKey,
  verify as verifySignature,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { TextDecoder } from 'node:util';

const SCHEMA_VERSION = 1;
const RELEASE_VERSION = '2.0.22';
const PACKAGE_NAMES = Object.freeze(['hd-wallet-ui', 'hd-wallet-wasm']);
const NPM_REGISTRY = 'https://registry.npmjs.org/';
const EXPECTED_REPOSITORY = 'https://github.com/DigitalArsenal/hd-wallet-wasm';
const EXPECTED_REPOSITORY_ID = '1142529413';
const EXPECTED_REPOSITORY_OWNER_ID = '29587475';
const EXPECTED_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
const EXPECTED_WORKFLOW = 'npm-publish.yml';
const EXPECTED_SOURCE_TAG = 'v2.0.22';
const PROVENANCE_PREDICATE = 'https://slsa.dev/provenance/v1';
const PUBLISH_PREDICATE = 'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
const STATEMENT_TYPE = 'https://in-toto.io/Statement/v1';
const PUBLISH_STATEMENT_TYPE = 'https://in-toto.io/Statement/v0.1';
const PAYLOAD_TYPE = 'application/vnd.in-toto+json';
const BUILD_TYPE = 'https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1';
const BUILDER_ID = 'https://github.com/actions/runner/github-hosted';
const BUNDLE_MEDIA_TYPE = 'application/vnd.dev.sigstore.bundle.v0.3+json';
const PUBLISH_BUNDLE_MEDIA_TYPE = 'application/vnd.dev.sigstore.bundle+json;version=0.2';
const MAX_JSON_BYTES = 16 * 1024 * 1024;
const MAX_RUN_ATTEMPTS = 32;
const TRUST_POLICY_URL = new URL('../release/provenance-trust.v1.json', import.meta.url);
const CERTIFICATE_OIDS = Object.freeze({
  codeSigning: '1.3.6.1.5.5.7.3.3',
  extendedKeyUsage: '2.5.29.37',
  issuer: '1.3.6.1.4.1.57264.1.1',
  issuerV2: '1.3.6.1.4.1.57264.1.8',
  keyUsage: '2.5.29.15',
  sourceRepositoryIdentifier: '1.3.6.1.4.1.57264.1.15',
  sourceRepositoryOwnerIdentifier: '1.3.6.1.4.1.57264.1.17',
  subjectAlternativeName: '2.5.29.17',
});
const STRICT_UTF8_DECODER = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

function fail(message) {
  throw new Error(`PROVENANCE_EVIDENCE: ${message}`);
}

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function requireRecord(value, label) {
  if (!isRecord(value)) fail(`${label} must be a plain JSON object`);
  return value;
}

function requireArray(value, label) {
  if (!Array.isArray(value)) fail(`${label} must be an array`);
  return value;
}

function requireString(value, label) {
  if (typeof value !== 'string' || value.length === 0) fail(`${label} must be a nonempty string`);
  assertUnicodeScalarString(value, label);
  return value;
}

function requireExactKeys(value, keys, label) {
  requireRecord(value, label);
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (actual.length !== expected.length || actual.some((key, index) => key !== expected[index])) {
    fail(`${label} must have exact keys ${expected.join(',')}`);
  }
  return value;
}

function assertUnicodeScalarString(value, label) {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) fail(`${label} contains an unpaired surrogate`);
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      fail(`${label} contains an unpaired surrogate`);
    }
  }
}

function canonicalValue(value, label) {
  if (value === null) return 'null';
  if (typeof value === 'string') {
    assertUnicodeScalarString(value, label);
    return JSON.stringify(value);
  }
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (!Number.isFinite(value) || Object.is(value, -0)) fail(`${label} contains a non-JCS number`);
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    const keys = Object.keys(value);
    if (keys.length !== value.length
        || keys.some((key, index) => key !== String(index))) {
      fail(`${label} must be a dense array with no extra properties`);
    }
    return `[${value.map((entry, index) => canonicalValue(entry, `${label}[${index}]`)).join(',')}]`;
  }
  if (!isRecord(value)) fail(`${label} must be a plain JSON object or JSON primitive`);
  const keys = Object.keys(value).sort();
  return `{${keys.map((key) => {
    assertUnicodeScalarString(key, `${label} key`);
    if (value[key] === undefined) fail(`${label}.${key} is undefined`);
    return `${JSON.stringify(key)}:${canonicalValue(value[key], `${label}.${key}`)}`;
  }).join(',')}}`;
}

export function canonicalizeJson(value) {
  return canonicalValue(value, 'JSON');
}

function clone(value) {
  return structuredClone(value);
}

function requireLowerHex(value, bytes, label) {
  requireString(value, label);
  const expression = new RegExp(`^[0-9a-f]{${bytes * 2}}$`, 'u');
  if (!expression.test(value)) fail(`${label} must be ${bytes}-byte lowercase hex`);
  return value;
}

function requireDecimal(value, label, { allowZero = true } = {}) {
  requireString(value, label);
  if (!/^(0|[1-9][0-9]*)$/u.test(value)) fail(`${label} must be canonical decimal`);
  const number = BigInt(value);
  if (!allowZero && number === 0n) fail(`${label} must be positive`);
  return number;
}

function decodeBase64(value, label, expectedBytes) {
  requireString(value, label);
  if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u.test(value)) {
    fail(`${label} must be canonical base64`);
  }
  const bytes = Buffer.from(value, 'base64');
  if (bytes.toString('base64') !== value) fail(`${label} must be canonical base64`);
  if (expectedBytes !== undefined && bytes.length !== expectedBytes) {
    fail(`${label} must encode ${expectedBytes} bytes`);
  }
  return bytes;
}

function sha256(...parts) {
  const hash = createHash('sha256');
  parts.forEach((part) => hash.update(part));
  return hash.digest();
}

function parseIntegrity(value, label) {
  requireString(value, label);
  if (!value.startsWith('sha512-')) fail(`${label} must use exactly sha512`);
  const digest = decodeBase64(value.slice('sha512-'.length), `${label} digest`, 64);
  return { integrity: value, sha512: digest.toString('hex') };
}

function parsePublicKey(value, label) {
  requireString(value, label);
  let key;
  try {
    key = createPublicKey(value);
  } catch {
    fail(`${label} is not a public key`);
  }
  const canonicalPem = key.export({ type: 'spki', format: 'pem' }).toString();
  if (canonicalPem !== value) fail(`${label} must be canonical SPKI PEM`);
  return key;
}

function requireP256PublicKey(key, label) {
  if (key.asymmetricKeyType !== 'ec'
      || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1') {
    fail(`${label} must be an ECDSA P-256 public key`);
  }
  return key;
}

function sha256Hex(value) {
  return createHash('sha256').update(value).digest('hex');
}

function requireValidity(value, label) {
  requireExactKeys(value, ['end', 'start'], label);
  const startText = requireString(value.start, `${label}.start`);
  const start = Date.parse(startText);
  if (!Number.isFinite(start) || new Date(start).toISOString() !== startText) {
    fail(`${label}.start must be canonical UTC RFC3339`);
  }
  let end = Number.POSITIVE_INFINITY;
  if (value.end !== null) {
    const endText = requireString(value.end, `${label}.end`);
    end = Date.parse(endText);
    if (!Number.isFinite(end) || new Date(end).toISOString() !== endText) {
      fail(`${label}.end must be canonical UTC RFC3339 or null`);
    }
  }
  if (end <= start) fail(`${label} is empty or reversed`);
  return { end, start };
}

function validAt(value, instant, label) {
  const validity = requireValidity(value, label);
  return validity.start <= instant && instant < validity.end;
}

export function validateProvenanceTrustPolicy(value) {
  requireExactKeys(value, [
    'npmRegistryKeys', 'release', 'schemaVersion', 'sigstoreCertificateAuthorities',
    'sigstoreTransparencyLogs', 'source',
  ], 'provenance trust policy');
  if (value.schemaVersion !== 1) fail('provenance trust policy schemaVersion is wrong');
  requireExactKeys(value.release, [
    'packages', 'repository', 'repositoryId', 'repositoryOwnerId', 'sourceTag',
    'version', 'workflow',
  ], 'provenance trust policy release');
  if (canonicalizeJson(value.release.packages) !== canonicalizeJson(PACKAGE_NAMES)
      || value.release.repository !== EXPECTED_REPOSITORY
      || value.release.repositoryId !== EXPECTED_REPOSITORY_ID
      || value.release.repositoryOwnerId !== EXPECTED_REPOSITORY_OWNER_ID
      || value.release.sourceTag !== EXPECTED_SOURCE_TAG
      || value.release.version !== RELEASE_VERSION
      || value.release.workflow !== `.github/workflows/${EXPECTED_WORKFLOW}`) {
    fail('provenance trust policy release binding is wrong');
  }
  requireExactKeys(value.source, [
    'npmVersion', 'registryKeysTarget', 'sigstoreTrustedRootTarget',
    'tufBootstrapRootSha256', 'tufBootstrapRootVersion', 'tufImplementationVersion',
    'tufMirror',
  ], 'provenance trust policy source');
  if (value.source.npmVersion !== '11.16.0'
      || value.source.registryKeysTarget !== 'registry.npmjs.org/keys.json'
      || value.source.sigstoreTrustedRootTarget !== 'trusted_root.json'
      || value.source.tufBootstrapRootSha256
        !== 'c8c41ec13f06ccabf5b48541ee2550098b4c7b5349e1d180390c29a7d5c2642c'
      || value.source.tufBootstrapRootVersion !== 14
      || value.source.tufImplementationVersion !== '4.0.2'
      || value.source.tufMirror !== 'https://tuf-repo-cdn.sigstore.dev') {
    fail('provenance trust policy source is not frozen');
  }
  const registryKeys = requireArray(value.npmRegistryKeys,
    'provenance trust policy npm registry keys');
  if (registryKeys.length !== 2) {
    fail('provenance trust policy must contain exactly two npm registry authorizations');
  }
  registryKeys.forEach((row, index) => {
    requireExactKeys(row, ['keyDetails', 'keyUsage', 'keyid', 'publicKeySha256', 'validFor'],
      `provenance trust policy npm key ${index}`);
    if (row.keyDetails !== 'PKIX_ECDSA_P256_SHA_256') {
      fail(`provenance trust policy npm key ${index} details are invalid`);
    }
    if (!['npm:attestations', 'npm:signatures'].includes(row.keyUsage)) {
      fail(`provenance trust policy npm key ${index} usage is invalid`);
    }
    if (!/^SHA256:[A-Za-z0-9+/]{43}$/u.test(requireString(
      row.keyid, `provenance trust policy npm key ${index} ID`,
    ))) fail(`provenance trust policy npm key ${index} ID is invalid`);
    requireLowerHex(row.publicKeySha256, 32,
      `provenance trust policy npm key ${index} public key SHA-256`);
    requireValidity(row.validFor, `provenance trust policy npm key ${index} validity`);
  });
  const authorities = requireArray(value.sigstoreCertificateAuthorities,
    'provenance trust policy certificate authorities');
  if (authorities.length === 0 || authorities.length > 16) {
    fail('provenance trust policy certificate authorities are empty or unbounded');
  }
  authorities.forEach((row, index) => {
    requireExactKeys(row, ['rootCertificateSha256', 'uri', 'validFor'],
      `provenance trust policy certificate authority ${index}`);
    if (row.uri !== 'https://fulcio.sigstore.dev') {
      fail(`provenance trust policy certificate authority ${index} URI is invalid`);
    }
    requireLowerHex(row.rootCertificateSha256, 32,
      `provenance trust policy certificate authority ${index} root SHA-256`);
    requireValidity(row.validFor,
      `provenance trust policy certificate authority ${index} validity`);
  });
  const logs = requireArray(value.sigstoreTransparencyLogs,
    'provenance trust policy transparency logs');
  if (logs.length === 0 || logs.length > 16) {
    fail('provenance trust policy transparency logs are empty or unbounded');
  }
  logs.forEach((row, index) => {
    requireExactKeys(row, [
      'baseUrl', 'effectiveLogId', 'hashAlgorithm', 'keyDetails',
      'publicKeySha256', 'validFor',
    ],
      `provenance trust policy transparency log ${index}`);
    if (row.hashAlgorithm !== 'SHA2_256'
        || row.keyDetails !== 'PKIX_ECDSA_P256_SHA_256') {
      fail(`provenance trust policy transparency log ${index} algorithm is invalid`);
    }
    const baseUrl = new URL(requireString(row.baseUrl,
      `provenance trust policy transparency log ${index} base URL`));
    if (baseUrl.protocol !== 'https:' || baseUrl.username || baseUrl.password
        || baseUrl.hash || baseUrl.search || baseUrl.pathname !== '/') {
      fail(`provenance trust policy transparency log ${index} base URL is invalid`);
    }
    decodeBase64(row.effectiveLogId,
      `provenance trust policy transparency log ${index} ID`, 32);
    requireLowerHex(row.publicKeySha256, 32,
      `provenance trust policy transparency log ${index} public key SHA-256`);
    requireValidity(row.validFor,
      `provenance trust policy transparency log ${index} validity`);
  });
  if (new Set(authorities.map(({ rootCertificateSha256 }) => rootCertificateSha256)).size
      !== authorities.length) {
    fail('provenance trust policy certificate authority identities must be unique');
  }
  if (new Set(logs.map(({ effectiveLogId }) => effectiveLogId)).size !== logs.length
      || new Set(logs.map(({ baseUrl }) => baseUrl)).size !== logs.length) {
    fail('provenance trust policy transparency log identities must be unique');
  }
  for (const [label, rows] of [
    ['npm keys', registryKeys], ['certificate authorities', authorities], ['transparency logs', logs],
  ]) {
    const serialized = rows.map((row) => canonicalizeJson(row));
    if (new Set(serialized).size !== serialized.length) {
      fail(`provenance trust policy ${label} contain duplicates`);
    }
    if (serialized.some((row, index) => row !== [...serialized].sort()[index])) {
      fail(`provenance trust policy ${label} must be sorted`);
    }
  }
  if (canonicalizeJson(registryKeys.map(({ keyUsage }) => keyUsage))
      !== canonicalizeJson(['npm:attestations', 'npm:signatures'])) {
    fail('provenance trust policy must authorize both exact npm key usages');
  }
  return clone(value);
}

let cachedTrustPolicy;
function defaultTrustPolicy() {
  if (!cachedTrustPolicy) {
    cachedTrustPolicy = validateProvenanceTrustPolicy(readStrictJson(
      TRUST_POLICY_URL,
      'signed-tag provenance trust policy',
    ));
  }
  return cachedTrustPolicy;
}

function integratedTimeFromBundle(bundle, name) {
  const material = requireRecord(bundle.verificationMaterial, `${name} verification material`);
  const entries = requireArray(material.tlogEntries, `${name} transparency log entries`);
  if (entries.length !== 1) fail(`${name} must have exactly one transparency log entry`);
  const entry = requireRecord(entries[0], `${name} transparency log entry`);
  const seconds = requireDecimal(entry.integratedTime,
    `${name} transparency integrated time`, { allowZero: false });
  if (seconds > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail(`${name} transparency integrated time is too large`);
  }
  return Number(seconds) * 1000;
}

function requireAuthorizedNpmKey({ bundle, keyUsage, name, registryKey, trustPolicy }) {
  const policy = validateProvenanceTrustPolicy(trustPolicy ?? defaultTrustPolicy());
  const instant = integratedTimeFromBundle(bundle, name);
  const parsedRegistryKey = requireRegistryKey(registryKey, `${name} registry trust key`);
  requireP256PublicKey(parsedRegistryKey.key, `${name} registry trust key`);
  const registryKeySha256 = sha256Hex(parsedRegistryKey.key.export({
    format: 'der', type: 'spki',
  }));
  const keyMatches = policy.npmRegistryKeys.filter((row, index) =>
    row.keyUsage === keyUsage
      && row.keyid === registryKey.keyid
      && row.publicKeySha256 === registryKeySha256
      && validAt(row.validFor, instant, `provenance trust policy npm key ${index} validity`));
  if (keyMatches.length !== 1) {
    fail(`${name} ${keyUsage} key is not authorized by the signed trust policy`);
  }
  return { instant, parsedRegistryKey, policy };
}

function requireAuthorizedTransparencyLog({ instant, name, policy, trust }) {
  requireExactKeys(trust.transparencyLog, ['baseUrl', 'logId', 'publicKeyPem'],
    `${name} transparency log trust material`);
  const logKey = parsePublicKey(trust.transparencyLog.publicKeyPem,
    `${name} transparency log public key`);
  requireP256PublicKey(logKey, `${name} transparency log public key`);
  const logKeySha256 = sha256Hex(logKey.export({ format: 'der', type: 'spki' }));
  const logMatches = policy.sigstoreTransparencyLogs.filter((row, index) =>
    row.baseUrl === trust.transparencyLog.baseUrl
      && row.effectiveLogId === trust.transparencyLog.logId
      && row.publicKeySha256 === logKeySha256
      && validAt(row.validFor, instant,
        `provenance trust policy transparency log ${index} validity`));
  if (logMatches.length !== 1) {
    fail(`${name} transparency log is not authorized by the signed trust policy`);
  }
}

function requireTrustedPackageMaterials({ bundle, name, registryKey, trust, trustPolicy }) {
  const { instant, policy } = requireAuthorizedNpmKey({
    bundle,
    keyUsage: 'npm:signatures',
    name,
    registryKey,
    trustPolicy,
  });

  requireExactKeys(trust, ['certificateChain', 'transparencyLog'], `${name} Sigstore trust`);
  const authorityRows = requireArray(trust.certificateChain?.certificates,
    `${name} certificate chain certificates`);
  if (authorityRows.length === 0) fail(`${name} certificate chain is empty`);
  const rootBytes = decodeBase64(authorityRows.at(-1)?.rawBytes,
    `${name} root certificate bytes`);
  const rootSha256 = sha256Hex(rootBytes);
  const authorityMatches = policy.sigstoreCertificateAuthorities.filter((row, index) =>
    row.rootCertificateSha256 === rootSha256
      && validAt(row.validFor, instant,
        `provenance trust policy certificate authority ${index} validity`));
  if (authorityMatches.length !== 1) {
    fail(`${name} certificate root is not authorized by the signed trust policy`);
  }

  requireAuthorizedTransparencyLog({ instant, name, policy, trust });
  return true;
}

function requireTrustedPublishMaterials({ bundle, name, registryKey, trust, trustPolicy }) {
  const { instant, parsedRegistryKey, policy } = requireAuthorizedNpmKey({
    bundle,
    keyUsage: 'npm:attestations',
    name: `${name} publish attestation`,
    registryKey,
    trustPolicy,
  });
  requireExactKeys(trust, ['certificateChain', 'transparencyLog'], `${name} Sigstore trust`);
  requireAuthorizedTransparencyLog({
    instant,
    name: `${name} publish attestation`,
    policy,
    trust,
  });
  return parsedRegistryKey;
}

export function verifyRegistryEvidenceTrust({ auditRow, packageName, registryEvidence, trustPolicy }) {
  const { provenance, publish } = selectAttestations(auditRow?.attestationBundles, packageName);
  const signatures = requireArray(registryEvidence?.dist?.signatures,
    `${packageName} registry signatures`);
  if (signatures.length !== 1) fail(`${packageName} must have exactly one registry signature`);
  const signatureKey = selectRegistryKey(
    registryEvidence?.registryKeys,
    signatures[0]?.keyid,
    packageName,
    'registry signature',
  );
  requireTrustedPackageMaterials({
    bundle: provenance.bundle,
    name: packageName,
    registryKey: signatureKey,
    trust: registryEvidence.sigstoreTrust,
    trustPolicy,
  });
  const publishSignatures = requireArray(publish.bundle?.dsseEnvelope?.signatures,
    `${packageName} publish DSSE signatures`);
  if (publishSignatures.length !== 1) {
    fail(`${packageName} publish attestation must have exactly one DSSE signature`);
  }
  requireExactlyBoundRegistryKeys(registryEvidence.registryKeys, [
    signatures[0]?.keyid,
    publishSignatures[0]?.keyid,
  ], packageName);
  const publishKey = selectRegistryKey(
    registryEvidence.registryKeys,
    publishSignatures[0]?.keyid,
    packageName,
    'publish attestation',
  );
  const integrity = parseIntegrity(registryEvidence?.dist?.integrity,
    `${packageName} registry integrity`);
  verifyPublishBundle(publish.bundle, registryEvidence.sigstoreTrust, publishKey, {
    name: packageName,
    sha512: integrity.sha512,
  }, trustPolicy);
  return true;
}

function signatureAlgorithm(key) {
  return key.asymmetricKeyType === 'ed25519' ? null : 'sha256';
}

function requireValidSignature(key, data, signature, label) {
  let valid = false;
  try {
    valid = verifySignature(signatureAlgorithm(key), data, key, signature);
  } catch {
    valid = false;
  }
  if (!valid) fail(`${label} is invalid`);
}

function parseJsonTextStrict(text, label) {
  if (typeof text !== 'string') fail(`${label} must be UTF-8 JSON text`);
  if (Buffer.byteLength(text, 'utf8') > MAX_JSON_BYTES) fail(`${label} is too large`);
  let offset = 0;

  function skipWhitespace() {
    while (offset < text.length && /[\u0009\u000a\u000d\u0020]/u.test(text[offset])) offset += 1;
  }

  function scanString() {
    const start = offset;
    if (text[offset] !== '"') fail(`${label} contains malformed JSON`);
    offset += 1;
    while (offset < text.length) {
      const code = text.charCodeAt(offset);
      if (code === 0x22) {
        offset += 1;
        try {
          return JSON.parse(text.slice(start, offset));
        } catch {
          fail(`${label} contains malformed JSON string data`);
        }
      }
      if (code < 0x20) fail(`${label} contains malformed JSON string data`);
      if (code === 0x5c) {
        offset += 1;
        if (offset >= text.length || !/["\\/bfnrtu]/u.test(text[offset])) {
          fail(`${label} contains malformed JSON escape data`);
        }
        if (text[offset] === 'u') {
          if (!/^[0-9a-fA-F]{4}$/u.test(text.slice(offset + 1, offset + 5))) {
            fail(`${label} contains malformed JSON Unicode data`);
          }
          offset += 4;
        }
      }
      offset += 1;
    }
    fail(`${label} contains an unterminated JSON string`);
  }

  function scanNumber() {
    const match = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/uy;
    match.lastIndex = offset;
    const found = match.exec(text);
    if (!found) fail(`${label} contains malformed JSON number data`);
    offset = match.lastIndex;
  }

  function scanLiteral(literal) {
    if (text.slice(offset, offset + literal.length) !== literal) fail(`${label} contains malformed JSON`);
    offset += literal.length;
  }

  function scanArray() {
    offset += 1;
    skipWhitespace();
    if (text[offset] === ']') {
      offset += 1;
      return;
    }
    while (offset < text.length) {
      scanValue();
      skipWhitespace();
      if (text[offset] === ']') {
        offset += 1;
        return;
      }
      if (text[offset] !== ',') fail(`${label} contains malformed JSON array data`);
      offset += 1;
      skipWhitespace();
    }
    fail(`${label} contains an unterminated JSON array`);
  }

  function scanObject() {
    offset += 1;
    skipWhitespace();
    const keys = new Set();
    if (text[offset] === '}') {
      offset += 1;
      return;
    }
    while (offset < text.length) {
      const key = scanString();
      if (keys.has(key)) fail(`${label} contains duplicate JSON object key ${JSON.stringify(key)}`);
      keys.add(key);
      skipWhitespace();
      if (text[offset] !== ':') fail(`${label} contains malformed JSON object data`);
      offset += 1;
      scanValue();
      skipWhitespace();
      if (text[offset] === '}') {
        offset += 1;
        return;
      }
      if (text[offset] !== ',') fail(`${label} contains malformed JSON object data`);
      offset += 1;
      skipWhitespace();
    }
    fail(`${label} contains an unterminated JSON object`);
  }

  function scanValue() {
    skipWhitespace();
    const current = text[offset];
    if (current === '{') scanObject();
    else if (current === '[') scanArray();
    else if (current === '"') scanString();
    else if (current === 't') scanLiteral('true');
    else if (current === 'f') scanLiteral('false');
    else if (current === 'n') scanLiteral('null');
    else scanNumber();
  }

  scanValue();
  skipWhitespace();
  if (offset !== text.length) fail(`${label} contains trailing JSON data`);
  let value;
  try {
    value = JSON.parse(text);
  } catch {
    fail(`${label} is not valid JSON`);
  }
  canonicalizeJson(value);
  return value;
}

function requireExpectedRelease({ repository, workflow, sourceTag, commit }) {
  if (repository !== EXPECTED_REPOSITORY) fail('source repository is not the frozen repository');
  if (workflow !== EXPECTED_WORKFLOW) fail('workflow name is not the frozen workflow');
  if (sourceTag !== EXPECTED_SOURCE_TAG) fail('source tag is not the frozen tag');
  requireLowerHex(commit, 20, 'source commit');
  return {
    repository,
    repositoryId: EXPECTED_REPOSITORY_ID,
    repositoryOwnerId: EXPECTED_REPOSITORY_OWNER_ID,
    sourceTag,
    commit,
    workflow: {
      identity: `${repository}/.github/workflows/${workflow}@refs/tags/${sourceTag}`,
      name: workflow,
      path: `.github/workflows/${workflow}`,
      ref: `refs/tags/${sourceTag}`,
    },
  };
}

function requireRunMetadata(value, commit) {
  requireExactKeys(value, ['attempts', 'commit', 'correlation', 'finalAttempt', 'runId'], 'run metadata');
  if (value.commit !== commit) fail('run metadata commit does not match source commit');
  requireLowerHex(value.correlation, 16, 'run correlation');
  requireString(value.runId, 'run ID');
  if (!/^[1-9][0-9]{0,19}$/u.test(value.runId)) fail('run ID must be canonical positive decimal');
  const attempts = requireArray(value.attempts, 'run attempts');
  if (attempts.length === 0 || attempts.length > MAX_RUN_ATTEMPTS) fail('run attempts are not bounded');
  let previous = 0;
  for (const attempt of attempts) {
    if (!Number.isSafeInteger(attempt) || attempt < 1 || attempt <= previous) {
      fail('run attempts must be strictly increasing positive safe integers');
    }
    previous = attempt;
  }
  if (!Number.isSafeInteger(value.finalAttempt) || value.finalAttempt !== attempts.at(-1)) {
    fail('run finalAttempt must equal the last recorded attempt');
  }
  return {
    attempts: [...attempts],
    correlation: value.correlation,
    finalAttempt: value.finalAttempt,
    id: value.runId,
  };
}

function requireNormalizedRun(value) {
  requireExactKeys(value, ['attempts', 'correlation', 'finalAttempt', 'id'], 'run');
  return requireRunMetadata({
    attempts: value.attempts,
    commit: '0'.repeat(40),
    correlation: value.correlation,
    finalAttempt: value.finalAttempt,
    runId: value.id,
  }, '0'.repeat(40));
}

function expectedTarballUrl(name) {
  return `${NPM_REGISTRY}${name}/-/${name}-${RELEASE_VERSION}.tgz`;
}

function expectedAttestationsUrl(name) {
  return `${NPM_REGISTRY}-/npm/v1/attestations/${name}@${RELEASE_VERSION}`;
}

function requireAttestations(value, name, label) {
  requireExactKeys(value, ['provenance', 'url'], label);
  requireExactKeys(value.provenance, ['predicateType'], `${label}.provenance`);
  if (value.provenance.predicateType !== PROVENANCE_PREDICATE) {
    fail(`${label} provenance predicate type is not supported`);
  }
  if (value.url !== expectedAttestationsUrl(name)) fail(`${label} URL does not match the exact package`);
  return value;
}

function requireRegistryKey(value, label) {
  requireExactKeys(value, ['keyid', 'publicKeyPem'], label);
  requireString(value.keyid, `${label}.keyid`);
  if (!/^SHA256:[A-Za-z0-9+/]{43}$/u.test(value.keyid)) {
    fail(`${label} key ID must match the npm registry key format`);
  }
  decodeBase64(`${value.keyid.slice('SHA256:'.length)}=`, `${label}.keyid digest`, 32);
  const key = parsePublicKey(value.publicKeyPem, `${label}.publicKeyPem`);
  return { key, normalized: clone(value) };
}

function selectRegistryKey(values, keyid, name, label) {
  const keys = requireArray(values, `${name} registry keys`);
  if (keys.length === 0 || keys.length > 8) fail(`${name} registry keys are empty or unbounded`);
  keys.forEach((key, index) => requireRegistryKey(key, `${name} registry key ${index}`));
  const matches = keys.filter((key) => key.keyid === keyid);
  if (matches.length !== 1) fail(`${name} must have exactly one ${label} key`);
  return matches[0];
}

function requireExactlyBoundRegistryKeys(values, keyids, name) {
  const keys = requireArray(values, `${name} registry keys`);
  keys.forEach((key, index) => requireRegistryKey(key, `${name} registry key ${index}`));
  const actual = keys.map(({ keyid }) => keyid).sort();
  const expected = [...new Set(keyids)].sort();
  if (canonicalizeJson(actual) !== canonicalizeJson(expected)) {
    fail(`${name} registry keys must be exactly bound to the registry and publish signatures`);
  }
}

function verifyRegistrySignature({ name, integrity, registrySignature }) {
  requireExactKeys(registrySignature, ['key', 'signature'], `${name} registry signature evidence`);
  const { key, normalized } = requireRegistryKey(registrySignature.key, `${name} registry signature key`);
  requireExactKeys(registrySignature.signature, ['keyid', 'sig'], `${name} registry signature`);
  if (registrySignature.signature.keyid !== normalized.keyid) {
    fail(`${name} registry signature key ID does not match`);
  }
  const signature = decodeBase64(registrySignature.signature.sig, `${name} registry signature bytes`);
  const message = Buffer.from(`${name}@${RELEASE_VERSION}:${integrity}`, 'utf8');
  requireValidSignature(key, message, signature, `${name} registry signature`);
}

function normalizeRegistrySignature(evidence, name, integrity) {
  requireExactKeys(evidence, [
    'dist', 'registryKeys', 'sigstoreTrust', 'workflowTarball',
  ], `${name} registry evidence`);
  requireExactKeys(evidence.dist, ['attestations', 'integrity', 'signatures', 'tarball'], `${name} registry dist`);
  const signatures = requireArray(evidence.dist.signatures, `${name} registry signatures`);
  if (signatures.length !== 1) fail(`${name} must have exactly one registry signature`);
  requireExactKeys(signatures[0], ['keyid', 'sig'], `${name} registry signature`);
  const key = selectRegistryKey(
    evidence.registryKeys,
    signatures[0].keyid,
    name,
    'registry signature',
  );
  const result = {
    key: clone(key),
    signature: clone(signatures[0]),
  };
  verifyRegistrySignature({ name, integrity, registrySignature: result });
  return result;
}

function dssePreAuthenticationEncoding(payloadType, payload) {
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `, 'utf8'),
    payload,
  ]);
}

function readDerElement(bytes, offset, limit, label) {
  if (!Buffer.isBuffer(bytes) || !Number.isSafeInteger(offset) || offset < 0 || offset >= limit) {
    fail(`${label} is truncated DER`);
  }
  const start = offset;
  const tag = bytes[offset];
  offset += 1;
  if ((tag & 0x1f) === 0x1f) fail(`${label} uses an unsupported DER high-tag form`);
  if (offset >= limit) fail(`${label} is truncated DER`);
  const firstLength = bytes[offset];
  offset += 1;
  let length;
  if ((firstLength & 0x80) === 0) {
    length = firstLength;
  } else {
    const lengthBytes = firstLength & 0x7f;
    if (lengthBytes === 0) fail(`${label} uses indefinite-length DER`);
    if (lengthBytes > 4 || offset + lengthBytes > limit) {
      fail(`${label} has an invalid DER length`);
    }
    if (bytes[offset] === 0) fail(`${label} has a non-canonical DER length`);
    length = 0;
    for (let index = 0; index < lengthBytes; index += 1) {
      length = (length * 256) + bytes[offset + index];
    }
    if (length < 0x80) fail(`${label} has a non-canonical DER length`);
    offset += lengthBytes;
  }
  if (!Number.isSafeInteger(length) || length < 0 || length > limit - offset) {
    fail(`${label} is truncated DER`);
  }
  return {
    contentStart: offset,
    end: offset + length,
    start,
    tag,
    value: bytes.subarray(offset, offset + length),
  };
}

function readSingleDer(bytes, tag, label) {
  const element = readDerElement(bytes, 0, bytes.length, label);
  if (element.tag !== tag || element.end !== bytes.length) {
    fail(`${label} has invalid DER structure`);
  }
  return element;
}

function derChildren(bytes, element, label) {
  const children = [];
  let offset = element.contentStart;
  while (offset < element.end) {
    const child = readDerElement(bytes, offset, element.end, label);
    children.push(child);
    offset = child.end;
  }
  if (offset !== element.end) fail(`${label} has invalid DER children`);
  return children;
}

function decodeDerOid(element, label) {
  if (element.tag !== 0x06 || element.value.length === 0) {
    fail(`${label} is not a DER object identifier`);
  }
  const subidentifiers = [];
  let current = 0n;
  let componentBytes = 0;
  for (const byte of element.value) {
    if (componentBytes === 0 && byte === 0x80) {
      fail(`${label} is a non-canonical DER object identifier`);
    }
    current = (current << 7n) | BigInt(byte & 0x7f);
    componentBytes += 1;
    if ((byte & 0x80) === 0) {
      subidentifiers.push(current);
      current = 0n;
      componentBytes = 0;
    }
  }
  if (componentBytes !== 0 || subidentifiers.length === 0) {
    fail(`${label} is a truncated DER object identifier`);
  }
  const first = subidentifiers.shift();
  let firstArc;
  let secondArc;
  if (first < 40n) {
    firstArc = 0n;
    secondArc = first;
  } else if (first < 80n) {
    firstArc = 1n;
    secondArc = first - 40n;
  } else {
    firstArc = 2n;
    secondArc = first - 80n;
  }
  return [firstArc, secondArc, ...subidentifiers].join('.');
}

function parseCertificateExtensions(certificate) {
  const bytes = certificate.raw;
  const outer = readSingleDer(bytes, 0x30, 'signing certificate');
  const certificateChildren = derChildren(bytes, outer, 'signing certificate');
  if (certificateChildren.length !== 3 || certificateChildren[0].tag !== 0x30) {
    fail('signing certificate has invalid DER structure');
  }
  const tbsChildren = derChildren(bytes, certificateChildren[0], 'signing certificate TBS');
  const wrappers = tbsChildren.filter(({ tag }) => tag === 0xa3);
  if (wrappers.length !== 1) fail('signing certificate extensions are missing or duplicated');
  const wrapperChildren = derChildren(bytes, wrappers[0], 'signing certificate extensions');
  if (wrapperChildren.length !== 1 || wrapperChildren[0].tag !== 0x30) {
    fail('signing certificate extensions have invalid DER structure');
  }
  const extensions = new Map();
  for (const [index, extension] of derChildren(
    bytes,
    wrapperChildren[0],
    'signing certificate extensions',
  ).entries()) {
    if (extension.tag !== 0x30) {
      fail(`signing certificate extension ${index} has invalid DER structure`);
    }
    const fields = derChildren(bytes, extension, `signing certificate extension ${index}`);
    if (fields.length !== 2 && fields.length !== 3) {
      fail(`signing certificate extension ${index} has invalid DER structure`);
    }
    const oid = decodeDerOid(fields[0], `signing certificate extension ${index} OID`);
    let critical = false;
    let valueField = fields[1];
    if (fields.length === 3) {
      if (fields[1].tag !== 0x01 || fields[1].value.length !== 1
          || fields[1].value[0] !== 0xff) {
        fail(`signing certificate extension ${oid} has invalid DER criticality`);
      }
      critical = true;
      valueField = fields[2];
    }
    if (valueField.tag !== 0x04) {
      fail(`signing certificate extension ${oid} value is not a DER octet string`);
    }
    if (extensions.has(oid)) fail(`signing certificate has duplicate extension ${oid}`);
    extensions.set(oid, { critical, value: valueField.value });
  }
  return extensions;
}

function requireCertificateExtension(extensions, oid, label, { optional = false } = {}) {
  const extension = extensions.get(oid);
  if (!extension && !optional) fail(`${label} is missing`);
  return extension ?? null;
}

function requireCriticality(extension, critical, label) {
  if (extension.critical !== critical) {
    fail(`${label} must ${critical ? 'be' : 'not be'} critical`);
  }
}

function decodeStrictUtf8(bytes, label) {
  let value;
  try {
    value = STRICT_UTF8_DECODER.decode(bytes);
  } catch {
    fail(`${label} is not valid UTF-8`);
  }
  assertUnicodeScalarString(value, label);
  if (!Buffer.from(value, 'utf8').equals(bytes)) fail(`${label} is not canonical UTF-8`);
  return value;
}

function decodeDerUtf8String(bytes, label) {
  const string = readSingleDer(bytes, 0x0c, label);
  return decodeStrictUtf8(string.value, label);
}

function verifyFulcioCertificateIdentity(certificate, expected) {
  const extensions = parseCertificateExtensions(certificate);

  const keyUsage = requireCertificateExtension(
    extensions,
    CERTIFICATE_OIDS.keyUsage,
    'signing certificate key usage',
  );
  requireCriticality(keyUsage, true, 'signing certificate key usage');
  if (!keyUsage.value.equals(Buffer.from([0x03, 0x02, 0x07, 0x80]))) {
    fail('signing certificate key usage must contain only digital signature');
  }

  const extendedKeyUsage = requireCertificateExtension(
    extensions,
    CERTIFICATE_OIDS.extendedKeyUsage,
    'signing certificate extended key usage',
  );
  const ekuSequence = readSingleDer(
    extendedKeyUsage.value,
    0x30,
    'signing certificate extended key usage',
  );
  const ekuOids = derChildren(
    extendedKeyUsage.value,
    ekuSequence,
    'signing certificate extended key usage',
  ).map((oid, index) => decodeDerOid(
    oid,
    `signing certificate extended key usage OID ${index}`,
  ));
  if (ekuOids.length !== 1 || ekuOids[0] !== CERTIFICATE_OIDS.codeSigning) {
    fail('signing certificate extended key usage must contain only code signing');
  }

  const workflowSan = requireCertificateExtension(
    extensions,
    CERTIFICATE_OIDS.subjectAlternativeName,
    'signing certificate workflow SAN',
  );
  requireCriticality(workflowSan, true, 'signing certificate workflow SAN');
  const sanSequence = readSingleDer(
    workflowSan.value,
    0x30,
    'signing certificate workflow SAN',
  );
  const names = derChildren(workflowSan.value, sanSequence, 'signing certificate workflow SAN');
  if (names.length !== 1 || names[0].tag !== 0x86
      || names[0].value.some((byte) => byte > 0x7f)) {
    fail('signing certificate workflow SAN must contain exactly one URI');
  }
  if (names[0].value.toString('ascii') !== expected.workflow.identity) {
    fail('signing certificate workflow SAN is wrong');
  }

  const issuer = requireCertificateExtension(
    extensions,
    CERTIFICATE_OIDS.issuer,
    'signing certificate OIDC issuer',
  );
  requireCriticality(issuer, false, 'signing certificate OIDC issuer');
  if (decodeStrictUtf8(issuer.value, 'signing certificate OIDC issuer')
      !== EXPECTED_OIDC_ISSUER) {
    fail('signing certificate OIDC issuer is wrong');
  }

  const issuerV2 = requireCertificateExtension(
    extensions,
    CERTIFICATE_OIDS.issuerV2,
    'signing certificate OIDC issuer V2',
  );
  requireCriticality(issuerV2, false, 'signing certificate OIDC issuer V2');
  if (decodeDerUtf8String(issuerV2.value, 'signing certificate OIDC issuer V2 DER')
      !== EXPECTED_OIDC_ISSUER) {
    fail('signing certificate OIDC issuer V2 is wrong');
  }

  for (const [oid, label, exact] of [
    [
      CERTIFICATE_OIDS.sourceRepositoryIdentifier,
      'signing certificate repository ID',
      expected.repositoryId,
    ],
    [
      CERTIFICATE_OIDS.sourceRepositoryOwnerIdentifier,
      'signing certificate repository owner ID',
      expected.repositoryOwnerId,
    ],
  ]) {
    const extension = requireCertificateExtension(extensions, oid, label);
    requireCriticality(extension, false, label);
    if (decodeDerUtf8String(extension.value, `${label} DER`) !== exact) {
      fail(`${label} is wrong`);
    }
  }

  if (certificate.subjectAltName !== `URI:${expected.workflow.identity}`) {
    fail('signing certificate identity is wrong');
  }
}

function requireCertificate(rawBytes, label) {
  const bytes = decodeBase64(rawBytes, label);
  let certificate;
  try {
    certificate = new X509Certificate(bytes);
  } catch {
    fail(`${label} is not an X.509 certificate`);
  }
  if (!certificate.raw.equals(bytes)) fail(`${label} must contain canonical DER`);
  return certificate;
}

function requireCertificateChain(value, label) {
  requireExactKeys(value, ['certificates'], label);
  const rows = requireArray(value.certificates, `${label}.certificates`);
  if (rows.length === 0 || rows.length > 8) fail(`${label} must contain a bounded authority chain`);
  return rows.map((row, index) => {
    requireExactKeys(row, ['rawBytes'], `${label}.certificates[${index}]`);
    return requireCertificate(row.rawBytes, `${label}.certificates[${index}].rawBytes`);
  });
}

function verifyCertificateChain(leaf, authorities, integratedTime) {
  if (leaf.ca) fail('certificate chain leaf must not be a CA');
  const instant = integratedTime * 1000;
  if (!(instant >= Date.parse(leaf.validFrom) && instant <= Date.parse(leaf.validTo))) {
    fail('certificate chain leaf is not valid at the signed log time');
  }
  let issued = leaf;
  for (const authority of authorities) {
    if (!authority.ca) fail('certificate chain authority is not a CA');
    if (issued.issuer !== authority.subject || !issued.checkIssued(authority)) {
      fail('certificate chain issuer binding is invalid');
    }
    if (!issued.verify(authority.publicKey)) fail('certificate chain signature is invalid');
    if (!(instant >= Date.parse(authority.validFrom) && instant <= Date.parse(authority.validTo))) {
      fail('certificate chain authority is not valid at the signed log time');
    }
    issued = authority;
  }
  const root = authorities.at(-1);
  if (root.issuer !== root.subject || !root.verify(root.publicKey)) {
    fail('certificate chain root is not self-signed');
  }
}

function verifyStatement(value, expected) {
  requireExactKeys(value, ['_type', 'predicate', 'predicateType', 'subject'], `${expected.name} statement`);
  if (value._type !== STATEMENT_TYPE) fail(`${expected.name} statement type is not supported`);
  if (value.predicateType !== PROVENANCE_PREDICATE) fail(`${expected.name} provenance predicate type is not supported`);
  const subjects = requireArray(value.subject, `${expected.name} statement subjects`);
  if (subjects.length !== 1) fail(`${expected.name} must have exactly one provenance subject`);
  requireExactKeys(subjects[0], ['digest', 'name'], `${expected.name} provenance subject`);
  requireExactKeys(subjects[0].digest, ['sha512'], `${expected.name} provenance subject digest`);
  const expectedSubject = `pkg:npm/${expected.name}@${RELEASE_VERSION}`;
  if (subjects[0].name !== expectedSubject) fail(`${expected.name} provenance subject name is wrong`);
  requireLowerHex(subjects[0].digest.sha512, 64, `${expected.name} provenance subject digest`);
  if (subjects[0].digest.sha512 !== expected.sha512) fail(`${expected.name} provenance subject digest is wrong`);

  requireExactKeys(value.predicate, ['buildDefinition', 'runDetails'], `${expected.name} provenance predicate`);
  const definition = value.predicate.buildDefinition;
  requireExactKeys(definition, [
    'buildType', 'externalParameters', 'internalParameters', 'resolvedDependencies',
  ], `${expected.name} build definition`);
  if (definition.buildType !== BUILD_TYPE) fail(`${expected.name} build type is not supported`);
  requireExactKeys(definition.externalParameters, ['workflow'], `${expected.name} external parameters`);
  const workflow = definition.externalParameters.workflow;
  requireExactKeys(workflow, ['path', 'ref', 'repository'], `${expected.name} workflow parameters`);
  if (workflow.repository !== expected.repository) fail(`${expected.name} source repository is wrong`);
  if (workflow.ref !== expected.workflow.ref) fail(`${expected.name} source ref is wrong`);
  if (workflow.path !== expected.workflow.path) fail(`${expected.name} workflow path is wrong`);

  requireExactKeys(definition.internalParameters, ['github'], `${expected.name} internal parameters`);
  requireExactKeys(definition.internalParameters.github, [
    'event_name', 'repository_id', 'repository_owner_id',
  ], `${expected.name} GitHub parameters`);
  const github = definition.internalParameters.github;
  if (github.event_name !== 'workflow_dispatch') fail(`${expected.name} workflow event is wrong`);
  if (github.repository_id !== expected.repositoryId) {
    fail(`${expected.name} GitHub repository ID is wrong`);
  }
  if (github.repository_owner_id !== expected.repositoryOwnerId) {
    fail(`${expected.name} GitHub repository owner ID is wrong`);
  }

  const dependencies = requireArray(definition.resolvedDependencies, `${expected.name} resolved dependencies`);
  if (dependencies.length !== 1) fail(`${expected.name} must have exactly one resolved source dependency`);
  requireExactKeys(dependencies[0], ['digest', 'uri'], `${expected.name} resolved source dependency`);
  requireExactKeys(dependencies[0].digest, ['gitCommit'], `${expected.name} resolved source digest`);
  if (dependencies[0].uri !== `git+${expected.repository}@${expected.workflow.ref}`) {
    fail(`${expected.name} resolved source ref is wrong`);
  }
  if (dependencies[0].digest.gitCommit !== expected.commit) fail(`${expected.name} source commit is wrong`);

  requireExactKeys(value.predicate.runDetails, ['builder', 'metadata'], `${expected.name} run details`);
  requireExactKeys(value.predicate.runDetails.builder, ['id'], `${expected.name} builder`);
  if (value.predicate.runDetails.builder.id !== BUILDER_ID) fail(`${expected.name} builder identity is wrong`);
  requireExactKeys(value.predicate.runDetails.metadata, ['invocationId'], `${expected.name} run metadata`);
  const prefix = `${expected.repository}/actions/runs/`;
  const invocation = requireString(value.predicate.runDetails.metadata.invocationId,
    `${expected.name} invocation ID`);
  if (!invocation.startsWith(prefix)) fail(`${expected.name} run ID is wrong`);
  const suffix = invocation.slice(prefix.length);
  const match = /^([1-9][0-9]{0,19})\/attempts\/([1-9][0-9]{0,8})$/u.exec(suffix);
  if (!match || match[1] !== expected.run.id) fail(`${expected.name} run ID is wrong`);
  const attempt = Number(match[2]);
  if (!Number.isSafeInteger(attempt) || !expected.run.attempts.includes(attempt)) {
    fail(`${expected.name} run attempt is not recorded in the bounded recovery chain`);
  }
  return {
    attempt,
    subject: clone(subjects[0]),
  };
}

function verifyPublishStatement(value, expected) {
  requireExactKeys(value, ['_type', 'predicate', 'predicateType', 'subject'],
    `${expected.name} publish statement`);
  if (value._type !== PUBLISH_STATEMENT_TYPE) {
    fail(`${expected.name} publish statement type is not supported`);
  }
  if (value.predicateType !== PUBLISH_PREDICATE) {
    fail(`${expected.name} publish predicate type is not supported`);
  }
  const subjects = requireArray(value.subject, `${expected.name} publish statement subjects`);
  if (subjects.length !== 1) fail(`${expected.name} must have exactly one publish subject`);
  requireExactKeys(subjects[0], ['digest', 'name'], `${expected.name} publish subject`);
  requireExactKeys(subjects[0].digest, ['sha512'], `${expected.name} publish subject digest`);
  if (subjects[0].name !== `pkg:npm/${expected.name}@${RELEASE_VERSION}`) {
    fail(`${expected.name} publish subject name is wrong`);
  }
  requireLowerHex(subjects[0].digest.sha512, 64, `${expected.name} publish subject digest`);
  if (subjects[0].digest.sha512 !== expected.sha512) {
    fail(`${expected.name} publish subject digest is wrong`);
  }
  requireExactKeys(value.predicate, ['name', 'registry', 'version'],
    `${expected.name} publish predicate`);
  if (value.predicate.name !== expected.name) fail(`${expected.name} publish package name is wrong`);
  if (value.predicate.version !== RELEASE_VERSION) {
    fail(`${expected.name} publish package version is wrong`);
  }
  if (value.predicate.registry !== 'https://registry.npmjs.org') {
    fail(`${expected.name} publish registry is wrong`);
  }
  return clone(subjects[0]);
}

function verifyTlogBody(entry, envelope, leaf) {
  const bodyBytes = decodeBase64(entry.canonicalizedBody, 'transparency log body');
  let body;
  try {
    body = parseJsonTextStrict(bodyBytes.toString('utf8'), 'transparency log body');
  } catch (error) {
    if (error instanceof Error && /PROVENANCE_EVIDENCE/u.test(error.message)) throw error;
    fail('transparency log body is not valid JSON');
  }
  if (canonicalizeJson(body) !== bodyBytes.toString('utf8')) fail('transparency log body is not JCS');
  requireExactKeys(body, ['apiVersion', 'kind', 'spec'], 'transparency log body');
  if (body.apiVersion !== '0.0.1' || body.kind !== 'dsse') fail('transparency log body kind/version is wrong');
  requireExactKeys(body.spec, [
    'envelopeHash', 'payloadHash', 'signatures',
  ], 'transparency log body spec');
  requireExactKeys(body.spec.envelopeHash, ['algorithm', 'value'],
    'transparency log envelope hash');
  if (body.spec.envelopeHash.algorithm !== 'sha256') {
    fail('transparency log envelope hash algorithm is wrong');
  }
  const serializedEnvelope = JSON.stringify({
    payload: envelope.payload,
    payloadType: envelope.payloadType,
    signatures: [{ sig: envelope.signatures[0].sig }],
  });
  if (body.spec.envelopeHash.value !== sha256(Buffer.from(serializedEnvelope, 'utf8')).toString('hex')) {
    fail('transparency log envelope hash is wrong');
  }
  requireExactKeys(body.spec.payloadHash, ['algorithm', 'value'], 'transparency log payload hash');
  if (body.spec.payloadHash.algorithm !== 'sha256') fail('transparency log body hash algorithm is wrong');
  const payload = decodeBase64(envelope.payload, 'DSSE payload');
  if (body.spec.payloadHash.value !== sha256(payload).toString('hex')) {
    fail('transparency log body payload hash is wrong');
  }
  const signatures = requireArray(body.spec.signatures, 'transparency log body signatures');
  if (signatures.length !== 1) fail('transparency log body must have exactly one signature');
  requireExactKeys(signatures[0], ['signature', 'verifier'], 'transparency log body signature');
  if (signatures[0].signature !== envelope.signatures[0].sig) {
    fail('transparency log body signature does not match DSSE signature');
  }
  const verifierBytes = decodeBase64(signatures[0].verifier, 'transparency log body verifier');
  let verifier;
  try {
    verifier = new X509Certificate(verifierBytes);
  } catch {
    fail('transparency log body verifier is not a certificate');
  }
  if (!verifier.raw.equals(leaf.raw)) fail('transparency log body verifier does not match certificate');
  if (!verifierBytes.equals(Buffer.from(leaf.toString(), 'utf8'))) {
    fail('transparency log body verifier is not canonical certificate PEM');
  }
  return bodyBytes;
}

function verifyPublishTlogBody(entry, envelope, publicKeyPem) {
  const bodyBytes = decodeBase64(entry.canonicalizedBody, 'publish transparency log body');
  const body = parseJsonTextStrict(bodyBytes.toString('utf8'), 'publish transparency log body');
  if (canonicalizeJson(body) !== bodyBytes.toString('utf8')) {
    fail('publish transparency log body is not JCS');
  }
  requireExactKeys(body, ['apiVersion', 'kind', 'spec'], 'publish transparency log body');
  if (body.apiVersion !== '0.0.1' || body.kind !== 'dsse') {
    fail('publish transparency log body kind/version is wrong');
  }
  requireExactKeys(body.spec, ['envelopeHash', 'payloadHash', 'signatures'],
    'publish transparency log body spec');
  requireExactKeys(body.spec.envelopeHash, ['algorithm', 'value'],
    'publish transparency log envelope hash');
  if (body.spec.envelopeHash.algorithm !== 'sha256') {
    fail('publish transparency log envelope hash algorithm is wrong');
  }
  requireLowerHex(body.spec.envelopeHash.value, 32,
    'publish transparency log envelope hash');
  const rekorEnvelope = {
    payload: envelope.payload,
    payloadType: envelope.payloadType,
    signatures: [{
      sig: envelope.signatures[0].sig,
      keyid: envelope.signatures[0].keyid,
    }],
  };
  const envelopeHash = sha256(Buffer.from(JSON.stringify(rekorEnvelope), 'utf8')).toString('hex');
  if (body.spec.envelopeHash.value !== envelopeHash) {
    fail('publish transparency log envelope hash is wrong');
  }
  requireExactKeys(body.spec.payloadHash, ['algorithm', 'value'],
    'publish transparency log payload hash');
  if (body.spec.payloadHash.algorithm !== 'sha256') {
    fail('publish transparency log payload hash algorithm is wrong');
  }
  requireLowerHex(body.spec.payloadHash.value, 32, 'publish transparency log payload hash');
  const payload = decodeBase64(envelope.payload, 'publish DSSE payload');
  if (body.spec.payloadHash.value !== sha256(payload).toString('hex')) {
    fail('publish transparency log payload hash is wrong');
  }
  const signatures = requireArray(body.spec.signatures,
    'publish transparency log body signatures');
  if (signatures.length !== 1) {
    fail('publish transparency log body must have exactly one signature');
  }
  requireExactKeys(signatures[0], ['signature', 'verifier'],
    'publish transparency log body signature');
  if (signatures[0].signature !== envelope.signatures[0].sig) {
    fail('publish transparency log body signature does not match DSSE signature');
  }
  const verifierBytes = decodeBase64(signatures[0].verifier,
    'publish transparency log body verifier');
  if (!verifierBytes.equals(Buffer.from(publicKeyPem, 'utf8'))) {
    fail('publish transparency log body verifier does not match the public key');
  }
  return bodyBytes;
}

function verifyInclusionPromise(entry, logKey, bodyBytes) {
  requireExactKeys(entry.inclusionPromise, ['signedEntryTimestamp'], 'transparency inclusion promise');
  const signature = decodeBase64(entry.inclusionPromise.signedEntryTimestamp,
    'transparency inclusion promise signature');
  const payload = {
    body: bodyBytes.toString('base64'),
    integratedTime: Number(entry.integratedTime),
    logIndex: Number(entry.logIndex),
    logID: decodeBase64(entry.logId.keyId, 'transparency log ID', 32).toString('hex'),
  };
  requireValidSignature(logKey, Buffer.from(canonicalizeJson(payload), 'utf8'), signature,
    'transparency log inclusion promise');
}

function hashLeaf(value) {
  return sha256(Buffer.from([0]), value);
}

function hashChildren(left, right) {
  return sha256(Buffer.from([1]), left, right);
}

function bitLength(value) {
  return value === 0n ? 0 : value.toString(2).length;
}

function onesCount(value) {
  return [...value.toString(2)].filter((bit) => bit === '1').length;
}

function verifyMerkleProof(bodyBytes, proof) {
  const index = requireDecimal(proof.logIndex, 'transparency inclusion proof index');
  const size = requireDecimal(proof.treeSize, 'transparency inclusion proof tree size', { allowZero: false });
  if (index >= size) fail('transparency inclusion proof index is outside the tree');
  const inner = bitLength(index ^ (size - 1n));
  const border = onesCount(index >> BigInt(inner));
  const hashes = requireArray(proof.hashes, 'transparency inclusion proof hashes')
    .map((hash, offset) => decodeBase64(hash, `transparency inclusion proof hash ${offset}`, 32));
  if (hashes.length !== inner + border) fail('transparency inclusion proof hash count is wrong');
  let root = hashLeaf(bodyBytes);
  for (let level = 0; level < inner; level += 1) {
    root = ((index >> BigInt(level)) & 1n) === 1n
      ? hashChildren(hashes[level], root)
      : hashChildren(root, hashes[level]);
  }
  for (let level = inner; level < hashes.length; level += 1) root = hashChildren(hashes[level], root);
  const claimed = decodeBase64(proof.rootHash, 'transparency inclusion proof root', 32);
  if (!root.equals(claimed)) fail('transparency inclusion proof root is wrong');
  return { index, size, root };
}

function verifyCheckpoint(proof, logKey, transparencyLog, merkle) {
  requireExactKeys(proof.checkpoint, ['envelope'], 'transparency checkpoint');
  const envelope = requireString(proof.checkpoint.envelope, 'transparency checkpoint envelope');
  const separator = envelope.indexOf('\n\n');
  if (separator < 0 || envelope.indexOf('\n\n', separator + 2) >= 0) {
    fail('transparency checkpoint separator is wrong');
  }
  const note = envelope.slice(0, separator + 1);
  const signatureLine = envelope.slice(separator + 2);
  const match = /^— ([^\s]+) ([A-Za-z0-9+/]+={0,2})\n$/u.exec(signatureLine);
  if (!match) fail('transparency checkpoint signature line is malformed');
  const baseUrl = new URL(transparencyLog.baseUrl);
  if (baseUrl.protocol !== 'https:' || baseUrl.username || baseUrl.hash || baseUrl.search) {
    fail('transparency log base URL is not an exact HTTPS origin');
  }
  if (match[1] !== baseUrl.hostname) fail('transparency checkpoint signer is wrong');
  const signed = decodeBase64(match[2], 'transparency checkpoint signature');
  if (signed.length <= 4) fail('transparency checkpoint signature is too short');
  const logId = decodeBase64(transparencyLog.logId, 'transparency log ID', 32);
  if (!signed.subarray(0, 4).equals(logId.subarray(0, 4))) {
    fail('transparency checkpoint key hint is wrong');
  }
  requireValidSignature(logKey, Buffer.from(note, 'utf8'), signed.subarray(4),
    'transparency checkpoint signature');
  const lines = note.trimEnd().split('\n');
  if (lines.length < 3 || !lines[0].startsWith(baseUrl.hostname)) {
    fail('transparency checkpoint origin is wrong');
  }
  if (requireDecimal(lines[1], 'transparency checkpoint tree size', { allowZero: false }) !== merkle.size) {
    fail('transparency checkpoint tree size is wrong');
  }
  const root = decodeBase64(lines[2], 'transparency checkpoint root', 32);
  if (!root.equals(merkle.root)) fail('transparency checkpoint root is wrong');
}

function verifyTransparency(entry, envelope, leaf, trust) {
  requireExactKeys(entry, [
    'canonicalizedBody', 'inclusionPromise', 'inclusionProof', 'integratedTime',
    'kindVersion', 'logId', 'logIndex',
  ], 'transparency log entry');
  requireExactKeys(entry.logId, ['keyId'], 'transparency log entry ID');
  requireExactKeys(entry.kindVersion, ['kind', 'version'], 'transparency log kind/version');
  if (entry.kindVersion.kind !== 'dsse' || entry.kindVersion.version !== '0.0.1') {
    fail('transparency log kind/version is wrong');
  }
  const integrated = requireDecimal(entry.integratedTime, 'transparency integrated time', { allowZero: false });
  const logIndex = requireDecimal(entry.logIndex, 'transparency log index');
  if (integrated > BigInt(Number.MAX_SAFE_INTEGER) || logIndex > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail('transparency log integer is not safely representable');
  }
  requireExactKeys(trust, ['certificateChain', 'transparencyLog'], 'Sigstore trust material');
  requireExactKeys(trust.transparencyLog, ['baseUrl', 'logId', 'publicKeyPem'], 'transparency log trust material');
  const logKey = parsePublicKey(trust.transparencyLog.publicKeyPem, 'transparency log public key');
  const trustLogId = decodeBase64(trust.transparencyLog.logId, 'transparency trust log ID', 32);
  const entryLogId = decodeBase64(entry.logId.keyId, 'transparency entry log ID', 32);
  if (!entryLogId.equals(trustLogId)) fail('transparency entry log ID does not match trusted log ID');
  const bodyBytes = verifyTlogBody(entry, envelope, leaf);
  verifyInclusionPromise(entry, logKey, bodyBytes);
  requireExactKeys(entry.inclusionProof, [
    'checkpoint', 'hashes', 'logIndex', 'rootHash', 'treeSize',
  ], 'transparency inclusion proof');
  const merkle = verifyMerkleProof(bodyBytes, entry.inclusionProof);
  verifyCheckpoint(entry.inclusionProof, logKey, trust.transparencyLog, merkle);
  return Number(integrated);
}

function verifyPublishTransparency(entry, envelope, publicKeyPem, trust) {
  requireExactKeys(entry, [
    'canonicalizedBody', 'inclusionPromise', 'inclusionProof', 'integratedTime',
    'kindVersion', 'logId', 'logIndex',
  ], 'publish transparency log entry');
  requireExactKeys(entry.logId, ['keyId'], 'publish transparency log entry ID');
  requireExactKeys(entry.kindVersion, ['kind', 'version'],
    'publish transparency log kind/version');
  if (entry.kindVersion.kind !== 'dsse' || entry.kindVersion.version !== '0.0.1') {
    fail('publish transparency log kind/version is wrong');
  }
  const integrated = requireDecimal(entry.integratedTime,
    'publish transparency integrated time', { allowZero: false });
  const logIndex = requireDecimal(entry.logIndex, 'publish transparency log index');
  if (integrated > BigInt(Number.MAX_SAFE_INTEGER) || logIndex > BigInt(Number.MAX_SAFE_INTEGER)) {
    fail('publish transparency log integer is not safely representable');
  }
  requireExactKeys(trust, ['certificateChain', 'transparencyLog'], 'Sigstore trust material');
  requireExactKeys(trust.transparencyLog, ['baseUrl', 'logId', 'publicKeyPem'],
    'publish transparency log trust material');
  const logKey = parsePublicKey(trust.transparencyLog.publicKeyPem,
    'publish transparency log public key');
  const trustLogId = decodeBase64(trust.transparencyLog.logId,
    'publish transparency trust log ID', 32);
  const entryLogId = decodeBase64(entry.logId.keyId,
    'publish transparency entry log ID', 32);
  if (!entryLogId.equals(trustLogId)) {
    fail('publish transparency entry log ID does not match trusted log ID');
  }
  const bodyBytes = verifyPublishTlogBody(entry, envelope, publicKeyPem);
  verifyInclusionPromise(entry, logKey, bodyBytes);
  requireExactKeys(entry.inclusionProof, [
    'checkpoint', 'hashes', 'logIndex', 'rootHash', 'treeSize',
  ], 'publish transparency inclusion proof');
  const merkle = verifyMerkleProof(bodyBytes, entry.inclusionProof);
  verifyCheckpoint(entry.inclusionProof, logKey, trust.transparencyLog, merkle);
  return Number(integrated);
}

function verifyBundle(value, trust, expected) {
  requireExactKeys(value, ['dsseEnvelope', 'mediaType', 'verificationMaterial'], `${expected.name} Sigstore bundle`);
  if (value.mediaType !== BUNDLE_MEDIA_TYPE) fail(`${expected.name} Sigstore bundle media type is wrong`);
  const envelope = value.dsseEnvelope;
  requireExactKeys(envelope, ['payload', 'payloadType', 'signatures'], `${expected.name} DSSE envelope`);
  if (envelope.payloadType !== PAYLOAD_TYPE) fail(`${expected.name} DSSE payload type is wrong`);
  const signatures = requireArray(envelope.signatures, `${expected.name} DSSE signatures`);
  if (signatures.length !== 1) fail(`${expected.name} must have exactly one DSSE signature`);
  const signatureKeys = Object.keys(requireRecord(
    signatures[0], `${expected.name} DSSE signature`,
  )).sort();
  if (signatureKeys.join('\0') === ['keyid', 'sig'].join('\0')) {
    if (signatures[0].keyid !== '') {
      fail(`${expected.name} DSSE signature key hint must be empty`);
    }
  } else {
    requireExactKeys(signatures[0], ['sig'], `${expected.name} DSSE signature`);
  }
  const payload = decodeBase64(envelope.payload, `${expected.name} DSSE payload`);
  const signature = decodeBase64(signatures[0].sig, `${expected.name} DSSE signature bytes`);

  const material = value.verificationMaterial;
  requireExactKeys(material, [
    'certificate', 'timestampVerificationData', 'tlogEntries',
  ], `${expected.name} verification material`);
  const timestampVerificationData = requireRecord(
    material.timestampVerificationData, `${expected.name} timestamp verification data`,
  );
  if (Object.keys(timestampVerificationData).length !== 0) {
    requireExactKeys(timestampVerificationData, ['rfc3161Timestamps'],
      `${expected.name} timestamp verification data`);
    const timestamps = requireArray(timestampVerificationData.rfc3161Timestamps,
      `${expected.name} RFC 3161 timestamps`);
    if (timestamps.length !== 0) {
      fail(`${expected.name} RFC 3161 timestamps must be empty`);
    }
  }
  requireExactKeys(material.certificate, ['rawBytes'], `${expected.name} signing certificate`);
  const leaf = requireCertificate(material.certificate.rawBytes, `${expected.name} signing certificate`);
  requireExactKeys(trust, ['certificateChain', 'transparencyLog'], 'Sigstore trust material');
  const authorities = requireCertificateChain(trust.certificateChain,
    `${expected.name} certificate chain`);
  const entries = requireArray(material.tlogEntries, `${expected.name} transparency log entries`);
  if (entries.length !== 1) fail(`${expected.name} must have exactly one transparency log entry`);
  const integratedTime = verifyTransparency(entries[0], envelope, leaf, trust);
  verifyFulcioCertificateIdentity(leaf, expected);
  verifyCertificateChain(leaf, authorities, integratedTime);
  requireValidSignature(leaf.publicKey, dssePreAuthenticationEncoding(PAYLOAD_TYPE, payload),
    signature, `${expected.name} DSSE signature`);
  const statement = parseJsonTextStrict(payload.toString('utf8'), `${expected.name} DSSE statement`);
  const binding = verifyStatement(statement, expected);
  return { binding, statement };
}

function verifyPublishBundle(value, trust, registryKey, expected, trustPolicy) {
  requireExactKeys(value, ['dsseEnvelope', 'mediaType', 'verificationMaterial'],
    `${expected.name} publish Sigstore bundle`);
  if (value.mediaType !== PUBLISH_BUNDLE_MEDIA_TYPE) {
    fail(`${expected.name} publish Sigstore bundle media type is wrong`);
  }
  const envelope = value.dsseEnvelope;
  requireExactKeys(envelope, ['payload', 'payloadType', 'signatures'],
    `${expected.name} publish DSSE envelope`);
  if (envelope.payloadType !== PAYLOAD_TYPE) {
    fail(`${expected.name} publish DSSE payload type is wrong`);
  }
  const signatures = requireArray(envelope.signatures, `${expected.name} publish DSSE signatures`);
  if (signatures.length !== 1) {
    fail(`${expected.name} publish attestation must have exactly one DSSE signature`);
  }
  requireExactKeys(signatures[0], ['keyid', 'sig'], `${expected.name} publish DSSE signature`);
  const { key, normalized } = requireRegistryKey(registryKey,
    `${expected.name} publish attestation key`);
  requireP256PublicKey(key, `${expected.name} publish attestation key`);
  if (signatures[0].keyid !== normalized.keyid) {
    fail(`${expected.name} publish DSSE key ID does not match the registry key`);
  }
  const payload = decodeBase64(envelope.payload, `${expected.name} publish DSSE payload`);
  const signature = decodeBase64(signatures[0].sig,
    `${expected.name} publish DSSE signature bytes`);
  const material = value.verificationMaterial;
  requireExactKeys(material, ['publicKey', 'timestampVerificationData', 'tlogEntries'],
    `${expected.name} publish verification material`);
  requireExactKeys(material.publicKey, ['hint'], `${expected.name} publish public-key material`);
  if (material.publicKey.hint !== normalized.keyid) {
    fail(`${expected.name} publish public-key hint does not match the registry key`);
  }
  requireExactKeys(material.timestampVerificationData, ['rfc3161Timestamps'],
    `${expected.name} publish timestamp verification data`);
  const timestamps = requireArray(material.timestampVerificationData.rfc3161Timestamps,
    `${expected.name} publish RFC 3161 timestamps`);
  if (timestamps.length !== 0) {
    fail(`${expected.name} publish RFC 3161 timestamps must be empty`);
  }
  const entries = requireArray(material.tlogEntries,
    `${expected.name} publish transparency log entries`);
  if (entries.length !== 1) {
    fail(`${expected.name} publish attestation must have exactly one transparency log entry`);
  }
  verifyPublishTransparency(entries[0], envelope, normalized.publicKeyPem, trust);
  requireTrustedPublishMaterials({
    bundle: value,
    name: expected.name,
    registryKey: normalized,
    trust,
    trustPolicy,
  });
  requireValidSignature(key, dssePreAuthenticationEncoding(PAYLOAD_TYPE, payload), signature,
    `${expected.name} publish DSSE signature`);
  const statement = parseJsonTextStrict(payload.toString('utf8'),
    `${expected.name} publish DSSE statement`);
  const subject = verifyPublishStatement(statement, expected);
  return { statement, subject };
}

function requireNormalizedPackage(value, expected, trustPolicy) {
  requireExactKeys(value, [
    'attestations', 'integrity', 'name', 'provenance', 'registrySignature',
    'run', 'subject', 'tarball', 'version',
  ], `${expected.name} package evidence`);
  if (value.name !== expected.name || value.version !== RELEASE_VERSION) {
    fail(`${expected.name} package evidence has wrong exact package version`);
  }
  const integrity = parseIntegrity(value.integrity, `${expected.name} integrity`);
  requireExactKeys(value.tarball, ['sha512', 'url'], `${expected.name} tarball`);
  requireLowerHex(value.tarball.sha512, 64, `${expected.name} tarball SHA-512`);
  if (value.tarball.sha512 !== integrity.sha512) fail(`${expected.name} tarball SHA-512 does not match integrity`);
  if (value.tarball.url !== expectedTarballUrl(expected.name)) fail(`${expected.name} tarball URL is wrong`);
  requireAttestations(value.attestations, expected.name, `${expected.name} attestations`);
  verifyRegistrySignature({
    name: expected.name,
    integrity: value.integrity,
    registrySignature: value.registrySignature,
  });
  requireExactKeys(value.run, ['attempt', 'id'], `${expected.name} package run`);
  if (value.run.id !== expected.run.id) fail(`${expected.name} package run ID is wrong`);
  if (!Number.isSafeInteger(value.run.attempt) || !expected.run.attempts.includes(value.run.attempt)) {
    fail(`${expected.name} package run attempt is not recorded in the bounded recovery chain`);
  }
  requireExactKeys(value.subject, ['digest', 'name'], `${expected.name} subject`);
  requireExactKeys(value.subject.digest, ['sha512'], `${expected.name} subject digest`);
  if (value.subject.name !== `pkg:npm/${expected.name}@${RELEASE_VERSION}`) {
    fail(`${expected.name} provenance subject name is wrong`);
  }
  if (value.subject.digest.sha512 !== value.tarball.sha512) {
    fail(`${expected.name} provenance subject digest is wrong`);
  }
  requireExactKeys(value.provenance, ['bundle', 'predicateType', 'statement', 'trust'],
    `${expected.name} provenance`);
  if (value.provenance.predicateType !== PROVENANCE_PREDICATE) {
    fail(`${expected.name} provenance predicate type is wrong`);
  }
  requireTrustedPackageMaterials({
    bundle: value.provenance.bundle,
    name: expected.name,
    registryKey: value.registrySignature.key,
    trust: value.provenance.trust,
    trustPolicy,
  });
  const verified = verifyBundle(value.provenance.bundle, value.provenance.trust, {
    ...expected,
    sha512: value.tarball.sha512,
  });
  if (canonicalizeJson(verified.statement) !== canonicalizeJson(value.provenance.statement)) {
    fail(`${expected.name} embedded statement does not match DSSE payload`);
  }
  if (verified.binding.attempt !== value.run.attempt) {
    fail(`${expected.name} package run attempt does not match provenance`);
  }
  if (canonicalizeJson(verified.binding.subject) !== canonicalizeJson(value.subject)) {
    fail(`${expected.name} subject does not match provenance`);
  }
}

export function verifyProvenanceEvidence(value, trustPolicy = defaultTrustPolicy()) {
  validateProvenanceTrustPolicy(trustPolicy);
  requireExactKeys(value, [
    'commit', 'packages', 'repository', 'run', 'schemaVersion', 'sourceTag', 'workflow',
  ], 'provenance evidence');
  if (value.schemaVersion !== SCHEMA_VERSION) fail('provenance evidence schemaVersion is wrong');
  const release = requireExpectedRelease({
    repository: value.repository,
    workflow: value.workflow?.name,
    sourceTag: value.sourceTag,
    commit: value.commit,
  });
  requireExactKeys(value.workflow, ['identity', 'name', 'path', 'ref'], 'workflow');
  if (canonicalizeJson(value.workflow) !== canonicalizeJson(release.workflow)) {
    fail('workflow identity is not the frozen workflow');
  }
  const run = requireNormalizedRun(value.run);
  const packages = requireArray(value.packages, 'packages');
  if (packages.length !== PACKAGE_NAMES.length) fail('provenance evidence must have exactly two package records');
  if (packages.map((entry) => entry?.name).join('\n') !== PACKAGE_NAMES.join('\n')) {
    fail('package records must be unique and sorted by name');
  }
  packages.forEach((entry, index) => requireNormalizedPackage(entry, {
    ...release,
    name: PACKAGE_NAMES[index],
    run,
  }, trustPolicy));
  return clone(value);
}

function requireAuditRow(value, name) {
  requireExactKeys(value, [
    'attestationBundles', 'attestations', 'location', 'name', 'registry', 'version',
  ], `${name} verified row`);
  if (value.name !== name || value.version !== RELEASE_VERSION) {
    fail(`${name} verified row has wrong exact package version`);
  }
  if (value.location !== `node_modules/${name}`) fail(`${name} verified row location is wrong`);
  if (value.registry !== NPM_REGISTRY) fail(`${name} verified row registry is wrong`);
}

function selectAttestations(value, name) {
  const attestations = requireArray(value, `${name} attestation bundles`);
  attestations.forEach((entry, index) => {
    requireExactKeys(entry, ['bundle', 'predicateType'], `${name} attestation bundle ${index}`);
    requireRecord(entry.bundle, `${name} attestation bundle ${index}.bundle`);
  });
  const predicates = attestations.map(({ predicateType }) => predicateType).sort();
  const current = [PROVENANCE_PREDICATE, PUBLISH_PREDICATE].sort();
  if (canonicalizeJson(predicates) !== canonicalizeJson(current)) {
    fail(`${name} attestation bundle set must contain exactly one SLSA v1 and one npm publish v0.1 attestation`);
  }
  return {
    provenance: attestations.find(({ predicateType }) => predicateType === PROVENANCE_PREDICATE),
    publish: attestations.find(({ predicateType }) => predicateType === PUBLISH_PREDICATE),
  };
}

function requirePackageLock(value) {
  requireRecord(value, 'package lock');
  if (value.lockfileVersion !== 3) fail('package lock must use lockfileVersion 3');
  requireRecord(value.packages, 'package lock packages');
  const root = requireRecord(value.packages[''], 'package lock root');
  requireRecord(root.dependencies, 'package lock root dependencies');
  for (const name of PACKAGE_NAMES) {
    if (root.dependencies[name] !== RELEASE_VERSION) fail(`package lock root must depend on exact ${name}@${RELEASE_VERSION}`);
  }
  const ui = requireRecord(value.packages['node_modules/hd-wallet-ui'], 'UI package lock entry');
  requireRecord(ui.dependencies, 'UI package lock dependencies');
  if (ui.dependencies['hd-wallet-wasm'] !== RELEASE_VERSION) {
    fail('UI package lock entry must have the exact core dependency');
  }
}

function requireSinglePackageLock(value, name) {
  requireRecord(value, 'package lock');
  if (value.lockfileVersion !== 3) fail('package lock must use lockfileVersion 3');
  requireRecord(value.packages, 'package lock packages');
  const root = requireRecord(value.packages[''], 'package lock root');
  requireRecord(root.dependencies, 'package lock root dependencies');
  if (root.dependencies[name] !== RELEASE_VERSION) {
    fail(`package lock root must depend on exact ${name}@${RELEASE_VERSION}`);
  }
  if (name === 'hd-wallet-ui') {
    const ui = requireRecord(value.packages['node_modules/hd-wallet-ui'], 'UI package lock entry');
    requireRecord(ui.dependencies, 'UI package lock dependencies');
    if (ui.dependencies['hd-wallet-wasm'] !== RELEASE_VERSION) {
      fail('UI package lock entry must have the exact core dependency');
    }
  }
}

function buildPackageEvidence({ auditRow, name, packageLock, registry, release, run, trustPolicy }) {
  requireAuditRow(auditRow, name);
  requireExactKeys(registry, [
    'dist', 'registryKeys', 'sigstoreTrust', 'workflowTarball',
  ], `${name} registry evidence`);
  requireExactKeys(registry.dist, [
    'attestations', 'integrity', 'signatures', 'tarball',
  ], `${name} registry dist`);
  const lock = requireRecord(packageLock.packages[`node_modules/${name}`],
    `${name} package lock entry`);
  if (lock.version !== RELEASE_VERSION) fail(`${name} package lock entry has wrong exact package version`);
  if (registry.dist.integrity !== lock.integrity) fail(`${name} registry integrity does not match package lock`);
  if (registry.dist.tarball !== lock.resolved) fail(`${name} registry tarball does not match package lock`);
  if (registry.dist.tarball !== expectedTarballUrl(name)) fail(`${name} registry tarball URL is wrong`);
  const integrity = parseIntegrity(registry.dist.integrity, `${name} registry integrity`);
  requireExactKeys(registry.workflowTarball, ['sha512'], `${name} workflow tarball`);
  requireLowerHex(registry.workflowTarball.sha512, 64, `${name} workflow tarball SHA-512`);
  if (registry.workflowTarball.sha512 !== integrity.sha512) {
    fail(`${name} workflow tarball SHA-512 does not match registry integrity`);
  }
  requireAttestations(auditRow.attestations, name, `${name} audit attestations`);
  requireAttestations(registry.dist.attestations, name, `${name} registry attestations`);
  if (canonicalizeJson(auditRow.attestations) !== canonicalizeJson(registry.dist.attestations)) {
    fail(`${name} audit and registry attestations metadata do not match`);
  }
  const registrySignature = normalizeRegistrySignature(registry, name, registry.dist.integrity);
  const { provenance, publish } = selectAttestations(auditRow.attestationBundles, name);
  if (provenance.predicateType !== auditRow.attestations.provenance.predicateType) {
    fail(`${name} provenance predicate type does not match attestations metadata`);
  }
  const publishSignature = requireArray(publish.bundle?.dsseEnvelope?.signatures,
    `${name} publish DSSE signatures`);
  if (publishSignature.length !== 1) {
    fail(`${name} publish attestation must have exactly one DSSE signature`);
  }
  requireExactlyBoundRegistryKeys(registry.registryKeys, [
    registry.dist.signatures[0]?.keyid,
    publishSignature[0]?.keyid,
  ], name);
  const publishKey = selectRegistryKey(
    registry.registryKeys,
    publishSignature[0]?.keyid,
    name,
    'publish attestation',
  );
  const verified = verifyBundle(provenance.bundle, registry.sigstoreTrust, {
    ...release,
    name,
    run,
    sha512: integrity.sha512,
  });
  verifyPublishBundle(publish.bundle, registry.sigstoreTrust, publishKey, {
    name,
    sha512: integrity.sha512,
  }, trustPolicy);
  requireTrustedPackageMaterials({
    bundle: provenance.bundle,
    name,
    registryKey: registrySignature.key,
    trust: registry.sigstoreTrust,
    trustPolicy,
  });
  return {
    attestations: clone(auditRow.attestations),
    integrity: registry.dist.integrity,
    name,
    provenance: {
      bundle: clone(provenance.bundle),
      predicateType: provenance.predicateType,
      statement: clone(verified.statement),
      trust: clone(registry.sigstoreTrust),
    },
    registrySignature,
    run: { attempt: verified.binding.attempt, id: run.id },
    subject: clone(verified.binding.subject),
    tarball: { sha512: integrity.sha512, url: registry.dist.tarball },
    version: RELEASE_VERSION,
  };
}

export function verifyPackageProvenanceEvidence(input, trustPolicy = defaultTrustPolicy()) {
  validateProvenanceTrustPolicy(trustPolicy);
  requireExactKeys(input, [
    'auditRow', 'commit', 'packageLock', 'packageName', 'registryEvidence',
    'repository', 'runMetadata', 'sourceTag', 'workflow',
  ], 'single-package provenance verifier input');
  const release = requireExpectedRelease(input);
  const run = requireRunMetadata(input.runMetadata, release.commit);
  const name = requireString(input.packageName, 'package name');
  if (!PACKAGE_NAMES.includes(name)) fail('package name is not an exact release package');
  requireSinglePackageLock(input.packageLock, name);
  const packageEvidence = buildPackageEvidence({
    auditRow: input.auditRow,
    name,
    packageLock: input.packageLock,
    registry: input.registryEvidence,
    release,
    run,
    trustPolicy,
  });
  requireNormalizedPackage(packageEvidence, { ...release, name, run }, trustPolicy);
  return clone(packageEvidence);
}

export function buildProvenanceEvidence(input, trustPolicy = defaultTrustPolicy()) {
  validateProvenanceTrustPolicy(trustPolicy);
  requireExactKeys(input, [
    'audit', 'commit', 'packageLock', 'registryEvidence', 'repository',
    'runMetadata', 'sourceTag', 'workflow',
  ], 'provenance verifier input');
  const release = requireExpectedRelease(input);
  const run = requireRunMetadata(input.runMetadata, release.commit);
  requirePackageLock(input.packageLock);
  requireExactKeys(input.audit, ['invalid', 'missing', 'verified'], 'audit');
  if (requireArray(input.audit.invalid, 'audit invalid').length !== 0) fail('audit invalid list must be empty');
  if (requireArray(input.audit.missing, 'audit missing').length !== 0) fail('audit missing list must be empty');
  const verifiedRows = requireArray(input.audit.verified, 'audit verified');
  requireExactKeys(input.registryEvidence, PACKAGE_NAMES, 'registry evidence');

  const packages = PACKAGE_NAMES.map((name) => {
    const rows = verifiedRows.filter((row) => row?.name === name && row?.version === RELEASE_VERSION);
    if (rows.length !== 1) fail(`${name} must have exactly one audit row for the exact package version`);
    return buildPackageEvidence({
      auditRow: rows[0],
      name,
      packageLock: input.packageLock,
      registry: input.registryEvidence[name],
      release,
      run,
      trustPolicy,
    });
  });

  if (verifiedRows.length !== PACKAGE_NAMES.length) fail('audit verified list contains an unexpected package row');
  const evidence = {
    commit: release.commit,
    packages,
    repository: release.repository,
    run,
    schemaVersion: SCHEMA_VERSION,
    sourceTag: release.sourceTag,
    workflow: release.workflow,
  };
  return verifyProvenanceEvidence(evidence, trustPolicy);
}

export function serializeProvenanceEvidence(value, trustPolicy = defaultTrustPolicy()) {
  const verified = verifyProvenanceEvidence(value, trustPolicy);
  return `${canonicalizeJson(verified)}\n`;
}

function readStrictJson(filename, label) {
  let text;
  try {
    text = readFileSync(filename, 'utf8');
  } catch (error) {
    fail(`${label} could not be read: ${error instanceof Error ? error.message : String(error)}`);
  }
  return parseJsonTextStrict(text, label);
}

function parseArguments(argv) {
  const values = new Map();
  const positional = [];
  const flags = new Set([
    '--commit', '--core-attestations', '--package', '--package-lock', '--registry-attestations',
    '--repository', '--run-metadata', '--tag', '--trust-policy', '--ui-attestations', '--workflow',
  ]);
  for (let index = 0; index < argv.length; index += 1) {
    const argument = argv[index];
    if (!argument.startsWith('--')) {
      positional.push(argument);
      continue;
    }
    if (!flags.has(argument)) fail(`unknown argument ${argument}`);
    if (values.has(argument)) fail(`duplicate argument ${argument}`);
    const next = argv[index + 1];
    if (!next || next.startsWith('--')) fail(`missing value for ${argument}`);
    values.set(argument, next);
    index += 1;
  }
  if (positional.length !== 1) fail('exactly one npm audit JSON file is required');
  const common = [
    '--commit', '--package-lock', '--repository', '--run-metadata', '--tag', '--trust-policy',
    '--workflow',
  ];
  for (const flag of common) if (!values.has(flag)) fail(`missing required argument ${flag}`);
  const singleMode = values.has('--package') || values.has('--registry-attestations');
  if (singleMode) {
    for (const flag of ['--package', '--registry-attestations']) {
      if (!values.has(flag)) fail(`missing required argument ${flag}`);
    }
    if (values.has('--core-attestations') || values.has('--ui-attestations')) {
      fail('single-package mode forbids two-package attestation flags');
    }
  } else {
    for (const flag of ['--core-attestations', '--ui-attestations']) {
      if (!values.has(flag)) fail(`missing required argument ${flag}`);
    }
  }
  return { auditFilename: positional[0], mode: singleMode ? 'single' : 'final', values };
}

function runCli(argv) {
  const { auditFilename, mode, values } = parseArguments(argv);
  const audit = readStrictJson(auditFilename, 'npm 11.16.0 audit JSON');
  const trustPolicy = readStrictJson(values.get('--trust-policy'),
    'signed-tag provenance trust policy');
  const shared = {
    commit: values.get('--commit'),
    packageLock: readStrictJson(values.get('--package-lock'), 'package lock JSON'),
    repository: values.get('--repository'),
    runMetadata: readStrictJson(values.get('--run-metadata'), 'run metadata JSON'),
    sourceTag: values.get('--tag'),
    workflow: values.get('--workflow'),
  };
  if (mode === 'single') {
    requireExactKeys(audit, ['invalid', 'missing', 'verified'], 'audit');
    if (requireArray(audit.invalid, 'audit invalid').length !== 0) {
      fail('audit invalid list must be empty');
    }
    if (requireArray(audit.missing, 'audit missing').length !== 0) {
      fail('audit missing list must be empty');
    }
    const packageName = values.get('--package');
    if (!PACKAGE_NAMES.includes(packageName)) fail('package name is not an exact release package');
    const rows = requireArray(audit.verified, 'audit verified')
      .filter((row) => row?.name === packageName && row?.version === RELEASE_VERSION);
    if (rows.length !== 1) fail(`${packageName} must have exactly one audit row`);
    const result = verifyPackageProvenanceEvidence({
      auditRow: rows[0],
      packageName,
      registryEvidence: readStrictJson(values.get('--registry-attestations'),
        `${packageName} registry evidence JSON`),
      ...shared,
    }, trustPolicy);
    process.stdout.write(`${canonicalizeJson(result)}\n`);
    return;
  }
  const input = {
    audit,
    registryEvidence: {
      'hd-wallet-ui': readStrictJson(values.get('--ui-attestations'), 'UI registry evidence JSON'),
      'hd-wallet-wasm': readStrictJson(values.get('--core-attestations'), 'core registry evidence JSON'),
    },
    ...shared,
  };
  process.stdout.write(serializeProvenanceEvidence(
    buildProvenanceEvidence(input, trustPolicy),
    trustPolicy,
  ));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    runCli(process.argv.slice(2));
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    process.stderr.write(`${message}\n`);
    process.exitCode = 1;
  }
}
