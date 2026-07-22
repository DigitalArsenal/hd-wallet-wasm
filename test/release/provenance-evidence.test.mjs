import assert from 'node:assert/strict';
import {
  X509Certificate,
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signData,
} from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

import {
  buildProvenanceEvidence as buildProvenanceEvidenceWithPolicy,
  canonicalizeJson,
  serializeProvenanceEvidence as serializeProvenanceEvidenceWithPolicy,
  validateProvenanceTrustPolicy,
  verifyPackageProvenanceEvidence as verifyPackageProvenanceEvidenceWithPolicy,
  verifyProvenanceEvidence as verifyProvenanceEvidenceWithPolicy,
} from '../../scripts/verify-provenance-evidence.mjs';

const here = dirname(fileURLToPath(import.meta.url));
const fixturePath = join(here, 'fixtures', 'npm-audit-signatures.v11.16.0.json');
const scriptPath = join(here, '..', '..', 'scripts', 'verify-provenance-evidence.mjs');
const fixtureText = readFileSync(fixturePath, 'utf8');
const fixture = JSON.parse(fixtureText);

const clone = (value) => structuredClone(value);

const PUBLISH_PREDICATE =
  'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
const RELEASE_VERSION = '2.0.25';
const EXPECTED_REPOSITORY_ID = '1142529413';
const EXPECTED_REPOSITORY_OWNER_ID = '29587475';
const EXPECTED_REPOSITORY = 'https://github.com/DigitalArsenal/hd-wallet-wasm';
const EXPECTED_REF = 'refs/tags/v2.0.25';
const EXPECTED_WORKFLOW_IDENTITY =
  'https://github.com/DigitalArsenal/hd-wallet-wasm/.github/workflows/npm-publish.yml@refs/tags/v2.0.25';
const EXPECTED_OIDC_ISSUER = 'https://token.actions.githubusercontent.com';
// Deterministic test-only fixture keys. They protect no production identity or material.
const PUBLISH_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgecpeZyPEcJu4OvGO
XWUDxzSe3rworLMiSoJUkavc3IihRANCAAT6owBD8pkBRuzA2rRiCPrl4pDRYUaM
fKsqQVTmeciNdlIV20e8EjGUfi/pJ0lGfaJ/D0omIKE6H5GrWi+QMxdh
-----END PRIVATE KEY-----
`;
const REGISTRY_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghtx+xEzeKPVMYTgC
N5tKESurRY6blloe5GAEujIcDomhRANCAASaOMzVeu6ltfAvfJUD9hJshc6nfMIZ
IayLpRpGds2I3VQYIv2EMNZB57BcmfBI1j7Kfa0dmBs3R/iMRMoO5Fmc
-----END PRIVATE KEY-----
`;
const LOG_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPcnHS2MCf26r2HEs
tmdtpI2Kwb+ir9r+BnUMmFfQEUKhRANCAATqc9WaNhUFLzedVJwPfwYhAlYmiJ5G
/TG1/ObRho28TFOMkKw/8gF5WKRxJCSNCEbF7Jeb9lbPAkOsQXcTDpNE
-----END PRIVATE KEY-----
`;
const FULCIO_ROOT_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgjtViI+81LWRyQ9rz
9gKqWKER1H2Vb66d0bk+9sR442ehRANCAAQNguoLacNpgyzwGADbyyChUduaRsGs
WoH05adz6IXTWoEa4sPSv6SIMw0GFDH0X2JcvaH8VPinA5jbnUNVI7Yr
-----END PRIVATE KEY-----
`;
const FULCIO_INTERMEDIATE_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu1qRtLNpalPu9w0X
VXMubRWKQ9CKbr0rVkouN5cz7oKhRANCAAQ+qHW8niVKFwJ+navEky1BGcQ3DJQd
U9fE9nDlGgDJ7UabPRp31DyYvMdos7iGblF1/tMEBL9VOiuFBTVNT/T6
-----END PRIVATE KEY-----
`;
const FULCIO_LEAF_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgvHbqDn4drOHTIyeN
hBCjOt+J/MQXkmxDayg+MmRJ1IOhRANCAAT/XA341EnexKK8oRC93QuTRwiph10s
Jy5cEvf3MCWq7awzAgLtnogcAR+huv+6/rWWOgLIoVhnuhcZQH7hMTl5
-----END PRIVATE KEY-----
`;
const publishPrivateKey = createPrivateKey(PUBLISH_PRIVATE_KEY_PEM);
const publishPublicKey = createPublicKey(publishPrivateKey);
const publishPublicKeyPem = publishPublicKey.export({ type: 'spki', format: 'pem' }).toString();
const publishPublicKeyDer = publishPublicKey.export({ type: 'spki', format: 'der' });
const publishKeyId = `SHA256:${createHash('sha256').update(publishPublicKeyDer)
  .digest('base64').replace(/=+$/u, '')}`;
const registryPrivateKey = createPrivateKey(REGISTRY_PRIVATE_KEY_PEM);
const registryPublicKey = createPublicKey(registryPrivateKey);
const registryPublicKeyPem = registryPublicKey.export({ type: 'spki', format: 'pem' }).toString();
const registryPublicKeyDer = registryPublicKey.export({ type: 'spki', format: 'der' });
const registryKeyId = fixture.registryEvidence['hd-wallet-wasm'].registryKeys[0].keyid;
const logPrivateKey = createPrivateKey(LOG_PRIVATE_KEY_PEM);
const logPublicKey = createPublicKey(logPrivateKey);
const logPublicKeyPem = logPublicKey.export({ type: 'spki', format: 'pem' }).toString();
const logPublicKeyDer = logPublicKey.export({ type: 'spki', format: 'der' });
const logId = createHash('sha256').update(logPublicKeyDer).digest('base64');
const fulcioRootPrivateKey = createPrivateKey(FULCIO_ROOT_PRIVATE_KEY_PEM);
const fulcioIntermediatePrivateKey = createPrivateKey(FULCIO_INTERMEDIATE_PRIVATE_KEY_PEM);
const fulcioLeafPrivateKey = createPrivateKey(FULCIO_LEAF_PRIVATE_KEY_PEM);

const OID = Object.freeze({
  basicConstraints: '2.5.29.19',
  buildConfigDigest: '1.3.6.1.4.1.57264.1.19',
  buildConfigUri: '1.3.6.1.4.1.57264.1.18',
  buildSignerDigest: '1.3.6.1.4.1.57264.1.10',
  buildSignerUri: '1.3.6.1.4.1.57264.1.9',
  buildTrigger: '1.3.6.1.4.1.57264.1.20',
  codeSigning: '1.3.6.1.5.5.7.3.3',
  extendedKeyUsage: '2.5.29.37',
  githubWorkflowName: '1.3.6.1.4.1.57264.1.4',
  githubWorkflowRef: '1.3.6.1.4.1.57264.1.6',
  githubWorkflowRepository: '1.3.6.1.4.1.57264.1.5',
  githubWorkflowSha: '1.3.6.1.4.1.57264.1.3',
  githubWorkflowTrigger: '1.3.6.1.4.1.57264.1.2',
  issuer: '1.3.6.1.4.1.57264.1.1',
  issuerV2: '1.3.6.1.4.1.57264.1.8',
  keyUsage: '2.5.29.15',
  runInvocationUri: '1.3.6.1.4.1.57264.1.21',
  runnerEnvironment: '1.3.6.1.4.1.57264.1.11',
  sourceRepositoryDigest: '1.3.6.1.4.1.57264.1.13',
  sourceRepositoryIdentifier: '1.3.6.1.4.1.57264.1.15',
  sourceRepositoryRef: '1.3.6.1.4.1.57264.1.14',
  sourceRepositoryUri: '1.3.6.1.4.1.57264.1.12',
  sourceRepositoryOwnerIdentifier: '1.3.6.1.4.1.57264.1.17',
  sourceRepositoryOwnerUri: '1.3.6.1.4.1.57264.1.16',
  sourceRepositoryVisibility: '1.3.6.1.4.1.57264.1.22',
  subjectAlternativeName: '2.5.29.17',
  tokenSubject: '1.3.6.1.4.1.57264.1.24',
});

function derLength(length) {
  assert.ok(Number.isSafeInteger(length) && length >= 0);
  if (length < 0x80) return Buffer.from([length]);
  const bytes = [];
  for (let remaining = length; remaining > 0; remaining >>>= 8) {
    bytes.unshift(remaining & 0xff);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

function der(tag, ...parts) {
  const value = Buffer.concat(parts.map((part) => Buffer.from(part)));
  return Buffer.concat([Buffer.from([tag]), derLength(value.length), value]);
}

const derSequence = (...parts) => der(0x30, ...parts);
const derSet = (...parts) => der(0x31, ...parts);
const derOctetString = (value) => der(0x04, value);
const derUtf8String = (value) => der(0x0c, Buffer.from(value, 'utf8'));

function derInteger(value) {
  assert.ok(Number.isSafeInteger(value) && value >= 0);
  const bytes = [];
  for (let remaining = value; remaining > 0; remaining >>>= 8) {
    bytes.unshift(remaining & 0xff);
  }
  if (bytes.length === 0) bytes.push(0);
  if ((bytes[0] & 0x80) !== 0) bytes.unshift(0);
  return der(0x02, Buffer.from(bytes));
}

function derOid(value) {
  const arcs = value.split('.').map((arc) => BigInt(arc));
  assert.ok(arcs.length >= 2 && arcs[0] >= 0n && arcs[0] <= 2n);
  assert.ok(arcs[1] >= 0n && (arcs[0] === 2n || arcs[1] <= 39n));
  const subidentifiers = [arcs[0] * 40n + arcs[1], ...arcs.slice(2)];
  const bytes = [];
  for (const subidentifier of subidentifiers) {
    assert.ok(subidentifier >= 0n);
    const encoded = [Number(subidentifier & 0x7fn)];
    for (let remaining = subidentifier >> 7n; remaining > 0n; remaining >>= 7n) {
      encoded.unshift(Number(remaining & 0x7fn) | 0x80);
    }
    bytes.push(...encoded);
  }
  return der(0x06, Buffer.from(bytes));
}

function derBitString(value, unusedBits = 0) {
  return der(0x03, Buffer.from([unusedBits]), value);
}

function derExtension(oid, value, { critical = false } = {}) {
  return derSequence(
    derOid(oid),
    ...(critical ? [der(0x01, Buffer.from([0xff]))] : []),
    derOctetString(value),
  );
}

function x509Name(commonName) {
  return derSequence(derSet(derSequence(
    derOid('2.5.4.3'),
    derUtf8String(commonName),
  )));
}

const ECDSA_WITH_SHA256 = derSequence(derOid('1.2.840.10045.4.3.2'));

function buildCertificate({
  extensions,
  issuerName,
  issuerPrivateKey,
  publicKey,
  serial,
  subjectName,
}) {
  const tbs = derSequence(
    der(0xa0, derInteger(2)),
    derInteger(serial),
    ECDSA_WITH_SHA256,
    x509Name(issuerName),
    derSequence(
      der(0x17, Buffer.from('260101000000Z', 'ascii')),
      der(0x17, Buffer.from('350101000000Z', 'ascii')),
    ),
    x509Name(subjectName),
    createPublicKey(publicKey).export({ format: 'der', type: 'spki' }),
    der(0xa3, derSequence(...extensions)),
  );
  const signature = signData('sha256', tbs, issuerPrivateKey);
  return derSequence(tbs, ECDSA_WITH_SHA256, derBitString(signature));
}

function authorityExtensions() {
  return [
    derExtension(OID.basicConstraints, derSequence(der(0x01, Buffer.from([0xff]))), {
      critical: true,
    }),
    derExtension(OID.keyUsage, derBitString(Buffer.from([0x06]), 1), { critical: true }),
  ];
}

const fulcioRootDer = buildCertificate({
  extensions: authorityExtensions(),
  issuerName: 'SDN Synthetic Fulcio Root',
  issuerPrivateKey: fulcioRootPrivateKey,
  publicKey: fulcioRootPrivateKey,
  serial: 1,
  subjectName: 'SDN Synthetic Fulcio Root',
});
const fulcioIntermediateDer = buildCertificate({
  extensions: authorityExtensions(),
  issuerName: 'SDN Synthetic Fulcio Root',
  issuerPrivateKey: fulcioRootPrivateKey,
  publicKey: fulcioIntermediatePrivateKey,
  serial: 2,
  subjectName: 'SDN Synthetic Fulcio Intermediate',
});
const fulcioRootSha256 = createHash('sha256').update(fulcioRootDer).digest('hex');

function leafExtension(oid, value, critical = false) {
  return { critical, oid, value: Buffer.from(value) };
}

function buildFulcioLeaf(overrides = {}) {
  const { duplicates = [], ...fieldOverrides } = overrides;
  const fields = {
    buildConfigDigest: leafExtension(OID.buildConfigDigest, derUtf8String(fixture.expected.commit)),
    buildConfigUri: leafExtension(OID.buildConfigUri, derUtf8String(EXPECTED_WORKFLOW_IDENTITY)),
    buildSignerDigest: leafExtension(OID.buildSignerDigest, derUtf8String(fixture.expected.commit)),
    buildSignerUri: leafExtension(OID.buildSignerUri, derUtf8String(EXPECTED_WORKFLOW_IDENTITY)),
    buildTrigger: leafExtension(OID.buildTrigger, derUtf8String('workflow_dispatch')),
    extendedKeyUsage: leafExtension(
      OID.extendedKeyUsage,
      derSequence(derOid(OID.codeSigning)),
    ),
    githubWorkflowName: leafExtension(
      OID.githubWorkflowName,
      Buffer.from('Publish to NPM', 'utf8'),
    ),
    githubWorkflowRef: leafExtension(OID.githubWorkflowRef, Buffer.from(EXPECTED_REF, 'utf8')),
    githubWorkflowRepository: leafExtension(
      OID.githubWorkflowRepository,
      Buffer.from('DigitalArsenal/hd-wallet-wasm', 'utf8'),
    ),
    githubWorkflowSha: leafExtension(
      OID.githubWorkflowSha,
      Buffer.from(fixture.expected.commit, 'utf8'),
    ),
    githubWorkflowTrigger: leafExtension(
      OID.githubWorkflowTrigger,
      Buffer.from('workflow_dispatch', 'utf8'),
    ),
    issuer: leafExtension(OID.issuer, Buffer.from(EXPECTED_OIDC_ISSUER, 'utf8')),
    issuerV2: leafExtension(OID.issuerV2, derUtf8String(EXPECTED_OIDC_ISSUER)),
    keyUsage: leafExtension(OID.keyUsage, derBitString(Buffer.from([0x80]), 7), true),
    repositoryId: leafExtension(
      OID.sourceRepositoryIdentifier,
      derUtf8String(EXPECTED_REPOSITORY_ID),
    ),
    repositoryOwnerId: leafExtension(
      OID.sourceRepositoryOwnerIdentifier,
      derUtf8String(EXPECTED_REPOSITORY_OWNER_ID),
    ),
    runInvocationUri: leafExtension(
      OID.runInvocationUri,
      derUtf8String(`${EXPECTED_REPOSITORY}/actions/runs/9876543210/attempts/2`),
    ),
    runnerEnvironment: leafExtension(OID.runnerEnvironment, derUtf8String('github-hosted')),
    sourceRepositoryDigest: leafExtension(
      OID.sourceRepositoryDigest,
      derUtf8String(fixture.expected.commit),
    ),
    sourceRepositoryOwnerUri: leafExtension(
      OID.sourceRepositoryOwnerUri,
      derUtf8String('https://github.com/DigitalArsenal'),
    ),
    sourceRepositoryRef: leafExtension(OID.sourceRepositoryRef, derUtf8String(EXPECTED_REF)),
    sourceRepositoryUri: leafExtension(OID.sourceRepositoryUri, derUtf8String(EXPECTED_REPOSITORY)),
    sourceRepositoryVisibility: leafExtension(
      OID.sourceRepositoryVisibility,
      derUtf8String('public'),
    ),
    subjectAlternativeName: leafExtension(
      OID.subjectAlternativeName,
      derSequence(der(0x86, Buffer.from(EXPECTED_WORKFLOW_IDENTITY, 'ascii'))),
      true,
    ),
    tokenSubject: leafExtension(
      OID.tokenSubject,
      derUtf8String('repo:DigitalArsenal/hd-wallet-wasm:ref:refs/tags/v2.0.25'),
    ),
    ...fieldOverrides,
  };
  const extensionRows = [
    leafExtension(OID.basicConstraints, derSequence(), true),
    ...Object.values(fields).filter((field) => field !== null),
  ];
  for (const duplicate of duplicates) {
    extensionRows.push(duplicate);
  }
  // Intentionally no SCT fixture: this verifier retains the documented limitation that
  // Fulcio CT-log keys are not pinned and the embedded SCT is not validated.
  return buildCertificate({
    extensions: extensionRows.map(({ critical, oid, value }) =>
      derExtension(oid, value, { critical })),
    issuerName: 'SDN Synthetic Fulcio Intermediate',
    issuerPrivateKey: fulcioIntermediatePrivateKey,
    publicKey: fulcioLeafPrivateKey,
    serial: 3,
    subjectName: 'SDN Synthetic npm provenance',
  });
}

const defaultFulcioLeafDer = buildFulcioLeaf();

function sha256(...parts) {
  const hash = createHash('sha256');
  parts.forEach((part) => hash.update(part));
  return hash.digest();
}

function dssePreAuthenticationEncoding(payloadType, payload) {
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${Buffer.byteLength(payloadType)} ${payloadType} ${payload.length} `,
      'utf8'),
    payload,
  ]);
}

function signLogEntry(entry) {
  entry.logId.keyId = logId;
  const bodyBytes = Buffer.from(entry.canonicalizedBody, 'base64');
  const promisePayload = {
    body: bodyBytes.toString('base64'),
    integratedTime: Number(entry.integratedTime),
    logIndex: Number(entry.logIndex),
    logID: Buffer.from(logId, 'base64').toString('hex'),
  };
  entry.inclusionPromise.signedEntryTimestamp = signData(
    'sha256',
    Buffer.from(canonicalizeJson(promisePayload), 'utf8'),
    logPrivateKey,
  ).toString('base64');
  const proof = entry.inclusionProof;
  const note = `synthetic.rekor.invalid\n${proof.treeSize}\n${proof.rootHash}\n`;
  const signature = signData('sha256', Buffer.from(note, 'utf8'), logPrivateKey);
  const signed = Buffer.concat([Buffer.from(logId, 'base64').subarray(0, 4), signature]);
  proof.checkpoint.envelope = `${note}\n— synthetic.rekor.invalid ${signed.toString('base64')}\n`;
}

function resignProvenanceBundle(targetBundle, leafDer = defaultFulcioLeafDer) {
  const { dsseEnvelope: envelope, verificationMaterial } = targetBundle;
  const payload = Buffer.from(envelope.payload, 'base64');
  envelope.signatures[0].sig = signData(
    'sha256',
    dssePreAuthenticationEncoding(envelope.payloadType, payload),
    fulcioLeafPrivateKey,
  ).toString('base64');
  verificationMaterial.certificate.rawBytes = leafDer.toString('base64');

  const entry = verificationMaterial.tlogEntries[0];
  const body = JSON.parse(Buffer.from(entry.canonicalizedBody, 'base64').toString('utf8'));
  const rekorEnvelope = {
    payload: envelope.payload,
    payloadType: envelope.payloadType,
    signatures: [{ sig: envelope.signatures[0].sig }],
  };
  body.spec.envelopeHash.value = sha256(
    Buffer.from(JSON.stringify(rekorEnvelope), 'utf8'),
  ).toString('hex');
  body.spec.payloadHash.value = sha256(payload).toString('hex');
  body.spec.signatures[0].signature = envelope.signatures[0].sig;
  body.spec.signatures[0].verifier = Buffer.from(
    new X509Certificate(leafDer).toString(),
    'utf8',
  ).toString('base64');
  const bodyBytes = Buffer.from(canonicalizeJson(body), 'utf8');
  entry.canonicalizedBody = bodyBytes.toString('base64');
  const leafHash = sha256(Buffer.from([0]), bodyBytes);
  const siblingHash = sha256(Buffer.from([0]), Buffer.from('synthetic earlier leaf', 'utf8'));
  entry.inclusionProof = {
    checkpoint: { envelope: 'placeholder' },
    hashes: [siblingHash.toString('base64')],
    logIndex: '1',
    rootHash: sha256(Buffer.from([1]), siblingHash, leafHash).toString('base64'),
    treeSize: '2',
  };
  entry.logIndex = '0';
  signLogEntry(entry);
}

function rewriteProvenanceStatement(targetBundle, mutate = () => {}) {
  const statement = JSON.parse(Buffer.from(
    targetBundle.dsseEnvelope.payload,
    'base64',
  ).toString('utf8'));
  const github = statement.predicate.buildDefinition.internalParameters.github;
  github.repository_id = EXPECTED_REPOSITORY_ID;
  github.repository_owner_id = EXPECTED_REPOSITORY_OWNER_ID;
  statement.subject[0].name = statement.subject[0].name.replace(
    /@[^@]+$/u,
    `@${RELEASE_VERSION}`,
  );
  const buildDefinition = statement.predicate.buildDefinition;
  if (buildDefinition.externalParameters.workflow.ref.startsWith('refs/tags/')) {
    buildDefinition.externalParameters.workflow.ref = EXPECTED_REF;
  }
  buildDefinition.resolvedDependencies[0].uri =
    buildDefinition.resolvedDependencies[0].uri.replace(
      /@refs\/tags\/[^@]+$/u,
      `@${EXPECTED_REF}`,
    );
  mutate(statement);
  targetBundle.dsseEnvelope.payload = Buffer.from(
    canonicalizeJson(statement),
    'utf8',
  ).toString('base64');
}

function installSyntheticFulcioTrust(registry) {
  registry.sigstoreTrust.certificateChain = {
    certificates: [fulcioIntermediateDer, fulcioRootDer]
      .map((rawBytes) => ({ rawBytes: rawBytes.toString('base64') })),
  };
}

function buildPublishBundle({ integratedTime, name, sha512, statementMutator }) {
  const statement = {
    _type: 'https://in-toto.io/Statement/v0.1',
    predicate: {
      name,
      registry: 'https://registry.npmjs.org',
      version: '2.0.25',
    },
    predicateType: PUBLISH_PREDICATE,
    subject: [{ digest: { sha512 }, name: `pkg:npm/${name}@2.0.25` }],
  };
  if (statementMutator) statementMutator(statement);
  const payloadType = 'application/vnd.in-toto+json';
  const payload = Buffer.from(canonicalizeJson(statement), 'utf8');
  const sig = signData(
    'sha256',
    dssePreAuthenticationEncoding(payloadType, payload),
    publishPrivateKey,
  ).toString('base64');
  const envelope = {
    payload: payload.toString('base64'),
    payloadType,
    signatures: [{ sig, keyid: publishKeyId }],
  };
  const rekorEnvelope = {
    payload: envelope.payload,
    payloadType,
    signatures: [{ sig, keyid: publishKeyId }],
  };
  const body = {
    apiVersion: '0.0.1',
    kind: 'dsse',
    spec: {
      envelopeHash: {
        algorithm: 'sha256',
        value: sha256(Buffer.from(JSON.stringify(rekorEnvelope), 'utf8')).toString('hex'),
      },
      payloadHash: { algorithm: 'sha256', value: sha256(payload).toString('hex') },
      signatures: [{
        signature: sig,
        verifier: Buffer.from(publishPublicKeyPem, 'utf8').toString('base64'),
      }],
    },
  };
  const bodyBytes = Buffer.from(canonicalizeJson(body), 'utf8');
  const leafHash = sha256(Buffer.from([0]), bodyBytes);
  const siblingHash = sha256(Buffer.from([0]), Buffer.from('synthetic earlier leaf', 'utf8'));
  const entry = {
    canonicalizedBody: bodyBytes.toString('base64'),
    inclusionPromise: { signedEntryTimestamp: 'placeholder' },
    inclusionProof: {
      checkpoint: { envelope: 'placeholder' },
      hashes: [siblingHash.toString('base64')],
      logIndex: '1',
      rootHash: sha256(Buffer.from([1]), siblingHash, leafHash).toString('base64'),
      treeSize: '2',
    },
    integratedTime: String(integratedTime),
    kindVersion: { kind: 'dsse', version: '0.0.1' },
    logId: { keyId: logId },
    logIndex: '0',
  };
  signLogEntry(entry);
  return {
    dsseEnvelope: envelope,
    mediaType: 'application/vnd.dev.sigstore.bundle+json;version=0.2',
    verificationMaterial: {
      publicKey: { hint: publishKeyId },
      timestampVerificationData: { rfc3161Timestamps: [] },
      tlogEntries: [entry],
    },
  };
}

function prepareSyntheticInput(value) {
  for (const row of value.audit.verified) {
    const provenance = row.attestationBundles.find(
      ({ predicateType }) => predicateType === 'https://slsa.dev/provenance/v1',
    );
    const registry = value.registryEvidence[row.name];
    registry.registryKeys = [{
      keyid: registryKeyId,
      publicKeyPem: registryPublicKeyPem,
    }];
    registry.dist.signatures = [{
      keyid: registryKeyId,
      sig: signData(
        'sha256',
        Buffer.from(`${row.name}@${RELEASE_VERSION}:${registry.dist.integrity}`, 'utf8'),
        registryPrivateKey,
      ).toString('base64'),
    }];
    rewriteProvenanceStatement(provenance.bundle);
    installSyntheticFulcioTrust(registry);
    resignProvenanceBundle(provenance.bundle);
    registry.sigstoreTrust.transparencyLog = {
      baseUrl: 'https://synthetic.rekor.invalid',
      logId,
      publicKeyPem: logPublicKeyPem,
    };
    registry.registryKeys.push({ keyid: publishKeyId, publicKeyPem: publishPublicKeyPem });
    const provenanceTime = Number(
      provenance.bundle.verificationMaterial.tlogEntries[0].integratedTime,
    );
    row.attestationBundles.push({
      bundle: buildPublishBundle({
        integratedTime: provenanceTime + 1,
        name: row.name,
        sha512: registry.workflowTarball.sha512,
      }),
      predicateType: PUBLISH_PREDICATE,
    });
  }
  return value;
}

const fixtureTrustPolicy = {
  npmRegistryKeys: [
    {
      keyDetails: 'PKIX_ECDSA_P256_SHA_256',
      keyUsage: 'npm:attestations',
      keyid: publishKeyId,
      publicKeySha256: createHash('sha256').update(publishPublicKeyDer).digest('hex'),
      validFor: { start: '2000-01-01T00:00:00.000Z', end: '2100-01-01T00:00:00.000Z' },
    },
    {
      keyDetails: 'PKIX_ECDSA_P256_SHA_256',
      keyUsage: 'npm:signatures',
      keyid: registryKeyId,
      publicKeySha256: createHash('sha256').update(registryPublicKeyDer).digest('hex'),
      validFor: { start: '2000-01-01T00:00:00.000Z', end: '2100-01-01T00:00:00.000Z' },
    },
  ],
  release: {
    packages: ['hd-wallet-ui', 'hd-wallet-wasm'],
    repository: 'https://github.com/DigitalArsenal/hd-wallet-wasm',
    repositoryId: EXPECTED_REPOSITORY_ID,
    repositoryOwnerId: EXPECTED_REPOSITORY_OWNER_ID,
    sourceTag: 'v2.0.25',
    version: '2.0.25',
    workflow: '.github/workflows/npm-publish.yml',
  },
  schemaVersion: 1,
  sigstoreCertificateAuthorities: [{
    rootCertificateSha256: fulcioRootSha256,
    uri: 'https://fulcio.sigstore.dev',
    validFor: { start: '2000-01-01T00:00:00.000Z', end: '2100-01-01T00:00:00.000Z' },
  }],
  sigstoreTransparencyLogs: [{
    baseUrl: 'https://synthetic.rekor.invalid',
    effectiveLogId: logId,
    hashAlgorithm: 'SHA2_256',
    keyDetails: 'PKIX_ECDSA_P256_SHA_256',
    publicKeySha256: createHash('sha256').update(logPublicKeyDer).digest('hex'),
    validFor: { start: '2000-01-01T00:00:00.000Z', end: '2100-01-01T00:00:00.000Z' },
  }],
  source: {
    npmVersion: '11.16.0',
    registryKeysTarget: 'registry.npmjs.org/keys.json',
    sigstoreTrustedRootTarget: 'trusted_root.json',
    tufBootstrapRootSha256: 'c8c41ec13f06ccabf5b48541ee2550098b4c7b5349e1d180390c29a7d5c2642c',
    tufBootstrapRootVersion: 14,
    tufImplementationVersion: '4.0.2',
    tufMirror: 'https://tuf-repo-cdn.sigstore.dev',
  },
};

const buildProvenanceEvidence = (input) =>
  buildProvenanceEvidenceWithPolicy(input, fixtureTrustPolicy);
const serializeProvenanceEvidence = (value) =>
  serializeProvenanceEvidenceWithPolicy(value, fixtureTrustPolicy);
const verifyPackageProvenanceEvidence = (input) =>
  verifyPackageProvenanceEvidenceWithPolicy(input, fixtureTrustPolicy);
const verifyProvenanceEvidence = (value) =>
  verifyProvenanceEvidenceWithPolicy(value, fixtureTrustPolicy);

const syntheticFixture = prepareSyntheticInput({
  audit: clone(fixture.audit),
  registryEvidence: clone(fixture.registryEvidence),
  packageLock: clone(fixture.packageLock),
  runMetadata: clone(fixture.runMetadata),
  ...fixture.expected,
});

function validInput() {
  return clone(syntheticFixture);
}

function auditRow(input, name = 'hd-wallet-wasm') {
  return input.audit.verified.find((row) => row.name === name);
}

function bundle(input, name = 'hd-wallet-wasm') {
  return auditRow(input, name).attestationBundles[0].bundle;
}

function publishBundle(input, name = 'hd-wallet-wasm') {
  return auditRow(input, name).attestationBundles.find(
    ({ predicateType }) => predicateType === PUBLISH_PREDICATE,
  ).bundle;
}

function replaceBundle(input, variant, name = 'hd-wallet-wasm') {
  const replacement = clone(fixture.adversarialBundles[variant]);
  auditRow(input, name).attestationBundles[0].bundle = replacement;
  rewriteProvenanceStatement(replacement);
  const leafDer = variant === 'wrongCertificateIdentity'
    ? buildFulcioLeaf({
      subjectAlternativeName: leafExtension(
        OID.subjectAlternativeName,
        derSequence(der(0x86, Buffer.from('https://attacker.invalid/workflow', 'ascii'))),
        true,
      ),
    })
    : defaultFulcioLeafDer;
  resignProvenanceBundle(replacement, leafDer);
}

function replaceFulcioLeaf(input, overrides, name = 'hd-wallet-wasm') {
  resignProvenanceBundle(bundle(input, name), buildFulcioLeaf(overrides));
}

function mutateProvenanceStatement(input, mutate, name = 'hd-wallet-wasm') {
  const targetBundle = bundle(input, name);
  rewriteProvenanceStatement(targetBundle, mutate);
  resignProvenanceBundle(targetBundle);
}

function replacePublishBundle(input, statementMutator, name = 'hd-wallet-wasm') {
  const target = auditRow(input, name).attestationBundles.find(
    ({ predicateType }) => predicateType === PUBLISH_PREDICATE,
  );
  const provenanceTime = Number(bundle(input, name)
    .verificationMaterial.tlogEntries[0].integratedTime);
  target.bundle = buildPublishBundle({
    integratedTime: provenanceTime + 1,
    name,
    sha512: input.registryEvidence[name].workflowTarball.sha512,
    statementMutator,
  });
}

function flipBase64(value) {
  const bytes = Buffer.from(value, 'base64');
  bytes[Math.floor(bytes.length / 2)] ^= 1;
  return bytes.toString('base64');
}

function assertForbiddenKeysAbsent(value) {
  const forbidden = /^(authorization|cookie|env|environment|headers|location|npm_config)$/iu;
  if (Array.isArray(value)) {
    value.forEach(assertForbiddenKeysAbsent);
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    assert.doesNotMatch(key, forbidden);
    assertForbiddenKeysAbsent(child);
  }
}

test('fixture records the exact npm 11.16.0 audit schema and real synthetic public proofs', () => {
  assert.equal(fixture.npmVersion, '11.16.0');
  assert.deepEqual(Object.keys(fixture.audit).sort(), ['invalid', 'missing', 'verified']);
  assert.equal(fixture.audit.invalid.length, 0);
  assert.equal(fixture.audit.missing.length, 0);
  assert.equal(fixture.audit.verified.length, 2);
  for (const row of fixture.audit.verified) {
    assert.deepEqual(Object.keys(row).sort(), [
      'attestationBundles', 'attestations', 'location', 'name', 'registry', 'version',
    ]);
    assert.equal(row.attestationBundles.length, 1);
    assert.equal(row.attestationBundles[0].predicateType, 'https://slsa.dev/provenance/v1');
    assert.equal(row.attestationBundles[0].bundle.mediaType,
      'application/vnd.dev.sigstore.bundle.v0.3+json');
    const { dsseEnvelope, verificationMaterial } = row.attestationBundles[0].bundle;
    assert.equal(dsseEnvelope.signatures.length, 1);
    assert.deepEqual(Object.keys(dsseEnvelope.signatures[0]), ['sig']);
    assert.deepEqual(Object.keys(verificationMaterial).sort(), [
      'certificate', 'timestampVerificationData', 'tlogEntries',
    ]);
    assert.deepEqual(verificationMaterial.timestampVerificationData, {});
    assert.equal(verificationMaterial.tlogEntries.length, 1);
    const logEntry = verificationMaterial.tlogEntries[0];
    assert.match(logEntry.logIndex, /^[1-9][0-9]*$/u);
    assert.match(logEntry.inclusionProof.logIndex, /^[1-9][0-9]*$/u);
    assert.ok(logEntry.inclusionProof.hashes.length > 0);
    const transparencyLog = fixture.registryEvidence[row.name].sigstoreTrust.transparencyLog;
    assert.equal(logEntry.logId.keyId, transparencyLog.logId);
    assert.notEqual(transparencyLog.logId, createHash('sha256')
      .update(createPublicKey(transparencyLog.publicKeyPem).export({ type: 'spki', format: 'der' }))
      .digest('base64'));
    const body = JSON.parse(Buffer.from(
      logEntry.canonicalizedBody,
      'base64',
    ).toString('utf8'));
    assert.deepEqual(Object.keys(body.spec).sort(), [
      'envelopeHash', 'payloadHash', 'signatures',
    ]);
    assert.equal(body.spec.envelopeHash.algorithm, 'sha256');
    assert.equal(body.spec.envelopeHash.value, createHash('sha256')
      .update(JSON.stringify(dsseEnvelope), 'utf8').digest('hex'));
    const verifierBytes = Buffer.from(body.spec.signatures[0].verifier, 'base64');
    assert.match(verifierBytes.toString('utf8'), /^-----BEGIN CERTIFICATE-----\n/u);
    assert.deepEqual(new X509Certificate(verifierBytes).raw,
      new X509Certificate(Buffer.from(verificationMaterial.certificate.rawBytes, 'base64')).raw);
    const registryKey = fixture.registryEvidence[row.name].registryKeys[0];
    assert.match(registryKey.keyid, /^SHA256:[A-Za-z0-9+/]{43}$/u);
    const derivedKeyId = `SHA256:${createHash('sha256')
      .update(createPublicKey(registryKey.publicKeyPem).export({ type: 'spki', format: 'der' }))
      .digest('base64').replace(/=+$/u, '')}`;
    assert.notEqual(registryKey.keyid, derivedKeyId);
  }
});

test('synthetic input mirrors the exact npm 11.16 keyed publish bundle shape', () => {
  for (const row of syntheticFixture.audit.verified) {
    assert.equal(row.attestationBundles.length, 2);
    const publish = row.attestationBundles.find(
      ({ predicateType }) => predicateType === PUBLISH_PREDICATE,
    );
    assert.equal(publish.bundle.mediaType,
      'application/vnd.dev.sigstore.bundle+json;version=0.2');
    assert.deepEqual(Object.keys(publish.bundle.verificationMaterial).sort(), [
      'publicKey', 'timestampVerificationData', 'tlogEntries',
    ]);
    assert.equal(publish.bundle.verificationMaterial.publicKey.hint, publishKeyId);
    assert.deepEqual(publish.bundle.verificationMaterial.timestampVerificationData,
      { rfc3161Timestamps: [] });
    const publishEntry = publish.bundle.verificationMaterial.tlogEntries[0];
    assert.deepEqual(publishEntry.kindVersion, { kind: 'dsse', version: '0.0.1' });
    assert.notEqual(publishEntry.logIndex, publishEntry.inclusionProof.logIndex);
    const logBody = JSON.parse(Buffer.from(
      publishEntry.canonicalizedBody,
      'base64',
    ).toString('utf8'));
    assert.deepEqual(Object.keys(logBody.spec).sort(), [
      'envelopeHash', 'payloadHash', 'signatures',
    ]);
    assert.equal(logBody.spec.signatures[0].signature,
      publish.bundle.dsseEnvelope.signatures[0].sig);
    assert.equal(Buffer.from(logBody.spec.signatures[0].verifier, 'base64').toString('utf8'),
      publishPublicKeyPem);
    const rekorEnvelope = {
      payload: publish.bundle.dsseEnvelope.payload,
      payloadType: publish.bundle.dsseEnvelope.payloadType,
      signatures: [{
        sig: publish.bundle.dsseEnvelope.signatures[0].sig,
        keyid: publish.bundle.dsseEnvelope.signatures[0].keyid,
      }],
    };
    assert.equal(logBody.spec.envelopeHash.value,
      sha256(Buffer.from(JSON.stringify(rekorEnvelope), 'utf8')).toString('hex'));
    const provenance = row.attestationBundles.find(
      ({ predicateType }) => predicateType === 'https://slsa.dev/provenance/v1',
    );
    const provenanceEntry = provenance.bundle.verificationMaterial.tlogEntries[0];
    assert.notEqual(provenanceEntry.logIndex, provenanceEntry.inclusionProof.logIndex);
    const statement = JSON.parse(Buffer.from(
      publish.bundle.dsseEnvelope.payload,
      'base64',
    ).toString('utf8'));
    assert.equal(statement._type, 'https://in-toto.io/Statement/v0.1');
    assert.equal(statement.subject[0].name, `pkg:npm/${row.name}@2.0.25`);
    assert.deepEqual(statement.predicate, {
      name: row.name,
      registry: 'https://registry.npmjs.org',
      version: '2.0.25',
    });
  }
});

test('signed release policy freezes immutable GitHub repository identities', () => {
  assert.equal(fixtureTrustPolicy.release.repositoryId, EXPECTED_REPOSITORY_ID);
  assert.equal(fixtureTrustPolicy.release.repositoryOwnerId, EXPECTED_REPOSITORY_OWNER_ID);
  assert.deepEqual(validateProvenanceTrustPolicy(clone(fixtureTrustPolicy)), fixtureTrustPolicy);

  for (const field of ['repositoryId', 'repositoryOwnerId']) {
    const wrong = clone(fixtureTrustPolicy);
    wrong.release[field] = '999999999';
    assert.throws(() => validateProvenanceTrustPolicy(wrong), /release binding/iu);

    const missing = clone(fixtureTrustPolicy);
    delete missing.release[field];
    assert.throws(() => validateProvenanceTrustPolicy(missing), /release.*exact keys/iu);
  }
});

test('requires exact immutable GitHub repository IDs in signed SLSA provenance', async (t) => {
  const cases = [
    ['wrong repository ID', /repository ID/iu, (github) => {
      github.repository_id = '999999999';
    }],
    ['missing repository ID', /GitHub parameters.*exact keys/iu, (github) => {
      delete github.repository_id;
    }],
    ['wrong repository owner ID', /repository owner ID/iu, (github) => {
      github.repository_owner_id = '999999999';
    }],
    ['missing repository owner ID', /GitHub parameters.*exact keys/iu, (github) => {
      delete github.repository_owner_id;
    }],
  ];
  for (const [name, pattern, mutate] of cases) {
    await t.test(name, () => {
      const input = validInput();
      mutateProvenanceStatement(input, (statement) => {
        mutate(statement.predicate.buildDefinition.internalParameters.github);
      });
      assert.throws(() => buildProvenanceEvidence(input), pattern);
    });
  }
});

test('requires exact Fulcio workflow identity, OIDC issuer, and code-signing usage', async (t) => {
  const cases = [
    ['missing legacy OIDC issuer', /OIDC issuer.*missing/iu, { issuer: null }],
    ['wrong legacy OIDC issuer', /OIDC issuer.*wrong/iu, {
      issuer: leafExtension(OID.issuer, Buffer.from('https://issuer.example.invalid', 'utf8')),
    }],
    ['duplicate legacy OIDC issuer', /duplicate.*1\.3\.6\.1\.4\.1\.57264\.1\.1/iu, {
      duplicates: [leafExtension(OID.issuer, Buffer.from(EXPECTED_OIDC_ISSUER, 'utf8'))],
    }],
    ['malformed legacy OIDC issuer', /OIDC issuer.*UTF-8|certificate identity/iu, {
      issuer: leafExtension(OID.issuer, Buffer.from([0xff])),
    }],
    ['critical legacy OIDC issuer', /OIDC issuer.*critical/iu, {
      issuer: leafExtension(OID.issuer, Buffer.from(EXPECTED_OIDC_ISSUER, 'utf8'), true),
    }],
    ['missing DER OIDC issuer', /OIDC issuer V2.*missing/iu, { issuerV2: null }],
    ['wrong DER OIDC issuer', /OIDC issuer V2.*wrong/iu, {
      issuerV2: leafExtension(OID.issuerV2, derUtf8String('https://issuer.example.invalid')),
    }],
    ['duplicate DER OIDC issuer', /duplicate.*1\.3\.6\.1\.4\.1\.57264\.1\.8/iu, {
      duplicates: [leafExtension(OID.issuerV2, derUtf8String(EXPECTED_OIDC_ISSUER))],
    }],
    ['malformed DER OIDC issuer', /OIDC issuer V2.*DER|certificate identity/iu, {
      issuerV2: leafExtension(OID.issuerV2, Buffer.from([0x0c, 0x01, 0xff])),
    }],
    ['missing workflow SAN', /workflow SAN.*missing|certificate identity/iu, {
      subjectAlternativeName: null,
    }],
    ['wrong workflow SAN', /workflow SAN.*wrong|certificate identity/iu, {
      subjectAlternativeName: leafExtension(
        OID.subjectAlternativeName,
        derSequence(der(0x86, Buffer.from('https://attacker.invalid/workflow', 'ascii'))),
        true,
      ),
    }],
    ['noncritical workflow SAN', /workflow SAN.*critical/iu, {
      subjectAlternativeName: leafExtension(
        OID.subjectAlternativeName,
        derSequence(der(0x86, Buffer.from(EXPECTED_WORKFLOW_IDENTITY, 'ascii'))),
      ),
    }],
    ['duplicate workflow SAN', /duplicate.*2\.5\.29\.17/iu, {
      duplicates: [leafExtension(
        OID.subjectAlternativeName,
        derSequence(der(0x86, Buffer.from(EXPECTED_WORKFLOW_IDENTITY, 'ascii'))),
        true,
      )],
    }],
    ['missing digital-signature key usage', /key usage.*missing/iu, { keyUsage: null }],
    ['noncritical digital-signature key usage', /key usage.*critical/iu, {
      keyUsage: leafExtension(OID.keyUsage, derBitString(Buffer.from([0x80]), 7)),
    }],
    ['wrong key usage', /key usage.*digital signature/iu, {
      keyUsage: leafExtension(OID.keyUsage, derBitString(Buffer.from([0x20]), 5), true),
    }],
    ['duplicate key usage', /duplicate.*2\.5\.29\.15/iu, {
      duplicates: [leafExtension(
        OID.keyUsage,
        derBitString(Buffer.from([0x80]), 7),
        true,
      )],
    }],
    ['missing code-signing EKU', /extended key usage.*missing/iu, {
      extendedKeyUsage: null,
    }],
    ['wrong extended key usage', /extended key usage.*code signing/iu, {
      extendedKeyUsage: leafExtension(
        OID.extendedKeyUsage,
        derSequence(derOid('1.3.6.1.5.5.7.3.2')),
      ),
    }],
    ['duplicate extended key usage', /duplicate.*2\.5\.29\.37/iu, {
      duplicates: [leafExtension(
        OID.extendedKeyUsage,
        derSequence(derOid(OID.codeSigning)),
      )],
    }],
  ];
  for (const [name, pattern, overrides] of cases) {
    await t.test(name, () => {
      const input = validInput();
      assert.throws(() => {
        replaceFulcioLeaf(input, overrides);
        buildProvenanceEvidence(input);
      }, pattern);
    });
  }
});

test('requires exact immutable Fulcio repository ID claims', async (t) => {
  for (const [name, pattern, overrides] of [
    ['missing repository ID', /certificate repository ID.*missing/iu, {
      repositoryId: null,
    }],
    ['wrong repository ID', /certificate repository ID.*wrong/iu, {
      repositoryId: leafExtension(
        OID.sourceRepositoryIdentifier,
        derUtf8String('999999999'),
      ),
    }],
    ['malformed repository ID', /certificate repository ID.*DER/iu, {
      repositoryId: leafExtension(
        OID.sourceRepositoryIdentifier,
        Buffer.from([0x0c, 0x01, 0xff]),
      ),
    }],
    ['duplicate repository ID', /duplicate.*1\.3\.6\.1\.4\.1\.57264\.1\.15/iu, {
      duplicates: [leafExtension(
        OID.sourceRepositoryIdentifier,
        derUtf8String(EXPECTED_REPOSITORY_ID),
      )],
    }],
    ['missing repository owner ID', /certificate repository owner ID.*missing/iu, {
      repositoryOwnerId: null,
    }],
    ['wrong repository owner ID', /certificate repository owner ID.*wrong/iu, {
      repositoryOwnerId: leafExtension(
        OID.sourceRepositoryOwnerIdentifier,
        derUtf8String('999999999'),
      ),
    }],
    ['malformed repository owner ID', /certificate repository owner ID.*DER/iu, {
      repositoryOwnerId: leafExtension(
        OID.sourceRepositoryOwnerIdentifier,
        Buffer.from([0x0c, 0x01, 0xff]),
      ),
    }],
    ['duplicate repository owner ID', /duplicate.*1\.3\.6\.1\.4\.1\.57264\.1\.17/iu, {
      duplicates: [leafExtension(
        OID.sourceRepositoryOwnerIdentifier,
        derUtf8String(EXPECTED_REPOSITORY_OWNER_ID),
      )],
    }],
  ]) {
    await t.test(name, () => {
      const input = validInput();
      assert.throws(() => {
        replaceFulcioLeaf(input, overrides);
        buildProvenanceEvidence(input);
      }, pattern);
    });
  }
});

test('builds deterministic sanitized JCS evidence and revalidates it offline', () => {
  const evidence = buildProvenanceEvidence(validInput());

  assert.deepEqual(Object.keys(evidence).sort(), [
    'commit', 'packages', 'repository', 'run', 'schemaVersion', 'sourceTag', 'workflow',
  ]);
  assert.equal(evidence.schemaVersion, 1);
  assert.equal(evidence.commit, fixture.expected.commit);
  assert.equal(evidence.repository, fixture.expected.repository);
  assert.equal(evidence.sourceTag, fixture.expected.sourceTag);
  assert.deepEqual(evidence.run, {
    attempts: [1, 2],
    correlation: '00112233445566778899aabbccddeeff',
    finalAttempt: 2,
    id: '9876543210',
  });
  assert.deepEqual(evidence.workflow, {
    identity: 'https://github.com/DigitalArsenal/hd-wallet-wasm/.github/workflows/npm-publish.yml@refs/tags/v2.0.25',
    name: 'npm-publish.yml',
    path: '.github/workflows/npm-publish.yml',
    ref: 'refs/tags/v2.0.25',
  });
  assert.deepEqual(evidence.packages.map(({ name }) => name), [
    'hd-wallet-ui', 'hd-wallet-wasm',
  ]);

  for (const entry of evidence.packages) {
    assert.deepEqual(Object.keys(entry).sort(), [
      'attestations', 'integrity', 'name', 'provenance', 'registrySignature',
      'run', 'subject', 'tarball', 'version',
    ]);
    assert.equal(entry.version, '2.0.25');
    assert.deepEqual(Object.keys(entry.tarball).sort(), ['sha512', 'url']);
    assert.match(entry.tarball.sha512, /^[0-9a-f]{128}$/u);
    assert.equal(entry.subject.digest.sha512, entry.tarball.sha512);
    assert.equal(entry.run.id, evidence.run.id);
    assert.ok(evidence.run.attempts.includes(entry.run.attempt));
    assert.deepEqual(Object.keys(entry.registrySignature).sort(), ['key', 'signature']);
    assert.deepEqual(Object.keys(entry.provenance).sort(), [
      'bundle', 'predicateType', 'statement', 'trust',
    ]);
    assert.equal(entry.provenance.trust.certificateChain.certificates.length, 2);
  }

  assert.deepEqual(verifyProvenanceEvidence(clone(evidence)), evidence);
  const serialized = serializeProvenanceEvidence(evidence);
  assert.equal(serialized, `${canonicalizeJson(evidence)}\n`);
  assert.equal(serialized.endsWith('\n\n'), false);
  assert.equal(serializeProvenanceEvidence(buildProvenanceEvidence(validInput())), serialized);
  assert.deepEqual(JSON.parse(serialized), evidence);
  assert.equal(serialized.includes('node_modules/'), false);
  assert.equal(serialized.includes('/tmp/'), false);
  assertForbiddenKeysAbsent(evidence);
});

test('validates either exact package independently for idempotent same-run recovery', () => {
  const complete = buildProvenanceEvidence(validInput());
  for (const packageName of ['hd-wallet-ui', 'hd-wallet-wasm']) {
    const input = validInput();
    input.packageLock.packages[''].dependencies = { [packageName]: '2.0.25' };
    if (packageName === 'hd-wallet-wasm') {
      delete input.packageLock.packages['node_modules/hd-wallet-ui'];
    }
    const packageEvidence = verifyPackageProvenanceEvidence({
      auditRow: clone(auditRow(input, packageName)),
      commit: input.commit,
      packageLock: input.packageLock,
      packageName,
      registryEvidence: clone(input.registryEvidence[packageName]),
      repository: input.repository,
      runMetadata: input.runMetadata,
      sourceTag: input.sourceTag,
      workflow: input.workflow,
    });
    assert.deepEqual(packageEvidence,
      complete.packages.find(({ name }) => name === packageName));
  }

  const unknown = validInput();
  assert.throws(() => verifyPackageProvenanceEvidence({
    auditRow: clone(auditRow(unknown)),
    commit: unknown.commit,
    packageLock: unknown.packageLock,
    packageName: 'not-the-wallet',
    registryEvidence: clone(unknown.registryEvidence['hd-wallet-wasm']),
    repository: unknown.repository,
    runMetadata: unknown.runMetadata,
    sourceTag: unknown.sourceTag,
    workflow: unknown.workflow,
  }), /package name/iu);

  const tampered = validInput();
  tampered.registryEvidence['hd-wallet-wasm'].dist.signatures[0].sig =
    flipBase64(tampered.registryEvidence['hd-wallet-wasm'].dist.signatures[0].sig);
  assert.throws(() => verifyPackageProvenanceEvidence({
    auditRow: clone(auditRow(tampered)),
    commit: tampered.commit,
    packageLock: tampered.packageLock,
    packageName: 'hd-wallet-wasm',
    registryEvidence: clone(tampered.registryEvidence['hd-wallet-wasm']),
    repository: tampered.repository,
    runMetadata: tampered.runMetadata,
    sourceTag: tampered.sourceTag,
    workflow: tampered.workflow,
  }), /registry signature.*invalid/iu);

  const incomplete = validInput();
  incomplete.audit.verified = [auditRow(incomplete, 'hd-wallet-wasm')];
  assert.throws(() => buildProvenanceEvidence(incomplete), /hd-wallet-ui.*audit row/iu);
});

test('requires and cryptographically verifies npm publish proof before excluding it', () => {
  const input = validInput();
  const evidence = buildProvenanceEvidence(input);
  assert.equal(JSON.stringify(evidence).includes(PUBLISH_PREDICATE), false);

  const tampered = validInput();
  publishBundle(tampered).dsseEnvelope.signatures[0].sig =
    flipBase64(publishBundle(tampered).dsseEnvelope.signatures[0].sig);
  assert.throws(() => buildProvenanceEvidence(tampered), /publish.*signature|transparency/iu);
});

test('requires exactly one SLSA v1 and one npm publish v0.1 bundle', () => {
  const missing = validInput();
  auditRow(missing).attestationBundles = auditRow(missing).attestationBundles.filter(
    ({ predicateType }) => predicateType !== PUBLISH_PREDICATE,
  );
  assert.throws(() => buildProvenanceEvidence(missing),
    /exactly one SLSA v1 and one npm publish v0\.1/iu);

  const duplicate = validInput();
  auditRow(duplicate).attestationBundles.push(clone(
    auditRow(duplicate).attestationBundles.find(
      ({ predicateType }) => predicateType === PUBLISH_PREDICATE,
    ),
  ));
  assert.throws(() => buildProvenanceEvidence(duplicate),
    /exactly one SLSA v1 and one npm publish v0\.1/iu);

  const extraKey = validInput();
  extraKey.registryEvidence['hd-wallet-wasm'].registryKeys.push({
    keyid: `SHA256:${'A'.repeat(43)}`,
    publicKeyPem: publishPublicKeyPem,
  });
  assert.throws(() => buildProvenanceEvidence(extraKey), /registry keys.*exactly bound/iu);
});

test('accepts one deduplicated public key for production npm signature and attestation usages', () => {
  const input = validInput();
  for (const row of input.audit.verified) {
    const registry = input.registryEvidence[row.name];
    registry.registryKeys = [{ keyid: publishKeyId, publicKeyPem: publishPublicKeyPem }];
    registry.dist.signatures = [{
      keyid: publishKeyId,
      sig: signData(
        'sha256',
        Buffer.from(`${row.name}@2.0.25:${registry.dist.integrity}`, 'utf8'),
        publishPrivateKey,
      ).toString('base64'),
    }];
  }
  const policy = clone(fixtureTrustPolicy);
  const signaturePolicy = policy.npmRegistryKeys.find(
    ({ keyUsage }) => keyUsage === 'npm:signatures',
  );
  signaturePolicy.keyid = publishKeyId;
  signaturePolicy.publicKeySha256 = createHash('sha256')
    .update(publishPublicKeyDer).digest('hex');
  assert.deepEqual(buildProvenanceEvidenceWithPolicy(input, policy)
    .packages.map(({ name }) => name), ['hd-wallet-ui', 'hd-wallet-wasm']);
});

test('rejects validly re-signed npm publish statements with wrong exact bindings', async (t) => {
  const cases = [
    ['statement type', /publish statement type/iu,
      (statement) => { statement._type = 'https://in-toto.io/Statement/v1'; }],
    ['predicate type', /publish predicate type/iu,
      (statement) => { statement.predicateType = 'https://example.invalid/publish'; }],
    ['subject name', /publish subject name/iu,
      (statement) => { statement.subject[0].name = 'pkg:npm/not-the-wallet@2.0.25'; }],
    ['subject digest', /publish subject digest/iu,
      (statement) => { statement.subject[0].digest.sha512 = '0'.repeat(128); }],
    ['package name', /publish package name/iu,
      (statement) => { statement.predicate.name = 'not-the-wallet'; }],
    ['package version', /publish package version/iu,
      (statement) => { statement.predicate.version = '2.0.21'; }],
    ['registry', /publish registry/iu,
      (statement) => { statement.predicate.registry = 'https://registry.example.invalid'; }],
  ];
  for (const [name, pattern, mutate] of cases) {
    await t.test(name, () => {
      const input = validInput();
      replacePublishBundle(input, mutate);
      assert.throws(() => buildProvenanceEvidence(input), pattern);
    });
  }
});

test('authorizes the npm attestation key at the publish bundle integrated time', () => {
  const input = validInput();
  const integratedTime = Number(publishBundle(input)
    .verificationMaterial.tlogEntries[0].integratedTime) * 1000;
  const beginsAtPublish = clone(fixtureTrustPolicy);
  beginsAtPublish.npmRegistryKeys.find(({ keyUsage }) => keyUsage === 'npm:attestations')
    .validFor.start = new Date(integratedTime).toISOString();
  assert.doesNotThrow(() => buildProvenanceEvidenceWithPolicy(input, beginsAtPublish));

  const expiresAtPublish = clone(fixtureTrustPolicy);
  expiresAtPublish.npmRegistryKeys.find(({ keyUsage }) => keyUsage === 'npm:attestations')
    .validFor.end = new Date(integratedTime).toISOString();
  assert.throws(() => buildProvenanceEvidenceWithPolicy(input, expiresAtPublish),
    /npm:attestations key.*trust policy/iu);
});

test('cryptographically rejects keyed publish Rekor proof and policy tampering', async (t) => {
  const cases = [
    ['keyed envelope binding', /envelope hash/iu, (input) => {
      const entry = publishBundle(input).verificationMaterial.tlogEntries[0];
      const body = JSON.parse(Buffer.from(entry.canonicalizedBody, 'base64').toString('utf8'));
      const envelope = publishBundle(input).dsseEnvelope;
      body.spec.envelopeHash.value = sha256(Buffer.from(JSON.stringify({
        payload: envelope.payload,
        payloadType: envelope.payloadType,
        signatures: [{ sig: envelope.signatures[0].sig }],
      }), 'utf8')).toString('hex');
      entry.canonicalizedBody = Buffer.from(canonicalizeJson(body), 'utf8').toString('base64');
    }],
    ['public-key verifier', /public key|verifier/iu, (input) => {
      const entry = publishBundle(input).verificationMaterial.tlogEntries[0];
      const body = JSON.parse(Buffer.from(entry.canonicalizedBody, 'base64').toString('utf8'));
      body.spec.signatures[0].verifier = Buffer.from(logPublicKeyPem, 'utf8').toString('base64');
      entry.canonicalizedBody = Buffer.from(canonicalizeJson(body), 'utf8').toString('base64');
    }],
    ['transparency body', /publish transparency log body/iu, (input) => {
      const entry = publishBundle(input).verificationMaterial.tlogEntries[0];
      entry.canonicalizedBody = flipBase64(entry.canonicalizedBody);
    }],
    ['inclusion promise', /inclusion promise/iu, (input) => {
      const promise = publishBundle(input).verificationMaterial.tlogEntries[0].inclusionPromise;
      promise.signedEntryTimestamp = flipBase64(promise.signedEntryTimestamp);
    }],
    ['inclusion root', /inclusion proof/iu, (input) => {
      const proof = publishBundle(input).verificationMaterial.tlogEntries[0].inclusionProof;
      proof.rootHash = flipBase64(proof.rootHash);
    }],
    ['checkpoint', /checkpoint/iu, (input) => {
      const checkpoint = publishBundle(input)
        .verificationMaterial.tlogEntries[0].inclusionProof.checkpoint;
      checkpoint.envelope = checkpoint.envelope.replace(
        'synthetic.rekor.invalid', 'synthetic.rekor.changed',
      );
    }],
  ];
  for (const [name, pattern, mutate] of cases) {
    await t.test(name, () => {
      const input = validInput();
      mutate(input);
      assert.throws(() => buildProvenanceEvidence(input), pattern);
    });
  }

  await t.test('signed-policy attestation key', () => {
    const policy = clone(fixtureTrustPolicy);
    policy.npmRegistryKeys.find(({ keyUsage }) => keyUsage === 'npm:attestations')
      .publicKeySha256 = '0'.repeat(64);
    assert.throws(() => buildProvenanceEvidenceWithPolicy(validInput(), policy),
      /npm:attestations key.*trust policy/iu);
  });
});

test('accepts npm 11.16 Sigstore v0.3 empty key hint and timestamp-array shape', () => {
  const input = validInput();
  for (const row of input.audit.verified) {
    const provenance = row.attestationBundles.find(
      ({ predicateType }) => predicateType === 'https://slsa.dev/provenance/v1',
    );
    provenance.bundle.dsseEnvelope.signatures[0].keyid = '';
    provenance.bundle.verificationMaterial.timestampVerificationData = {
      rfc3161Timestamps: [],
    };
  }
  assert.deepEqual(buildProvenanceEvidence(input).packages.map(({ name }) => name), [
    'hd-wallet-ui', 'hd-wallet-wasm',
  ]);
});

test('rejects malformed, missing, duplicate, and npm-schema-drifted evidence', async (t) => {
  const cases = [
    ['unknown audit field', /audit.*exact keys/iu, (input) => { input.audit.extra = true; }],
    ['nonempty invalid list', /audit invalid/iu, (input) => { input.audit.invalid.push({ code: 'EATTESTATIONVERIFY' }); }],
    ['nonempty missing list', /audit missing/iu, (input) => { input.audit.missing.push({ name: 'hd-wallet-wasm' }); }],
    ['unknown verified-row field', /verified row.*exact keys/iu, (input) => { auditRow(input).resolved = 'https://example.invalid/a.tgz'; }],
    ['missing package row', /exactly one audit row/iu, (input) => { input.audit.verified = input.audit.verified.filter(({ name }) => name !== 'hd-wallet-wasm'); }],
    ['duplicate package row', /exactly one audit row/iu, (input) => { input.audit.verified.push(clone(auditRow(input))); }],
    ['wrong version', /exact package version/iu, (input) => { auditRow(input).version = '2.0.21'; }],
    ['missing registry signature', /exactly one registry signature/iu, (input) => { input.registryEvidence['hd-wallet-wasm'].dist.signatures = []; }],
    ['duplicate registry signature', /exactly one registry signature/iu, (input) => { input.registryEvidence['hd-wallet-wasm'].dist.signatures.push(clone(input.registryEvidence['hd-wallet-wasm'].dist.signatures[0])); }],
    ['invalid registry signature', /registry signature.*invalid/iu, (input) => { const signature = input.registryEvidence['hd-wallet-wasm'].dist.signatures[0]; signature.sig = flipBase64(signature.sig); }],
    ['wrong registry key', /registry signature.*invalid/iu, (input) => {
      const evidence = input.registryEvidence['hd-wallet-wasm'];
      evidence.registryKeys[0] = {
        keyid: `SHA256:${evidence.sigstoreTrust.transparencyLog.logId.replace(/=+$/u, '')}`,
        publicKeyPem: evidence.sigstoreTrust.transparencyLog.publicKeyPem,
      };
      evidence.dist.signatures[0].keyid = evidence.registryKeys[0].keyid;
    }],
    ['missing provenance', /exactly one SLSA v1 and one npm publish/iu, (input) => { auditRow(input).attestationBundles = []; }],
    ['duplicate provenance', /exactly one SLSA v1 and one npm publish/iu, (input) => { auditRow(input).attestationBundles.push(clone(auditRow(input).attestationBundles[0])); }],
    ['nonempty DSSE key hint', /DSSE signature key hint must be empty/iu, (input) => { auditRow(input).attestationBundles[0].bundle.dsseEnvelope.signatures[0].keyid = 'unexpected'; }],
    ['nonempty RFC 3161 timestamps', /RFC 3161 timestamps must be empty/iu, (input) => { auditRow(input).attestationBundles[0].bundle.verificationMaterial.timestampVerificationData = { rfc3161Timestamps: [{}] }; }],
    ['missing certificate chain', /Sigstore trust material.*exact keys/iu, (input) => { delete input.registryEvidence['hd-wallet-wasm'].sigstoreTrust.certificateChain; }],
    ['wrong predicate type', /exactly one SLSA v1 and one npm publish|provenance predicate type/iu, (input) => { auditRow(input).attestationBundles[0].predicateType = 'https://example.invalid/predicate'; }],
    ['dist/audit attestation mismatch', /registry attestations URL|attestations metadata/iu, (input) => { input.registryEvidence['hd-wallet-wasm'].dist.attestations.url += '?changed=1'; }],
    ['integrity mismatch', /integrity.*package lock/iu, (input) => { input.registryEvidence['hd-wallet-wasm'].dist.integrity = input.registryEvidence['hd-wallet-ui'].dist.integrity; }],
    ['tarball mismatch', /tarball.*package lock/iu, (input) => { input.registryEvidence['hd-wallet-wasm'].dist.tarball += '?changed=1'; }],
    ['workflow tarball mismatch', /workflow tarball.*integrity/iu, (input) => { input.registryEvidence['hd-wallet-wasm'].workflowTarball.sha512 = '0'.repeat(128); }],
    ['UI dependency drift', /exact core dependency/iu, (input) => { input.packageLock.packages['node_modules/hd-wallet-ui'].dependencies['hd-wallet-wasm'] = '^2.0.25'; }],
    ['run attempts out of order', /strictly increasing/iu, (input) => { input.runMetadata.attempts = [2, 1]; }],
    ['duplicate run attempt', /strictly increasing/iu, (input) => { input.runMetadata.attempts = [1, 1, 2]; }],
    ['wrong final run attempt', /finalAttempt.*last/iu, (input) => { input.runMetadata.finalAttempt = 1; }],
    ['wrong run commit', /run metadata commit/iu, (input) => { input.runMetadata.commit = 'f'.repeat(40); }],
  ];

  for (const [name, pattern, mutate] of cases) {
    await t.test(name, () => {
      const input = validInput();
      mutate(input);
      assert.throws(() => buildProvenanceEvidence(input), pattern);
    });
  }
});

test('rejects validly signed provenance with wrong release bindings', async (t) => {
  const cases = [
    ['wrong repository', 'wrongRepository', /source repository/iu],
    ['wrong source ref', 'wrongSourceRef', /source ref/iu],
    ['wrong workflow', 'wrongWorkflow', /workflow path/iu],
    ['wrong commit', 'wrongCommit', /source commit/iu],
    ['wrong subject name', 'wrongSubjectName', /subject name/iu],
    ['wrong subject digest', 'wrongSubjectDigest', /subject digest/iu],
    ['wrong run ID', 'wrongRunId', /run ID/iu],
    ['unrecorded run attempt', 'wrongRunAttempt', /run attempt.*recorded/iu],
    ['wrong certificate workflow identity', 'wrongCertificateIdentity', /certificate (?:identity|workflow SAN)/iu],
  ];

  for (const [name, variant, pattern] of cases) {
    await t.test(name, () => {
      const input = validInput();
      replaceBundle(input, variant);
      assert.throws(() => buildProvenanceEvidence(input), pattern);
    });
  }
});

test('cryptographically rejects DSSE, certificate, and transparency-log tampering', async (t) => {
  const cases = [
    ['DSSE signature', /DSSE signature|envelope hash/iu, (input) => {
      const signature = bundle(input).dsseEnvelope.signatures[0];
      signature.sig = flipBase64(signature.sig);
    }],
    ['certificate bytes', /certificate/iu, (input) => {
      const certificate = bundle(input).verificationMaterial.certificate;
      certificate.rawBytes = flipBase64(certificate.rawBytes);
    }],
    ['certificate authority', /certificate chain/iu, (input) => {
      const authority = input.registryEvidence['hd-wallet-wasm']
        .sigstoreTrust.certificateChain.certificates[1];
      authority.rawBytes = flipBase64(authority.rawBytes);
    }],
    ['transparency body', /transparency log body/iu, (input) => {
      const entry = bundle(input).verificationMaterial.tlogEntries[0];
      entry.canonicalizedBody = flipBase64(entry.canonicalizedBody);
    }],
    ['transparency inclusion promise', /inclusion promise/iu, (input) => {
      const promise = bundle(input).verificationMaterial.tlogEntries[0].inclusionPromise;
      promise.signedEntryTimestamp = flipBase64(promise.signedEntryTimestamp);
    }],
    ['transparency inclusion root', /inclusion proof/iu, (input) => {
      const proof = bundle(input).verificationMaterial.tlogEntries[0].inclusionProof;
      proof.rootHash = flipBase64(proof.rootHash);
    }],
    ['transparency checkpoint', /checkpoint/iu, (input) => {
      const checkpoint = bundle(input).verificationMaterial.tlogEntries[0].inclusionProof.checkpoint;
      checkpoint.envelope = checkpoint.envelope.replace('synthetic.rekor.invalid', 'synthetic.rekor.changed');
    }],
    ['transparency key', /transparency log/iu, (input) => {
      const log = input.registryEvidence['hd-wallet-wasm'].sigstoreTrust.transparencyLog;
      log.publicKeyPem = input.registryEvidence['hd-wallet-wasm'].registryKeys[0].publicKeyPem;
    }],
  ];

  for (const [name, pattern, mutate] of cases) {
    await t.test(name, () => {
      const input = validInput();
      mutate(input);
      assert.throws(() => buildProvenanceEvidence(input), pattern);
    });
  }
});

test('offline verification requires signed-policy npm, Fulcio, and Rekor anchors', async (t) => {
  const evidence = buildProvenanceEvidence(validInput());
  const cases = [
    ['npm key', /trust policy.*npm|npm.*trust policy/iu, (policy) => {
      policy.npmRegistryKeys.find(({ keyUsage }) => keyUsage === 'npm:signatures')
        .publicKeySha256 = '0'.repeat(64);
    }],
    ['Fulcio root', /trust policy.*certificate|certificate.*trust policy/iu, (policy) => {
      policy.sigstoreCertificateAuthorities[0].rootCertificateSha256 = '0'.repeat(64);
    }],
    ['Rekor key', /trust policy.*transparency|transparency.*trust policy/iu, (policy) => {
      policy.sigstoreTransparencyLogs[0].publicKeySha256 = '0'.repeat(64);
    }],
    ['expired authorization', /valid|trust policy/iu, (policy) => {
      policy.npmRegistryKeys.find(({ keyUsage }) => keyUsage === 'npm:signatures')
        .validFor.end = '2001-01-01T00:00:00.000Z';
    }],
  ];
  for (const [name, pattern, mutate] of cases) {
    await t.test(name, () => {
      const policy = clone(fixtureTrustPolicy);
      mutate(policy);
      assert.throws(() => verifyProvenanceEvidenceWithPolicy(clone(evidence), policy), pattern);
    });
  }
});

test('offline normalized-evidence verifier rejects post-generation tampering', async (t) => {
  const baseline = buildProvenanceEvidence(validInput());
  const cases = [
    ['repository', /source repository/iu, (value) => { value.repository = 'https://github.com/attacker/repo'; }],
    ['integrity', /tarball SHA-512|registry signature.*invalid/iu, (value) => { value.packages[0].integrity = value.packages[1].integrity; }],
    ['subject', /subject digest/iu, (value) => { value.packages[0].subject.digest.sha512 = '0'.repeat(128); }],
    ['duplicate package', /exactly two package records/iu, (value) => { value.packages.push(clone(value.packages[0])); }],
    ['run attempt', /run attempt.*recorded/iu, (value) => { value.packages[0].run.attempt = 9; }],
  ];
  for (const [name, pattern, mutate] of cases) {
    await t.test(name, () => {
      const value = clone(baseline);
      mutate(value);
      assert.throws(() => verifyProvenanceEvidence(value), pattern);
    });
  }
});

test('CLI accepts only strict local inputs and emits no source paths', () => {
  const directory = mkdtempSync(join(tmpdir(), 'sdn-provenance-test-'));
  try {
    const paths = {
      audit: join(directory, 'npm-signatures.json'),
      core: join(directory, 'core-registry-evidence.json'),
      ui: join(directory, 'ui-registry-evidence.json'),
      lock: join(directory, 'package-lock.json'),
      policy: join(directory, 'provenance-trust.json'),
      run: join(directory, 'run-metadata.json'),
    };
    writeFileSync(paths.audit, `${JSON.stringify(syntheticFixture.audit)}\n`);
    writeFileSync(paths.core,
      `${JSON.stringify(syntheticFixture.registryEvidence['hd-wallet-wasm'])}\n`);
    writeFileSync(paths.ui,
      `${JSON.stringify(syntheticFixture.registryEvidence['hd-wallet-ui'])}\n`);
    writeFileSync(paths.lock, `${JSON.stringify(fixture.packageLock)}\n`);
    writeFileSync(paths.policy, `${JSON.stringify(fixtureTrustPolicy)}\n`);
    writeFileSync(paths.run, `${JSON.stringify(fixture.runMetadata)}\n`);
    const result = spawnSync(process.execPath, [
      scriptPath,
      paths.audit,
      '--core-attestations', paths.core,
      '--ui-attestations', paths.ui,
      '--package-lock', paths.lock,
      '--run-metadata', paths.run,
      '--trust-policy', paths.policy,
      '--repository', fixture.expected.repository,
      '--workflow', fixture.expected.workflow,
      '--tag', fixture.expected.sourceTag,
      '--commit', fixture.expected.commit,
    ], { encoding: 'utf8' });

    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    assert.equal(result.stdout, serializeProvenanceEvidence(buildProvenanceEvidence(validInput())));
    assert.equal(result.stdout.includes(directory), false);

    writeFileSync(paths.audit, '{"invalid":[],"invalid":[],"missing":[],"verified":[]}\n');
    const duplicate = spawnSync(process.execPath, [
      scriptPath,
      paths.audit,
      '--core-attestations', paths.core,
      '--ui-attestations', paths.ui,
      '--package-lock', paths.lock,
      '--run-metadata', paths.run,
      '--trust-policy', paths.policy,
      '--repository', fixture.expected.repository,
      '--workflow', fixture.expected.workflow,
      '--tag', fixture.expected.sourceTag,
      '--commit', fixture.expected.commit,
    ], { encoding: 'utf8' });
    assert.notEqual(duplicate.status, 0);
    assert.match(duplicate.stderr, /duplicate JSON object key/iu);

    writeFileSync(paths.audit, `${JSON.stringify(syntheticFixture.audit)}\n`);
    writeFileSync(paths.core,
      `${JSON.stringify(fixture.registryEvidence['hd-wallet-wasm'].dist.attestations)}\n`);
    const insufficient = spawnSync(process.execPath, [
      scriptPath,
      paths.audit,
      '--core-attestations', paths.core,
      '--ui-attestations', paths.ui,
      '--package-lock', paths.lock,
      '--run-metadata', paths.run,
      '--trust-policy', paths.policy,
      '--repository', fixture.expected.repository,
      '--workflow', fixture.expected.workflow,
      '--tag', fixture.expected.sourceTag,
      '--commit', fixture.expected.commit,
    ], { encoding: 'utf8' });
    assert.notEqual(insufficient.status, 0);
    assert.match(insufficient.stderr, /registry evidence.*exact keys/iu);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('CLI verifies one exact package for an idempotent same-run recovery', () => {
  const directory = mkdtempSync(join(tmpdir(), 'sdn-provenance-package-test-'));
  try {
    const name = 'hd-wallet-ui';
    const packageLock = clone(fixture.packageLock);
    delete packageLock.packages[''].dependencies['hd-wallet-wasm'];
    const paths = {
      audit: join(directory, 'npm-signatures.json'),
      evidence: join(directory, 'registry-evidence.json'),
      lock: join(directory, 'package-lock.json'),
      policy: join(directory, 'provenance-trust.json'),
      run: join(directory, 'run-metadata.json'),
    };
    writeFileSync(paths.audit, `${JSON.stringify(syntheticFixture.audit)}\n`);
    writeFileSync(paths.evidence,
      `${JSON.stringify(syntheticFixture.registryEvidence[name])}\n`);
    writeFileSync(paths.lock, `${JSON.stringify(packageLock)}\n`);
    writeFileSync(paths.policy, `${JSON.stringify(fixtureTrustPolicy)}\n`);
    writeFileSync(paths.run, `${JSON.stringify(fixture.runMetadata)}\n`);
    const result = spawnSync(process.execPath, [
      scriptPath,
      paths.audit,
      '--package', name,
      '--registry-attestations', paths.evidence,
      '--package-lock', paths.lock,
      '--run-metadata', paths.run,
      '--trust-policy', paths.policy,
      '--repository', fixture.expected.repository,
      '--workflow', fixture.expected.workflow,
      '--tag', fixture.expected.sourceTag,
      '--commit', fixture.expected.commit,
    ], { encoding: 'utf8' });

    const expected = verifyPackageProvenanceEvidence({
      auditRow: auditRow(validInput(), name),
      commit: fixture.expected.commit,
      packageLock,
      packageName: name,
      registryEvidence: syntheticFixture.registryEvidence[name],
      repository: fixture.expected.repository,
      runMetadata: fixture.runMetadata,
      sourceTag: fixture.expected.sourceTag,
      workflow: fixture.expected.workflow,
    });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stderr, '');
    assert.equal(result.stdout, `${canonicalizeJson(expected)}\n`);

    const badAudit = clone(syntheticFixture.audit);
    badAudit.invalid.push({ name: 'transitive-package' });
    writeFileSync(paths.audit, `${JSON.stringify(badAudit)}\n`);
    const invalid = spawnSync(process.execPath, [
      scriptPath,
      paths.audit,
      '--package', name,
      '--registry-attestations', paths.evidence,
      '--package-lock', paths.lock,
      '--run-metadata', paths.run,
      '--trust-policy', paths.policy,
      '--repository', fixture.expected.repository,
      '--workflow', fixture.expected.workflow,
      '--tag', fixture.expected.sourceTag,
      '--commit', fixture.expected.commit,
    ], { encoding: 'utf8' });
    assert.notEqual(invalid.status, 0);
    assert.match(invalid.stderr, /audit invalid list must be empty/iu);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});

test('implementation has no network, subprocess, environment, or credential input path', () => {
  const source = readFileSync(scriptPath, 'utf8');
  assert.doesNotMatch(source, /node:(?:http|https|net|tls|child_process)/u);
  assert.doesNotMatch(source, /\bfetch\s*\(/u);
  assert.doesNotMatch(source, /process\.env/u);
  assert.equal(source.split(EXPECTED_OIDC_ISSUER).length - 1, 1);
  assert.doesNotMatch(source.replace(EXPECTED_OIDC_ISSUER, ''), /cookie|credential|token/iu);
});

test('JCS serializer rejects sparse arrays instead of collapsing them', () => {
  assert.throws(() => canonicalizeJson(Array(1)), /dense array/iu);
});

test('JCS serializer rejects non-plain objects instead of erasing their value', () => {
  assert.throws(() => canonicalizeJson(new Date(0)), /plain JSON object/iu);
});
