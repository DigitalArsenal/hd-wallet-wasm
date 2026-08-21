import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  sign as signData,
} from 'node:crypto';
import {
  mkdir,
  mkdtemp,
  readFile,
  readdir,
  realpath,
  rm,
  stat,
  symlink,
  writeFile,
} from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { brotliDecompressSync } from 'node:zlib';

import {
  buildRegistryEvidenceEnvelope,
  buildRegistryEvidenceEnvelopes,
  parseProvenanceInputArguments,
} from '../../scripts/collect-provenance-inputs.mjs';
import { canonicalizeJson } from '../../scripts/verify-provenance-evidence.mjs';

const fixture = JSON.parse(await readFile(new URL(
  './fixtures/npm-audit-signatures.v11.16.0.json',
  import.meta.url,
)));
const PUBLISH_PREDICATE =
  'https://github.com/npm/attestation/tree/main/specs/publish/v0.1';
// Deterministic test-only fixture keys. They protect no production identity or material.
const PUBLISH_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgecpeZyPEcJu4OvGO
XWUDxzSe3rworLMiSoJUkavc3IihRANCAAT6owBD8pkBRuzA2rRiCPrl4pDRYUaM
fKsqQVTmeciNdlIV20e8EjGUfi/pJ0lGfaJ/D0omIKE6H5GrWi+QMxdh
-----END PRIVATE KEY-----
`;
const LOG_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgPcnHS2MCf26r2HEs
tmdtpI2Kwb+ir9r+BnUMmFfQEUKhRANCAATqc9WaNhUFLzedVJwPfwYhAlYmiJ5G
/TG1/ObRho28TFOMkKw/8gF5WKRxJCSNCEbF7Jeb9lbPAkOsQXcTDpNE
-----END PRIVATE KEY-----
`;
const publishPrivateKey = createPrivateKey(PUBLISH_PRIVATE_KEY_PEM);
const publishPublicKey = createPublicKey(publishPrivateKey);
const publishPublicKeyPem = publishPublicKey.export({ type: 'spki', format: 'pem' }).toString();
const publishPublicKeyDer = publishPublicKey.export({ type: 'spki', format: 'der' });
const publishKeyId = `SHA256:${createHash('sha256').update(publishPublicKeyDer)
  .digest('base64').replace(/=+$/u, '')}`;
const logPrivateKey = createPrivateKey(LOG_PRIVATE_KEY_PEM);
const logPublicKey = createPublicKey(logPrivateKey);
const logPublicKeyPem = logPublicKey.export({ type: 'spki', format: 'pem' }).toString();
const logPublicKeyDer = logPublicKey.export({ type: 'spki', format: 'der' });
const logId = createHash('sha256').update(logPublicKeyDer).digest('base64');
const execFileAsync = promisify(execFile);
const collectorPath = fileURLToPath(new URL(
  '../../scripts/collect-provenance-inputs.mjs',
  import.meta.url,
));
const TUF_MIRROR = 'https://tuf-repo-cdn.sigstore.dev';
const FROZEN_TUF_ROOT_BROTLI_BASE64 = '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';

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
    'sha256', Buffer.from(canonicalizeJson(promisePayload), 'utf8'), logPrivateKey,
  ).toString('base64');
  const proof = entry.inclusionProof;
  const note = `synthetic.rekor.invalid\n${proof.treeSize}\n${proof.rootHash}\n`;
  const signature = signData('sha256', Buffer.from(note, 'utf8'), logPrivateKey);
  const signed = Buffer.concat([Buffer.from(logId, 'base64').subarray(0, 4), signature]);
  proof.checkpoint.envelope = `${note}\n— synthetic.rekor.invalid ${signed.toString('base64')}\n`;
}

function buildPublishBundle({ integratedTime, name, sha512 }) {
  const statement = {
    _type: 'https://in-toto.io/Statement/v0.1',
    predicate: { name, registry: 'https://registry.npmjs.org', version: '2.0.30' },
    predicateType: PUBLISH_PREDICATE,
    subject: [{ digest: { sha512 }, name: `pkg:npm/${name}@2.0.30` }],
  };
  const payloadType = 'application/vnd.in-toto+json';
  const payload = Buffer.from(canonicalizeJson(statement), 'utf8');
  const sig = signData(
    'sha256', dssePreAuthenticationEncoding(payloadType, payload), publishPrivateKey,
  ).toString('base64');
  const envelope = {
    payload: payload.toString('base64'),
    payloadType,
    signatures: [{ sig, keyid: publishKeyId }],
  };
  const body = {
    apiVersion: '0.0.1',
    kind: 'dsse',
    spec: {
      envelopeHash: {
        algorithm: 'sha256',
        value: sha256(Buffer.from(JSON.stringify(envelope), 'utf8')).toString('hex'),
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

function prepareSyntheticAudit(audit, distRecords) {
  for (const row of audit.verified) {
    const provenance = row.attestationBundles.find(
      ({ predicateType }) => predicateType === 'https://slsa.dev/provenance/v1',
    );
    provenance.signedAccessSignatureUrl = '';
    signLogEntry(provenance.bundle.verificationMaterial.tlogEntries[0]);
    const integratedTime = Number(
      provenance.bundle.verificationMaterial.tlogEntries[0].integratedTime,
    );
    const sha512 = Buffer.from(
      distRecords[row.name].integrity.slice('sha512-'.length), 'base64',
    ).toString('hex');
    row.attestationBundles.push({
      bundle: buildPublishBundle({ integratedTime: integratedTime + 1, name: row.name, sha512 }),
      predicateType: PUBLISH_PREDICATE,
      signedAccessSignatureUrl: '',
    });
  }
  return audit;
}

async function temporaryDirectory(t, prefix) {
  const root = await mkdtemp(join(await realpath(tmpdir()), prefix));
  t.after(() => rm(root, { force: true, recursive: true }));
  return root;
}

function tarballIntegrity(bytes) {
  return `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
}

async function installFakeTuf(npmRoot, {
  bootstrapRoot,
  defaultMirror = TUF_MIRROR,
  implementationVersion = '4.0.2',
} = {}) {
  const moduleRoot = join(npmRoot, 'node_modules', '@sigstore', 'tuf');
  const material = syntheticTufMaterial();
  const frozenRoot = bootstrapRoot ?? brotliDecompressSync(Buffer.from(
    FROZEN_TUF_ROOT_BROTLI_BASE64, 'base64',
  ));
  const initMarker = join(npmRoot, 'tuf-init-called');
  await mkdir(moduleRoot, { recursive: true });
  await Promise.all([
    writeFile(join(moduleRoot, 'package.json'), `${JSON.stringify({
      exports: {
        '.': './index.cjs',
        './package.json': './package.json',
        './seeds.json': './seeds.json',
      },
      main: 'index.cjs',
      name: '@sigstore/tuf',
      version: implementationVersion,
    })}\n`),
    writeFile(join(moduleRoot, 'seeds.json'), `${JSON.stringify({
      [TUF_MIRROR]: { 'root.json': frozenRoot.toString('base64') },
    })}\n`),
    writeFile(join(moduleRoot, 'targets.json'), `${JSON.stringify({
      'registry.npmjs.org/keys.json': material.registryKeysTarget,
      'trusted_root.json': material.trustedRoot,
    })}\n`),
    writeFile(join(moduleRoot, 'index.cjs'), [
      "'use strict';",
      "const crypto = require('node:crypto');",
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "const targets = require('./targets.json');",
      `const initMarker = ${JSON.stringify(initMarker)};`,
      `exports.DEFAULT_MIRROR_URL = ${JSON.stringify(defaultMirror)};`,
      'exports.initTUF = async (options) => {',
      "  fs.writeFileSync(initMarker, 'called\\n', { flag: 'wx' });",
      '  const optionKeys = Object.keys(options).sort();',
      "  const expectedKeys = ['cachePath', 'forceCache', 'forceInit', 'mirrorURL', 'rootPath'];",
      '  if (JSON.stringify(optionKeys) !== JSON.stringify(expectedKeys)',
      '      || options.forceCache !== false || options.forceInit !== true',
      `      || options.mirrorURL !== ${JSON.stringify(TUF_MIRROR)}`,
      '      || path.dirname(options.cachePath) !== path.dirname(options.rootPath)) {',
      "    throw new Error('unsafe fixture TUF initialization options');",
      '  }',
      '  const root = fs.readFileSync(options.rootPath);',
      `  if (crypto.createHash('sha256').update(root).digest('hex') !== ${JSON.stringify(syntheticTrustPolicy().source.tufBootstrapRootSha256)}`,
      '      || JSON.parse(root).signed.version !== 14) {',
      "    throw new Error('wrong fixture TUF bootstrap root');",
      '  }',
      '  return {',
      '    getTarget: async (name) => {',
      "      if (!Object.hasOwn(targets, name)) throw new Error('unexpected fixture TUF target');",
      '      return JSON.stringify(targets[name]);',
      '    },',
      '  };',
      '};',
      '',
    ].join('\n')),
  ]);
  return initMarker;
}

async function writeMinimalCliFixture(t, { tufOptions, withTuf = false } = {}) {
  const root = await temporaryDirectory(t, 'sdn-provenance-inputs-');
  const inputs = join(root, 'inputs');
  const npmRoot = join(inputs, 'fake-npm');
  await mkdir(join(npmRoot, 'bin'), { recursive: true });
  const coreTarball = Buffer.from('fixture core package tarball\n');
  const uiTarball = Buffer.from('fixture UI package tarball\n');
  const coreDist = structuredClone(fixture.registryEvidence['hd-wallet-wasm'].dist);
  const uiDist = structuredClone(fixture.registryEvidence['hd-wallet-ui'].dist);
  coreDist.integrity = tarballIntegrity(coreTarball);
  uiDist.integrity = tarballIntegrity(uiTarball);
  const audit = prepareSyntheticAudit(structuredClone(fixture.audit), {
    'hd-wallet-ui': uiDist,
    'hd-wallet-wasm': coreDist,
  });
  const paths = {
    audit: join(inputs, 'audit.json'),
    coreDist: join(inputs, 'core-dist.json'),
    coreTarball: join(inputs, 'core-package.tgz'),
    dist: join(inputs, 'core-dist.json'),
    npmCli: join(npmRoot, 'bin', 'npm-cli.js'),
    tarball: join(inputs, 'core-package.tgz'),
    trustPolicy: join(inputs, 'trust-policy.json'),
    uiDist: join(inputs, 'ui-dist.json'),
    uiTarball: join(inputs, 'ui-package.tgz'),
  };
  await Promise.all([
    writeFile(paths.audit, `${JSON.stringify(audit)}\n`),
    writeFile(paths.coreDist, `${JSON.stringify(coreDist)}\n`),
    writeFile(paths.coreTarball, coreTarball),
    writeFile(paths.npmCli, '#!/usr/bin/env node\n'),
    writeFile(paths.trustPolicy, `${JSON.stringify(syntheticTrustPolicy())}\n`),
    writeFile(paths.uiDist, `${JSON.stringify(uiDist)}\n`),
    writeFile(paths.uiTarball, uiTarball),
    writeFile(join(npmRoot, 'package.json'), '{"name":"npm","version":"11.16.0"}\n'),
  ]);
  const tufInitMarker = withTuf ? await installFakeTuf(npmRoot, tufOptions) : undefined;
  return { inputs, paths, root, tufInitMarker };
}

function singlePackageArguments(paths, outputDirectory) {
  return [
    '--audit', paths.audit,
    '--package', 'hd-wallet-wasm',
    '--dist', paths.dist,
    '--tarball', paths.tarball,
    '--npm-cli', paths.npmCli,
    '--trust-policy', paths.trustPolicy,
    '--output-directory', outputDirectory,
  ];
}

function finalPackageArguments(paths, outputDirectory) {
  return [
    '--audit', paths.audit,
    '--core-dist', paths.coreDist,
    '--core-tarball', paths.coreTarball,
    '--ui-dist', paths.uiDist,
    '--ui-tarball', paths.uiTarball,
    '--npm-cli', paths.npmCli,
    '--trust-policy', paths.trustPolicy,
    '--output-directory', outputDirectory,
  ];
}

async function runCollector(args) {
  return execFileAsync(process.execPath, [collectorPath, ...args], {
    encoding: 'utf8',
    env: {},
  });
}

async function expectCollectorFailure(args, pattern) {
  await assert.rejects(
    runCollector(args),
    (error) => pattern.test(`${error.stderr ?? ''}\n${error.message ?? ''}`),
  );
}

function publicKeyRawBytes(publicKeyPem) {
  return createPublicKey(publicKeyPem).export({ format: 'der', type: 'spki' }).toString('base64');
}

function syntheticTufMaterial() {
  const registryKeys = new Map();
  const certificateAuthorities = new Map();
  for (const evidence of Object.values(fixture.registryEvidence)) {
    const key = evidence.registryKeys[0];
    registryKeys.set(`npm:signatures:${key.keyid}`, {
      keyId: key.keyid,
      keyUsage: 'npm:signatures',
      publicKey: {
        rawBytes: publicKeyRawBytes(key.publicKeyPem),
        validFor: { start: '2000-01-01T00:00:00.000Z', end: '2100-01-01T00:00:00.000Z' },
      },
    });
    const authority = {
      certChain: structuredClone(evidence.sigstoreTrust.certificateChain),
      uri: 'https://fulcio.sigstore.dev',
      validFor: { start: '2000-01-01T00:00:00.000Z', end: '2100-01-01T00:00:00.000Z' },
    };
    certificateAuthorities.set(JSON.stringify(authority), authority);
  }
  registryKeys.set(`npm:attestations:${publishKeyId}`, {
    keyId: publishKeyId,
    keyUsage: 'npm:attestations',
    publicKey: {
      rawBytes: publishPublicKeyDer.toString('base64'),
      validFor: { start: '2000-01-01T00:00:00.000Z', end: '2100-01-01T00:00:00.000Z' },
    },
  });
  return {
    registryKeysTarget: { keys: [...registryKeys.values()] },
    trustedRoot: {
      certificateAuthorities: [...certificateAuthorities.values()],
      tlogs: [{
        baseUrl: 'https://synthetic.rekor.invalid',
        hashAlgorithm: 'SHA2_256',
        logId: { keyId: logId },
        publicKey: {
          rawBytes: logPublicKeyDer.toString('base64'),
          validFor: {
            end: '2100-01-01T00:00:00.000Z',
            start: '2000-01-01T00:00:00.000Z',
          },
        },
      }],
    },
  };
}

function syntheticTrustPolicy() {
  const evidence = fixture.registryEvidence['hd-wallet-wasm'];
  return {
    npmRegistryKeys: [
      {
        keyDetails: 'PKIX_ECDSA_P256_SHA_256',
        keyUsage: 'npm:attestations',
        keyid: publishKeyId,
        publicKeySha256: createHash('sha256').update(publishPublicKeyDer).digest('hex'),
        validFor: { end: '2100-01-01T00:00:00.000Z', start: '2000-01-01T00:00:00.000Z' },
      },
      {
        keyDetails: 'PKIX_ECDSA_P256_SHA_256',
        keyUsage: 'npm:signatures',
        keyid: evidence.registryKeys[0].keyid,
        publicKeySha256: 'd3cb46d722bcf8a0f6b809c95a0e8bc78692e19f6f4640ad3c04400d36db57ee',
        validFor: { end: '2100-01-01T00:00:00.000Z', start: '2000-01-01T00:00:00.000Z' },
      },
    ],
    release: {
      packages: ['hd-wallet-ui', 'hd-wallet-wasm'],
      repository: 'https://github.com/DigitalArsenal/hd-wallet-wasm',
      repositoryId: '1142529413',
      repositoryOwnerId: '29587475',
      sourceTag: 'v2.0.30',
      version: '2.0.30',
      workflow: '.github/workflows/npm-publish.yml',
    },
    schemaVersion: 1,
    sigstoreCertificateAuthorities: [{
      rootCertificateSha256: '42eb70c1f53ad90480b6fdb2aa75eba9b283fbb0976bc188dfe040849e154ad5',
      uri: 'https://fulcio.sigstore.dev',
      validFor: { end: '2100-01-01T00:00:00.000Z', start: '2000-01-01T00:00:00.000Z' },
    }],
    sigstoreTransparencyLogs: [{
      baseUrl: 'https://synthetic.rekor.invalid',
      effectiveLogId: logId,
      hashAlgorithm: 'SHA2_256',
      keyDetails: 'PKIX_ECDSA_P256_SHA_256',
      publicKeySha256: createHash('sha256').update(logPublicKeyDer).digest('hex'),
      validFor: { end: '2100-01-01T00:00:00.000Z', start: '2000-01-01T00:00:00.000Z' },
    }],
    source: {
      npmVersion: '11.16.0',
      registryKeysTarget: 'registry.npmjs.org/keys.json',
      sigstoreTrustedRootTarget: 'trusted_root.json',
      tufBootstrapRootSha256: 'c8c41ec13f06ccabf5b48541ee2550098b4c7b5349e1d180390c29a7d5c2642c',
      tufBootstrapRootVersion: 14,
      tufImplementationVersion: '4.0.2',
      tufMirror: TUF_MIRROR,
    },
  };
}

function validInput() {
  const tuf = syntheticTufMaterial();
  const distRecords = Object.fromEntries(Object.entries(fixture.registryEvidence).map(
    ([name, evidence]) => [name, structuredClone(evidence.dist)],
  ));
  return {
    audit: prepareSyntheticAudit(structuredClone(fixture.audit), distRecords),
    distRecords,
    registryKeysTarget: tuf.registryKeysTarget,
    trustPolicy: syntheticTrustPolicy(),
    trustedRoot: tuf.trustedRoot,
    workflowTarballSha512: Object.fromEntries(Object.entries(fixture.registryEvidence).map(
      ([name, evidence]) => [name, evidence.workflowTarball.sha512],
    )),
  };
}

function expectedRegistryEvidence(input) {
  const trust = {
    certificateChain: structuredClone(
      fixture.registryEvidence['hd-wallet-wasm'].sigstoreTrust.certificateChain,
    ),
    transparencyLog: {
      baseUrl: 'https://synthetic.rekor.invalid',
      logId,
      publicKeyPem: logPublicKeyPem,
    },
  };
  return Object.fromEntries(['hd-wallet-ui', 'hd-wallet-wasm'].map((name) => [name, {
    dist: structuredClone(input.distRecords[name]),
    registryKeys: [
      { keyid: input.distRecords[name].signatures[0].keyid, publicKeyPem: fixture.registryEvidence[name].registryKeys[0].publicKeyPem },
      { keyid: publishKeyId, publicKeyPem: publishPublicKeyPem },
    ],
    sigstoreTrust: structuredClone(trust),
    workflowTarball: { sha512: input.workflowTarballSha512[name] },
  }]));
}

test('builds the strict offline registry envelopes from TUF-authenticated material', () => {
  const input = validInput();
  assert.deepEqual(buildRegistryEvidenceEnvelopes(input), expectedRegistryEvidence(input));
});

test('synthetic npm publish bundles match keyed Rekor DSSE production evidence', () => {
  const input = validInput();
  for (const row of input.audit.verified) {
    const publish = row.attestationBundles.find(
      ({ predicateType }) => predicateType === PUBLISH_PREDICATE,
    );
    const { dsseEnvelope, verificationMaterial } = publish.bundle;
    assert.deepEqual(Object.keys(dsseEnvelope.signatures[0]), ['sig', 'keyid']);
    assert.equal(dsseEnvelope.signatures[0].keyid, publishKeyId);
    const entry = verificationMaterial.tlogEntries[0];
    assert.deepEqual(entry.kindVersion, { kind: 'dsse', version: '0.0.1' });
    assert.notEqual(entry.logIndex, entry.inclusionProof.logIndex);
    assert.equal(entry.inclusionProof.treeSize, '2');
    assert.equal(entry.inclusionProof.hashes.length, 1);

    const body = JSON.parse(Buffer.from(entry.canonicalizedBody, 'base64').toString('utf8'));
    assert.deepEqual(body, {
      apiVersion: '0.0.1',
      kind: 'dsse',
      spec: {
        envelopeHash: {
          algorithm: 'sha256',
          value: sha256(Buffer.from(JSON.stringify(dsseEnvelope), 'utf8')).toString('hex'),
        },
        payloadHash: {
          algorithm: 'sha256',
          value: sha256(Buffer.from(dsseEnvelope.payload, 'base64')).toString('hex'),
        },
        signatures: [{
          signature: dsseEnvelope.signatures[0].sig,
          verifier: Buffer.from(publishPublicKeyPem, 'utf8').toString('base64'),
        }],
      },
    });
  }
});

test('builds one strict envelope for an idempotent same-run package check', () => {
  const input = validInput();
  const expected = expectedRegistryEvidence(input);
  for (const packageName of ['hd-wallet-ui', 'hd-wallet-wasm']) {
    const auditRow = input.audit.verified.find(({ name }) => name === packageName);
    assert.deepEqual(buildRegistryEvidenceEnvelope({
      auditRow,
      distRecord: input.distRecords[packageName],
      packageName,
      registryKeysTarget: input.registryKeysTarget,
      trustedRoot: input.trustedRoot,
      trustPolicy: input.trustPolicy,
      workflowTarballSha512: input.workflowTarballSha512[packageName],
    }), expected[packageName]);
  }
});

test('requires the exact provenance and npm publish attestation pair', () => {
  const input = validInput();
  assert.deepEqual(buildRegistryEvidenceEnvelopes(input), expectedRegistryEvidence(input));
  input.audit.verified[0].attestationBundles = input.audit.verified[0].attestationBundles.filter(
    ({ predicateType }) => predicateType !== PUBLISH_PREDICATE,
  );
  assert.throws(() => buildRegistryEvidenceEnvelopes(input), /publish|attestation bundle set/iu);
});

test('deduplicates one public key authorized for both npm usages', () => {
  const input = validInput();
  const signatureTarget = input.registryKeysTarget.keys.find(
    ({ keyUsage }) => keyUsage === 'npm:signatures',
  );
  signatureTarget.keyId = publishKeyId;
  signatureTarget.publicKey.rawBytes = publishPublicKeyDer.toString('base64');
  for (const dist of Object.values(input.distRecords)) dist.signatures[0].keyid = publishKeyId;
  const signaturePolicy = input.trustPolicy.npmRegistryKeys.find(
    ({ keyUsage }) => keyUsage === 'npm:signatures',
  );
  signaturePolicy.keyid = publishKeyId;
  signaturePolicy.publicKeySha256 = createHash('sha256').update(publishPublicKeyDer).digest('hex');
  const result = buildRegistryEvidenceEnvelopes(input);
  for (const evidence of Object.values(result)) {
    assert.deepEqual(evidence.registryKeys, [{
      keyid: publishKeyId,
      publicKeyPem: publishPublicKeyPem,
    }]);
  }
});

test('rejects ambiguous keys, logs, and certificate paths', () => {
  const keyInput = validInput();
  keyInput.registryKeysTarget.keys.push(structuredClone(keyInput.registryKeysTarget.keys[0]));
  assert.throws(() => buildRegistryEvidenceEnvelopes(keyInput), /registry.*key|key selection/iu);

  const logInput = validInput();
  logInput.trustedRoot.tlogs.push(structuredClone(logInput.trustedRoot.tlogs[0]));
  assert.throws(() => buildRegistryEvidenceEnvelopes(logInput), /transparency log/u);

  const chainInput = validInput();
  chainInput.trustedRoot.certificateAuthorities.push(
    structuredClone(chainInput.trustedRoot.certificateAuthorities[0]),
  );
  assert.throws(() => buildRegistryEvidenceEnvelopes(chainInput), /certificate chain/u);
});

test('rejects a digest, signature key, or audit package mismatch', () => {
  const digestInput = validInput();
  digestInput.workflowTarballSha512['hd-wallet-ui'] = '0'.repeat(128);
  assert.throws(() => buildRegistryEvidenceEnvelopes(digestInput), /tarball/u);

  const signatureInput = validInput();
  signatureInput.distRecords['hd-wallet-ui'].signatures[0].keyid = 'SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
  assert.throws(() => buildRegistryEvidenceEnvelopes(signatureInput), /registry.*key|key selection/iu);

  const auditInput = validInput();
  auditInput.audit.verified = auditInput.audit.verified.filter(
    ({ name }) => name !== 'hd-wallet-wasm',
  );
  assert.throws(() => buildRegistryEvidenceEnvelopes(auditInput), /audit row/u);
});

test('rejects expired, wrong-usage, unpinned, and wrong-effective-ID trust material', () => {
  const expired = validInput();
  expired.registryKeysTarget.keys[0].publicKey.validFor.end = '2001-01-01T00:00:00.000Z';
  assert.throws(() => buildRegistryEvidenceEnvelopes(expired), /registry.*key|key selection|valid/iu);

  const usage = validInput();
  usage.registryKeysTarget.keys[0].keyUsage = 'npm:attestations';
  assert.throws(() => buildRegistryEvidenceEnvelopes(usage), /registry.*key|key selection/iu);

  const unpinned = validInput();
  unpinned.trustPolicy.sigstoreTransparencyLogs[0].publicKeySha256 = '0'.repeat(64);
  assert.throws(() => buildRegistryEvidenceEnvelopes(unpinned), /trust policy/iu);

  const checkpoint = validInput();
  checkpoint.trustedRoot.tlogs[0].checkpointKeyId = { keyId: 'A'.repeat(43) + '=' };
  assert.throws(() => buildRegistryEvidenceEnvelopes(checkpoint), /transparency log/iu);
});

test('rejects drifted normalized TUF registry key details', () => {
  const input = validInput();
  input.registryKeysTarget.keys.find(
    ({ keyUsage }) => keyUsage === 'npm:signatures',
  ).keyDetails = 'PKIX_RSA_PKCS1V15_2048_SHA256';
  assert.throws(
    () => buildRegistryEvidenceEnvelopes(input),
    /key details|signed trust policy|authorization/iu,
  );
});

test('rejects overlapping but non-policy TUF registry key validity', () => {
  const input = validInput();
  input.registryKeysTarget.keys.find(
    ({ keyUsage }) => keyUsage === 'npm:signatures',
  ).publicKey.validFor.start = '1999-01-01T00:00:00.000Z';
  assert.throws(
    () => buildRegistryEvidenceEnvelopes(input),
    /key validity|signed trust policy|authorization/iu,
  );
});

test('rejects overlapping but non-policy TUF transparency-log validity', () => {
  const input = validInput();
  input.trustedRoot.tlogs[0].publicKey.validFor.start = '1999-01-01T00:00:00.000Z';
  assert.throws(
    () => buildRegistryEvidenceEnvelopes(input),
    /transparency log.*validity|signed trust policy|authorization/iu,
  );
});

test('rejects overlapping but non-policy TUF Fulcio validity', () => {
  const input = validInput();
  input.trustedRoot.certificateAuthorities[0].validFor.start = '1999-01-01T00:00:00.000Z';
  assert.throws(
    () => buildRegistryEvidenceEnvelopes(input),
    /certificate authority.*validity|signed trust policy|authorization/iu,
  );
});

test('CLI argument contract separates final and single-package modes', () => {
  const common = [
    '--audit', '/tmp/audit.json', '--npm-cli', '/tmp/npm-cli.js',
    '--output-directory', '/tmp/output', '--trust-policy', '/tmp/trust.json',
  ];
  assert.equal(parseProvenanceInputArguments([
    ...common,
    '--core-dist', '/tmp/core.json', '--core-tarball', '/tmp/core.tgz',
    '--ui-dist', '/tmp/ui.json', '--ui-tarball', '/tmp/ui.tgz',
  ]).mode, 'final');
  assert.equal(parseProvenanceInputArguments([
    ...common,
    '--package', 'hd-wallet-ui', '--dist', '/tmp/ui.json', '--tarball', '/tmp/ui.tgz',
  ]).mode, 'single');
  assert.throws(() => parseProvenanceInputArguments([
    ...common,
    '--package', 'hd-wallet-ui', '--dist', '/tmp/ui.json', '--tarball', '/tmp/ui.tgz',
    '--core-dist', '/tmp/core.json',
  ]), /mode|flags/iu);
});

test('CLI rejects a symlinked ancestor for every caller-supplied input', async (t) => {
  const cli = await writeMinimalCliFixture(t);
  const linkedInputs = join(cli.root, 'linked-inputs');
  await symlink(cli.inputs, linkedInputs, 'dir');
  const linkedPaths = {
    audit: join(linkedInputs, 'audit.json'),
    dist: join(linkedInputs, 'core-dist.json'),
    npmCli: join(linkedInputs, 'fake-npm', 'bin', 'npm-cli.js'),
    tarball: join(linkedInputs, 'core-package.tgz'),
    trustPolicy: join(linkedInputs, 'trust-policy.json'),
  };
  for (const name of Object.keys(linkedPaths)) {
    const paths = { ...cli.paths, [name]: linkedPaths[name] };
    await expectCollectorFailure(
      singlePackageArguments(paths, join(cli.root, `evidence-${name}`)),
      /path component.*symlink|symlink.*path component/iu,
    );
  }
});

test('CLI rejects a symlinked output ancestor before loading TUF', async (t) => {
  const cli = await writeMinimalCliFixture(t);
  const realOutputParent = join(cli.root, 'real-output-parent');
  const linkedOutputParent = join(cli.root, 'linked-output-parent');
  await mkdir(realOutputParent);
  await symlink(realOutputParent, linkedOutputParent, 'dir');
  await expectCollectorFailure(
    singlePackageArguments(cli.paths, join(linkedOutputParent, 'evidence')),
    /path component.*symlink|symlink.*path component/iu,
  );
});

test('fixture-only CLI publishes both final envelopes in one directory handoff', async (t) => {
  const cli = await writeMinimalCliFixture(t, { withTuf: true });
  const outputDirectory = join(cli.root, 'registry-evidence');
  const result = await runCollector(finalPackageArguments(cli.paths, outputDirectory));
  assert.deepEqual(JSON.parse(result.stdout), {
    files: {
      'hd-wallet-ui': 'hd-wallet-ui.registry-evidence.v1.json',
      'hd-wallet-wasm': 'hd-wallet-wasm.registry-evidence.v1.json',
    },
    status: 'verified',
  });
  assert.deepEqual((await readdir(outputDirectory)).sort(), [
    'hd-wallet-ui.registry-evidence.v1.json',
    'hd-wallet-wasm.registry-evidence.v1.json',
  ]);
  assert.equal((await stat(outputDirectory)).mode & 0o777, 0o700);
  for (const name of await readdir(outputDirectory)) {
    assert.equal((await stat(join(outputDirectory, name))).mode & 0o777, 0o600);
  }
  const stagingPrefix = '.registry-evidence.stage-';
  assert.deepEqual((await readdir(cli.root)).filter((name) => name.startsWith(stagingPrefix)), []);
  const core = JSON.parse(await readFile(
    join(outputDirectory, 'hd-wallet-wasm.registry-evidence.v1.json'),
    'utf8',
  ));
  const ui = JSON.parse(await readFile(
    join(outputDirectory, 'hd-wallet-ui.registry-evidence.v1.json'),
    'utf8',
  ));
  assert.equal(core.workflowTarball.sha512, createHash('sha512')
    .update(await readFile(cli.paths.coreTarball)).digest('hex'));
  assert.equal(ui.workflowTarball.sha512, createHash('sha512')
    .update(await readFile(cli.paths.uiTarball)).digest('hex'));

  const before = await Promise.all((await readdir(outputDirectory)).sort().map(
    (name) => readFile(join(outputDirectory, name), 'utf8'),
  ));
  await expectCollectorFailure(
    finalPackageArguments(cli.paths, outputDirectory),
    /output directory.*already exist/iu,
  );
  const after = await Promise.all((await readdir(outputDirectory)).sort().map(
    (name) => readFile(join(outputDirectory, name), 'utf8'),
  ));
  assert.deepEqual(after, before);
});

test('CLI rejects a drifted TUF implementation or mirror before initialization', async (t) => {
  for (const [label, tufOptions, pattern] of [
    [
      'implementation',
      { implementationVersion: '4.0.1' },
      /@sigstore\/tuf.*4\.0\.2|implementation.*version/iu,
    ],
    [
      'mirror',
      { defaultMirror: 'https://wrong-tuf-mirror.invalid' },
      /TUF.*mirror|mirror.*TUF/iu,
    ],
  ]) {
    await t.test(label, async (t) => {
      const cli = await writeMinimalCliFixture(t, { tufOptions, withTuf: true });
      await expectCollectorFailure(
        finalPackageArguments(cli.paths, join(cli.root, 'registry-evidence')),
        pattern,
      );
      await assert.rejects(readFile(cli.tufInitMarker), { code: 'ENOENT' });
    });
  }
});

test('CLI rejects a TUF bootstrap-root hash drift before initialization', async (t) => {
  const frozenRoot = brotliDecompressSync(Buffer.from(
    FROZEN_TUF_ROOT_BROTLI_BASE64, 'base64',
  ));
  const cli = await writeMinimalCliFixture(t, {
    tufOptions: { bootstrapRoot: Buffer.concat([frozenRoot, Buffer.from('\n')]) },
    withTuf: true,
  });
  await expectCollectorFailure(
    finalPackageArguments(cli.paths, join(cli.root, 'registry-evidence')),
    /bootstrap root.*trust policy|trust policy.*bootstrap root/iu,
  );
  await assert.rejects(readFile(cli.tufInitMarker), { code: 'ENOENT' });
});

test('CLI rejects a trust policy with a different bootstrap-root version before TUF', async (t) => {
  const cli = await writeMinimalCliFixture(t, { withTuf: true });
  const policy = JSON.parse(await readFile(cli.paths.trustPolicy, 'utf8'));
  policy.source.tufBootstrapRootVersion = 13;
  await writeFile(cli.paths.trustPolicy, `${JSON.stringify(policy)}\n`);
  await expectCollectorFailure(
    finalPackageArguments(cli.paths, join(cli.root, 'registry-evidence')),
    /trust policy source.*frozen|bootstrap.*version/iu,
  );
  await assert.rejects(readFile(cli.tufInitMarker), { code: 'ENOENT' });
});
