import { runInNewContext } from 'node:vm';

import { describe, expect, test } from 'vitest';

import * as wire from '../client/wire.mjs';
import assetReviewProtocol from '../../release/protocol/asset-review-v1.json' with { type: 'json' };

const CHALLENGE_BYTES = Uint8Array.from({ length: 32 }, (_, index) => index);
const CHALLENGE_BASE64URL = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8';
const HEX_32 = 'a'.repeat(64);
const SIGNATURE_HEX = 'b'.repeat(128);
const BASE32_ALPHABET = 'abcdefghijklmnopqrstuvwxyz234567';

function base32(bytes) {
  let accumulator = 0;
  let bits = 0;
  let output = '';
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(accumulator >>> bits) & 31];
      accumulator &= (1 << bits) - 1;
    }
  }
  if (bits !== 0) output += BASE32_ALPHABET[(accumulator << (5 - bits)) & 31];
  return output;
}

function rawSha256Cid({
  version = 0x01,
  codec = 0x55,
  hash = 0x12,
  digestLength = 0x20,
  digestHex = HEX_32,
} = {}) {
  const digest = Uint8Array.from(digestHex.match(/../gu), (byte) => Number.parseInt(byte, 16));
  return `b${base32(Uint8Array.of(version, codec, hash, digestLength, ...digest))}`;
}

const EXPECTED_EXPORTS = [
  'buildAssetReviewAuthorityActivationRequest',
  'buildAssetReviewAuthorityActivationResult',
  'buildAssetReviewDecisionRequest',
  'buildAssetReviewDecisionResult',
  'buildSdnLoginV1Request',
  'buildSdnLoginV1Result',
  'buildSdnLoginV2Request',
  'buildSdnLoginV2Result',
  'buildWalletAccountRequest',
  'buildWalletAccountResult',
  'buildWalletConnectRequest',
  'buildWalletConnectResult',
  'parseAssetReviewAuthorityActivationRequest',
  'parseAssetReviewAuthorityActivationResult',
  'parseAssetReviewDecisionRequest',
  'parseAssetReviewDecisionResult',
  'parseSdnLoginV1Request',
  'parseSdnLoginV1Result',
  'parseSdnLoginV2Request',
  'parseSdnLoginV2Result',
  'parseWalletAccountRequest',
  'parseWalletAccountResult',
  'parseWalletConnectRequest',
  'parseWalletConnectResult',
].sort();

function approvalIdentity(accountIndex = 0) {
  return {
    schemaVersion: 1,
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    seedProfile: 'password-scrypt-v2',
    accountIndex,
    accountLabel: null,
    accountXpub: accountIndex === 0
      ? 'xpub6D9SXNXfAWtnHw8uWqUwMCBFh4R5bvzzWWemXtzwNhojQnYXyQARwhphkvtN4AJ93QFhzzHQZHj7MYQ7KuQ8vsXiTEwUq6MiF7iaLXTPFRT'
      : 'xpub6D9SXNXfAWtnLsmiHP7yjWHAmZoYMgp6yWLMr42BWdpgyE6mTNAukCm2PW5AdEG33RTxNgKg42cUE69zrundhquxbWj8sHe2jxtDb3VFoT4',
    accountPeerId: accountIndex === 0
      ? '16Uiu2HAkzgWPa6HTtNTU8WQi1kppaRsYUDBxNKygQNYUk7N73CMA'
      : '16Uiu2HAm4ZJR19pVznz3KFcQYjjnyCwcspueFV19m7ca5CVPWy3b',
    accountFingerprint: accountIndex === 0 ? '9b582711' : 'e8214de1',
    keys: [
      {
        purpose: 'asset-review-approval',
        identityScheme: 'sdn-bip32-slip10-purpose-v1',
        seedProfile: 'password-scrypt-v2',
        signatureProfile: 'ed25519-over-sha256-jcs-v1',
        curve: 'ed25519',
        derivation: 'slip10',
        path: `m/44'/0'/${accountIndex}'/2'/0'`,
        encoding: 'raw',
        publicKeyHex: accountIndex === 0
          ? '9210df41afc82babe9f512d781d6d7a8452060515117c00a28a12ce85ae1c6ff'
          : '8225fc858d41aa082ac813b8b613dcc282e285090363de2ff80bff182eeb18d0',
        bip32Fingerprint: null,
        keyId: accountIndex === 0
          ? 'sha256:150b5f54946e1a16d50eaadaaa5f6f12611a19bfbfcbec03157bdcebd4b2e27d'
          : 'sha256:791e490a08f2a1616fc7fd610e4a9a1f28fdfd0205c429ddeb7902420ec9ad14',
      },
      {
        purpose: 'contact-encryption',
        identityScheme: 'sdn-bip32-slip10-purpose-v1',
        seedProfile: 'password-scrypt-v2',
        signatureProfile: null,
        curve: 'x25519',
        derivation: 'slip10',
        path: `m/44'/0'/${accountIndex}'/1'/0'`,
        encoding: 'raw',
        publicKeyHex: accountIndex === 0
          ? '1349c6136a8765e4b2a8795037cc6233e22d31a08c76e328ad247daf836c6c0c'
          : 'd03c2cd449e689c1f93c17f53bc08cb3f55ecb5c3accf6c1e86b14e9bdf6a610',
        bip32Fingerprint: null,
        keyId: accountIndex === 0
          ? 'sha256:289fa9392a192258ac096b8596d8625d5824b5e5b5368072a5adf5d31c369e2b'
          : 'sha256:dbbdd815d1069051cc3e634923d9bc18483ca7274863734da4d21a8431f4951c',
      },
      {
        purpose: 'sdn-authentication',
        identityScheme: 'sdn-bip32-slip10-purpose-v1',
        seedProfile: 'password-scrypt-v2',
        signatureProfile: 'ed25519-over-sha256-jcs-v1',
        curve: 'ed25519',
        derivation: 'slip10',
        path: `m/44'/0'/${accountIndex}'/0'/0'`,
        encoding: 'raw',
        publicKeyHex: accountIndex === 0
          ? 'f5b8e91319472049d552f37d58f528eecefd68cfc4c462c6fcff279c76afb319'
          : '999b912a96fde6be3e718f573c29f16cc97d13fd128c2eb6a7d089af7c0fc2b0',
        bip32Fingerprint: null,
        keyId: accountIndex === 0
          ? 'sha256:d997ad2bf7dbf21c490695eba54d3054628d7f7fb9037fb8145ea32b4e384b7c'
          : 'sha256:72a40224fc9ba6c1ddeaa4f6da6cd53ab6015f591b76f77c984a6b7d4573b9ef',
      },
    ],
  };
}

function jcs(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'number'
      || typeof value === 'string') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(jcs).join(',')}]`;
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jcs(value[key])}`).join(',')}}`;
}

function canonicalEnvelope(kind, reviewDecision = 'approve') {
  if (kind === 'sdn-login') {
    return {
      audience: 'sdn-login:sdn.spaceaware.io',
      challengeSha256: HEX_32,
      clientId: 'sdn-node-console-v1',
      expiresAt: '2026-07-20T20:05:00.000Z',
      identityScheme: 'sdn-bip32-slip10-purpose-v1',
      issuedAt: '2026-07-20T20:00:00.000Z',
      keyId: `sha256:${HEX_32}`,
      kind,
      nonce: 'c'.repeat(64),
      protocolVersion: 2,
      requestOrigin: 'https://sdn.spaceaware.io',
      signatureProfile: 'ed25519-over-sha256-jcs-v1',
    };
  }
  if (kind === 'asset-review-authority-activation') {
    return { ...activationRequest(), kind };
  }
  return {
    ...(reviewDecision === 'disapprove' ? disapprovalRequest() : approvalRequest()),
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    keyId: `sha256:${HEX_32}`,
    kind: 'asset-review-attestation',
    purpose: 'asset-review-approval',
    signatureProfile: 'ed25519-over-sha256-jcs-v1',
  };
}

function canonicalSignature(kind = 'sdn-login', reviewDecision = 'approve') {
  return {
    schemaVersion: 1,
    keyId: `sha256:${HEX_32}`,
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    algorithm: 'ed25519',
    encoding: 'raw',
    signatureProfile: 'ed25519-over-sha256-jcs-v1',
    canonicalEnvelope: jcs(canonicalEnvelope(kind, reviewDecision)),
    signedDigestSha256: HEX_32,
    signatureHex: SIGNATURE_HEX,
  };
}

function activationRequest() {
  return {
    protocolVersion: 1,
    audience: 'asset-review-authority:assets.ipfs.01',
    requestOrigin: 'https://review.spacedatanetwork.org',
    clientId: 'sdn-asset-review-v1',
    serviceInstance: 'assets.ipfs.01/asset-review-attestation',
    purpose: 'asset-review-authority-activation',
    nonce: '0'.repeat(64),
    issuedAt: '2026-07-20T22:00:00.000Z',
    expiresAt: '2026-07-20T22:05:00.000Z',
    publicKeyHex: '1'.repeat(64),
    keyId: `sha256:${HEX_32}`,
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    signatureProfile: 'ed25519-over-sha256-jcs-v1',
  };
}

function approvalRequest() {
  const modelSha256 = 'a'.repeat(64);
  return {
    protocolVersion: 1,
    audience: 'asset-review:assets.ipfs.01',
    requestOrigin: 'https://review.spacedatanetwork.org',
    clientId: 'sdn-asset-review-v1',
    challengeId: '2'.repeat(64),
    nonce: '4'.repeat(64),
    issuedAt: '2026-07-20T23:00:00.000Z',
    expiresAt: '2026-07-20T23:05:00.000Z',
    candidateKey: `asset-review:spacecraft/example:${modelSha256}`,
    modelCid: 'bafkreifkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvi',
    modelSha256,
    modelBytes: 12345,
    metadataSha256: 'b'.repeat(64),
    previousDecisionHead: null,
    decision: 'approve',
    reviewedTransform: {
      translation: [0, 0, 0],
      rotation: [0, 0, 0, 1],
      scale: [1, 1, 1],
      upAxis: 'Y_UP',
      sourceUnits: 'm',
      metersPerSourceUnit: 1,
    },
    note: 'Synthetic fixture approval.',
  };
}

function disapprovalRequest() {
  const value = approvalRequest();
  delete value.note;
  delete value.reviewedTransform;
  value.decision = 'disapprove';
  value.previousDecisionHead = '5'.repeat(64);
  value.reason = 'Synthetic fixture rejection.';
  return value;
}

function expectDeepFrozen(value) {
  expect(Object.isFrozen(value)).toBe(true);
  if (Array.isArray(value)) {
    for (const item of value) {
      if (item && typeof item === 'object') expectDeepFrozen(item);
    }
    return;
  }
  for (const item of Object.values(value)) {
    if (item && typeof item === 'object') expectDeepFrozen(item);
  }
}

describe('operation-specific wire surface', () => {
  test('exports only the six operation-specific parse/build pairs', () => {
    expect(Object.keys(wire).sort()).toEqual(EXPECTED_EXPORTS);
  });

  test('round-trips an exact 32-byte challenge as 43 canonical base64url characters', () => {
    const input = { protocolVersion: 1, challenge: CHALLENGE_BYTES };
    const built = wire.buildSdnLoginV1Request(input);
    expect(built).toEqual({ challengeBase64url: CHALLENGE_BASE64URL, protocolVersion: 1 });
    expect(built.challengeBase64url).toHaveLength(43);
    expect(wire.parseSdnLoginV1Request(JSON.stringify(built))).toEqual(built);
    expectDeepFrozen(built);
  });

  test.each([
    ['duplicate', `{"challengeBase64url":"${CHALLENGE_BASE64URL}","challengeBase64url":"${CHALLENGE_BASE64URL}","protocolVersion":1}`],
    ['missing', { protocolVersion: 1 }],
    ['unknown', { challengeBase64url: CHALLENGE_BASE64URL, protocolVersion: 1, signer: 'forbidden' }],
    ['undefined', { challengeBase64url: undefined, protocolVersion: 1 }],
    ['padded base64url', { challengeBase64url: `${CHALLENGE_BASE64URL}=`, protocolVersion: 1 }],
    ['standard base64', { challengeBase64url: `${CHALLENGE_BASE64URL.slice(0, -1)}+`, protocolVersion: 1 }],
    ['noncanonical base64url tail bits', { challengeBase64url: `${CHALLENGE_BASE64URL.slice(0, -1)}9`, protocolVersion: 1 }],
    ['hex substitution', { challengeBase64url: '00'.repeat(32), protocolVersion: 1 }],
    ['numeric array', { challengeBase64url: [...CHALLENGE_BYTES], protocolVersion: 1 }],
  ])('rejects %s request encoding', (_name, value) => {
    expect(() => wire.parseSdnLoginV1Request(value)).toThrow();
  });

  test('rejects non-finite nested fields and nested duplicate JSON members', () => {
    const request = approvalRequest();
    request.reviewedTransform.metersPerSourceUnit = Number.POSITIVE_INFINITY;
    expect(() => wire.buildAssetReviewDecisionRequest(request)).toThrow();

    const duplicate = JSON.stringify(approvalRequest()).replace(
      '"translation":[0,0,0]',
      '"translation":[0,0,0],"translation":[0,0,0]',
    );
    expect(() => wire.parseAssetReviewDecisionRequest(duplicate)).toThrow(/duplicate/iu);
  });

  test('rejects an absent or non-object empty-operation wire request', () => {
    expect(() => wire.parseWalletConnectRequest(undefined)).toThrow();
    expect(() => wire.parseWalletAccountRequest(null)).toThrow();
    expect(() => wire.parseWalletConnectRequest([])).toThrow();
  });
});

describe('defensive public results', () => {
  test('narrows Task 5 identities to the complete account-0 descriptor matrix', () => {
    const identity = approvalIdentity();
    const result = wire.buildWalletConnectResult({
      connectionExpiresAt: '2026-07-20T20:05:00.000Z',
      event: 'connected',
      identity,
      schemaVersion: 1,
    });

    identity.keys[0].publicKeyHex = 'f'.repeat(64);
    identity.keys.reverse();
    expect(result.identity.keys.map((key) => key.purpose)).toEqual([
      'asset-review-approval',
      'contact-encryption',
      'sdn-authentication',
    ]);
    expect(result.identity.keys[0].publicKeyHex).toBe(
      '9210df41afc82babe9f512d781d6d7a8452060515117c00a28a12ce85ae1c6ff',
    );
    expectDeepFrozen(result);
  });

  test('rejects account 1 before a relay-visible result can be created', () => {
    const raw = {
      connectionExpiresAt: '2026-07-20T20:05:00.000Z',
      event: 'connected',
      identity: approvalIdentity(1),
      schemaVersion: 1,
    };
    expect(() => wire.buildWalletConnectResult(raw)).toThrow(/account 0/iu);
    expect(() => wire.parseWalletConnectResult(JSON.stringify(raw))).toThrow(/account 0/iu);
  });

  test('rejects incomplete, relabeled, unsorted, and forbidden descriptors', () => {
    const cases = [];
    const missing = approvalIdentity();
    missing.keys.pop();
    cases.push(missing);
    const relabeled = approvalIdentity();
    relabeled.keys[0].signatureProfile = 'ed25519-raw-32-v1';
    cases.push(relabeled);
    const unsorted = approvalIdentity();
    unsorted.keys.reverse();
    cases.push(unsorted);
    const forbidden = approvalIdentity();
    forbidden.keys[0].purpose = 'node-identity';
    cases.push(forbidden);
    const sparse = approvalIdentity();
    sparse.keys = new Array(3);
    cases.push(sparse);

    for (const identity of cases) {
      expect(() => wire.buildWalletAccountResult({
        connectionExpiresAt: '2026-07-20T20:05:00.000Z',
        event: 'connected',
        identity,
        schemaVersion: 1,
      })).toThrow();
    }
  });

  test('copies and freezes all operation request and result shapes', () => {
    const v2 = {
      protocolVersion: 2,
      audience: 'sdn-login:sdn.spaceaware.io',
      nonce: 'c'.repeat(64),
      issuedAt: '2026-07-20T20:00:00.000Z',
      expiresAt: '2026-07-20T20:05:00.000Z',
      challenge: CHALLENGE_BYTES,
    };
    const rawSignature = {
      schemaVersion: 1,
      keyId: `sha256:${HEX_32}`,
      identityScheme: 'sdn-fast-password-auth-v1-legacy',
      algorithm: 'ed25519',
      encoding: 'raw',
      signatureProfile: 'ed25519-raw-32-v1',
      signatureHex: SIGNATURE_HEX,
    };
    const values = [
      wire.buildWalletConnectRequest(),
      wire.parseWalletConnectRequest('{}'),
      wire.buildWalletAccountRequest(),
      wire.parseWalletAccountRequest({}),
      wire.buildSdnLoginV2Request(v2),
      wire.parseSdnLoginV2Request(JSON.stringify(wire.buildSdnLoginV2Request(v2))),
      wire.buildAssetReviewAuthorityActivationRequest(activationRequest()),
      wire.parseAssetReviewAuthorityActivationRequest(JSON.stringify(activationRequest())),
      wire.buildAssetReviewDecisionRequest(approvalRequest()),
      wire.parseAssetReviewDecisionRequest(JSON.stringify(approvalRequest())),
      wire.buildSdnLoginV1Result(rawSignature),
      wire.parseSdnLoginV1Result(JSON.stringify(rawSignature)),
      wire.buildSdnLoginV2Result(canonicalSignature()),
      wire.parseSdnLoginV2Result(JSON.stringify(canonicalSignature())),
      wire.buildAssetReviewAuthorityActivationResult(canonicalSignature('asset-review-authority-activation')),
      wire.parseAssetReviewAuthorityActivationResult(JSON.stringify(canonicalSignature('asset-review-authority-activation'))),
      wire.buildAssetReviewDecisionResult(canonicalSignature('asset-review-attestation')),
      wire.parseAssetReviewDecisionResult(JSON.stringify(canonicalSignature('asset-review-attestation'))),
    ];
    for (const value of values) expectDeepFrozen(value);
  });

  test('signature results never accept authority-bearing or secret fields', () => {
    for (const forbidden of ['handle', 'verifier', 'code', 'seed', 'signer', 'privateKey']) {
      expect(() => wire.buildSdnLoginV2Result({
        ...canonicalSignature(),
        [forbidden]: 'forbidden',
      })).toThrow();
    }
  });

  test('requires every operation-specific canonical envelope field and outer descriptor equality', () => {
    const missing = canonicalSignature();
    const missingEnvelope = JSON.parse(missing.canonicalEnvelope);
    delete missingEnvelope.audience;
    missing.canonicalEnvelope = jcs(missingEnvelope);
    expect(() => wire.buildSdnLoginV2Result(missing)).toThrow(/field/iu);

    for (const field of ['keyId', 'identityScheme', 'signatureProfile']) {
      const mismatched = canonicalSignature();
      const envelope = JSON.parse(mismatched.canonicalEnvelope);
      envelope[field] = field === 'keyId'
        ? `sha256:${'f'.repeat(64)}`
        : `mismatched-${field}`;
      mismatched.canonicalEnvelope = jcs(envelope);
      const expectation = expect(() => wire.buildSdnLoginV2Result(mismatched));
      if (field === 'keyId') expectation.toThrow(/match/iu);
      else expectation.toThrow();
    }
  });

  test('rejects sparse reviewed-transform tuples', () => {
    for (const field of ['translation', 'rotation', 'scale']) {
      const request = approvalRequest();
      request.reviewedTransform[field] = new Array(field === 'rotation' ? 4 : 3);
      expect(() => wire.buildAssetReviewDecisionRequest(request)).toThrow(/array|finite/iu);
    }
  });

  test('rejects a decision accessor without invoking it', () => {
    const request = approvalRequest();
    let reads = 0;
    Object.defineProperty(request, 'decision', {
      enumerable: true,
      get() {
        reads += 1;
        return 'approve';
      },
    });
    expect(() => wire.buildAssetReviewDecisionRequest(request)).toThrow(/field/iu);
    expect(reads).toBe(0);
  });

  test('enforces every frozen reviewed-transform boundary vector', () => {
    const { baseTransform } = assetReviewProtocol.boundaryVectors;
    const assertVector = (transform, expected) => {
      const request = approvalRequest();
      request.reviewedTransform = structuredClone(transform);
      const expectation = expect(() => wire.buildAssetReviewDecisionRequest(request));
      if (expected === 'accept') expectation.not.toThrow();
      else expectation.toThrow();
    };

    for (const vector of assetReviewProtocol.boundaryVectors.translationComponents) {
      const transform = structuredClone(baseTransform);
      transform.translation[0] = vector.value;
      assertVector(transform, vector.expected);
    }
    for (const vector of assetReviewProtocol.boundaryVectors.scaleComponents) {
      const transform = structuredClone(baseTransform);
      transform.scale[0] = vector.value;
      assertVector(transform, vector.expected);
    }
    for (const vector of assetReviewProtocol.boundaryVectors.rotations) {
      const transform = structuredClone(baseTransform);
      transform.rotation = vector.value;
      assertVector(transform, vector.expected);
    }
    for (const vector of assetReviewProtocol.boundaryVectors.unitPairs) {
      const transform = structuredClone(baseTransform);
      transform.sourceUnits = vector.sourceUnits;
      transform.metersPerSourceUnit = vector.metersPerSourceUnit;
      assertVector(transform, vector.expected);
    }
    for (const vector of assetReviewProtocol.boundaryVectors.upAxes) {
      const transform = structuredClone(baseTransform);
      transform.upAxis = vector.value;
      assertVector(transform, vector.expected);
    }
  });

  test('rejects Array subclasses before invoking inherited collection methods', () => {
    let mapCalls = 0;
    class HostileArray extends Array {
      map(callback) {
        mapCalls += 1;
        return Array.from({ length: this.length }, (_, index) => callback(this[index], index, this));
      }
    }
    const identity = approvalIdentity();
    identity.keys = HostileArray.from(identity.keys);
    expect(() => wire.buildWalletConnectResult({
      connectionExpiresAt: '2026-07-20T20:05:00.000Z',
      event: 'connected',
      identity,
      schemaVersion: 1,
    })).toThrow(/array/iu);
    expect(mapCalls).toBe(0);

    const request = approvalRequest();
    request.reviewedTransform.translation = new HostileArray(0, 0, 0);
    expect(() => wire.buildAssetReviewDecisionRequest(request)).toThrow(/array/iu);
  });

  test('requires a canonical CIDv1 raw sha2-256 that embeds modelSha256', () => {
    expect(rawSha256Cid()).toBe('bafkreifkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvkvi');
    const invalidCids = [
      `b${'a'.repeat(58)}`,
      rawSha256Cid({ version: 0x02 }),
      rawSha256Cid({ codec: 0x70 }),
      rawSha256Cid({ hash: 0x13 }),
      rawSha256Cid({ digestLength: 0x1f }),
      `${rawSha256Cid().slice(0, -1)}j`,
    ];
    for (const modelCid of invalidCids) {
      const request = approvalRequest();
      request.modelCid = modelCid;
      expect(() => wire.buildAssetReviewDecisionRequest(request)).toThrow(/cid/iu);
    }

    const mismatch = approvalRequest();
    mismatch.modelSha256 = 'c'.repeat(64);
    mismatch.candidateKey = `asset-review:spacecraft/example:${mismatch.modelSha256}`;
    expect(() => wire.buildAssetReviewDecisionRequest(mismatch)).toThrow(/cid/iu);
  });

  test('rejects Uint8Array subclasses without invoking a hostile iterator', () => {
    let iteratorCalls = 0;
    class HostileBytes extends Uint8Array {
      *[Symbol.iterator]() {
        iteratorCalls += 1;
        for (let index = 0; index < this.byteLength; index += 1) yield this[index] ^ 0xff;
      }
    }
    const challenge = new HostileBytes(32);
    expect(() => wire.buildSdnLoginV1Request({
      challenge,
      protocolVersion: 1,
    })).toThrow(/Uint8Array/iu);
    expect(iteratorCalls).toBe(0);
  });

  test('rejects SharedArrayBuffer-backed challenge bytes', () => {
    if (typeof SharedArrayBuffer === 'undefined') return;
    const challenge = new Uint8Array(new SharedArrayBuffer(32));
    expect(() => wire.buildSdnLoginV2Request({
      audience: 'sdn-login:sdn.spaceaware.io',
      challenge,
      expiresAt: '2026-07-20T20:05:00.000Z',
      issuedAt: '2026-07-20T20:00:00.000Z',
      nonce: 'c'.repeat(64),
      protocolVersion: 2,
    })).toThrow(/SharedArrayBuffer/iu);
  });

  test('rejects a local Uint8Array view over a foreign-realm SharedArrayBuffer', () => {
    if (typeof SharedArrayBuffer === 'undefined') return;
    const foreignSharedBuffer = runInNewContext('new SharedArrayBuffer(32)');
    expect(foreignSharedBuffer instanceof SharedArrayBuffer).toBe(false);
    const challenge = new Uint8Array(foreignSharedBuffer);
    expect(Object.getPrototypeOf(challenge)).toBe(Uint8Array.prototype);
    expect(() => wire.buildSdnLoginV1Request({ challenge, protocolVersion: 1 }))
      .toThrow(/SharedArrayBuffer/iu);
  });

  test('freezes the exact disapprove request and canonical result branch', () => {
    const request = disapprovalRequest();
    const built = wire.buildAssetReviewDecisionRequest(request);
    const parsed = wire.parseAssetReviewDecisionRequest(JSON.stringify(request));
    expect(built).toEqual(parsed);
    expect(built.decision).toBe('disapprove');
    expect(built.reason).toBe('Synthetic fixture rejection.');
    expect(built).not.toHaveProperty('note');
    expect(built).not.toHaveProperty('reviewedTransform');
    expectDeepFrozen(built);

    const signature = canonicalSignature('asset-review-attestation', 'disapprove');
    expect(wire.buildAssetReviewDecisionResult(signature)).toEqual(signature);
    expect(wire.parseAssetReviewDecisionResult(JSON.stringify(signature))).toEqual(signature);
  });

  test('keeps approve and disapprove request fields mutually exclusive', () => {
    expect(() => wire.buildAssetReviewDecisionRequest({
      ...approvalRequest(),
      reason: 'not allowed',
    })).toThrow(/field/iu);
    expect(() => wire.buildAssetReviewDecisionRequest({
      ...disapprovalRequest(),
      note: 'not allowed',
      reviewedTransform: approvalRequest().reviewedTransform,
    })).toThrow(/field/iu);
    const { reason: _missing, ...missingReason } = disapprovalRequest();
    expect(() => wire.buildAssetReviewDecisionRequest(missingReason)).toThrow(/field/iu);
    expect(() => wire.buildAssetReviewDecisionRequest({
      ...disapprovalRequest(),
      reason: ' leading whitespace',
    })).toThrow(/trimmed/iu);
    expect(() => wire.buildAssetReviewDecisionRequest({
      ...disapprovalRequest(),
      reason: 'x'.repeat(2001),
    })).toThrow(/length/iu);
    const { note: _note, ...approveWithoutNote } = approvalRequest();
    expect(() => wire.buildAssetReviewDecisionRequest(approveWithoutNote)).toThrow(/field/iu);
    const { reviewedTransform: _transform, ...approveWithoutTransform } = approvalRequest();
    expect(() => wire.buildAssetReviewDecisionRequest(approveWithoutTransform)).toThrow(/field/iu);
  });

  test('allows disconnected account results but never disconnected connect results', () => {
    const disconnected = {
      connectionExpiresAt: null,
      event: 'disconnected',
      identity: null,
      schemaVersion: 1,
    };
    expect(wire.buildWalletAccountResult(disconnected)).toEqual(disconnected);
    expect(wire.parseWalletAccountResult(JSON.stringify(disconnected))).toEqual(disconnected);
    expect(() => wire.buildWalletConnectResult(disconnected)).toThrow(/connected/iu);
    expect(() => wire.parseWalletConnectResult(JSON.stringify(disconnected))).toThrow(/connected/iu);
    expect(() => wire.buildWalletAccountResult({
      ...disconnected,
      connectionExpiresAt: '2026-07-20T20:05:00.000Z',
    })).toThrow(/clear/iu);
    expect(() => wire.buildWalletAccountResult({
      ...disconnected,
      identity: approvalIdentity(),
    })).toThrow(/clear/iu);
  });

  test('rejects non-JCS canonical envelope bytes and nested duplicate members', () => {
    const whitespace = canonicalSignature();
    whitespace.canonicalEnvelope = ` ${whitespace.canonicalEnvelope}`;
    expect(() => wire.buildSdnLoginV2Result(whitespace)).toThrow(/JCS/iu);

    const reordered = canonicalSignature();
    reordered.canonicalEnvelope = JSON.stringify(Object.fromEntries(
      Object.entries(JSON.parse(reordered.canonicalEnvelope)).reverse(),
    ));
    expect(() => wire.buildSdnLoginV2Result(reordered)).toThrow(/JCS/iu);

    const alternateEscape = canonicalSignature();
    alternateEscape.canonicalEnvelope = alternateEscape.canonicalEnvelope
      .replace('sdn-login', 'sdn\\u002dlogin');
    expect(() => wire.buildSdnLoginV2Result(alternateEscape)).toThrow(/JCS/iu);

    const duplicate = canonicalSignature('asset-review-attestation');
    duplicate.canonicalEnvelope = duplicate.canonicalEnvelope.replace(
      '"translation":[0,0,0]',
      '"translation":[0,0,0],"translation":[0,0,0]',
    );
    expect(() => wire.buildAssetReviewDecisionResult(duplicate)).toThrow(/duplicate/iu);
  });

  test('does not retain caller arrays in reviewed transforms', () => {
    const request = approvalRequest();
    const built = wire.buildAssetReviewDecisionRequest(request);
    request.reviewedTransform.translation[0] = 99;
    request.reviewedTransform.rotation.reverse();
    expect(built.reviewedTransform.translation).toEqual([0, 0, 0]);
    expect(built.reviewedTransform.rotation).toEqual([0, 0, 0, 1]);
    expectDeepFrozen(built);
  });
});
