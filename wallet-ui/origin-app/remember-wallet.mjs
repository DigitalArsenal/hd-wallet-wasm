import { getWalletOriginCapabilities } from 'hd-wallet-wasm';

import { copyModernPublicIdentity } from './account.mjs';
import { createRandomFiller, randomBytes } from './rng.mjs';
import {
  beginRememberedWalletWrite,
  commitRememberedWalletWrite,
  decodeCanonicalBase64url,
  deleteQuarantinedWalletRecord,
  exportQuarantinedWalletRecord,
  forgetRememberedWallet,
  inspectQuarantinedWalletStorage,
  inspectRememberedWalletStorage,
} from '../src/wallet-storage.js';

const encoder = new TextEncoder();
const fatalDecoder = new TextDecoder('utf-8', { fatal: true });
const intrinsicFill = Uint8Array.prototype.fill;
const intrinsicUint8Slice = Uint8Array.prototype.slice;
const intrinsicUint8Subarray = Uint8Array.prototype.subarray;
const TypedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype);
const typedArrayBufferGetter = Object.getOwnPropertyDescriptor(TypedArrayPrototype, 'buffer').get;
const typedArrayByteLengthGetter = Object.getOwnPropertyDescriptor(TypedArrayPrototype, 'byteLength').get;
const typedArrayByteOffsetGetter = Object.getOwnPropertyDescriptor(TypedArrayPrototype, 'byteOffset').get;
const arrayBufferByteLengthGetter = Object.getOwnPropertyDescriptor(ArrayBuffer.prototype, 'byteLength').get;
const intrinsicArrayBufferSlice = ArrayBuffer.prototype.slice;
const PROFILE = 'webauthn-prf-hkdf-sha256-aes256gcm-v2';
const IDENTITY_SCHEME = 'sdn-bip32-slip10-purpose-v1';
const SEED_PROFILE = 'password-scrypt-v2';
const DEFAULT_RP_NAME = 'Space Data Network Wallet';
const REQUEST_TIMEOUT = 120000;

export class RememberedWalletError extends Error {
  constructor(code) {
    super(code);
    this.name = 'RememberedWalletError';
    this.code = code;
  }
}

function fail(code) {
  throw new RememberedWalletError(code);
}

// WebAuthn Relying Party ID resolution.
//
// A passkey is bound to an rp.id, and the browser refuses any call whose rp.id
// is not the document origin's effective domain or a registrable suffix of it.
// This used to be the hard-coded constant 'wallet.spacedatanetwork.org', which
// made the remembered-wallet path work on exactly one deployment and throw
// SecurityError everywhere else — including every self-hosted SDN node.
//
// The rp.id is now HOST-INJECTABLE, defaulting to the serving origin, and it is
// VALIDATED against the current document origin before use. The validation is
// not defensive politeness: an rp.id the host may set to an arbitrary string is
// a phishing primitive. It would let a page served from one origin mint or
// assert credentials scoped to a domain it does not control, which is precisely
// the attack WebAuthn's origin binding exists to prevent. The browser would
// reject it too, but a library must not depend on a downstream check for a
// property it can enforce itself — refusing here means a misconfiguration fails
// loudly at the wallet boundary instead of surfacing as an opaque
// SecurityError deep inside a credential ceremony.
//
// Accepted: the current hostname, or a registrable suffix of it (app.example.com
// may use 'app.example.com' or 'example.com'). Refused: anything else, including
// a bare public suffix — the browser applies the public-suffix list on top of
// this, and we do not duplicate that list here.
function normalizeHostname(value) {
  if (typeof value !== 'string') return '';
  const trimmed = value.trim().toLowerCase();
  return trimmed.endsWith('.') ? trimmed.slice(0, -1) : trimmed;
}

export function resolveRelyingPartyId(requested, hostname) {
  // Nothing requested: OMIT rp.id entirely. WebAuthn defines the default as the
  // caller's effective domain, so omitting it is exactly "use the serving
  // origin" — what every self-hosted node wants. It needs no hostname lookup,
  // works in any embedding, and cannot drift from the real origin the way a
  // computed string can.
  if (requested === undefined || requested === null || requested === '') return undefined;

  const candidate = normalizeHostname(requested);
  if (candidate === '') fail('INVALID_RP_ID');

  const current = normalizeHostname(hostname);
  if (current === '') {
    // Origin unknown (non-browser embedding, test harness). The registrable
    // suffix rule cannot be checked here, but the BROWSER always enforces it,
    // so a wrong value still cannot mint a credential for a domain the page
    // does not control. Accept the well-formed string rather than fail closed
    // and break legitimate embeddings.
    return candidate;
  }
  if (candidate === current) return candidate;
  if (current.endsWith(`.${candidate}`)) return candidate;
  fail('INVALID_RP_ID');
  return undefined;
}

function wipe(bytes) {
  if (!(bytes instanceof Uint8Array)) return;
  try { intrinsicFill.call(bytes, 0); } catch { /* detached secret bytes are unusable */ }
}

function ordinaryRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactKeys(value, expected) {
  if (!ordinaryRecord(value)) return false;
  let keys;
  try { keys = Reflect.ownKeys(value); } catch { return false; }
  if (keys.some((key) => typeof key !== 'string')) return false;
  const actual = [...keys].sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length
    && actual.every((key, index) => key === sortedExpected[index]);
}

function exactDataRecord(value, expected) {
  if (!exactKeys(value, expected)) return null;
  const output = {};
  for (const field of expected) {
    let descriptor;
    try { descriptor = Object.getOwnPropertyDescriptor(value, field); } catch { return null; }
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) {
      return null;
    }
    output[field] = descriptor.value;
  }
  return output;
}

function ordinaryFullSpanBytes(value, length = null) {
  if (!(value instanceof Uint8Array) || Object.getPrototypeOf(value) !== Uint8Array.prototype) {
    return false;
  }
  let buffer;
  let byteLength;
  let byteOffset;
  let bufferByteLength;
  try {
    buffer = Reflect.apply(typedArrayBufferGetter, value, []);
    byteLength = Reflect.apply(typedArrayByteLengthGetter, value, []);
    byteOffset = Reflect.apply(typedArrayByteOffsetGetter, value, []);
    bufferByteLength = Reflect.apply(arrayBufferByteLengthGetter, buffer, []);
  } catch {
    return false;
  }
  return Object.getPrototypeOf(buffer) === ArrayBuffer.prototype
    && byteOffset === 0 && byteLength === bufferByteLength
    && (length === null || byteLength === length);
}

function ordinaryArrayBuffer(value, minimum, maximum) {
  if (!(value instanceof ArrayBuffer) || Object.getPrototypeOf(value) !== ArrayBuffer.prototype) {
    return false;
  }
  let byteLength;
  try { byteLength = Reflect.apply(arrayBufferByteLengthGetter, value, []); } catch { return false; }
  return byteLength >= minimum && byteLength <= maximum;
}

function uint8ByteLength(value) {
  try { return Reflect.apply(typedArrayByteLengthGetter, value, []); } catch { return -1; }
}

function encodeBase64url(bytes) {
  let binary = '';
  const length = uint8ByteLength(bytes);
  if (length < 0) fail('INVALID_REMEMBERED_WALLET');
  for (let offset = 0; offset < length; offset += 0x8000) {
    binary += String.fromCharCode(...Reflect.apply(
      intrinsicUint8Subarray,
      bytes,
      [offset, offset + 0x8000],
    ));
  }
  return btoa(binary).replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
}

function hex(bytes) {
  let result = '';
  for (const byte of bytes) result += byte.toString(16).padStart(2, '0');
  return result;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!ordinaryRecord(value)) fail('INVALID_REMEMBERED_WALLET');
  return `{${Object.keys(value).sort().map((key) => (
    `${JSON.stringify(key)}:${canonicalJson(value[key])}`
  )).join(',')}}`;
}

function constantBytesEqual(left, right) {
  if (!(left instanceof Uint8Array) || !(right instanceof Uint8Array)) return false;
  const leftLength = uint8ByteLength(left);
  const rightLength = uint8ByteLength(right);
  if (leftLength < 0 || rightLength < 0) return false;
  const maximum = Math.max(leftLength, rightLength);
  let difference = leftLength ^ rightLength;
  for (let index = 0; index < maximum; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function sameIdentity(left, right) {
  return canonicalJson(left) === canonicalJson(right);
}

function snapshotCredential(credential) {
  if (!credential || (typeof credential !== 'object' && typeof credential !== 'function')) {
    fail('WEBAUTHN_INVALID_RESPONSE');
  }
  let type;
  let rawId;
  let extensionReader;
  try {
    type = credential.type;
    rawId = credential.rawId;
    extensionReader = credential.getClientExtensionResults;
  } catch {
    fail('WEBAUTHN_INVALID_RESPONSE');
  }
  if (type !== 'public-key' || !ordinaryArrayBuffer(rawId, 1, 1024)
      || typeof extensionReader !== 'function') {
    fail('WEBAUTHN_INVALID_RESPONSE');
  }
  return Object.freeze({
    rawId: new Uint8Array(Reflect.apply(intrinsicArrayBufferSlice, rawId, [0])),
    readExtensionResults() {
      try { return Reflect.apply(extensionReader, credential, []); } catch {
        fail('WEBAUTHN_PRF_REQUIRED');
      }
    },
  });
}

function creationPrfEnabled(snapshot) {
  const extensionResults = exactDataRecord(snapshot.readExtensionResults(), ['prf']);
  const prf = extensionResults ? exactDataRecord(extensionResults.prf, ['enabled']) : null;
  if (!prf || prf.enabled !== true) {
    fail('WEBAUTHN_PRF_REQUIRED');
  }
}

function assertionPrfOutput(credential, expectedCredentialId) {
  const snapshot = snapshotCredential(credential);
  const actualCredentialId = snapshot.rawId;
  if (!constantBytesEqual(actualCredentialId, expectedCredentialId)) {
    wipe(actualCredentialId);
    fail('WEBAUTHN_CREDENTIAL_MISMATCH');
  }
  wipe(actualCredentialId);
  const extensionResults = exactDataRecord(snapshot.readExtensionResults(), ['prf']);
  const prf = extensionResults ? exactDataRecord(extensionResults.prf, ['results']) : null;
  const results = prf ? exactDataRecord(prf.results, ['first']) : null;
  const first = results?.first;
  if (!ordinaryArrayBuffer(first, 32, 32)) {
    fail('WEBAUTHN_PRF_REQUIRED');
  }
  const platformPrf = new Uint8Array(first);
  const copy = Reflect.apply(intrinsicUint8Slice, platformPrf, []);
  wipe(platformPrf);
  return copy;
}

function makeAssertionRequest({ challenge, credentialId, prfInput, rpId, signal }) {
  return {
    publicKey: {
      allowCredentials: [{
        id: credentialId,
        type: 'public-key',
      }],
      challenge,
      extensions: { prf: { eval: { first: prfInput } } },
      ...(rpId === undefined ? {} : { rpId }),
      timeout: REQUEST_TIMEOUT,
      userVerification: 'required',
    },
    signal,
  };
}

async function requestAssertion({ assertCurrent, credentials, credentialId, fillRandom, prfInput, rpId, signal }) {
  const challenge = randomBytes(fillRandom, 32);
  let assertion;
  try {
    assertion = await credentials.get(makeAssertionRequest({
      challenge,
      credentialId,
      prfInput,
      rpId,
      signal,
    }));
  } catch (error) {
    assertCurrent();
    throw error;
  } finally {
    wipe(challenge);
  }
  assertCurrent();
  return assertionPrfOutput(assertion, credentialId);
}

function isWellFormed(value) {
  if (typeof value !== 'string') return false;
  for (let index = 0; index < value.length; index += 1) {
    const first = value.charCodeAt(index);
    if (first >= 0xd800 && first <= 0xdbff) {
      const second = value.charCodeAt(++index);
      if (!(second >= 0xdc00 && second <= 0xdfff)) return false;
    } else if (first >= 0xdc00 && first <= 0xdfff) {
      return false;
    }
  }
  return true;
}

function decodeUsername(input) {
  if (typeof input === 'string') {
    if (!isWellFormed(input)) fail('INVALID_USERNAME');
    const bytes = encoder.encode(input);
    if (bytes.length > 256) fail('INVALID_USERNAME');
    return input;
  }
  if (!ordinaryFullSpanBytes(input) || uint8ByteLength(input) > 256) {
    fail('INVALID_USERNAME');
  }
  try {
    return fatalDecoder.decode(input);
  } catch {
    fail('INVALID_USERNAME');
  }
}

export function canonicalizeWalletUsername(input) {
  const decoded = decodeUsername(input);
  const canonical = decoded
    .replace(/^ +/u, '')
    .replace(/ +$/u, '')
    .replace(/[A-Z]/gu, (character) => character.toLowerCase());
  const canonicalBytes = encoder.encode(canonical);
  if (canonicalBytes.length < 3 || canonicalBytes.length > 64
      || !/^[a-z0-9][a-z0-9._-]*$/u.test(canonical)) {
    fail('INVALID_USERNAME');
  }
  return canonical;
}

function requireCoordinatorDependencies(configuration) {
  let binding;
  try { binding = getWalletOriginCapabilities(configuration?.module); } catch {
    fail('WASM_UNAVAILABLE');
  }
  if (!exactKeys(binding, ['sdn', 'sha256'])
      || typeof binding.sha256 !== 'function'
      || !binding.sdn || typeof binding.sdn !== 'object') {
    fail('WASM_UNAVAILABLE');
  }
  return binding;
}

export function createRememberedWalletCoordinator(configuration) {
  const binding = requireCoordinatorDependencies(configuration);
  const capabilities = binding.sdn;
  const storage = configuration?.storage;
  const credentials = configuration?.credentials;
  const fillRandom = createRandomFiller(configuration?.rng);
  const createRequestController = configuration?.createRequestController;
  const releaseRequestController = configuration?.releaseRequestController;
  const ownHandle = configuration?.ownHandle;
  const destroyHandle = configuration?.destroyHandle;
  const ownedHandlesClean = configuration?.ownedHandlesClean;
  const now = configuration?.now ?? (() => new Date());
  // Resolved ONCE, at coordinator construction, against the serving origin —
  // so a bad rpId fails at wiring time rather than mid-ceremony, and cannot be
  // swapped between the create and assert halves of a single flow.
  const rpHostname = configuration?.rpHostname
    ?? configuration?.window?.location?.hostname
    ?? globalThis?.location?.hostname;
  const rpId = resolveRelyingPartyId(configuration?.rpId, rpHostname);
  const rpName = typeof configuration?.rpName === 'string' && configuration.rpName !== ''
    ? configuration.rpName
    : DEFAULT_RP_NAME;

  const supported = () => typeof credentials?.create === 'function'
    && typeof credentials?.get === 'function';

  const inspect = () => inspectRememberedWalletStorage(storage);

  const listQuarantine = () => inspectQuarantinedWalletStorage(storage);

  const exportQuarantine = (key) => exportQuarantinedWalletRecord(storage, key);

  const deleteQuarantine = (key, confirmation) => {
    deleteQuarantinedWalletRecord(storage, key, confirmation);
    if (listQuarantine().some((entry) => entry.key === key)) fail('STORAGE_WRITE_FAILED');
    return true;
  };

  const canForget = () => inspect().active.status === 'valid';

  const forget = ({ confirmation } = {}) => {
    if (!canForget()) fail('REMEMBER_UNAVAILABLE');
    forgetRememberedWallet(storage, confirmation);
    if (inspect().active.status !== 'empty') fail('STORAGE_WRITE_FAILED');
    return true;
  };

  const hashCanonicalUsername = async (canonicalUsername) => {
    let digest;
    try { digest = await binding.sha256(encoder.encode(canonicalUsername)); } catch {
      fail('WASM_FAILURE');
    }
    if (!ordinaryFullSpanBytes(digest, 32)) fail('WASM_FAILURE');
    return hex(digest);
  };

  const setup = async ({ assertCurrent, canonicalUsername, handle, identity, passwordUtf8 }) => {
    try {
    if (typeof assertCurrent !== 'function' || handle === null || handle === undefined
        || !ordinaryFullSpanBytes(passwordUtf8)
        || uint8ByteLength(passwordUtf8) === 0 || uint8ByteLength(passwordUtf8) > 256
        || canonicalizeWalletUsername(canonicalUsername) !== canonicalUsername
        || !supported() || typeof capabilities.sealRememberedIdentity !== 'function'
        || typeof capabilities.importRememberedIdentity !== 'function'
        || typeof ownHandle !== 'function' || typeof destroyHandle !== 'function'
        || typeof ownedHandlesClean !== 'function'
        || typeof createRequestController !== 'function'
        || typeof releaseRequestController !== 'function') {
      wipe(passwordUtf8);
      fail('REMEMBER_UNAVAILABLE');
    }
    const sourceIdentity = copyModernPublicIdentity(identity);
    const state = inspect();
    if (!state.canSetup) {
      wipe(passwordUtf8);
      fail('STORAGE_QUARANTINED');
    }
    const requestController = typeof createRequestController === 'function'
      ? createRequestController()
      : null;
    if (!requestController?.signal || typeof requestController.abort !== 'function') {
      wipe(passwordUtf8);
      fail('WEBAUTHN_UNAVAILABLE');
    }
    let creationChallenge;
    let userHandle;
    let prfInput;
    let hkdfSalt;
    let nonce;
    let credentialId;
    let rawPrf;
    let sealingPrf;
    let verificationPrf;
    let verificationHandle = null;
    let pendingTransaction = null;
    try {
      creationChallenge = randomBytes(fillRandom, 32);
      userHandle = randomBytes(fillRandom, 32);
      prfInput = randomBytes(fillRandom, 32);
      hkdfSalt = randomBytes(fillRandom, 32);
      nonce = randomBytes(fillRandom, 12);
      assertCurrent();
      let credential;
      try {
        credential = await credentials.create({
          publicKey: {
            attestation: 'none',
            authenticatorSelection: {
              residentKey: 'preferred',
              userVerification: 'required',
            },
            challenge: creationChallenge,
            extensions: { prf: {} },
            pubKeyCredParams: [
              { alg: -7, type: 'public-key' },
              { alg: -257, type: 'public-key' },
            ],
            rp: rpId === undefined ? { name: rpName } : { id: rpId, name: rpName },
            timeout: REQUEST_TIMEOUT,
            user: {
              displayName: canonicalUsername,
              id: userHandle,
              name: canonicalUsername,
            },
          },
          signal: requestController.signal,
        });
      } catch (error) {
        assertCurrent();
        throw error;
      }
      assertCurrent();
      const credentialSnapshot = snapshotCredential(credential);
      credentialId = credentialSnapshot.rawId;
      creationPrfEnabled(credentialSnapshot);
      rawPrf = await requestAssertion({
        assertCurrent,
        credentialId,
        credentials,
        fillRandom,
        prfInput,
        rpId,
        signal: requestController.signal,
      });
      sealingPrf = rawPrf.slice();
      verificationPrf = rawPrf.slice();
      wipe(rawPrf);
      rawPrf = null;
      const usernameSha256 = await hashCanonicalUsername(canonicalUsername);
      assertCurrent();
      const credentialIdBase64url = encodeBase64url(credentialId);
      const aad = Object.freeze({
        credentialIdBase64url,
        identityScheme: IDENTITY_SCHEME,
        schemaVersion: 2,
        seedProfile: SEED_PROFILE,
        storageProfile: PROFILE,
        usernameSha256,
      });
      const canonicalAad = canonicalJson(aad);
      let sealed;
      try {
        sealed = capabilities.sealRememberedIdentity(handle, {
          canonicalAad,
          hkdfSalt,
          nonce,
          passwordUtf8,
          prfOutput: sealingPrf,
        });
      } finally {
        wipe(passwordUtf8);
        wipe(sealingPrf);
      }
      passwordUtf8 = null;
      sealingPrf = null;
      const sealedLength = uint8ByteLength(sealed);
      if (!ordinaryFullSpanBytes(sealed) || sealedLength < 17 || sealedLength > 1024) {
        fail('WASM_FAILURE');
      }
      let createdAt;
      try {
        const instant = now();
        createdAt = instant instanceof Date ? instant.toISOString() : new Date(instant).toISOString();
      } catch {
        fail('CLOCK_FAILURE');
      }
      const candidate = Object.freeze({
        aad,
        canonicalUsername,
        ciphertextBase64url: encodeBase64url(sealed),
        createdAt,
        credentialIdBase64url,
        hkdfSaltBase64url: encodeBase64url(hkdfSalt),
        nonceBase64url: encodeBase64url(nonce),
        prfInputBase64url: encodeBase64url(prfInput),
        schemaVersion: 2,
        storageProfile: PROFILE,
      });
      assertCurrent();
      pendingTransaction = beginRememberedWalletWrite(storage, candidate);
      let restored;
      const openPrf = verificationPrf;
      try {
        restored = capabilities.importRememberedIdentity({
          canonicalAad,
          canonicalUsernameUtf8: encoder.encode(canonicalUsername),
          ciphertextAndTag: sealed.slice(),
          hkdfSalt: hkdfSalt.slice(),
          nonce: nonce.slice(),
          prfOutput: openPrf,
        });
      } finally {
        wipe(openPrf);
        verificationPrf = null;
      }
      if (!ordinaryRecord(restored)) fail('WASM_FAILURE');
      verificationHandle = restored.handle;
      if (verificationHandle === null || verificationHandle === undefined
          || typeof ownHandle !== 'function') {
        fail('WASM_FAILURE');
      }
      ownHandle(verificationHandle);
      const restoredIdentity = copyModernPublicIdentity(restored.identity);
      if (!sameIdentity(sourceIdentity, restoredIdentity)) fail('IDENTITY_MISMATCH');
      assertCurrent();
      if (typeof destroyHandle !== 'function' || !destroyHandle(verificationHandle)) {
        fail('DESTRUCTION_FAILED');
      }
      verificationHandle = null;
      if (typeof ownedHandlesClean !== 'function' || !ownedHandlesClean(handle)) {
        fail('DESTRUCTION_FAILED');
      }
      assertCurrent();
      commitRememberedWalletWrite(storage, pendingTransaction);
      pendingTransaction = null;
      return Object.freeze({ remembered: true });
    } finally {
      if (verificationHandle !== null && typeof destroyHandle === 'function') {
        destroyHandle(verificationHandle);
      }
      wipe(passwordUtf8);
      wipe(creationChallenge);
      wipe(userHandle);
      wipe(rawPrf);
      wipe(sealingPrf);
      wipe(verificationPrf);
      wipe(hkdfSalt);
      wipe(nonce);
      wipe(credentialId);
      if (typeof releaseRequestController === 'function') {
        releaseRequestController(requestController);
      }
    }
    } finally {
      wipe(passwordUtf8);
    }
  };

  const restore = async ({ assertCurrent } = {}) => {
    if (typeof assertCurrent !== 'function' || !supported()
        || typeof capabilities.importRememberedIdentity !== 'function'
        || typeof ownHandle !== 'function' || typeof destroyHandle !== 'function'
        || typeof createRequestController !== 'function'
        || typeof releaseRequestController !== 'function') {
      fail('REMEMBER_UNAVAILABLE');
    }
    const state = inspect();
    if (!state.canRestore || !state.active.record) fail('STORAGE_QUARANTINED');
    const record = state.active.record;
    if (canonicalizeWalletUsername(record.canonicalUsername) !== record.canonicalUsername) {
      fail('INVALID_REMEMBERED_WALLET');
    }
    const usernameSha256 = await hashCanonicalUsername(record.canonicalUsername);
    if (usernameSha256 !== record.aad.usernameSha256) fail('INVALID_REMEMBERED_WALLET');
    assertCurrent();
    const credentialId = decodeCanonicalBase64url(record.credentialIdBase64url, {
      minimum: 1,
      maximum: 1024,
    });
    const prfInput = decodeCanonicalBase64url(record.prfInputBase64url, { exact: 32 });
    const ciphertextAndTag = decodeCanonicalBase64url(record.ciphertextBase64url, {
      minimum: 17,
      maximum: 1024,
    });
    const hkdfSalt = decodeCanonicalBase64url(record.hkdfSaltBase64url, { exact: 32 });
    const nonce = decodeCanonicalBase64url(record.nonceBase64url, { exact: 12 });
    const canonicalUsernameUtf8 = encoder.encode(record.canonicalUsername);
    const canonicalAad = canonicalJson(record.aad);
    const requestController = typeof createRequestController === 'function'
      ? createRequestController()
      : null;
    if (!requestController?.signal || typeof requestController.abort !== 'function') {
      wipe(credentialId);
      wipe(prfInput);
      wipe(ciphertextAndTag);
      wipe(hkdfSalt);
      wipe(nonce);
      wipe(canonicalUsernameUtf8);
      fail('WEBAUTHN_UNAVAILABLE');
    }
    let prfOutput;
    let restoredHandle = null;
    let completed = false;
    try {
      prfOutput = await requestAssertion({
        assertCurrent,
        credentialId,
        credentials,
        fillRandom,
        prfInput,
        rpId,
        signal: requestController.signal,
      });
      assertCurrent();
      let restored;
      const openPrf = prfOutput;
      try {
        restored = capabilities.importRememberedIdentity({
          canonicalAad,
          canonicalUsernameUtf8,
          ciphertextAndTag,
          hkdfSalt,
          nonce,
          prfOutput: openPrf,
        });
      } finally {
        wipe(openPrf);
        prfOutput = null;
      }
      if (!ordinaryRecord(restored)) fail('WASM_FAILURE');
      restoredHandle = restored.handle;
      if (restoredHandle === null || restoredHandle === undefined || typeof ownHandle !== 'function') {
        fail('WASM_FAILURE');
      }
      ownHandle(restoredHandle);
      const identity = copyModernPublicIdentity(restored.identity);
      assertCurrent();
      completed = true;
      return Object.freeze({ handle: restoredHandle, identity });
    } finally {
      if (!completed && restoredHandle !== null && typeof destroyHandle === 'function') {
        if (!destroyHandle(restoredHandle)) fail('DESTRUCTION_FAILED');
      }
      wipe(prfOutput);
      wipe(credentialId);
      wipe(prfInput);
      wipe(ciphertextAndTag);
      wipe(hkdfSalt);
      wipe(nonce);
      wipe(canonicalUsernameUtf8);
      if (typeof releaseRequestController === 'function') {
        releaseRequestController(requestController);
      }
    }
  };

  return Object.freeze({
    canForget,
    deleteQuarantine,
    exportQuarantine,
    forget,
    inspect,
    listQuarantine,
    restore,
    setup,
    supported,
  });
}
