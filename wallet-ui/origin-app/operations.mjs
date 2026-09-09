import {
  buildAssetReviewAuthorityActivationResult,
  buildAssetReviewDecisionResult,
  buildSdnLoginV1Result,
  buildSdnLoginV2Result,
  buildSdnPublishResult,
  buildWalletAccountResult,
  buildWalletConnectResult,
  parseAssetReviewAuthorityActivationRequest,
  parseAssetReviewDecisionRequest,
  parseSdnLoginV1Request,
  parseSdnLoginV2Request,
  parseSdnPublishRequest,
  parseWalletAccountRequest,
  parseWalletConnectRequest,
} from '../client/wire.mjs';

const TRANSACTION_FIELDS = Object.freeze([
  'callbackUri',
  'clientDisplayName',
  'clientId',
  'expiresAt',
  'operation',
  'registryVersion',
  'request',
  'requestOrigin',
  'requestSha256',
  'resultToken',
  'schemaVersion',
  'state',
  'transactionId',
]);
const LOWER_HEX_32 = /^[0-9a-f]{64}$/u;
const BASE64URL_32 = /^[A-Za-z0-9_-]{43}$/u;
const RFC3339_MILLISECONDS = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u;
const textEncoder = new TextEncoder();

const OPERATIONS = Object.freeze({
  'sdn.auth.publish-request.v1': Object.freeze({
    parseRequest: parseSdnPublishRequest,
    buildResult: buildSdnPublishResult,
    publish: true,
  }),
  'sdn.auth.jcs-envelope.v2': Object.freeze({
    parseRequest: parseSdnLoginV2Request,
    buildResult: buildSdnLoginV2Result,
    sign(capabilities, handle, request, binding) {
      return capabilities.signSdnLoginV2(handle, request, binding.registryRow);
    },
  }),
  'sdn.auth.raw-challenge.v1': Object.freeze({
    parseRequest: parseSdnLoginV1Request,
    buildResult: buildSdnLoginV1Result,
    sign(capabilities, handle, request) {
      return capabilities.signSdnLoginV1(handle, decodeBase64url32(request.challengeBase64url));
    },
  }),
  'sdn.asset-review.authority-activation.v1': Object.freeze({
    parseRequest: parseAssetReviewAuthorityActivationRequest,
    buildResult: buildAssetReviewAuthorityActivationResult,
    sign(capabilities, handle, request, binding) {
      return capabilities.signAssetReviewAuthorityActivation(handle, request, binding.registryRow);
    },
  }),
  'sdn.asset-review.decision.v1': Object.freeze({
    parseRequest: parseAssetReviewDecisionRequest,
    buildResult: buildAssetReviewDecisionResult,
    sign(capabilities, handle, request, binding) {
      return capabilities.signAssetReviewDecision(handle, request, binding.registryRow);
    },
  }),
  'sdn.wallet.account.v1': Object.freeze({
    parseRequest: parseWalletAccountRequest,
    buildResult: buildWalletAccountResult,
    connect: true,
  }),
  'sdn.wallet.connect.v1': Object.freeze({
    parseRequest: parseWalletConnectRequest,
    buildResult: buildWalletConnectResult,
    connect: true,
  }),
});

export class WalletOperationError extends Error {
  constructor(code) {
    super(code);
    this.name = 'WalletOperationError';
    this.code = code;
  }
}

function fail(code) {
  throw new WalletOperationError(code);
}

function isRecord(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactRecord(value, fields, code = 'INVALID_TRANSACTION') {
  if (!isRecord(value)) fail(code);
  let keys;
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    fail(code);
  }
  if (keys.some((key) => typeof key !== 'string')) fail(code);
  const actual = [...keys].sort();
  const expected = [...fields].sort();
  if (actual.length !== expected.length
      || actual.some((field, index) => field !== expected[index])) fail(code);
  const output = Object.create(null);
  for (const field of actual) {
    let descriptor;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, field);
    } catch {
      fail(code);
    }
    if (!descriptor?.enumerable || !('value' in descriptor) || descriptor.value === undefined) fail(code);
    output[field] = descriptor.value;
  }
  return output;
}

function exactTimestamp(value, code = 'INVALID_TRANSACTION') {
  if (typeof value !== 'string' || !RFC3339_MILLISECONDS.test(value)) fail(code);
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds) || new Date(milliseconds).toISOString() !== value) fail(code);
  return milliseconds;
}

function deepFreezeCopy(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(deepFreezeCopy));
  if (!isRecord(value)) return value;
  const copy = {};
  for (const key of Object.keys(value).sort()) copy[key] = deepFreezeCopy(value[key]);
  return Object.freeze(copy);
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('INVALID_TRANSACTION');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!isRecord(value)) fail('INVALID_TRANSACTION');
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

async function nativeRequestHash(request, sha256) {
  if (typeof sha256 !== 'function') fail('CRYPTO_UNAVAILABLE');
  let digest;
  try {
    digest = await sha256(textEncoder.encode(canonicalJson(request)));
  } catch {
    fail('CRYPTO_UNAVAILABLE');
  }
  if (!(digest instanceof Uint8Array) || digest.byteLength !== 32) fail('CRYPTO_UNAVAILABLE');
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function constantTimeString(left, right) {
  if (typeof left !== 'string' || typeof right !== 'string') return false;
  const maximum = Math.max(left.length, right.length);
  let difference = left.length ^ right.length;
  for (let index = 0; index < maximum; index += 1) {
    difference |= (left.charCodeAt(index) || 0) ^ (right.charCodeAt(index) || 0);
  }
  return difference === 0;
}

function resolveBinding(registry, lookup) {
  try {
    if (typeof registry?.resolveRegistryBinding === 'function') {
      return registry.resolveRegistryBinding(lookup);
    }
    if (typeof registry?.resolve === 'function') return registry.resolve(lookup);
    if (typeof registry === 'function') return registry(lookup);
  } catch (error) {
    if (error instanceof WalletOperationError) throw error;
    fail('UNREGISTERED_TRANSACTION');
  }
  fail('UNREGISTERED_TRANSACTION');
}

export function assertWalletContext({ document, window }) {
  let topLevel = false;
  try {
    topLevel = window?.top === window;
  } catch {
    topLevel = false;
  }
  if (!topLevel || document?.visibilityState !== 'visible'
      || typeof document?.hasFocus !== 'function' || document.hasFocus() !== true) {
    fail('WALLET_CONTEXT_UNTRUSTED');
  }
}

export async function validateWalletTransaction(
  input,
  {
    registry,
    relay,
    sha256,
    window,
    now = () => Date.now(),
    expectedTransactionId = null,
  },
) {
  const value = exactRecord(input, TRANSACTION_FIELDS);
  if (value.schemaVersion !== 1
      || typeof value.clientDisplayName !== 'string' || value.clientDisplayName.length < 1
      || value.clientDisplayName.length > 80
      || !LOWER_HEX_32.test(value.transactionId)
      || !LOWER_HEX_32.test(value.state)
      || !LOWER_HEX_32.test(value.requestSha256)
      || !BASE64URL_32.test(value.resultToken)) {
    fail('INVALID_TRANSACTION');
  }
  if (expectedTransactionId !== null && value.transactionId !== expectedTransactionId) {
    fail('INVALID_TRANSACTION');
  }
  const operation = OPERATIONS[value.operation];
  if (!operation) fail('UNREGISTERED_TRANSACTION');
  const binding = resolveBinding(registry, {
    clientId: value.clientId,
    operation: value.operation,
    requestOrigin: value.requestOrigin,
  });
  if (binding.registryReleaseSha256 !== value.registryVersion
      || binding.callbackUri !== value.callbackUri
      || binding.clientDisplayName !== value.clientDisplayName
      || binding.clientId !== value.clientId
      || binding.operation !== value.operation
      || binding.requestOrigin !== value.requestOrigin) {
    fail('REGISTRY_BINDING_MISMATCH');
  }
  const currentTime = now();
  const expiresAt = exactTimestamp(value.expiresAt);
  if (!Number.isFinite(currentTime) || expiresAt <= currentTime
      || expiresAt - currentTime > (binding.maxLifetimeSeconds * 1000)) {
    fail('TRANSACTION_EXPIRED');
  }
  let request;
  try {
    request = operation.parseRequest(value.request);
  } catch {
    fail('INVALID_TRANSACTION');
  }
  let requestSha256;
  try {
    requestSha256 = await nativeRequestHash(request, sha256);
  } catch (error) {
    if (error instanceof WalletOperationError) throw error;
    fail('CRYPTO_UNAVAILABLE');
  }
  if (!constantTimeString(requestSha256, value.requestSha256)) fail('REQUEST_HASH_MISMATCH');
  const canonicalTransaction = { ...value, request };
  return Object.freeze({
    binding: deepFreezeCopy(binding),
    operation,
    request: deepFreezeCopy(request),
    transaction: deepFreezeCopy(canonicalTransaction),
  });
}

function decodeBase64url32(value) {
  if (!BASE64URL_32.test(value)) fail('INVALID_TRANSACTION');
  let binary;
  try {
    binary = globalThis.atob(`${value.replace(/-/gu, '+').replace(/_/gu, '/')}=`);
  } catch {
    fail('INVALID_TRANSACTION');
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (bytes.byteLength !== 32) fail('INVALID_TRANSACTION');
  return bytes;
}

function appendRow(document, container, label, value) {
  const row = document.createElement('div');
  row.className = 'wallet-confirmation-row';
  const labelNode = document.createElement('strong');
  labelNode.textContent = `${label}: `;
  const valueNode = document.createElement('span');
  valueNode.textContent = value === null ? 'null' : typeof value === 'string' ? value : canonicalJson(value);
  row.append(labelNode, valueNode);
  container.append(row);
}

export function renderTransactionConfirmation(container, {
  binding,
  document,
  identity = null,
  request,
  transaction = null,
}) {
  container.replaceChildren();
  const heading = document.createElement('h1');
  heading.id = 'wallet-confirmation-heading';
  heading.textContent = 'Confirm wallet action';
  container.append(heading);
  appendRow(document, container, 'Client', binding.clientDisplayName);
  appendRow(document, container, 'Requesting origin', binding.requestOrigin);
  appendRow(document, container, 'Operation', binding.operation);
  if (binding.audience !== undefined) appendRow(document, container, 'Audience', binding.audience);
  if (binding.callbackUri !== undefined) appendRow(document, container, 'Callback URI', binding.callbackUri);
  if (transaction) {
    appendRow(document, container, 'Transaction ID', transaction.transactionId);
    appendRow(document, container, 'Request hash', transaction.requestSha256);
    appendRow(document, container, 'Registry release', transaction.registryVersion);
    appendRow(document, container, 'Transaction expiry', transaction.expiresAt);
  }
  const purpose = binding.operation.startsWith('sdn.asset-review.')
    ? 'asset-review-approval'
    : binding.operation.startsWith('sdn.auth.') ? 'sdn-authentication' : null;
  const key = purpose && Array.isArray(identity?.keys)
    ? identity.keys.find((candidate) => candidate?.purpose === purpose)
    : null;
  if (key?.keyId) appendRow(document, container, 'Signing key ID', key.keyId);
  if (binding.operation === 'sdn.auth.publish-request.v1') {
    appendRow(document, container, 'Action', 'Publish this exact payload to the provider shown below. This grants no session or future write permission.');
    appendRow(document, container, 'Descriptions', 'Entity name, ID, schema and document count are supplied by the requesting application; the wallet does not inspect or certify the payload.');
  }
  for (const field of Object.keys(request).sort()) appendRow(document, container, field, request[field]);
  return container;
}

async function signPublication({ assertCurrent, binding, capabilities, handle, identity, transaction }) {
  const request = parseSdnPublishRequest(transaction.request);
  if (binding.clientId !== 'spaceaware-web-v1' || binding.requestOrigin !== 'https://spaceaware.io'
      || binding.registryRow !== 'spaceaware-publish-request-v1'
      || typeof capabilities.signSdnPublishRequest !== 'function'
      || identity?.identityScheme !== 'sdn-bip32-slip10-purpose-v1' || identity?.seedProfile !== 'password-scrypt-v2') {
    fail('OPERATION_NOT_ALLOWED');
  }
  const keys = identity.keys?.filter(key => key?.purpose === 'sdn-authentication') ?? [];
  if (keys.length !== 1 || keys[0].identityScheme !== identity.identityScheme
      || keys[0].seedProfile !== identity.seedProfile || keys[0].curve !== 'ed25519'
      || !LOWER_HEX_32.test(keys[0].publicKeyHex) || !/^sha256:[0-9a-f]{64}$/u.test(keys[0].keyId)) fail('OPERATION_NOT_ALLOWED');
  const { publicKeyHex, keyId } = keys[0];
  const endpoint = `${request.providerOrigin}/api/auth/challenge`;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 10000);
  let challenge;
  try {
    assertCurrent();
    if (Date.now() >= exactTimestamp(transaction.expiresAt)) fail('TRANSACTION_EXPIRED');
    // executePrepared calls this only after its trusted confirmation and a
    // second registry/transaction check. The application never supplies a nonce.
    const response = await globalThis.fetch(endpoint, {
      method: 'POST', credentials: 'omit', redirect: 'error', cache: 'no-store', referrerPolicy: 'no-referrer',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ client_pubkey_hex: publicKeyHex, ts: Math.floor(Date.now() / 1000) }),
      signal: controller.signal,
    });
    assertCurrent();
    if (!response.ok || response.redirected || (response.url && response.url !== endpoint)) fail('PROVIDER_CHALLENGE_FAILED');
    const reader = response.body?.getReader();
    if (!reader) fail('PROVIDER_CHALLENGE_FAILED');
    const chunks = []; let length = 0;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        assertCurrent();
        if (done) break;
        length += value.byteLength;
        if (length > 4096) fail('PROVIDER_CHALLENGE_FAILED');
        chunks.push(value);
      }
    } finally { await reader.cancel().catch(() => {}); }
    const bytes = new Uint8Array(length); let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    challenge = exactRecord(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)), ['challenge_id', 'challenge', 'expires_at'], 'PROVIDER_CHALLENGE_FAILED');
    if (!/^[0-9a-f]{32}$/u.test(challenge.challenge_id) || !/^[A-Za-z0-9+/]{43}$/u.test(challenge.challenge)
        || !Number.isSafeInteger(challenge.expires_at) || challenge.expires_at * 1000 <= Date.now()
        || challenge.expires_at * 1000 - Date.now() > 300000) fail('PROVIDER_CHALLENGE_FAILED');
    const binary = globalThis.atob(`${challenge.challenge}=`);
    if (binary.length !== 32 || globalThis.btoa(binary).replace(/=+$/u, '') !== challenge.challenge) fail('PROVIDER_CHALLENGE_FAILED');
  } catch (error) {
    assertCurrent();
    if (error instanceof WalletOperationError) throw error;
    fail('PROVIDER_CHALLENGE_FAILED');
  } finally { clearTimeout(timer); }
  const challengeBase64url = challenge.challenge.replace(/\+/gu, '-').replace(/\//gu, '_').replace(/=+$/u, '');
  assertCurrent();
  if (Date.now() >= exactTimestamp(transaction.expiresAt) || challenge.expires_at * 1000 <= Date.now()) fail('TRANSACTION_EXPIRED');
  const raw = await capabilities.signSdnPublishRequest(handle, {
    ...request, challengeId: challenge.challenge_id, challengeBase64url,
  }, binding.registryRow);
  assertCurrent();
  if (Date.now() >= exactTimestamp(transaction.expiresAt) || challenge.expires_at * 1000 <= Date.now()) fail('TRANSACTION_EXPIRED');
  const signed = exactRecord(raw, ['schemaVersion', 'keyId', 'identityScheme', 'algorithm', 'encoding', 'signatureProfile', 'publicKeyHex', 'signatureHex', 'requestDigestSha256'], 'INVALID_WALLET_RESULT');
  if (signed.keyId !== keyId || signed.publicKeyHex !== publicKeyHex) fail('INVALID_WALLET_RESULT');
  return buildSdnPublishResult({ ...signed, challengeId: challenge.challenge_id, challengeBase64url });
}

export function requestTrustedConfirmation({ binding, document, identity = null, request, transaction = null }) {
  const previousFocus = document.activeElement ?? null;
  const root = document.createElement('section');
  root.className = 'wallet-confirmation';
  root.setAttribute?.('role', 'dialog');
  root.setAttribute?.('aria-modal', 'true');
  root.setAttribute?.('aria-labelledby', 'wallet-confirmation-heading');
  root.tabIndex = -1;
  renderTransactionConfirmation(root, { binding, document, identity, request, transaction });
  const actions = document.createElement('div');
  actions.className = 'wallet-confirmation-actions';
  const confirm = document.createElement('button');
  confirm.type = 'button';
  confirm.dataset.walletAction = 'confirm';
  confirm.textContent = request?.decision === 'approve'
    ? 'Approve'
    : request?.decision === 'disapprove'
      ? 'Disapprove'
      : binding.operation === 'sdn.asset-review.authority-activation.v1'
        ? 'Activate'
        : 'Confirm';
  const cancel = document.createElement('button');
  cancel.type = 'button';
  cancel.dataset.walletAction = 'cancel';
  cancel.textContent = 'Cancel';
  actions.append(confirm, cancel);
  root.append(actions);
  document.body.append(root);

  let settled = false;
  let resolvePromise;
  let rejectPromise;
  const promise = new Promise((resolve, reject) => {
    resolvePromise = resolve;
    rejectPromise = reject;
  });
  const finish = (accepted, event) => {
    if (settled || event?.isTrusted !== true) return;
    settled = true;
    confirm.disabled = true;
    cancel.disabled = true;
    if (accepted) resolvePromise();
    else rejectPromise(new WalletOperationError('USER_CANCELLED'));
  };
  const onConfirm = (event) => finish(true, event);
  const onCancel = (event) => finish(false, event);
  const onKeydown = (event) => {
    if (event?.isTrusted !== true) return;
    if (event.key === 'Escape') {
      event.preventDefault?.();
      finish(false, event);
      return;
    }
    if (event.key !== 'Tab') return;
    event.preventDefault?.();
    const active = document.activeElement;
    if (event.shiftKey === true) {
      (active === confirm ? cancel : confirm).focus?.();
    } else {
      (active === cancel ? confirm : cancel).focus?.();
    }
  };
  const onFocusIn = (event) => {
    let contained = false;
    try { contained = root.contains?.(event?.target) === true; } catch { contained = false; }
    if (!contained) confirm.focus?.();
  };
  confirm.addEventListener('click', onConfirm);
  cancel.addEventListener('click', onCancel);
  root.addEventListener('keydown', onKeydown);
  document.addEventListener?.('focusin', onFocusIn);
  try { confirm.focus?.(); } catch { /* focus remains within the popup document */ }
  return Object.freeze({
    promise,
    cancel(reason = 'STALE_CONTROLLER') {
      if (settled) return;
      settled = true;
      rejectPromise(new WalletOperationError(reason));
    },
    destroy() {
      confirm.removeEventListener?.('click', onConfirm);
      cancel.removeEventListener?.('click', onCancel);
      root.removeEventListener?.('keydown', onKeydown);
      document.removeEventListener?.('focusin', onFocusIn);
      root.remove();
      try { previousFocus?.focus?.(); } catch { /* prior node may no longer exist */ }
    },
  });
}

export async function executeWalletOperation({
  assertCurrent = () => {},
  binding,
  handle,
  identity,
  transaction,
  wasm,
}) {
  const capabilities = wasm?.sdn ?? wasm;
  const operation = OPERATIONS[transaction.operation];
  if (!operation || !capabilities) fail('OPERATION_NOT_ALLOWED');
  if (operation.publish) return signPublication({ assertCurrent, binding, capabilities, handle, identity, transaction });
  if (operation.connect) {
    return operation.buildResult({
      connectionExpiresAt: transaction.expiresAt,
      event: 'connected',
      identity,
      schemaVersion: 1,
    });
  }
  let rawResult;
  try {
    rawResult = await operation.sign(capabilities, handle, transaction.request, binding);
  } catch (error) {
    throw error;
  }
  assertCurrent();
  try {
    return operation.buildResult(rawResult);
  } catch {
    fail('INVALID_WALLET_RESULT');
  }
}

export function disconnectedAccountResult() {
  return buildWalletAccountResult({
    connectionExpiresAt: null,
    event: 'disconnected',
    identity: null,
    schemaVersion: 1,
  });
}
