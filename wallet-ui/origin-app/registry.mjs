import registrySource from '../relay/config/client-registry.v1.json' with { type: 'json' };

const textEncoder = new TextEncoder();
const RELEASE_SHA256 = /^[0-9a-f]{64}$/u;
const CLIENT_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/u;

const OPERATION_POLICY = Object.freeze({
  'sdn.wallet.account.v1': Object.freeze({
    audience: null,
    registryRow: null,
    serviceActivationState: null,
    serviceInstance: null,
  }),
  'sdn.wallet.connect.v1': Object.freeze({
    audience: null,
    registryRow: null,
    serviceActivationState: null,
    serviceInstance: null,
  }),
  'sdn.auth.raw-challenge.v1': Object.freeze({
    audience: 'sdn-login:sdn.spaceaware.io',
    registryRow: null,
    serviceActivationState: null,
    serviceInstance: null,
  }),
  'sdn.auth.jcs-envelope.v2': Object.freeze({
    audience: 'sdn-login:sdn.spaceaware.io',
    registryRow: 'sdn-node-console-v2',
    serviceActivationState: null,
    serviceInstance: null,
  }),
  'sdn.asset-review.authority-activation.v1': Object.freeze({
    audience: 'asset-review-authority:assets.ipfs.01',
    registryRow: 'asset-review-authority-activation-v1',
    serviceActivationState: 'unactivated',
    serviceInstance: 'assets.ipfs.01/asset-review-attestation',
  }),
  'sdn.asset-review.decision.v1': Object.freeze({
    audience: 'asset-review:assets.ipfs.01',
    registryRow: 'asset-review-decision-v1',
    serviceActivationState: 'activated',
    serviceInstance: null,
  }),
});

const PUBLIC_OPERATIONS = Object.freeze([
  'sdn.wallet.account.v1',
  'sdn.wallet.connect.v1',
]);
const SDN_OPERATIONS = Object.freeze([
  'sdn.auth.jcs-envelope.v2',
  'sdn.auth.raw-challenge.v1',
  ...PUBLIC_OPERATIONS,
]);
const REVIEW_OPERATIONS = Object.freeze([
  'sdn.asset-review.authority-activation.v1',
  'sdn.asset-review.decision.v1',
  ...PUBLIC_OPERATIONS,
]);

const EXPECTED_CLIENTS = Object.freeze([
  Object.freeze(['sdn-landing-web-v1', 'Space Data Network', 'https://spacedatanetwork.org', 'https://spacedatanetwork.org/wallet-callback.html', PUBLIC_OPERATIONS]),
  Object.freeze(['sdn-standards-web-v1', 'Space Data Standards', 'https://spacedatastandards.org', 'https://spacedatastandards.org/wallet-callback.html', PUBLIC_OPERATIONS]),
  Object.freeze(['sdn-flatbuffers-pages-v1', 'FlatBuffers Documentation', 'https://digitalarsenal.github.io', 'https://digitalarsenal.github.io/flatbuffers/wallet-callback.html', PUBLIC_OPERATIONS]),
  Object.freeze(['sdn-flatsql-pages-v1', 'FlatSQL Documentation', 'https://digitalarsenal.github.io', 'https://digitalarsenal.github.io/flatsql/wallet-callback.html', PUBLIC_OPERATIONS]),
  Object.freeze(['sdn-module-sdk-pages-v1', 'Space Data Module SDK', 'https://digitalarsenal.github.io', 'https://digitalarsenal.github.io/space-data-module-sdk/wallet-callback.html', PUBLIC_OPERATIONS]),
  Object.freeze(['spaceaware-web-v1', 'SpaceAware', 'https://spaceaware.io', 'https://spaceaware.io/wallet/callback', PUBLIC_OPERATIONS]),
  Object.freeze(['sdn-node-console-v1', 'SDN Node Console', 'https://sdn.spaceaware.io', 'https://sdn.spaceaware.io/wallet/callback', SDN_OPERATIONS]),
  Object.freeze(['orbpro-pages-v1', 'OrbPro', 'https://digitalarsenal.github.io', 'https://digitalarsenal.github.io/OrbPro/wallet-callback.html', PUBLIC_OPERATIONS]),
  Object.freeze(['sdn-asset-models-pages-v1', 'SDN Asset Models', 'https://digitalarsenal.github.io', 'https://digitalarsenal.github.io/asset-models/wallet-callback.html', PUBLIC_OPERATIONS]),
  Object.freeze(['sdn-asset-review-v1', 'SDN Asset Review', 'https://review.spacedatanetwork.org', 'https://review.spacedatanetwork.org/wallet/callback', REVIEW_OPERATIONS]),
]);

const COMPILED_SIGNING_ROWS = Object.freeze([
  Object.freeze({
    audience: 'sdn-login:sdn.spaceaware.io',
    clientId: 'sdn-node-console-v1',
    maxLifetimeSeconds: 300,
    operation: 'sdn.auth.jcs-envelope.v2',
    requestOrigin: 'https://sdn.spaceaware.io',
    registryRow: 'sdn-node-console-v2',
    serviceActivationState: null,
    serviceInstance: null,
  }),
  Object.freeze({
    audience: 'asset-review-authority:assets.ipfs.01',
    clientId: 'sdn-asset-review-v1',
    maxLifetimeSeconds: 300,
    operation: 'sdn.asset-review.authority-activation.v1',
    requestOrigin: 'https://review.spacedatanetwork.org',
    registryRow: 'asset-review-authority-activation-v1',
    serviceActivationState: 'unactivated',
    serviceInstance: 'assets.ipfs.01/asset-review-attestation',
  }),
  Object.freeze({
    audience: 'asset-review:assets.ipfs.01',
    clientId: 'sdn-asset-review-v1',
    maxLifetimeSeconds: 300,
    operation: 'sdn.asset-review.decision.v1',
    requestOrigin: 'https://review.spacedatanetwork.org',
    registryRow: 'asset-review-decision-v1',
    serviceActivationState: 'activated',
    serviceInstance: null,
  }),
]);

function fail(message) {
  throw new TypeError(message);
}

function isRecord(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function exactFields(value, expectedFields, label) {
  if (!isRecord(value)) fail(`${label} must be an object`);
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.some((key) => typeof key !== 'string')) fail(`${label} has missing or unknown fields`);
  const actual = ownKeys.sort();
  const expected = [...expectedFields].sort();
  if (actual.length !== expected.length || actual.some((name, index) => name !== expected[index])) {
    fail(`${label} has missing or unknown fields`);
  }
  for (const name of actual) {
    const descriptor = Object.getOwnPropertyDescriptor(value, name);
    if (!descriptor || !descriptor.enumerable || !('value' in descriptor)
        || descriptor.value === undefined) {
      fail(`${label} has an invalid field`);
    }
  }
  return value;
}

function canonicalJson(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) fail('registry contains a non-finite number');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (!isRecord(value)) fail('registry contains an unsupported value');
  return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`).join(',')}}`;
}

async function sha256Hex(value) {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) fail('Web Crypto SHA-256 is unavailable');
  const digest = new Uint8Array(await subtle.digest('SHA-256', textEncoder.encode(value)));
  return Array.from(digest, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

function freezeCopy(value) {
  if (Array.isArray(value)) return Object.freeze(value.map(freezeCopy));
  if (!isRecord(value)) return value;
  const copy = {};
  for (const key of Object.keys(value).sort()) copy[key] = freezeCopy(value[key]);
  return Object.freeze(copy);
}

function validateHttpsOrigin(value, label) {
  if (typeof value !== 'string' || !value.startsWith('https://') || value.includes('*')) fail(`${label} must be exact HTTPS`);
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail(`${label} must be a valid URL`);
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port
      || parsed.origin !== value || parsed.pathname !== '/' || parsed.search || parsed.hash) {
    fail(`${label} must be an exact HTTPS origin`);
  }
}

function validateHttpsCallback(value, origin) {
  if (typeof value !== 'string' || !value.startsWith('https://') || value.includes('*')) fail('callbackUri must be exact HTTPS');
  let parsed;
  try {
    parsed = new URL(value);
  } catch {
    fail('callbackUri must be a valid URL');
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password || parsed.port
      || parsed.origin !== origin || parsed.search || parsed.hash || parsed.href !== value) {
    fail('callbackUri must be exact and same-origin');
  }
}

function validateRegistry(value) {
  exactFields(value, ['clients', 'registryReleaseSha256', 'schemaVersion'], 'registry');
  if (value.schemaVersion !== 1) fail('registry schemaVersion must be 1');
  if (typeof value.registryReleaseSha256 !== 'string' || !RELEASE_SHA256.test(value.registryReleaseSha256)) {
    fail('registryReleaseSha256 must be lowercase SHA-256');
  }
  if (!Array.isArray(value.clients) || value.clients.length !== EXPECTED_CLIENTS.length) {
    fail('registry must contain exactly the reviewed clients');
  }

  const seenClients = new Set();
  const seenBindings = new Set();
  value.clients.forEach((client, clientIndex) => {
    exactFields(client, [
      'allowedOperations',
      'audiences',
      'callbackUri',
      'clientDisplayName',
      'clientId',
      'operationBindings',
      'requestOrigin',
    ], `client ${clientIndex}`);
    const [expectedId, expectedName, expectedOrigin, expectedCallback, expectedOperations] = EXPECTED_CLIENTS[clientIndex];
    if (client.clientId !== expectedId || client.clientDisplayName !== expectedName
        || client.requestOrigin !== expectedOrigin || client.callbackUri !== expectedCallback) {
      fail(`client ${clientIndex} differs from the reviewed row`);
    }
    if (!CLIENT_ID.test(client.clientId) || seenClients.has(client.clientId)) fail('clientId must be unique and canonical');
    seenClients.add(client.clientId);
    if (typeof client.clientDisplayName !== 'string' || client.clientDisplayName.length < 1
        || client.clientDisplayName.length > 80) fail('clientDisplayName is invalid');
    validateHttpsOrigin(client.requestOrigin, 'requestOrigin');
    validateHttpsCallback(client.callbackUri, client.requestOrigin);
    if (!Array.isArray(client.allowedOperations)
        || canonicalJson(client.allowedOperations) !== canonicalJson(expectedOperations)) {
      fail(`${client.clientId} allowedOperations differ from the reviewed allowlist`);
    }
    if (!Array.isArray(client.operationBindings)
        || client.operationBindings.length !== expectedOperations.length) {
      fail(`${client.clientId} operationBindings differ from the reviewed allowlist`);
    }
    client.operationBindings.forEach((operation, operationIndex) => {
      exactFields(operation, [
        'audience',
        'maxLifetimeSeconds',
        'operation',
        'registryRow',
        'serviceActivationState',
        'serviceInstance',
      ], `${client.clientId} operation ${operationIndex}`);
      const expectedOperation = expectedOperations[operationIndex];
      if (operation.operation !== expectedOperation) fail(`${client.clientId} operation allowlist order or value changed`);
      const policy = OPERATION_POLICY[operation.operation];
      if (!policy) fail('unknown registry operation');
      if (operation.maxLifetimeSeconds !== 300 || operation.audience !== policy.audience
          || operation.registryRow !== policy.registryRow
          || operation.serviceActivationState !== policy.serviceActivationState
          || operation.serviceInstance !== policy.serviceInstance) {
        fail(`${client.clientId} operation policy differs from the reviewed binding`);
      }
      const key = `${client.clientId}\u0000${client.requestOrigin}\u0000${operation.operation}`;
      if (seenBindings.has(key)) fail('duplicate registry binding');
      seenBindings.add(key);
    });
    const projectedAudiences = [...new Set(client.operationBindings
      .map(({ audience }) => audience)
      .filter((audience) => audience !== null))].sort();
    if (!Array.isArray(client.audiences)
        || canonicalJson(client.audiences) !== canonicalJson(projectedAudiences)) {
      fail(`${client.clientId} audiences differ from operationBindings`);
    }
    if (canonicalJson(client.allowedOperations)
        !== canonicalJson(client.operationBindings.map(({ operation }) => operation))) {
      fail(`${client.clientId} allowedOperations differ from operationBindings`);
    }
  });

  for (const expected of COMPILED_SIGNING_ROWS) {
    const client = value.clients.find((candidate) => candidate.clientId === expected.clientId
      && candidate.requestOrigin === expected.requestOrigin);
    const operation = client?.operationBindings.find((candidate) => candidate.operation === expected.operation);
    const actual = operation && {
      audience: operation.audience,
      clientId: client.clientId,
      maxLifetimeSeconds: operation.maxLifetimeSeconds,
      operation: operation.operation,
      requestOrigin: client.requestOrigin,
      registryRow: operation.registryRow,
      serviceActivationState: operation.serviceActivationState,
      serviceInstance: operation.serviceInstance,
    };
    if (!actual || canonicalJson(actual) !== canonicalJson(expected)) {
      fail(`registry projection drifted from compiled row ${expected.registryRow}`);
    }
  }

  return freezeCopy(value);
}

const { registryReleaseSha256, ...unsignedRegistry } = registrySource;
const computedReleaseSha256 = await sha256Hex(canonicalJson(unsignedRegistry));
if (computedReleaseSha256 !== registryReleaseSha256) fail('registry release SHA-256 mismatch');
const immutableRegistry = validateRegistry(registrySource);

export function verifyRegistry() {
  return freezeCopy(immutableRegistry);
}

export function resolveRegistryBinding(input) {
  const value = exactFields(input, ['clientId', 'operation', 'requestOrigin'], 'registry lookup');
  if (typeof value.clientId !== 'string' || typeof value.requestOrigin !== 'string'
      || typeof value.operation !== 'string') fail('registry lookup fields must be strings');
  const client = immutableRegistry.clients.find((candidate) => candidate.clientId === value.clientId
    && candidate.requestOrigin === value.requestOrigin);
  const operation = client?.operationBindings.find((candidate) => candidate.operation === value.operation);
  if (!client || !operation) fail('no exact registry binding exists');
  return freezeCopy({
    audience: operation.audience,
    callbackUri: client.callbackUri,
    clientDisplayName: client.clientDisplayName,
    clientId: client.clientId,
    maxLifetimeSeconds: operation.maxLifetimeSeconds,
    operation: operation.operation,
    requestOrigin: client.requestOrigin,
    registryReleaseSha256: immutableRegistry.registryReleaseSha256,
    registryRow: operation.registryRow,
    serviceActivationState: operation.serviceActivationState,
    serviceInstance: operation.serviceInstance,
  });
}
