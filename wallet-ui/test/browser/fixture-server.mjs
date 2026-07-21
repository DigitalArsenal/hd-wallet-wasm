import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
import { createHash, webcrypto } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import {
  SubjectAlternativeNameExtension,
  X509CertificateGenerator,
  cryptoProvider,
} from '@peculiar/x509';

const PROXY_PORT = 18_776;
const CONSUMER_TLS_PORT = 18_777;
const WALLET_TLS_PORT = 18_778;
const CONSUMER_HOSTS = new Set(['spacedatanetwork.org', 'static.spacedatanetwork.org']);
const WALLET_HOST = 'wallet.spacedatanetwork.org';
const CONNECT_DESTINATIONS = new Map([
  ...[...CONSUMER_HOSTS].map((host) => [`${host}:443`, CONSUMER_TLS_PORT]),
  [`${WALLET_HOST}:443`, WALLET_TLS_PORT],
]);
const SYSTEM_CHROME_CONNECT_PROBES = new Set([
  'content-autofill.googleapis.com:443',
  'www.google.com:443',
]);
const MAPPED_ORIGINS = Object.freeze({
  consumer: 'https://spacedatanetwork.org',
  static: 'https://static.spacedatanetwork.org',
  wallet: 'https://wallet.spacedatanetwork.org',
});
const walletUiDirectory = fileURLToPath(new URL('../../', import.meta.url));
const walletHostDirectory = `${walletUiDirectory}dist/wallet-origin-host/`;
const walletIndex = readFileSync(`${walletHostDirectory}index.html`);
const walletIntegrityBytes = readFileSync(`${walletHostDirectory}integrity.json`);
const walletIntegrity = JSON.parse(walletIntegrityBytes.toString('utf8'));
const walletAssets = new Map(
  Object.keys(walletIntegrity.files)
    .filter((path) => path.startsWith('assets/'))
    .map((path) => [`/${path}`, readFileSync(`${walletHostDirectory}${path}`)]),
);
const publicClient = readFileSync(`${walletUiDirectory}dist/browser/sdn-wallet-public-client.js`);
const publicStyle = readFileSync(`${walletUiDirectory}dist/client/style.css`);
const callbackDocument = readFileSync(`${walletUiDirectory}dist/browser/wallet-callback.html`);
const callbackHelper = readFileSync(`${walletUiDirectory}dist/browser/sdn-wallet-callback.js`);
const registry = JSON.parse(readFileSync(`${walletUiDirectory}relay/config/client-registry.v1.json`, 'utf8'));
const registryClient = registry.clients.find(({ clientId }) => clientId === 'sdn-landing-web-v1');
if (!registryClient) throw new Error('browser fixture requires the frozen landing client');

const ledger = {
  browserProbes: [],
  connects: [],
  requests: [],
  unexpected: [],
};
const transactions = new Map();
const TAMPER_MODES = new Set([
  'origin-css',
  'origin-js',
  'origin-wasm',
  'public-css',
  'public-js',
]);
let tamperMode = null;

function resetFixture() {
  ledger.browserProbes.length = 0;
  ledger.connects.length = 0;
  ledger.requests.length = 0;
  ledger.unexpected.length = 0;
  transactions.clear();
  tamperMode = null;
}

function serializableFixture() {
  return {
    browserProbes: ledger.browserProbes.map((request) => ({ ...request })),
    connects: [...ledger.connects],
    requests: ledger.requests.map((request) => ({ ...request })),
    transactions: [...transactions.values()].map((record) => ({
      codeIssued: typeof record.code === 'string',
      completed: record.result !== null,
      ...record.public,
    })),
    tamperMode,
    unexpected: ledger.unexpected.map((request) => ({ ...request })),
  };
}

function digest(algorithm, bytes, encoding) {
  return createHash(algorithm).update(bytes).digest(encoding);
}

function immutablePath(name, extension, bytes) {
  return `/assets/hd-wallet-ui/2.0.22/${name}.${digest('sha256', bytes, 'hex')}.${extension}`;
}

function sri(bytes) {
  return `sha384-${digest('sha384', bytes, 'base64')}`;
}

const publicClientPath = immutablePath('sdn-wallet-public-client', 'js', publicClient);
const publicStylePath = immutablePath('sdn-wallet-public-client', 'css', publicStyle);
const staticAssets = new Map([
  [publicClientPath, {
    body: publicClient,
    contentType: 'text/javascript; charset=utf-8',
    tamperKind: 'public-js',
  }],
  [publicStylePath, {
    body: publicStyle,
    contentType: 'text/css; charset=utf-8',
    tamperKind: 'public-css',
  }],
]);

const instrumentationSource = Buffer.from(`(() => {
  const startup = { eventListeners: [], opens: 0, storageCalls: [], walletFetches: 0 };
  const fixture = { events: [], startup };
  const nativeOpen = window.open;
  const nativeFetch = window.fetch;
  const nativeAddEventListener = window.addEventListener;
  const nativeStorageGet = Storage.prototype.getItem;
  const nativeStorageSet = Storage.prototype.setItem;
  const nativeStorageRemove = Storage.prototype.removeItem;
  const recordStorage = (name, nativeMethod) => function (...args) {
    startup.storageCalls.push(name);
    return Reflect.apply(nativeMethod, this, args);
  };
  Storage.prototype.getItem = recordStorage('getItem', nativeStorageGet);
  Storage.prototype.setItem = recordStorage('setItem', nativeStorageSet);
  Storage.prototype.removeItem = recordStorage('removeItem', nativeStorageRemove);
  window.addEventListener = function (type, ...args) {
    if (type === 'storage') startup.eventListeners.push(type);
    return Reflect.apply(nativeAddEventListener, this, [type, ...args]);
  };
  window.fetch = function (input, ...args) {
    const url = typeof input === 'string' ? input : input?.url;
    if (typeof url === 'string' && url.startsWith('https://wallet.spacedatanetwork.org/')) {
      startup.walletFetches += 1;
    }
    return Reflect.apply(nativeFetch, this, [input, ...args]);
  };
  window.open = function (...args) {
    startup.opens += 1;
    fixture.events.push({
      args: [...args],
      kind: 'popup-open',
      sync: fixture.inTrustedHandler === true,
    });
    const result = Reflect.apply(nativeOpen, this, args);
    fixture.events.push({ kind: 'popup-return', returnedNull: result === null });
    return result;
  };
  Object.defineProperty(globalThis, '__walletTest', { value: fixture });
})();\n`);

const presenterSource = Buffer.from(`(() => {
  const fixture = globalThis.__walletTest;
  const client = globalThis.SDNWalletPublicClient.create({ clientId: 'sdn-landing-web-v1' });
  const presenters = [...document.querySelectorAll('[data-wallet-presenter]')];
  fixture.client = client;
  const render = (snapshot) => {
    fixture.snapshot = snapshot;
    for (const presenter of presenters) {
      const button = presenter.querySelector('button');
      const status = presenter.querySelector('[role="status"]');
      const connected = snapshot.status === 'connected';
      button.textContent = connected ? 'Account' : snapshot.status === 'opening' ? 'Opening wallet…' : 'Login';
      button.disabled = snapshot.status === 'opening';
      status.textContent = snapshot.error?.message ?? '';
    }
  };
  const invoke = (event) => {
    if (event.isTrusted !== true) return;
    fixture.inTrustedHandler = true;
    fixture.events.push({ kind: 'trusted-click', trusted: event.isTrusted });
    const connected = client.getSnapshot().status === 'connected';
    fixture.events.push({ kind: connected ? 'open-account-enter' : 'connect-enter' });
    const completion = connected ? client.openAccount() : client.connect();
    fixture.events.push({ kind: connected ? 'open-account-return' : 'connect-return' });
    fixture.inTrustedHandler = false;
    fixture.events.push({ kind: 'handler-return' });
    void completion.catch((error) => { fixture.lastError = { code: error?.code, message: error?.message }; });
  };
  for (const presenter of presenters) presenter.querySelector('button').addEventListener('click', invoke);
  fixture.unsubscribe = client.subscribe(render);
})();\n`);
const instrumentationPath = immutablePath('consumer-instrumentation', 'js', instrumentationSource);
const presenterPath = immutablePath('consumer-presenter', 'js', presenterSource);
const consumerAssets = new Map([
  [instrumentationPath, { body: instrumentationSource, contentType: 'text/javascript; charset=utf-8' }],
  [presenterPath, { body: presenterSource, contentType: 'text/javascript; charset=utf-8' }],
]);
const consumerHarness = Buffer.from(`<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="referrer" content="no-referrer">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SDN consumer isolation fixture</title>
<link data-public-client-style rel="stylesheet" href="${MAPPED_ORIGINS.static}${publicStylePath}" integrity="${sri(publicStyle)}" crossorigin="anonymous">
<script defer src="${instrumentationPath}" integrity="${sri(instrumentationSource)}"></script>
<script data-public-client-script defer src="${MAPPED_ORIGINS.static}${publicClientPath}" integrity="${sri(publicClient)}" crossorigin="anonymous"></script>
<script defer src="${presenterPath}" integrity="${sri(presenterSource)}"></script>
</head><body>
<main><h1 data-public-content>Public models remain available</h1>
<div data-wallet-presenter class="sdn-wallet-control"><button class="sdn-wallet-control__button" type="button">Login</button><span class="sdn-wallet-control__status" role="status" aria-live="polite"></span></div>
<div data-wallet-presenter class="sdn-wallet-control"><button class="sdn-wallet-control__button" type="button">Login</button><span class="sdn-wallet-control__status" role="status" aria-live="polite"></span></div>
</main></body></html>\n`);
const frameHarness = Buffer.from(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="referrer" content="no-referrer">
<title>Wallet frame refusal fixture</title></head><body>
<main><h1>Public frame test remains available</h1>
<iframe title="untrusted wallet frame" src="${MAPPED_ORIGINS.wallet}/transaction/${'f'.repeat(64)}"></iframe>
</main></body></html>\n`);
const CONSUMER_CSP = "default-src 'none'; script-src 'self' https://static.spacedatanetwork.org; style-src 'self' https://static.spacedatanetwork.org; connect-src https://wallet.spacedatanetwork.org; frame-src https://wallet.spacedatanetwork.org; object-src 'none'; base-uri 'none'; form-action 'none'";
const CALLBACK_CSP = "default-src 'none'; script-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function recordRequest(scope, request) {
  const entry = {
    host: requestHost(request),
    method: request.method ?? '',
    scope,
    url: request.url ?? '',
  };
  ledger.requests.push(entry);
  return entry;
}

function unexpected(entry) {
  ledger.unexpected.push(entry);
}

function recordBrowserProbe(request, entry) {
  if (request.method !== 'GET' || request.url !== '/favicon.ico'
      || request.headers['sec-fetch-dest'] !== 'image'
      || request.headers['sec-fetch-mode'] !== 'no-cors'
      || request.headers['sec-fetch-site'] !== 'same-origin') return false;
  ledger.browserProbes.push(entry);
  return true;
}
const WALLET_CSP = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; worker-src 'none'; manifest-src 'self'";
const WALLET_SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy': WALLET_CSP,
  'Cross-Origin-Embedder-Policy': 'require-corp',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=(), publickey-credentials-get=(self), publickey-credentials-create=(self)',
  'Referrer-Policy': 'no-referrer',
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
});

function pem(label, bytes) {
  const encoded = Buffer.from(bytes).toString('base64').match(/.{1,64}/gu).join('\n');
  return `-----BEGIN ${label}-----\n${encoded}\n-----END ${label}-----\n`;
}

// The private key is generated for this process only. No reusable test key or
// production trust material is written to the repository or filesystem.
cryptoProvider.set(webcrypto);
const tlsAlgorithm = {
  hash: 'SHA-256',
  modulusLength: 2048,
  name: 'RSASSA-PKCS1-v1_5',
  publicExponent: new Uint8Array([1, 0, 1]),
};
const tlsKeys = await webcrypto.subtle.generateKey(tlsAlgorithm, true, ['sign', 'verify']);
const tlsCertificate = await X509CertificateGenerator.createSelfSigned({
  extensions: [new SubjectAlternativeNameExtension([
    { type: 'dns', value: WALLET_HOST },
    ...[...CONSUMER_HOSTS].map((value) => ({ type: 'dns', value })),
  ])],
  keys: tlsKeys,
  name: `CN=${WALLET_HOST}`,
  notAfter: new Date('2036-01-01T00:00:00.000Z'),
  notBefore: new Date('2026-01-01T00:00:00.000Z'),
  serialNumber: '01',
  signingAlgorithm: tlsAlgorithm,
});
const certificate = tlsCertificate.toString('pem');
const privateKey = pem('PRIVATE KEY', await webcrypto.subtle.exportKey('pkcs8', tlsKeys.privateKey));

function requestHost(request) {
  const value = request.headers.host;
  return typeof value === 'string' ? value.toLowerCase().replace(/:443$/u, '') : '';
}

function send(response, status, body, headers = {}) {
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Length': String(body.byteLength),
    'X-Content-Type-Options': 'nosniff',
    ...headers,
  });
  response.end(body);
}

function deliveryBytes(kind, body, entry) {
  if (tamperMode !== kind) return body;
  const delivered = Buffer.from(body);
  const offset = Math.floor(delivered.byteLength / 2);
  delivered[offset] ^= 1;
  entry.tampered = kind;
  return delivered;
}

const consumerTlsServer = https.createServer({ cert: certificate, key: privateKey }, (request, response) => {
  const host = requestHost(request);
  const entry = recordRequest('consumer', request);
  if (!CONSUMER_HOSTS.has(host)) {
    unexpected(entry);
    send(response, 421, Buffer.from('misdirected\n'), { 'Content-Type': 'text/plain; charset=utf-8' });
    return;
  }
  if (host === 'spacedatanetwork.org' && request.method === 'GET' && request.url === '/harness') {
    send(response, 200, consumerHarness, {
      'Content-Security-Policy': CONSUMER_CSP,
      'Content-Type': 'text/html; charset=utf-8',
      'Referrer-Policy': 'no-referrer',
    });
    return;
  }
  if (host === 'spacedatanetwork.org' && request.method === 'GET'
      && request.url === '/frame-harness') {
    send(response, 200, frameHarness, {
      'Content-Security-Policy': "default-src 'none'; frame-src https://wallet.spacedatanetwork.org; style-src 'none'; object-src 'none'; base-uri 'none'",
      'Content-Type': 'text/html; charset=utf-8',
      'Referrer-Policy': 'no-referrer',
    });
    return;
  }
  if (host === 'spacedatanetwork.org' && request.method === 'GET'
      && request.url === '/wallet-callback.html') {
    send(response, 200, callbackDocument, {
      'Content-Security-Policy': CALLBACK_CSP,
      'Content-Type': 'text/html; charset=utf-8',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Referrer-Policy': 'no-referrer',
      'X-Frame-Options': 'DENY',
    });
    return;
  }
  if (host === 'spacedatanetwork.org' && request.method === 'GET'
      && request.url === '/sdn-wallet-callback.js') {
    send(response, 200, callbackHelper, {
      'Content-Type': 'text/javascript; charset=utf-8',
      'Cross-Origin-Resource-Policy': 'same-origin',
      'Referrer-Policy': 'no-referrer',
    });
    return;
  }
  if (host === 'spacedatanetwork.org' && request.method === 'GET' && consumerAssets.has(request.url)) {
    const asset = consumerAssets.get(request.url);
    send(response, 200, asset.body, {
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Content-Type': asset.contentType,
      'Cross-Origin-Resource-Policy': 'same-origin',
    });
    return;
  }
  if (host === 'static.spacedatanetwork.org' && request.method === 'GET' && staticAssets.has(request.url)) {
    const asset = staticAssets.get(request.url);
    send(response, 200, deliveryBytes(asset.tamperKind, asset.body, entry), {
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Content-Type': asset.contentType,
      'Cross-Origin-Resource-Policy': 'cross-origin',
    });
    return;
  }
  if (!recordBrowserProbe(request, entry)) unexpected(entry);
  send(response, 404, Buffer.from('not found\n'), { 'Content-Type': 'text/plain; charset=utf-8' });
});

function jsonBytes(value) {
  return Buffer.from(`${JSON.stringify(value)}\n`);
}

function corsHeaders(origin) {
  return {
    'Access-Control-Allow-Origin': origin,
    Vary: 'Origin',
  };
}

async function readJsonRequest(request, maximumBytes = 32 * 1024) {
  const chunks = [];
  let length = 0;
  for await (const chunk of request) {
    length += chunk.byteLength;
    if (length > maximumBytes) throw new Error('body too large');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

function publicIdentity() {
  const descriptor = (purpose, curve, signatureProfile, path, fill) => ({
    bip32Fingerprint: null,
    curve,
    derivation: 'slip10',
    encoding: 'raw',
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    keyId: `sha256:${fill.repeat(64)}`,
    path,
    publicKeyHex: fill.repeat(64),
    purpose,
    seedProfile: 'password-scrypt-v2',
    signatureProfile,
  });
  return {
    accountFingerprint: '1234abcd',
    accountIndex: 0,
    accountLabel: null,
    accountPeerId: `16Uiu2H${'1'.repeat(40)}`,
    accountXpub: `xpub${'1'.repeat(107)}`,
    identityScheme: 'sdn-bip32-slip10-purpose-v1',
    keys: [
      descriptor('asset-review-approval', 'ed25519', 'ed25519-over-sha256-jcs-v1', "m/44'/0'/0'/2'/0'", 'a'),
      descriptor('contact-encryption', 'x25519', null, "m/44'/0'/0'/1'/0'", 'b'),
      descriptor('sdn-authentication', 'ed25519', 'ed25519-over-sha256-jcs-v1', "m/44'/0'/0'/0'/0'", 'c'),
    ],
    schemaVersion: 1,
    seedProfile: 'password-scrypt-v2',
  };
}

function relayJson(response, status, value, origin = null) {
  send(response, status, jsonBytes(value), {
    ...WALLET_SECURITY_HEADERS,
    ...(origin ? corsHeaders(origin) : {}),
    'Content-Type': 'application/json; charset=utf-8',
  });
}

function pkceChallenge(verifier) {
  return digest('sha256', Buffer.from(verifier, 'ascii'), 'base64url');
}

async function handleRelay(request, response, entry) {
  const origin = request.headers.origin;
  const registrationPath = '/relay/v1/transactions';
  const redeemPath = '/relay/v1/codes/redeem';
  const transactionMatch = /^\/relay\/v1\/transactions\/([0-9a-f]{64})$/u.exec(request.url ?? '');
  const resultMatch = /^\/relay\/v1\/transactions\/([0-9a-f]{64})\/result$/u.exec(request.url ?? '');
  const cancelMatch = /^\/relay\/v1\/transactions\/([0-9a-f]{64})\/cancel$/u.exec(request.url ?? '');

  if (request.method === 'OPTIONS' && (request.url === registrationPath
      || request.url === redeemPath || cancelMatch)) {
    if (origin !== registryClient.requestOrigin) {
      relayJson(response, 403, { error: { code: 'FORBIDDEN', message: 'Forbidden' }, schemaVersion: 1 });
      return true;
    }
    send(response, 204, Buffer.alloc(0), {
      ...WALLET_SECURITY_HEADERS,
      ...corsHeaders(origin),
      'Access-Control-Allow-Headers': 'content-type',
      'Access-Control-Allow-Methods': 'POST',
    });
    return true;
  }

  if (request.method === 'POST' && request.url === registrationPath) {
    if (origin !== registryClient.requestOrigin
        || request.headers['content-type'] !== 'application/json') {
      relayJson(response, 403, { error: { code: 'FORBIDDEN', message: 'Forbidden' }, schemaVersion: 1 });
      return true;
    }
    const value = await readJsonRequest(request);
    entry.body = value;
    if (value?.schemaVersion !== 1 || value.clientId !== registryClient.clientId
        || !/^[0-9a-f]{64}$/u.test(value.transactionId)
        || !/^[0-9a-f]{64}$/u.test(value.state)
        || !/^[A-Za-z0-9_-]{43}$/u.test(value.codeChallenge)
        || value.codeChallengeMethod !== 'S256'
        || !['sdn.wallet.connect.v1', 'sdn.wallet.account.v1'].includes(value.operation)
        || JSON.stringify(value.request) !== '{}') {
      relayJson(response, 400, { error: { code: 'INVALID_REQUEST', message: 'Invalid request' }, schemaVersion: 1 }, origin);
      return true;
    }
    const expiresAt = new Date(Date.now() + 120_000).toISOString();
    const transaction = {
      callbackUri: registryClient.callbackUri,
      clientDisplayName: registryClient.clientDisplayName,
      clientId: value.clientId,
      expiresAt,
      operation: value.operation,
      registryVersion: registry.registryReleaseSha256,
      request: value.request,
      requestOrigin: registryClient.requestOrigin,
      requestSha256: digest('sha256', Buffer.from('{}'), 'hex'),
      resultToken: 'R'.repeat(43),
      schemaVersion: 1,
      state: value.state,
      transactionId: value.transactionId,
    };
    transactions.set(value.transactionId, {
      code: null,
      codeChallenge: value.codeChallenge,
      public: transaction,
      result: null,
    });
    relayJson(response, 201, {
      expiresAt,
      schemaVersion: 1,
      transactionId: value.transactionId,
    }, origin);
    return true;
  }

  if (request.method === 'GET' && transactionMatch) {
    const record = transactions.get(transactionMatch[1]);
    if (!record) {
      relayJson(response, 404, { error: { code: 'NOT_FOUND', message: 'Not found' }, schemaVersion: 1 });
      return true;
    }
    relayJson(response, 200, record.public);
    return true;
  }

  if (request.method === 'POST' && resultMatch) {
    if (request.headers['content-type'] !== 'application/json') {
      relayJson(response, 415, { error: { code: 'MEDIA_TYPE', message: 'Unsupported media type' }, schemaVersion: 1 });
      return true;
    }
    const value = await readJsonRequest(request, 70 * 1024);
    entry.body = value;
    const record = transactions.get(resultMatch[1]);
    if (!record || record.result !== null || value?.schemaVersion !== 1
        || value.transactionId !== resultMatch[1]
        || value.resultToken !== record.public.resultToken
        || value.result === null || typeof value.result !== 'object'
        || value.result.schemaVersion !== 1) {
      relayJson(response, 400, { error: { code: 'INVALID_RESULT', message: 'Invalid result' }, schemaVersion: 1 });
      return true;
    }
    if (record.public.operation === 'sdn.wallet.connect.v1'
        && (value.result.event !== 'connected' || !value.result.identity
          || typeof value.result.connectionExpiresAt !== 'string')) {
      relayJson(response, 400, { error: { code: 'INVALID_RESULT', message: 'Invalid result' }, schemaVersion: 1 });
      return true;
    }
    if (record.public.operation === 'sdn.wallet.account.v1'
        && !['connected', 'disconnected'].includes(value.result.event)) {
      relayJson(response, 400, { error: { code: 'INVALID_RESULT', message: 'Invalid result' }, schemaVersion: 1 });
      return true;
    }
    record.result = value.result;
    record.code = digest(
      'sha256',
      Buffer.from(`${record.public.transactionId}:${record.public.state}:${record.public.resultToken}`),
      'hex',
    );
    relayJson(response, 201, {
      redirectUri: `${record.public.callbackUri}#code=${record.code}&state=${record.public.state}`,
      schemaVersion: 1,
      transactionId: record.public.transactionId,
    });
    return true;
  }

  if (request.method === 'POST' && request.url === redeemPath) {
    if (origin !== registryClient.requestOrigin
        || request.headers['content-type'] !== 'application/json') {
      relayJson(response, 403, { error: { code: 'FORBIDDEN', message: 'Forbidden' }, schemaVersion: 1 });
      return true;
    }
    const value = await readJsonRequest(request, 2 * 1024);
    entry.body = value;
    const record = transactions.get(value?.transactionId);
    if (!record || record.result === null || value.schemaVersion !== 1
        || value.state !== record.public.state || value.code !== record.code
        || !/^[A-Za-z0-9_-]{43}$/u.test(value.codeVerifier)
        || pkceChallenge(value.codeVerifier) !== record.codeChallenge) {
      relayJson(response, 400, { error: { code: 'INVALID_BINDING', message: 'Invalid binding' }, schemaVersion: 1 }, origin);
      return true;
    }
    relayJson(response, 200, {
      result: record.result,
      schemaVersion: 1,
      transactionId: record.public.transactionId,
    }, origin);
    transactions.delete(record.public.transactionId);
    return true;
  }

  if (request.method === 'POST' && cancelMatch) {
    transactions.delete(cancelMatch[1]);
    send(response, 204, Buffer.alloc(0), {
      ...WALLET_SECURITY_HEADERS,
      ...(origin === registryClient.requestOrigin ? corsHeaders(origin) : {}),
    });
    return true;
  }
  return false;
}

const walletTlsServer = https.createServer({ cert: certificate, key: privateKey }, (request, response) => {
  const entry = recordRequest('wallet', request);
  if (requestHost(request) !== WALLET_HOST) {
    unexpected(entry);
    send(response, 421, Buffer.from('misdirected\n'), { 'Content-Type': 'text/plain; charset=utf-8' });
    return;
  }
  if ((request.url ?? '').startsWith('/relay/v1/')) {
    void handleRelay(request, response, entry).then((handled) => {
      if (handled) return;
      unexpected(entry);
      relayJson(response, 404, { error: { code: 'NOT_FOUND', message: 'Not found' }, schemaVersion: 1 });
    }).catch(() => {
      if (!response.headersSent) {
        relayJson(response, 400, { error: { code: 'INVALID_REQUEST', message: 'Invalid request' }, schemaVersion: 1 });
      } else {
        response.destroy();
      }
    });
    return;
  }
  if (request.method === 'GET' && (request.url === '/'
      || /^\/transaction\/[0-9a-f]{64}$/u.test(request.url ?? ''))) {
    send(response, 200, walletIndex, {
      ...WALLET_SECURITY_HEADERS,
      'Content-Type': 'text/html; charset=utf-8',
    });
    return;
  }
  if (request.method === 'GET' && request.url === '/integrity.json') {
    send(response, 200, walletIntegrityBytes, {
      ...WALLET_SECURITY_HEADERS,
      'Content-Type': 'application/json; charset=utf-8',
    });
    return;
  }
  if (request.method === 'GET' && walletAssets.has(request.url)) {
    const body = walletAssets.get(request.url);
    const extension = request.url.slice(request.url.lastIndexOf('.') + 1);
    const contentTypes = {
      css: 'text/css; charset=utf-8',
      js: 'text/javascript; charset=utf-8',
      wasm: 'application/wasm',
    };
    send(response, 200, deliveryBytes(`origin-${extension}`, body, entry), {
      ...WALLET_SECURITY_HEADERS,
      'Cache-Control': 'public, max-age=31536000, immutable',
      'Content-Type': contentTypes[extension],
    });
    return;
  }
  if (!recordBrowserProbe(request, entry)) unexpected(entry);
  send(response, 404, Buffer.from('not found\n'), {
    ...WALLET_SECURITY_HEADERS,
    'Content-Type': 'text/plain; charset=utf-8',
  });
});

const server = http.createServer((request, response) => {
  if (request.method === 'GET' && request.url === '/healthz') {
    response.writeHead(200, {
      'Cache-Control': 'no-store',
      'Content-Type': 'text/plain; charset=utf-8',
    });
    response.end('ok\n');
    return;
  }
  if (request.method === 'POST' && request.url === '/__fixture/reset') {
    resetFixture();
    response.writeHead(204, { 'Cache-Control': 'no-store' });
    response.end();
    return;
  }
  if (request.method === 'GET' && request.url === '/__fixture/snapshot') {
    const body = jsonBytes(serializableFixture());
    response.writeHead(200, {
      'Cache-Control': 'no-store',
      'Content-Length': String(body.byteLength),
      'Content-Type': 'application/json; charset=utf-8',
    });
    response.end(body);
    return;
  }
  if (request.method === 'POST' && request.url === '/__fixture/tamper') {
    void readJsonRequest(request, 256).then((value) => {
      if (value === null || typeof value !== 'object' || !TAMPER_MODES.has(value.mode)
          || Object.keys(value).length !== 1) {
        response.writeHead(400, { 'Cache-Control': 'no-store' });
        response.end();
        return;
      }
      tamperMode = value.mode;
      response.writeHead(204, { 'Cache-Control': 'no-store' });
      response.end();
    }).catch(() => {
      response.writeHead(400, { 'Cache-Control': 'no-store' });
      response.end();
    });
    return;
  }
  if (request.method === 'POST' && request.url === '/__fixture/complete') {
    void readJsonRequest(request, 2 * 1024).then((value) => {
      const record = transactions.get(value?.transactionId);
      if (!record || value.event !== 'connected' || record.result !== null) {
        const body = jsonBytes({ error: 'invalid fixture completion' });
        response.writeHead(400, {
          'Cache-Control': 'no-store',
          'Content-Length': String(body.byteLength),
          'Content-Type': 'application/json; charset=utf-8',
        });
        response.end(body);
        return;
      }
      record.result = {
        connectionExpiresAt: new Date(Date.now() + 60_000).toISOString(),
        event: 'connected',
        identity: publicIdentity(),
        schemaVersion: 1,
      };
      record.code = digest(
        'sha256',
        Buffer.from(`${record.public.transactionId}:${record.public.state}:${record.public.resultToken}`),
        'hex',
      );
      const body = jsonBytes({ code: record.code, state: record.public.state });
      response.writeHead(200, {
        'Cache-Control': 'no-store',
        'Content-Length': String(body.byteLength),
        'Content-Type': 'application/json; charset=utf-8',
      });
      response.end(body);
    }).catch(() => {
      response.writeHead(400, { 'Cache-Control': 'no-store' });
      response.end();
    });
    return;
  }
  unexpected({ host: request.headers.host ?? '', method: request.method ?? '', scope: 'proxy-http', url: request.url ?? '' });
  response.writeHead(403, {
    'Cache-Control': 'no-store',
    'Content-Type': 'text/plain; charset=utf-8',
  });
  response.end('forbidden\n');
});

function containTransportErrors(transportServer) {
  transportServer.on('connection', (socket) => {
    socket.on('error', () => socket.destroy());
  });
  transportServer.on('clientError', (_error, socket) => socket.destroy());
}

containTransportErrors(server);
containTransportErrors(consumerTlsServer);
containTransportErrors(walletTlsServer);
consumerTlsServer.on('tlsClientError', (_error, socket) => socket.destroy());
walletTlsServer.on('tlsClientError', (_error, socket) => socket.destroy());

server.on('connect', (request, clientSocket, head) => {
  const target = String(request.url ?? '').toLowerCase();
  const destination = CONNECT_DESTINATIONS.get(target);
  if (destination === undefined) {
    const entry = { host: target, method: 'CONNECT', scope: 'proxy', url: target };
    // System Chrome performs these browser-level connectivity/autofill probes
    // even with background networking disabled. Playwright does not surface
    // them as page requests. Attribute only these exact targets; both remain
    // denied, and browser tests independently reject non-frozen page requests.
    if (SYSTEM_CHROME_CONNECT_PROBES.has(target)) ledger.browserProbes.push(entry);
    else unexpected(entry);
    clientSocket.end('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
    return;
  }
  ledger.connects.push(target);
  const upstream = net.connect(destination, '127.0.0.1');
  upstream.once('connect', () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    if (head.byteLength !== 0) upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  // Chrome can reset a CONNECT tunnel more than once while tearing down an
  // isolated browser context. Keep permanent handlers on both pipe endpoints
  // so a later reset cannot become an unhandled process-level error.
  upstream.on('error', () => clientSocket.destroy());
  clientSocket.on('error', () => upstream.destroy());
});

await Promise.all([
  new Promise((resolve) => consumerTlsServer.listen(CONSUMER_TLS_PORT, '127.0.0.1', resolve)),
  new Promise((resolve) => walletTlsServer.listen(WALLET_TLS_PORT, '127.0.0.1', resolve)),
]);
server.listen(PROXY_PORT, '127.0.0.1');

const close = () => {
  server.close();
  consumerTlsServer.close();
  walletTlsServer.close(() => process.exit(0));
};
process.once('SIGINT', close);
process.once('SIGTERM', close);
