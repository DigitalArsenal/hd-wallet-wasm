// Browser harness for the wallet E2Es (after npm run build:release).
//
// Chromium headless shell. The built public client runs on each site origin
// at <origin>[/<prefix>]/e2e.html?client=<clientId>; the built wallet origin
// (WASM) runs on https://wallet.spacedatanetwork.org; its relay is the relay's
// own registry and wire parsers with an in-memory store. The wallet is the
// throwaway vector account alice_01 (test/fixtures/sdn-wallet-vectors.v1.json).
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Builder } from 'flatbuffers';
import { chromium } from 'playwright';

import * as wire from '../../client/wire.mjs';

const ui = fileURLToPath(new URL('../../', import.meta.url));
const { ClientRegistry } = await import(new URL('../../relay/dist/src/registry.js', import.meta.url).href);
const { jcs, sha256Hex } = await import(new URL('../../relay/dist/src/json.js', import.meta.url).href);

export const WALLET = 'https://wallet.spacedatanetwork.org';
const USERNAME = 'alice_01';
const PASSWORD = 'Correct Horse Battery Staple!';
export const hex = (bytes) => Buffer.from(bytes).toString('hex');
export const unhex = (text) => new Uint8Array(Buffer.from(text, 'hex'));

export function reporter(name) {
  const checks = [];
  return {
    checks,
    fail(message) {
      console.error(`${name} E2E FAIL: ${message}`);
      process.exit(1);
    },
    pass(message) {
      checks.push(message);
      console.log(`  ok  ${message}`);
    },
  };
}

// The relay: its registry and wire parsers, an in-memory store.
const registry = new ClientRegistry();
const relayRequestParsers = {
  'sdn.wallet.connect.v1': wire.parseWalletConnectRequest,
  'sdn.wallet.field-open.v1': wire.parseFieldOpenRequest,
  'sdn.wallet.key-unwrap.v1': wire.parseKeyUnwrapRequest,
};
const relayResultParsers = {
  'sdn.wallet.field-open.v1': wire.parseFieldOpenResult,
  'sdn.wallet.key-unwrap.v1': wire.parseKeyUnwrapResult,
};
export const transactions = new Map();
export const relayRefusals = [];

// The public record the relay keeps for a registered transaction.
export function publicRecord({ binding, request, state, transactionId }) {
  return {
    callbackUri: binding.callbackUri, clientDisplayName: binding.clientDisplayName, clientId: binding.clientId,
    expiresAt: new Date(Date.now() + 300_000).toISOString(), operation: binding.operation,
    registryVersion: binding.registryReleaseSha256, request,
    requestOrigin: binding.requestOrigin, requestSha256: sha256Hex(jcs(request)),
    resultToken: randomBytes(32).toString('base64url'), schemaVersion: 1, state, transactionId,
  };
}

function relayResponse(status, body, origin) {
  return {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store',
      ...(origin ? { 'access-control-allow-origin': origin, vary: 'Origin' } : {}) },
    body: body === null ? '' : JSON.stringify(body),
  };
}
function relay(method, path, origin, text) {
  const tooLarge = (limit) => Buffer.byteLength(text ?? '') > limit;
  if (method === 'OPTIONS') {
    return { status: 204, headers: { 'access-control-allow-origin': origin, 'access-control-allow-methods': 'POST', 'access-control-allow-headers': 'content-type' }, body: '' };
  }
  if (method === 'POST' && path === '/relay/v1/transactions') {
    if (tooLarge(32 * 1024)) return relayResponse(413, { error: 'too large' }, origin);
    const body = JSON.parse(text);
    let binding;
    let request;
    try {
      binding = registry.resolve(body.clientId, origin, body.operation);
      request = relayRequestParsers[binding.operation](body.request);
    } catch {
      relayRefusals.push({ clientId: body.clientId, operation: body.operation, origin });
      return relayResponse(400, { error: 'unregistered' }, origin);
    }
    const record = publicRecord({ binding, request, state: body.state, transactionId: body.transactionId });
    transactions.set(body.transactionId, { codeChallenge: body.codeChallenge, public: record, result: null, resultText: null, code: null });
    return relayResponse(201, { expiresAt: record.expiresAt, schemaVersion: 1, transactionId: body.transactionId }, origin);
  }
  let match = /^\/relay\/v1\/transactions\/([0-9a-f]{64})$/u.exec(path);
  if (method === 'GET' && match) {
    const record = transactions.get(match[1]);
    return record ? relayResponse(200, record.public) : relayResponse(404, { error: 'not found' });
  }
  match = /^\/relay\/v1\/transactions\/([0-9a-f]{64})\/result$/u.exec(path);
  if (method === 'POST' && match) {
    if (tooLarge(64 * 1024)) return relayResponse(413, { error: 'too large' });
    const record = transactions.get(match[1]);
    const body = JSON.parse(text);
    if (!record || record.result || body.resultToken !== record.public.resultToken) return relayResponse(400, { error: 'binding' });
    try {
      record.result = (relayResultParsers[record.public.operation] ?? ((value) => value))(body.result);
    } catch {
      return relayResponse(400, { error: 'invalid result' });
    }
    record.resultText = text;
    record.code = randomBytes(32).toString('hex');
    return relayResponse(201, { redirectUri: `${record.public.callbackUri}#code=${record.code}&state=${record.public.state}`, schemaVersion: 1, transactionId: match[1] });
  }
  if (method === 'POST' && path === '/relay/v1/codes/redeem') {
    const body = JSON.parse(text);
    const record = transactions.get(body.transactionId);
    if (!record?.result || body.code !== record.code || body.state !== record.public.state
        || createHash('sha256').update(body.codeVerifier).digest('base64url') !== record.codeChallenge) {
      return relayResponse(400, { error: 'binding' }, origin);
    }
    return relayResponse(200, { result: record.result, schemaVersion: 1, transactionId: body.transactionId }, origin);
  }
  match = /^\/relay\/v1\/transactions\/([0-9a-f]{64})\/cancel$/u.exec(path);
  if (method === 'POST' && match) return { status: 204, headers: origin ? { 'access-control-allow-origin': origin } : {}, body: '' };
  return relayResponse(404, { error: 'not found' });
}

// What the browser loads.
const walletHost = `${ui}dist/wallet-origin-host/`;
const walletFiles = new Map(Object.keys(JSON.parse(readFileSync(`${walletHost}integrity.json`, 'utf8')).files)
  .map((name) => [`/${name}`, readFileSync(`${walletHost}${name}`)]));
const WALLET_HEADERS = {
  'cross-origin-embedder-policy': 'require-corp', 'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin', 'referrer-policy': 'no-referrer', 'x-frame-options': 'DENY',
};
const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.wasm': 'application/wasm' };
const publicClient = readFileSync(`${ui}dist/browser/sdn-wallet-public-client.js`);
const callbackPage = readFileSync(`${ui}dist/browser/wallet-callback.html`);
const callbackScript = readFileSync(`${ui}dist/browser/sdn-wallet-callback.js`);
const harness = (clientId) => `<!doctype html><meta charset="utf-8"><title>${clientId}</title>
<script src="./sdn-wallet-public-client.js"></script>
<button id="run" type="button">Run</button>
<script>
  window.__client = SDNWalletPublicClient.create({ clientId: ${JSON.stringify(clientId)} });
  window.__outcomes = [];
  document.getElementById('run').addEventListener('click', () => {
    const job = window.__job; window.__job = null;
    const index = window.__outcomes.push({ state: 'pending' }) - 1;
    Promise.resolve().then(job).then(
      (value) => { window.__outcomes[index] = { state: 'resolved', value }; },
      (error) => { window.__outcomes[index] = { state: 'rejected', code: error?.code ?? String(error) }; });
  });
</script>`;

// `sites` lists every page origin the harness serves.
export async function launchWallet({ sites }) {
  const siteOrigins = new Set(sites);
  async function serve(route) {
    const request = route.request();
    const url = new URL(request.url());
    const origin = request.headers().origin ?? null;
    if (url.origin === WALLET && url.pathname.startsWith('/relay/v1/')) {
      const answer = relay(request.method(), url.pathname, origin, request.postData());
      return route.fulfill({ ...answer, headers: { ...WALLET_HEADERS, ...answer.headers, 'cross-origin-resource-policy': 'cross-origin' } });
    }
    if (url.origin === WALLET) {
      const file = /^\/transaction\/[0-9a-f]{64}$/u.test(url.pathname) ? '/index.html' : url.pathname;
      const body = walletFiles.get(file);
      if (!body) return route.fulfill({ status: 404, body: '' });
      return route.fulfill({ status: 200, body, headers: { ...WALLET_HEADERS, 'content-type': TYPES[file.slice(file.lastIndexOf('.'))] } });
    }
    if (siteOrigins.has(url.origin)) {
      const name = url.pathname.slice(url.pathname.lastIndexOf('/') + 1);
      const clientId = url.searchParams.get('client');
      const pages = {
        'e2e.html': clientId && [harness(clientId), TYPES['.html']],
        'sdn-wallet-public-client.js': [publicClient, TYPES['.js']],
        'wallet-callback.html': [callbackPage, TYPES['.html']],
        'sdn-wallet-callback.js': [callbackScript, TYPES['.js']],
      };
      if (pages[name]) return route.fulfill({ status: 200, body: pages[name][0], headers: { 'content-type': pages[name][1] } });
    }
    return route.fulfill({ status: 404, body: '' });
  }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  await context.route('**/*', serve);
  const pageErrors = [];
  context.on('page', (page) => page.on('pageerror', (error) => pageErrors.push(error.message)));

  return {
    browser,
    context,
    pageErrors,
    // Opens the harness page at `pageUrl` (…/e2e.html) for `clientId`.
    async openSite(pageUrl, clientId) {
      const page = await context.newPage();
      await page.goto(`${pageUrl}?client=${encodeURIComponent(clientId)}`);
      return page;
    },
    // Starts `job` (page-side source) from a trusted click and returns the wallet popup.
    async start(page, job, { popup = true } = {}) {
      await page.evaluate(`window.__job = ${job};`);
      const index = await page.evaluate('window.__outcomes.length');
      const opened = popup ? context.waitForEvent('page') : null;
      await page.click('#run');
      return { index, popup: opened ? await opened : null };
    },
    async outcome(page, index, ms = 60_000) {
      await page.waitForFunction((i) => window.__outcomes[i]?.state !== 'pending', index, { timeout: ms });
      return page.evaluate((i) => window.__outcomes[i], index);
    },
    async unlock(popup) {
      await popup.bringToFront();
      await popup.getByLabel('Username', { exact: true }).fill(USERNAME, { timeout: 30_000 });
      await popup.getByLabel('Password', { exact: true }).fill(PASSWORD);
      await popup.getByRole('button', { exact: true, name: 'Login' }).click();
    },
  };
}

export const fieldsJs = (fields) => JSON.stringify(fields.map((field) => ({
  encHex: hex(field.enc), ciphertextHex: hex(field.ciphertext), context: field.context, fieldId: field.fieldId,
})));
export const openFieldsJob = (fields) => `async () => {
  const bytes = (h) => Uint8Array.from(h.match(/../g), (p) => parseInt(p, 16));
  const fields = ${fieldsJs(fields)}.map((f) => ({ enc: bytes(f.encHex), ciphertext: bytes(f.ciphertextHex), context: f.context, fieldId: f.fieldId }));
  const opened = await window.__client.openFields({ fields });
  return opened.map((f) => f.plaintext ? { plaintextHex: Array.from(f.plaintext, (b) => b.toString(16).padStart(2, '0')).join('') } : f);
}`;
export const unwrapKeyJob = ({ enc, kmf, context }) => `async () => {
  const bytes = (h) => Uint8Array.from(h.match(/../g), (p) => parseInt(p, 16));
  const { contentKey } = await window.__client.unwrapKey({ enc: bytes(${JSON.stringify(hex(enc))}), kmf: bytes(${JSON.stringify(hex(kmf))}), context: ${JSON.stringify(context)} });
  return Array.from(contentKey, (b) => b.toString(16).padStart(2, '0')).join('');
}`;

// Sealing as the SDN runtimes seal: Python `cryptography` (field_open_vector.py)
// from the vector seed, wrapped in SDS $ENC / $KMF records.
const SEED = 'c63fbe791b92d91eb828eab4b203cffe7f333e9d200ec2355d77c7796c080f79c9ed753af213bf155512e3c667c3be26a22c1c599cbae52cb44add279559fe5b';
const here = fileURLToPath(new URL('.', import.meta.url));

export function python(request) {
  const run = spawnSync('python3', ['-I', `${here}field_open_vector.py`], { input: JSON.stringify({ seedHex: SEED, ...request }), encoding: 'utf8' });
  if (run.status !== 0) throw new Error(`python: ${run.stderr}`);
  return JSON.parse(run.stdout);
}

function byteVector(builder, bytes) {
  builder.startVector(1, bytes.length, 1);
  for (let index = bytes.length - 1; index >= 0; index -= 1) builder.addInt8(bytes[index]);
  return builder.endVector();
}
function encRecord({ ephemeralPublic, recipientKeyId, context }) {
  const builder = new Builder(256);
  const ephemeral = byteVector(builder, ephemeralPublic);
  const nonce = byteVector(builder, randomBytes(12));
  const keyId = byteVector(builder, recipientKeyId);
  const text = builder.createString(context);
  builder.startObject(11);
  builder.addFieldInt8(0, 1, 0);
  builder.addFieldOffset(4, ephemeral, 0);
  builder.addFieldOffset(5, nonce, 0);
  builder.addFieldOffset(6, keyId, 0);
  builder.addFieldOffset(7, text, 0);
  builder.finish(builder.endObject(), '$ENC');
  return builder.asUint8Array().slice();
}
export function kmfRecord(keyBytes) {
  const builder = new Builder(128);
  const key = byteVector(builder, keyBytes);
  builder.startObject(7);
  builder.addFieldOffset(4, key, 0);
  builder.finish(builder.endObject(), '$KMF');
  return builder.asUint8Array().slice();
}
export function pythonSealed(account, context, fieldId, plaintext) {
  const sealed = python({ op: 'seal', account, context, fieldId, plaintextHex: hex(plaintext) });
  return {
    enc: encRecord({ ephemeralPublic: unhex(sealed.ephemeralPublicHex), recipientKeyId: unhex(sealed.recipientKeyIdHex), context }),
    ciphertext: unhex(sealed.ciphertextHex), context, fieldId,
  };
}
