// E2E: the wallet opens per-field ciphertext sealed to the signed-in user, for
// the one site the field is bound to, only after the user consents.
//
//   node wallet-ui/test/e2e/field-open-e2e.mjs        (after npm run build:release)
//
// Chromium headless shell. The built public client runs on
// https://digitalarsenal.github.io/flatbuffers/ and /flatsql/; the built wallet
// origin (WASM) runs on https://wallet.spacedatanetwork.org; its relay is the
// relay's own registry and wire parsers with an in-memory store. The wallet is
// the throwaway vector account alice_01 (test/fixtures/sdn-wallet-vectors.v1.json).
//
//  1. fields sealed by the flatbuffers demo (fixtures/flatbuffers-demo-fields.json)
//     do not open while the consent prompt is open, nor after Cancel;
//  2. after consent they open; Python `cryptography` (field_open_vector.py)
//     reproduces every plaintext from the seed; a field sealed to another
//     account comes back refused; the relay never holds a plaintext;
//  3. "Don't ask again for this site" opens the next batch without a prompt;
//  4. a field bound to another site is refused by the client and, sent raw,
//     by the wallet before it asks for a password;
//  5. FlatSQL: a content key wrapped to the user ($ENC + $KMF) unwraps after
//     consent and equals the key Python unwraps.
import { spawnSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { Builder } from 'flatbuffers';
import { chromium } from 'playwright';

import * as wire from '../../client/wire.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const ui = fileURLToPath(new URL('../../', import.meta.url));
const { ClientRegistry } = await import(new URL('../../relay/dist/src/registry.js', import.meta.url).href);
const { jcs, sha256Hex } = await import(new URL('../../relay/dist/src/json.js', import.meta.url).href);

const WALLET = 'https://wallet.spacedatanetwork.org';
const PAGES = 'https://digitalarsenal.github.io';
const USERNAME = 'alice_01';
const PASSWORD = 'Correct Horse Battery Staple!';
const SEED = 'c63fbe791b92d91eb828eab4b203cffe7f333e9d200ec2355d77c7796c080f79c9ed753af213bf155512e3c667c3be26a22c1c599cbae52cb44add279559fe5b';
const demo = JSON.parse(readFileSync(`${here}fixtures/flatbuffers-demo-fields.json`, 'utf8'));
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const unhex = (text) => new Uint8Array(Buffer.from(text, 'hex'));
const checks = [];

function fail(message) {
  console.error(`field-open E2E FAIL: ${message}`);
  process.exit(1);
}
function pass(message) {
  checks.push(message);
  console.log(`  ok  ${message}`);
}

function python(request) {
  const run = spawnSync('python3', ['-I', `${here}field_open_vector.py`], { input: JSON.stringify({ seedHex: SEED, ...request }), encoding: 'utf8' });
  if (run.status !== 0) fail(`python: ${run.stderr}`);
  return JSON.parse(run.stdout);
}

// SDS $ENC / $KMF records, built as the SDN runtimes build them.
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
function kmfRecord(keyBytes) {
  const builder = new Builder(128);
  const key = byteVector(builder, keyBytes);
  builder.startObject(7);
  builder.addFieldOffset(4, key, 0);
  builder.finish(builder.endObject(), '$KMF');
  return builder.asUint8Array().slice();
}
function pythonSealed(account, context, fieldId, plaintext) {
  const sealed = python({ op: 'seal', account, context, fieldId, plaintextHex: hex(plaintext) });
  return {
    enc: encRecord({ ephemeralPublic: unhex(sealed.ephemeralPublicHex), recipientKeyId: unhex(sealed.recipientKeyIdHex), context }),
    ciphertext: unhex(sealed.ciphertextHex), context, fieldId,
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
const transactions = new Map();
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
      return relayResponse(400, { error: 'unregistered' }, origin);
    }
    const expiresAt = new Date(Date.now() + 300_000).toISOString();
    transactions.set(body.transactionId, {
      codeChallenge: body.codeChallenge,
      public: {
        callbackUri: binding.callbackUri, clientDisplayName: binding.clientDisplayName, clientId: binding.clientId,
        expiresAt, operation: binding.operation, registryVersion: binding.registryReleaseSha256, request,
        requestOrigin: binding.requestOrigin, requestSha256: sha256Hex(jcs(request)),
        resultToken: randomBytes(32).toString('base64url'), schemaVersion: 1, state: body.state, transactionId: body.transactionId,
      },
      result: null, resultText: null, code: null,
    });
    return relayResponse(201, { expiresAt, schemaVersion: 1, transactionId: body.transactionId }, origin);
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
  if (url.origin === PAGES) {
    const [, site, name] = /^\/(flatbuffers|flatsql)\/(.*)$/u.exec(url.pathname) ?? [];
    const pages = {
      'e2e.html': [harness(`sdn-${site}-pages-v1`), TYPES['.html']],
      'sdn-wallet-public-client.js': [publicClient, TYPES['.js']],
      'wallet-callback.html': [callbackPage, TYPES['.html']],
      'sdn-wallet-callback.js': [callbackScript, TYPES['.js']],
    };
    if (site && pages[name]) return route.fulfill({ status: 200, body: pages[name][0], headers: { 'content-type': pages[name][1] } });
  }
  return route.fulfill({ status: 404, body: '' });
}

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext();
await context.route('**/*', serve);
const consoleErrors = [];
context.on('page', (page) => page.on('pageerror', (error) => consoleErrors.push(error.message)));

async function openSite(site) {
  const page = await context.newPage();
  await page.goto(`${PAGES}/${site}/e2e.html`);
  return page;
}

// Starts `job` (page-side source) from a trusted click and returns the wallet popup.
async function start(page, job, { popup = true } = {}) {
  await page.evaluate(`window.__job = ${job};`);
  const index = await page.evaluate('window.__outcomes.length');
  const opened = popup ? context.waitForEvent('page') : null;
  await page.click('#run');
  return { index, popup: opened ? await opened : null };
}

async function outcome(page, index, ms = 60_000) {
  await page.waitForFunction((i) => window.__outcomes[i]?.state !== 'pending', index, { timeout: ms });
  return page.evaluate((i) => window.__outcomes[i], index);
}

async function unlock(popup) {
  await popup.bringToFront();
  await popup.getByLabel('Username', { exact: true }).fill(USERNAME, { timeout: 30_000 });
  await popup.getByLabel('Password', { exact: true }).fill(PASSWORD);
  await popup.getByRole('button', { exact: true, name: 'Login' }).click();
}

const fieldsJs = (fields) => JSON.stringify(fields.map((field) => ({
  encHex: hex(field.enc), ciphertextHex: hex(field.ciphertext), context: field.context, fieldId: field.fieldId,
})));
const openFieldsJob = (fields) => `async () => {
  const bytes = (h) => Uint8Array.from(h.match(/../g), (p) => parseInt(p, 16));
  const fields = ${fieldsJs(fields)}.map((f) => ({ enc: bytes(f.encHex), ciphertext: bytes(f.ciphertextHex), context: f.context, fieldId: f.fieldId }));
  const opened = await window.__client.openFields({ fields });
  return opened.map((f) => f.plaintext ? { plaintextHex: Array.from(f.plaintext, (b) => b.toString(16).padStart(2, '0')).join('') } : f);
}`;

try {
  const demoFields = demo.fields.map((field) => ({ enc: unhex(field.encHex), ciphertext: unhex(field.ciphertextHex), context: field.context, fieldId: field.fieldId }));
  const reproduced = python({ op: 'open', account: 0, fields: demo.fields });
  if (reproduced.publicKeyHex !== '1349c6136a8765e4b2a8795037cc6233e22d31a08c76e328ad247daf836c6c0c') fail('Python derives another contact key');
  reproduced.fields.forEach((field, index) => {
    if (field.plaintextHex !== demo.fields[index].plaintextHex || field.context !== demo.fields[index].context) fail(`Python does not reproduce demo field ${index}`);
  });
  pass(`Python reproduces all ${demo.fields.length} flatbuffers-demo plaintexts from the seed`);
  const otherAccount = pythonSealed(1, 'sdn-field-encryption/v1|flatbuffers|monster|name|k1', 3, new TextEncoder().encode('account one'));
  const crossSite = pythonSealed(0, 'sdn-field-encryption/v1|flatsql|monster|name|k1', 3, new TextEncoder().encode('flatsql field'));

  const flatbuffers = await openSite('flatbuffers');

  // 1. Consent first: nothing opens while the prompt is open, nor after Cancel.
  let run = await start(flatbuffers, openFieldsJob(demoFields));
  await unlock(run.popup);
  const prompt = run.popup.getByRole('dialog');
  await prompt.waitFor({ timeout: 60_000 });
  const heading = await prompt.getByRole('heading').textContent();
  if (heading !== `Open ${demoFields.length} encrypted fields for FlatBuffers Documentation`) fail(`prompt heading: ${heading}`);
  if (!(await prompt.textContent()).includes('digitalarsenal.github.io')) fail('prompt does not name the site');
  if ([...transactions.values()].some((record) => record.result)) fail('a result exists before consent');
  if ((await flatbuffers.evaluate((i) => window.__outcomes[i].state, run.index)) !== 'pending') fail('page settled before consent');
  await prompt.getByRole('button', { name: 'Cancel' }).click();
  await run.popup.waitForTimeout(2000);
  if ([...transactions.values()].some((record) => record.result)) fail('a result exists after Cancel');
  if ((await flatbuffers.evaluate((i) => window.__outcomes[i].state, run.index)) === 'resolved') fail('page got fields after Cancel');
  pass('the prompt names the site and the field count; before consent and after Cancel nothing opens');

  // 2. Consent: the demo fields open; another account's field is refused.
  run = await start(flatbuffers, openFieldsJob([...demoFields, otherAccount]));
  await unlock(run.popup);
  await run.popup.getByRole('dialog').waitFor({ timeout: 60_000 });
  await run.popup.getByLabel(/Don't ask again for this site/u).check();
  await run.popup.getByRole('button', { exact: true, name: 'Open' }).click();
  let result = await outcome(flatbuffers, run.index);
  if (result.state !== 'resolved') fail(`openFields: ${JSON.stringify(result)}`);
  result.value.slice(0, demoFields.length).forEach((field, index) => {
    if (field.plaintextHex !== reproduced.fields[index].plaintextHex) fail(`demo field ${index} opened to ${JSON.stringify(field)}`);
  });
  if (result.value[demoFields.length]?.refused !== 'NOT_ADDRESSED_TO_ACCOUNT') fail(`another account's field: ${JSON.stringify(result.value[demoFields.length])}`);
  pass(`after consent the wallet opens all ${demoFields.length} demo fields to the plaintexts Python reproduces`);
  pass('a field sealed to another account (alice_01 account 1) is refused: NOT_ADDRESSED_TO_ACCOUNT');
  const stored = [...transactions.values()].filter((record) => record.resultText).map((record) => record.resultText).join('\n');
  for (const field of demo.fields) {
    const plain = Buffer.from(field.plaintextHex, 'hex');
    if (plain.length >= 4 && (stored.includes(field.plaintextHex) || stored.includes(plain.toString('base64url')))) fail('the relay holds a plaintext');
  }
  if (!stored.includes('replyEphemeralPublicKeyHex')) fail('no sealed reply reached the relay');
  pass('the relay holds only reply ciphertext, never a plaintext');

  // 3. Remembered for this site: the next batch opens without a prompt.
  run = await start(flatbuffers, openFieldsJob([demoFields[3]]));
  await unlock(run.popup);
  result = await outcome(flatbuffers, run.index);
  if (result.state !== 'resolved' || result.value[0].plaintextHex !== demo.fields[3].plaintextHex) fail(`remembered open: ${JSON.stringify(result)}`);
  pass('"Don\'t ask again for this site" opens the next batch for this site without a prompt');

  // 4. A field bound to another site: the client refuses it, and so does the wallet.
  run = await start(flatbuffers, openFieldsJob([crossSite]), { popup: false });
  result = await outcome(flatbuffers, run.index);
  if (result.state !== 'rejected' || result.code !== 'INVALID_REQUEST') fail(`client cross-site: ${JSON.stringify(result)}`);
  const transactionId = randomBytes(32).toString('hex');
  const verifier = randomBytes(32).toString('base64url');
  const rawRequest = wire.buildFieldOpenRequest({ fields: [crossSite] }, hex(randomBytes(32)));
  // The page's request goes to the routed relay above, never the network.
  const registered = await flatbuffers.evaluate(async ({ id, url, body }) => (await fetch(url, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ...body, transactionId: id }),
  })).status, { id: transactionId, url: `${WALLET}/relay/v1/transactions`, body: {
    clientId: 'sdn-flatbuffers-pages-v1', codeChallenge: createHash('sha256').update(verifier).digest('base64url'), codeChallengeMethod: 'S256',
    operation: 'sdn.wallet.field-open.v1', request: rawRequest, schemaVersion: 1, state: randomBytes(32).toString('hex'),
  } });
  if (registered !== 201) fail(`raw registration: ${registered}`);
  const hostile = await context.newPage();
  await hostile.goto(`${WALLET}/transaction/${transactionId}`);
  await hostile.locator('.wallet-terminal-error').waitFor({ timeout: 30_000 });
  if (await hostile.getByLabel('Password', { exact: true }).count()) fail('the wallet asked for a password for a cross-site field');
  if (transactions.get(transactionId).result) fail('the wallet answered a cross-site field');
  await hostile.close();
  pass('a field bound to flatsql is refused on flatbuffers: by the client, and sent raw by the wallet before any password');

  // 5. FlatSQL reopens a database: the wallet unwraps its content key.
  const contentKey = randomBytes(32);
  const dbContext = 'sdn-field-encryption/v1|flatsql|records|db|k1';
  const wrapped = pythonSealed(0, dbContext, 4, contentKey);
  const kmf = kmfRecord(wrapped.ciphertext);
  const pythonKey = python({ op: 'open', account: 0, fields: [{ encHex: hex(wrapped.enc), ciphertextHex: hex(wrapped.ciphertext), fieldId: 4 }] });
  if (pythonKey.fields[0].plaintextHex !== contentKey.toString('hex')) fail('Python does not unwrap the content key');
  const flatsql = await openSite('flatsql');
  run = await start(flatsql, `async () => {
    const bytes = (h) => Uint8Array.from(h.match(/../g), (p) => parseInt(p, 16));
    const { contentKey } = await window.__client.unwrapKey({ enc: bytes(${JSON.stringify(hex(wrapped.enc))}), kmf: bytes(${JSON.stringify(hex(kmf))}), context: ${JSON.stringify(dbContext)} });
    return Array.from(contentKey, (b) => b.toString(16).padStart(2, '0')).join('');
  }`);
  await unlock(run.popup);
  const unwrapPrompt = run.popup.getByRole('dialog');
  await unwrapPrompt.waitFor({ timeout: 60_000 });
  if ((await unwrapPrompt.getByRole('heading').textContent()) !== 'Reopen a database for FlatSQL Documentation') fail('unwrap prompt heading');
  await run.popup.getByRole('button', { exact: true, name: 'Reopen' }).click();
  result = await outcome(flatsql, run.index);
  if (result.state !== 'resolved' || result.value !== contentKey.toString('hex')) fail(`unwrapKey: ${JSON.stringify(result)}`);
  pass('FlatSQL: after consent the wallet unwraps the database content key; Python unwraps the same key');

  if (consoleErrors.length) fail(`page errors: ${consoleErrors.join(' | ')}`);
  console.log(`field-open E2E PASS (${checks.length} checks, ${browser.version()} headless shell)`);
} finally {
  await browser.close();
}
