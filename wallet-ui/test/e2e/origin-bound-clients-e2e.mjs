// E2E: a page on one origin cannot use another origin's client ID for a key
// operation (openFields, unwrapKey), and the shared digitalarsenal.github.io
// origin signs in only.
//
//   node wallet-ui/test/e2e/origin-bound-clients-e2e.mjs   (after npm run build:release)
//
// Chromium headless shell (wallet-harness.mjs). Sites:
//   https://flatbuffers.spacedatanetwork.org  sdn-flatbuffers-pages-v1 (openFields)
//   https://flatsql.spacedatanetwork.org      sdn-flatsql-pages-v1 (unwrapKey)
//   https://digitalarsenal.github.io          digitalarsenal-pages-v1 (connect only)
//
//  1. Each site's own client ID works on its own origin (openFields, unwrapKey).
//  2. The same calls from another origin under that client ID are refused by
//     the relay, which binds the client ID to the request's Origin; no wallet
//     transaction exists and no password is asked.
//  3. A relay that lies (a record that binds a client ID to another origin) is
//     refused by the wallet before it asks for a password; the true binding
//     reaches the password prompt.
//  4. digitalarsenal-pages-v1 connects, and has no openFields or unwrapKey.
import { randomBytes } from 'node:crypto';

import registrySource from '../../relay/config/client-registry.v1.json' with { type: 'json' };
import * as wire from '../../client/wire.mjs';
import {
  WALLET, kmfRecord, launchWallet, openFieldsJob, publicRecord, pythonSealed, relayRefusals, reporter, transactions, unwrapKeyJob,
} from './wallet-harness.mjs';

const FLATBUFFERS = 'https://flatbuffers.spacedatanetwork.org';
const FLATSQL = 'https://flatsql.spacedatanetwork.org';
const PAGES = 'https://digitalarsenal.github.io';
const { checks, fail, pass } = reporter('origin-bound-clients');
const wallet = await launchWallet({ sites: [FLATBUFFERS, FLATSQL, PAGES] });
const { browser, context, outcome, start, unlock } = wallet;

const field = pythonSealed(0, 'sdn-field-encryption/v1|flatbuffers|monster|name|k1', 3, new TextEncoder().encode('flatbuffers field'));
const contentKey = randomBytes(32);
const dbContext = 'sdn-field-encryption/v1|flatsql|records|db|k1';
const wrapped = pythonSealed(0, dbContext, 4, contentKey);
const unwrap = { enc: wrapped.enc, kmf: kmfRecord(wrapped.ciphertext), context: dbContext };

async function approve(run, button) {
  await unlock(run.popup);
  await run.popup.getByRole('dialog').waitFor({ timeout: 60_000 });
  await run.popup.getByRole('button', { exact: true, name: button }).click();
}

// A call under `clientId` from `origin`: the relay refuses it, nothing reaches the wallet.
async function refusedFrom(origin, clientId, job, operation) {
  const page = await wallet.openSite(`${origin}/e2e.html`, clientId);
  const before = transactions.size;
  const refusals = relayRefusals.length;
  const opened = [];
  const onPage = (popup) => opened.push(popup);
  context.on('page', onPage);
  const run = await start(page, job, { popup: false });
  const result = await outcome(page, run.index);
  context.off('page', onPage);
  if (result.state !== 'rejected') fail(`${clientId} from ${origin}: ${JSON.stringify(result)}`);
  if (transactions.size !== before) fail(`${clientId} from ${origin}: the relay registered a transaction`);
  const refusal = relayRefusals.slice(refusals).find((entry) => entry.clientId === clientId && entry.origin === origin);
  if (!refusal || refusal.operation !== operation) fail(`${clientId} from ${origin}: the relay did not refuse ${operation}`);
  for (const popup of opened) {
    if (!popup.isClosed() && await popup.getByLabel('Password', { exact: true }).count()) fail(`${clientId} from ${origin}: the wallet asked for a password`);
  }
  await page.close();
  return result.code;
}

// A relay record binding `clientId` to `requestOrigin`. A lie is refused before any
// password; the true binding (the control) reaches the password prompt.
async function walletOnRecord(clientId, requestOrigin, operation, request, { truthful = false } = {}) {
  const transactionId = randomBytes(32).toString('hex');
  // The registry's own row for the client; only the request origin differs in a lie.
  const row = registrySource.clients.find((client) => client.clientId === clientId);
  const binding = {
    callbackUri: row.callbackUri, clientDisplayName: row.clientDisplayName, clientId, operation,
    registryReleaseSha256: registrySource.registryReleaseSha256, requestOrigin,
  };
  transactions.set(transactionId, {
    codeChallenge: randomBytes(32).toString('base64url'),
    public: publicRecord({ binding, request, state: randomBytes(32).toString('hex'), transactionId }),
    result: null, resultText: null, code: null,
  });
  const popup = await context.newPage();
  await popup.goto(`${WALLET}/transaction/${transactionId}`);
  if (truthful) {
    await popup.getByLabel('Password', { exact: true }).waitFor({ timeout: 30_000 });
    await popup.close();
    return;
  }
  await popup.locator('.wallet-terminal-error').waitFor({ timeout: 30_000 });
  if (await popup.getByLabel('Password', { exact: true }).count()) fail(`${clientId} at ${requestOrigin}: the wallet asked for a password`);
  if (transactions.get(transactionId).result) fail(`${clientId} at ${requestOrigin}: the wallet answered`);
  await popup.close();
}

try {
  // 1. Positive controls: each client ID on its own origin.
  const flatbuffers = await wallet.openSite(`${FLATBUFFERS}/e2e.html`, 'sdn-flatbuffers-pages-v1');
  let run = await start(flatbuffers, openFieldsJob([field]));
  await approve(run, 'Open');
  let result = await outcome(flatbuffers, run.index);
  if (result.state !== 'resolved' || result.value[0].plaintextHex !== Buffer.from('flatbuffers field').toString('hex')) fail(`flatbuffers openFields: ${JSON.stringify(result)}`);
  pass('flatbuffers.spacedatanetwork.org opens its field under sdn-flatbuffers-pages-v1');
  const flatsql = await wallet.openSite(`${FLATSQL}/e2e.html`, 'sdn-flatsql-pages-v1');
  run = await start(flatsql, unwrapKeyJob(unwrap));
  await approve(run, 'Reopen');
  result = await outcome(flatsql, run.index);
  if (result.state !== 'resolved' || result.value !== contentKey.toString('hex')) fail(`flatsql unwrapKey: ${JSON.stringify(result)}`);
  pass('flatsql.spacedatanetwork.org unwraps its content key under sdn-flatsql-pages-v1');

  // 2. Another origin's client ID: the relay refuses, the wallet never sees it.
  for (const [origin, clientId, job, operation] of [
    [FLATBUFFERS, 'sdn-flatsql-pages-v1', unwrapKeyJob(unwrap), 'sdn.wallet.key-unwrap.v1'],
    [PAGES, 'sdn-flatsql-pages-v1', unwrapKeyJob(unwrap), 'sdn.wallet.key-unwrap.v1'],
    [FLATSQL, 'sdn-flatbuffers-pages-v1', openFieldsJob([field]), 'sdn.wallet.field-open.v1'],
    [PAGES, 'sdn-flatbuffers-pages-v1', openFieldsJob([field]), 'sdn.wallet.field-open.v1'],
  ]) {
    const code = await refusedFrom(origin, clientId, job, operation);
    pass(`${new URL(origin).host} under ${clientId}: ${operation} refused by the relay (${code}), no transaction, no password`);
  }

  // 3. A lying relay: the wallet holds its own registry and refuses the binding.
  const unwrapRequest = () => wire.buildKeyUnwrapRequest(unwrap, randomBytes(32).toString('hex'));
  await walletOnRecord('sdn-flatsql-pages-v1', FLATSQL, 'sdn.wallet.key-unwrap.v1', unwrapRequest(), { truthful: true });
  await walletOnRecord('sdn-flatsql-pages-v1', PAGES, 'sdn.wallet.key-unwrap.v1', unwrapRequest());
  await walletOnRecord('sdn-flatbuffers-pages-v1', FLATSQL, 'sdn.wallet.field-open.v1',
    wire.buildFieldOpenRequest({ fields: [field] }, randomBytes(32).toString('hex')));
  pass('a relay record binding sdn-flatsql-pages-v1 to digitalarsenal.github.io, or sdn-flatbuffers-pages-v1 to flatsql, is refused by the wallet before any password (the true flatsql binding reaches the password prompt)');

  // 4. The shared github.io origin signs in only.
  const pages = await wallet.openSite(`${PAGES}/hd-wallet-wasm/e2e.html`, 'digitalarsenal-pages-v1');
  const methods = await pages.evaluate(() => ({ openFields: typeof window.__client.openFields, unwrapKey: typeof window.__client.unwrapKey }));
  if (methods.openFields !== 'undefined' || methods.unwrapKey !== 'undefined') fail(`digitalarsenal-pages-v1 methods: ${JSON.stringify(methods)}`);
  run = await start(pages, 'async () => { await window.__client.connect(); return window.__client.getSnapshot().status; }');
  await unlock(run.popup);
  await run.popup.getByRole('heading', { name: 'Connect your wallet to DigitalArsenal GitHub Pages' }).waitFor({ timeout: 60_000 });
  await run.popup.getByRole('button', { exact: true, name: 'Connect' }).click();
  result = await outcome(pages, run.index);
  if (result.state !== 'resolved' || result.value !== 'connected') fail(`digitalarsenal-pages-v1 connect: ${JSON.stringify(result)}`);
  const callback = [...transactions.values()].find((record) => record.public.clientId === 'digitalarsenal-pages-v1')?.public.callbackUri;
  if (callback !== `${PAGES}/hd-wallet-wasm/wallet-callback.html`) fail(`digitalarsenal-pages-v1 callback: ${callback}`);
  for (const operation of ['sdn.wallet.key-unwrap.v1', 'sdn.wallet.field-open.v1']) {
    // The client has no such method; sent raw, the relay has no such binding.
    const status = await pages.evaluate(async ({ url, body }) => (await fetch(url, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
    })).status, { url: `${WALLET}/relay/v1/transactions`, body: {
      clientId: 'digitalarsenal-pages-v1', codeChallenge: randomBytes(32).toString('base64url'), codeChallengeMethod: 'S256',
      operation, request: operation === 'sdn.wallet.key-unwrap.v1'
        ? wire.buildKeyUnwrapRequest(unwrap, randomBytes(32).toString('hex'))
        : wire.buildFieldOpenRequest({ fields: [field] }, randomBytes(32).toString('hex')),
      schemaVersion: 1, state: randomBytes(32).toString('hex'), transactionId: randomBytes(32).toString('hex'),
    } });
    if (status !== 400) fail(`digitalarsenal-pages-v1 raw ${operation}: ${status}`);
  }
  pass('digitalarsenal-pages-v1 connects (callback /hd-wallet-wasm/wallet-callback.html); it has no openFields or unwrapKey, and the relay refuses both raw');

  if (wallet.pageErrors.length) fail(`page errors: ${wallet.pageErrors.join(' | ')}`);
  console.log(`origin-bound-clients E2E PASS (${checks.length} checks, ${browser.version()} headless shell)`);
} finally {
  await browser.close();
}
