// E2E: the wallet opens per-field ciphertext sealed to the signed-in user, for
// the one site the field is bound to, only after the user consents.
//
//   node wallet-ui/test/e2e/field-open-e2e.mjs        (after npm run build:release)
//
// Chromium headless shell (wallet-harness.mjs). The built public client runs on
// https://flatbuffers.spacedatanetwork.org and https://flatsql.spacedatanetwork.org,
// the wallet origin on https://wallet.spacedatanetwork.org.
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
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import * as wire from '../../client/wire.mjs';
import {
  WALLET, hex, kmfRecord, launchWallet, openFieldsJob, python, pythonSealed, reporter, transactions, unhex, unwrapKeyJob,
} from './wallet-harness.mjs';

const here = fileURLToPath(new URL('.', import.meta.url));
const FLATBUFFERS = 'https://flatbuffers.spacedatanetwork.org';
const FLATSQL = 'https://flatsql.spacedatanetwork.org';
const demo = JSON.parse(readFileSync(`${here}fixtures/flatbuffers-demo-fields.json`, 'utf8'));
const { checks, fail, pass } = reporter('field-open');
const wallet = await launchWallet({ sites: [FLATBUFFERS, FLATSQL] });
const { browser, context, outcome, start, unlock } = wallet;

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

  const flatbuffers = await wallet.openSite(`${FLATBUFFERS}/e2e.html`, 'sdn-flatbuffers-pages-v1');

  // 1. Consent first: nothing opens while the prompt is open, nor after Cancel.
  let run = await start(flatbuffers, openFieldsJob(demoFields));
  await unlock(run.popup);
  const prompt = run.popup.getByRole('dialog');
  await prompt.waitFor({ timeout: 60_000 });
  const heading = await prompt.getByRole('heading').textContent();
  if (heading !== `Open ${demoFields.length} encrypted fields for FlatBuffers Documentation`) fail(`prompt heading: ${heading}`);
  if (!(await prompt.textContent()).includes('flatbuffers.spacedatanetwork.org')) fail('prompt does not name the site');
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
  const flatsql = await wallet.openSite(`${FLATSQL}/e2e.html`, 'sdn-flatsql-pages-v1');
  run = await start(flatsql, unwrapKeyJob({ enc: wrapped.enc, kmf, context: dbContext }));
  await unlock(run.popup);
  const unwrapPrompt = run.popup.getByRole('dialog');
  await unwrapPrompt.waitFor({ timeout: 60_000 });
  if ((await unwrapPrompt.getByRole('heading').textContent()) !== 'Reopen a database for FlatSQL Documentation') fail('unwrap prompt heading');
  await run.popup.getByRole('button', { exact: true, name: 'Reopen' }).click();
  result = await outcome(flatsql, run.index);
  if (result.state !== 'resolved' || result.value !== contentKey.toString('hex')) fail(`unwrapKey: ${JSON.stringify(result)}`);
  pass('FlatSQL: after consent the wallet unwraps the database content key; Python unwraps the same key');

  if (wallet.pageErrors.length) fail(`page errors: ${wallet.pageErrors.join(' | ')}`);
  console.log(`field-open E2E PASS (${checks.length} checks, ${browser.version()} headless shell)`);
} finally {
  await browser.close();
}
