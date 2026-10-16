#!/usr/bin/env node
/**
 * Writes the SDS envelope interop fixtures into test/fixtures/envelopes/,
 * made by the wallet's own code (src/envelopes.js, src/contact-card.js,
 * src/identity-keys.js) with the one hd-wallet-wasm instance:
 *
 *   message.txt          the signed and encrypted text
 *   message.txt.rec      the text, $REC{$PNM} and the trailer
 *   message.txt.pnm      the detached signature (size-prefixed $PNM)
 *   message.txt.enc      the text as a $FIL, signed inside, encrypted to account 0
 *   plain.bin            3000 fixed bytes
 *   plain.bin.enc        plain.bin as a $FIL, unsigned, encrypted to account 0
 *   contact.epm          the account-0 contact card (size-prefixed $EPM)
 *   keys.json            the public keys and peer ID of account 0 and the
 *                        account-0 X25519 private key, so other runtimes (the Go
 *                        node, module-sdk) can decrypt message.txt.enc
 *
 * The seed is the public BIP-39 test vector "abandon ×11 about"; every key
 * here is a test-vector key and controls nothing. Signatures and ciphertexts
 * use fresh randomness and the current time where the formats need them, so a
 * rerun writes different bytes that check the same way
 * (test/envelope-fixtures.test.mjs).
 *
 *   node scripts/make-envelope-fixtures.mjs [outDir]
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { register } from 'node:module';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const OUT = path.resolve(process.argv[2] ?? path.join(ROOT, 'test/fixtures/envelopes'));

// src/envelopes.js imports the SDS bindings through the `@sds` alias that
// vite.config.js defines; map it the same way for plain Node.
const sdsRoot = pathToFileURL(path.join(ROOT, 'node_modules/spacedatastandards.org/')).href;
const hooks = `export async function resolve(specifier, context, next) {
  if (specifier.startsWith('@sds/')) return next(${JSON.stringify(sdsRoot)} + specifier.slice(5), context);
  return next(specifier, context);
}`;
register(`data:text/javascript,${encodeURIComponent(hooks)}`, import.meta.url);

const { default: initHDWallet } = await import('hd-wallet-wasm');
const envelopes = await import('../src/envelopes.js');
const contactCard = await import('../src/contact-card.js');
const identityKeys = await import('../src/identity-keys.js');

export const TEST_PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
export const FIXTURE_TEXT = 'hello SDN — ünïcödé ✓\n';
export const FIXTURE_TIMESTAMP = '2026-10-15T00:00:00.000Z';

const wasm = await initHDWallet();
const hex = (bytes) => Buffer.from(bytes).toString('hex');

const seed = new Uint8Array(wasm.mnemonic.toSeed(TEST_PHRASE));
const root = wasm.hdkey.fromSeed(seed);
const account = 0;
const identity = identityKeys.deriveIdentity(wasm, seed, account);
const withEdKey = (fn) => identityKeys.withEdKey(wasm, seed, account, fn);

mkdirSync(OUT, { recursive: true });
const written = [];
function put(name, bytes) {
  writeFileSync(path.join(OUT, name), bytes);
  written.push(`${name} ${bytes.length} B`);
}

try {
  const text = new TextEncoder().encode(FIXTURE_TEXT);
  put('message.txt', text);
  const notice = withEdKey((signingKey) => envelopes.signContent(wasm, {
    content: text,
    name: 'message.txt',
    signingKey,
    timestamp: FIXTURE_TIMESTAMP,
  }));
  put('message.txt.rec', envelopes.buildRecFile(wasm, text, notice));
  put('message.txt.pnm', envelopes.buildPnmFile(wasm, notice));
  put('message.txt.enc', withEdKey((signingKey) => envelopes.encryptContent(wasm, {
    content: FIXTURE_TEXT,
    name: 'message.txt',
    recipientPublicKey: identity.xPub,
    signingKey,
    timestamp: FIXTURE_TIMESTAMP,
  })).bytes);

  const bin = Uint8Array.from({ length: 3000 }, (_, index) => (index * 31 + 7) & 0xff);
  put('plain.bin', bin);
  put('plain.bin.enc', envelopes.encryptContent(wasm, {
    content: bin,
    name: 'plain.bin',
    mediaType: 'application/octet-stream',
    modifiedAtMs: 1_700_000_000_000,
    recipientPublicKey: identity.xPub,
  }).bytes);

  put('contact.epm', contactCard.contactCardBytes(wasm, envelopes, {
    profile: {
      name: 'Ada Lovelace',
      jobTitle: 'Analyst',
      organization: 'Analytical Engines, Ltd',
      email: 'ada@example.org',
      city: 'London',
      country: 'GB',
    },
    identity,
    addresses: identityKeys.deriveAccountAddresses(wasm, root, account),
    withChainKey: (keyPath, fn) => identityKeys.withChainKey(root, keyPath, fn),
    withEdKey,
  }));

  const keys = {
    note: 'Public BIP-39 test vector "abandon x11 about". Test keys only; they control nothing.',
    account,
    signingKeyPath: identityKeys.signingKeyPath(account),
    encryptionKeyPath: identityKeys.encryptionKeyPath(account),
    edPub: hex(identity.edPub),
    xPub: hex(identity.xPub),
    peerId: identity.peerId,
    testOnlyX25519PrivateKey: identityKeys.withXKey(wasm, seed, account, (key) => hex(key)),
    messageSha256: hex(wasm.utils.sha256(text)),
    plainBinSha256: hex(wasm.utils.sha256(bin)),
    cid: notice.CID,
    publishTimestamp: FIXTURE_TIMESTAMP,
    context: envelopes.MESSAGE_CONTEXT,
  };
  writeFileSync(path.join(OUT, 'keys.json'), `${JSON.stringify(keys, null, 2)}\n`);
  written.push('keys.json');
} finally {
  seed.fill(0);
}

console.log(`envelope fixtures in ${path.relative(process.cwd(), OUT) || '.'}:\n  ${written.join('\n  ')}`);
