// The committed interop fixtures (test/fixtures/envelopes/, written by
// scripts/make-envelope-fixtures.mjs) still read the same way with the
// current code: the keys are the test seed's, the signatures verify, both
// .enc files decrypt to their originals and the contact card imports.
// The Go node and module-sdk read these same files (spec §7.21, §8.3).

import { readFileSync } from 'node:fs';
import initHDWallet from 'hd-wallet-wasm';
import { describe, expect, it } from 'vitest';

import * as envelopes from '../src/envelopes.js';
import { contactFromCardBytes } from '../src/contact-card.js';
import { deriveIdentity } from '../src/identity-keys.js';

const DIR = new URL('./fixtures/envelopes/', import.meta.url);
const read = (name) => new Uint8Array(readFileSync(new URL(name, DIR)));
const keys = JSON.parse(readFileSync(new URL('keys.json', DIR), 'utf8'));
const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

const wallet = await initHDWallet();
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const fromHex = (text) => Uint8Array.from(Buffer.from(text, 'hex'));

describe('envelope fixtures', () => {
  it('keys.json holds the test seed account-0 identity', () => {
    const seed = wallet.mnemonic.toSeed(PHRASE);
    const identity = deriveIdentity(wallet, seed, 0);
    seed.fill(0);
    expect(keys).toMatchObject({
      account: 0,
      signingKeyPath: "m/44'/0'/0'/0'/0'",
      encryptionKeyPath: "m/44'/0'/0'/1'/0'",
      edPub: hex(identity.edPub),
      xPub: hex(identity.xPub),
      peerId: identity.peerId,
      context: envelopes.MESSAGE_CONTEXT,
    });
    expect(hex(wallet.curves.x25519.publicKey(fromHex(keys.testOnlyX25519PrivateKey)))).toBe(keys.xPub);
  });

  it('message.txt.rec verifies, signed by the test peer, over message.txt', () => {
    const original = read('message.txt');
    const result = envelopes.verifyInput(wallet, read('message.txt.rec'));
    expect(result).toMatchObject({ kind: 'rec', valid: true, timestampValid: true });
    expect(result.signer.peerId).toBe(keys.peerId);
    expect(hex(result.content)).toBe(hex(original));
    expect(result.notice.CID).toBe(keys.cid);
    expect(result.notice.PUBLISH_TIMESTAMP).toBe(keys.publishTimestamp);
    expect(hex(wallet.utils.sha256(original))).toBe(keys.messageSha256);
  });

  it('message.txt.pnm is a size-prefixed $PNM that verifies against message.txt only', () => {
    const pnm = read('message.txt.pnm');
    expect(String.fromCharCode(...pnm.slice(8, 12))).toBe('$PNM');
    expect(envelopes.verifyInput(wallet, pnm, { original: read('message.txt') })).toMatchObject({ kind: 'pnm', valid: true });
    expect(envelopes.verifyInput(wallet, pnm, { original: read('plain.bin') })).toMatchObject({ valid: false, reason: 'changed' });
  });

  it('message.txt.enc decrypts with the account-0 X25519 key to message.txt, signed by the test peer', () => {
    const r = envelopes.decryptFile(wallet, read('message.txt.enc'), {
      encryptionKey: fromHex(keys.testOnlyX25519PrivateKey),
      fileName: 'message.txt.enc',
    });
    expect(r.ok).toBe(true);
    expect(r.file).toMatchObject({ name: 'message.txt', mediaType: envelopes.TEXT_MEDIA_TYPE });
    expect(hex(r.file.content)).toBe(hex(read('message.txt')));
    expect(r.signature).toMatchObject({ valid: true });
    expect(r.signature.signer.peerId).toBe(keys.peerId);
  });

  it('plain.bin.enc decrypts byte-identical to plain.bin, unsigned', () => {
    const r = envelopes.decryptFile(wallet, read('plain.bin.enc'), { encryptionKey: fromHex(keys.testOnlyX25519PrivateKey) });
    expect(r).toMatchObject({ ok: true, isFileRecord: true, signature: null });
    expect(hex(wallet.utils.sha256(r.file.content))).toBe(keys.plainBinSha256);
    expect(hex(r.file.content)).toBe(hex(read('plain.bin')));
  });

  it('contact.epm imports as the test peer with an encryption key and no xpub', () => {
    const bytes = read('contact.epm');
    const contact = contactFromCardBytes(wallet, envelopes, bytes);
    expect(contact).toMatchObject({ peerId: keys.peerId, name: 'Ada Lovelace', encryptionKey: keys.xPub, signingKey: keys.edPub });
    expect(Buffer.from(bytes).toString('latin1')).not.toMatch(/xpub[1-9A-HJ-NP-Za-km-z]{100,}/u);
  });
});
