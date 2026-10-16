// The contact card as a file, end to end: buildContactEpm fields encoded by
// envelopes.js encodeEpm into a size-prefixed $EPM, read back by decodeEpm
// and checked by contactFromEpm, then used between two identities in the real
// Messages pane (spec §3.1, §3.3, checklist item 9).

import initHDWallet, { verifyChainProof, verifyEPMSignature } from 'hd-wallet-wasm';
import * as flatbuffers from 'flatbuffers';
import { EPM } from '@sds/lib/js/EPM/EPM.js';
import { describe, expect, it } from 'vitest';

import {
  CONTACT_CARD_INVALID,
  CONTACT_CARD_NOT_EPM,
  bytesToBase64,
  buildContactEpm,
  contactCardBytes,
  contactFromCardBytes,
  upsertContact,
} from '../src/contact-card.js';
import * as envelopes from '../src/envelopes.js';
import { accountXpub, deriveAccountAddresses, deriveIdentity, withChainKey, withEdKey } from '../src/identity-keys.js';
import { createMessagesPane } from '../src/messages-ui.js';
import { createTestContext } from './helpers/account-context.mjs';
import { StubDocument, buttonByText, flush, rowValue, textOf, waitFor } from './helpers/stub-dom.mjs';

const PHRASE_A = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PHRASE_B = `${'zoo '.repeat(11)}wrong`;
const wallet = await initHDWallet();

function jpeg(width = 16, height = 16, padding = 11) {
  const bytes = new Uint8Array(21 + padding);
  bytes.set([0xff, 0xd8, 0xff, 0xc0, 0x00, 0x11, 0x08, height >> 8, height & 0xff, width >> 8, width & 0xff, 0x03]);
  return bytes;
}
const PHOTO = `data:image/jpeg;base64,${bytesToBase64(jpeg())}`;

function person(phrase, profile) {
  const seed = wallet.mnemonic.toSeed(phrase);
  const root = wallet.hdkey.fromSeed(seed);
  const identity = deriveIdentity(wallet, seed, 0);
  const addresses = deriveAccountAddresses(wallet, root, 0);
  const options = {
    profile,
    identity,
    accountXpub: accountXpub(root, 0),
    addresses,
    withChainKey: (path, fn) => withChainKey(root, path, fn),
    withEdKey: (fn) => withEdKey(wallet, seed, 0, fn),
  };
  return { seed, root, identity, addresses, profile, options };
}

const alice = person(PHRASE_A, { name: 'Ada Lovelace', organization: 'Analytical Engines', email: 'ada@example.org', city: 'London', photo: PHOTO });
const bob = person(PHRASE_B, { name: 'Bob Babbage' });

function find(bytes, text) {
  const needle = new TextEncoder().encode(text);
  outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    return i;
  }
  return -1;
}

describe('the .epm file', () => {
  it('is a size-prefixed $EPM that the SDS reader and the contact import both accept', () => {
    const bytes = contactCardBytes(wallet, envelopes, alice.options);
    expect(new DataView(bytes.buffer, bytes.byteOffset).getUint32(0, true)).toBe(bytes.length - 4);
    expect(String.fromCharCode(...bytes.slice(8, 12))).toBe('$EPM');

    // The generated SDS 1.249.0 reader sees the same card.
    const sds = EPM.getSizePrefixedRootAsEPM(new flatbuffers.ByteBuffer(bytes)).unpack();
    expect(sds.LEGAL_NAME).toBe('Ada Lovelace');
    expect(sds.DN).toBe('CN=Ada Lovelace,O=Analytical Engines');
    expect(sds.PHOTO).toBe(PHOTO);
    expect(sds.KEYS.map((key) => [key.KEY_TYPE, key.ALGORITHM])).toEqual([[0, 'ed25519'], [1, 'x25519']]);
    expect(sds.KEYS.every((key) => key.PRIVATE_KEY === null && key.XPRIV === null && key.XPUB === null && key.KEY_PATH === null)).toBe(true);
    expect(sds.MULTIFORMAT_ADDRESS).toEqual([`/p2p/${alice.identity.peerId}`]);
    expect(sds.SIGNATURE_ALGORITHM).toBe('ed25519');

    // decodeEpm gives back fields whose signature and proofs verify.
    const fields = envelopes.decodeEpm(wallet, bytes);
    expect(verifyEPMSignature(wallet, fields, alice.identity.edPub)).toBe(true);
    for (const proof of fields.CHAIN_PROOFS) expect(verifyChainProof(wallet, proof)).toBe(true);

    const contact = contactFromCardBytes(wallet, envelopes, bytes);
    expect(contact).toMatchObject({
      peerId: alice.identity.peerId,
      name: 'Ada Lovelace',
      organization: 'Analytical Engines',
      email: 'ada@example.org',
      city: 'London',
      photo: PHOTO,
      encryptionKey: wallet.utils.encodeHex(alice.identity.xPub),
    });
    expect(contact.addresses).toEqual({
      btc: alice.addresses.btc.address,
      eth: alice.addresses.eth.address,
      sol: alice.addresses.sol.address,
    });
  });

  it('round-trips the field object exactly (what was signed is what is read)', () => {
    const epm = buildContactEpm(wallet, alice.options);
    const decoded = envelopes.decodeEpm(wallet, envelopes.encodeEpm(wallet, epm));
    expect(decoded.LEGAL_NAME).toBe(epm.LEGAL_NAME);
    expect(decoded.ADDRESS).toEqual(epm.ADDRESS);
    expect(decoded.KEYS).toEqual(epm.KEYS);
    expect(decoded.CHAIN_PROOFS).toEqual(epm.CHAIN_PROOFS);
    expect(decoded.SIGNATURE).toBe(epm.SIGNATURE);
    expect(decoded.SIGNATURE_TIMESTAMP).toBe(epm.SIGNATURE_TIMESTAMP);
    expect(decoded.ENTITY_TYPE).toBe(0);
  });

  it('also reads a root (not size-prefixed) $EPM', () => {
    const bytes = contactCardBytes(wallet, envelopes, bob.options);
    const table = EPM.getSizePrefixedRootAsEPM(new flatbuffers.ByteBuffer(bytes)).unpack();
    const builder = new flatbuffers.Builder(1024);
    EPM.finishEPMBuffer(builder, table.pack(builder));
    const root = builder.asUint8Array();
    expect(String.fromCharCode(...root.slice(4, 8))).toBe('$EPM');
    expect(contactFromCardBytes(wallet, envelopes, root).peerId).toBe(bob.identity.peerId);
  });

  it('one changed byte in the card makes its signature invalid', () => {
    const bytes = contactCardBytes(wallet, envelopes, alice.options);
    const at = find(bytes, 'Ada Lovelace');
    expect(at).toBeGreaterThan(0);
    const tampered = bytes.slice();
    tampered[at] ^= 0x01;
    expect(() => contactFromCardBytes(wallet, envelopes, tampered)).toThrow(CONTACT_CARD_INVALID);
  });

  it('anything that is not a well-formed $EPM is "not an SDS contact card"', () => {
    const card = contactCardBytes(wallet, envelopes, alice.options);
    const notice = withEdKey(wallet, alice.seed, 0, (signingKey) => envelopes.signContent(wallet, { content: 'x', signingKey }));
    for (const bytes of [
      new Uint8Array(0),
      new TextEncoder().encode('BEGIN:VCARD\nFN:Ada\nEND:VCARD'),
      envelopes.buildPnmFile(wallet, notice),
      card.slice(0, card.length - 9),
      (() => { const b = card.slice(); b.set([0xff, 0xff, 0xff, 0x7f], 4); return b; })(),
    ]) {
      expect(() => envelopes.decodeEpm(wallet, bytes)).toThrow(envelopes.EnvelopeError);
      expect(() => contactFromCardBytes(wallet, envelopes, bytes)).toThrow(CONTACT_CARD_NOT_EPM);
    }
  });

  it('never writes a private key into a card', () => {
    const epm = buildContactEpm(wallet, alice.options);
    const withSecret = { ...epm, KEYS: [{ ...epm.KEYS[0], PRIVATE_KEY: '00'.repeat(32) }] };
    expect(() => envelopes.encodeEpm(wallet, withSecret)).toThrow(/private key/u);
  });
});

// ---- two people exchange cards and encrypt to each other ---------------------

function file(bytes, name) {
  return { name, type: '', size: bytes.length, lastModified: 0, arrayBuffer: async () => bytes.slice().buffer };
}

function pane(who, contacts) {
  const doc = new StubDocument();
  const panel = doc.createElement('section');
  doc.body.append(panel);
  const ctx = createTestContext({
    document: doc,
    wasm: wallet,
    seed: who.seed,
    profile: { name: who.profile.name },
    contacts,
    envelopes,
  });
  const messages = createMessagesPane(panel, ctx);
  return { panel, ctx, messages };
}

async function decryptIn(view, bytes) {
  view.messages.show({ mode: 'decrypt' });
  view.panel.querySelector('.drop-zone').dispatch('drop', { dataTransfer: { files: [file(bytes, 'message.txt.enc')] } });
  await waitFor(() => {
    const result = view.panel.querySelector('.result');
    return result && !result.hidden;
  }, { label: 'the decrypt result' });
  return view.panel.querySelector('.result');
}

describe('two people exchange contact cards', () => {
  it('encrypts to a contact: only they can open it, and they see who signed it', async () => {
    const aliceAtBob = contactFromCardBytes(wallet, envelopes, contactCardBytes(wallet, envelopes, alice.options));
    const bobAtAlice = contactFromCardBytes(wallet, envelopes, contactCardBytes(wallet, envelopes, bob.options));
    const bobView = pane(bob, upsertContact([], aliceAtBob));
    const aliceView = pane(alice, upsertContact([], bobAtAlice));

    // Bob encrypts to Alice, signed.
    bobView.messages.show({ mode: 'encrypt', peerId: alice.identity.peerId });
    const select = bobView.panel.querySelector('select');
    expect(select.value).toBe(`contact:${alice.identity.peerId}`);
    const textarea = bobView.panel.querySelector('textarea');
    textarea.value = 'meet at noon';
    textarea.dispatch('input');
    buttonByText(bobView.panel, 'Encrypt').click();
    await waitFor(() => /Encrypted for/u.test(textOf(bobView.panel)), { label: 'the encrypt result' });
    expect(textOf(bobView.panel.querySelector('.result'))).toContain('Encrypted for Ada Lovelace');
    expect(textOf(bobView.panel.querySelector('.result'))).toContain('Only they can open it.');
    buttonByText(bobView.panel, 'Download message.txt.enc').click();
    const enc = bobView.ctx.state.downloads.at(-1).bytes;

    // Bob cannot open it: it was meant for Alice.
    const bobResult = await decryptIn(bobView, enc);
    expect(textOf(bobResult)).toContain('This file was encrypted for a different key.');

    // Alice opens it and sees Bob, from her contacts, as the signer.
    const aliceResult = await decryptIn(aliceView, enc);
    await flush();
    expect(textOf(aliceResult.querySelector('.status'))).toBe('Decrypted');
    expect(textOf(aliceResult.querySelector('.signature-line'))).toMatch(/^Signed by Bob Babbage · 12D3KooW…\w{4} · Valid signature$/u);
    expect(rowValue(aliceResult, 'File')).toBe('message.txt');
    expect(textOf(aliceResult.querySelector('.code pre'))).toBe('meet at noon');
  });
});
