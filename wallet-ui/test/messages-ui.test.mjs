// Messages end to end on a stub DOM: the real pane (messages-ui.js), the real
// envelopes (envelopes.js) and the real WASM keys of the test seed. Every
// file the pane offers is captured and fed back in, as a person would.

import initHDWallet from 'hd-wallet-wasm';
import { describe, expect, it } from 'vitest';

import {
  MAX_MESSAGE_BYTES,
  SEED_ONLY,
  TOO_LARGE,
  classifyRecipientInput,
  createMessagesPane,
  decryptErrorText,
  verifyReasonText,
} from '../src/messages-ui.js';
import * as envelopes from '../src/envelopes.js';
import { createTestContext } from './helpers/account-context.mjs';
import { StubDocument, buttonByText, flush, rowValue, textOf, waitFor } from './helpers/stub-dom.mjs';

const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const PEER = '12D3KooWJB7pwCc5pMGNVykovHTSMHGTxiQBEFBVwsgFoAmMkmWZ';
const wallet = await initHDWallet();
const seed = wallet.mnemonic.toSeed(PHRASE);

function file(bytes, name, type = '') {
  const data = bytes instanceof Uint8Array ? bytes : new TextEncoder().encode(bytes);
  return {
    name,
    type,
    size: data.length,
    lastModified: 1_700_000_000_000,
    arrayBuffer: async () => data.slice().buffer,
  };
}

function setup(options = {}) {
  const doc = new StubDocument();
  const panel = doc.createElement('section');
  doc.body.append(panel);
  const ctx = createTestContext({
    document: doc,
    wasm: wallet,
    seed,
    profile: { name: 'Ada' },
    envelopes,
    ...options,
  });
  const pane = createMessagesPane(panel, ctx);
  pane.show();
  return { doc, panel, ctx, pane };
}

function chip(panel, label) {
  return panel.querySelectorAll('.chip').find((node) => textOf(node) === label);
}

function resultText(panel) {
  const result = panel.querySelector('.result');
  return result && !result.hidden ? textOf(result) : '';
}

async function settled(panel) {
  await waitFor(() => resultText(panel) || panel.querySelectorAll('.drop-zone').length > 1, { label: 'a result' });
}

async function typeAndRun(panel, text, action) {
  const textarea = panel.querySelector('textarea');
  textarea.value = text;
  textarea.dispatch('input');
  buttonByText(panel, action).click();
  await settled(panel);
}

async function dropOn(target, f) {
  const panel = target.closest('section') ?? target;
  const before = resultText(panel);
  const zones = panel.querySelectorAll('.drop-zone').length;
  target.dispatch('drop', { dataTransfer: { files: [f] } });
  await flush(4);
  await waitFor(() => resultText(panel) !== before
    || panel.querySelectorAll('.drop-zone').length !== zones
    || /This file is encrypted/u.test(textOf(panel))
    || panel.querySelector('.file-row:not([hidden=true])'), { label: 'the drop to land' }).catch(() => {});
}

describe('Messages pane', () => {
  it('has Sign · Verify · Encrypt · Decrypt and no key-type or path controls', () => {
    const { panel } = setup();
    expect(panel.querySelectorAll('.chip').map(textOf)).toEqual(['Sign', 'Verify', 'Encrypt', 'Decrypt']);
    expect(chip(panel, 'Sign').getAttribute('aria-pressed')).toBe('true');
    expect(panel.querySelectorAll('select')).toHaveLength(0);
    expect(textOf(panel)).not.toMatch(/Bitcoin|Ethereum|Solana|HD path/u);
    expect(textOf(panel)).toContain('Signed as Ada · 12D3KooW…kmWZ');
    expect(buttonByText(panel, 'Sign').disabled).toBe(true);
  });

  it('signs typed text and verifies the .rec: valid, signed by you, content shown', async () => {
    const { panel, ctx } = setup();
    await typeAndRun(panel, 'hello SDN', 'Sign');
    expect(textOf(panel)).toContain('Signed');
    buttonByText(panel, 'Download message.txt.rec').click();
    buttonByText(panel, 'Download signature only').click();
    const [rec, pnm] = ctx.state.downloads;
    expect(rec.name).toBe('message.txt.rec');
    expect(rec.mime).toBe('application/octet-stream');
    expect(pnm.name).toBe('message.txt.pnm');
    expect(pnm.mime).toBe('application/vnd.sdn.pnm');
    // Size-prefixed FlatBuffer: u32 size, u32 root offset, then the file identifier.
    expect(String.fromCharCode(...pnm.bytes.slice(8, 12))).toBe('$PNM');
    expect(new DataView(pnm.bytes.buffer, pnm.bytes.byteOffset).getUint32(0, true)).toBe(pnm.bytes.length - 4);

    chip(panel, 'Verify').click();
    await dropOn(panel.querySelector('.drop-zone'), file(rec.bytes, 'message.txt.rec'));
    const resultNode = panel.querySelector('.result');
    expect(textOf(resultNode.querySelector('.status'))).toBe('Valid signature');
    expect(rowValue(resultNode, 'Signed by')).toBe('Ada');
    expect(rowValue(resultNode, 'Peer ID')).toBe('12D3KooW…kmWZCopy');
    // SEC-039: the date and file name are claims, not part of what was signed.
    expect(rowValue(resultNode, 'Date')).toContain('(claimed: the date is signed separately from the content)');
    expect(textOf(resultNode)).not.toContain('timestamp signature valid');
    expect(rowValue(resultNode, 'File name (not signed)')).toBe('message.txt');
    expect(rowValue(resultNode, 'Size')).toBe('9 B');
    expect(textOf(resultNode)).toContain('The file name is not part of what was signed.');
    expect(textOf(panel.querySelector('.result .code pre'))).toBe('hello SDN');
    buttonByText(panel, 'Save original file').click();
    expect(new TextDecoder().decode(ctx.state.downloads.at(-1).bytes)).toBe('hello SDN');
    expect(ctx.state.downloads.at(-1).name).toBe('message.txt');
  });

  it('reports a tampered payload as changed after signing', async () => {
    const { panel, ctx } = setup();
    await typeAndRun(panel, 'hello SDN', 'Sign');
    buttonByText(panel, 'Download message.txt.rec').click();
    const tampered = ctx.state.downloads[0].bytes.slice();
    tampered[0] ^= 0x01;
    chip(panel, 'Verify').click();
    await dropOn(panel.querySelector('.drop-zone'), file(tampered, 'message.txt.rec'));
    const result = textOf(panel.querySelector('.result'));
    expect(result).toContain('Not valid');
    expect(result).toContain('The content was changed after signing.');
  });

  it('a detached .pnm asks for the original file and checks it', async () => {
    const { panel, ctx } = setup();
    const original = new Uint8Array([0x25, 0x50, 0x44, 0x46, 1, 2, 3, 4, 5]);
    await dropOn(panel, file(original, 'test.pdf', 'application/pdf'));
    expect(textOf(panel.querySelector('.file-name'))).toBe('test.pdf');
    buttonByText(panel, 'Sign').click();
    await flush();
    buttonByText(panel, 'Download signature only').click();
    const pnm = ctx.state.downloads.at(-1);
    expect(pnm.name).toBe('test.pdf.pnm');

    chip(panel, 'Verify').click();
    await dropOn(panel.querySelector('.drop-zone'), file(pnm.bytes, 'test.pdf.pnm'));
    const zones = panel.querySelectorAll('.drop-zone');
    expect(zones).toHaveLength(2);
    expect(textOf(zones[1])).toContain('Now add the original file');
    await dropOn(zones[1], file(original, 'test.pdf'));
    expect(textOf(panel.querySelector('.result'))).toContain('Valid signature');

    await dropOn(panel.querySelectorAll('.drop-zone')[1], file(new Uint8Array([9, 9, 9]), 'other.pdf'));
    expect(textOf(panel.querySelector('.result'))).toContain('Not valid');
  });

  it('a non-SDS file is not a signed SDS file', async () => {
    const { panel } = setup();
    chip(panel, 'Verify').click();
    await dropOn(panel.querySelector('.drop-zone'), file('just text', 'notes.txt'));
    expect(textOf(panel.querySelector('.result'))).toContain('This is not a signed SDS file.');
  });

  it('encrypts to Myself, signed, and decrypts it: signer, name, type and content', async () => {
    const { panel, ctx } = setup();
    chip(panel, 'Encrypt').click();
    expect(panel.querySelector('select').value).toBe('self');
    await typeAndRun(panel, 'secret plans', 'Encrypt');
    expect(textOf(panel.querySelector('.result'))).toContain('Encrypted for yourself');
    expect(textOf(panel.querySelector('.result'))).toContain('Only you can open it.');
    buttonByText(panel, 'Download message.txt.enc').click();
    const enc = ctx.state.downloads.at(-1);
    expect(enc.name).toBe('message.txt.enc');

    chip(panel, 'Verify').click();
    await dropOn(panel.querySelector('.drop-zone'), file(enc.bytes, 'message.txt.enc'));
    expect(textOf(panel)).toContain('This file is encrypted. Open it in Decrypt.');
    buttonByText(panel, 'Decrypt').click();
    await flush(10);
    expect(chip(panel, 'Decrypt').getAttribute('aria-pressed')).toBe('true');
    const resultNode = panel.querySelector('.result');
    expect(textOf(resultNode.querySelector('.status'))).toBe('Decrypted');
    expect(textOf(resultNode.querySelector('.signature-line'))).toBe('Signed by Ada · 12D3KooW…kmWZ · Valid signature');
    // SEC-071: the signature does not name the recipient.
    expect(textOf(resultNode.querySelector('.signature-block'))).toContain('it may have been forwarded to you by someone else');
    expect(rowValue(resultNode, 'File')).toBe('message.txt');
    expect(rowValue(resultNode, 'Type')).toBe('text/plain; charset=utf-8');
    expect(textOf(panel.querySelector('.result .code pre'))).toBe('secret plans');
    buttonByText(panel, 'Save message.txt').click();
    expect(new TextDecoder().decode(ctx.state.downloads.at(-1).bytes)).toBe('secret plans');
  });

  it('round-trips a binary file byte for byte, unsigned', async () => {
    const { panel, ctx } = setup();
    const bytes = new Uint8Array(4096).map((_, index) => (index * 31) & 0xff);
    chip(panel, 'Encrypt').click();
    await dropOn(panel, file(bytes, 'blob.bin', 'application/octet-stream'));
    panel.querySelector('input[type=checkbox]').checked = false;
    buttonByText(panel, 'Encrypt').click();
    await flush();
    buttonByText(panel, 'Download blob.bin.enc').click();
    chip(panel, 'Decrypt').click();
    await dropOn(panel.querySelector('.drop-zone'), file(ctx.state.downloads.at(-1).bytes, 'blob.bin.enc'));
    expect(textOf(panel.querySelector('.result'))).toContain('Not signed');
    buttonByText(panel, 'Save blob.bin').click();
    expect([...ctx.state.downloads.at(-1).bytes]).toEqual([...bytes]);
  });

  it('a file encrypted for another key says so', async () => {
    const { panel, ctx } = setup();
    chip(panel, 'Encrypt').click();
    const select = panel.querySelector('select');
    select.value = 'other';
    select.dispatch('change');
    const keyInput = panel.querySelector('input[type=text]');
    keyInput.value = wallet.utils.encodeHex(wallet.curves.x25519.publicKey(new Uint8Array(32).fill(7)));
    keyInput.dispatch('input');
    await typeAndRun(panel, 'for someone else', 'Encrypt');
    expect(textOf(panel.querySelector('.result'))).toMatch(/Encrypted for key [0-9a-f]{4}…[0-9a-f]{4}/u);
    buttonByText(panel, 'Download message.txt.enc').click();
    chip(panel, 'Decrypt').click();
    await dropOn(panel.querySelector('.drop-zone'), file(ctx.state.downloads.at(-1).bytes, 'message.txt.enc'));
    expect(textOf(panel.querySelector('.result'))).toContain('This file was encrypted for a different key.');
  });

  it('keeps the composed text between Sign and Encrypt', () => {
    const { panel } = setup();
    const textarea = panel.querySelector('textarea');
    textarea.value = 'carry me';
    textarea.dispatch('input');
    chip(panel, 'Encrypt').click();
    expect(panel.querySelector('textarea').value).toBe('carry me');
    chip(panel, 'Sign').click();
    expect(panel.querySelector('textarea').value).toBe('carry me');
  });

  it('refuses files over 50 MB', async () => {
    const { panel } = setup();
    panel.dispatch('drop', { dataTransfer: { files: [{ name: 'huge.bin', size: MAX_MESSAGE_BYTES + 1, type: '' }] } });
    await flush();
    expect(textOf(panel)).toContain(TOO_LARGE);
  });

  it('an external-wallet session sees one line and nothing else', () => {
    const { panel } = setup({ kind: 'external' });
    expect(textOf(panel)).toContain(SEED_ONLY);
    expect(panel.querySelectorAll('.chip')).toHaveLength(0);
    expect(panel.querySelectorAll('textarea')).toHaveLength(0);
  });

  it('leaving the pane drops results and input', async () => {
    const { panel, pane } = setup();
    await typeAndRun(panel, 'hello', 'Sign');
    expect(pane.hasResult).toBe(true);
    pane.reset();
    expect(panel.childNodes).toHaveLength(0);
    pane.show();
    expect(panel.querySelector('textarea').value).toBe('');
  });
});

describe('recipient input and messages', () => {
  const contacts = [{ peerId: PEER, name: 'Ada', encryptionKey: 'ab'.repeat(32) }];

  it('classifies keys, peer IDs and xpubs', () => {
    expect(classifyRecipientInput('AB'.repeat(32))).toEqual({ kind: 'key', key: 'ab'.repeat(32) });
    expect(classifyRecipientInput(PEER, contacts)).toEqual({ kind: 'contact', contact: contacts[0] });
    expect(classifyRecipientInput('12D3KooWCbzh8GgBWc9NC14XLA2ZjeNUQRUsjdH58fk6n5uruRqw', contacts)).toEqual({
      kind: 'error',
      message: 'A peer ID has no encryption key. Add their contact card first.',
    });
    expect(classifyRecipientInput(`xpub${'6'.repeat(107)}`).message).toBe("An xpub can't receive encrypted files. Use their contact card.");
    expect(classifyRecipientInput('').kind).toBe('empty');
  });

  it('maps envelope reason codes to the spec sentences', () => {
    expect(verifyReasonText('changed')).toBe('The content was changed after signing.');
    expect(verifyReasonText('signature')).toBe('The signature does not match the signer.');
    expect(verifyReasonText('not-sds')).toBe('This is not a signed SDS file.');
    expect(verifyReasonText('not-peer-id')).toBe('The signer address is not an SDN peer ID.');
    expect(decryptErrorText({ code: 'not-enc' })).toBe('This file is not an SDS encrypted file.');
    expect(decryptErrorText({ code: 'wrong-recipient' })).toBe('This file was encrypted for a different key.');
    expect(decryptErrorText({ code: 'auth-failed' })).toBe('Decryption failed: the file was changed or the key is wrong.');
    expect(decryptErrorText({ code: 'unsupported' })).toBe('Only X25519 / AES-256-GCM files are supported.');
  });
});
