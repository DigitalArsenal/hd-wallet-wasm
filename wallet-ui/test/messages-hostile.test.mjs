// Messages with files a stranger made: a forged signature that names one of
// your contacts, a decrypted file that claims to be HTML under a
// right-to-left-override name, and a contact whose name imitates the verdict.
// Real pane, real envelopes, real WASM keys of the public test seed.

import initHDWallet from 'hd-wallet-wasm';
import { describe, expect, it } from 'vitest';

import { createMessagesPane, safeFileName } from '../src/messages-ui.js';
import * as envelopes from '../src/envelopes.js';
import { deriveIdentity } from '../src/identity-keys.js';
import { createTestContext } from './helpers/account-context.mjs';
import { StubDocument, flush, rowValue, textOf, waitFor } from './helpers/stub-dom.mjs';

const PHRASE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const wallet = await initHDWallet();
const seed = wallet.mnemonic.toSeed(PHRASE);
const me = deriveIdentity(wallet, seed, 0);

function file(bytes, name) {
  return { name, type: '', size: bytes.length, lastModified: 0, arrayBuffer: async () => bytes.slice().buffer };
}

function setup(contacts = []) {
  const doc = new StubDocument();
  const panel = doc.createElement('section');
  doc.body.append(panel);
  const ctx = createTestContext({ document: doc, wasm: wallet, seed, profile: { name: 'Ada' }, envelopes, contacts });
  const pane = createMessagesPane(panel, ctx);
  pane.show();
  return { panel, ctx, pane };
}

async function drop(panel, mode, bytes, name) {
  panel.querySelectorAll('.chip').find((node) => textOf(node) === mode).click();
  panel.querySelector('.drop-zone').dispatch('drop', { dataTransfer: { files: [file(bytes, name)] } });
  await flush(4);
  await waitFor(() => panel.querySelector('.result') && !panel.querySelector('.result').hidden, { label: 'a result' });
  return panel.querySelector('.result');
}

function signWithMyKey(content, overrides = {}) {
  const edPriv = wallet.slip10.deriveEd25519Path(seed, "m/44'/0'/0'/0'/0'").privateKey;
  try {
    const notice = envelopes.signContent(wallet, { content, name: 'note.txt', signingKey: edPriv });
    return envelopes.buildRecFile(wallet, content, { ...notice, ...overrides });
  } finally {
    edPriv.fill(0);
  }
}

describe('Verify', () => {
  it('never puts a contact name on a signature that is not valid', async () => {
    const alice = { peerId: me.peerId, name: 'Alice', signingKey: 'a'.repeat(64), encryptionKey: null, addresses: {} };
    const { panel } = setup([alice]);
    const content = new TextEncoder().encode('pay Mallory');
    const forged = signWithMyKey(content, { SIGNATURE: '00'.repeat(64) });
    const result = await drop(panel, 'Verify', forged, 'note.txt.rec');
    expect(textOf(result.querySelector('.status'))).toBe('Not valid');
    expect(textOf(result)).toContain('The signature does not match the signer.');
    expect(rowValue(result, 'Signed by')).toBe('Unknown signer');
    expect(textOf(result)).not.toContain('Alice');

    const genuine = signWithMyKey(content);
    const valid = await drop(panel, 'Verify', genuine, 'note.txt.rec');
    expect(rowValue(valid, 'Signed by')).toBe('Alice');
  });

  it('shows and saves a signed file name without bidi or control characters', async () => {
    const { panel, ctx } = setup();
    const content = new TextEncoder().encode('MZ');
    const rec = signWithMyKey(content, { FILE_NAME: 'invoice\u202Etxt.exe' });
    const result = await drop(panel, 'Verify', rec, 'x.rec');
    expect(rowValue(result, 'File name (not signed)')).toBe('invoicetxt.exe');
    expect(rowValue(result, 'Size')).toBe('2 B');
    [...result.querySelectorAll('button')].find((node) => textOf(node) === 'Save original file').click();
    expect(ctx.state.downloads.at(-1)).toMatchObject({ name: 'invoicetxt.exe', mime: 'application/octet-stream' });
  });
});

describe('Decrypt', () => {
  it('saves as plain bytes whatever media type the sender claims, under a cleaned name', async () => {
    const { panel, ctx } = setup();
    const sealed = envelopes.encryptContent(wallet, {
      content: '<script>alert(1)</script>',
      name: '../evil\u202Elmth.txt',
      mediaType: 'text/html',
      recipientPublicKey: me.xPub,
    }).bytes;
    const result = await drop(panel, 'Decrypt', sealed, 'evil.enc');
    expect(rowValue(result, 'Type')).toBe('text/html');
    expect(rowValue(result, 'File')).toBe('evillmth.txt');
    expect(result.querySelectorAll('script')).toHaveLength(0);
    [...result.querySelectorAll('button')].find((node) => textOf(node) === 'Save evillmth.txt').click();
    expect(ctx.state.downloads.at(-1)).toMatchObject({ name: 'evillmth.txt', mime: 'application/octet-stream' });
  });

  it('keeps a contact name, the peer ID and the verdict in separate elements', async () => {
    const spoof = 'Bob · 12D3KooW…x7Qp · Valid signature';
    const contact = { peerId: me.peerId, name: spoof, signingKey: 'a'.repeat(64), encryptionKey: null, addresses: {} };
    const { panel } = setup([contact]);
    const edPriv = wallet.slip10.deriveEd25519Path(seed, "m/44'/0'/0'/0'/0'").privateKey;
    let sealed;
    try {
      sealed = envelopes.encryptContent(wallet, { content: 'hi', recipientPublicKey: me.xPub, signingKey: edPriv }).bytes;
    } finally {
      edPriv.fill(0);
    }
    const result = await drop(panel, 'Decrypt', sealed, 'hi.enc');
    const line = result.querySelector('.signature-line');
    expect(textOf(line.querySelector('.signer-name'))).toBe(spoof);
    expect(textOf(line.querySelector('.signature-verdict'))).toBe('Valid signature');
    expect(line.querySelector('.mono').title).toBe(me.peerId);
  });
});

describe('safeFileName', () => {
  it('drops controls, bidi overrides, line separators and path separators', () => {
    expect(safeFileName('a\u0000b\u001fc\u202Ed\u2066e\u2028f/g\\h')).toBe('abcdefgh');
    expect(safeFileName('..\u202E')).toBe('file');
    expect(safeFileName('', 'original')).toBe('original');
    expect(safeFileName('report.pdf')).toBe('report.pdf');
  });
});
