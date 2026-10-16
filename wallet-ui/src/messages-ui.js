/**
 * Messages: sign, verify, encrypt and decrypt with the account's SDN identity.
 *
 * Every output is a Space Data Standards file built by envelopes.js:
 *   .rec  the content, then $REC{$PNM}, then the 8-byte trailer
 *   .pnm  a size-prefixed $PNM over the content's CID (detached signature)
 *   .enc  AES-256-GCM ciphertext plus $REC{$ENC}; the plaintext is a $FIL,
 *         signed inside when "Sign it" is on
 *
 * Keys: Ed25519 at m/44'/0'/N'/0'/0' signs, X25519 at m/44'/0'/N'/1'/0'
 * receives. Private keys are derived per operation by ctx.keys and zeroed by
 * the scope that derived them; this module never stores one.
 *
 * The envelope functions this pane calls (envelopes.js, spec §4):
 *   signContent(wasm, { content, name, signingKey })        -> PNM notice
 *   buildRecFile(wasm, content, notice)                     -> .rec bytes
 *   buildPnmFile(wasm, notice)                              -> .pnm bytes
 *   verifyInput(wasm, bytes, { original? })                 -> { kind, valid, reason, timestampValid,
 *                                                                signer, notice, content, fileName, size }
 *   encryptContent(wasm, { content, name, mediaType, modifiedAtMs,
 *                          recipientPublicKey, signingKey? }) -> { bytes, fileName, ... }
 *   decryptFile(wasm, bytes, { encryptionKey, fileName })   -> { ok, isFileRecord, file | bytes, signature }
 * The module is loaded lazily (ctx.loadEnvelopes) so a host or test can
 * supply its own implementation.
 */

import {
  actions,
  announce,
  button,
  chip,
  codeBlock,
  copyChip,
  details,
  dropZone,
  el,
  field,
  filePicker,
  formatBytes,
  input,
  muted,
  paneHead,
  row,
  select,
  setBusy,
  setPressed,
  statusLine,
  swapPane,
} from './ui-dom.js';
import { encryptionKeyPath, shortPeerId, signingKeyPath, toHex } from './identity-keys.js';

export const MAX_MESSAGE_BYTES = 50 * 1024 * 1024;
export const MAX_SHOWN_TEXT_BYTES = 64 * 1024;
export const TOO_LARGE = 'Files up to 50 MB can be signed or encrypted here.';
export const SEED_ONLY = 'Sign in with a seed phrase to use your SDN identity.';

export const VERIFY_REASONS = Object.freeze({
  changed: 'The content was changed after signing.',
  signature: 'The signature does not match the signer.',
  'not-signed': 'This is not a signed SDS file.',
  'not-peer-id': 'The signer address is not an SDN peer ID.',
});

export const DECRYPT_ERRORS = Object.freeze({
  'not-enc': 'This file is not an SDS encrypted file.',
  'wrong-key': 'This file was encrypted for a different key.',
  'decrypt-failed': 'Decryption failed: the file was changed or the key is wrong.',
  unsupported: 'Only X25519 / AES-256-GCM files are supported.',
  'file-changed': 'Decryption failed: the file was changed or the key is wrong.',
});

const REASON_ALIASES = Object.freeze({
  CHANGED: 'changed',
  CONTENT_CHANGED: 'changed',
  CID_MISMATCH: 'changed',
  SIGNATURE: 'signature',
  BAD_SIGNATURE: 'signature',
  SIGNATURE_MISMATCH: 'signature',
  NOT_SIGNED: 'not-signed',
  NOT_SDS: 'not-signed',
  NOT_SIGNED_SDS: 'not-signed',
  NOT_PEER_ID: 'not-peer-id',
  BAD_PEER_ID: 'not-peer-id',
  NOT_ENC: 'not-enc',
  NOT_ENCRYPTED: 'not-enc',
  WRONG_KEY: 'wrong-key',
  WRONG_RECIPIENT: 'wrong-key',
  DIFFERENT_KEY: 'wrong-key',
  DECRYPT_FAILED: 'decrypt-failed',
  AUTH_FAILED: 'decrypt-failed',
  UNSUPPORTED: 'unsupported',
  FILE_CHANGED: 'file-changed',
  DIGEST_MISMATCH: 'file-changed',
});

function reasonKey(value) {
  if (value === null || value === undefined || value === '') return null;
  const text = String(value);
  if (VERIFY_REASONS[text] || DECRYPT_ERRORS[text]) return text;
  return REASON_ALIASES[text.toUpperCase().replace(/[^A-Z]+/gu, '_').replace(/^_|_$/gu, '')] ?? null;
}

/** The UI sentence for a verification reason (a code, or the sentence itself). */
export function verifyReasonText(reason) {
  const key = reasonKey(reason);
  if (key && VERIFY_REASONS[key]) return VERIFY_REASONS[key];
  const text = String(reason ?? '');
  if (Object.values(VERIFY_REASONS).includes(text)) return text;
  return VERIFY_REASONS.signature;
}

/** The UI sentence for a decryption failure (an error with a code or message). */
export function decryptErrorText(error) {
  const key = reasonKey(error?.code) ?? reasonKey(error?.reason);
  if (key && DECRYPT_ERRORS[key]) return DECRYPT_ERRORS[key];
  const message = String(error?.message ?? '');
  if (Object.values(DECRYPT_ERRORS).includes(message)) return message;
  if (/different key|recipient/iu.test(message)) return DECRYPT_ERRORS['wrong-key'];
  if (/not an? .*encrypted|no enc|trailer/iu.test(message)) return DECRYPT_ERRORS['not-enc'];
  if (/unsupported|x25519|aes-256-gcm/iu.test(message)) return DECRYPT_ERRORS.unsupported;
  return DECRYPT_ERRORS['decrypt-failed'];
}

const HEX64 = /^[0-9a-f]{64}$/iu;
const PEER_ID = /^(?:12D3KooW|16Uiu2H|Qm)[1-9A-HJ-NP-Za-km-z]{20,}$/u;
const XPUB = /^[xyztuv]pub[1-9A-HJ-NP-Za-km-z]{100,}$/u;

/** Classify what someone pasted into "Their encryption key". */
export function classifyRecipientInput(value, contacts = []) {
  const text = String(value ?? '').trim();
  if (text === '') return { kind: 'empty' };
  if (HEX64.test(text)) return { kind: 'key', key: text.toLowerCase() };
  if (PEER_ID.test(text)) {
    const contact = contacts.find((entry) => entry.peerId === text);
    if (contact?.encryptionKey) return { kind: 'contact', contact };
    return { kind: 'error', message: 'A peer ID has no encryption key. Add their contact card first.' };
  }
  if (XPUB.test(text)) return { kind: 'error', message: "An xpub can't receive encrypted files. Use their contact card." };
  return { kind: 'error', message: 'Their encryption key is 64 hex characters.' };
}

/**
 * One verification shape for the UI, whatever the envelope layer returned:
 * `{ kind, valid, reason, peerId, signedAt, timestampValid, fileName, size, payload }`.
 */
export function normalizeVerification(result) {
  if (!result || typeof result !== 'object') return { valid: false, reason: 'not-signed' };
  return {
    ...result,
    peerId: result.peerId ?? result.signer?.peerId ?? '',
    signedAt: result.signedAt ?? result.notice?.PUBLISH_TIMESTAMP ?? '',
    fileName: result.fileName ?? result.notice?.FILE_NAME ?? '',
    payload: result.payload ?? result.content ?? null,
  };
}

function shortKey(hex) {
  const value = String(hex ?? '');
  return value.length > 8 ? `key ${value.slice(0, 4)}…${value.slice(-4)}` : `key ${value}`;
}

function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function utf8Text(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length > MAX_SHOWN_TEXT_BYTES) return null;
  try {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}

// Control, line-separator and bidi-override characters (U+202E can make
// "exe.txt" read as "txt.exe"), and path separators.
const UNSAFE_NAME_CHARS = /[\u0000-\u001f\u007f-\u009f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069\ufeff/\\]/gu;

/** A file name from someone else's file, safe to show and to save under. */
export function safeFileName(value, fallback = 'file') {
  const cleaned = String(value ?? '').replace(UNSAFE_NAME_CHARS, '').trim().replace(/^\.+/u, '').slice(0, 200);
  return cleaned || fallback;
}

function localDateTime(value) {
  const date = value instanceof Date ? value : new Date(value);
  return Number.isNaN(date.getTime()) ? String(value ?? '') : date.toLocaleString();
}

async function fileBytes(file) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 0) throw new Error('This file could not be read.');
  if (file.size > MAX_MESSAGE_BYTES) throw new RangeError(TOO_LARGE);
  const buffer = await file.arrayBuffer();
  const bytes = new Uint8Array(buffer);
  if (bytes.length !== file.size) throw new Error('This file could not be read.');
  return bytes;
}

/**
 * @param {HTMLElement} panel  #account-pane-messages
 * @param {object} ctx         the account context from app.js
 */
export function createMessagesPane(panel, ctx) {
  const doc = panel.ownerDocument ?? ctx.document;
  let mode = 'sign';
  // The composed input, shared by Sign and Encrypt: typed text or one file.
  let composedText = '';
  let composedFile = null;
  let carriedFile = null;
  let generation = 0;

  const chips = new Map();
  let bodyEl = null;
  let detailsEl = null;
  let liveResult = null;

  function session() {
    return ctx.session();
  }

  function identity() {
    return session().identity;
  }

  function myName() {
    const name = ctx.profile.get()?.name;
    return name && name.trim() ? name.trim() : 'you';
  }

  function contacts() {
    return ctx.contacts.list();
  }

  function contactByPeerId(peerId) {
    return contacts().find((entry) => entry.peerId === peerId) ?? null;
  }

  async function envelopes() {
    return ctx.loadEnvelopes();
  }

  function stale(token) {
    return token !== generation || !ctx.isCurrent();
  }

  // ---- input block ----------------------------------------------------------
  function inputBlock(onChange) {
    const wrap = el(doc, 'div', 'message-input');
    const textarea = el(doc, 'textarea', 'textarea');
    textarea.rows = 6;
    textarea.placeholder = 'Write a message, or drop a file here';
    textarea.value = composedText;
    textarea.setAttribute('spellcheck', 'true');
    const textField = field(doc, 'Message', textarea);
    const picker = filePicker(doc, '', (file) => setFile(file));
    const choose = button(doc, 'Choose a file…', { variant: 'link' });
    choose.addEventListener('click', picker.open);
    const fileRow = el(doc, 'div', 'file-row');
    const fileName = el(doc, 'span', 'file-name');
    const fileSize = el(doc, 'span', 'file-size');
    const remove = button(doc, 'Remove', { variant: 'link' });
    fileRow.append(fileName, fileSize, remove);
    const error = el(doc, 'p', 'field-error');
    error.hidden = true;
    wrap.append(textField, choose, picker.input, fileRow, error);

    function render() {
      const hasFile = composedFile !== null;
      textField.hidden = hasFile;
      choose.hidden = hasFile;
      fileRow.hidden = !hasFile;
      if (hasFile) {
        fileName.textContent = composedFile.name;
        fileSize.textContent = formatBytes(composedFile.size);
      }
      onChange();
    }

    function setFile(file) {
      if (file && Number(file.size) > MAX_MESSAGE_BYTES) {
        error.textContent = TOO_LARGE;
        error.hidden = false;
        return;
      }
      error.hidden = true;
      composedFile = file;
      render();
    }

    textarea.addEventListener('input', () => {
      composedText = textarea.value;
      onChange();
    });
    remove.addEventListener('click', () => {
      composedFile = null;
      render();
    });
    render();
    return {
      wrap,
      setFile,
      showError(message) {
        error.textContent = message;
        error.hidden = !message;
      },
    };
  }

  function hasInput() {
    return composedFile !== null || composedText !== '';
  }

  async function readComposed() {
    if (composedFile) {
      return {
        content: await fileBytes(composedFile),
        name: composedFile.name || 'file',
        mediaType: composedFile.type || 'application/octet-stream',
        modifiedAt: Number.isFinite(composedFile.lastModified) ? composedFile.lastModified : Date.now(),
      };
    }
    const content = new TextEncoder().encode(composedText);
    if (content.length > MAX_MESSAGE_BYTES) throw new RangeError(TOO_LARGE);
    return {
      content,
      name: 'message.txt',
      mediaType: 'text/plain; charset=utf-8',
      modifiedAt: Date.now(),
    };
  }

  function resultArea() {
    const area = el(doc, 'div', 'result');
    area.hidden = true;
    return area;
  }

  function showResult(area, children) {
    area.replaceChildren(...children.filter(Boolean));
    area.hidden = false;
    liveResult = area;
  }

  function errorResult(area, word, message) {
    showResult(area, [statusLine(doc, word, message, { error: true })]);
  }

  // ---- Sign -----------------------------------------------------------------
  function renderSign() {
    const token = generation;
    const signButton = button(doc, 'Sign', { variant: 'primary' });
    const block = inputBlock(() => { signButton.disabled = !hasInput(); });
    const signer = muted(doc, `Signed as ${myName()} · ${shortPeerId(identity()?.peerId)}`);
    signer.classList.add('signer-line');
    const area = resultArea();
    signButton.addEventListener('click', async () => {
      setBusy(signButton, true, 'Signing…');
      try {
        const composed = await readComposed();
        if (stale(token)) return;
        const env = await envelopes();
        if (stale(token)) return;
        const wasm = ctx.wasm();
        const notice = await ctx.keys.withEdKey((signingKey) => env.signContent(wasm, {
          content: composed.content,
          name: composed.name,
          signingKey,
        }));
        if (stale(token)) return;
        const recBytes = await env.buildRecFile(wasm, composed.content, notice);
        const pnmBytes = await env.buildPnmFile(wasm, notice);
        if (stale(token)) return;
        const at = new Date();
        const saveRec = button(doc, `Download ${composed.name}.rec`, { variant: 'primary' });
        saveRec.addEventListener('click', () => ctx.download(recBytes, `${composed.name}.rec`, 'application/octet-stream'));
        const savePnm = button(doc, 'Download signature only');
        savePnm.addEventListener('click', () => ctx.download(pnmBytes, `${composed.name}.pnm`, 'application/vnd.sdn.pnm'));
        showResult(area, [
          statusLine(doc, 'Signed', at.toLocaleTimeString()),
          actions(doc, saveRec, savePnm),
          muted(doc, 'Anyone can check it in Verify, or with an SDN node.'),
        ]);
      } catch (error) {
        if (stale(token)) return;
        if (error instanceof RangeError) block.showError(TOO_LARGE);
        else errorResult(area, 'Not signed', error?.message || 'The message could not be signed.');
      } finally {
        if (!stale(token)) {
          setBusy(signButton, false);
          signButton.disabled = !hasInput();
        }
      }
    });
    signButton.disabled = !hasInput();
    return { nodes: [block.wrap, signer, actions(doc, signButton), area], onFile: block.setFile };
  }

  // ---- Verify ---------------------------------------------------------------
  function renderVerify() {
    const token = generation;
    const area = resultArea();
    const secondHolder = el(doc, 'div', 'second-zone');
    const encNote = el(doc, 'p', 'inline-note');
    encNote.hidden = true;

    function signerName(peerId) {
      const contact = contactByPeerId(peerId);
      if (contact?.name) return contact.name;
      if (peerId && peerId === identity()?.peerId) {
        const name = ctx.profile.get()?.name;
        return name && name.trim() ? name.trim() : 'You';
      }
      return 'Unknown signer';
    }

    function renderVerification(raw) {
      const result = normalizeVerification(raw);
      const valid = result?.valid === true;
      const children = [statusLine(
        doc,
        valid ? 'Valid signature' : 'Not valid',
        valid ? '' : verifyReasonText(result?.reason),
        { error: !valid },
      )];
      if (result?.peerId) {
        const rows = el(doc, 'div', 'rows');
        // The peer ID in an invalid file is only a claim: never put a contact's name on it.
        rows.append(row(doc, 'Signed by', valid ? signerName(result.peerId) : 'Unknown signer'));
        const peerValue = el(doc, 'span', 'with-copy');
        const shortValue = el(doc, 'span', 'mono', shortPeerId(result.peerId));
        shortValue.title = result.peerId;
        peerValue.append(shortValue, copyChip(doc, () => result.peerId));
        rows.append(row(doc, 'Peer ID', peerValue));
        // SEC-039: a $PNM signs the content's CID and, separately, the
        // timestamp; the date can be spliced from another notice by the same
        // signer, and FILE_NAME is not signed at all. Both are shown as
        // claims, never as part of what was signed.
        if (result.signedAt) {
          const when = el(doc, 'span');
          when.append(doc.createTextNode(`${localDateTime(result.signedAt)} `));
          when.append(el(
            doc,
            'span',
            result.timestampValid === false ? 'alert-text' : 'muted-inline',
            result.timestampValid === false
              ? '(date signature not valid)'
              : '(claimed: the date is signed separately from the content)',
          ));
          rows.append(row(doc, 'Date', when));
        }
        if (result.fileName) {
          rows.append(row(doc, 'File name (not signed)', safeFileName(result.fileName)));
        }
        if (Number.isFinite(result.size)) {
          rows.append(row(doc, 'Size', formatBytes(result.size)));
        }
        children.push(rows);
      }
      if (valid && result.kind === 'rec' && result.payload instanceof Uint8Array) {
        const text = utf8Text(result.payload);
        if (text !== null) children.push(codeBlock(doc, { label: 'Content', value: text }).block);
        const save = button(doc, 'Save original file');
        save.addEventListener('click', () => ctx.download(
          result.payload,
          safeFileName(result.fileName, 'original'),
          'application/octet-stream',
        ));
        children.push(actions(doc, save));
        if (result.fileName) {
          children.push(muted(doc, 'The file name is not part of what was signed. Check it before you open the saved file.'));
        }
      }
      showResult(area, children);
    }

    async function verifyBytes(bytes, name, original = null) {
      const env = await envelopes();
      if (stale(token)) return null;
      void name;
      return env.verifyInput(ctx.wasm(), bytes, original ? { original } : {});
    }

    async function onFirst(file) {
      area.hidden = true;
      encNote.hidden = true;
      secondHolder.replaceChildren();
      try {
        const bytes = await fileBytes(file);
        if (stale(token)) return;
        const result = await verifyBytes(bytes, file.name);
        if (!result || stale(token)) return;
        if (result.kind === 'enc') {
          encNote.replaceChildren(doc.createTextNode('This file is encrypted. Open it in Decrypt. '));
          const go = button(doc, 'Decrypt', { variant: 'link' });
          go.addEventListener('click', () => {
            carriedFile = file;
            setMode('decrypt');
            chips.get('decrypt')?.focus?.();
          });
          encNote.append(go);
          encNote.hidden = false;
          return;
        }
        if (result.kind === 'pnm' && result.needsOriginal) {
          const second = dropZone(doc, 'Now add the original file', async (originalFile) => {
            try {
              const original = await fileBytes(originalFile);
              if (stale(token)) return;
              const checked = await verifyBytes(bytes, file.name, original);
              if (!checked || stale(token)) return;
              renderVerification({ ...checked, fileName: checked.fileName || originalFile.name, size: checked.size ?? original.length });
            } catch (error) {
              if (!stale(token)) errorResult(area, 'Not valid', error instanceof RangeError ? TOO_LARGE : verifyReasonText(error?.code ?? error?.reason ?? error?.message));
            }
          });
          secondHolder.replaceChildren(second.zone);
          return;
        }
        renderVerification(result);
      } catch (error) {
        if (stale(token)) return;
        errorResult(area, 'Not valid', error instanceof RangeError ? TOO_LARGE : verifyReasonText(error?.code ?? error?.reason ?? 'not-signed'));
      }
    }

    const first = dropZone(doc, 'Drop a signed file (.rec) or a signature (.pnm)', onFirst);
    return { nodes: [first.zone, secondHolder, encNote, area], onFile: onFirst };
  }

  // ---- Encrypt --------------------------------------------------------------
  function renderEncrypt(intent) {
    const token = generation;
    const recipients = () => contacts()
      .filter((entry) => entry.encryptionKey)
      .sort((a, b) => (a.name || a.peerId).localeCompare(b.name || b.peerId));
    const toSelect = select(doc, [], '');
    function fillRecipients(selected) {
      const options = [{ value: 'self', label: 'Myself' }];
      for (const contact of recipients()) options.push({ value: `contact:${contact.peerId}`, label: contact.name || shortPeerId(contact.peerId) });
      options.push({ value: 'other', label: 'Someone else…' });
      toSelect.replaceChildren(...options.map((option) => {
        const node = el(doc, 'option', null, option.label);
        node.value = option.value;
        return node;
      }));
      toSelect.value = options.some((option) => option.value === selected) ? selected : 'self';
    }
    const otherInput = input(doc, { placeholder: '64 hex characters, or drop their contact card (.epm)' });
    const otherField = field(doc, 'Their encryption key', otherInput);
    const otherError = el(doc, 'p', 'field-error');
    otherError.hidden = true;
    otherField.append(otherError);
    otherField.hidden = true;

    const encryptButton = button(doc, 'Encrypt', { variant: 'primary' });
    const block = inputBlock(() => { encryptButton.disabled = !hasInput(); });
    const signBox = el(doc, 'input');
    signBox.type = 'checkbox';
    signBox.checked = true;
    const signLabel = el(doc, 'label', 'check');
    signLabel.append(signBox, doc.createTextNode(` Sign it as ${myName()}`));
    const area = resultArea();

    function showOther() {
      otherField.hidden = toSelect.value !== 'other';
      otherError.hidden = true;
    }

    function selectContact(peerId) {
      fillRecipients(`contact:${peerId}`);
      showOther();
    }

    toSelect.addEventListener('change', showOther);
    otherInput.addEventListener('input', () => {
      const classified = classifyRecipientInput(otherInput.value, contacts());
      if (classified.kind === 'contact') {
        otherInput.value = '';
        selectContact(classified.contact.peerId);
        return;
      }
      otherError.hidden = classified.kind !== 'error';
      otherError.textContent = classified.kind === 'error' ? classified.message : '';
    });
    otherField.addEventListener('dragover', (event) => { event.preventDefault?.(); event.stopPropagation?.(); });
    otherField.addEventListener('drop', async (event) => {
      event.preventDefault?.();
      event.stopPropagation?.();
      const file = event.dataTransfer?.files?.[0];
      if (!file) return;
      try {
        const contact = await ctx.contacts.importFile(file);
        if (stale(token)) return;
        if (contact?.encryptionKey) selectContact(contact.peerId);
        else {
          otherError.textContent = 'This contact card has no encryption key.';
          otherError.hidden = false;
        }
      } catch (error) {
        if (stale(token)) return;
        otherError.textContent = error?.message || 'This is not an SDS contact card (.epm).';
        otherError.hidden = false;
      }
    });

    function recipient() {
      const value = toSelect.value;
      const me = identity();
      if (value === 'self') return { key: me.xPub, label: 'yourself', self: true };
      if (value.startsWith('contact:')) {
        const contact = contactByPeerId(value.slice('contact:'.length));
        if (!contact?.encryptionKey) return null;
        return { key: hexToBytes(contact.encryptionKey), label: contact.name || shortPeerId(contact.peerId), self: false };
      }
      const classified = classifyRecipientInput(otherInput.value, contacts());
      if (classified.kind === 'key') return { key: hexToBytes(classified.key), label: shortKey(classified.key), self: false };
      if (classified.kind === 'contact') {
        return { key: hexToBytes(classified.contact.encryptionKey), label: classified.contact.name || shortPeerId(classified.contact.peerId), self: false };
      }
      otherError.textContent = classified.kind === 'error' ? classified.message : 'Enter their encryption key.';
      otherError.hidden = false;
      return null;
    }

    encryptButton.addEventListener('click', async () => {
      const to = recipient();
      if (!to) return;
      setBusy(encryptButton, true, 'Encrypting…');
      try {
        const composed = await readComposed();
        if (stale(token)) return;
        const env = await envelopes();
        if (stale(token)) return;
        const wasm = ctx.wasm();
        const options = {
          content: composed.content,
          name: composed.name,
          mediaType: composed.mediaType,
          modifiedAtMs: composed.modifiedAt,
          recipientPublicKey: to.key,
        };
        const sealed = signBox.checked
          ? await ctx.keys.withEdKey((signingKey) => env.encryptContent(wasm, { ...options, signingKey }))
          : await env.encryptContent(wasm, options);
        const bytes = sealed instanceof Uint8Array ? sealed : sealed?.bytes;
        if (stale(token)) return;
        if (!(bytes instanceof Uint8Array)) throw new Error('The message could not be encrypted.');
        const save = button(doc, `Download ${composed.name}.enc`, { variant: 'primary' });
        save.addEventListener('click', () => ctx.download(bytes, `${composed.name}.enc`, 'application/octet-stream'));
        showResult(area, [
          statusLine(doc, `Encrypted for ${to.label}`),
          actions(doc, save),
          muted(doc, to.self ? 'Only you can open it.' : 'Only they can open it. Send the file any way you like.'),
        ]);
      } catch (error) {
        if (stale(token)) return;
        if (error instanceof RangeError) block.showError(TOO_LARGE);
        else errorResult(area, 'Not encrypted', error?.message || 'The message could not be encrypted.');
      } finally {
        if (!stale(token)) {
          setBusy(encryptButton, false);
          encryptButton.disabled = !hasInput();
        }
      }
    });

    fillRecipients(intent?.peerId ? `contact:${intent.peerId}` : 'self');
    showOther();
    encryptButton.disabled = !hasInput();
    return {
      nodes: [field(doc, 'To', toSelect), otherField, block.wrap, signLabel, actions(doc, encryptButton), area],
      onFile: block.setFile,
    };
  }

  // ---- Decrypt --------------------------------------------------------------
  function renderDecrypt() {
    const token = generation;
    const area = resultArea();

    function signatureLine(signature) {
      if (!signature) return muted(doc, 'Not signed');
      if (signature.valid) {
        const peerId = signature.signer?.peerId ?? signature.peerId ?? '';
        const contact = contactByPeerId(peerId);
        let name = contact?.name || 'Unknown signer';
        if (!contact && peerId === identity()?.peerId) name = ctx.profile.get()?.name?.trim() || 'You';
        // Name, peer ID and verdict are separate elements, so a contact named
        // "Bob · 12D3KooW… · Valid signature" can't pass as the verdict.
        const line = el(doc, 'p', 'signature-line');
        const peer = el(doc, 'span', 'mono', shortPeerId(peerId));
        peer.title = peerId;
        line.append(
          doc.createTextNode('Signed by '),
          el(doc, 'span', 'signer-name', name),
          doc.createTextNode(' · '),
          peer,
          doc.createTextNode(' · '),
          el(doc, 'span', 'signature-verdict', 'Valid signature'),
        );
        announce(doc, `Signed by ${name}. Valid signature`);
        // SEC-071: the signature covers the content, not the recipient, so a
        // signed file sealed to you may have been forwarded by someone else.
        const wrap = el(doc, 'div', 'signature-block');
        wrap.append(line, muted(doc, 'The signature covers the content, not who it was sent to: it may have been forwarded to you by someone else.'));
        return wrap;
      }
      return statusLine(doc, 'Signature not valid', verifyReasonText(signature.reason), { error: true });
    }

    async function onFile(file) {
      area.hidden = true;
      try {
        const bytes = await fileBytes(file);
        if (stale(token)) return;
        const env = await envelopes();
        if (stale(token)) return;
        const wasm = ctx.wasm();
        const result = await ctx.keys.withXKey((encryptionKey) => env.decryptFile(wasm, bytes, {
          encryptionKey,
          fileName: file.name,
        }));
        if (stale(token)) return;
        if (!result || result.ok === false) {
          errorResult(area, 'Not decrypted', decryptErrorText({ code: result?.error, message: result?.message }));
          return;
        }
        if (result.isFileRecord === false) {
          const plain = result.bytes instanceof Uint8Array ? result.bytes : new Uint8Array(0);
          const plainName = safeFileName(result.saveName || String(file.name || 'decrypted').replace(/\.enc$/iu, ''), 'decrypted');
          const save = button(doc, 'Save decrypted bytes', { variant: 'primary' });
          save.addEventListener('click', () => ctx.download(plain, plainName, 'application/octet-stream'));
          showResult(area, [statusLine(doc, 'Decrypted (not a file record)'), signatureLine(result.signature), actions(doc, save)]);
          return;
        }
        const record = result.file ?? {};
        const content = record.content instanceof Uint8Array ? record.content : new Uint8Array(0);
        const name = safeFileName(record.name, 'decrypted');
        const mediaType = record.mediaType || 'application/octet-stream';
        const rows = el(doc, 'div', 'rows');
        rows.append(
          row(doc, 'File', name),
          row(doc, 'Type', mediaType),
          row(doc, 'Size', formatBytes(Number.isFinite(record.size) ? record.size : content.length)),
        );
        const children = [statusLine(doc, 'Decrypted'), signatureLine(result.signature), rows];
        if (/^text\//iu.test(mediaType)) {
          const text = utf8Text(content);
          if (text !== null) children.push(codeBlock(doc, { label: 'Content', value: text }).block);
        }
        const save = button(doc, `Save ${name}`, { variant: 'primary' });
        // The media type is the sender's claim: save as plain bytes whatever it says.
        save.addEventListener('click', () => ctx.download(content, name, 'application/octet-stream'));
        children.push(actions(doc, save));
        showResult(area, children);
      } catch (error) {
        if (stale(token)) return;
        errorResult(area, 'Not decrypted', error instanceof RangeError ? TOO_LARGE : decryptErrorText(error));
      }
    }

    const zone = dropZone(doc, 'Drop an encrypted file (.enc)', onFile);
    if (carriedFile) {
      const file = carriedFile;
      carriedFile = null;
      Promise.resolve().then(() => onFile(file));
    }
    return { nodes: [zone.zone, area], onFile };
  }

  // ---- shell ----------------------------------------------------------------
  let current = null;

  function setMode(next, intent = null) {
    if (next === 'encrypt' || next === 'sign') {
      if (!(mode === 'sign' || mode === 'encrypt')) {
        composedText = '';
        composedFile = null;
      }
    }
    mode = next;
    generation += 1;
    liveResult = null;
    setPressed([...chips.values()], chips.get(mode));
    const renderer = { sign: renderSign, verify: renderVerify, encrypt: renderEncrypt, decrypt: renderDecrypt }[mode];
    current = renderer(intent);
    bodyEl.replaceChildren(...current.nodes);
  }

  function renderDetails() {
    const me = identity();
    const account = session().account;
    const table = el(doc, 'div', 'format-table');
    table.append(
      row(doc, '.rec', 'The content, then $REC{$PNM}, then the trailer.'),
      row(doc, '.pnm', 'A size-prefixed $PNM over the CID of the content.'),
      row(doc, '.enc', 'AES-256-GCM ciphertext plus $REC{$ENC}; the plaintext is a $FIL, signed inside when "Sign it" is on.'),
    );
    return details(doc, [
      codeBlock(doc, { label: `Ed25519 · ${signingKeyPath(account)}`, value: me ? toHex(me.edPub) : '' }).block,
      codeBlock(doc, { label: `X25519 · ${encryptionKeyPath(account)}`, value: me ? toHex(me.xPub) : '' }).block,
      table,
    ]).node;
  }

  function render(intent = null) {
    generation += 1;
    const { head } = paneHead(doc, {
      eyebrow: 'Messages',
      title: 'Sign and encrypt',
      lede: 'Sign, verify, encrypt and decrypt messages and files with your SDN identity. Every output is a Space Data Standards file.',
    });
    const wrap = el(doc, 'div', 'pane');
    wrap.append(head);
    if (session().kind !== 'seed' || !identity()) {
      wrap.append(muted(doc, SEED_ONLY));
      swapPane(panel, wrap);
      return;
    }
    const chipRow = el(doc, 'div', 'chips');
    chipRow.setAttribute('role', 'group');
    chipRow.setAttribute('aria-label', 'Mode');
    chips.clear();
    for (const [id, label] of [['sign', 'Sign'], ['verify', 'Verify'], ['encrypt', 'Encrypt'], ['decrypt', 'Decrypt']]) {
      const node = chip(doc, label, id === mode);
      node.setAttribute('data-focus-key', `mode:${id}`);
      node.addEventListener('click', () => setMode(id));
      chips.set(id, node);
      chipRow.append(node);
    }
    bodyEl = el(doc, 'div', 'mode-body');
    detailsEl = renderDetails();
    wrap.append(chipRow, bodyEl, detailsEl);
    swapPane(panel, wrap);
    setMode(intent?.mode ?? mode, intent);
  }

  // Dropping a file anywhere on the pane feeds the current mode.
  panel.addEventListener('dragover', (event) => {
    if (session().kind === 'seed') event.preventDefault?.();
  });
  panel.addEventListener('drop', (event) => {
    if (session().kind !== 'seed' || !current) return;
    event.preventDefault?.();
    const file = event.dataTransfer?.files?.[0];
    if (file) current.onFile(file);
  });

  return Object.freeze({
    render,
    show(intent) {
      if (intent?.mode) mode = intent.mode;
      render(intent);
    },
    reset() {
      // Leaving the pane drops results and composed input; nothing lingers.
      generation += 1;
      mode = 'sign';
      composedText = '';
      composedFile = null;
      carriedFile = null;
      liveResult = null;
      current = null;
      panel.replaceChildren();
    },
    get mode() { return mode; },
    get hasResult() { return liveResult !== null; },
  });
}
