/**
 * Small DOM builders for the account view's panes.
 *
 * Every node is made with createElement and every string goes in through
 * textContent; there are no markup sinks here (test/dom-security.test.mjs).
 * The builders produce the SDN pane grammar of the 3.0 design: pane heads,
 * hairline rows, `.code` blocks with a Copy chip, pill buttons, status words.
 */

import { SECRET_CLIPBOARD_MS, copySecretText, safeCopyText } from './clipboard.js';

export function el(doc, tag, className, text) {
  const node = doc.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

/**
 * A button. `variant`: 'primary' | 'secondary' (default) | 'link' | 'danger-link' |
 * 'danger'. `small`: the 14px pill.
 */
export function button(doc, label, { variant = 'secondary', small = false, className = '' } = {}) {
  let classes;
  if (variant === 'link') classes = 'link-btn';
  else if (variant === 'danger-link') classes = 'link-btn danger';
  else {
    classes = 'btn';
    if (variant === 'primary') classes += ' btn-primary';
    if (variant === 'danger') classes += ' btn-danger';
    if (small) classes += ' btn-sm';
  }
  const node = el(doc, 'button', className ? `${classes} ${className}` : classes, label);
  node.type = 'button';
  return node;
}

export function actions(doc, ...buttons) {
  const row = el(doc, 'div', 'actions');
  row.append(...buttons.filter(Boolean));
  return row;
}

/** The pane head: eyebrow, title (focus target after a switch) and lede. */
export function paneHead(doc, { eyebrow, title, lede }) {
  const head = el(doc, 'header', 'pane-head');
  const eyebrowEl = el(doc, 'p', 'eyebrow', eyebrow);
  const titleEl = el(doc, 'h2', 'pane-title', title);
  titleEl.tabIndex = -1;
  const ledeEl = el(doc, 'p', 'lede', lede);
  head.append(eyebrowEl, titleEl, ledeEl);
  return { head, titleEl, ledeEl };
}

/** A hairline row: 13px label, 15px value (13px mono for machine values). */
export function row(doc, label, value, { mono = false, title = '' } = {}) {
  const node = el(doc, 'div', 'row');
  const labelEl = el(doc, 'span', 'row-label', label);
  let valueEl;
  if (value && typeof value === 'object' && 'nodeType' in value) {
    valueEl = el(doc, 'span', mono ? 'row-value mono' : 'row-value');
    valueEl.append(value);
  } else {
    valueEl = el(doc, 'span', mono ? 'row-value mono' : 'row-value', value ?? '');
  }
  if (title) valueEl.title = title;
  node.append(labelEl, valueEl);
  return node;
}

const copyTimers = new WeakMap();

/**
 * Copy text and show "Copied" on the chip for 1.5 s. With `secret`, the copy
 * goes through copySecretText (the clipboard is overwritten after 30 s) and
 * the announcement says so.
 */
export function wireCopy(chip, getText, {
  secret = false,
  copy = secret ? copySecretText : safeCopyText,
  setTimer = (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimer = (id) => globalThis.clearTimeout(id),
} = {}) {
  const label = chip.textContent || 'Copy';
  const copiedMessage = secret
    ? `Copied. The clipboard is cleared in ${Math.round(SECRET_CLIPBOARD_MS / 1000)} seconds.`
    : 'Copied';
  chip.addEventListener('click', async (event) => {
    event?.stopPropagation?.();
    const text = typeof getText === 'function' ? getText() : getText;
    if (!text) return;
    const ok = await copy(String(text));
    if (!ok) return;
    const previous = copyTimers.get(chip);
    if (previous) clearTimer(previous);
    chip.textContent = 'Copied';
    announce(chip.ownerDocument, copiedMessage);
    copyTimers.set(chip, setTimer(() => {
      chip.textContent = label;
      copyTimers.delete(chip);
    }, 1500));
  });
  return chip;
}

/** A Copy chip. `what` names the value for screen readers ("Copy peer ID"). */
export function copyChip(doc, getText, options = {}) {
  const chip = el(doc, 'button', 'copy', 'Copy');
  chip.type = 'button';
  if (options.what) chip.setAttribute('aria-label', `Copy ${options.what}`);
  return wireCopy(chip, getText, options);
}

/**
 * The SDN `.code` block: a label, a Copy chip and the value in a <pre>.
 * `copyOptions` go to the chip (`{ secret: true }` for a private key).
 */
export function codeBlock(doc, { label, value, copy = true, className = '', copyOptions = {} }) {
  const block = el(doc, 'div', className ? `code ${className}` : 'code');
  const labelEl = el(doc, 'span', 'label', label);
  const pre = el(doc, 'pre', null, value ?? '');
  block.append(labelEl);
  if (copy) block.append(copyChip(doc, () => pre.textContent, { what: label, ...copyOptions }));
  block.append(pre);
  return { block, pre };
}

// ---------------------------------------------------------------------------
// Announcements. The account view has one polite live region
// (#account-live, in template.js); every status line is read out through it.
// Lines made in the same task are joined, so "Decrypted" and the signature
// line after it are announced together.
// ---------------------------------------------------------------------------

const pendingAnnouncements = new WeakMap();

export function announce(doc, text) {
  const message = String(text ?? '').trim();
  if (!doc || !message) return;
  const region = doc.getElementById?.('account-live');
  if (!region) return;
  let queue = pendingAnnouncements.get(doc);
  if (!queue) {
    queue = [];
    pendingAnnouncements.set(doc, queue);
    const flush = () => {
      pendingAnnouncements.delete(doc);
      // Clearing first makes a repeated message ("Copied", "Signed") speak again.
      region.textContent = '';
      region.textContent = queue.join('. ');
    };
    if (typeof globalThis.queueMicrotask === 'function') globalThis.queueMicrotask(flush);
    else Promise.resolve().then(flush);
  }
  queue.push(message);
}

// ---------------------------------------------------------------------------
// Focus across re-renders. Panes rebuild their DOM on interaction; controls
// that should keep focus carry data-focus-key, and swapPane() puts focus back
// on the control with the same key (or on a requested one, or on the pane
// title) when focus was inside the pane before the swap.
// ---------------------------------------------------------------------------

const requestedFocus = new WeakMap();

/** Tag a control so focus can find it again after the pane re-renders. */
export function focusKey(node, key) {
  if (node && key) node.setAttribute('data-focus-key', key);
  return node;
}

/** Ask the next swapPane() on this panel to focus the control with `key`. */
export function requestFocus(panel, key) {
  if (panel && key) requestedFocus.set(panel, key);
}

function isVisible(node, root) {
  for (let n = node; n && n !== root; n = n.parentNode) if (n.hidden) return false;
  return true;
}

/** Replace a pane's content, keeping keyboard focus where the user was. */
export function swapPane(panel, content) {
  const doc = panel.ownerDocument;
  const active = doc?.activeElement;
  const inside = Boolean(active && active !== doc.body && panel.contains(active));
  const requested = requestedFocus.get(panel) ?? null;
  requestedFocus.delete(panel);
  const key = requested ?? (inside ? active.getAttribute?.('data-focus-key') : null);
  panel.replaceChildren(content);
  if (!inside && !requested) return;
  if (panel.hidden) return;
  let target = null;
  if (key) {
    for (const node of panel.querySelectorAll('[data-focus-key]')) {
      if (node.getAttribute('data-focus-key') === key && !node.disabled && isVisible(node, panel)) {
        target = node;
        break;
      }
    }
  }
  target ??= panel.querySelector('.pane-title');
  try { target?.focus?.({ preventScroll: !key }); } catch { /* not focusable */ }
}

/** `● word`: an 8px dot plus a word (accent, or alert for errors). */
export function status(doc, word, { error = false } = {}) {
  return el(doc, 'span', error ? 'status error' : 'status', word);
}

/** A status word with an optional message after it. */
export function statusLine(doc, word, message = '', { error = false, speak = true } = {}) {
  const line = el(doc, 'p', error ? 'status-line is-error' : 'status-line');
  line.append(status(doc, word, { error }));
  if (message) line.append(el(doc, 'span', 'status-message', message));
  if (speak) announce(doc, message ? `${word}. ${message}` : word);
  return line;
}

export function muted(doc, text, tag = 'p') {
  return el(doc, tag, 'muted', text);
}

/** `<details class="more"><summary>Details</summary>…` closed by default. */
export function details(doc, children = []) {
  const node = el(doc, 'details', 'more');
  node.append(el(doc, 'summary', null, 'Details'));
  const body = el(doc, 'div', 'more-body');
  body.append(...children.filter(Boolean));
  node.append(body);
  return { node, body };
}

let fieldSequence = 0;

/** A labelled input (13px label above the control). */
export function field(doc, label, control) {
  const wrapper = el(doc, 'div', 'field');
  const id = control.id || `hdw-field-${++fieldSequence}`;
  control.id = id;
  const labelEl = el(doc, 'label', null, label);
  labelEl.htmlFor = id;
  wrapper.append(labelEl, control);
  return wrapper;
}

export function input(doc, { type = 'text', value = '', placeholder = '', autocomplete = 'off' } = {}) {
  const node = el(doc, 'input', 'input');
  node.type = type;
  node.value = value;
  if (placeholder) node.placeholder = placeholder;
  node.setAttribute('autocomplete', autocomplete);
  node.setAttribute('spellcheck', 'false');
  return node;
}

export function select(doc, options, value) {
  const node = el(doc, 'select', 'select');
  for (const option of options) {
    const opt = el(doc, 'option', null, option.label);
    opt.value = option.value;
    node.append(opt);
  }
  if (value !== undefined) node.value = value;
  return node;
}

/** A `.chip` choice button with aria-pressed. */
export function chip(doc, label, pressed = false) {
  const node = el(doc, 'button', 'chip', label);
  node.type = 'button';
  node.setAttribute('aria-pressed', pressed ? 'true' : 'false');
  return node;
}

export function setPressed(chips, active) {
  for (const node of chips) node.setAttribute('aria-pressed', node === active ? 'true' : 'false');
}

/** A hidden file input plus the function that opens it. */
export function filePicker(doc, accept, onFile) {
  const node = el(doc, 'input', 'visually-hidden-file');
  node.type = 'file';
  if (accept) node.accept = accept;
  node.hidden = true;
  node.addEventListener('change', () => {
    const file = node.files && node.files[0];
    node.value = '';
    if (file) onFile(file);
  });
  return { input: node, open: () => node.click() };
}

/**
 * A dashed drop zone: one line of text and a small "Choose file…" button.
 * `onFile(file)` runs as soon as a file is chosen or dropped.
 */
export function dropZone(doc, text, onFile, { accept = '' } = {}) {
  const zone = el(doc, 'div', 'drop-zone');
  const line = el(doc, 'p', 'drop-zone-text', text);
  const picker = filePicker(doc, accept, onFile);
  const choose = button(doc, 'Choose file…', { small: true });
  choose.addEventListener('click', picker.open);
  zone.append(line, choose, picker.input);
  zone.addEventListener('dragover', (event) => {
    event.preventDefault?.();
    zone.classList.add('is-over');
  });
  zone.addEventListener('dragleave', () => zone.classList.remove('is-over'));
  zone.addEventListener('drop', (event) => {
    event.preventDefault?.();
    event.stopPropagation?.();
    zone.classList.remove('is-over');
    const file = event.dataTransfer?.files?.[0];
    if (file) onFile(file);
  });
  return { zone, line };
}

/** Save bytes as a file through a temporary Blob URL. */
export function downloadBytes(doc, bytes, fileName, mimeType = 'application/octet-stream') {
  const BlobCtor = doc.defaultView?.Blob ?? globalThis.Blob;
  const URLCtor = doc.defaultView?.URL ?? globalThis.URL;
  const blob = new BlobCtor([bytes], { type: mimeType });
  const url = URLCtor.createObjectURL(blob);
  const link = doc.createElement('a');
  link.href = url;
  link.download = fileName;
  link.rel = 'noopener';
  link.hidden = true;
  doc.body.append(link);
  try {
    link.click();
  } finally {
    link.remove();
    // Safari starts large downloads late; keep the URL alive for a while.
    setTimeout(() => { try { URLCtor.revokeObjectURL(url); } catch { /* released */ } }, 30_000);
  }
}

export function formatBytes(size) {
  const n = Number(size);
  if (!Number.isFinite(n) || n < 0) return '';
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(n < 10 * 1024 ? 1 : 0)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

/** "just now", "3 minutes ago", "2 hours ago", or a date. */
export function relativeTime(timestamp, now = Date.now()) {
  const t = Number(timestamp);
  if (!Number.isFinite(t) || t <= 0) return '';
  const seconds = Math.max(0, Math.round((now - t) / 1000));
  if (seconds < 45) return 'just now';
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  return new Date(t).toLocaleDateString();
}

/** Disable a button (with an optional busy label) while work runs; restore it after. */
export function setBusy(buttonNode, busy, busyLabel) {
  if (!buttonNode) return;
  if (busy) {
    buttonNode.dataset.label = buttonNode.textContent;
    if (busyLabel) buttonNode.textContent = busyLabel;
    buttonNode.disabled = true;
  } else {
    if (buttonNode.dataset.label) buttonNode.textContent = buttonNode.dataset.label;
    delete buttonNode.dataset.label;
    buttonNode.disabled = false;
  }
}
