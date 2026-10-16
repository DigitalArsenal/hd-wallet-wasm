export async function safeCopyText(value) {
  const text = String(value ?? '');
  if (!text) return false;

  try {
    const writeText = globalThis.navigator?.clipboard?.writeText;
    if (typeof writeText === 'function') {
      await writeText.call(globalThis.navigator.clipboard, text);
      return true;
    }
  } catch {
    // Fall through to the legacy DOM copy path below.
  }

  return fallbackCopyText(text);
}

function fallbackCopyText(text) {
  const doc = globalThis.document;
  if (!doc?.body || typeof doc.createElement !== 'function' || typeof doc.execCommand !== 'function') {
    return false;
  }

  const textarea = doc.createElement('textarea');
  textarea.value = text;
  textarea.readOnly = true;
  textarea.setAttribute('aria-hidden', 'true');
  textarea.style.position = 'fixed';
  textarea.style.left = '-9999px';
  textarea.style.top = '0';
  textarea.style.opacity = '0';

  doc.body.appendChild(textarea);
  try {
    textarea.focus();
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    return Boolean(doc.execCommand('copy'));
  } catch {
    return false;
  } finally {
    textarea.remove();
  }
}

// ---------------------------------------------------------------------------
// Secrets (SEC-081). A copied private key is overwritten on the clipboard
// after SECRET_CLIPBOARD_MS. The page cannot read the clipboard without a
// permission prompt, so it does not check what is there: it overwrites it.
// When the page is not focused the browser refuses the write; it is retried
// the next time the window gets focus. Signing out clears it at once.
// Clipboard history and clipboard sync (OS or browser) may still keep a copy;
// the UI says so.
// ---------------------------------------------------------------------------

export const SECRET_CLIPBOARD_MS = 30 * 1000;

let pendingSecretClear = null;

function cancelPendingSecretClear() {
  if (!pendingSecretClear) return;
  const { timer, clearTimer, win, onFocus } = pendingSecretClear;
  try { clearTimer(timer); } catch { /* gone */ }
  if (onFocus) {
    try { win?.removeEventListener?.('focus', onFocus); } catch { /* gone */ }
  }
  pendingSecretClear = null;
}

async function overwriteClipboard(win) {
  try {
    const clipboard = win?.navigator?.clipboard;
    if (typeof clipboard?.writeText === 'function') {
      await clipboard.writeText('');
      return true;
    }
  } catch {
    // Not focused, or no permission: retried on focus.
  }
  return false;
}

/**
 * Overwrite the clipboard now if a copied secret may still be on it. Returns
 * true when nothing is pending or the overwrite succeeded.
 */
export async function clearSecretClipboard() {
  const pending = pendingSecretClear;
  if (!pending) return true;
  const ok = await overwriteClipboard(pending.win);
  if (ok && pendingSecretClear === pending) cancelPendingSecretClear();
  return ok;
}

/**
 * Copy a secret (an xprv) and schedule the clipboard to be overwritten after
 * `clearAfterMs`. Resolves true when the copy succeeded.
 */
export async function copySecretText(value, {
  clearAfterMs = SECRET_CLIPBOARD_MS,
  setTimer = (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimer = (id) => globalThis.clearTimeout(id),
  win = globalThis,
  copy = safeCopyText,
} = {}) {
  const ok = await copy(value);
  if (!ok) return false;
  cancelPendingSecretClear();
  const pending = { timer: null, clearTimer, win, onFocus: null };
  pendingSecretClear = pending;
  pending.timer = setTimer(async () => {
    if (pendingSecretClear !== pending) return;
    if (await overwriteClipboard(win)) {
      if (pendingSecretClear === pending) cancelPendingSecretClear();
      return;
    }
    if (pendingSecretClear !== pending || typeof win?.addEventListener !== 'function') return;
    pending.onFocus = async () => {
      if (pendingSecretClear !== pending) return;
      if (await overwriteClipboard(win) && pendingSecretClear === pending) cancelPendingSecretClear();
    };
    win.addEventListener('focus', pending.onFocus);
  }, clearAfterMs);
  return true;
}
