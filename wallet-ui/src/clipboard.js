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
