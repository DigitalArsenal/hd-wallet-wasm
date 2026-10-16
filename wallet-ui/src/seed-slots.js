/**
 * Seed phrase word slots: the login modal's numbered word fields.
 *
 * The slots are the single place a typed, pasted or generated mnemonic lives.
 * Nothing here logs, stores or mirrors the words anywhere else (no window
 * globals, no storage, no data attributes); `read()` joins the slot values and
 * `clear()` empties them.
 */

/** The BIP-39 mnemonic lengths, in words. */
export const BIP39_WORD_COUNTS = Object.freeze([12, 15, 18, 21, 24]);

/** Slots shown when there is no phrase yet. */
export const DEFAULT_SLOT_COUNT = 24;

const MAX_SLOT_COUNT = BIP39_WORD_COUNTS[BIP39_WORD_COUNTS.length - 1];

/**
 * Split pasted or typed text into lowercase mnemonic words.
 *
 * Whitespace of any kind (spaces, tabs, newlines, ideographic spaces), commas
 * and semicolons separate words; numbered lists ("1. word", "01) word",
 * "#1 word", "1.word") lose their numbering and punctuation.
 *
 * @param {unknown} text
 * @returns {string[]}
 */
export function parseSeedWords(text) {
  return String(text ?? '')
    .toLowerCase()
    .split(/[\s,;]+/u)
    .map((token) => token.replace(/^[^\p{L}]+/u, '').replace(/[^\p{L}]+$/u, ''))
    .filter(Boolean);
}

/**
 * The number of slots to show for a phrase of `wordCount` words: exactly the
 * word count for a BIP-39 length, the default when empty, otherwise the next
 * BIP-39 length up (at most 24).
 *
 * @param {number} wordCount
 * @returns {number}
 */
export function slotCountFor(wordCount) {
  if (!Number.isInteger(wordCount) || wordCount <= 0) return DEFAULT_SLOT_COUNT;
  return BIP39_WORD_COUNTS.find((count) => count >= wordCount) ?? MAX_SLOT_COUNT;
}

function pad2(n) {
  return n < 10 ? `0${n}` : String(n);
}

/**
 * Build the word slots inside `container` and wire their keyboard and paste
 * behaviour.
 *
 * @param {HTMLElement} container
 * A phrase of more than 24 words is never truncated into a shorter valid one:
 * the slots show the first 24 words marked as errors, `overflow` is true (so
 * Login stays disabled) and `onOverflow` fires, until the next edit.
 *
 *
 * The words are masked by default (SEC-081): every slot is a password field,
 * so the phrase is not on screen for shoulder-surfing or screen recording,
 * and mobile keyboards treat it as a password (no learning, no suggestions).
 * `setMasked(false)` shows them (the "Show words" toggle, and Generate, whose
 * new phrase has to be written down).
 *
 * @param {{ document?: Document, onChange?: () => void, onOverflow?: () => void, masked?: boolean }} [options]
 */
export function createSeedSlots(container, options = {}) {
  const doc = options.document || container.ownerDocument || globalThis.document;
  const onChange = typeof options.onChange === 'function' ? options.onChange : () => {};
  const onOverflow = typeof options.onOverflow === 'function' ? options.onOverflow : () => {};
  /** @type {{ slot: HTMLElement, input: HTMLInputElement }[]} */
  let slots = [];
  let overflow = false;
  let masked = options.masked !== false;

  function applyMask(input) {
    input.type = masked ? 'password' : 'text';
  }

  function setMasked(next) {
    masked = Boolean(next);
    for (const { input } of slots) applyMask(input);
    if (masked) container.classList?.add?.('is-masked');
    else container.classList?.remove?.('is-masked');
  }

  function setOverflow(next) {
    overflow = next;
    if (next) container.classList?.add?.('is-overflow');
    else container.classList?.remove?.('is-overflow');
  }

  function notify() {
    onChange();
  }

  function focusSlot(index, caretAtEnd = false) {
    const entry = slots[index];
    if (!entry) return;
    entry.input.focus();
    if (caretAtEnd && typeof entry.input.setSelectionRange === 'function') {
      const end = entry.input.value.length;
      try { entry.input.setSelectionRange(end, end); } catch { /* not a text input */ }
    }
  }

  function clearMarks() {
    for (const { slot } of slots) slot.classList.remove('is-invalid');
  }

  /** Fill slots from `start` with `words`; returns the index after the last word written. */
  function fillFrom(start, words) {
    let index = start;
    for (const word of words) {
      if (index >= slots.length) break;
      slots[index].input.value = word;
      index += 1;
    }
    return index;
  }

  function handlePaste(event) {
    const data = event.clipboardData;
    // Without clipboard access the browser pastes into the field and the
    // input handler spreads the words.
    if (!data || typeof data.getData !== 'function') return;
    const words = parseSeedWords(data.getData('text/plain') || data.getData('text'));
    event.preventDefault();
    if (words.length === 0) return;
    if (words.length === 1) {
      // One word belongs to the field it was pasted into.
      const index = slots.findIndex(({ input }) => input === event.currentTarget);
      if (index >= 0) {
        if (overflow) {
          setOverflow(false);
          clearMarks();
        }
        slots[index].input.value = words[0];
        slots[index].slot.classList.remove('is-invalid');
        notify();
      }
      return;
    }
    setWords(words);
    const next = Math.min(words.length, slots.length) - 1;
    focusSlot(next, true);
  }

  function handleInput(index) {
    const { input, slot } = slots[index];
    slot.classList.remove('is-invalid');
    if (overflow) {
      setOverflow(false);
      clearMarks();
    }
    const raw = input.value;
    const lower = raw.toLowerCase();
    if (/\s/u.test(lower)) {
      // A space or a multi-word entry (mobile keyboards, autocomplete): spread
      // the words from this slot on and move past the last one.
      const words = parseSeedWords(lower);
      input.value = words[0] || '';
      const after = fillFrom(index + 1, words.slice(1));
      let target = index;
      if (words.length > 0) target = /\s$/u.test(lower) ? after : after - 1;
      if (target !== index) focusSlot(Math.min(target, slots.length - 1), true);
    } else if (lower !== raw) {
      input.value = lower;
    }
    // With every slot empty again the grid returns to its 24-slot default.
    if (slots.length !== DEFAULT_SLOT_COUNT && slots.every(({ input: field }) => !String(field.value || '').trim())) {
      setCount(DEFAULT_SLOT_COUNT);
    }
    notify();
  }

  function handleKeydown(index, event) {
    const { input } = slots[index];
    if (event.isComposing) return;
    if (event.key === ' ' || event.key === 'Spacebar') {
      event.preventDefault();
      if (input.value.trim()) focusSlot(index + 1);
      return;
    }
    if (event.key === 'Backspace' && input.value === '' && index > 0) {
      event.preventDefault();
      focusSlot(index - 1, true);
    }
  }

  function buildSlot(index) {
    const slot = doc.createElement('label');
    slot.className = 'seed-slot';
    const number = doc.createElement('span');
    number.className = 'seed-slot-index';
    number.textContent = pad2(index + 1);
    number.setAttribute('aria-hidden', 'true');
    const input = doc.createElement('input');
    applyMask(input);
    input.className = 'seed-slot-input';
    input.setAttribute('autocomplete', 'off');
    // Password managers must not offer to save a seed word as a password.
    input.setAttribute('data-1p-ignore', '');
    input.setAttribute('data-lpignore', 'true');
    input.setAttribute('data-bwignore', '');
    input.setAttribute('data-form-type', 'other');
    input.setAttribute('autocapitalize', 'off');
    input.setAttribute('autocorrect', 'off');
    input.setAttribute('spellcheck', 'false');
    input.spellcheck = false;
    input.setAttribute('aria-label', `Word ${index + 1}`);
    input.addEventListener('paste', handlePaste);
    input.addEventListener('input', () => handleInput(index));
    input.addEventListener('keydown', (event) => handleKeydown(index, event));
    slot.append(number, input);
    return { slot, input };
  }

  /** Show `count` slots, keeping the words already in the slots that remain. */
  function setCount(count) {
    const target = Math.max(1, Math.min(MAX_SLOT_COUNT, Math.trunc(count) || DEFAULT_SLOT_COUNT));
    if (target === slots.length) return;
    if (target < slots.length) {
      for (const { input } of slots.slice(target)) input.value = '';
      slots = slots.slice(0, target);
    } else {
      for (let index = slots.length; index < target; index += 1) slots.push(buildSlot(index));
    }
    container.replaceChildren(...slots.map(({ slot }) => slot));
  }

  /** Replace every slot's word with `words`, resizing to the phrase's length. */
  function setWords(words) {
    const list = Array.isArray(words) ? words.flatMap((word) => parseSeedWords(word)) : parseSeedWords(words);
    setCount(slotCountFor(list.length));
    clearMarks();
    for (const { input } of slots) input.value = '';
    fillFrom(0, list);
    const tooLong = list.length > MAX_SLOT_COUNT;
    setOverflow(tooLong);
    if (tooLong) {
      for (const { slot } of slots) slot.classList.add('is-invalid');
    }
    notify();
    if (tooLong) onOverflow();
  }

  /** The phrase in the slots: their words, lowercase, joined by single spaces. */
  function read() {
    return slots
      .map(({ input }) => String(input.value || '').trim().toLowerCase())
      .filter(Boolean)
      .join(' ');
  }

  /** Empty every slot and return to the default slot count. */
  function clear() {
    for (const { input } of slots) input.value = '';
    clearMarks();
    setOverflow(false);
    setCount(DEFAULT_SLOT_COUNT);
    setMasked(true);
  }

  /**
   * Mark the slots whose word `isBad(word, index)` rejects, and the empty
   * slots before the last filled one. Returns how many were marked.
   */
  function markInvalid(isBad) {
    clearMarks();
    const values = slots.map(({ input }) => String(input.value || '').trim().toLowerCase());
    let last = -1;
    values.forEach((value, index) => { if (value) last = index; });
    let marked = 0;
    values.forEach((value, index) => {
      const bad = value ? Boolean(isBad?.(value, index)) : index < last;
      if (bad) {
        slots[index].slot.classList.add('is-invalid');
        marked += 1;
      }
    });
    return marked;
  }

  setCount(DEFAULT_SLOT_COUNT);
  setMasked(masked);

  return {
    clear,
    clearMarks,
    focus: focusSlot,
    markInvalid,
    read,
    setCount,
    setMasked,
    setWords,
    /** True while the words are hidden (password fields). */
    get masked() { return masked; },
    get count() { return slots.length; },
    /** True after a paste of more than 24 words, until the next edit. */
    get overflow() { return overflow; },
    get inputs() { return slots.map(({ input }) => input); },
  };
}

const flashTimers = new WeakMap();

function prefersReducedMotion() {
  try {
    return Boolean(globalThis.matchMedia?.('(prefers-reduced-motion: reduce)')?.matches);
  } catch {
    return false;
  }
}

/**
 * Flash a button's result ("Validated" / "Error") and fade back.
 *
 * The button gets `is-ok` or `is-error` for `holdMs`, then `is-settling`
 * while its colour transitions back (CSS owns the fade; with
 * prefers-reduced-motion there is no fade and the label returns at once),
 * then its original label. A new flash cancels the
 * previous cycle.
 *
 * @param {HTMLButtonElement} button
 * @param {{ ok: boolean, okText?: string, errorText?: string, holdMs?: number, fadeMs?: number, setTimer?: Function, clearTimer?: Function }} options
 */
export function flashResult(button, options) {
  if (!button) return;
  const setTimer = options.setTimer || globalThis.setTimeout.bind(globalThis);
  const clearTimer = options.clearTimer || globalThis.clearTimeout.bind(globalThis);
  const holdMs = options.holdMs ?? 1200;
  const fadeMs = options.fadeMs ?? (prefersReducedMotion() ? 0 : 600);
  const timers = flashTimers.get(button);
  if (timers) {
    for (const timer of timers.ids) clearTimer(timer);
  }
  const label = timers ? timers.label : button.textContent;
  button.classList.remove('is-ok', 'is-error', 'is-settling');
  button.classList.add(options.ok ? 'is-ok' : 'is-error');
  button.textContent = options.ok ? (options.okText || 'Validated') : (options.errorText || 'Error');
  const state = { label, ids: [] };
  flashTimers.set(button, state);
  const settle = () => {
    button.classList.remove('is-settling');
    button.textContent = label;
    flashTimers.delete(button);
  };
  state.ids.push(setTimer(() => {
    button.classList.remove('is-ok', 'is-error');
    if (fadeMs <= 0) {
      settle();
      return;
    }
    button.classList.add('is-settling');
    state.ids.push(setTimer(settle, fadeMs));
  }, holdMs));
}
