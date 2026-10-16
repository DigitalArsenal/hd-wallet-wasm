import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

import initHDWallet from 'hd-wallet-wasm';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';

import {
  BIP39_WORD_COUNTS,
  DEFAULT_SLOT_COUNT,
  createSeedSlots,
  flashResult,
  parseSeedWords,
  slotCountFor,
} from '../src/seed-slots.js';
import { getModalHTML } from '../src/template.js';

const here = dirname(fileURLToPath(import.meta.url));
const read = (path) => readFileSync(join(here, '..', path), 'utf8');

// The BIP-39 test vectors' all-zero-entropy phrases (public test data).
const TWELVE = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
const TWENTY_FOUR = `${'abandon '.repeat(23)}art`;

// A small DOM: just what seed-slots.js touches.
class FakeElement {
  constructor(tagName, document) {
    this.tagName = tagName.toUpperCase();
    this.ownerDocument = document;
    this.children = [];
    this.attributes = new Map();
    this.listeners = new Map();
    this.className = '';
    this.textContent = '';
    this.value = '';
    this.type = '';
    this.spellcheck = true;
    this.selection = null;
    this.classList = {
      add: (...names) => { this.className = [...new Set([...this.#classes(), ...names])].join(' '); },
      remove: (...names) => { this.className = this.#classes().filter((name) => !names.includes(name)).join(' '); },
      contains: (name) => this.#classes().includes(name),
    };
  }

  #classes() {
    return this.className.split(/\s+/u).filter(Boolean);
  }

  setAttribute(name, value) { this.attributes.set(name, String(value)); }
  getAttribute(name) { return this.attributes.has(name) ? this.attributes.get(name) : null; }
  append(...nodes) { this.children.push(...nodes); }
  replaceChildren(...nodes) { this.children = [...nodes]; }
  focus() { this.ownerDocument.activeElement = this; }
  setSelectionRange(start, end) { this.selection = [start, end]; }

  addEventListener(type, listener) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(listener);
  }

  dispatch(type, init = {}) {
    const event = {
      type,
      currentTarget: this,
      target: this,
      defaultPrevented: false,
      preventDefault() { this.defaultPrevented = true; },
      ...init,
    };
    for (const listener of this.listeners.get(type) || []) listener(event);
    return event;
  }
}

class FakeDocument {
  constructor() { this.activeElement = null; }
  createElement(tagName) { return new FakeElement(tagName, this); }
}

function mountSlots() {
  const document = new FakeDocument();
  const container = document.createElement('div');
  const onChange = vi.fn();
  const onOverflow = vi.fn();
  const slots = createSeedSlots(container, { document, onChange, onOverflow });
  const inputs = () => container.children.map((slot) => slot.children[1]);
  const labels = () => container.children.map((slot) => slot.children[0].textContent);
  const paste = (index, text) => inputs()[index].dispatch('paste', {
    clipboardData: { getData: (type) => (type === 'text/plain' ? text : '') },
  });
  return { document, container, slots, inputs, labels, onChange, onOverflow, paste };
}

describe('parseSeedWords', () => {
  it('splits on any whitespace and lowercases', () => {
    expect(parseSeedWords('  Abandon\tABILITY\n\nable 　 about  ')).toEqual(['abandon', 'ability', 'able', 'about']);
  });

  it('strips list numbering and punctuation', () => {
    expect(parseSeedWords('1. abandon 2) ability\n03: able\n#4 about 5.above, 6-absent;')).toEqual([
      'abandon', 'ability', 'able', 'about', 'above', 'absent',
    ]);
    expect(parseSeedWords('1.abandon 2.ability')).toEqual(['abandon', 'ability']);
  });

  it('splits on commas and semicolons too', () => {
    expect(parseSeedWords('abandon,ability;able, about ;above')).toEqual(['abandon', 'ability', 'able', 'about', 'above']);
  });

  it('returns nothing for empty or non-word input', () => {
    expect(parseSeedWords('')).toEqual([]);
    expect(parseSeedWords(null)).toEqual([]);
    expect(parseSeedWords(' 1. 2. -- ')).toEqual([]);
  });
});

describe('slotCountFor', () => {
  it('shows exactly the BIP-39 lengths and 24 when empty', () => {
    for (const count of BIP39_WORD_COUNTS) expect(slotCountFor(count)).toBe(count);
    expect(slotCountFor(0)).toBe(DEFAULT_SLOT_COUNT);
    expect(DEFAULT_SLOT_COUNT).toBe(24);
  });

  it('rounds other lengths up to the next BIP-39 length, at most 24', () => {
    expect(slotCountFor(5)).toBe(12);
    expect(slotCountFor(13)).toBe(15);
    expect(slotCountFor(23)).toBe(24);
    expect(slotCountFor(30)).toBe(24);
  });
});

describe('seed word slots', () => {
  it('starts with 24 numbered, non-autocompleting lowercase slots, masked', () => {
    const { slots, inputs, labels } = mountSlots();
    expect(slots.count).toBe(24);
    expect(labels()[0]).toBe('01');
    expect(labels()[23]).toBe('24');
    expect(slots.masked).toBe(true);
    for (const input of inputs()) {
      // SEC-081: password fields, so the words are not on screen and mobile
      // keyboards do not learn them; password managers are told to ignore them.
      expect(input.type).toBe('password');
      expect(input.getAttribute('data-1p-ignore')).toBe('');
      expect(input.getAttribute('data-lpignore')).toBe('true');
      expect(input.getAttribute('data-bwignore')).toBe('');
      expect(input.getAttribute('autocomplete')).toBe('off');
      expect(input.getAttribute('autocapitalize')).toBe('off');
      expect(input.getAttribute('spellcheck')).toBe('false');
      expect(input.spellcheck).toBe(false);
    }
    expect(inputs()[4].getAttribute('aria-label')).toBe('Word 5');
    expect(slots.read()).toBe('');
  });

  it('Show words unmasks every slot, new slots follow the setting, and clear masks again', () => {
    const { slots, inputs, paste } = mountSlots();
    slots.setMasked(false);
    expect(slots.masked).toBe(false);
    expect(inputs().every((input) => input.type === 'text')).toBe(true);
    paste(0, TWELVE);
    slots.setCount(24);
    expect(inputs().every((input) => input.type === 'text')).toBe(true);
    slots.setMasked(true);
    expect(inputs().every((input) => input.type === 'password')).toBe(true);
    // A paste into masked slots still fills them all.
    paste(3, TWELVE);
    expect(slots.read()).toBe(TWELVE);
    slots.setMasked(false);
    slots.clear();
    expect(slots.masked).toBe(true);
    expect(inputs().every((input) => input.type === 'password' && input.value === '')).toBe(true);
  });

  it('a 12-word paste into any slot fills all slots from slot 1 and shows 12', () => {
    const { slots, inputs, paste, onChange, document } = mountSlots();
    const event = paste(6, TWELVE.toUpperCase());
    expect(event.defaultPrevented).toBe(true);
    expect(slots.count).toBe(12);
    expect(inputs().map((input) => input.value)).toEqual(TWELVE.split(' '));
    expect(slots.read()).toBe(TWELVE);
    expect(onChange).toHaveBeenCalled();
    expect(document.activeElement).toBe(inputs()[11]);
  });

  it('a numbered 24-word list with extra whitespace fills 24 slots', () => {
    const { slots, inputs, paste } = mountSlots();
    slots.setWords(TWELVE);
    expect(slots.count).toBe(12);
    const list = TWENTY_FOUR.split(' ').map((word, index) => `${index + 1}.  ${word}`).join('\r\n\n');
    paste(11, `\n\n${list}\n  `);
    expect(slots.count).toBe(24);
    expect(inputs().map((input) => input.value)).toEqual(TWENTY_FOUR.split(' '));
    expect(slots.read()).toBe(TWENTY_FOUR);
  });

  it('a paste of a non-BIP-39 length fills from slot 1 and pads to the next length', () => {
    const { slots, paste, inputs } = mountSlots();
    paste(0, 'abandon ability able about above absent absorb abstract absurd abuse access accident acoustic');
    expect(slots.count).toBe(15);
    expect(inputs()[12].value).toBe('acoustic');
    expect(inputs()[13].value).toBe('');
    expect(slots.read().split(' ')).toHaveLength(13);
  });

  it('a single pasted word stays in the slot it was pasted into', () => {
    const { slots, paste, inputs } = mountSlots();
    slots.setWords(TWELVE);
    const event = paste(3, '  Zoo\n');
    expect(event.defaultPrevented).toBe(true);
    expect(slots.count).toBe(12);
    expect(inputs()[3].value).toBe('zoo');
    expect(inputs()[0].value).toBe('abandon');
  });

  it('typing lowercases, a space moves to the next slot and Backspace on empty moves back', () => {
    const { inputs, document, slots } = mountSlots();
    const [first, second] = inputs();
    first.value = 'ABANDON';
    first.dispatch('input');
    expect(first.value).toBe('abandon');

    const space = first.dispatch('keydown', { key: ' ' });
    expect(space.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(second);

    const back = second.dispatch('keydown', { key: 'Backspace' });
    expect(back.defaultPrevented).toBe(true);
    expect(document.activeElement).toBe(first);

    second.value = 'abi';
    const notEmpty = second.dispatch('keydown', { key: 'Backspace' });
    expect(notEmpty.defaultPrevented).toBe(false);

    // Mobile keyboards insert the space (and autocomplete whole words) as input.
    second.value = 'ability able ';
    second.dispatch('input');
    expect(inputs()[1].value).toBe('ability');
    expect(inputs()[2].value).toBe('able');
    expect(document.activeElement).toBe(inputs()[3]);
    expect(slots.read()).toBe('abandon ability able');
  });

  it('read joins the filled slots by single spaces, and clear empties back to 24', () => {
    const { slots, inputs } = mountSlots();
    inputs()[0].value = '  abandon ';
    inputs()[1].value = 'ABILITY';
    inputs()[5].value = 'able';
    expect(slots.read()).toBe('abandon ability able');
    slots.setWords(TWELVE);
    slots.clear();
    expect(slots.count).toBe(24);
    expect(inputs().every((input) => input.value === '')).toBe(true);
    expect(slots.read()).toBe('');
  });

  it('a paste of more than 24 words is an error, never a truncated phrase', () => {
    const { slots, container, inputs, paste, onOverflow } = mountSlots();
    paste(0, `${TWENTY_FOUR} extra`);
    expect(slots.count).toBe(24);
    expect(slots.overflow).toBe(true);
    expect(onOverflow).toHaveBeenCalledTimes(1);
    expect(container.classList.contains('is-overflow')).toBe(true);
    expect(container.children.every((slot) => slot.classList.contains('is-invalid'))).toBe(true);
    // The next edit clears the error state.
    inputs()[0].value = 'abandon';
    inputs()[0].dispatch('input');
    expect(slots.overflow).toBe(false);
    expect(container.classList.contains('is-overflow')).toBe(false);
    slots.setWords(TWELVE);
    expect(slots.overflow).toBe(false);
  });

  it('returns to 24 slots once every slot is empty again', () => {
    const { slots, inputs, document } = mountSlots();
    slots.setWords(TWELVE);
    expect(slots.count).toBe(12);
    for (const input of inputs()) {
      input.value = '';
      input.dispatch('input');
    }
    expect(slots.count).toBe(24);
    // Clearing a single slot of a full phrase keeps the shorter grid.
    slots.setWords(TWELVE);
    inputs()[3].value = '';
    inputs()[3].focus();
    inputs()[3].dispatch('input');
    expect(slots.count).toBe(12);
    expect(document.activeElement).toBe(inputs()[3]);
  });

  it('marks unknown words and gaps, and clears the mark on edit', () => {
    const { slots, container, inputs } = mountSlots();
    slots.setWords(TWELVE);
    inputs()[2].value = 'notaword';
    inputs()[5].value = '';
    const marked = slots.markInvalid((word) => word === 'notaword');
    const invalid = container.children.map((slot) => slot.classList.contains('is-invalid'));
    expect(marked).toBe(2);
    expect(invalid[2]).toBe(true);
    expect(invalid[5]).toBe(true);
    expect(invalid.filter(Boolean)).toHaveLength(2);
    inputs()[2].dispatch('input');
    expect(container.children[2].classList.contains('is-invalid')).toBe(false);
  });
});

describe('seed slots with the real hd-wallet-wasm module', () => {
  let wallet;
  beforeAll(async () => {
    wallet = await initHDWallet();
  });

  it('Generate fills 24 slots with a valid phrase', () => {
    const { slots, inputs } = mountSlots();
    slots.setWords(TWELVE);
    slots.setWords(wallet.mnemonic.generate(24));
    expect(slots.count).toBe(24);
    expect(inputs().every((input) => /^[a-z]+$/u.test(input.value))).toBe(true);
    const phrase = slots.read();
    expect(phrase.split(' ')).toHaveLength(24);
    expect(wallet.mnemonic.validate(phrase)).toBe(true);
  });

  it('pasted test-vector phrases validate, and an unknown word is marked by checkWord', () => {
    const { slots, paste, container } = mountSlots();
    paste(3, TWELVE);
    expect(wallet.mnemonic.validate(slots.read())).toBe(true);
    paste(0, TWENTY_FOUR);
    expect(wallet.mnemonic.validate(slots.read())).toBe(true);
    paste(0, TWELVE.replace('about', 'aboutt'));
    expect(wallet.mnemonic.validate(slots.read())).toBe(false);
    slots.markInvalid((word) => !wallet.mnemonic.checkWord(word));
    const invalid = container.children.map((slot) => slot.classList.contains('is-invalid'));
    expect(invalid.map((bad, index) => (bad ? index : -1)).filter((index) => index >= 0)).toEqual([11]);
  });
});

describe('Validate result flash', () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  function button() {
    const element = new FakeElement('button', new FakeDocument());
    element.className = 'glass-btn small';
    element.textContent = 'Validate';
    return element;
  }

  it('says Validated in green, then fades back to Validate', () => {
    vi.useFakeTimers();
    const btn = button();
    flashResult(btn, { ok: true });
    expect(btn.textContent).toBe('Validated');
    expect(btn.classList.contains('is-ok')).toBe(true);
    vi.advanceTimersByTime(1199);
    expect(btn.classList.contains('is-ok')).toBe(true);
    vi.advanceTimersByTime(1);
    expect(btn.classList.contains('is-ok')).toBe(false);
    expect(btn.classList.contains('is-settling')).toBe(true);
    vi.advanceTimersByTime(600);
    expect(btn.textContent).toBe('Validate');
    expect(btn.className).toBe('glass-btn small');
  });

  it('says Error in red, then fades back', () => {
    vi.useFakeTimers();
    const btn = button();
    flashResult(btn, { ok: false });
    expect(btn.textContent).toBe('Error');
    expect(btn.classList.contains('is-error')).toBe(true);
    expect(btn.classList.contains('is-ok')).toBe(false);
    vi.advanceTimersByTime(1800);
    expect(btn.textContent).toBe('Validate');
    expect(btn.className).toBe('glass-btn small');
  });

  it('a repeated click restarts the cycle without sticking', () => {
    vi.useFakeTimers();
    const btn = button();
    flashResult(btn, { ok: true });
    vi.advanceTimersByTime(1000);
    flashResult(btn, { ok: false });
    expect(btn.textContent).toBe('Error');
    expect(btn.classList.contains('is-ok')).toBe(false);
    vi.advanceTimersByTime(300); // the first cycle's timer would have fired here
    expect(btn.classList.contains('is-error')).toBe(true);
    vi.advanceTimersByTime(1000); // into the fade
    flashResult(btn, { ok: true });
    expect(btn.textContent).toBe('Validated');
    expect(btn.classList.contains('is-settling')).toBe(false);
    vi.advanceTimersByTime(1800);
    expect(btn.textContent).toBe('Validate');
    expect(btn.className).toBe('glass-btn small');
    expect(vi.getTimerCount()).toBe(0);
  });

  it('with prefers-reduced-motion the label returns as the colour does', () => {
    vi.useFakeTimers();
    vi.stubGlobal('matchMedia', (query) => ({ matches: query.includes('reduce') }));
    const btn = button();
    flashResult(btn, { ok: true });
    vi.advanceTimersByTime(1200);
    expect(btn.textContent).toBe('Validate');
    expect(btn.className).toBe('glass-btn small');
  });
});

describe('login modal wiring', () => {
  const app = read('src/app.js');
  const css = read('styles/main.css');

  it('the Seed Phrase tab is a word-slot grid with Generate and Validate under it', () => {
    const html = getModalHTML();
    const seed = html.slice(html.indexOf('id="seed-method"'), html.indexOf('id="legacy-wallet-quarantine"'));
    expect(seed).not.toContain('<textarea');
    expect(seed).toMatch(/<div id="seed-phrase" class="seed-slots"[^>]*><\/div>\s*<div class="seed-actions"><button id="generate-seed"[^>]*>Generate<\/button><button id="validate-seed"[^>]*>Validate<\/button><button id="toggle-seed-vis"[^>]*aria-pressed="false"[^>]*>Show words<\/button><\/div>/u);
    expect(seed).toContain('id="derive-from-seed"');
    expect(css).toMatch(/\.modal-glass\.login-modal-content \.seed-actions \{[^}]*justify-content: center;/u);
    expect(css).toMatch(/\.seed-slots \{[^}]*repeat\(4, minmax\(0, 1fr\)\)/u);
    expect(css).toMatch(/@media \(max-width: 560px\) \{\s*\.seed-slots \{[^}]*repeat\(2, minmax\(0, 1fr\)\)/u);
  });

  it('every seed reader goes through readSeedPhrase and the slots are cleared like the textarea was', () => {
    expect(app).not.toMatch(/\$\('seed-phrase'\)\?\.value/u);
    expect(app).toMatch(/function readSeedPhrase\(\) \{\s*return _seedSlots \? _seedSlots\.read\(\) : '';/u);
    expect(app).toMatch(/\$\('derive-from-seed'\)\?\.addEventListener\('click', async \(\) => \{\s*const phrase = readSeedPhrase\(\);/u);
    expect(app).toMatch(/\$\('validate-seed'\)\?\.addEventListener\('click', \(\) => \{\s*const phrase = readSeedPhrase\(\);[\s\S]*?flashResult\(\$\('validate-seed'\), \{ ok: valid \}\);/u);
    expect(app).toMatch(/\$\('generate-seed'\)\?\.addEventListener\('click', \(\) => \{\s*_seedSlots\?\.setWords\(generateSeedPhrase\(\)\);\s*_seedSlots\?\.setMasked\(false\);/u);
    expect(app).toMatch(/seedToggle\?\.addEventListener\('click', \(\) => \{\s*_seedSlots\?\.setMasked\(!_seedSlots\.masked\);/u);
    expect(app).toMatch(/function clearSeedPhrase\(\) \{\s*_seedSlots\?\.clear\(\);\s*_seedSlotsMaskChanged\(\);/u);
    // logout, a successful login, and closing the login modal all empty the slots
    expect(app.match(/clearSeedPhrase\(\);/gu).length).toBeGreaterThanOrEqual(5);
    expect(app).not.toMatch(/alert\('Valid BIP39 seed phrase!'\)|alert\('Invalid seed phrase'\)/u);
  });

  it('more than 24 words keeps Login disabled and flashes Error', () => {
    expect(app).toMatch(/function seedPhraseIsValid\(phrase\) \{\s*if \(!phrase \|\| !state\.hdWalletModule \|\| _seedSlots\?\.overflow\) return false;/u);
    expect(app).toMatch(/onOverflow: \(\) => \{\s*flashResult\(\$\('validate-seed'\), \{ ok: false \}\);/u);
  });

  it('only a deliberate close (backdrop press and release, the close button, Escape) clears the slots', () => {
    expect(app).toMatch(/modal\.addEventListener\('mousedown', \(e\) => \{\s*pressedOnBackdrop = e\.target === modal;/u);
    expect(app).toMatch(/const backdrop = e\.target === modal && pressedOnBackdrop;/u);
    expect(app).toMatch(/if \(backdrop \|\| e\.target\.closest\?\.\('\.modal-close'\)\) closeModal\(modal\);/u);
    expect(app).toMatch(/function closeModal\(modal\) \{[\s\S]*?if \(modal\.id === 'login-modal'\) \{\s*clearSeedPhrase\(\);/u);
    expect(app).toMatch(/if \(e\.key === 'Escape'\) \{\s*\$qa\('\.modal\.active'\)\.forEach\(\(m\) => closeModal\(m\)\);/u);
  });

  it('switching from Seed Phrase to Password or External clears the slots', () => {
    expect(app).toMatch(/const leavingSeed = \$\('seed-method'\)\?\.classList\.contains\('active'\) && tab\.dataset\.method !== 'seed';/u);
    expect(app).toMatch(/if \(leavingSeed\) \{\s*clearSeedPhrase\(\);\s*updateSeedLoginButton\(\);/u);
  });

  it('Validate and Show/Hide words keep their width while their labels change', () => {
    expect(css).toMatch(/#validate-seed,\s*#toggle-seed-vis \{[^}]*min-width: \d+px;/u);
    // Masked slots draw no per-field reveal button (the toggle does that).
    expect(css).toMatch(/\.seed-slot-input::-ms-reveal/u);
  });

  it('the slots never mirror the phrase into logs, storage, globals or data attributes', () => {
    const source = read('src/seed-slots.js');
    expect(source).not.toMatch(/console\.|localStorage|sessionStorage|indexedDB|dataset|window\.|innerHTML|insertAdjacentHTML/u);
  });
});
