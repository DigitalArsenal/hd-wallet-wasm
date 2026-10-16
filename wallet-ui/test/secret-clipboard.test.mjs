// SEC-081: a copied private key does not stay on the clipboard. The xprv
// Copy chip goes through copySecretText, which overwrites the clipboard after
// 30 seconds (retrying on the next window focus when the browser refuses the
// write), and sign-out overwrites it at once.

import { readFileSync } from 'node:fs';
import initHDWallet from 'hd-wallet-wasm';
import { describe, expect, it } from 'vitest';

import { SECRET_CLIPBOARD_MS, clearSecretClipboard, copySecretText } from '../src/clipboard.js';
import { XPRV_NOTE, createSettingsPane } from '../src/settings-ui.js';
import { createTestContext } from './helpers/account-context.mjs';
import { StubDocument, buttonByText, flush, textOf } from './helpers/stub-dom.mjs';

function fakeTimers() {
  const timers = new Map();
  let next = 1;
  return {
    timers,
    setTimer: (fn, ms) => { const id = next++; timers.set(id, { fn, ms }); return id; },
    clearTimer: (id) => { timers.delete(id); },
    async runAll() {
      for (const [id, timer] of [...timers]) {
        timers.delete(id);
        await timer.fn();
      }
    },
  };
}

function fakeWindow({ writable = true } = {}) {
  const listeners = new Map();
  const win = {
    clipboardText: '',
    writable,
    writes: [],
    navigator: {
      clipboard: {
        writeText: async (text) => {
          if (!win.writable) throw new Error('Document is not focused.');
          win.writes.push(text);
          win.clipboardText = text;
        },
      },
    },
    addEventListener: (type, fn) => listeners.set(type, fn),
    removeEventListener: (type, fn) => { if (listeners.get(type) === fn) listeners.delete(type); },
    async fire(type) { await listeners.get(type)?.(); },
    listening: (type) => listeners.has(type),
  };
  return win;
}

const copyInto = (win) => async (text) => { await win.navigator.clipboard.writeText(text); return true; };

describe('copySecretText', () => {
  it('copies, then overwrites the clipboard after 30 seconds', async () => {
    const win = fakeWindow();
    const timers = fakeTimers();
    expect(await copySecretText('xprvSECRET', { win, copy: copyInto(win), ...timers })).toBe(true);
    expect(win.clipboardText).toBe('xprvSECRET');
    expect([...timers.timers.values()].map((t) => t.ms)).toEqual([SECRET_CLIPBOARD_MS]);
    expect(SECRET_CLIPBOARD_MS).toBe(30000);
    await timers.runAll();
    expect(win.clipboardText).toBe('');
  });

  it('retries on the next focus when the browser refuses the write', async () => {
    const win = fakeWindow();
    const timers = fakeTimers();
    await copySecretText('xprvSECRET', { win, copy: copyInto(win), ...timers });
    win.writable = false;
    await timers.runAll();
    expect(win.clipboardText).toBe('xprvSECRET');
    expect(win.listening('focus')).toBe(true);
    win.writable = true;
    await win.fire('focus');
    expect(win.clipboardText).toBe('');
    expect(win.listening('focus')).toBe(false);
  });

  it('sign-out clears at once, and a failed copy schedules nothing', async () => {
    const win = fakeWindow();
    const timers = fakeTimers();
    await copySecretText('xprvSECRET', { win, copy: copyInto(win), ...timers });
    expect(await clearSecretClipboard()).toBe(true);
    expect(win.clipboardText).toBe('');
    expect(timers.timers.size).toBe(0);
    expect(await copySecretText('xprvSECRET', { win, copy: async () => false, ...timers })).toBe(false);
    expect(timers.timers.size).toBe(0);
  });

  it('logout calls the clear, and the quarantined wallet-record export copies as a secret', () => {
    const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
    const logout = app.slice(app.indexOf('function logout() {'), app.indexOf('\n}\n', app.indexOf('function logout() {')));
    expect(logout).toContain('void clearSecretClipboard();');
    expect(app).toContain('const copied = raw !== null && await copySecretText(raw);');
    expect(app).not.toContain('await safeCopyText(raw)');
  });
});

describe('the xprv Copy chip in Settings', () => {
  it('copies through the secret path and says the clipboard will be cleared', async () => {
    const wallet = await initHDWallet();
    const seed = wallet.mnemonic.toSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
    const root = wallet.hdkey.fromSeed(seed);
    const doc = new StubDocument();
    const panel = doc.createElement('section');
    doc.body.append(panel);
    const ctx = createTestContext({ document: doc, wasm: wallet, seed, hdRoot: root });
    const copied = [];
    const timers = fakeTimers();
    const pane = createSettingsPane(panel, ctx, { ...timers, copySecret: async (text) => { copied.push(text); return true; } });
    pane.show();
    buttonByText(panel, 'Reveal private key').click();
    buttonByText(panel, 'Reveal').click();
    expect(textOf(panel)).toContain(XPRV_NOTE);
    expect(XPRV_NOTE).toMatch(/clipboard is cleared after 30 seconds/u);
    const chip = panel.querySelector('.code.secret .copy');
    chip.click();
    await flush();
    expect(copied).toHaveLength(1);
    expect(copied[0]).toMatch(/^xprv[0-9A-Za-z]{100,}$/u);
    pane.reset();
  });
});
