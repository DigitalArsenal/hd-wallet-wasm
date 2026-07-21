import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const BUILD_SCRIPT = resolve(ROOT, 'scripts/build-widget-css.mjs');
const MAIN_CSS = resolve(ROOT, 'styles/main.css');
const WIDGET_CSS = resolve(ROOT, 'styles/widget.css');

async function loadBuilder() {
  const builder = await import(`${pathToFileURL(BUILD_SCRIPT).href}?vitest`);
  expect(builder.buildWidgetCss).toBeTypeOf('function');
  expect(builder.prefixSelector).toBeTypeOf('function');
  return builder;
}

describe('widget CSS namespace build', () => {
  it('generates to an explicit temp output without touching committed CSS', async () => {
    const committedBefore = readFileSync(WIDGET_CSS);
    const modifiedBefore = statSync(WIDGET_CSS).mtimeMs;
    const tempDir = mkdtempSync(join(tmpdir(), 'hd-wallet-widget-css-'));
    const tempOutput = join(tempDir, 'widget.css');

    try {
      const { buildWidgetCss } = await loadBuilder();
      await buildWidgetCss({ sourcePath: MAIN_CSS, outputPath: tempOutput });

      expect(readFileSync(tempOutput)).toEqual(committedBefore);
      expect(readFileSync(WIDGET_CSS)).toEqual(committedBefore);
      expect(statSync(WIDGET_CSS).mtimeMs).toBe(modifiedBefore);
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it('keeps equivalent RTL host selectors above the wallet namespace', async () => {
    const { prefixSelector } = await loadBuilder();

    expect(prefixSelector('html[dir="rtl"] .lang-switcher'))
      .toBe('html[dir="rtl"] #hd-wallet-ui-container .lang-switcher');
    expect(prefixSelector("HTML[DIR='RTL'] .lang-switcher"))
      .toBe('html[dir="rtl"] #hd-wallet-ui-container .lang-switcher');
    expect(prefixSelector('html[ dir = RTL ]\tcode'))
      .toBe('html[dir="rtl"] #hd-wallet-ui-container code');
    expect(prefixSelector('Html [ DiR = "rtl" ] .balance-value'))
      .toBe('html[dir="rtl"] #hd-wallet-ui-container .balance-value');
    expect(prefixSelector('html[dir="rtl"] #hd-wallet-ui-container code'))
      .toBe('html[dir="rtl"] #hd-wallet-ui-container code');
    expect(prefixSelector('html[dir="rtl" i] .lang-switcher'))
      .toBe('html[dir="rtl"] #hd-wallet-ui-container .lang-switcher');
    expect(prefixSelector("html[dir='rtl' s] code"))
      .toBe('html[dir="rtl"] #hd-wallet-ui-container code');
    expect(prefixSelector("HTML [ DIR = 'RTL' s ] code"))
      .toBe("#hd-wallet-ui-container HTML [ DIR = 'RTL' s ] code");
  });

  it('balances nested functional selectors when scoping body:has()', async () => {
    const { prefixSelector } = await loadBuilder();

    expect(prefixSelector('body:has(.modal:is(.active, .opening)) .nav-bar'))
      .toBe('body:has(#hd-wallet-ui-container .modal:is(.active, .opening)) #hd-wallet-ui-container .nav-bar');
    expect(prefixSelector('body:has([data-label=")"] .modal) .nav-bar'))
      .toBe('body:has(#hd-wallet-ui-container [data-label=")"] .modal) #hd-wallet-ui-container .nav-bar');
    expect(prefixSelector('body:has(#hd-wallet-ui-container .modal:not(.closed)) #hd-wallet-ui-container .nav-bar'))
      .toBe('body:has(#hd-wallet-ui-container .modal:not(.closed)) #hd-wallet-ui-container .nav-bar');
    expect(prefixSelector('body:has(.modal, .dialog) .nav-bar'))
      .toBe('body:has(#hd-wallet-ui-container .modal, #hd-wallet-ui-container .dialog) #hd-wallet-ui-container .nav-bar');
    expect(prefixSelector('body:has(.modal /* ) */ .dialog, [data-label="a,b"]) .nav-bar'))
      .toBe('body:has(#hd-wallet-ui-container .modal /* ) */ .dialog, #hd-wallet-ui-container [data-label="a,b"]) #hd-wallet-ui-container .nav-bar');
    expect(prefixSelector('body:has(.modal\\)name, [data-label=")"], .dialog:not(.closed)) .nav-bar'))
      .toBe('body:has(#hd-wallet-ui-container .modal\\)name, #hd-wallet-ui-container [data-label=")"], #hd-wallet-ui-container .dialog:not(.closed)) #hd-wallet-ui-container .nav-bar');
  });
});
