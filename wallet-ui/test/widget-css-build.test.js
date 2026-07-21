import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');
const BUILD_SCRIPT = resolve(ROOT, 'scripts/build-widget-css.mjs');
const WIDGET_CSS = resolve(ROOT, 'styles/widget.css');

describe('widget CSS namespace build', () => {
  it('keeps the host RTL attribute above the wallet namespace', () => {
    const originalWidgetCss = readFileSync(WIDGET_CSS, 'utf8');

    try {
      execFileSync(process.execPath, [BUILD_SCRIPT], { cwd: ROOT });
      const generated = readFileSync(WIDGET_CSS, 'utf8');

      expect(generated).toContain('html[dir="rtl"] #hd-wallet-ui-container .lang-switcher');
      expect(generated).toContain('html[dir="rtl"] #hd-wallet-ui-container code');
      expect(generated).not.toContain('#hd-wallet-ui-container html[dir="rtl"]');
    } finally {
      writeFileSync(WIDGET_CSS, originalWidgetCss, 'utf8');
    }
  });
});
