import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');

function readStyle(relativePath) {
  return readFileSync(resolve(ROOT, relativePath), 'utf8');
}

describe('account header address field styles', () => {
  it('lets XPUB and PeerID fields use the available header width', () => {
    const css = readStyle('styles/main.css');
    const displayRule = css.match(/\.account-address-display\s*\{[^}]+\}/)?.[0] ?? '';
    const infoRule = css.match(/\.account-header-info\s*\{[^}]+\}/)?.[0] ?? '';
    const rowRule = css.match(/\.account-address-row\s*\{[^}]+\}/)?.[0] ?? '';
    const labelRule = css.match(/\.account-address-label\s*\{[^}]+\}/)?.[0] ?? '';
    const copyRule = css.match(/\.account-address-copy\s*\{[^}]+\}/)?.[0] ?? '';

    expect(infoRule).toContain('flex: 1 1 auto');
    expect(infoRule).toContain('min-width: 0');
    expect(rowRule).toContain('min-width: 0');
    expect(labelRule).toContain('flex: 0 0 auto');
    expect(displayRule).toContain('flex: 1 1 auto');
    expect(displayRule).toContain('min-width: 12ch');
    expect(displayRule).not.toContain('max-width');
    expect(copyRule).toContain('width: 24px');
  });

  it('keeps generated widget styles aligned with the source styles', () => {
    const css = readStyle('styles/widget.css');
    const infoRule = css.match(/#hd-wallet-ui-container \.account-header-info\s*\{[^}]+\}/)?.[0] ?? '';
    const displayRule = css.match(/#hd-wallet-ui-container \.account-address-display\s*\{[^}]+\}/)?.[0] ?? '';

    expect(infoRule).toContain('flex: 1 1 auto');
    expect(infoRule).toContain('min-width: 0');
    expect(displayRule).toContain('flex: 1 1 auto');
    expect(displayRule).toContain('min-width: 12ch');
    expect(displayRule).not.toContain('max-width');
  });

  it('lets wallet tab xpub and PeerID rows use the modal body width', () => {
    const css = readStyle('styles/main.css');
    const rowRule = css.match(/\.ph-portfolio-xpub\s*\{[^}]+\}/)?.[0] ?? '';
    const valueRule = css.match(/\.ph-xpub-text\s*\{[^}]+\}/)?.[0] ?? '';

    expect(rowRule).toContain('max-width: 100%');
    expect(valueRule).toContain('flex: 1 1 auto');
    expect(valueRule).toContain('min-width: 0');
    expect(valueRule).toContain('width: 100%');
    expect(valueRule).not.toContain('max-width: 200px');
  });
});
