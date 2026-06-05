import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';

const ROOT = resolve(import.meta.dirname, '..');

function read(relativePath) {
  return readFileSync(resolve(ROOT, relativePath), 'utf8');
}

describe('account modal wallet layout', () => {
  it('uses the header for wallet selection instead of root XPUB and PeerID rows', () => {
    const template = read('src/template.js');

    expect(template).toContain('id="account-wallet-select"');
    expect(template).toContain('id="account-wallet-manage-btn"');
    expect(template).not.toContain('id="account-address-display"');
    expect(template).not.toContain('id="account-peerid-display"');
  });

  it('keeps selected wallet identity keys in the Identity tab', () => {
    const template = read('src/template.js');

    expect(template).toContain('id="identity-wallet-xpub"');
    expect(template).toContain('id="identity-wallet-peerid"');
    expect(template).not.toContain('id="wallet-tab-xpub"');
    expect(template).not.toContain('id="wallet-tab-peerid"');
  });

  it('makes asset rows the send and receive entry point', () => {
    const template = read('src/template.js');
    const app = read('src/app.js');

    expect(template).toContain('id="wallet-asset-action-overlay"');
    expect(template).not.toContain('id="wallet-send-btn"');
    expect(template).not.toContain('id="wallet-receive-btn-main"');
    expect(app).toContain('showAssetActionOverlay(acct, idx)');
  });

  it('highlights active modal tabs without the green underline', () => {
    const css = read('styles/main.css');
    const activeRule = css.match(/\.modal-tab\.active\s*\{[^}]+\}/)?.[0] ?? '';

    expect(activeRule).toContain('background:');
    expect(activeRule).toContain('border-color:');
    expect(activeRule).not.toContain('border-bottom-color');
  });
});
