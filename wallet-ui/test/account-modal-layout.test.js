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
    expect(template).not.toContain('id="account-address-display"');
    expect(template).not.toContain('id="account-peerid-display"');
    expect(template).not.toContain('<h3>Account</h3>');
    expect(template).not.toContain('id="account-total-value"');
    expect(template).not.toContain('id="account-wallet-manage-btn"');
  });

  it('puts wallet management beside the Wallet tab instead of in the header', () => {
    const template = read('src/template.js');
    const app = read('src/app.js');

    expect(template).toContain('id="wallet-manage-tab"');
    expect(template).toContain('data-modal-tab="wallet-tab-content"');
    expect(app).toContain("$('wallet-manage-tab')?.addEventListener('click'");
  });

  it('shows Bond for the selected wallet and keeps the selected dropdown label amount-free', () => {
    const template = read('src/template.js');
    const app = read('src/app.js');

    expect(template).toContain('<div class="ph-portfolio-label">Bond</div>');
    expect(app).toContain('function updateWalletBondDisplay');
    expect(app).toContain('state.walletFiatTotals?.[wallet.id]');
    expect(app).toContain('wallet.id === state.activeWalletId');
    expect(app).toContain('? wallet.name');
  });

  it('places a compact wallet picker above the large current wallet balance in the account header', () => {
    const template = read('src/template.js');
    const css = read('styles/main.css');
    const app = read('src/app.js');
    const header = template.match(/<div class="modal-header account-modal-header">[\s\S]+?<div class="modal-tabs">/)?.[0] ?? '';
    const selectRule = css.match(/\.account-wallet-select\.glass-input\.compact\s*\{[^}]+\}/)?.[0] ?? '';

    expect(header).toContain('id="account-wallet-select"');
    expect(header).toContain('class="account-wallet-summary"');
    expect(header).toContain('id="wallet-bond-value"');
    expect(header.indexOf('id="account-wallet-select"')).toBeLessThan(header.indexOf('id="wallet-bond-value"'));
    expect(template.match(/id="wallet-bond-value"/g)).toHaveLength(1);
    expect(selectRule).toContain('width: auto');
    expect(selectRule).toContain('max-width:');
    expect(selectRule).not.toContain('width: 100%');
    expect(app).toContain('fitWalletSelectorToSelectedLabel');
  });

  it('left-aligns the account header and puts a large Bond label beside the green balance', () => {
    const template = read('src/template.js');
    const css = read('styles/main.css');
    const headerInfoRule = css.match(/\.account-header-info\s*\{[^}]+\}/)?.[0] ?? '';
    const modalHeaderRule = css.match(/\.account-modal-header\s*\{[^}]+\}/)?.[0] ?? '';
    const walletRowRule = css.match(/\.account-wallet-row\s*\{[^}]+\}/)?.[0] ?? '';
    const summaryRule = css.match(/\.account-wallet-summary\s*\{[^}]+\}/)?.[0] ?? '';
    const balanceLineRule = css.match(/\.account-wallet-balance-line\s*\{[^}]+\}/)?.[0] ?? '';
    const valueRule = css.match(/\.account-wallet-summary\s+\.ph-portfolio-value\s*\{[^}]+\}/)?.[0] ?? '';
    const labelRule = css.match(/\.account-wallet-summary\s+\.ph-portfolio-label\s*\{[^}]+\}/)?.[0] ?? '';

    expect(template).toContain('class="account-wallet-balance-line"');
    expect(template.indexOf('id="wallet-bond-value"')).toBeLessThan(template.indexOf('<div class="ph-portfolio-label">Bond</div>'));
    expect(headerInfoRule).toContain('align-items: flex-start');
    expect(headerInfoRule).toContain('justify-content: center');
    expect(modalHeaderRule).toContain('align-items: center');
    expect(walletRowRule).toContain('justify-content: flex-start');
    expect(summaryRule).toContain('text-align: left');
    expect(balanceLineRule).toContain('align-items: center');
    expect(valueRule).toContain('color: #4ade80');
    expect(labelRule).toContain('font-size: 18px');
  });

  it('labels the vCard camera action as Use Camera', () => {
    const template = read('src/template.js');

    expect(template).toContain('id="vcard-camera-btn"');
    expect(template).toContain('Use Camera');
    expect(template).not.toContain('>Take Photo<');
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

  it('uses a bare icon-only close control in the account modal header', () => {
    const template = read('src/template.js');
    const css = read('styles/main.css');
    const closeRule = css.match(/\.modal-close\s*\{[^}]+\}/)?.[0] ?? '';

    expect(template).toContain('class="modal-close account-modal-close"');
    expect(template).toContain('aria-label="Close"');
    expect(template).not.toContain('<button class="modal-close">&times;</button>');
    expect(closeRule).toContain('background: transparent');
    expect(closeRule).toContain('border: none');
    expect(closeRule).not.toContain('border-radius: 50%');
  });
});
