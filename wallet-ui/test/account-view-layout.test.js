// The 3.0 account view layout (replaces account-modal-layout.test.js): a page
// panel with an identity bar and five section tabs, none of the 2.x wallets
// layer, Bond, key-type select or vCard controls, and the SDN design tokens.

import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

import { describe, expect, it } from 'vitest';

import { DEFAULT_ACCOUNT_TABS, createAccountView } from '../account/index.mjs';
import { getModalHTML } from '../src/template.js';
import { SECTIONS, SECTION_LABELS } from '../src/account-view.js';
import { StubDocument, parseTemplate, textOf } from './helpers/stub-dom.mjs';

const ROOT = resolve(import.meta.dirname, '..');
const read = (path) => readFileSync(resolve(ROOT, path), 'utf8');

const REMOVED_IDS = [
  'account-wallet-select',
  'wallet-bond-value',
  'wallet-manage-tab',
  'wallet-wallets-view',
  'wallet-main-view',
  'messaging-key-type',
  'messaging-hd-path',
  'generate-vcard',
  'vcf-import-input',
  'keys-modal',
  'photo-remove-confirm-modal',
];

describe('template', () => {
  const html = getModalHTML();
  const doc = new StubDocument();
  const root = parseTemplate(doc, html);
  const view = root.querySelector('#account-view');

  it('has #account-view with an identity bar and five tabs in the spec order', () => {
    expect(view).not.toBeNull();
    expect(view.hidden).toBe(true);
    const tabs = view.querySelectorAll('[role=tab]');
    expect(tabs.map(textOf)).toEqual(['Profile', 'Messages', 'People', 'Assets', 'Settings']);
    expect(tabs.map((tab) => tab.getAttribute('aria-controls'))).toEqual(SECTIONS.map((id) => `account-pane-${id}`));
    expect(view.querySelector('[role=tablist]')).not.toBeNull();
    const panels = view.querySelectorAll('[role=tabpanel]');
    expect(panels.map((panel) => panel.id)).toEqual(SECTIONS.map((id) => `account-pane-${id}`));
    expect(panels.filter((panel) => !panel.hidden)).toHaveLength(1);
    for (const id of ['account-avatar', 'account-name', 'account-add-name', 'account-peer-id', 'account-copy-peer', 'account-status', 'account-close']) {
      expect(view.querySelector(`#${id}`), id).not.toBeNull();
    }
    expect(view.querySelector('#account-close').getAttribute('aria-label')).toBe('Close');
    expect(SECTIONS.map((id) => SECTION_LABELS[id])).toEqual(['Profile', 'Messages', 'People', 'Assets', 'Settings']);
  });

  it('has none of the 2.x wallets layer, Bond, messaging key controls or vCard controls', () => {
    for (const id of REMOVED_IDS) expect(html, id).not.toContain(`id="${id}"`);
    for (const fragment of ['ph-portfolio-value', 'modal-tab', 'Bond', 'vcard', 'Trust Map', '>Manage<', '>Wallet<']) {
      expect(html, fragment).not.toContain(fragment);
    }
    expect(view.querySelectorAll('select')).toHaveLength(0);
  });

  it('keeps the login window with the seed word slots', () => {
    expect(root.querySelector('#login-modal')).not.toBeNull();
    expect(root.querySelector('#seed-phrase')).not.toBeNull();
    expect(root.querySelector('#validate-seed')).not.toBeNull();
  });

  it('is a constant string with no interpolation', () => {
    const source = read('src/template.js');
    expect(source).not.toMatch(/\$\{/u);
  });
});

describe('public account view export', () => {
  it('ships the five sections as DEFAULT_ACCOUNT_TABS', () => {
    expect(DEFAULT_ACCOUNT_TABS).toEqual([
      { id: 'profile', label: 'Profile' },
      { id: 'messages', label: 'Messages' },
      { id: 'people', label: 'People' },
      { id: 'assets', label: 'Assets' },
      { id: 'settings', label: 'Settings' },
    ]);
  });

  it('has no bond option and renders no Bond', () => {
    const doc = new StubDocument();
    const view = createAccountView({ document: doc, title: 'Ada', bond: { value: '$1.00' } });
    expect(textOf(view.element)).not.toMatch(/Bond|\$1\.00/u);
    expect(view.element.querySelector('#wallet-bond-value')).toBeNull();
    const declarations = read('account/index.d.ts');
    expect(declarations).not.toMatch(/bond/iu);
    expect(declarations).toContain('peerId?: string;');
    expect(declarations).toContain('avatar?: AccountViewAvatar;');
  });
});

describe('design tokens and type', () => {
  const account = read('styles/account.css');
  const main = read('styles/main.css');

  it('puts the SDN tokens on :root in account.css and main.css, with real light values', () => {
    for (const token of ['--bg:', '--text:', '--text-2:', '--muted:', '--border:', '--border-strong:', '--wash:', '--accent:', '--alert:']) {
      expect(account, token).toContain(token);
      expect(main, token).toContain(token);
    }
    expect(account).toMatch(/:root\[data-theme="light"\] \{[^}]*--bg: #f5f5f7;/u);
    expect(account).toMatch(/:root\[data-theme="light"\] \{[^}]*--rim-primary-fill: #1d1d1f;/u);
    expect(main).not.toMatch(/--white-\d+/u);
    expect(main).toContain("@import url('./account.css');");
  });

  it('uses only the allowed font sizes and no !important in account.css', () => {
    const sizes = [...account.matchAll(/font(?:-size)?:\s*(?:[0-9]{3}\s+)?(\d+(?:\.\d+)?)(px|rem|em)/gu)]
      .map((match) => `${match[1]}${match[2]}`);
    expect(sizes.length).toBeGreaterThan(10);
    for (const size of sizes) expect(['12px', '13px', '14px', '15px', '17px', '19px', '24px'], size).toContain(size);
    expect(account).not.toContain('!important');
  });

  it('has no rim on tabs, an amber underline on the active tab, and drops the purple and cyan', () => {
    const activeTab = account.match(/\.account-tab\[aria-selected="true"\] \{[^}]+\}/gu)?.join('\n') ?? '';
    expect(activeTab).toContain('box-shadow: inset 0 -2px 0 var(--accent)');
    expect(account).not.toMatch(/\.account-tab[^{]*\{[^}]*rim/u);
    for (const css of [account, main]) {
      expect(css).not.toMatch(/171,\s*130,\s*255|#c4b5fd|#00dc82/iu);
    }
    expect(account).not.toMatch(/89,\s*217,\s*255|#59d9ff/iu);
    expect(main).not.toMatch(/\.modal-tab|\.modal-wide|\.wallet-manage|\.messaging-|\.hd-key-|\.account-modal-header/u);
  });

  it('the landing page uses real light tokens instead of inverting', () => {
    const html = read('index.html');
    expect(html).not.toContain('data-sdn-light="invert"');
    expect(html).not.toContain('autoOpenWallet');
  });
});
