// The account view shell: one pane at a time, #account/<section> routing,
// Close / Back / Escape, and the inert landing page. Runs the real template
// (src/template.js) through the real shell (src/account-view.js) on a stub DOM.

import { describe, expect, it } from 'vitest';

import { getModalHTML } from '../src/template.js';
import { SECTIONS, createAccountShell, parseAccountHash } from '../src/account-view.js';
import { createAssetsPane } from '../src/assets-ui.js';
import { createSettingsPane } from '../src/settings-ui.js';
import { createTestContext } from './helpers/account-context.mjs';
import {
  StubDocument,
  buttonByText,
  memoryStorage,
  parseTemplate,
  stubWindow,
  textOf,
} from './helpers/stub-dom.mjs';

function mount({ hash = '', panes = null, loggedIn = true } = {}) {
  const doc = new StubDocument();
  const win = stubWindow(doc, { hash });
  const header = doc.createElement('header');
  header.className = 'sdn-header';
  header.rectBottom = 52;
  const hero = doc.createElement('section');
  hero.id = 'hero';
  const footer = doc.createElement('footer');
  const container = parseTemplate(doc, getModalHTML());
  container.id = 'hd-wallet-ui-container';
  doc.body.append(header, hero, footer, container);
  const root = doc.getElementById('account-view');
  const storage = memoryStorage();
  const calls = { reset: {}, show: {} };
  const fakePanes = Object.fromEntries(SECTIONS.map((section) => [section, {
    reset() { calls.reset[section] = (calls.reset[section] ?? 0) + 1; },
    show(intent) { calls.show[section] = [...(calls.show[section] ?? []), intent]; },
  }]));
  let closed = 0;
  const shell = createAccountShell({
    document: doc,
    window: win,
    root,
    panes: panes ? panes(doc, root) : fakePanes,
    canOpen: () => loggedIn,
    onClose: () => { closed += 1; },
    storage,
  });
  return { doc, win, root, shell, storage, calls, header, hero, footer, container, closed: () => closed };
}

function visiblePanels(root) {
  return root.querySelectorAll('[role=tabpanel]').filter((panel) => !panel.hidden);
}

describe('showSection', () => {
  it('shows exactly the chosen pane for every ordered pair of sections', () => {
    const { root, shell } = mount();
    shell.open('profile');
    for (const from of SECTIONS) {
      for (const to of SECTIONS) {
        shell.showSection(from);
        shell.showSection(to);
        const visible = visiblePanels(root);
        expect(visible, `${from} → ${to}`).toHaveLength(1);
        expect(visible[0].id).toBe(`account-pane-${to}`);
        const selected = root.querySelectorAll('[role=tab]').filter((tab) => tab.getAttribute('aria-selected') === 'true');
        expect(selected.map((tab) => tab.id)).toEqual([`account-tab-${to}`]);
      }
    }
  });

  it('resets every pane on a switch, so no sub-view survives a round trip', () => {
    const { shell, calls } = mount();
    shell.open('assets');
    const before = calls.reset.assets ?? 0;
    shell.showSection('settings');
    shell.showSection('assets');
    expect(calls.reset.assets).toBeGreaterThanOrEqual(before + 2);
    expect(calls.show.assets.length).toBeGreaterThanOrEqual(2);
  });

  it('Assets › Send › Settings › Assets shows the asset table, not the Send form', () => {
    const { doc, root, shell } = mount({
      panes: (document, viewRoot) => {
        const ctx = createTestContext({ document });
        return {
          assets: createAssetsPane(viewRoot.querySelector('#account-pane-assets'), ctx),
          settings: createSettingsPane(viewRoot.querySelector('#account-pane-settings'), ctx),
        };
      },
    });
    void doc;
    shell.open('assets');
    const panel = root.querySelector('#account-pane-assets');
    panel.querySelector('.asset-toggle').click();
    expect(textOf(panel)).toContain('To address');
    expect(panel.querySelectorAll('.send').length).toBe(1);
    shell.showSection('settings');
    expect(panel.childNodes).toHaveLength(0);
    shell.showSection('assets');
    expect(panel.querySelectorAll('.send')).toHaveLength(0);
    expect(panel.querySelectorAll('.asset-toggle')).toHaveLength(3);
    expect(textOf(panel.querySelector('.pane-title'))).toBe('Addresses and balances');
  });

  it('remembers the last section per viewer', () => {
    const { shell, storage } = mount();
    shell.open('people');
    expect(storage.getItem('hdw-account-section')).toBe('people');
    shell.close();
    shell.open();
    expect(shell.currentSection()).toBe('people');
  });
});

describe('routing', () => {
  it('maps #account/<section> to the five sections only', () => {
    expect(parseAccountHash('#account/profile')).toBe('profile');
    expect(parseAccountHash('#account/assets')).toBe('assets');
    expect(parseAccountHash('#account/wallet')).toBeNull();
    expect(parseAccountHash('#packages')).toBeNull();
  });

  it('opening sets the hash, switching replaces it, Close clears it', () => {
    const { win, shell, root } = mount();
    shell.open('messages');
    expect(win.location.hash).toBe('#account/messages');
    expect(root.hidden).toBe(false);
    root.querySelector('#account-tab-settings').click();
    expect(win.location.hash).toBe('#account/settings');
    root.querySelector('#account-close').click();
    expect(root.hidden).toBe(true);
    expect(win.location.hash).toBe('');
  });

  it('a #account/<section> hash opens that pane, and Back (a non-account hash) closes the view', () => {
    const { win, shell, root, closed } = mount();
    win.navigate('#account/people');
    expect(shell.isOpen()).toBe(true);
    expect(visiblePanels(root)[0].id).toBe('account-pane-people');
    win.navigate('#account/assets');
    expect(visiblePanels(root)[0].id).toBe('account-pane-assets');
    win.navigate('');
    expect(shell.isOpen()).toBe(false);
    expect(root.hidden).toBe(true);
    expect(closed()).toBe(1);
  });

  it('a hash route without a session does not open the view', () => {
    const { win, shell } = mount({ loggedIn: false });
    win.navigate('#account/profile');
    expect(shell.isOpen()).toBe(false);
    expect(win.location.hash).toBe('');
  });

  it('Escape closes the view', () => {
    const { doc, shell } = mount();
    shell.open('profile');
    doc.dispatch('keydown', { key: 'Escape' });
    expect(shell.isOpen()).toBe(false);
  });
});

describe('page panel', () => {
  it('sits under the SDN header and makes the landing page inert while open', () => {
    const { shell, root, header, hero, footer, container } = mount();
    shell.open('profile');
    expect(root.style.getPropertyValue('--account-top')).toBe('52px');
    expect(hero.inert).toBe(true);
    expect(footer.inert).toBe(true);
    expect(header.inert).toBe(false);
    expect(container.inert).toBe(false);
    shell.close();
    expect(hero.inert).toBe(false);
    expect(footer.inert).toBe(false);
  });

  it('tabs are reachable with the arrow keys and focus lands on the pane title', () => {
    const { doc, shell, root } = mount({
      panes: (document, viewRoot) => {
        const ctx = createTestContext({ document });
        return { assets: createAssetsPane(viewRoot.querySelector('#account-pane-assets'), ctx) };
      },
    });
    shell.open('profile');
    root.querySelector('#account-tab-profile').dispatch('keydown', { key: 'ArrowRight' });
    expect(doc.activeElement.id).toBe('account-tab-messages');
    root.querySelector('#account-tab-messages').dispatch('keydown', { key: 'End' });
    expect(doc.activeElement.id).toBe('account-tab-settings');
    root.querySelector('#account-tab-assets').click();
    expect(doc.activeElement.classList.contains('pane-title')).toBe(true);
  });

  it('the identity bar shows a short peer ID with Copy, the status and no selector or Bond', () => {
    const { shell, root } = mount();
    shell.setIdentity({
      name: '',
      avatar: { initials: '' },
      peerId: '12D3KooWJB7pwCc5pMGNVykovHTSMHGTxiQBEFBVwsgFoAmMkmWZ',
      statusText: 'Seed phrase',
      onAddName: () => {},
    });
    expect(textOf(root.querySelector('#account-peer-id'))).toBe('12D3KooW…kmWZ');
    expect(root.querySelector('#account-peer-id').title).toBe('12D3KooWJB7pwCc5pMGNVykovHTSMHGTxiQBEFBVwsgFoAmMkmWZ');
    expect(root.querySelector('#account-add-name').hidden).toBe(false);
    expect(textOf(root.querySelector('#account-status'))).toBe('Seed phrase');
    expect(root.querySelectorAll('select')).toHaveLength(0);
    expect(textOf(root)).not.toMatch(/Bond/u);
    expect(buttonByText(root, 'Copy')).not.toBeNull();
    shell.setIdentity({ name: 'Ada Lovelace', avatar: { initials: 'AL' }, peerId: 'x', statusText: '' });
    expect(textOf(root.querySelector('#account-name'))).toBe('Ada Lovelace');
    expect(root.querySelector('#account-add-name').hidden).toBe(true);
    expect(textOf(root.querySelector('#account-avatar'))).toBe('AL');
  });
});
