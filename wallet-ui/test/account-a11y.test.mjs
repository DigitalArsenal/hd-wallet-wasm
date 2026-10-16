// Keyboard, focus and screen-reader behaviour of the account view: the shell
// (Close, Back, Escape, inert), focus kept across pane re-renders, the asset
// row's toggle, the polite live region, and People in an external session.
// Real template, real shell and panes, stub DOM.

import { describe, expect, it } from 'vitest';

import { getModalHTML } from '../src/template.js';
import { SECTIONS, createAccountShell } from '../src/account-view.js';
import { createAssetsPane } from '../src/assets-ui.js';
import { CONTACTS_SEED_ONLY, createPeoplePane } from '../src/people-ui.js';
import { createSettingsPane } from '../src/settings-ui.js';
import { createProfilePane } from '../src/profile-ui.js';
import { announce, statusLine } from '../src/ui-dom.js';
import { createTestContext } from './helpers/account-context.mjs';
import {
  StubDocument,
  buttonByText,
  flush,
  memoryStorage,
  parseTemplate,
  stubWindow,
  textOf,
} from './helpers/stub-dom.mjs';

function mount({ panes = null } = {}) {
  const doc = new StubDocument();
  const win = stubWindow(doc);
  let backs = 0;
  win.history.back = () => { backs += 1; };
  const header = doc.createElement('header');
  header.className = 'sdn-header';
  const navKeys = doc.createElement('button');
  navKeys.id = 'nav-keys';
  header.append(navKeys);
  const menu = doc.createElement('nav');
  menu.className = 'sdn-menu';
  const main = doc.createElement('main');
  const container = parseTemplate(doc, getModalHTML());
  container.id = 'hd-wallet-ui-container';
  doc.body.append(header, menu, main, container);
  const root = doc.getElementById('account-view');
  const fakePanes = Object.fromEntries(SECTIONS.map((section) => [section, { reset() {}, show() {} }]));
  const shell = createAccountShell({
    document: doc,
    window: win,
    root,
    panes: panes ? panes(doc, root) : fakePanes,
    storage: memoryStorage(),
  });
  return { doc, win, root, shell, navKeys, menu, main, backs: () => backs };
}

function paneFor(section, create, ctxOptions = {}) {
  const doc = new StubDocument();
  const panel = doc.createElement('section');
  doc.body.append(panel);
  const ctx = createTestContext({ document: doc, ...ctxOptions });
  const pane = create(panel, ctx);
  pane.show();
  return { doc, panel, ctx, pane };
}

function focusKeyOf(doc) {
  return doc.activeElement?.getAttribute?.('data-focus-key') ?? null;
}

describe('the shell', () => {
  it('Close returns focus to the control that opened the view', () => {
    const { doc, root, shell, navKeys } = mount();
    navKeys.focus();
    shell.open('profile');
    root.querySelector('#account-close').focus();
    root.querySelector('#account-close').click();
    expect(doc.activeElement).toBe(navKeys);
  });

  it('the SDN header and its mobile menu stay usable while the page behind is inert', () => {
    const { shell, menu, main } = mount();
    shell.open('profile');
    expect(main.inert).toBe(true);
    expect(menu.inert).not.toBe(true);
    shell.close();
    expect(main.inert).toBe(false);
  });

  it('Close after Open steps back over the pushed history entry, so one Back leaves the page', () => {
    const { win, shell, backs } = mount();
    shell.open('messages');
    shell.showSection('assets');
    shell.close();
    expect(win.location.hash).toBe('');
    expect(backs()).toBe(1);
  });

  it('a view opened from a #account/ link (no entry pushed) and Back do not step back again', () => {
    const { win, shell, backs } = mount();
    win.navigate('#account/people');
    shell.close();
    expect(backs()).toBe(0);
    shell.open('profile');
    win.navigate('');
    expect(shell.isOpen()).toBe(false);
    shell.open('profile');
    shell.close();
    expect(backs()).toBe(1);
  });

  it('Escape in a text field does not close the view; Escape elsewhere does', () => {
    const { doc, shell, root } = mount();
    shell.open('messages');
    const textarea = doc.createElement('textarea');
    const text = doc.createElement('input');
    text.type = 'text';
    const checkbox = doc.createElement('input');
    checkbox.type = 'checkbox';
    root.querySelector('#account-pane-messages').append(textarea, text, checkbox);
    doc.dispatch('keydown', { key: 'Escape', target: textarea });
    doc.dispatch('keydown', { key: 'Escape', target: text });
    expect(shell.isOpen()).toBe(true);
    doc.dispatch('keydown', { key: 'Escape', target: checkbox });
    expect(shell.isOpen()).toBe(false);
  });

  it('is a named region with a polite live region that reads out status lines', async () => {
    const { doc, root } = mount();
    expect(root.getAttribute('role')).toBe('region');
    expect(root.getAttribute('aria-label')).toBe('Account');
    const live = doc.getElementById('account-live');
    expect(live.getAttribute('role')).toBe('status');
    expect(live.getAttribute('aria-live')).toBe('polite');
    statusLine(doc, 'Decrypted');
    statusLine(doc, 'Signature not valid', 'The content was changed after signing.', { error: true });
    await flush(1);
    expect(textOf(live)).toBe('Decrypted. Signature not valid. The content was changed after signing.');
    announce(doc, 'Copied');
    await flush(1);
    expect(textOf(live)).toBe('Copied');
  });
});

describe('assets rows', () => {
  it('the toggle is a real button with aria-expanded, and Copy sits beside it, not inside', () => {
    const { panel } = paneFor('assets', createAssetsPane);
    const toggles = panel.querySelectorAll('.asset-toggle');
    expect(toggles).toHaveLength(3);
    for (const toggle of toggles) {
      expect(toggle.localName).toBe('button');
      expect(toggle.getAttribute('aria-expanded')).toBe('false');
      expect(toggle.querySelectorAll('button')).toHaveLength(0);
    }
    expect(panel.querySelectorAll('[role=button]')).toHaveLength(0);
  });

  it('Copy copies without opening the row; the toggle opens it and keeps focus', async () => {
    const { doc, panel } = paneFor('assets', createAssetsPane);
    const copy = panel.querySelectorAll('.asset-row .copy')[0];
    copy.click();
    await flush(2);
    expect(panel.querySelector('.asset-detail')).toBeNull();
    const toggle = panel.querySelectorAll('.asset-toggle')[0];
    toggle.focus();
    toggle.click();
    expect(panel.querySelector('.asset-detail')).not.toBeNull();
    expect(focusKeyOf(doc)).toBe('asset:btc');
    expect(doc.activeElement.getAttribute('aria-expanded')).toBe('true');
    expect(doc.activeElement.getAttribute('aria-controls')).toBe('asset-detail-btc');
  });

  it('balance figures update while a row is open', () => {
    let balance = '0.5';
    const base = createTestContext({ document: new StubDocument() }).assets;
    const assets = { ...base, state: () => ({ ...base.state(), rows: base.state().rows.map((row) => (row.chain === 'btc' ? { ...row, balance } : row)) }) };
    const { panel, ctx } = paneFor('assets', createAssetsPane, { assets });
    panel.querySelectorAll('.asset-toggle')[0].click();
    balance = '1.25';
    ctx.emit('assets');
    expect(textOf(panel.querySelector('.asset-row:not(.asset-head) .asset-balance'))).toBe('1.2500');
    expect(panel.querySelector('.send')).not.toBeNull();
  });
});

describe('focus across re-renders', () => {
  it('Settings: Change moves focus to the account number, Cancel back to Change', () => {
    const { doc, panel } = paneFor('settings', createSettingsPane);
    const change = buttonByText(panel, 'Change');
    change.focus();
    change.click();
    expect(focusKeyOf(doc)).toBe('account-number');
    expect(doc.activeElement.localName).toBe('input');
    buttonByText(panel, 'Cancel').click();
    expect(focusKeyOf(doc)).toBe('account-change');
  });

  it('Settings: Switch keeps focus in the pane, on Change', async () => {
    const { doc, panel } = paneFor('settings', createSettingsPane);
    buttonByText(panel, 'Change').click();
    const number = panel.querySelector('input[type=number]');
    number.value = '1';
    buttonByText(panel, 'Switch').focus();
    buttonByText(panel, 'Switch').click();
    await flush(2);
    expect(textOf(panel)).toContain('Account 1');
    expect(focusKeyOf(doc)).toBe('account-change');
  });

  it('People: expanding a row keeps focus on that row; Remove › Cancel returns to Remove contact', () => {
    const contact = { peerId: `12D3KooW${'A'.repeat(44)}`, name: 'Grace', signingKey: 'a'.repeat(64), encryptionKey: 'b'.repeat(64), addresses: {} };
    const { doc, panel } = paneFor('people', createPeoplePane, { contacts: [contact] });
    const row = panel.querySelector('.person-row');
    row.focus();
    row.click();
    expect(focusKeyOf(doc)).toBe(`person:contact:${contact.peerId}`);
    expect(doc.activeElement.getAttribute('aria-expanded')).toBe('true');
    expect(panel.querySelector('.person-row .chevron').getAttribute('aria-hidden')).toBe('true');
    buttonByText(panel, 'Remove contact').click();
    expect(focusKeyOf(doc)).toBe('remove-cancel');
    buttonByText(panel, 'Cancel').click();
    expect(focusKeyOf(doc)).toBe(`remove:contact:${contact.peerId}`);
  });

  it('People: the Chain and Level chips are labelled groups', () => {
    const { panel } = paneFor('people', createPeoplePane);
    buttonByText(panel, 'Publish trust').click();
    const groups = panel.querySelectorAll('.chips');
    expect(groups.length).toBeGreaterThanOrEqual(2);
    for (const group of groups) {
      expect(group.getAttribute('role')).toBe('group');
      const label = panel.querySelectorAll('.field-label').find((node) => node.id === group.getAttribute('aria-labelledby'));
      expect(['Chain', 'Level']).toContain(textOf(label));
    }
  });

  it('Profile: Edit focuses Name; Cancel returns to Edit profile', () => {
    const doc = new StubDocument();
    const panel = doc.createElement('section');
    doc.body.append(panel);
    const identity = { peerId: `12D3KooW${'B'.repeat(44)}`, edPub: new Uint8Array(32), xPub: new Uint8Array(32) };
    const ctx = createTestContext({ document: doc, profile: { name: 'Ada' } });
    const session = ctx.session;
    ctx.session = () => ({ ...session(), identity });
    const pane = createProfilePane(panel, ctx);
    pane.show();
    buttonByText(panel, 'Edit profile').click();
    expect(focusKeyOf(doc)).toBe('profile-name');
    buttonByText(panel, 'Cancel').click();
    expect(focusKeyOf(doc)).toBe('profile-edit');
  });
});

describe('People in an external-wallet session', () => {
  it('offers no Add contact (contacts need a seed) and says so', () => {
    const { panel } = paneFor('people', createPeoplePane, { kind: 'external' });
    expect(buttonByText(panel, 'Add contact')).toBeNull();
    expect(panel.querySelector('input[type=file]')).toBeNull();
    expect(textOf(panel)).toContain(CONTACTS_SEED_ONLY);
    expect(buttonByText(panel, 'Publish trust')).not.toBeNull();
  });
});
