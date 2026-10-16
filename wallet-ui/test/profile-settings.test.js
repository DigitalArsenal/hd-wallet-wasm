// Profile and Settings panes on a stub DOM with the real per-account keys.

import initHDWallet from 'hd-wallet-wasm';
import { describe, expect, it } from 'vitest';

import { createProfilePane, profileRows, SEED_ONLY } from '../src/profile-ui.js';
import { ACCOUNT_HELP, FORGET_WARNING, REVEAL_MS, REVEAL_WARNING, createSettingsPane } from '../src/settings-ui.js';
import { createTestContext } from './helpers/account-context.mjs';
import { StubDocument, buttonByText, flush, rowValue, textOf } from './helpers/stub-dom.mjs';

const wallet = await initHDWallet();
const seed = wallet.mnemonic.toSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const root = wallet.hdkey.fromSeed(seed);

function mount(create, options = {}, extra) {
  const doc = new StubDocument();
  const panel = doc.createElement('section');
  doc.body.append(panel);
  const ctx = createTestContext({ document: doc, wasm: wallet, seed, hdRoot: root, ...options });
  const pane = create(panel, ctx, extra);
  pane.show(options.intent);
  return { doc, panel, ctx, pane };
}

describe('Profile', () => {
  it('lists only the non-empty fields and joins the address', () => {
    expect(profileRows({ name: 'Ada', email: '', city: 'London', country: 'UK' })).toEqual([
      ['Name', 'Ada'],
      ['Address', 'London, UK'],
    ]);
  });

  it('view mode: head, rows, actions and Details with the peer ID and both keys', () => {
    const { panel } = mount(createProfilePane, { profile: { name: 'Ada Lovelace', organization: 'Analytical Engines' } });
    expect(textOf(panel.querySelector('.eyebrow'))).toBe('Profile');
    expect(textOf(panel.querySelector('.pane-title'))).toBe('Ada Lovelace');
    expect(textOf(panel.querySelector('.lede'))).toBe('This is what people see when you share your contact card.');
    expect(rowValue(panel, 'Organization')).toBe('Analytical Engines');
    expect(rowValue(panel, 'Email')).toBeNull();
    expect(buttonByText(panel, 'Edit profile')).not.toBeNull();
    expect(buttonByText(panel, 'Download contact card')).not.toBeNull();
    const labels = panel.querySelectorAll('details.more .code .label').map(textOf);
    expect(labels).toEqual(['Peer ID', "Ed25519 · m/44'/0'/0'/0'/0'", "X25519 · m/44'/0'/0'/1'/0'"]);
    const values = panel.querySelectorAll('details.more .code pre').map(textOf);
    expect(values).toEqual([
      '12D3KooWJB7pwCc5pMGNVykovHTSMHGTxiQBEFBVwsgFoAmMkmWZ',
      '7c2e79f3a1701fb2a86a2c24a3fdf8634b7aad80886c0c0a526d44d23fe8e19a',
      '654f607c4395ac0599a6c38bc34315dd6644f405218daa4ec5318068f008a364',
    ]);
    expect(panel.querySelectorAll('details.more')).toHaveLength(1);
  });

  it('an empty profile says so and is titled Your profile', () => {
    const { panel } = mount(createProfilePane);
    expect(textOf(panel.querySelector('.pane-title'))).toBe('Your profile');
    expect(textOf(panel)).toContain('No details yet.');
  });

  it('edit mode replaces the view in place; Save stores, Cancel discards', () => {
    const { panel, ctx } = mount(createProfilePane, { profile: { name: 'Ada' } });
    buttonByText(panel, 'Edit profile').click();
    const labels = panel.querySelectorAll('.field label').map(textOf);
    expect(labels).toEqual(['Name', 'Job title', 'Organization', 'Email', 'Phone', 'Street', 'City', 'State or region', 'Postal code', 'Country']);
    expect(panel.querySelectorAll('input').find((input) => input.type === 'email')).toBeTruthy();
    expect(panel.querySelectorAll('input').find((input) => input.type === 'tel')).toBeTruthy();
    expect(buttonByText(panel, 'Upload photo')).not.toBeNull();
    expect(buttonByText(panel, 'Remove photo').hidden).toBe(true);
    const inputs = panel.querySelectorAll('.field input');
    inputs[1].value = 'Analyst';
    inputs[1].dispatch('input');
    buttonByText(panel, 'Cancel').click();
    expect(ctx.state.profile.jobTitle).toBeUndefined();
    buttonByText(panel, 'Edit profile').click();
    const again = panel.querySelectorAll('.field input');
    again[1].value = 'Analyst';
    again[1].dispatch('input');
    buttonByText(panel, 'Save').click();
    expect(ctx.state.profile).toMatchObject({ name: 'Ada', jobTitle: 'Analyst' });
    expect(rowValue(panel, 'Job title')).toBe('Analyst');
  });

  it('"Add your name" opens edit mode', () => {
    const { pane } = mount(createProfilePane, { intent: { edit: true } });
    expect(pane.mode).toBe('edit');
  });

  it('downloads the contact card the context builds', async () => {
    const { panel, ctx } = mount(createProfilePane, { profile: { name: 'Ada' } });
    buttonByText(panel, 'Download contact card').click();
    await flush();
    expect(ctx.state.downloads.at(-1)).toMatchObject({ name: 'contact.epm', mime: 'application/octet-stream' });
  });

  it('an external-wallet session sees one line', () => {
    const { panel } = mount(createProfilePane, { kind: 'external' });
    expect(textOf(panel)).toContain(SEED_ONLY);
    expect(buttonByText(panel, 'Edit profile')).toBeNull();
  });
});

describe('Settings', () => {
  function fakeTimers() {
    const timers = new Map();
    let next = 1;
    return {
      setTimer: (fn, ms) => { timers.set(next, { fn, ms }); return next++; },
      clearTimer: (id) => timers.delete(id),
      runAll() {
        for (const [id, timer] of [...timers]) {
          timers.delete(id);
          timer.fn();
        }
      },
      timers,
    };
  }

  it('rows: Currency, Account; Details with the account xpub; Sign out; Forget', () => {
    const { panel } = mount(createSettingsPane);
    expect(textOf(panel.querySelector('.pane-title'))).toBe('Settings');
    const currency = panel.querySelector('select');
    expect(currency.childNodes.map(textOf)).toEqual(['USD', 'EUR', 'GBP', 'JPY', 'CHF', 'CAD', 'AUD']);
    expect(textOf(panel)).toContain('Account 0');
    expect(textOf(panel.querySelector('details.more .code .label'))).toBe("m/44'/0'/0'");
    expect(textOf(panel.querySelector('details.more .code pre'))).toMatch(/^xpub/u);
    expect(buttonByText(panel, 'Sign out')).not.toBeNull();
    expect(buttonByText(panel, 'Forget this wallet on this device')).not.toBeNull();
  });

  it('Change › Switch moves to another account number', async () => {
    const { panel, ctx } = mount(createSettingsPane);
    buttonByText(panel, 'Change').click();
    expect(textOf(panel)).toContain(ACCOUNT_HELP);
    const number = panel.querySelector('input[type=number]');
    number.value = '100';
    buttonByText(panel, 'Switch').click();
    await flush();
    expect(textOf(panel)).toContain('Choose a whole number from 0 to 99.');
    number.value = '1';
    buttonByText(panel, 'Switch').click();
    await flush();
    expect(ctx.state.account).toBe(1);
    expect(textOf(panel)).toContain('Account 1');
  });

  it('reveals the account xprv only after a warning, and hides it after 60 s and on a section switch', () => {
    const timers = fakeTimers();
    const { panel, pane } = mount(createSettingsPane, {}, timers);
    buttonByText(panel, 'Reveal private key').click();
    expect(textOf(panel)).toContain(REVEAL_WARNING);
    expect(textOf(panel)).not.toMatch(/xprv[0-9A-Za-z]{20}/u);
    buttonByText(panel, 'Reveal').click();
    expect(textOf(panel)).toMatch(/xprv[0-9A-Za-z]{20}/u);
    expect([...timers.timers.values()].map((timer) => timer.ms)).toEqual([REVEAL_MS]);
    timers.runAll();
    expect(pane.revealStep).toBe('hidden');
    expect(textOf(panel)).not.toMatch(/xprv[0-9A-Za-z]{20}/u);

    buttonByText(panel, 'Reveal private key').click();
    buttonByText(panel, 'Reveal').click();
    expect(textOf(panel)).toMatch(/xprv/u);
    pane.reset();
    expect(textOf(panel)).toBe('');
    expect(timers.timers.size).toBe(0);
    pane.show();
    expect(textOf(panel)).not.toMatch(/xprv[0-9A-Za-z]{20}/u);
  });

  it('Forget asks first, then forgets; Sign out signs out', () => {
    const calls = [];
    const { panel } = mount(createSettingsPane, {
      settings: {
        currency: () => 'EUR',
        setCurrency: (code) => calls.push(['currency', code]),
        switchAccount: async () => {},
        signOut: () => calls.push(['signOut']),
        forget: () => calls.push(['forget']),
      },
    });
    expect(panel.querySelector('select').value).toBe('EUR');
    panel.querySelector('select').value = 'GBP';
    panel.querySelector('select').dispatch('change');
    buttonByText(panel, 'Forget this wallet on this device').click();
    expect(textOf(panel)).toContain(FORGET_WARNING);
    buttonByText(panel, 'Forget').click();
    buttonByText(panel, 'Sign out').click();
    expect(calls).toEqual([['currency', 'GBP'], ['forget'], ['signOut']]);
  });

  it('an external-wallet session sees Currency and Sign out only', () => {
    const { panel } = mount(createSettingsPane, { kind: 'external' });
    expect(panel.querySelector('select')).not.toBeNull();
    expect(buttonByText(panel, 'Sign out')).not.toBeNull();
    expect(buttonByText(panel, 'Change')).toBeNull();
    expect(panel.querySelector('details.more')).toBeNull();
    expect(buttonByText(panel, 'Forget this wallet on this device')).toBeNull();
  });
});
