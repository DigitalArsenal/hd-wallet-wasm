// Assets: one refresh scans exactly the current account's three addresses,
// the 2-minute cache is respected, and the pane offers Send for Bitcoin and
// Ethereum only.

import initHDWallet from 'hd-wallet-wasm';
import { describe, expect, it } from 'vitest';

import { createBalanceScanner } from '../src/balances.js';
import { ASSET_CHAINS, SOL_SEND_UNSUPPORTED, assetsLede, createAssetsPane, formatBalance } from '../src/assets-ui.js';
import { chainPaths, deriveAccountAddresses } from '../src/identity-keys.js';
import { createTestContext } from './helpers/account-context.mjs';
import { StubDocument, buttonByText, rowValue, textOf } from './helpers/stub-dom.mjs';

const wallet = await initHDWallet();
const seed = wallet.mnemonic.toSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const root = wallet.hdkey.fromSeed(seed);

function scanner({ clock, responses = {} } = {}) {
  const calls = [];
  let cache = {};
  const fetcher = (chain) => async (address) => {
    calls.push([chain, address]);
    const response = responses[chain];
    if (typeof response === 'function') return response(address);
    return response ?? { balance: '1.5' };
  };
  const instance = createBalanceScanner({
    fetchers: { btc: fetcher('btc'), eth: fetcher('eth'), sol: fetcher('sol') },
    readCache: () => cache,
    writeCache: (next) => { cache = next; },
    now: () => clock.now,
    sleep: async (ms) => { clock.now += ms; },
  });
  return { instance, calls, cache: () => cache };
}

function targetsFor(account) {
  const addresses = deriveAccountAddresses(wallet, root, account);
  return ['btc', 'eth', 'sol'].map((chain) => ({ chain, address: addresses[chain].address }));
}

describe('balance scan', () => {
  it('one refresh makes exactly 3 balance requests, for account N’s addresses', async () => {
    const clock = { now: 1_000_000 };
    const { instance, calls } = scanner({ clock });
    const targets = targetsFor(2);
    const result = await instance.scan(targets, () => true);
    expect(calls).toEqual(targets.map(({ chain, address }) => [chain, address]));
    expect(result).toEqual({ balances: { btc: '1.5', eth: '1.5', sol: '1.5' }, failures: 0, cancelled: false });
    expect(targets.map((t) => t.address)).not.toEqual(targetsFor(0).map((t) => t.address));
  });

  it('respects the 2-minute cache, and Refresh with force asks again', async () => {
    const clock = { now: 1_000_000 };
    const { instance, calls } = scanner({ clock });
    const targets = targetsFor(0);
    await instance.scan(targets, () => true);
    expect(calls).toHaveLength(3);
    clock.now += 60 * 1000;
    await instance.scan(targets, () => true);
    expect(calls).toHaveLength(3);
    await instance.scan(targets, () => true, { force: true });
    expect(calls).toHaveLength(6);
    clock.now += 3 * 60 * 1000;
    await instance.scan(targets, () => true);
    expect(calls).toHaveLength(9);
  });

  it('falls back to a stale cached balance when the network fails, and stops when the session ends', async () => {
    const clock = { now: 1_000_000 };
    let fail = false;
    const { instance } = scanner({
      clock,
      responses: { btc: () => (fail ? { error: 'HTTP 500' } : { balance: '0.25' }) },
    });
    const [btc] = targetsFor(0);
    await instance.scan([btc], () => true);
    fail = true;
    clock.now += 10 * 60 * 1000;
    const stale = await instance.fetchBalance(btc, () => true);
    expect(stale).toMatchObject({ ok: true, balance: '0.25', stale: true });
    let live = true;
    const cancelled = instance.scan(targetsFor(0), () => live, { force: true });
    live = false;
    expect((await cancelled).cancelled).toBe(true);
  });

  it('cools a rate-limited chain down and serves its cache meanwhile', async () => {
    const clock = { now: 1_000_000 };
    let limited = false;
    const { instance, calls } = scanner({
      clock,
      responses: { eth: () => (limited ? { error: '429 Too Many Requests' } : { balance: '2' }) },
    });
    const eth = targetsFor(0)[1];
    await instance.fetchBalance(eth, () => true);
    limited = true;
    await instance.fetchBalance(eth, () => true, { force: true });
    const before = calls.length;
    const cooled = await instance.fetchBalance(eth, () => true, { force: true });
    expect(calls.length).toBe(before);
    expect(cooled).toMatchObject({ ok: true, balance: '2', source: 'cache' });
  });
});

describe('Assets pane', () => {
  function mount(options = {}) {
    const doc = new StubDocument();
    const panel = doc.createElement('section');
    doc.body.append(panel);
    const refreshes = [];
    const ctx = createTestContext({ document: doc, ...options });
    const original = ctx.assets.refresh;
    ctx.assets.refresh = async (opts) => { refreshes.push(opts); return original(opts); };
    const pane = createAssetsPane(panel, ctx);
    pane.show();
    return { panel, ctx, pane, refreshes };
  }

  it('one row per chain with balance and value, a lede before the first scan, and the paths in Details', () => {
    const { panel, refreshes } = mount();
    expect(refreshes).toEqual([{ force: false }]);
    expect(textOf(panel.querySelector('.lede'))).toBe('Balances not checked yet');
    const rows = panel.querySelectorAll('.asset-row:not(.asset-head)');
    expect(rows.map((row) => textOf(row.querySelector('.asset-title')))).toEqual(['Bitcoin', 'Ethereum', 'Solana']);
    expect(textOf(rows[0].querySelector('.asset-balance'))).toBe('0.5000');
    expect(textOf(rows[1].querySelector('.asset-balance'))).toBe('--');
    expect(textOf(rows[0].querySelector('.asset-value'))).toBe('$10.00');
    const details = panel.querySelector('details.more');
    expect(rowValue(details, 'Bitcoin')).toBe(chainPaths(0).btc);
    expect(rowValue(details, 'Ethereum')).toBe(chainPaths(0).eth);
    expect(rowValue(details, 'Solana')).toBe(chainPaths(0).sol);
    buttonByText(panel, 'Refresh balances').click();
    expect(refreshes.at(-1)).toEqual({ force: true });
  });

  it('a row opens Receive and, for Bitcoin and Ethereum, Send; Solana has no Send', () => {
    const { panel } = mount();
    const rows = () => panel.querySelectorAll('.asset-toggle');
    rows()[0].click();
    expect(textOf(panel.querySelector('.receive'))).toContain('View on Blockstream');
    expect(panel.querySelector('.receive canvas')).not.toBeNull();
    expect(textOf(panel.querySelector('.send'))).toContain('To address');
    expect(textOf(panel.querySelector('.send'))).toContain('Network fee: 10,000 sats');
    rows()[2].click();
    expect(textOf(panel.querySelector('.send'))).toBe(`Send${SOL_SEND_UNSUPPORTED}`);
    expect(panel.querySelector('.send input')).toBeNull();
  });

  it('Send goes through Review, then Send or Back', async () => {
    const { panel, ctx } = mount();
    const sent = [];
    ctx.assets.send = async (request) => { sent.push(request); return 'd'.repeat(64); };
    panel.querySelectorAll('.asset-toggle')[0].click();
    const inputs = panel.querySelectorAll('.send input');
    inputs[0].value = 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh';
    inputs[0].dispatch('input');
    inputs[1].value = '0.1';
    inputs[1].dispatch('input');
    buttonByText(panel, 'Review').click();
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(rowValue(panel.querySelector('.send'), 'Amount')).toBe('0.1 BTC');
    buttonByText(panel, 'Back').click();
    expect(panel.querySelector('.send input').value).toBe('bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh');
    buttonByText(panel, 'Review').click();
    await new Promise((resolve) => setTimeout(resolve, 0));
    buttonByText(panel, 'Send').click();
    await new Promise((resolve) => setTimeout(resolve, 0));
    // Send executes the reviewed plan, not the typed text.
    expect(sent).toHaveLength(1);
    expect(sent[0].review).toMatchObject({ to: 'bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh', amount: '0.1 BTC' });
    expect(textOf(panel.querySelector('.send'))).toContain('Sent');
  });

  it('formats balances and the lede', () => {
    expect(formatBalance('--')).toBe('--');
    expect(formatBalance('0')).toBe('0');
    expect(formatBalance('0.0001')).toBe('0.00010000');
    expect(assetsLede({ updatedAt: 0 })).toBe('Balances not checked yet');
    expect(assetsLede({ updatedAt: 1000, totalText: '$5.00' }, 2000)).toBe('Total value $5.00 · Updated just now');
    expect(ASSET_CHAINS.map((chain) => chain.ticker)).toEqual(['BTC', 'ETH', 'SOL']);
  });
});
