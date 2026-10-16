// SEC-014 in the Assets pane: Review stays disabled until the recipient and
// the amount parse exactly, the review screen shows the plan's DECODED
// recipient (not the typed text), and Send executes the reviewed plan.
// SEC-015: a wallet opened with the old password method is read-only and
// offers only the guided sweep to a new wallet.

import { describe, expect, it } from 'vitest';

import { createAssetsPane, sendInputProblem } from '../src/assets-ui.js';
import { createTestContext } from './helpers/account-context.mjs';
import { StubDocument, buttonByText, rowValue, textOf } from './helpers/stub-dom.mjs';

const GOOD = '0x52908400098527886E0F7030069857D2E4169EE7';

function mount(options = {}, tweak = () => {}) {
  const doc = new StubDocument();
  const panel = doc.createElement('section');
  doc.body.append(panel);
  const ctx = createTestContext({ document: doc, ...options });
  tweak(ctx);
  const pane = createAssetsPane(panel, ctx);
  pane.show();
  return { panel, ctx, pane };
}

const tick = () => new Promise((resolve) => setTimeout(resolve, 0));

function openEthSend(panel) {
  panel.querySelectorAll('.asset-toggle')[1].click();
  const [to, amount] = panel.querySelectorAll('.send input');
  return { to, amount, review: buttonByText(panel, 'Review') };
}

function type(input, value) {
  input.value = value;
  input.dispatch('input');
}

describe('Send form gate', () => {
  it('keeps Review disabled, with the reason, for every recipient the old ">10 characters" check let through', () => {
    const { panel } = mount();
    const { to, amount, review } = openEthSend(panel);
    type(amount, '0.5');
    for (const bad of ['vitalik.eth', GOOD.slice(0, -1), `${GOOD}x`, `0x0x${GOOD.slice(4)}`, `0x${'0'.repeat(40)}`,
      '0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAeD', 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq']) {
      type(to, bad);
      expect([bad, review.disabled]).toEqual([bad, true]);
      expect(textOf(panel.querySelector('.field-hint'))).not.toBe('');
    }
    type(to, GOOD);
    expect(review.disabled).toBe(false);
    expect(textOf(panel.querySelector('.field-hint'))).toBe('');
  });

  it('refuses amounts that are not plain decimals, or more precise than the asset', () => {
    expect(sendInputProblem('eth', GOOD, '1e18')).toMatch(/plain number/u);
    expect(sendInputProblem('eth', GOOD, '0.0000000000000000001')).toMatch(/18 decimal places/u);
    expect(sendInputProblem('btc', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', '0.000000001')).toMatch(/8 decimal places/u);
    expect(sendInputProblem('btc', '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2', '0.1')).toBeNull();
    expect(sendInputProblem('eth', GOOD, '20')).toBeNull();
  });
});

describe('Review shows the decoded transaction', () => {
  it('shows the recipient and amount read back from the built bytes, and sends that plan', async () => {
    const sent = [];
    const { panel } = mount({}, (ctx) => {
      // The builder's own reading of the transaction (EIP-55 form).
      ctx.assets.prepare = async ({ chain }) => ({
        chain,
        review: { to: GOOD, amount: '0.5 ETH', fee: 'up to 0.000084 ETH', network: 'Ethereum mainnet' },
      });
      ctx.assets.send = async (plan) => { sent.push(plan); return `0x${'d'.repeat(64)}`; };
    });
    const { to, amount, review } = openEthSend(panel);
    type(to, `  ${GOOD.toLowerCase()} `);
    type(amount, '0.5');
    review.click();
    await tick();
    const send = panel.querySelector('.send');
    expect(rowValue(send, 'To')).toBe(GOOD);
    expect(rowValue(send, 'Amount')).toBe('0.5 ETH');
    expect(rowValue(send, 'Network')).toBe('Ethereum mainnet');
    expect(textOf(send)).toContain('read back from the transaction that will be signed');
    buttonByText(panel, 'Send').click();
    await tick();
    expect(sent).toHaveLength(1);
    expect(sent[0].review.to).toBe(GOOD);
  });

  it('a transaction that cannot be built or decoded never reaches the review screen', async () => {
    const { panel } = mount({}, (ctx) => {
      ctx.assets.prepare = async () => {
        throw Object.assign(new Error('The built transaction does not match what you reviewed (recipient). Nothing was sent.'), { code: 'TX_MISMATCH' });
      };
    });
    const { to, amount, review } = openEthSend(panel);
    type(to, GOOD);
    type(amount, '1');
    review.click();
    await tick();
    expect(panel.querySelector('.send-review')).toBeNull();
    expect(textOf(panel.querySelector('.send'))).toContain('does not match what you reviewed (recipient)');
    expect(buttonByText(panel, 'Send')).toBeNull();
  });

  it('a failed send keeps the plan from being sent twice', async () => {
    let attempts = 0;
    const { panel } = mount({}, (ctx) => {
      ctx.assets.send = async () => { attempts += 1; throw new Error('Review the transaction again before sending.'); };
    });
    const { to, amount, review } = openEthSend(panel);
    type(to, GOOD);
    type(amount, '1');
    review.click();
    await tick();
    const send = buttonByText(panel, 'Send');
    send.click();
    await tick();
    expect(attempts).toBe(1);
    expect(send.disabled).toBe(true);
    expect(textOf(panel.querySelector('.send'))).toContain('Not sent');
  });
});

describe('Old password method: read-only with a guided sweep', () => {
  function legacyContext(ctx, log) {
    let destination = null;
    ctx.session = () => ({ kind: 'seed', method: 'password-legacy', readOnly: true, account: 0, identity: null, external: null, addresses: {} });
    ctx.assets.canSend = () => false;
    ctx.migration = {
      active: () => true,
      username: () => 'Alice',
      loadEstimator: async () => {},
      assess: ({ password }) => (password === 'quiver lantern basalt orchid pemmican tundra'
        ? { ok: true, message: '' }
        : { ok: false, message: 'This password is too easy to guess.' }),
      setUp: async ({ username, password }) => {
        log.push(['setUp', username, password]);
        destination = { username: 'alice', btc: '1NewBtcAddressxxxxxxxxxxxxxxxxxxx', eth: '0x1111111111111111111111111111111111111111', sol: 'NewSol1111111111111111111111111111111111111' };
        return destination;
      },
      destination: () => destination,
      prepareSweep: async (chain) => {
        log.push(['prepareSweep', chain]);
        return { chain, review: { to: destination[chain], amount: chain === 'eth' ? '0.29 ETH' : '0.0099 BTC', fee: 'x', network: 'y' } };
      },
      send: async (plan) => { log.push(['send', plan.review.to]); return `0x${'e'.repeat(64)}`; },
    };
  }

  it('Send is replaced by the read-only notice', () => {
    const { panel } = mount({}, (ctx) => legacyContext(ctx, []));
    panel.querySelectorAll('.asset-toggle')[1].click();
    expect(textOf(panel.querySelector('.send'))).toContain('This wallet is read-only.');
    expect(panel.querySelector('.send input')).toBeNull();
  });

  it('sets up the new wallet from a new password (twice, strong enough), then sweeps to it after review', async () => {
    const log = [];
    const { panel } = mount({}, (ctx) => legacyContext(ctx, log));
    const migration = panel.querySelector('.migration');
    expect(textOf(migration)).toContain('Move your funds to a new wallet');
    expect(textOf(migration)).toContain('old password method');
    const [username, password, repeat] = migration.querySelectorAll('input');
    expect(username.value).toBe('Alice');
    expect(password.type).toBe('password');
    const setUp = buttonByText(migration, 'Set up new wallet');
    await tick();
    type(password, 'password123');
    expect(setUp.disabled).toBe(true);
    type(password, 'quiver lantern basalt orchid pemmican tundra');
    type(repeat, 'quiver lantern basalt orchid');
    expect(setUp.disabled).toBe(true);
    expect(textOf(migration.querySelector('.field-hint'))).toBe('The two passwords differ.');
    type(repeat, 'quiver lantern basalt orchid pemmican tundra');
    expect(setUp.disabled).toBe(false);
    setUp.click();
    await tick();
    expect(log[0]).toEqual(['setUp', 'Alice', 'quiver lantern basalt orchid pemmican tundra']);
    const after = panel.querySelector('.migration');
    expect(rowValue(after, 'New Ethereum address')).toBe('0x1111111111111111111111111111111111111111');
    buttonByText(after, 'Move all ETH to the new wallet').click();
    await tick();
    expect(rowValue(after, 'To')).toBe('0x1111111111111111111111111111111111111111');
    buttonByText(after, 'Move ETH').click();
    await tick();
    expect(log).toContainEqual(['send', '0x1111111111111111111111111111111111111111']);
    expect(textOf(after)).toContain('Solana: moving SOL is not supported here yet.');
  });
});
