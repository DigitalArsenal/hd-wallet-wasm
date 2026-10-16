/**
 * Assets: the current account's three addresses, their balances and value.
 *
 * One table row per chain for account N. A row opens inline to Receive (QR,
 * full address, explorer link) and, for Bitcoin and Ethereum, Send. The
 * balance scan covers exactly the three addresses of the current account
 * (ctx.assets.refresh in app.js keeps the 2-minute cache and the fallbacks).
 */

import QRCode from 'qrcode';

import {
  actions,
  button,
  codeBlock,
  copyChip,
  details,
  el,
  field,
  focusKey,
  input,
  muted,
  paneHead,
  relativeTime,
  requestFocus,
  row,
  setBusy,
  statusLine,
  swapPane,
} from './ui-dom.js';
import { chainPaths, shortAddress } from './identity-keys.js';
import {
  BTC_DECIMALS,
  BTC_MAX_SATS,
  UINT256_MAX,
  parseBtcRecipient,
  parseDecimalAmount,
  parseEthRecipient,
} from './send-safety.js';

/** Why the typed recipient/amount cannot be reviewed yet, or null. */
export function sendInputProblem(chain, to, amount) {
  try {
    if (chain === 'eth') parseEthRecipient(to);
    else if (chain === 'btc') parseBtcRecipient(to);
    else return "Sending isn't supported for this asset.";
  } catch (error) {
    return error?.message || 'Check the address.';
  }
  try {
    if (chain === 'eth') parseDecimalAmount(amount, 18, { max: UINT256_MAX, unit: 'ETH' });
    else parseDecimalAmount(amount, BTC_DECIMALS, { max: BTC_MAX_SATS, unit: 'BTC' });
  } catch (error) {
    return error?.message || 'Check the amount.';
  }
  return null;
}

export const ASSET_CHAINS = Object.freeze([
  Object.freeze({ id: 'btc', name: 'Bitcoin', ticker: 'BTC', explorer: 'Blockstream', explorerUrl: 'https://blockstream.info/address/' }),
  Object.freeze({ id: 'eth', name: 'Ethereum', ticker: 'ETH', explorer: 'Etherscan', explorerUrl: 'https://etherscan.io/address/' }),
  Object.freeze({ id: 'sol', name: 'Solana', ticker: 'SOL', explorer: 'Solscan', explorerUrl: 'https://solscan.io/account/' }),
]);

export const SOL_SEND_UNSUPPORTED = "Sending SOL isn't supported yet.";

export function formatBalance(balance) {
  const value = Number.parseFloat(balance);
  if (!Number.isFinite(value)) return '--';
  if (value === 0) return '0';
  return value.toFixed(value < 0.001 ? 8 : 4);
}

/** The pane lede: total value and when, or "Balances not checked yet". */
export function assetsLede(state, now = Date.now()) {
  if (!state?.updatedAt) return 'Balances not checked yet';
  const total = state.totalText ?? '--';
  return `Total value ${total} · Updated ${relativeTime(state.updatedAt, now)}`;
}

/**
 * @param {HTMLElement} panel  #account-pane-assets
 * @param {object} ctx
 */
export function createAssetsPane(panel, ctx) {
  const doc = panel.ownerDocument ?? ctx.document;
  let expanded = null;
  let sendStep = null;
  let generation = 0;
  // Typing a new password or reviewing a sweep keeps the pane's DOM: a
  // balance update then moves only the figures (like an open row).
  let migrationEngaged = false;
  let ledeEl = null;
  let spokenError = '';

  function stale(token) {
    return token !== generation || !ctx.isCurrent();
  }

  function receiveBlock(chain, address) {
    const block = el(doc, 'div', 'receive');
    block.append(el(doc, 'h3', 'sub-head', 'Receive'));
    const qrWrap = el(doc, 'div', 'qr');
    const canvas = el(doc, 'canvas');
    canvas.width = 160;
    canvas.height = 160;
    canvas.setAttribute('aria-label', `QR code for the ${chain.name} address`);
    qrWrap.append(canvas);
    const token = generation;
    try {
      Promise.resolve(QRCode.toCanvas(canvas, address, {
        width: 160,
        margin: 1,
        color: { dark: '#000000', light: '#ffffff' },
      })).catch(() => { if (!stale(token)) qrWrap.hidden = true; });
    } catch {
      qrWrap.hidden = true;
    }
    const link = el(doc, 'a', 'explorer-link', `View on ${chain.explorer}`);
    link.href = chain.explorerUrl + encodeURIComponent(address);
    link.target = '_blank';
    link.rel = 'noopener noreferrer';
    block.append(qrWrap, codeBlock(doc, { label: `${chain.name} address`, value: address }).block, link);
    return block;
  }

  function sendBlock(chain, assetRow) {
    const block = el(doc, 'div', 'send');
    block.append(el(doc, 'h3', 'sub-head', 'Send'));
    if (chain.id === 'sol') {
      block.append(muted(doc, SOL_SEND_UNSUPPORTED));
      return block;
    }
    if (!ctx.assets.canSend(chain.id)) {
      block.append(muted(doc, ctx.session().readOnly
        ? 'This wallet is read-only. Move its funds to a new wallet (above).'
        : 'Sending needs a seed-phrase session.'));
      return block;
    }
    const token = generation;
    const to = input(doc, { placeholder: `${chain.name} address` });
    const amount = input(doc, { type: 'text', placeholder: `0.00 ${chain.ticker}` });
    amount.setAttribute('inputmode', 'decimal');
    const max = button(doc, 'Max', { variant: 'link' });
    const amountField = field(doc, 'Amount', amount);
    amountField.append(max);
    max.setAttribute('aria-label', `Send the whole ${chain.ticker} balance`);
    const feeLine = muted(doc, chain.id === 'btc' ? 'Network fee: 10,000 sats' : 'Network fee: estimating…');
    const review = button(doc, 'Review', { variant: 'primary' });
    const result = el(doc, 'div', 'inline-result');

    if (chain.id !== 'btc') {
      Promise.resolve(ctx.assets.feeLine(chain.id)).then((text) => {
        if (!stale(token)) feeLine.textContent = text;
      }).catch(() => {
        if (!stale(token)) feeLine.textContent = 'Network fee: unavailable';
      });
    }

    const hint = el(doc, 'p', 'field-hint');
    hint.id = `send-hint-${chain.id}-${generation}`;
    hint.setAttribute('aria-live', 'polite');
    to.setAttribute('aria-describedby', hint.id);
    amount.setAttribute('aria-describedby', hint.id);

    // Review is enabled only for a recipient and an amount that parse
    // exactly (send-safety.js); the reason is shown under the fields.
    const validate = () => {
      const problem = sendInputProblem(chain.id, to.value, amount.value);
      review.disabled = problem !== null;
      hint.textContent = problem && (to.value.trim() || amount.value.trim()) ? problem : '';
      to.setAttribute('aria-invalid', problem && to.value.trim() && sendInputProblem(chain.id, to.value, '1') ? 'true' : 'false');
    };
    to.addEventListener('input', validate);
    amount.addEventListener('input', validate);
    max.addEventListener('click', () => {
      const balance = String(assetRow.balance ?? '').trim();
      if (/^\d+(?:\.\d+)?$/u.test(balance) && Number.parseFloat(balance) > 0) {
        amount.value = balance;
        validate();
      }
    });
    validate();

    const compose = el(doc, 'div', 'send-compose');
    compose.append(field(doc, 'To address', to), amountField, feeLine, hint, actions(doc, review), result);

    review.addEventListener('click', async () => {
      const typed = { to: to.value, amount: amount.value };
      setBusy(review, true, 'Checking…');
      result.replaceChildren();
      let plan;
      try {
        plan = await ctx.assets.prepare({ chain: chain.id, to: typed.to, amount: typed.amount });
      } catch (error) {
        if (stale(token)) return;
        setBusy(review, false);
        result.replaceChildren(statusLine(doc, 'Not ready', error?.message || 'This transaction could not be built.', { error: true }));
        return;
      }
      if (stale(token)) return;
      setBusy(review, false);
      sendStep = { plan };
      const reviewed = reviewBlock(chain, plan, {
        onBack: () => {
          sendStep = null;
          step.replaceChildren(compose);
          review.focus?.();
        },
        onSend: (reviewedPlan) => ctx.assets.send(reviewedPlan),
        token,
      });
      step.replaceChildren(reviewed.node);
      reviewed.focus();
    });

    const step = el(doc, 'div', 'send-step');
    step.append(compose);
    block.append(step);
    return block;
  }

  /**
   * The review screen: every value shown is DECODED from the built,
   * unsigned transaction (plan.review), never the typed text.
   */
  function reviewBlock(chain, plan, { onBack, onSend, token, sendLabel = 'Send' }) {
    const confirm = el(doc, 'div', 'send-review');
    const rows = el(doc, 'div', 'rows');
    rows.append(
      row(doc, 'To', plan.review.to, { mono: true }),
      row(doc, 'Amount', plan.review.amount),
      row(doc, 'Network fee', plan.review.fee),
      row(doc, 'Network', plan.review.network),
    );
    const note = muted(doc, 'Check the address character by character. The recipient and amount above are read back from the transaction that will be signed.');
    const send = button(doc, sendLabel, { variant: 'primary' });
    const back = button(doc, 'Back');
    const sendResult = el(doc, 'div', 'inline-result');
    back.addEventListener('click', onBack);
    send.addEventListener('click', async () => {
      setBusy(send, true, 'Sending…');
      back.disabled = true;
      try {
        const txHash = await onSend(plan);
        if (stale(token)) return;
        setBusy(send, false);
        send.disabled = true;
        sendResult.replaceChildren(statusLine(doc, 'Sent', shortAddress(txHash, 10, 6)));
      } catch (error) {
        if (stale(token)) return;
        setBusy(send, false);
        send.disabled = true;
        back.disabled = false;
        sendResult.replaceChildren(statusLine(doc, 'Not sent', error?.message || 'The transaction failed.', { error: true }));
      }
    });
    confirm.append(rows, note, actions(doc, send, back), sendResult);
    return { node: confirm, focus: () => send.focus?.() };
  }

  /**
   * Old password method (read-only session): set up the new wallet from a
   * new password (scrypt profile), then sweep BTC and ETH to it. Every sweep
   * goes through the same decoded review as Send.
   */
  function migrationBlock() {
    const token = generation;
    const block = el(doc, 'section', 'migration');
    block.setAttribute('aria-labelledby', `migration-head-${token}`);
    const engage = () => { migrationEngaged = true; };
    block.addEventListener('input', engage);
    block.addEventListener('click', engage);
    const head = el(doc, 'h3', 'sub-head', 'Move your funds to a new wallet');
    head.id = `migration-head-${token}`;
    block.append(
      head,
      muted(doc, 'This wallet was made with the old password method, which computers can guess quickly, so it is open read-only. Choose a new password (it is stretched with scrypt), move each balance to the new wallet, then sign in with the new password. This old wallet keeps opening read-only, so anything left here stays reachable.'),
    );
    const destination = ctx.migration.destination();
    if (!destination) {
      const username = input(doc, { value: ctx.migration.username() });
      username.setAttribute('autocapitalize', 'none');
      const password = input(doc, { type: 'password' });
      const repeat = input(doc, { type: 'password' });
      const hint = el(doc, 'p', 'field-hint');
      hint.id = `migration-hint-${token}`;
      hint.setAttribute('aria-live', 'polite');
      password.setAttribute('aria-describedby', hint.id);
      const setUp = button(doc, 'Set up new wallet', { variant: 'primary' });
      const result = el(doc, 'div', 'inline-result');
      const check = () => {
        if (!password.value) {
          hint.textContent = '';
          setUp.disabled = true;
          return;
        }
        const assessment = ctx.migration.assess({ username: username.value, password: password.value });
        let message = assessment.ok ? 'Strong enough for a password wallet.' : assessment.message;
        let ok = assessment.ok;
        if (ok && repeat.value !== password.value) {
          ok = false;
          message = repeat.value ? 'The two passwords differ.' : 'Type the new password again.';
        }
        hint.textContent = message;
        hint.classList.toggle('is-ok', ok);
        setUp.disabled = !ok;
      };
      for (const node of [username, password, repeat]) node.addEventListener('input', check);
      Promise.resolve(ctx.migration.loadEstimator()).then(() => { if (!stale(token)) check(); }, () => {
        if (!stale(token)) hint.textContent = 'The password checker could not load, so a new wallet cannot be set up right now.';
      });
      setUp.disabled = true;
      setUp.addEventListener('click', async () => {
        setBusy(setUp, true, 'Deriving…');
        result.replaceChildren();
        try {
          await ctx.migration.setUp({ username: username.value, password: password.value });
          password.value = '';
          repeat.value = '';
          if (stale(token)) return;
          render();
        } catch (error) {
          if (stale(token)) return;
          setBusy(setUp, false);
          result.replaceChildren(statusLine(doc, 'Not set up', error?.message || 'The new wallet could not be derived.', { error: true }));
        }
      });
      block.append(
        field(doc, 'Username for the new wallet', username),
        field(doc, 'New password', password),
        field(doc, 'New password again', repeat),
        hint,
        muted(doc, 'Write the new password down somewhere safe. Anyone who learns it and your username can take the funds, and nobody can recover it for you.'),
        actions(doc, setUp),
        result,
      );
      return block;
    }
    const rows = el(doc, 'div', 'rows');
    rows.append(
      row(doc, 'New wallet username', destination.username),
      row(doc, 'New Bitcoin address', destination.btc, { mono: true }),
      row(doc, 'New Ethereum address', destination.eth, { mono: true }),
      row(doc, 'New Solana address', destination.sol, { mono: true }),
    );
    block.append(rows);
    for (const chain of ASSET_CHAINS.filter((candidate) => candidate.id !== 'sol')) {
      const area = el(doc, 'div', 'migration-chain');
      const move = button(doc, `Move all ${chain.ticker} to the new wallet`);
      const result = el(doc, 'div', 'inline-result');
      move.addEventListener('click', async () => {
        setBusy(move, true, 'Checking…');
        result.replaceChildren();
        let plan;
        try {
          plan = await ctx.migration.prepareSweep(chain.id);
        } catch (error) {
          if (stale(token)) return;
          setBusy(move, false);
          result.replaceChildren(statusLine(doc, 'Not ready', error?.message || 'This transaction could not be built.', { error: true }));
          return;
        }
        if (stale(token)) return;
        setBusy(move, false);
        const reviewed = reviewBlock(chain, plan, {
          onBack: () => {
            area.replaceChildren(move, result);
            move.focus?.();
          },
          onSend: (reviewedPlan) => ctx.migration.send(reviewedPlan),
          token,
          sendLabel: `Move ${chain.ticker}`,
        });
        area.replaceChildren(reviewed.node);
        reviewed.focus();
      });
      area.append(move, result);
      block.append(area);
    }
    block.append(muted(doc, 'Solana: moving SOL is not supported here yet. Your SOL stays reachable through this read-only sign-in.'));
    return block;
  }

  function assetRow(entry, state) {
    const chain = ASSET_CHAINS.find((candidate) => candidate.id === entry.chain);
    const item = el(doc, 'div', 'asset');
    const line = el(doc, 'div', 'asset-row');
    const open = expanded === entry.chain;
    if (open) line.classList.add('is-open');

    // The keyboard and screen-reader control is the asset name, a real
    // <button aria-expanded>. The rest of the row is a mouse target only, and
    // the Copy chip sits beside the button, never inside it.
    const asset = focusKey(el(doc, 'button', 'asset-name asset-toggle'), `asset:${entry.chain}`);
    asset.type = 'button';
    asset.setAttribute('aria-expanded', open ? 'true' : 'false');
    asset.setAttribute('aria-controls', `asset-detail-${entry.chain}`);
    asset.append(el(doc, 'span', 'asset-title', chain.name), el(doc, 'span', 'asset-ticker', chain.ticker));
    const address = el(doc, 'span', 'asset-address');
    const addressText = el(doc, 'span', 'mono', shortAddress(entry.address, 6, 4));
    addressText.title = entry.address;
    address.append(addressText, copyChip(doc, () => entry.address, { what: `${chain.name} address` }));
    const balance = el(doc, 'span', 'asset-balance', formatBalance(entry.balance));
    const value = el(doc, 'span', 'asset-value', entry.valueText ?? '');
    line.append(asset, address, balance, value);

    const toggle = () => {
      expanded = open ? null : entry.chain;
      sendStep = null;
      requestFocus(panel, `asset:${entry.chain}`);
      render();
    };
    asset.addEventListener('click', (event) => {
      event?.stopPropagation?.();
      toggle();
    });
    line.addEventListener('click', (event) => {
      // Clicks on the row's own controls (Copy) are theirs.
      if (event?.target?.closest?.('button, a, input') && event.target !== line) return;
      toggle();
    });
    item.append(line);
    if (open) {
      const body = el(doc, 'div', 'asset-detail');
      body.id = `asset-detail-${entry.chain}`;
      body.append(receiveBlock(chain, entry.address), sendBlock(chain, entry));
      item.append(body);
    }
    void state;
    return item;
  }

  function render() {
    generation += 1;
    migrationEngaged = false;
    const state = ctx.assets.state();
    const wrap = el(doc, 'div', 'pane');
    const { head, ledeEl: lede } = paneHead(doc, {
      eyebrow: 'Assets',
      title: 'Addresses and balances',
      lede: assetsLede(state),
    });
    ledeEl = lede;
    wrap.append(head);
    if (ctx.session().readOnly && ctx.migration?.active?.()) wrap.append(migrationBlock());

    const table = el(doc, 'div', 'asset-table');
    const header = el(doc, 'div', 'asset-row asset-head');
    header.append(
      el(doc, 'span', 'asset-name', 'Asset'),
      el(doc, 'span', 'asset-address', 'Address'),
      el(doc, 'span', 'asset-balance', 'Balance'),
      el(doc, 'span', 'asset-value', 'Value'),
    );
    table.append(header);
    for (const entry of state.rows) table.append(assetRow(entry, state));
    wrap.append(table);

    if (state.error) {
      wrap.append(statusLine(doc, 'Not updated', state.error, { error: true, speak: state.error !== spokenError }));
    }
    spokenError = state.error || '';
    const refresh = button(doc, state.scanning ? 'Refreshing…' : 'Refresh balances');
    refresh.disabled = Boolean(state.scanning);
    refresh.addEventListener('click', () => { void ctx.assets.refresh({ force: true }); });
    wrap.append(actions(doc, refresh));

    if (ctx.session().kind === 'seed') {
      const paths = chainPaths(ctx.session().account);
      const list = el(doc, 'div', 'rows');
      list.append(
        row(doc, 'Bitcoin', paths.btc, { mono: true }),
        row(doc, 'Ethereum', paths.eth, { mono: true }),
        row(doc, 'Solana', paths.sol, { mono: true }),
      );
      wrap.append(details(doc, [list]).node);
    }
    swapPane(panel, wrap);
  }

  function updateFigures(state) {
    // While a row is open (a send in progress keeps its DOM), only the lede
    // and the figures move.
    if (ledeEl) ledeEl.textContent = assetsLede(state);
    for (const entry of state.rows ?? []) {
      const toggle = [...panel.querySelectorAll('[data-focus-key]')]
        .find((node) => node.getAttribute('data-focus-key') === `asset:${entry.chain}`);
      const line = toggle?.parentNode;
      if (!line) continue;
      const balance = line.querySelector('.asset-balance');
      const value = line.querySelector('.asset-value');
      if (balance) balance.textContent = formatBalance(entry.balance);
      if (value) value.textContent = entry.valueText ?? '';
    }
  }

  const unsubscribe = ctx.on?.('assets', () => {
    if (panel.hidden) return;
    // A send or receive in progress keeps its DOM; only the lede and figures move.
    if (expanded || migrationEngaged) {
      updateFigures(ctx.assets.state());
      return;
    }
    render();
  });

  return Object.freeze({
    render,
    show() {
      render();
      void ctx.assets.refresh({ force: false });
    },
    reset() {
      generation += 1;
      migrationEngaged = false;
      expanded = null;
      sendStep = null;
      panel.replaceChildren();
    },
    destroy() { unsubscribe?.(); },
    get expanded() { return expanded; },
  });
}
