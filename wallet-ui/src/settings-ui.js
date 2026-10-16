/**
 * Settings: display currency, the account number, key export, sign out and
 * forget-this-wallet.
 *
 * The account number N (0–99) selects the whole identity: SDN peer ID,
 * signing and encryption keys, contacts, trust and the three addresses.
 * Switching it re-derives everything (ctx.settings.switchAccount).
 *
 * The account xprv is shown only after an explicit Reveal, hides itself after
 * 60 seconds, and is removed from the DOM on any section switch (reset()).
 * Copying it overwrites the clipboard 30 seconds later (clipboard.js).
 */

import {
  actions,
  button,
  codeBlock,
  details,
  el,
  field,
  focusKey,
  input,
  muted,
  paneHead,
  requestFocus,
  row,
  select,
  statusLine,
  swapPane,
} from './ui-dom.js';
import { CURRENCIES } from './account-storage.js';
import { MAX_ACCOUNT, accountKeyPath } from './identity-keys.js';

export const REVEAL_MS = 60 * 1000;
export const ACCOUNT_HELP = 'Each account number gives a separate identity, peer ID, contacts and set of addresses from the same seed. Most people only use account 0.';
export const REVEAL_WARNING = 'Anyone with this key controls every address in this account.';
export const XPRV_NOTE = 'This key hides itself in 60 seconds. If you copy it, the clipboard is cleared after 30 seconds; clipboard history or sync can still keep a copy, so paste it only where it belongs.';
export const FORGET_WARNING = 'This removes your profile, contacts and trust history for this seed from this browser.';

/**
 * @param {HTMLElement} panel  #account-pane-settings
 * @param {object} ctx
 * @param {{ setTimer?: Function, clearTimer?: Function }} [timers]
 */
export function createSettingsPane(panel, ctx, {
  setTimer = (fn, ms) => globalThis.setTimeout(fn, ms),
  clearTimer = (id) => globalThis.clearTimeout(id),
  copySecret,
} = {}) {
  const doc = panel.ownerDocument ?? ctx.document;
  let changing = false;
  let revealStep = 'hidden'; // 'hidden' | 'confirm' | 'shown'
  let forgetting = false;
  let revealTimer = null;
  let notice = null;
  let generation = 0;

  function hideKey() {
    if (revealTimer !== null) clearTimer(revealTimer);
    revealTimer = null;
    revealStep = 'hidden';
  }

  function currencyRow() {
    const currency = select(doc, CURRENCIES.map((code) => ({ value: code, label: code })), ctx.settings.currency());
    currency.setAttribute('aria-label', 'Currency');
    currency.classList.add('select-inline');
    currency.addEventListener('change', () => ctx.settings.setCurrency(currency.value));
    return row(doc, 'Currency', currency);
  }

  function accountBlock() {
    const account = ctx.session().account;
    const block = el(doc, 'div', 'setting');
    const value = el(doc, 'span', 'row-value');
    value.append(doc.createTextNode(`Account ${account} `));
    const change = focusKey(button(doc, 'Change', { variant: 'link' }), 'account-change');
    change.setAttribute('aria-label', 'Change account number');
    change.addEventListener('click', () => {
      changing = true;
      requestFocus(panel, 'account-number');
      render();
    });
    if (!changing) value.append(change);
    const line = el(doc, 'div', 'row');
    line.append(el(doc, 'span', 'row-label', 'Account'), value);
    block.append(line);
    if (changing) {
      const number = focusKey(input(doc, { type: 'number', value: String(account) }), 'account-number');
      number.min = '0';
      number.max = String(MAX_ACCOUNT);
      number.step = '1';
      const error = el(doc, 'p', 'field-error');
      error.hidden = true;
      const switchButton = button(doc, 'Switch', { variant: 'primary' });
      const cancel = button(doc, 'Cancel');
      cancel.addEventListener('click', () => {
        changing = false;
        requestFocus(panel, 'account-change');
        render();
      });
      switchButton.addEventListener('click', async () => {
        const next = Number(number.value);
        if (!Number.isInteger(next) || next < 0 || next > MAX_ACCOUNT) {
          error.textContent = `Choose a whole number from 0 to ${MAX_ACCOUNT}.`;
          error.hidden = false;
          return;
        }
        switchButton.disabled = true;
        try {
          await ctx.settings.switchAccount(next);
          changing = false;
          notice = { word: 'Switched', message: `Account ${next}` };
          requestFocus(panel, 'account-change');
        } catch (failure) {
          notice = { word: 'Not switched', message: failure?.message || 'The account could not be switched.', error: true };
          requestFocus(panel, 'account-number');
        }
        render();
      });
      const form = el(doc, 'div', 'setting-form');
      form.append(field(doc, 'Account number', number), error, muted(doc, ACCOUNT_HELP), actions(doc, switchButton, cancel));
      block.append(form);
    }
    return block;
  }

  function exportKeys() {
    const account = ctx.session().account;
    const children = [
      el(doc, 'h3', 'sub-head', 'Export keys'),
      codeBlock(doc, { label: accountKeyPath(account), value: ctx.keys.accountXpub() }).block,
    ];
    if (revealStep === 'hidden') {
      const reveal = focusKey(button(doc, 'Reveal private key', { variant: 'link' }), 'reveal');
      reveal.addEventListener('click', () => {
        revealStep = 'confirm';
        requestFocus(panel, 'reveal-cancel');
        render({ openDetails: true });
      });
      const line = el(doc, 'p', 'reveal-line');
      line.append(reveal);
      children.push(line);
    } else if (revealStep === 'confirm') {
      const confirm = el(doc, 'div', 'inline-confirm');
      const yes = button(doc, 'Reveal', { variant: 'danger', small: true });
      const no = focusKey(button(doc, 'Cancel', { small: true }), 'reveal-cancel');
      yes.addEventListener('click', () => {
        revealStep = 'shown';
        if (revealTimer !== null) clearTimer(revealTimer);
        revealTimer = setTimer(() => {
          revealTimer = null;
          if (revealStep !== 'shown') return;
          revealStep = 'hidden';
          render({ openDetails: true });
        }, REVEAL_MS);
        requestFocus(panel, 'xprv');
        render({ openDetails: true });
      });
      no.addEventListener('click', () => {
        revealStep = 'hidden';
        requestFocus(panel, 'reveal');
        render({ openDetails: true });
      });
      confirm.append(el(doc, 'p', 'alert-text', REVEAL_WARNING), actions(doc, yes, no));
      children.push(confirm);
    } else {
      const secret = codeBlock(doc, {
        label: `xprv · ${accountKeyPath(account)}`,
        value: ctx.keys.accountXprv(),
        className: 'secret',
        // SEC-081: a copied key is overwritten on the clipboard after 30 s.
        copyOptions: copySecret ? { secret: true, copy: copySecret } : { secret: true },
      }).block;
      focusKey(secret.querySelector('.copy'), 'xprv');
      children.push(secret);
      children.push(muted(doc, XPRV_NOTE));
    }
    return children;
  }

  function forgetBlock() {
    const block = el(doc, 'div', 'setting');
    if (!forgetting) {
      const forget = focusKey(button(doc, 'Forget this wallet on this device', { variant: 'danger-link' }), 'forget');
      forget.addEventListener('click', () => {
        forgetting = true;
        requestFocus(panel, 'forget-cancel');
        render();
      });
      const line = el(doc, 'p', 'forget-line');
      line.append(forget);
      block.append(line);
      return block;
    }
    const confirm = el(doc, 'div', 'inline-confirm');
    const yes = button(doc, 'Forget', { variant: 'danger', small: true });
    const no = focusKey(button(doc, 'Cancel', { small: true }), 'forget-cancel');
    yes.addEventListener('click', () => ctx.settings.forget());
    no.addEventListener('click', () => {
      forgetting = false;
      requestFocus(panel, 'forget');
      render();
    });
    confirm.append(el(doc, 'p', null, FORGET_WARNING), actions(doc, yes, no));
    block.append(confirm);
    return block;
  }

  function render({ openDetails = false } = {}) {
    generation += 1;
    const seed = ctx.session().kind === 'seed';
    const wrap = el(doc, 'div', 'pane');
    const { head } = paneHead(doc, {
      eyebrow: 'Settings',
      title: 'Settings',
      lede: 'Display, account and keys for this wallet.',
    });
    wrap.append(head);
    if (notice) {
      // A notice stays on screen across re-renders; it is read out once.
      wrap.append(statusLine(doc, notice.word, notice.message, { error: Boolean(notice.error), speak: !notice.spoken }));
      notice.spoken = true;
    }
    const rows = el(doc, 'div', 'rows');
    rows.append(currencyRow());
    if (seed) rows.append(accountBlock());
    wrap.append(rows);
    if (seed) {
      const more = details(doc, exportKeys());
      if (openDetails || revealStep !== 'hidden') more.node.open = true;
      wrap.append(more.node);
    }
    const signOut = button(doc, 'Sign out');
    signOut.addEventListener('click', () => ctx.settings.signOut());
    wrap.append(actions(doc, signOut));
    if (seed) wrap.append(forgetBlock());
    swapPane(panel, wrap);
  }

  return Object.freeze({
    render,
    show() { render(); },
    reset() {
      generation += 1;
      hideKey();
      changing = false;
      forgetting = false;
      notice = null;
      panel.replaceChildren();
    },
    destroy() { hideKey(); },
    get revealStep() { return revealStep; },
  });
}
