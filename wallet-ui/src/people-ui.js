/**
 * People: contacts (signed $EPM cards) merged with on-chain trust records.
 *
 * A contact comes only from a contact card whose signature, peer address and
 * chain proofs check out (contact-card.js). An on-chain trust relationship
 * joins a contact when its address equals one of the contact's verified
 * chain-proof addresses; otherwise it is listed as "On-chain only".
 *
 * Trust records are published and revoked with the CURRENT account's keys
 * (ctx.trust in app.js); the scan runs when People opens (at most once per two
 * minutes) and on Refresh — never in the background.
 *
 * Everything other people wrote (names, addresses, photos) is set through
 * textContent or as a validated Blob URL; nothing here parses markup.
 */

import {
  actions,
  button,
  chip,
  copyChip,
  el,
  focusKey,
  field,
  filePicker,
  input,
  muted,
  paneHead,
  relativeTime,
  requestFocus,
  row,
  select,
  setBusy,
  setPressed,
  statusLine,
  swapPane,
} from './ui-dom.js';
import { initialsOf, photoBytesFromDataUrl } from './contact-card.js';
import { shortAddress, shortPeerId } from './identity-keys.js';
import { PhotoUrlController } from '../origin-app/photo.mjs';

export const TRUST_WORDS = Object.freeze({ 5: 'Ultimate', 4: 'Full', 3: 'Marginal', 1: 'Never' });
export const PUBLISH_LEVELS = Object.freeze([
  Object.freeze({ level: 5, label: 'Ultimate' }),
  Object.freeze({ level: 4, label: 'Full' }),
  Object.freeze({ level: 3, label: 'Marginal' }),
  Object.freeze({ level: 1, label: 'Never' }),
]);
export const CHAINS = Object.freeze([
  Object.freeze({ id: 'btc', label: 'Bitcoin' }),
  Object.freeze({ id: 'eth', label: 'Ethereum' }),
  Object.freeze({ id: 'sol', label: 'Solana' }),
]);
const CHAIN_LABEL = Object.freeze({ btc: 'Bitcoin', eth: 'Ethereum', sol: 'Solana' });
const EXPLORER_TX = Object.freeze({
  btc: 'https://blockstream.info/tx/',
  eth: 'https://etherscan.io/tx/',
  sol: 'https://solscan.io/tx/',
});

export const EMPTY_PEOPLE = 'No contacts yet. Ask someone for their contact card (.epm), then choose Add contact.';
export const CONTACTS_SEED_ONLY = 'Sign in with a seed phrase to add contacts.';
/**
 * SEC-056: a contact card is signed by its own key, so the card proves the
 * peer ID and the listed addresses belong together, not who the person is.
 */
export const SELF_ASSERTED_NOTE = 'The name and details are what the card’s owner typed. The card proves only that this peer ID holds the keys and addresses listed; check the peer ID with the person before you rely on the name.';

/** 'bitcoin' | 'btc' | 'ethereum' | ... → 'btc' | 'eth' | 'sol' | null */
export function chainSlug(value) {
  const c = String(value ?? '').toLowerCase();
  if (c.startsWith('bitcoin') || c === 'btc') return 'btc';
  if (c.startsWith('ethereum') || c === 'eth') return 'eth';
  if (c.startsWith('solana') || c === 'sol') return 'sol';
  return null;
}

/** The chain an address belongs to, from its format alone. */
export function detectChainFromAddress(address) {
  const value = String(address ?? '').trim();
  if (/^(?:1|3)[a-km-zA-HJ-NP-Z1-9]{25,34}$/u.test(value) || /^bc1[a-z0-9]{25,90}$/u.test(value)) return 'btc';
  if (/^0x[0-9a-fA-F]{40}$/u.test(value)) return 'eth';
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/u.test(value)) return 'sol';
  return null;
}

export function explorerTxUrl(chain, hash) {
  const slug = chainSlug(chain);
  if (!slug || typeof hash !== 'string' || !/^[A-Za-z0-9]{16,128}$/u.test(hash)) return null;
  return EXPLORER_TX[slug] + hash;
}

function sameAddress(a, b) {
  if (!a || !b) return false;
  const left = String(a);
  const right = String(b);
  return /^0x/iu.test(left) ? left.toLowerCase() === right.toLowerCase() : left === right;
}

/**
 * Contacts merged with trust relationships. A relationship joins the contact
 * that holds its address among the contact's verified chain-proof addresses.
 *
 * @returns {Array<{ key, contact, relationships, addresses, name, peerId, level, drained }>}
 */
export function mergePeople(contacts = [], relationships = []) {
  const entries = [];
  const used = new Set();
  for (const contact of contacts) {
    const addresses = contact.addresses ?? {};
    const owned = relationships.filter((rel, index) => {
      const match = Object.values(addresses).some((address) => sameAddress(address, rel.address));
      if (match) used.add(index);
      return match;
    });
    entries.push(personEntry({ contact, relationships: owned }));
  }
  relationships.forEach((rel, index) => {
    if (used.has(index)) return;
    entries.push(personEntry({ contact: null, relationships: [rel] }));
  });
  return entries;
}

function personEntry({ contact, relationships }) {
  const latest = [...relationships].sort((a, b) => (b.lastSeen ?? 0) - (a.lastSeen ?? 0))[0] ?? null;
  const addresses = { ...(contact?.addresses ?? {}) };
  if (!contact && latest?.address) {
    const chain = chainSlug(latest.chain) ?? detectChainFromAddress(latest.address);
    if (chain) addresses[chain] = latest.address;
  }
  return {
    key: contact ? `contact:${contact.peerId}` : `address:${latest?.address}`,
    contact,
    relationships,
    addresses,
    name: contact?.name ?? '',
    peerId: contact?.peerId ?? '',
    level: latest?.level ?? null,
    drained: relationships.some((rel) => rel.drained),
  };
}

/** The second line of a person row: peer or "On-chain only", trust word, Drained. */
export function personSubline(entry) {
  const parts = [entry.contact ? shortPeerId(entry.peerId) : 'On-chain only'];
  const word = TRUST_WORDS[entry.level];
  if (word) parts.push(word);
  return parts.join(' · ');
}

/**
 * @param {HTMLElement} panel  #account-pane-people
 * @param {object} ctx
 */
export function createPeoplePane(panel, ctx) {
  const doc = panel.ownerDocument ?? ctx.document;
  let view = 'list';
  let expanded = null;
  let confirming = null;
  let notice = null;
  let generation = 0;
  const photoControllers = [];

  function stale(token) {
    return token !== generation || !ctx.isCurrent();
  }

  function releasePhotos() {
    while (photoControllers.length) {
      try { photoControllers.pop().destroy(); } catch { /* revoked */ }
    }
  }

  function avatar(entry) {
    const node = el(doc, 'span', 'person-avatar');
    const bytes = entry.contact?.photo ? photoBytesFromDataUrl(entry.contact.photo) : null;
    if (bytes) {
      const controller = new PhotoUrlController();
      photoControllers.push(controller);
      const token = generation;
      controller.replace(bytes).then((url) => {
        if (stale(token)) return;
        const image = el(doc, 'img');
        image.alt = '';
        image.src = url;
        image.onerror = () => { controller.imageError(url); image.remove(); };
        node.replaceChildren(image);
      }).catch(() => { /* initials stay */ });
    }
    const initials = initialsOf(entry.name);
    node.append(el(doc, 'span', 'avatar-initials', initials));
    return node;
  }

  function trustRows(entry) {
    const list = el(doc, 'div', 'trust-history');
    const transactions = entry.relationships.flatMap((rel) => (rel.transactions?.length ? rel.transactions : [rel]));
    if (transactions.length === 0) {
      list.append(muted(doc, 'No published trust records.'));
      return list;
    }
    for (const tx of transactions) {
      const line = el(doc, 'div', 'history-row');
      const date = Number(tx.timestamp) ? new Date(Number(tx.timestamp)).toLocaleDateString() : '—';
      const chain = CHAIN_LABEL[chainSlug(tx.chain)] ?? 'Unknown chain';
      const word = TRUST_WORDS[tx.level] ?? 'Unknown';
      line.append(el(doc, 'span', null, `${date} · ${chain} · ${word}${tx.direction === 'inbound' ? ' (to you)' : ''}`));
      const url = explorerTxUrl(tx.chain, tx.txHash || tx.hash);
      if (url) {
        const link = el(doc, 'a', 'link-btn', 'View');
        link.href = url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        line.append(doc.createTextNode(' '), link);
      }
      list.append(line);
    }
    return list;
  }

  function expandedBody(entry) {
    const body = el(doc, 'div', 'person-detail');
    const rows = el(doc, 'div', 'rows');
    if (entry.contact) {
      const peer = el(doc, 'span', 'with-copy');
      const peerText = el(doc, 'span', 'mono', shortPeerId(entry.peerId));
      peerText.title = entry.peerId;
      peer.append(peerText, copyChip(doc, () => entry.peerId, { what: 'peer ID' }));
      rows.append(row(doc, 'Peer ID', peer));
      if (entry.contact.encryptionKey) {
        const key = el(doc, 'span', 'with-copy');
        key.append(el(doc, 'span', 'mono', shortAddress(entry.contact.encryptionKey, 8, 6)), copyChip(doc, () => entry.contact.encryptionKey, { what: 'encryption key' }));
        rows.append(row(doc, 'Encryption key', key));
      }
    }
    const addressLines = el(doc, 'div', 'address-lines');
    let addressCount = 0;
    for (const { id, label } of CHAINS) {
      if (!entry.addresses[id]) continue;
      addressLines.append(el(doc, 'div', 'mono', `${label} ${entry.addresses[id]}`));
      addressCount += 1;
    }
    if (addressCount) rows.append(row(doc, 'Addresses', addressLines));
    rows.append(row(doc, 'Trust history', trustRows(entry)));
    body.append(rows);
    if (entry.contact) body.append(muted(doc, SELF_ASSERTED_NOTE));

    const buttons = [];
    if (entry.contact?.encryptionKey) {
      const encrypt = button(doc, 'Encrypt a message', { variant: 'primary' });
      encrypt.addEventListener('click', () => ctx.showSection('messages', { intent: { mode: 'encrypt', peerId: entry.peerId } }));
      buttons.push(encrypt);
    }
    if (Object.keys(entry.addresses).length && ctx.trust.canPublish()) {
      const publish = button(doc, 'Publish trust');
      publish.addEventListener('click', () => openPublish(entry));
      buttons.push(publish);
    }
    const active = Object.values(entry.addresses).map((address) => ctx.trust.outboundRecord(address)).find(Boolean);
    if (active && ctx.trust.canPublish()) {
      const revoke = button(doc, 'Revoke trust');
      focusKey(revoke, `revoke:${entry.key}`);
      revoke.addEventListener('click', () => {
        confirming = { kind: 'revoke', key: entry.key };
        requestFocus(panel, 'revoke-cancel');
        render();
      });
      buttons.push(revoke);
    }
    if (buttons.length) body.append(actions(doc, ...buttons));

    if (confirming?.key === entry.key && confirming.kind === 'revoke' && active) {
      body.append(revokeConfirm(active, entry.key));
    }
    if (entry.contact) {
      if (confirming?.key === entry.key && confirming.kind === 'remove') {
        const confirm = el(doc, 'div', 'inline-confirm');
        confirm.append(el(doc, 'p', null, `Remove ${entry.name || shortPeerId(entry.peerId)}?`));
        const yes = button(doc, 'Remove', { variant: 'danger', small: true });
        const no = button(doc, 'Cancel', { small: true });
        focusKey(no, 'remove-cancel');
        yes.addEventListener('click', () => {
          ctx.contacts.remove(entry.peerId);
          confirming = null;
          expanded = null;
          requestFocus(panel, 'people-add');
          render();
        });
        no.addEventListener('click', () => {
          confirming = null;
          requestFocus(panel, `remove:${entry.key}`);
          render();
        });
        confirm.append(actions(doc, yes, no));
        body.append(confirm);
      } else {
        const remove = button(doc, 'Remove contact', { variant: 'danger-link' });
        focusKey(remove, `remove:${entry.key}`);
        remove.addEventListener('click', () => {
          confirming = { kind: 'remove', key: entry.key };
          requestFocus(panel, 'remove-cancel');
          render();
        });
        const line = el(doc, 'p', 'remove-line');
        line.append(remove);
        body.append(line);
      }
    }
    return body;
  }

  function revokeConfirm(record, entryKey) {
    const token = generation;
    const chain = chainSlug(record.chain);
    const box = el(doc, 'div', 'inline-confirm');
    box.append(el(doc, 'p', null, `This publishes a permanent revocation on ${CHAIN_LABEL[chain] ?? 'its chain'}.`));
    const yes = button(doc, 'Revoke', { variant: 'danger', small: true });
    const no = button(doc, 'Cancel', { small: true });
    const result = el(doc, 'div', 'inline-result');
    yes.addEventListener('click', async () => {
      setBusy(yes, true, 'Publishing…');
      try {
        const { txHash } = await ctx.trust.revoke(record);
        if (stale(token)) return;
        notice = { word: 'Revocation published', message: shortAddress(txHash, 10, 6) };
        confirming = null;
        requestFocus(panel, `person:${entryKey}`);
        render();
      } catch (error) {
        if (stale(token)) return;
        setBusy(yes, false);
        result.replaceChildren(statusLine(doc, 'Not published', error?.message || 'The revocation failed.', { error: true }));
      }
    });
    focusKey(no, 'revoke-cancel');
    no.addEventListener('click', () => {
      confirming = null;
      requestFocus(panel, `revoke:${entryKey}`);
      render();
    });
    box.append(actions(doc, yes, no), result);
    return box;
  }

  function personRow(entry) {
    const item = el(doc, 'div', 'person');
    const head = el(doc, 'button', 'person-row');
    head.type = 'button';
    focusKey(head, `person:${entry.key}`);
    const open = expanded === entry.key;
    head.setAttribute('aria-expanded', open ? 'true' : 'false');
    const text = el(doc, 'span', 'person-text');
    const title = entry.contact
      ? el(doc, 'span', 'person-name', entry.name || shortPeerId(entry.peerId))
      : el(doc, 'span', 'person-name mono', shortAddress(Object.values(entry.addresses)[0] ?? '', 8, 6));
    const sub = el(doc, 'span', 'person-sub', personSubline(entry));
    if (entry.drained) {
      sub.append(doc.createTextNode(' · '), el(doc, 'span', 'alert-text', 'Drained'));
    }
    text.append(title, sub);
    const chevron = el(doc, 'span', 'chevron', open ? '⌃' : '⌄');
    chevron.setAttribute('aria-hidden', 'true');
    head.append(avatar(entry), text, chevron);
    head.addEventListener('click', () => {
      expanded = open ? null : entry.key;
      confirming = null;
      render();
    });
    item.append(head);
    if (open) item.append(expandedBody(entry));
    return item;
  }

  async function importCard(file) {
    const token = generation;
    try {
      const contact = await ctx.contacts.importFile(file);
      if (stale(token)) return;
      notice = {
        word: 'Added',
        message: `${contact.name ? `${contact.name} (name as typed by the card’s owner)` : shortPeerId(contact.peerId)} · ${shortPeerId(contact.peerId)}`,
      };
      expanded = `contact:${contact.peerId}`;
      requestFocus(panel, `person:contact:${contact.peerId}`);
    } catch (error) {
      if (stale(token)) return;
      notice = { word: 'Not added', message: error?.message || 'This is not an SDS contact card (.epm).', error: true };
    }
    render();
  }

  function renderList(wrap) {
    // Contacts are stored per seed (hdw:<fp>:a<N>:contacts); an external
    // wallet session has no seed fingerprint, so it shows trust records only.
    const seed = (ctx.session?.()?.kind ?? 'seed') === 'seed';
    const head = [];
    let picker = null;
    if (seed) {
      picker = filePicker(doc, '.epm,application/octet-stream', importCard);
      const add = focusKey(button(doc, 'Add contact', { variant: 'primary' }), 'people-add');
      add.addEventListener('click', picker.open);
      head.push(add);
    }
    if (ctx.trust.canPublish()) {
      const publish = focusKey(button(doc, 'Publish trust'), 'people-publish');
      publish.addEventListener('click', () => openPublish(null));
      head.push(publish);
    }
    if (head.length) {
      const headActions = actions(doc, ...head);
      headActions.classList.add('head-actions');
      wrap.append(headActions);
    }
    if (picker) wrap.append(picker.input);
    if (!seed) wrap.append(muted(doc, CONTACTS_SEED_ONLY));
    if (notice) {
      // A notice stays on screen across re-renders; it is read out once.
      wrap.append(statusLine(doc, notice.word, notice.message, { error: Boolean(notice.error), speak: !notice.spoken }));
      notice.spoken = true;
    }

    const state = ctx.trust.state();
    const people = mergePeople(ctx.contacts.list(), state.relationships ?? []);
    const list = el(doc, 'div', 'people-list');
    if (people.length === 0 && seed) list.append(el(doc, 'p', 'empty', EMPTY_PEOPLE));
    for (const entry of people) list.append(personRow(entry));
    wrap.append(list);

    const footer = el(doc, 'p', 'pane-footer');
    let checked;
    if (state.scanning) checked = 'Checking…';
    else if (state.error) checked = 'Check delayed';
    else if (state.checkedAt) checked = `Checked ${relativeTime(state.checkedAt)}`;
    else checked = 'Not checked yet';
    footer.append(doc.createTextNode(`${checked} · `));
    const refresh = focusKey(button(doc, 'Refresh', { variant: 'link' }), 'people-refresh');
    refresh.disabled = Boolean(state.scanning);
    refresh.addEventListener('click', () => { void ctx.trust.refresh({ force: true }); });
    footer.append(refresh);
    wrap.append(footer);
  }

  let publishTarget = null;

  function openPublish(entry) {
    view = 'publish';
    publishTarget = entry;
    notice = null;
    requestFocus(panel, 'publish-who');
    render();
  }

  function closePublish() {
    const key = publishTarget ? `person:${publishTarget.key}` : 'people-publish';
    view = 'list';
    publishTarget = null;
    requestFocus(panel, key);
    render();
  }

  function renderPublish(wrap) {
    const token = generation;
    const back = button(doc, '‹ People', { variant: 'link' });
    back.addEventListener('click', closePublish);
    const backLine = el(doc, 'p', 'back-line');
    backLine.append(back);
    wrap.append(backLine);
    wrap.append(el(doc, 'h3', 'sub-head', 'Publish trust'));

    const contacts = ctx.contacts.list().filter((contact) => Object.keys(contact.addresses ?? {}).length);
    const whoOptions = contacts.map((contact) => ({ value: `contact:${contact.peerId}`, label: contact.name || shortPeerId(contact.peerId) }));
    whoOptions.push({ value: 'paste', label: 'Paste an address…' });
    const initial = publishTarget?.contact ? `contact:${publishTarget.contact.peerId}` : (whoOptions[0]?.value ?? 'paste');
    const who = focusKey(select(doc, whoOptions, initial), 'publish-who');
    const pasted = input(doc, { placeholder: 'Bitcoin, Ethereum or Solana address' });
    if (publishTarget && !publishTarget.contact) {
      who.value = 'paste';
      pasted.value = Object.values(publishTarget.addresses)[0] ?? '';
    }
    const pastedField = field(doc, 'Address', pasted);
    const chainRow = el(doc, 'div', 'chips');
    const levelRow = el(doc, 'div', 'chips');
    const feeLine = muted(doc, '');
    const result = el(doc, 'div', 'inline-result');
    const publish = button(doc, 'Publish', { variant: 'primary' });
    const cancel = button(doc, 'Cancel');
    cancel.addEventListener('click', closePublish);

    let chain = null;
    let level = 4;
    let feeToken = 0;

    function counterpartyAddresses() {
      if (who.value === 'paste') {
        const value = pasted.value.trim();
        const detected = detectChainFromAddress(value);
        return detected ? { [detected]: value } : {};
      }
      const contact = contacts.find((entry) => `contact:${entry.peerId}` === who.value);
      return { ...(contact?.addresses ?? {}) };
    }

    function updateFee() {
      const token2 = ++feeToken;
      if (!chain) {
        feeLine.textContent = '';
        return;
      }
      feeLine.textContent = `Network fee about … This publishes a public record on ${CHAIN_LABEL[chain]}.`;
      Promise.resolve(ctx.trust.feeEstimate(chain)).then((fee) => {
        if (token2 !== feeToken || stale(token)) return;
        feeLine.textContent = `Network fee about ${fee}. This publishes a public record on ${CHAIN_LABEL[chain]}.`;
      }).catch(() => {
        if (token2 !== feeToken || stale(token)) return;
        feeLine.textContent = `Network fee unknown. This publishes a public record on ${CHAIN_LABEL[chain]}.`;
      });
    }

    function renderChains() {
      const available = counterpartyAddresses();
      const allowed = CHAINS.filter(({ id }) => available[id] && ctx.trust.supportsChain(id));
      if (!allowed.some(({ id }) => id === chain)) chain = allowed[0]?.id ?? null;
      const nodes = allowed.map(({ id, label }) => {
        const node = chip(doc, label, id === chain);
        node.addEventListener('click', () => {
          chain = id;
          setPressed(nodes, node);
          updateFee();
        });
        return node;
      });
      chainRow.replaceChildren(...nodes);
      if (nodes.length === 0) chainRow.append(muted(doc, 'No chain available for this address.', 'span'));
      pastedField.hidden = who.value !== 'paste';
      publish.disabled = !chain;
      updateFee();
    }

    const levelNodes = PUBLISH_LEVELS.map(({ level: value, label }) => {
      const node = chip(doc, label, value === level);
      node.addEventListener('click', () => {
        level = value;
        setPressed(levelNodes, node);
      });
      return node;
    });
    levelRow.append(...levelNodes);
    who.addEventListener('change', renderChains);
    pasted.addEventListener('input', renderChains);

    publish.addEventListener('click', async () => {
      const recipientAddress = counterpartyAddresses()[chain];
      if (!chain || !recipientAddress) return;
      setBusy(publish, true, 'Publishing…');
      try {
        const { txHash } = await ctx.trust.publish({ network: chain, level, recipientAddress });
        if (stale(token)) return;
        notice = { word: 'Published', message: `${CHAIN_LABEL[chain]} · ${shortAddress(txHash, 10, 6)}` };
        closePublish();
      } catch (error) {
        if (stale(token)) return;
        setBusy(publish, false);
        result.replaceChildren(statusLine(doc, 'Not published', error?.message || 'The trust record could not be published.', { error: true }));
      }
    });

    wrap.append(
      field(doc, 'Who', who),
      pastedField,
      labelled('Chain', chainRow, 'chain'),
      labelled('Level', levelRow, 'level'),
      feeLine,
      actions(doc, publish, cancel),
      result,
    );
    renderChains();
  }

  let groupSequence = 0;

  function labelled(label, node, id) {
    const wrapper = el(doc, 'div', 'field');
    const labelEl = el(doc, 'span', 'field-label', label);
    labelEl.id = `people-${id}-label-${++groupSequence}`;
    node.setAttribute('role', 'group');
    node.setAttribute('aria-labelledby', labelEl.id);
    wrapper.append(labelEl, node);
    return wrapper;
  }

  function render() {
    generation += 1;
    releasePhotos();
    const wrap = el(doc, 'div', 'pane');
    const { head } = paneHead(doc, {
      eyebrow: 'People',
      title: 'Contacts and trust',
      lede: 'Add people from their contact cards to encrypt to them and check their signatures.',
    });
    wrap.append(head);
    if (view === 'publish') renderPublish(wrap);
    else renderList(wrap);
    swapPane(panel, wrap);
  }

  const unsubscribe = ctx.on?.('trust', () => { if (!panel.hidden && view === 'list') render(); });
  const unsubscribeContacts = ctx.on?.('contacts', () => { if (!panel.hidden && view === 'list') render(); });

  return Object.freeze({
    render,
    show() {
      render();
      void ctx.trust.refresh({ force: false });
    },
    reset() {
      generation += 1;
      view = 'list';
      expanded = null;
      confirming = null;
      notice = null;
      publishTarget = null;
      releasePhotos();
      panel.replaceChildren();
    },
    destroy() {
      unsubscribe?.();
      unsubscribeContacts?.();
      releasePhotos();
    },
    get view() { return view; },
  });
}
