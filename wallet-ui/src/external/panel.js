/*
 * CONNECT WALLET PANEL — the external-wallet component every app mounts
 * (owner 2026-08-20: the external wallet code lives in hd-wallet-ui and is
 * used "only as a component in all apps"; owner 2026-08-19: external wallet
 * is the FIRST sign-in path, the HD wallet is the backup).
 *
 * DESIGN SOURCE (IRIS): the rendered form and copy of spaceaware-ui's
 * ConnectWalletPanel.svelte (hand-authored 2026-08-19, styled on the
 * Student-UI theme via the dashboard's PROVENANCE.json chain). This file is
 * that panel as a framework-free DOM component; the Svelte panel becomes a
 * thin mount wrapper over it. Default styling (styles/external-panel.css)
 * carries the dashboard palette through CSS custom properties — hosts skin
 * with the --hdw-ext-* variables, never by forking markup.
 *
 * KEY-ROLE GRAMMAR (IRIS 2026-08-19): an external wallet is VALUE the user
 * attaches, never AUTHORITY. Attachment chrome only — the copy says
 * "connected", never "unlocked"; no presence dot, no bond rollup.
 *
 * CUSTODY: the wallet holds the key. This panel sees addresses and
 * normalized provider info only, persists nothing, loads zero external
 * bytes (icons are data: URIs or nothing — enforced in accounts.js), and
 * imports NOTHING from the HD custody core.
 *
 * All rendering is textContent/appendChild — wallet-supplied strings are
 * hostile by assumption and never reach innerHTML.
 */

import { createDiscovery } from './discovery.js';
import { connectEvm, connectSolana, normalizeProviderError } from './provider.js';
import { chainLabel } from './chains.js';
import { truncateMiddle } from './format.js';

/** Plain product copy (IRIS: the built-in wallet is the backup METHOD,
 *  not a position on the page). */
const COPY = Object.freeze({
  scanning: 'SCANNING FOR WALLETS…',
  noWalletTitle: 'NO WALLET DETECTED',
  noWalletBody:
    "Open this page inside a wallet's browser, or install a wallet extension — or sign in with the built-in wallet.",
  connecting: 'CONNECTING…',
  connected: 'CONNECTED',
  disconnect: 'DISCONNECT',
  copied: 'COPIED',
  emptyAccount: 'The wallet connected but shared no account.',
  rejected: 'Request declined in the wallet.',
  pending: 'Check your wallet — a request is already open there.',
  disconnected: 'The wallet is not connected to a network.',
});

function describeWalletError(err) {
  const { kind, message } = normalizeProviderError(err);
  if (kind === 'rejected') return COPY.rejected;
  if (kind === 'pending') return COPY.pending;
  if (kind === 'disconnected') return COPY.disconnected;
  return message;
}

/**
 * Mount the connect-wallet panel into `mount` and start discovery.
 *
 * @param {{
 *   mount: Element,                       // REQUIRED — the panel renders here
 *   onConnected?: (account: {lane, address, addressKey, chainId,
 *                            walletName, icon}) => void,
 *   connectedView?: boolean,              // render the connected account
 *                                         // in-panel (copyable address +
 *                                         // disconnect). Default false: the
 *                                         // host owns the session surface
 *                                         // and this panel only hands up.
 *   document?: Document,
 *   events?: EventTarget, globals?: object,
 *   schedule?: Function, unschedule?: Function,  // discovery test ports
 * }} options
 * @returns {{ destroy: () => void }}
 */
export function createExternalWalletPanel({
  mount,
  onConnected = null,
  connectedView = false,
  document: doc = globalThis.document,
  events,
  globals,
  schedule,
  unschedule,
} = {}) {
  if (!mount || typeof mount.appendChild !== 'function') {
    throw new Error('createExternalWalletPanel needs a mount element.');
  }

  const el = (tag, className, text) => {
    const node = doc.createElement(tag);
    if (className) node.className = className;
    if (text !== undefined) node.textContent = text;
    return node;
  };

  let discovered = { evm: [], solana: [], legacy: null, settled: false };
  let connecting = '';
  let notice = '';
  let connected = null; // the connectedView-only state; hosts hand up instead

  const root = el('div', 'hdw-ext-panel');
  mount.appendChild(root);

  const discovery = createDiscovery({
    ...(events ? { events } : {}),
    ...(globals ? { globals } : {}),
    ...(schedule ? { schedule } : {}),
    ...(unschedule ? { unschedule } : {}),
  });

  function walletRow({ icon, name, kind, key, onPick }) {
    const row = el('button', 'hdw-ext-wallet');
    row.type = 'button';
    row.disabled = connecting !== '';
    if (icon) {
      const img = el('img', 'hdw-ext-wicon');
      img.src = icon; // data: URI or nothing — accounts.js sanitized
      img.alt = '';
      row.appendChild(img);
    } else {
      row.appendChild(el('span', 'hdw-ext-wicon hdw-ext-wicon-fallback', '◆'));
    }
    row.appendChild(el('span', 'hdw-ext-wname', name));
    row.appendChild(
      el('span', 'hdw-ext-wkind', connecting === key ? COPY.connecting : kind)
    );
    row.addEventListener('click', onPick);
    return row;
  }

  async function pick(key, connect) {
    connecting = key;
    notice = '';
    render();
    try {
      const account = await connect();
      if (!account) {
        notice = COPY.emptyAccount;
        return;
      }
      if (connectedView) connected = account;
      onConnected?.(account);
    } catch (err) {
      notice = describeWalletError(err);
    } finally {
      connecting = '';
      render();
    }
  }

  const pickEvm = (entry, key) =>
    pick(key, async () => {
      const { accounts, chainId } = await connectEvm(entry.provider, entry.info);
      if (!accounts.length) return null;
      return {
        lane: 'evm',
        address: accounts[0].address,
        addressKey: accounts[0].addressKey,
        chainId,
        walletName: entry.info.name,
        icon: entry.info.icon,
      };
    });

  const pickSolana = (entry, key) =>
    pick(key, async () => {
      const { accounts } = await connectSolana(entry.wallet);
      if (!accounts.length) return null;
      return {
        lane: 'solana',
        address: accounts[0].address,
        addressKey: accounts[0].addressKey,
        chainId: null,
        walletName: entry.name,
        icon: entry.icon,
      };
    });

  function renderConnected() {
    const card = el('div', 'hdw-ext-connected');
    const head = el('div', 'hdw-ext-chead');
    if (connected.icon) {
      const img = el('img', 'hdw-ext-wicon');
      img.src = connected.icon;
      img.alt = '';
      head.appendChild(img);
    } else {
      head.appendChild(el('span', 'hdw-ext-wicon hdw-ext-wicon-fallback', '◆'));
    }
    head.appendChild(el('span', 'hdw-ext-cname', connected.walletName || COPY.connected));
    const badge = connected.lane === 'evm' ? chainLabel(connected.chainId) || 'EVM' : 'SOLANA';
    head.appendChild(el('span', 'hdw-ext-badge', badge));
    card.appendChild(head);

    // The address IS the account's public identity — copy on click.
    const addr = el('button', 'hdw-ext-caddr');
    addr.type = 'button';
    addr.title = connected.address;
    addr.textContent = truncateMiddle(connected.address);
    addr.addEventListener('click', async () => {
      try {
        await doc.defaultView?.navigator?.clipboard?.writeText(connected.address);
        addr.textContent = COPY.copied;
        setTimeout(() => {
          addr.textContent = truncateMiddle(connected.address);
        }, 900);
      } catch {
        /* clipboard refusal is the browser's answer; the title still shows it */
      }
    });
    card.appendChild(addr);

    const off = el('button', 'hdw-ext-disconnect', COPY.disconnect);
    off.type = 'button';
    off.addEventListener('click', () => {
      connected = null;
      notice = '';
      render();
    });
    card.appendChild(off);
    return card;
  }

  function render() {
    root.textContent = '';

    if (connectedView && connected) {
      root.appendChild(renderConnected());
      if (notice) root.appendChild(el('div', 'hdw-ext-notice', notice));
      return;
    }

    const hasAny =
      discovered.evm.length > 0 || discovered.solana.length > 0 || discovered.legacy !== null;

    if (!discovered.settled && !hasAny) {
      root.appendChild(el('div', 'hdw-ext-scan', COPY.scanning));
    } else if (!hasAny) {
      // HONEST no-wallet state: no dead buttons.
      const box = el('div', 'hdw-ext-nowallet');
      box.appendChild(el('span', 'hdw-ext-nwtitle', COPY.noWalletTitle));
      box.appendChild(el('span', 'hdw-ext-nwbody', COPY.noWalletBody));
      root.appendChild(box);
    } else {
      const list = el('div', 'hdw-ext-list');
      list.setAttribute('role', 'list');
      for (const entry of discovered.evm) {
        list.appendChild(
          walletRow({
            icon: entry.info.icon,
            name: entry.info.name,
            kind: 'EVM',
            key: entry.info.uuid,
            onPick: () => pickEvm(entry, entry.info.uuid),
          })
        );
      }
      for (const entry of discovered.solana) {
        list.appendChild(
          walletRow({
            icon: entry.icon,
            name: entry.name,
            kind: 'SOLANA',
            key: entry.name,
            onPick: () => pickSolana(entry, entry.name),
          })
        );
      }
      if (discovered.legacy) {
        list.appendChild(
          walletRow({
            icon: null,
            name: discovered.legacy.info.name,
            kind: 'EVM',
            key: 'legacy',
            onPick: () => pickEvm(discovered.legacy, 'legacy'),
          })
        );
      }
      root.appendChild(list);
    }

    if (notice) root.appendChild(el('div', 'hdw-ext-notice', notice));
  }

  const unsubscribe = discovery.subscribe((view) => {
    discovered = view;
    render();
  });
  discovery.start();

  return {
    destroy() {
      unsubscribe();
      discovery.stop();
      root.remove();
    },
  };
}
