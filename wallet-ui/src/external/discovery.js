/*
 * WALLET DISCOVERY — EIP-6963 (EVM) + Wallet Standard (Solana), and nothing
 * else.
 *
 * HOME: hd-wallet-ui src/external (owner 2026-08-20). Ported byte-verbatim
 * from spaceaware-ui src/dashboard/src/lib/wallet-external/discovery.js
 * (task sdn-wallet-external-provider-lane) — header relabel only.
 *
 * WHY EVENTS AND NEVER `window.ethereum` ALONE: multiple extensions clobber
 * one global — the last injector wins and every other wallet disappears.
 * EIP-6963 makes each wallet ANNOUNCE itself with a CustomEvent instead, so
 * discovery is a listener plus a request dispatch. `window.ethereum` survives
 * only as the LAST-RESORT legacy admission for in-app browsers that predate
 * 6963, and only after the announce window closes with no announces.
 *
 * INJECTION IS ASYNCHRONOUS: in-app wallet browsers (and MV3 extensions)
 * inject after our code runs. So the request dispatch is REPEATED on a short
 * bounded schedule, and `ethereum#initialized` triggers one more. Detection
 * is always by what the environment injects — NEVER by UA string.
 *
 * CSP DELTA: ZERO. Everything here is same-document CustomEvents and method
 * calls on objects a wallet already injected. Nothing in this file runs at
 * import time, and every environment handle is an injectable port so the
 * whole state machine is testable in node.
 */

import { normalizeWalletInfo, sanitizeIcon } from './accounts.js';

export const EVM_ANNOUNCE = 'eip6963:announceProvider';
export const EVM_REQUEST = 'eip6963:requestProvider';
export const ETHEREUM_INITIALIZED = 'ethereum#initialized';
export const SOLANA_REGISTER = 'wallet-standard:register-wallet';
export const SOLANA_APP_READY = 'wallet-standard:app-ready';

/**
 * Re-request offsets (ms from start). In-app browsers observed to inject
 * anywhere from immediately to ~1.5 s after document scripts run; past ~2 s a
 * wallet that has not announced is not coming, and the legacy fallback (or
 * the built-in wallet, per the owner's ordering) takes over.
 */
export const ANNOUNCE_SCHEDULE_MS = Object.freeze([250, 750, 2000]);

/** A Wallet Standard wallet is admissible on the Solana lane when it can
 *  connect and claims at least one solana: chain. */
export function isSolanaStandardWallet(wallet) {
  const name = String(wallet?.name ?? '').trim();
  const features = wallet?.features;
  const chains = Array.isArray(wallet?.chains) ? wallet.chains : [];
  return (
    name.length > 0 &&
    !!features &&
    typeof features['standard:connect']?.connect === 'function' &&
    chains.some((c) => typeof c === 'string' && c.startsWith('solana:'))
  );
}

/**
 * Create the discovery state machine.
 *
 * @param {{
 *   events?: EventTarget,          // where wallets announce (window)
 *   globals?: object,              // where legacy `ethereum` lives (window)
 *   schedule?: (fn: () => void, ms: number) => any,
 *   unschedule?: (handle: any) => void,
 * }} [ports] — every default is the real browser; tests inject their own.
 */
export function createDiscovery({
  events = globalThis.window,
  globals = globalThis.window,
  schedule = (fn, ms) => setTimeout(fn, ms),
  unschedule = (handle) => clearTimeout(handle),
} = {}) {
  /**
   * uuid → {info, provider}. EIP-6963's uuid is the per-session provider
   * identity: one wallet reuses it across every re-announce (so repeats
   * collapse), while two DISTINCT providers — even white-labels sharing an
   * rdns — each keep their own entry. rdns is self-attested and collides;
   * keying on it would let a later announce silently clobber a real wallet.
   */
  const evm = new Map();
  /** wallet object → admission record; the object IS the standard's identity. */
  const solana = new Map();
  const subscribers = new Set();
  const timers = new Set();
  let legacy = null;
  let started = false;
  let settled = false;

  const snapshot = () => Object.freeze({
    evm: [...evm.values()],
    solana: [...solana.values()],
    legacy,
    settled,
  });

  const emit = () => {
    const view = snapshot();
    for (const fn of subscribers) {
      try {
        fn(view);
      } catch {
        /* a broken subscriber must not break discovery */
      }
    }
  };

  const onAnnounce = (event) => {
    const info = normalizeWalletInfo(event?.detail?.info);
    const provider = event?.detail?.provider;
    if (!info || !provider || typeof provider.request !== 'function') return;
    // A 6963 wallet arriving retires the legacy admission: same injector,
    // better identity.
    legacy = null;
    evm.set(info.uuid, Object.freeze({ info, provider }));
    emit();
  };

  const admitSolana = (wallet) => {
    if (!isSolanaStandardWallet(wallet) || solana.has(wallet)) return;
    solana.set(wallet, Object.freeze({
      name: String(wallet.name).trim(),
      icon: sanitizeIcon(wallet.icon),
      wallet,
    }));
    emit();
  };

  // The Wallet Standard handshake runs BOTH directions: wallets that loaded
  // first respond to our app-ready dispatch; wallets that load later dispatch
  // register-wallet with a callback expecting our API.
  const registerApi = Object.freeze({
    register: (...wallets) => {
      for (const w of wallets) admitSolana(w);
      return () => {};
    },
  });

  const onSolanaRegister = (event) => {
    const callback = event?.detail;
    if (typeof callback !== 'function') return;
    try {
      callback(registerApi);
    } catch {
      /* a wallet's callback is foreign code; its failure is its own */
    }
  };

  const request = () => {
    try {
      events.dispatchEvent(new CustomEvent(EVM_REQUEST));
      events.dispatchEvent(new CustomEvent(SOLANA_APP_READY, { detail: registerApi }));
    } catch {
      /* a sandboxed document may refuse synthetic dispatch; listeners stand */
    }
  };

  const settle = () => {
    settled = true;
    // Legacy last resort: nothing announced over the whole window, but a
    // pre-6963 injector left `ethereum` behind. Feature-detected, never
    // UA-sniffed, and identified honestly as legacy — no invented branding.
    const injected = globals?.ethereum;
    if (evm.size === 0 && injected && typeof injected.request === 'function') {
      legacy = Object.freeze({
        info: Object.freeze({ uuid: '', name: 'Injected wallet (legacy)', rdns: '', icon: null }),
        provider: injected,
      });
    }
    emit();
  };

  const onEthereumInitialized = () => request();

  return {
    /** Begin listening and dispatch the announce requests. Idempotent. */
    start() {
      if (started) return;
      started = true;
      events.addEventListener(EVM_ANNOUNCE, onAnnounce);
      events.addEventListener(SOLANA_REGISTER, onSolanaRegister);
      events.addEventListener(ETHEREUM_INITIALIZED, onEthereumInitialized);
      request();
      for (const ms of ANNOUNCE_SCHEDULE_MS) {
        const handle = schedule(() => {
          timers.delete(handle);
          request();
          if (ms === ANNOUNCE_SCHEDULE_MS[ANNOUNCE_SCHEDULE_MS.length - 1]) settle();
        }, ms);
        timers.add(handle);
      }
    },
    /** Stop listening and cancel the schedule. The registry is retained. */
    stop() {
      if (!started) return;
      started = false;
      events.removeEventListener(EVM_ANNOUNCE, onAnnounce);
      events.removeEventListener(SOLANA_REGISTER, onSolanaRegister);
      events.removeEventListener(ETHEREUM_INITIALIZED, onEthereumInitialized);
      for (const handle of timers) unschedule(handle);
      timers.clear();
    },
    /** @param {(view: object) => void} fn — called on every registry change. */
    subscribe(fn) {
      subscribers.add(fn);
      fn(snapshot());
      return () => subscribers.delete(fn);
    },
    snapshot,
  };
}
