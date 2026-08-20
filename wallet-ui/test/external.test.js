/*
 * OUTCOME TESTS for the external-wallet lane (tests-only-for-specific-outcomes
 * law): wire exactness of the EIP-1193 requests, the discovery state machine's
 * registry as a computable function of the event sequence, and the validation
 * truth tables that enforce zero-external-origin-bytes. No source patterns,
 * no UI wiring.
 */
import { describe, expect, it } from 'vitest';
import {
  accountKey,
  decodeBase58,
  evmAddressKey,
  isEvmAddress,
  isReverseDns,
  isSolanaAddress,
  normalizeEvmAccount,
  normalizeSolanaAccount,
  normalizeWalletInfo,
  sanitizeIcon,
} from '../src/external/accounts.js';
import { chainLabel } from '../src/external/chains.js';
import {
  ANNOUNCE_SCHEDULE_MS,
  ETHEREUM_INITIALIZED,
  EVM_ANNOUNCE,
  EVM_REQUEST,
  SOLANA_APP_READY,
  SOLANA_REGISTER,
  createDiscovery,
  isSolanaStandardWallet,
} from '../src/external/discovery.js';
import {
  connectEvm,
  connectSolana,
  normalizeProviderError,
  parseChainId,
  personalSign,
  signSolanaMessage,
  toPersonalSignRequest,
  watchEvmProvider,
} from '../src/external/provider.js';

const EVM_ADDR = '0x8ba1f109551bD432803012645Ac136ddd64DBA72';
const SOL_SYSTEM = '11111111111111111111111111111111';
const DATA_ICON = 'data:image/svg+xml;base64,PHN2Zy8+';

/** A manually driven scheduler so the announce window is deterministic. */
function manualClock() {
  const queue = [];
  return {
    schedule: (fn, ms) => {
      const handle = { fn, ms };
      queue.push(handle);
      return handle;
    },
    unschedule: (handle) => {
      const i = queue.indexOf(handle);
      if (i >= 0) queue.splice(i, 1);
    },
    /** Fire everything scheduled at or before `ms`. */
    advance(ms) {
      for (const handle of [...queue]) {
        if (handle.ms <= ms) {
          queue.splice(queue.indexOf(handle), 1);
          handle.fn();
        }
      }
    },
    pending: () => queue.length,
  };
}

function announce(events, info, provider = { request: async () => [] }) {
  events.dispatchEvent(new CustomEvent(EVM_ANNOUNCE, { detail: { info, provider } }));
}

const WALLET_INFO = { uuid: 'u-1', name: 'Test Wallet', rdns: 'com.example.wallet', icon: DATA_ICON };

function solanaWallet(overrides = {}) {
  return {
    name: 'Sol Wallet',
    icon: DATA_ICON,
    chains: ['solana:mainnet'],
    features: {
      'standard:connect': { connect: async () => ({ accounts: [{ address: SOL_SYSTEM }] }) },
      'solana:signMessage': { signMessage: async () => [{ signature: new Uint8Array(64) }] },
    },
    ...overrides,
  };
}

describe('icon admission (zero external-origin bytes)', () => {
  it('admits only data:image URIs', () => {
    expect(sanitizeIcon(DATA_ICON)).toBe(DATA_ICON);
    expect(sanitizeIcon('https://wallet.example/icon.png')).toBeNull();
    expect(sanitizeIcon('javascript:alert(1)')).toBeNull();
    expect(sanitizeIcon('data:text/html,<script>')).toBeNull();
    expect(sanitizeIcon('')).toBeNull();
  });
});

describe('wallet info admission', () => {
  it('requires uuid, name and a reverse-DNS rdns', () => {
    expect(normalizeWalletInfo(WALLET_INFO)).toMatchObject({ rdns: 'com.example.wallet', icon: DATA_ICON });
    expect(normalizeWalletInfo({ ...WALLET_INFO, rdns: 'wallet' })).toBeNull();
    expect(normalizeWalletInfo({ ...WALLET_INFO, uuid: '' })).toBeNull();
    expect(normalizeWalletInfo({ ...WALLET_INFO, name: ' ' })).toBeNull();
  });
  it('keeps the wallet but strips a non-data icon', () => {
    const info = normalizeWalletInfo({ ...WALLET_INFO, icon: 'https://x.example/i.png' });
    expect(info).not.toBeNull();
    expect(info.icon).toBeNull();
  });
  it('validates rdns shape', () => {
    expect(isReverseDns('io.metamask')).toBe(true);
    expect(isReverseDns('com.example.sub.wallet')).toBe(true);
    expect(isReverseDns('nodots')).toBe(false);
    expect(isReverseDns('.leading.dot')).toBe(false);
    expect(isReverseDns('spa ces.example')).toBe(false);
  });
});

describe('address forms', () => {
  it('EVM: 0x + 40 hex, identity form is lowercase', () => {
    expect(isEvmAddress(EVM_ADDR)).toBe(true);
    expect(isEvmAddress('0x123')).toBe(false);
    expect(isEvmAddress(EVM_ADDR.slice(2))).toBe(false);
    expect(evmAddressKey(EVM_ADDR)).toBe(EVM_ADDR.toLowerCase());
    expect(evmAddressKey(EVM_ADDR.toUpperCase().replace('0X', '0x'))).toBe(EVM_ADDR.toLowerCase());
  });
  it('base58 decodes the Solana system program to 32 zero bytes', () => {
    const bytes = decodeBase58(SOL_SYSTEM);
    expect(bytes).toHaveLength(32);
    expect([...bytes].every((b) => b === 0)).toBe(true);
  });
  it('base58 refuses the forbidden alphabet and wrong lengths', () => {
    expect(decodeBase58('0OIl')).toBeNull();
    expect(isSolanaAddress('abc')).toBe(false);
    expect(isSolanaAddress(SOL_SYSTEM)).toBe(true);
  });
  it('base58 is bounded — hostile-length wallet input is refused, fast', () => {
    expect(decodeBase58('1'.repeat(129))).toBeNull();
    expect(decodeBase58('1'.repeat(128))).toHaveLength(128);
    const t0 = performance.now();
    expect(isSolanaAddress('2'.repeat(100_000))).toBe(false);
    expect(performance.now() - t0).toBeLessThan(50);
  });
  it('normalized accounts carry one collision-free key per lane', () => {
    const evm = normalizeEvmAccount({ address: EVM_ADDR, chainId: 1 });
    const sol = normalizeSolanaAccount({ address: SOL_SYSTEM });
    expect(accountKey(evm)).toBe(`evm:${EVM_ADDR.toLowerCase()}`);
    expect(accountKey(sol)).toBe(`solana:${SOL_SYSTEM}`);
    expect(normalizeEvmAccount({ address: 'nope' })).toBeNull();
    expect(normalizeSolanaAccount({ address: '0OIl' })).toBeNull();
  });
});

describe('discovery state machine', () => {
  it('collapses re-announces by uuid; distinct providers coexist even under one rdns', () => {
    const events = new EventTarget();
    const clock = manualClock();
    const d = createDiscovery({ events, globals: {}, schedule: clock.schedule, unschedule: clock.unschedule });
    d.start();
    // One wallet re-announcing (spec: uuid is stable across a page session).
    announce(events, WALLET_INFO);
    announce(events, WALLET_INFO);
    expect(d.snapshot().evm).toHaveLength(1);
    // A DIFFERENT provider sharing the rdns must not clobber the first.
    announce(events, { ...WALLET_INFO, uuid: 'u-2', name: 'Test Wallet vNext' });
    const names = d.snapshot().evm.map((w) => w.info.name).sort();
    expect(names).toEqual(['Test Wallet', 'Test Wallet vNext']);
    d.stop();
  });

  it('ignores malformed announces entirely', () => {
    const events = new EventTarget();
    const clock = manualClock();
    const d = createDiscovery({ events, globals: {}, schedule: clock.schedule, unschedule: clock.unschedule });
    d.start();
    announce(events, { ...WALLET_INFO, rdns: 'nodots' });
    announce(events, WALLET_INFO, { notAProvider: true });
    expect(d.snapshot().evm).toHaveLength(0);
    d.stop();
  });

  it('re-dispatches the announce request across the schedule and on ethereum#initialized', () => {
    const events = new EventTarget();
    const clock = manualClock();
    let requests = 0;
    events.addEventListener(EVM_REQUEST, () => {
      requests += 1;
    });
    const d = createDiscovery({ events, globals: {}, schedule: clock.schedule, unschedule: clock.unschedule });
    d.start();
    expect(requests).toBe(1);
    clock.advance(ANNOUNCE_SCHEDULE_MS[ANNOUNCE_SCHEDULE_MS.length - 1]);
    expect(requests).toBe(1 + ANNOUNCE_SCHEDULE_MS.length);
    events.dispatchEvent(new CustomEvent(ETHEREUM_INITIALIZED));
    expect(requests).toBe(2 + ANNOUNCE_SCHEDULE_MS.length);
    d.stop();
  });

  it('admits window.ethereum as legacy ONLY when the window closes empty', () => {
    const events = new EventTarget();
    const clock = manualClock();
    const injected = { request: async () => [] };
    const d = createDiscovery({ events, globals: { ethereum: injected }, schedule: clock.schedule, unschedule: clock.unschedule });
    d.start();
    expect(d.snapshot().legacy).toBeNull();
    clock.advance(ANNOUNCE_SCHEDULE_MS[ANNOUNCE_SCHEDULE_MS.length - 1]);
    const view = d.snapshot();
    expect(view.settled).toBe(true);
    expect(view.legacy.provider).toBe(injected);
    expect(view.legacy.info.name).toBe('Injected wallet (legacy)');
  });

  it('never admits legacy when a 6963 wallet announced', () => {
    const events = new EventTarget();
    const clock = manualClock();
    const d = createDiscovery({ events, globals: { ethereum: { request: async () => [] } }, schedule: clock.schedule, unschedule: clock.unschedule });
    d.start();
    announce(events, WALLET_INFO);
    clock.advance(ANNOUNCE_SCHEDULE_MS[ANNOUNCE_SCHEDULE_MS.length - 1]);
    expect(d.snapshot().legacy).toBeNull();
  });

  it('admits Solana wallets from both handshake directions', () => {
    const events = new EventTarget();
    const clock = manualClock();
    const early = solanaWallet({ name: 'Early Wallet' });
    // A wallet that loaded FIRST answers our app-ready dispatch.
    events.addEventListener(SOLANA_APP_READY, (event) => event.detail.register(early));
    const d = createDiscovery({ events, globals: {}, schedule: clock.schedule, unschedule: clock.unschedule });
    d.start();
    // A wallet that loads LATER dispatches register-wallet with a callback.
    const late = solanaWallet({ name: 'Late Wallet' });
    events.dispatchEvent(new CustomEvent(SOLANA_REGISTER, { detail: (api) => api.register(late) }));
    const names = d.snapshot().solana.map((w) => w.name).sort();
    expect(names).toEqual(['Early Wallet', 'Late Wallet']);
    d.stop();
  });

  it('refuses non-Solana and connect-less standard wallets', () => {
    expect(isSolanaStandardWallet(solanaWallet({ chains: ['eip155:1'] }))).toBe(false);
    expect(isSolanaStandardWallet(solanaWallet({ features: {} }))).toBe(false);
    expect(isSolanaStandardWallet(solanaWallet())).toBe(true);
  });

  it('stop() cancels the schedule so a torn-down page never settles late', () => {
    const events = new EventTarget();
    const clock = manualClock();
    const d = createDiscovery({ events, globals: { ethereum: { request: async () => [] } }, schedule: clock.schedule, unschedule: clock.unschedule });
    d.start();
    d.stop();
    expect(clock.pending()).toBe(0);
    clock.advance(10_000);
    expect(d.snapshot().settled).toBe(false);
  });
});

describe('the personal_sign wire (EIP-191)', () => {
  it('pins the exact request: hex message FIRST, address second', () => {
    const req = toPersonalSignRequest({ address: EVM_ADDR, message: new Uint8Array([0xde, 0xad, 0x01]) });
    expect(req).toEqual({ method: 'personal_sign', params: ['0xdead01', EVM_ADDR] });
  });
  it('refuses non-byte messages', () => {
    expect(() => toPersonalSignRequest({ address: EVM_ADDR, message: 'hello' })).toThrow(/BYTES/);
    expect(() => toPersonalSignRequest({ address: EVM_ADDR, message: new Uint8Array(0) })).toThrow(/BYTES/);
  });
  it('passes a 65-byte signature through verbatim and refuses anything else', async () => {
    const sig = `0x${'ab'.repeat(65)}`;
    const good = { request: async () => sig };
    await expect(personalSign(good, { address: EVM_ADDR, message: new Uint8Array([1]) })).resolves.toBe(sig);
    const short = { request: async () => `0x${'ab'.repeat(64)}` };
    await expect(personalSign(short, { address: EVM_ADDR, message: new Uint8Array([1]) })).rejects.toThrow(/65 bytes/);
  });
});

describe('EVM connect + session events', () => {
  it('normalizes accounts and chain, dropping invalid addresses', async () => {
    const provider = {
      request: async ({ method }) => (method === 'eth_requestAccounts' ? [EVM_ADDR, 'garbage'] : '0x89'),
    };
    const { accounts, chainId } = await connectEvm(provider);
    expect(chainId).toBe(137);
    expect(accounts).toHaveLength(1);
    expect(accounts[0].addressKey).toBe(EVM_ADDR.toLowerCase());
    expect(accounts[0].chainId).toBe(137);
  });
  it('parses chain ids strictly', () => {
    expect(parseChainId('0x1')).toBe(1);
    expect(parseChainId('0x89')).toBe(137);
    expect(parseChainId('1')).toBeNull();
    expect(parseChainId('0x')).toBeNull();
    expect(parseChainId('0x0')).toBeNull();
  });
  it('classifies provider errors by code', () => {
    expect(normalizeProviderError({ code: 4001 }).kind).toBe('rejected');
    expect(normalizeProviderError({ code: -32002 }).kind).toBe('pending');
    expect(normalizeProviderError({ code: 4902 }).kind).toBe('chain-missing');
    expect(normalizeProviderError({ code: 4900 }).kind).toBe('disconnected');
    expect(normalizeProviderError({ code: -32601 }).kind).toBe('unsupported');
    expect(normalizeProviderError(new Error('boom')).kind).toBe('other');
  });
  it('normalizes event payloads before consumers see them', () => {
    const handlers = {};
    const provider = {
      request: async () => [],
      on: (event, fn) => {
        handlers[event] = fn;
      },
      removeListener: (event) => {
        delete handlers[event];
      },
    };
    const seen = { accounts: null, chain: null };
    const off = watchEvmProvider(provider, {
      onAccounts: (a) => {
        seen.accounts = a;
      },
      onChain: (c) => {
        seen.chain = c;
      },
    });
    handlers.accountsChanged([EVM_ADDR, 'junk']);
    handlers.chainChanged('0x1');
    expect(seen.accounts).toHaveLength(1);
    expect(seen.accounts[0].addressKey).toBe(EVM_ADDR.toLowerCase());
    expect(seen.chain).toBe(1);
    off();
    expect(Object.keys(handlers)).toHaveLength(0);
  });
  it('a provider without events yields a no-op unsubscribe', () => {
    expect(watchEvmProvider({ request: async () => [] })()).toBeUndefined();
  });
});

describe('chain badges', () => {
  it('names the known chains and stays honest about the rest', () => {
    expect(chainLabel(1)).toBe('ETHEREUM');
    expect(chainLabel(137)).toBe('POLYGON');
    expect(chainLabel(8453)).toBe('BASE');
    expect(chainLabel(999999)).toBe('CHAIN 999999');
    expect(chainLabel(null)).toBe('');
    expect(chainLabel(0)).toBe('');
  });
});

describe('Solana connect + signMessage', () => {
  it('normalizes standard:connect accounts', async () => {
    const { accounts } = await connectSolana(solanaWallet());
    expect(accounts).toHaveLength(1);
    expect(accounts[0].lane).toBe('solana');
    expect(accounts[0].addressKey).toBe(SOL_SYSTEM);
  });
  it('returns exactly the 64-byte Ed25519 signature', async () => {
    const wallet = solanaWallet();
    const sig = await signSolanaMessage(wallet, { address: SOL_SYSTEM }, new Uint8Array([1, 2, 3]));
    expect(sig).toHaveLength(64);
    const bad = solanaWallet({
      features: {
        ...solanaWallet().features,
        'solana:signMessage': { signMessage: async () => [{ signature: new Uint8Array(63) }] },
      },
    });
    await expect(signSolanaMessage(bad, { address: SOL_SYSTEM }, new Uint8Array([1]))).rejects.toThrow(/malformed/);
  });
});

describe('display truncation', () => {
  it('keeps short values verbatim and truncates long ones middle-out', async () => {
    const { truncateMiddle } = await import('../src/external/format.js');
    expect(truncateMiddle('0x8ba1f109551bD432803012645Ac136ddd64DBA72')).toBe('0x8ba1f1…4DBA72');
    expect(truncateMiddle('short')).toBe('short');
    expect(truncateMiddle('')).toBe('');
    expect(truncateMiddle(null)).toBe('');
  });
});

describe('the zero-dependency firewall (HERMES/ARACHNE 2026-08-20)', () => {
  it('src/external imports nothing from the custody world', async () => {
    const { readdir, readFile } = await import('node:fs/promises');
    const { join, dirname } = await import('node:path');
    const { fileURLToPath } = await import('node:url');
    const dir = join(dirname(fileURLToPath(import.meta.url)), '..', 'src', 'external');
    for (const file of await readdir(dir)) {
      if (!file.endsWith('.js')) continue;
      const source = await readFile(join(dir, file), 'utf8');
      for (const match of source.matchAll(/from\s+['"]([^'"]+)['"]/g)) {
        // Every import stays inside the lane: relative, same directory.
        expect(match[1], `${file} imports ${match[1]}`).toMatch(/^\.\/[a-z-]+\.js$/);
      }
    }
  });
});
