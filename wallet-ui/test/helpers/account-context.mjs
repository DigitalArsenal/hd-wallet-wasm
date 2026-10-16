// A test account context: the object app.js hands every pane, with the
// session, profile, contacts, keys and services replaced by in-memory fakes.
// Pass `wasm` and `seed` to drive the real per-account keys.

import { deriveIdentity, withEdKey, withXKey, accountXpub, accountXprv } from '../../src/identity-keys.js';

export function createTestContext({
  document,
  wasm = null,
  seed = null,
  hdRoot = null,
  account = 0,
  kind = 'seed',
  profile = {},
  contacts = [],
  envelopes = null,
  assets = null,
  trust = null,
  settings = null,
  contactCard = null,
} = {}) {
  const listeners = new Map();
  const state = {
    account,
    kind,
    profile: { ...profile },
    contacts: [...contacts],
    downloads: [],
    shown: [],
    current: true,
  };
  const identity = wasm && seed ? deriveIdentity(wasm, seed, account) : null;
  const ctx = {
    document,
    state,
    wasm: () => wasm,
    session: () => ({
      kind: state.kind,
      method: state.kind === 'seed' ? 'seed' : state.kind,
      account: state.account,
      identity: state.kind === 'seed' ? identity : null,
      external: state.kind === 'external' ? { address: '0x' + '1'.repeat(40), chain: 'eth', walletName: 'MetaMask' } : null,
      addresses: {},
    }),
    isCurrent: () => state.current,
    on(name, handler) {
      if (!listeners.has(name)) listeners.set(name, new Set());
      listeners.get(name).add(handler);
      return () => listeners.get(name)?.delete(handler);
    },
    emit(name) {
      for (const handler of [...(listeners.get(name) ?? [])]) handler();
    },
    loadEnvelopes: async () => envelopes ?? import('../../src/envelopes.js'),
    download: (bytes, name, mime) => { state.downloads.push({ bytes, name, mime }); },
    copy: async () => true,
    showSection: (section, options = {}) => { state.shown.push({ section, options }); },
    profile: {
      get: () => ({ ...state.profile }),
      save: (next) => { state.profile = { ...next }; ctx.emit('profile'); },
    },
    contacts: {
      list: () => [...state.contacts],
      importFile: async () => { throw new Error('This is not an SDS contact card (.epm).'); },
      remove: (peerId) => {
        state.contacts = state.contacts.filter((contact) => contact.peerId !== peerId);
        ctx.emit('contacts');
      },
    },
    contactCard: contactCard ?? { build: async () => ({ bytes: new Uint8Array([1, 2, 3]), fileName: 'contact.epm' }) },
    keys: {
      withEdKey: (fn) => withEdKey(wasm, seed, state.account, fn),
      withXKey: (fn) => withXKey(wasm, seed, state.account, fn),
      accountXpub: () => (hdRoot ? accountXpub(hdRoot, state.account) : 'xpub-test'),
      accountXprv: () => (hdRoot ? accountXprv(hdRoot, state.account) : 'xprv-test'),
    },
    trust: trust ?? {
      state: () => ({ relationships: [], transactions: [], checkedAt: 0, scanning: false, error: '' }),
      refresh: async () => {},
      publish: async () => ({ txHash: 'a'.repeat(64) }),
      revoke: async () => ({ txHash: 'b'.repeat(64) }),
      outboundRecord: () => null,
      canPublish: () => true,
      supportsChain: () => true,
      feeEstimate: async () => '5,000 sats',
    },
    assets: assets ?? {
      state: () => ({
        rows: [
          { chain: 'btc', address: '1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA', path: "m/44'/0'/0'/0/0", balance: '0.5', valueText: '$10.00' },
          { chain: 'eth', address: '0x9858EfFD232B4033E47d90003D41EC34EcaEda94', path: "m/44'/60'/0'/0/0", balance: '--', valueText: '' },
          { chain: 'sol', address: '4EngF3p73rFnEgjcAG5DVQ91QGFze4vsvjVUkAwLjv14', path: "m/44'/501'/0'/0/0", balance: '--', valueText: '' },
        ],
        currency: 'USD',
        updatedAt: 0,
        totalText: '--',
        scanning: false,
        error: '',
      }),
      refresh: async () => {},
      canSend: (chain) => chain === 'btc' || chain === 'eth',
      // A plan as send-flow.js returns it: the review shows decoded values.
      prepare: async ({ chain, to, amount }) => ({
        chain,
        review: {
          to: String(to).trim(),
          amount: `${String(amount).trim()} ${chain === 'btc' ? 'BTC' : 'ETH'}`,
          fee: chain === 'btc' ? '10,000 sats' : 'up to 0.0004 ETH',
          network: chain === 'btc' ? 'Bitcoin mainnet' : 'Ethereum mainnet',
        },
      }),
      send: async () => 'c'.repeat(64),
      feeLine: async () => 'Network fee: up to 0.0004 ETH',
    },
    settings: settings ?? {
      currency: () => 'USD',
      setCurrency: () => {},
      switchAccount: async (n) => { state.account = n; },
      signOut: () => {},
      forget: () => {},
    },
  };
  return ctx;
}
