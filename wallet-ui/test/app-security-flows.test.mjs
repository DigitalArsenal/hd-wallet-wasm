// The page (src/app.js init) end to end on the stub DOM, with the real
// hd-wallet-wasm module and a scripted network:
//
//   SEC-015  password sign-in: a weak password cannot sign in; a strong one
//            signs in to the scrypt-profile wallet; the old method opens the
//            2.x wallet read-only; the migration derives the new wallet and
//            sweeps to it, and only to it.
//   SEC-014  Send from a seed session: a bad recipient never reaches review;
//            the review shows the decoded recipient; the broadcast bytes pay it.

import { createHash, hkdfSync, scryptSync } from 'node:crypto';

import initHDWallet from 'hd-wallet-wasm';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';
import { afterAll, describe, expect, it } from 'vitest';

import { deriveAccountAddresses } from '../src/identity-keys.js';
import { bytesToHex, decodeEip1559, hexToBytes, toChecksumAddress } from '../src/send-safety.js';
import { StubDocument, StubNode, buttonByText, memoryStorage, parseTemplate, rowValue, stubWindow, textOf, waitFor } from './helpers/stub-dom.mjs';

// ---- the page's globals ------------------------------------------------------
const doc = new StubDocument();
const win = stubWindow(doc);
const previous = {};
for (const [name, value] of Object.entries({
  window: win,
  document: doc,
  localStorage: memoryStorage(),
  history: win.history,
  location: win.location,
  Node: StubNode,
  DOMParser: class {
    parseFromString(source) {
      const root = parseTemplate(doc, source);
      return { body: { childNodes: [...root.childNodes] } };
    }
  },
})) {
  previous[name] = Object.getOwnPropertyDescriptor(globalThis, name);
  Object.defineProperty(globalThis, name, { value, configurable: true, writable: true });
}
doc.importNode = (node) => node;
doc.addEventListener ??= () => {};
win.dispatchEvent = () => true;
win.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {} });
win.innerWidth = 1200;
win.innerHeight = 800;

const network = { eth: [], sent: [], balance: 0n, requests: [] };
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
  const target = String(url);
  let rpcMethod = null;
  try { rpcMethod = JSON.parse(init.body ?? 'null')?.method ?? null; } catch { /* not JSON */ }
  network.requests.push({ url: target, method: rpcMethod });
  // In tests import.meta.env.DEV is set, so apiUrl() maps the RPC origins to
  // the dev proxy paths (/api/eth, ...).
  if (/cloudflare-eth\.com|publicnode\.com|^\/api\/eth/u.test(target)) {
    const { method, params } = JSON.parse(init.body);
    network.eth.push(method);
    const result = {
      eth_getTransactionCount: '0x2',
      eth_getBlockByNumber: { baseFeePerGas: '0x3b9aca00' },
      eth_getBalance: `0x${network.balance.toString(16)}`,
      eth_chainId: '0x1',
    }[method];
    if (method === 'eth_sendRawTransaction') {
      network.sent.push(params[0]);
      return { ok: true, json: async () => ({ result: `0x${bytesToHex(keccak_256(hexToBytes(params[0].slice(2))))}` }) };
    }
    if (method === 'eth_getBalance' && params[0] === undefined) throw new Error('no address');
    return { ok: true, json: async () => ({ result: result ?? '0x0' }) };
  }
  // Balances, prices: nothing.
  return { ok: false, status: 503, json: async () => ({}), text: async () => '' };
};

/** Requests that send an address or ask for prices (SEC-054), since `from`. */
function balanceLookups(from = 0) {
  return network.requests.slice(from).filter((r) => r.method === 'eth_getBalance'
    || r.method === 'getBalance'
    || /blockstream|blockchain|coinbase|coingecko|solana/u.test(r.url));
}

afterAll(() => {
  globalThis.fetch = realFetch;
  for (const [name, descriptor] of Object.entries(previous)) {
    if (descriptor) Object.defineProperty(globalThis, name, descriptor);
    else delete globalThis[name];
  }
});

const logins = [];
const { init } = await import('../src/app.js');
const controls = await init(doc.body, { onLogin: (payload) => logins.push(payload), openAccountAfterLogin: true });
const wallet = await initHDWallet();

const $ = (id) => doc.getElementById(id);
const tick = (ms = 0) => new Promise((resolve) => setTimeout(resolve, ms));
function type(input, value) {
  input.value = value;
  input.dispatch('input');
}

const STRONG = 'quiver lantern basalt orchid pemmican tundra';
const NEW_PASSWORD = 'saffron glacier mosaic tortoise velvet quorum';

function scryptRoot(canonical, password) {
  const salt = Buffer.concat([Buffer.from('sdn-hd-wallet/password-scrypt-v2'), Buffer.from([0]), Buffer.from(canonical)]);
  return wallet.hdkey.fromSeed(new Uint8Array(scryptSync(password, salt, 64, { N: 65536, r: 8, p: 1, maxmem: 256 * 1024 * 1024 })));
}

function legacyRoot(username, password) {
  const user = Buffer.from(username);
  const initial = createHash('sha256').update(Buffer.concat([user, Buffer.from(password)])).digest();
  const master = Buffer.from(hkdfSync('sha256', initial, user, Buffer.from('master-key'), 32));
  return wallet.hdkey.fromSeed(new Uint8Array(hkdfSync('sha256', master, Buffer.alloc(0), Buffer.from('hd-wallet-seed'), 64)));
}

function ethSigner(raw) {
  const d = decodeEip1559(raw);
  const int = (v) => {
    if (v === 0n) return [0x80];
    let h = v.toString(16);
    if (h.length % 2) h = `0${h}`;
    const b = hexToBytes(h);
    return b.length === 1 && b[0] < 0x80 ? [...b] : [0x80 + b.length, ...b];
  };
  const body = [...int(d.chainId), ...int(d.nonce), ...int(d.maxPriorityFeePerGas), ...int(d.maxFeePerGas), ...int(d.gasLimit),
    0x94, ...hexToBytes(d.to.slice(2)), ...int(d.value), 0x80, 0xc0];
  const hash = keccak_256(Uint8Array.from([0x02, 0xc0 + body.length, ...body]));
  const pub = new secp256k1.Signature(d.r, d.s).addRecoveryBit(Number(d.yParity)).recoverPublicKey(hash).toRawBytes(false);
  return { decoded: d, from: `0x${bytesToHex(keccak_256(pub.slice(1)).slice(-20))}` };
}

async function openPasswordTab() {
  controls.openLogin();
  [...doc.body.querySelectorAll('.method-tab')].find((tab) => tab.getAttribute('data-method') === 'password').click();
}

async function typePassword(value) {
  type($('wallet-password'), value);
  await waitFor(() => textOf($('password-feedback')) && !textOf($('password-feedback')).includes('Loading'), { timeout: 30000, label: 'estimate' });
}

describe('password sign-in on the page (SEC-015)', () => {
  it('a weak password cannot sign in, whatever its length or character classes', async () => {
    await openPasswordTab();
    type($('wallet-username'), 'Alice.Example');
    await typePassword('passwordpasswordpassword');
    expect($('derive-from-password').disabled).toBe(true);
    expect(textOf($('password-feedback'))).toContain('too easy to guess');
    // Even a forced click does nothing.
    $('derive-from-password').disabled = false;
    $('derive-from-password').click();
    await tick(50);
    expect(logins).toHaveLength(0);
  }, 60000);

  it('a strong password signs in to the scrypt-profile wallet (not the 2.x fast one)', async () => {
    await typePassword(STRONG);
    expect($('derive-from-password').disabled).toBe(false);
    const requestsBefore = network.requests.length;
    $('derive-from-password').click();
    await waitFor(() => logins.length === 1, { timeout: 20000, label: 'login' });
    expect(logins[0].xpub).toBe(scryptRoot('alice.example', STRONG).toXpub());
    expect(logins[0].xpub).not.toBe(legacyRoot('Alice.Example', STRONG).toXpub());
    expect($('wallet-password').value).toBe('');
    expect(textOf($('account-status'))).toBe('Password');
    // SEC-054: signing in (the view opens on Profile) sends the account's
    // addresses to no balance or price API; opening Assets does.
    await tick(100);
    expect(balanceLookups(requestsBefore)).toEqual([]);
    controls.openAccount('assets');
    await waitFor(() => balanceLookups(requestsBefore).length > 0, { timeout: 10000, label: 'balance lookups on Assets' });
    controls.logout();
  }, 60000);

  it('the old method opens the 2.x wallet read-only, and the migration sweeps to the new wallet only', async () => {
    await openPasswordTab();
    type($('wallet-username'), 'bob');
    await typePassword('passwordpasswordpassword');
    expect($('derive-from-legacy-password').disabled).toBe(false);
    $('derive-from-legacy-password').click();
    await waitFor(() => logins.length === 2, { timeout: 20000, label: 'legacy login' });
    const old = legacyRoot('bob', 'passwordpasswordpassword');
    expect(logins[1].xpub).toBe(old.toXpub());
    expect(textOf($('account-status'))).toBe('Old password method · read-only');
    const oldAddresses = deriveAccountAddresses(wallet, old, 0);

    controls.openAccount('assets');
    await tick();
    const pane = $('account-pane-assets');
    const migration = await waitFor(() => pane.querySelector('.migration'), { label: 'migration block' });
    const [username, password, repeat] = migration.querySelectorAll('input');
    expect(username.value).toBe('bob');
    type(username, 'Bob.New');
    type(password, NEW_PASSWORD);
    type(repeat, NEW_PASSWORD);
    const setUp = buttonByText(migration, 'Set up new wallet');
    await waitFor(() => setUp.disabled === false, { label: 'set up enabled' });
    setUp.click();
    const expected = deriveAccountAddresses(wallet, scryptRoot('bob.new', NEW_PASSWORD), 0);
    const ready = await waitFor(() => (rowValue(pane, 'New Ethereum address') ? pane.querySelector('.migration') : null), { timeout: 20000, label: 'destination' });
    expect(rowValue(ready, 'New Ethereum address')).toBe(expected.eth.address);
    expect(rowValue(ready, 'New Bitcoin address')).toBe(expected.btc.address);

    // Read-only: no Send in the asset rows.
    pane.querySelectorAll('.asset-toggle')[1].click();
    expect(textOf(pane.querySelector('.send'))).toContain('read-only');

    network.balance = 5n * 10n ** 16n;
    buttonByText(pane.querySelector('.migration'), 'Move all ETH to the new wallet').click();
    await waitFor(() => rowValue(pane.querySelector('.migration'), 'To'), { timeout: 10000, label: 'sweep review' });
    expect(rowValue(pane.querySelector('.migration'), 'To')).toBe(toChecksumAddress(expected.eth.address));
    buttonByText(pane.querySelector('.migration'), 'Move ETH').click();
    await waitFor(() => network.sent.length === 1, { timeout: 10000, label: 'sweep broadcast' });
    const { decoded, from } = ethSigner(hexToBytes(network.sent[0].slice(2)));
    expect(decoded.to).toBe(expected.eth.address.toLowerCase());
    expect(from).toBe(oldAddresses.eth.address.toLowerCase());
    expect(decoded.value).toBe(network.balance - (2n * 1_000_000_000n + 2_000_000_000n) * 21000n);
    controls.logout();
  }, 60000);
});

describe('Send from a seed session (SEC-014)', () => {
  it('a bad recipient never reaches review; a good one is reviewed decoded and broadcast as reviewed', async () => {
    controls.openLogin();
    [...doc.body.querySelectorAll('.method-tab')].find((tab) => tab.getAttribute('data-method') === 'seed').click();
    const phrase = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const slot = doc.body.querySelector('.seed-slot-input');
    slot.dispatch('paste', { clipboardData: { getData: () => phrase }, preventDefault() {} });
    await tick();
    const requestsBefore = network.requests.length;
    $('derive-from-seed').disabled = false;
    $('derive-from-seed').click();
    await waitFor(() => logins.length === 3, { timeout: 20000, label: 'seed login' });
    // The view reopens on the section open before (Assets, from the sweep
    // test), and Assets looks the balances up: that is the only trigger.
    await waitFor(() => balanceLookups(requestsBefore).length > 0, { timeout: 10000, label: 'balance lookups on Assets' });
    controls.openAccount('assets');
    await tick();
    const pane = $('account-pane-assets');
    pane.querySelectorAll('.asset-toggle')[1].click();
    const [to, amount] = pane.querySelectorAll('.send input');
    const review = buttonByText(pane, 'Review');
    type(amount, '0.25');
    type(to, 'vitalik.eth');
    expect(review.disabled).toBe(true);
    type(to, '0x0x52908400098527886E0F7030069857D2E4169E');
    expect(review.disabled).toBe(true);
    type(to, '0x52908400098527886e0f7030069857d2e4169ee7');
    expect(review.disabled).toBe(false);
    review.click();
    await waitFor(() => rowValue(pane, 'To'), { timeout: 10000, label: 'review' });
    expect(rowValue(pane, 'To')).toBe('0x52908400098527886E0F7030069857D2E4169EE7');
    expect(rowValue(pane, 'Amount')).toBe('0.25 ETH');
    const before = network.sent.length;
    buttonByText(pane, 'Send').click();
    await waitFor(() => network.sent.length === before + 1, { timeout: 10000, label: 'broadcast' });
    const { decoded, from } = ethSigner(hexToBytes(network.sent.at(-1).slice(2)));
    expect(decoded.to).toBe('0x52908400098527886e0f7030069857d2e4169ee7');
    expect(decoded.value).toBe(25n * 10n ** 16n);
    const seedRoot = wallet.hdkey.fromSeed(wallet.mnemonic.toSeed(phrase));
    expect(from).toBe(deriveAccountAddresses(wallet, seedRoot, 0).eth.address.toLowerCase());
    controls.logout();
  }, 60000);
});

describe('the other Ethereum signer on the page: trust records (SEC-014)', () => {
  it('parses the recipient strictly, pins mainnet, and compares the decoded bytes before and after signing', async () => {
    const { readFileSync } = await import('node:fs');
    const app = readFileSync(new URL('../src/app.js', import.meta.url), 'utf8');
    const lane = app.slice(app.indexOf("  if (network === 'eth') {"), app.indexOf("  if (network === 'sol') {"));
    expect(lane).toContain('const to = parseEthRecipient(recipientAddress).lower;');
    expect(lane).toContain("if (chainIdHex !== '0x1') throw new Error('The Ethereum RPC is not on mainnet.');");
    // The same 256-bit builder as Send (the value never passes a uint64 setter).
    expect(lane).toContain('const tx = buildEthTransaction(module, expected);');
    expect(lane).not.toContain('createEIP1559');
    expect(lane).toContain('assertEthTransactionMatches(decodeEip1559(tx.serialize()), expected, { signed: false });');
    expect(lane).toContain('assertEthTransactionMatches(decodeEip1559(signed), expected, { signed: true });');
    // No float arithmetic on amounts anywhere in the send paths.
    expect(app).not.toMatch(/Math\.round\(\s*amount\w*\s*\*\s*1e(?:8|18)\)/u);
    expect(app).not.toMatch(/tx\.addInput\(utxo\.tx_hash_big_endian/u);
  });
});
