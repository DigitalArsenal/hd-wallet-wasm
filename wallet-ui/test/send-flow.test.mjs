// SEC-014 / SEC-057 end to end: the Send flow runs against the real
// hd-wallet-wasm builder and real account keys, with a scripted network.
// The review shows the recipient and amount decoded from the built bytes;
// Send refuses to broadcast bytes that differ from what was reviewed; the
// Bitcoin flow takes input values from verified previous transactions only.

import initHDWallet from 'hd-wallet-wasm';
import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';
import { describe, expect, it } from 'vitest';

import { btcSignedTransaction, fetchBtcUtxos } from '../src/blockchain-trust.js';
import { deriveAccountAddresses, withChainKey } from '../src/identity-keys.js';
import { BTC_FLAT_FEE_SATS, buildEthTransaction, createSendFlow } from '../src/send-flow.js';
import {
  bytesToHex,
  assertEthTransactionMatches,
  decodeEip1559,
  hexToBytes,
  parseBtcRecipient,
  parseBtcTransaction,
} from '../src/send-safety.js';
import { rawTx } from './helpers/btc-raw.mjs';

const wallet = await initHDWallet();
const seed = wallet.mnemonic.toSeed('abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about');
const root = wallet.hdkey.fromSeed(seed);
const accounts = deriveAccountAddresses(wallet, root, 0);
const GOOD = '0x52908400098527886E0F7030069857D2E4169EE7';
const BASE_FEE = 1_000_000_000n; // 1 gwei
const MAX_FEE_PER_GAS = BASE_FEE * 2n + 2_000_000_000n;

function rlpBytes(bytes) {
  if (bytes.length === 1 && bytes[0] < 0x80) return [...bytes];
  if (bytes.length < 56) return [0x80 + bytes.length, ...bytes];
  if (bytes.length < 256) return [0xb8, bytes.length, ...bytes];
  throw new Error('long');
}
function rlpInt(value) {
  if (value === 0n) return [0x80];
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return rlpBytes(hexToBytes(hex));
}
function rlpList(items) {
  const body = items.flat();
  if (body.length < 56) return [0xc0 + body.length, ...body];
  if (body.length < 256) return [0xf7 + 1, body.length, ...body];
  throw new Error('long list');
}

/** The EIP-1559 signing hash, computed here from the decoded fields. */
function signingHash(d) {
  const payload = rlpList([
    rlpInt(d.chainId), rlpInt(d.nonce), rlpInt(d.maxPriorityFeePerGas), rlpInt(d.maxFeePerGas),
    rlpInt(d.gasLimit), rlpBytes(hexToBytes(d.to.slice(2))), rlpInt(d.value), rlpBytes(d.data), [0xc0],
  ]);
  return keccak_256(Uint8Array.from([0x02, ...payload]));
}

function ethAddressOf(publicKey) {
  const point = secp256k1.ProjectivePoint.fromHex(publicKey).toRawBytes(false);
  return `0x${bytesToHex(keccak_256(point.slice(1)).slice(-20))}`;
}

function ethNetwork({ nonce = '0x5', baseFee = `0x${BASE_FEE.toString(16)}`, balance = '0x0', hashOverride = null } = {}) {
  const sent = [];
  const calls = [];
  const ethRpc = async (method, params) => {
    calls.push(method);
    if (method === 'eth_getTransactionCount') return nonce;
    if (method === 'eth_getBlockByNumber') return { baseFeePerGas: baseFee };
    if (method === 'eth_getBalance') return balance;
    if (method === 'eth_sendRawTransaction') {
      sent.push(params[0]);
      return hashOverride ?? `0x${bytesToHex(keccak_256(hexToBytes(params[0].slice(2))))}`;
    }
    throw new Error(`unexpected ${method}`);
  };
  return { ethRpc, sent, calls };
}

function flow({ ethRpc = async () => { throw new Error('no eth'); }, wasm = () => wallet, fetchUtxos, broadcastBtc } = {}) {
  return createSendFlow({
    wasm,
    ethRpc,
    fetchBtcUtxos: fetchUtxos ?? (async () => []),
    broadcastBtc: broadcastBtc ?? (async () => { throw new Error('no btc'); }),
    withChainKey: (path, fn) => withChainKey(root, path, fn),
    btcSign: btcSignedTransaction,
  });
}

async function rejection(promise) {
  try {
    await promise;
  } catch (error) {
    return error.code ?? error.message;
  }
  return 'RESOLVED';
}

describe('Ethereum send (real builder, real key)', () => {
  it('reviews the decoded recipient and amount, then broadcasts exactly that, signed by the account', async () => {
    const net = ethNetwork();
    const send = flow({ ethRpc: net.ethRpc });
    const plan = await send.prepare({ chain: 'eth', from: accounts.eth, to: GOOD.toLowerCase(), amount: '0.5' });
    expect(plan.review).toEqual({
      to: GOOD,
      amount: '0.5 ETH',
      fee: `up to ${Number(MAX_FEE_PER_GAS * 21000n) / 1e18} ETH`,
      network: 'Ethereum mainnet',
    });
    expect(net.sent).toHaveLength(0);
    const hash = await send.execute(plan);
    expect(net.sent).toHaveLength(1);
    const raw = hexToBytes(net.sent[0].slice(2));
    expect(hash).toBe(`0x${bytesToHex(keccak_256(raw))}`);
    const decoded = decodeEip1559(raw);
    expect(decoded.signed).toBe(true);
    expect(decoded.to).toBe(GOOD.toLowerCase());
    expect(decoded.value).toBe(5n * 10n ** 17n);
    expect(decoded.chainId).toBe(1n);
    expect(decoded.nonce).toBe(5n);
    expect(decoded.maxFeePerGas).toBe(MAX_FEE_PER_GAS);
    const signature = new secp256k1.Signature(decoded.r, decoded.s).addRecoveryBit(Number(decoded.yParity));
    const signer = signature.recoverPublicKey(signingHash(decoded)).toRawBytes(true);
    expect(ethAddressOf(signer)).toBe(accounts.eth.address.toLowerCase());
  });

  it('refuses at review every recipient the 2.1.0 builder signed to 0x00…00, before any network call', async () => {
    for (const to of ['vitalik.eth', GOOD.slice(0, -1), `${GOOD}x`, `0x0x${GOOD.slice(4)}`, `0x${'0'.repeat(40)}`]) {
      const net = ethNetwork();
      expect(await rejection(flow({ ethRpc: net.ethRpc }).prepare({ chain: 'eth', from: accounts.eth, to, amount: '1' }))).not.toBe('RESOLVED');
      expect(net.calls).toEqual([]);
    }
  });

  it('sends 20 ETH as 20 ETH: the value reaches the builder as 32 bytes (2.1.0 wrapped 2^64 wei and more)', async () => {
    for (const [amount, wei] of [
      ['20', 20n * 10n ** 18n],
      ['18.446744073709551616', 1n << 64n],
      ['115792089237316195423570985008687907853269984665640564039457.584007913129639935', (1n << 256n) - 1n],
    ]) {
      const net = ethNetwork();
      const send = flow({ ethRpc: net.ethRpc });
      const plan = await send.prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount });
      expect(plan.expected.value).toBe(wei);
      expect(plan.review.amount).toBe(`${amount} ETH`);
      await send.execute(plan);
      const decoded = decodeEip1559(hexToBytes(net.sent[0].slice(2)));
      expect(decoded.value).toBe(wei);
      expect(decoded.to).toBe(GOOD.toLowerCase());
      const signature = new secp256k1.Signature(decoded.r, decoded.s).addRecoveryBit(Number(decoded.yParity));
      expect(ethAddressOf(signature.recoverPublicKey(signingHash(decoded)).toRawBytes(true))).toBe(accounts.eth.address.toLowerCase());
    }
  });

  it('an amount of 2^256 wei or more is refused before anything is built', async () => {
    const net = ethNetwork();
    const huge = '115792089237316195423570985008687907853269984665640564039457.584007913129639936';
    expect(await rejection(flow({ ethRpc: net.ethRpc }).prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: huge }))).toBe('AMOUNT_TOO_LARGE');
  });

  // A builder that changes what it was given: it parses the page's bytes,
  // after `mutate` has rewritten their fields.
  function encodeTx(d) {
    return Uint8Array.from([0x02, ...rlpList([
      rlpInt(d.chainId), rlpInt(d.nonce), rlpInt(d.maxPriorityFeePerGas), rlpInt(d.maxFeePerGas), rlpInt(d.gasLimit),
      rlpBytes(d.to ? hexToBytes(d.to.slice(2)) : new Uint8Array(0)), rlpInt(d.value), rlpBytes(d.data ?? new Uint8Array(0)),
      [0xc0], [0x80], [0x80], [0x80],
    ])]);
  }
  const lyingBuilder = (mutate) => () => ({
    ...wallet,
    ethereum: {
      ...wallet.ethereum,
      tx: { parse: (bytes) => wallet.ethereum.tx.parse(encodeTx(mutate({ ...decodeEip1559(bytes) }))) },
    },
  });

  it('refuses a builder that dropped the recipient or wrapped the value', async () => {
    const dropped = flow({ ethRpc: ethNetwork().ethRpc, wasm: lyingBuilder((d) => ({ ...d, to: null })) });
    const droppedError = await dropped.prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '1' }).catch((e) => e);
    expect(droppedError.code).toBe('TX_MISMATCH');
    const zeroed = flow({ ethRpc: ethNetwork().ethRpc, wasm: lyingBuilder((d) => ({ ...d, to: `0x${'0'.repeat(40)}` })) });
    expect((await zeroed.prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '1' }).catch((e) => e)).message).toContain('recipient');
    const wrapped = flow({ ethRpc: ethNetwork().ethRpc, wasm: lyingBuilder((d) => ({ ...d, value: d.value & ((1n << 64n) - 1n) })) });
    expect((await wrapped.prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '20' }).catch((e) => e)).message).toContain('amount');
    const missing = flow({ ethRpc: ethNetwork().ethRpc, wasm: () => ({ ...wallet, ethereum: { ...wallet.ethereum, tx: {} } }) });
    expect(await rejection(missing.prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '1' }))).toBe('SEND_FAILED');
    const throwing = flow({ ethRpc: ethNetwork().ethRpc, wasm: () => ({ ...wallet, ethereum: { ...wallet.ethereum, tx: { parse: () => { throw new Error('INVALID_TRANSACTION'); } } } }) });
    expect(await rejection(throwing.prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '1' }))).toBe('BAD_TX');
  });

  it('refuses to broadcast when the signed bytes differ from the reviewed plan', async () => {
    const net = ethNetwork();
    let calls = 0;
    // Honest at review, swaps the recipient when signing.
    const drifting = lyingBuilder((d) => (calls++ === 0 ? d : { ...d, to: '0x9858effd232b4033e47d90003d41ec34ecaeda94' }));
    const send = flow({ ethRpc: net.ethRpc, wasm: drifting });
    const plan = await send.prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '1' });
    expect(await rejection(send.execute(plan))).toBe('TX_MISMATCH');
    expect(net.sent).toHaveLength(0);
  });

  it('refuses hostile RPC answers: malformed nonce, absurd fees, a different transaction hash', async () => {
    expect(await rejection(flow({ ethRpc: ethNetwork({ nonce: '5' }).ethRpc }).prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '1' }))).toBe('BAD_RPC');
    expect(await rejection(flow({ ethRpc: ethNetwork({ baseFee: '0x56bc75e2d63100000' }).ethRpc }).prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '1' }))).toBe('BAD_RPC');
    const lying = ethNetwork({ hashOverride: `0x${'ab'.repeat(32)}` });
    const send = flow({ ethRpc: lying.ethRpc });
    const plan = await send.prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '1' });
    expect(await rejection(send.execute(plan))).toBe('BAD_RPC');
  });

  it('a sweep sends the exact balance minus the maximum fee', async () => {
    const balance = 3n * 10n ** 17n;
    const net = ethNetwork({ balance: `0x${balance.toString(16)}` });
    const plan = await flow({ ethRpc: net.ethRpc }).prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '', sweep: true });
    expect(plan.expected.value).toBe(balance - MAX_FEE_PER_GAS * 21000n);
    const poor = ethNetwork({ balance: '0x1' });
    expect(await rejection(flow({ ethRpc: poor.ethRpc }).prepare({ chain: 'eth', from: accounts.eth, to: GOOD, amount: '', sweep: true }))).toBe('INSUFFICIENT_FUNDS');
  });
});

describe('buildEthTransaction (also the trust-record signer)', () => {
  it('a zero-value transaction with data signs exactly what was built', () => {
    const data = new TextEncoder().encode('SDN-TRUST:'.padEnd(80, 'x'));
    const expected = {
      chainId: 1n, nonce: 9n, maxPriorityFeePerGas: 2_000_000_000n, maxFeePerGas: 4_000_000_000n,
      gasLimit: 21000n + 80n * 16n + 4000n, to: GOOD.toLowerCase(), value: 0n, data,
    };
    const tx = buildEthTransaction(wallet, expected);
    let signed;
    try {
      assertEthTransactionMatches(decodeEip1559(tx.serialize()), expected, { signed: false });
      withChainKey(root, accounts.eth.path, (key) => tx.sign(key));
      signed = tx.serialize();
    } finally {
      tx.destroy();
    }
    const decoded = decodeEip1559(signed);
    assertEthTransactionMatches(decoded, expected, { signed: true });
    const signature = new secp256k1.Signature(decoded.r, decoded.s).addRecoveryBit(Number(decoded.yParity));
    expect(ethAddressOf(signature.recoverPublicKey(signingHash(decoded)).toRawBytes(true))).toBe(accounts.eth.address.toLowerCase());
  });
});

describe('Bitcoin send (verified UTXOs, real key)', () => {
  const own = parseBtcRecipient(accounts.btc.address).script;
  const recipient = 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4';
  const funding = rawTx({ outputs: [{ value: 1_000_000n, script: own }] });

  // The API claims 5 BTC; the previous transaction says 0.01 BTC.
  function api({ raw = funding.hex } = {}) {
    const requests = [];
    const fetchImpl = async (url) => {
      requests.push(url);
      if (url.endsWith('/utxo')) {
        return { ok: true, json: async () => [{ txid: funding.txid, vout: 0, value: 500_000_000, status: { confirmed: true } }] };
      }
      if (url.endsWith(`/tx/${funding.txid}/hex`)) return { ok: true, text: async () => raw };
      return { ok: false, status: 404 };
    };
    return { fetchImpl, requests };
  }

  it('spends the verified value, pays the decoded recipient and change, signs a valid legacy input', async () => {
    const { fetchImpl } = api();
    const broadcasts = [];
    const send = flow({
      fetchUtxos: (address) => fetchBtcUtxos(address, { fetchImpl }),
      broadcastBtc: async (rawHex) => { broadcasts.push(rawHex); return parseBtcTransaction(hexToBytes(rawHex)).txid; },
    });
    const plan = await send.prepare({ chain: 'btc', from: accounts.btc, to: recipient, amount: '0.005' });
    expect(plan.review).toEqual({ to: recipient, amount: '0.005 BTC', fee: '10,000 sats', network: 'Bitcoin mainnet' });
    expect(plan.expected.inputs.map((u) => u.value)).toEqual([1_000_000n]);
    const txid = await send.execute(plan);
    expect(broadcasts).toHaveLength(1);
    const raw = hexToBytes(broadcasts[0]);
    const parsed = parseBtcTransaction(raw);
    expect(parsed.txid).toBe(txid);
    expect(parsed.inputs).toEqual([{ txid: funding.txid, vout: 0 }]);
    expect(parsed.outputs.map((o) => [bytesToHex(o.script), o.value])).toEqual([
      [bytesToHex(parseBtcRecipient(recipient).script), 500_000n],
      [bytesToHex(own), 1_000_000n - 500_000n - BTC_FLAT_FEE_SATS],
    ]);
    // Legacy SIGHASH_ALL digest, rebuilt here: the input's script is the
    // previous output's script; then verify the DER signature with the
    // account's public key.
    const o = 4 + 1 + 36;
    const scriptLength = raw[o];
    const scriptSig = raw.slice(o + 1, o + 1 + scriptLength);
    const sigLength = scriptSig[0];
    const der = scriptSig.slice(1, sigLength); // drop the sighash byte
    const publicKey = scriptSig.slice(2 + sigLength);
    expect(bytesToHex(publicKey)).toBe(bytesToHex(accounts.btc.publicKey));
    const before = raw.slice(0, o);
    const after = raw.slice(o + 1 + scriptLength);
    const preimage = Uint8Array.from([...before, own.length, ...own, ...after, 1, 0, 0, 0]);
    const digest = sha256(sha256(preimage));
    expect(secp256k1.verify(secp256k1.Signature.fromDER(der), digest, publicKey)).toBe(true);
  });

  it('refuses when the API lists coins its previous transaction does not show', async () => {
    const { fetchImpl } = api({ raw: rawTx({ outputs: [{ value: 999_999_999n, script: own }] }).hex });
    const send = flow({ fetchUtxos: (address) => fetchBtcUtxos(address, { fetchImpl }) });
    expect(await rejection(send.prepare({ chain: 'btc', from: accounts.btc, to: recipient, amount: '0.005' }))).toBe('BAD_UTXO');
  });

  it('counts only verified funds: the API’s 5 BTC cannot be spent', async () => {
    const { fetchImpl } = api();
    const send = flow({ fetchUtxos: (address) => fetchBtcUtxos(address, { fetchImpl }) });
    expect(await rejection(send.prepare({ chain: 'btc', from: accounts.btc, to: recipient, amount: '1' }))).toBe('INSUFFICIENT_FUNDS');
  });

  it('refuses to broadcast when the signed transaction differs from the plan', async () => {
    const { fetchImpl } = api();
    const broadcasts = [];
    const send = createSendFlow({
      wasm: () => wallet,
      ethRpc: async () => { throw new Error('no eth'); },
      fetchBtcUtxos: (address) => fetchBtcUtxos(address, { fetchImpl }),
      broadcastBtc: async (rawHex) => { broadcasts.push(rawHex); return ''; },
      withChainKey: (path, fn) => withChainKey(root, path, fn),
      // A signer that pays someone else.
      btcSign: (opts) => btcSignedTransaction({
        ...opts,
        outputs: [{ script: parseBtcRecipient('3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy').script, value: opts.outputs[0].value }, ...opts.outputs.slice(1)],
      }),
    });
    const plan = await send.prepare({ chain: 'btc', from: accounts.btc, to: recipient, amount: '0.005' });
    expect(await rejection(send.execute(plan))).toBe('TX_MISMATCH');
    expect(broadcasts).toHaveLength(0);
  });

  it('refuses unsupported or malformed recipients before fetching anything', async () => {
    const { fetchImpl, requests } = api();
    const send = flow({ fetchUtxos: (address) => fetchBtcUtxos(address, { fetchImpl }) });
    for (const to of ['bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5', GOOD, 'tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx']) {
      expect(await rejection(send.prepare({ chain: 'btc', from: accounts.btc, to, amount: '0.001' }))).not.toBe('RESOLVED');
    }
    expect(requests).toEqual([]);
  });
});
