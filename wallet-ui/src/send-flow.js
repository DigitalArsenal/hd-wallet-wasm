/**
 * Send flow: prepare → review → execute, for Ethereum and Bitcoin.
 *
 * prepare() parses what the user typed (send-safety.js), fetches the nonce,
 * fees or verified UTXOs, builds the UNSIGNED transaction and decodes it.
 * The review screen shows only decoded values: the recipient read back from
 * the built bytes, the amount in exact base units and the fee.
 *
 * execute() rebuilds and signs exactly that plan, decodes the SIGNED bytes,
 * and refuses to broadcast unless they match the plan field for field. A
 * builder that dropped the recipient (SEC-014: an unparsable `to` used to be
 * signed as a transfer to 0x00…00) or wrapped the amount (SEC-057: values
 * of 2^64 wei and more wrapped in hd-wallet-wasm 2.1.0) is caught here
 * whatever hd-wallet-wasm version is installed. The value itself goes to the
 * builder as 32 bytes (buildEthTransaction), so 20 ETH is sent as 20 ETH.
 *
 * Every dependency is passed in, so the whole flow runs in tests against the
 * real WASM builder with a scripted network.
 */

import { keccak_256 } from '@noble/hashes/sha3';

import {
  BTC_DECIMALS,
  BTC_DUST_SATS,
  BTC_MAX_SATS,
  ETH_MAINNET_CHAIN_ID,
  ETH_TRANSFER_GAS,
  SendInputError,
  UINT256_MAX,
  UINT64_MAX,
  assertEthTransactionMatches,
  btcScriptToAddress,
  bytesToHex,
  decodeEip1559,
  encodeUnsignedEip1559,
  formatUnits,
  hexToBytes,
  parseBtcRecipient,
  parseBtcTransaction,
  parseDecimalAmount,
  parseEthRecipient,
  toChecksumAddress,
} from './send-safety.js';

export const BTC_FLAT_FEE_SATS = 10_000n;
/** The most a Bitcoin send may pay in fees (flat fee plus dust folded in). */
export const BTC_MAX_FEE_SATS = 20_000n;
export const ETH_PRIORITY_FEE_WEI = 2_000_000_000n; // 2 gwei
/** A base fee above this (1,000 gwei) is treated as a broken or hostile RPC. */
export const ETH_MAX_FEE_PER_GAS_WEI = 1_000_000_000_000n;

function fail(message, code = 'SEND_FAILED') {
  throw new SendInputError(message, code);
}

function quantity(hex, label, max = UINT256_MAX) {
  if (typeof hex !== 'string' || !/^0x(?:0|[1-9a-f][0-9a-f]*)$/u.test(hex)) {
    fail(`The network returned a malformed ${label}.`, 'BAD_RPC');
  }
  const value = BigInt(hex);
  if (value > max) fail(`The network returned an out-of-range ${label}.`, 'BAD_RPC');
  return value;
}

/**
 * Build an unsigned EIP-1559 transaction in hd-wallet-wasm through the
 * 256-bit value path: the page encodes the exact fields
 * (send-safety.js encodeUnsignedEip1559) and the WASM parses them, so the
 * value reaches the builder as 32 bytes whatever hd-wallet-wasm version is
 * installed. The caller still decodes what the builder serializes, before and
 * after signing, and compares it with `expected`; the caller destroys `tx`.
 */
export function buildEthTransaction(module, expected) {
  const parse = module?.ethereum?.tx?.parse;
  if (typeof parse !== 'function') fail('The Ethereum transaction builder is not available.');
  let tx;
  try {
    tx = module.ethereum.tx.parse(encodeUnsignedEip1559(expected));
  } catch (error) {
    if (error instanceof SendInputError) throw error;
    fail('The Ethereum transaction could not be built. Nothing was sent.', 'BAD_TX');
  }
  if (!tx || typeof tx.serialize !== 'function' || typeof tx.sign !== 'function') {
    fail('The Ethereum transaction could not be built. Nothing was sent.', 'BAD_TX');
  }
  return tx;
}

function sameAddress(a, b) {
  return String(a).toLowerCase() === String(b).toLowerCase();
}

/**
 * @param {object} deps
 * @param {() => object} deps.wasm                 the hd-wallet-wasm module
 * @param {(method: string, params: any[]) => Promise<any>} deps.ethRpc
 * @param {(address: string) => Promise<Array>} deps.fetchBtcUtxos    verified UTXOs
 * @param {(rawHex: string) => Promise<string>} deps.broadcastBtc
 * @param {(path: string, fn: (key: Uint8Array) => any) => any} deps.withChainKey
 * @param {(opts: object) => {rawHex: string}} deps.btcSign     btcSignedTransaction
 */
export function createSendFlow(deps) {
  const { wasm, ethRpc, fetchBtcUtxos, broadcastBtc, withChainKey, btcSign } = deps;

  // ---------------------------------------------------------------------------
  // Ethereum
  // ---------------------------------------------------------------------------

  function buildEth(expected) {
    return buildEthTransaction(wasm(), expected);
  }

  function release(tx) {
    try { tx?.destroy?.(); } catch { /* released either way */ }
  }

  async function prepareEth({ from, to, amount, sweep = false }) {
    const recipient = parseEthRecipient(to);
    if (!from?.address || !from?.path) fail('No Ethereum address for this account.');
    const [nonceHex, block] = await Promise.all([
      ethRpc('eth_getTransactionCount', [from.address, 'pending']),
      ethRpc('eth_getBlockByNumber', ['latest', false]),
    ]);
    const nonce = quantity(nonceHex, 'nonce', UINT64_MAX);
    const baseFee = quantity(block?.baseFeePerGas ?? '', 'base fee', ETH_MAX_FEE_PER_GAS_WEI);
    const maxFeePerGas = baseFee * 2n + ETH_PRIORITY_FEE_WEI;
    if (maxFeePerGas > ETH_MAX_FEE_PER_GAS_WEI) fail('Network fees are implausibly high right now. Nothing was sent.', 'FEE_TOO_HIGH');
    const maxFee = maxFeePerGas * ETH_TRANSFER_GAS;
    let value;
    if (sweep) {
      const balance = quantity(await ethRpc('eth_getBalance', [from.address, 'latest']), 'balance');
      value = balance - maxFee;
      if (value <= 0n) fail('The balance does not cover the network fee.', 'INSUFFICIENT_FUNDS');
    } else {
      value = parseDecimalAmount(amount, 18, { max: UINT256_MAX, unit: 'ETH' });
    }
    const expected = Object.freeze({
      chainId: ETH_MAINNET_CHAIN_ID,
      nonce,
      maxPriorityFeePerGas: ETH_PRIORITY_FEE_WEI,
      maxFeePerGas,
      gasLimit: ETH_TRANSFER_GAS,
      to: recipient.lower,
      value,
    });
    const tx = buildEth(expected);
    let decoded;
    try {
      decoded = decodeEip1559(tx.serialize());
    } finally {
      release(tx);
    }
    assertEthTransactionMatches(decoded, expected, { signed: false });
    return Object.freeze({
      chain: 'eth',
      from: Object.freeze({ address: from.address, path: from.path }),
      expected,
      review: Object.freeze({
        to: toChecksumAddress(decoded.to),
        amount: `${formatUnits(decoded.value, 18)} ETH`,
        fee: `up to ${formatUnits(maxFee, 18)} ETH`,
        network: 'Ethereum mainnet',
      }),
    });
  }

  async function executeEth(plan) {
    const tx = buildEth(plan.expected);
    let signed;
    try {
      withChainKey(plan.from.path, (key) => tx.sign(key));
      signed = tx.serialize();
    } finally {
      release(tx);
    }
    assertEthTransactionMatches(decodeEip1559(signed), plan.expected, { signed: true });
    const computedHash = `0x${bytesToHex(keccak_256(signed))}`;
    const returned = await ethRpc('eth_sendRawTransaction', [`0x${bytesToHex(signed)}`]);
    if (typeof returned === 'string' && !sameAddress(returned, computedHash)) {
      fail(`The network reported a different transaction hash (${returned}); the signed transaction is ${computedHash}.`, 'BAD_RPC');
    }
    return computedHash;
  }

  // ---------------------------------------------------------------------------
  // Bitcoin
  // ---------------------------------------------------------------------------

  async function prepareBtc({ from, to, amount, sweep = false }) {
    const recipient = parseBtcRecipient(to);
    if (!from?.address || !from?.path) fail('No Bitcoin address for this account.');
    const own = parseBtcRecipient(from.address);
    const utxos = await fetchBtcUtxos(from.address);
    if (!utxos.length) fail('No confirmed coins to spend.', 'INSUFFICIENT_FUNDS');
    let fee = BTC_FLAT_FEE_SATS;
    let value;
    let selected;
    if (sweep) {
      selected = utxos;
      const total = utxos.reduce((sum, u) => sum + u.value, 0n);
      value = total - fee;
      if (value < BTC_DUST_SATS) fail('The balance does not cover the network fee.', 'INSUFFICIENT_FUNDS');
    } else {
      value = parseDecimalAmount(amount, BTC_DECIMALS, { max: BTC_MAX_SATS, unit: 'BTC' });
      if (value < BTC_DUST_SATS) fail(`Bitcoin cannot send less than ${BTC_DUST_SATS} satoshis.`, 'DUST');
      selected = [];
      let sum = 0n;
      for (const utxo of utxos) {
        selected.push(utxo);
        sum += utxo.value;
        if (sum >= value + fee) break;
      }
      if (sum < value + fee) fail('Insufficient funds for this amount and the network fee.', 'INSUFFICIENT_FUNDS');
    }
    const inputSum = selected.reduce((sum, u) => sum + u.value, 0n);
    const outputs = [{ script: recipient.script, value }];
    const change = inputSum - value - fee;
    if (change >= BTC_DUST_SATS) outputs.push({ script: own.script, value: change });
    else fee += change;
    if (fee > BTC_MAX_FEE_SATS) fail('The network fee would be unusually high. Nothing was sent.', 'FEE_TOO_HIGH');
    const decodedTo = btcScriptToAddress(outputs[0].script);
    if (!decodedTo) fail('The recipient script cannot be shown as an address.', 'INVALID_ADDRESS');
    return Object.freeze({
      chain: 'btc',
      from: Object.freeze({ address: from.address, path: from.path }),
      expected: Object.freeze({
        inputs: Object.freeze(selected.map((u) => Object.freeze({ ...u }))),
        outputs: Object.freeze(outputs.map((o) => Object.freeze({ script: o.script, value: o.value }))),
        fee,
      }),
      review: Object.freeze({
        to: decodedTo,
        amount: `${formatUnits(value, BTC_DECIMALS)} BTC`,
        fee: `${fee.toLocaleString('en-US')} sats`,
        network: 'Bitcoin mainnet',
      }),
    });
  }

  async function executeBtc(plan) {
    const { inputs, outputs, fee } = plan.expected;
    const { rawHex } = withChainKey(plan.from.path, (signPrivateKey) => btcSign({
      utxos: inputs,
      outputs,
      signPrivateKey,
    }));
    const parsed = parseBtcTransaction(hexToBytes(rawHex));
    const mismatch = (what) => fail(`The built transaction does not match what you reviewed (${what}). Nothing was sent.`, 'TX_MISMATCH');
    if (parsed.inputs.length !== inputs.length) mismatch('inputs');
    parsed.inputs.forEach((input, i) => {
      if (input.txid !== inputs[i].txid || input.vout !== inputs[i].vout) mismatch('inputs');
    });
    if (parsed.outputs.length !== outputs.length) mismatch('outputs');
    parsed.outputs.forEach((output, i) => {
      if (output.value !== outputs[i].value || bytesToHex(output.script) !== bytesToHex(outputs[i].script)) mismatch('outputs');
    });
    const paid = inputs.reduce((sum, u) => sum + u.value, 0n) - parsed.outputs.reduce((sum, o) => sum + o.value, 0n);
    if (paid !== fee) mismatch('fee');
    const txid = await broadcastBtc(rawHex);
    if (typeof txid === 'string' && txid.toLowerCase() !== parsed.txid) {
      fail(`The network reported a different transaction id (${txid}); the signed transaction is ${parsed.txid}.`, 'BAD_RPC');
    }
    return parsed.txid;
  }

  return Object.freeze({
    async prepare({ chain, ...request }) {
      if (chain === 'eth') return prepareEth(request);
      if (chain === 'btc') return prepareBtc(request);
      fail("Sending SOL isn't supported yet.", 'UNSUPPORTED');
    },
    async execute(plan) {
      if (plan?.chain === 'eth') return executeEth(plan);
      if (plan?.chain === 'btc') return executeBtc(plan);
      fail('Nothing to send.', 'UNSUPPORTED');
    },
  });
}
