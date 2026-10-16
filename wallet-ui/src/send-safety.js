/**
 * Send safety: strict parsing of what the user typed, and strict decoding of
 * what the wallet is about to sign.
 *
 * The Send flow never trusts the transaction builder to have used the typed
 * values. It parses the recipient and the amount here (exact formats, no
 * rounding, no silent fallbacks), builds the transaction, DECODES the bytes
 * the builder produced, shows the decoded recipient and amount on the review
 * screen, and refuses to broadcast unless the signed bytes decode to exactly
 * what was reviewed (SEC-014, SEC-057).
 *
 *   Ethereum recipient  ^0x[0-9a-fA-F]{40}$ only; mixed case must pass
 *                       EIP-55; the zero (burn) address is refused.
 *   Amounts             decimal strings parsed to integer base units
 *                       (wei, satoshis) with BigInt; more fractional digits
 *                       than the unit allows is an error, never a rounding.
 *   Bitcoin recipient   base58check P2PKH (version 0x00) / P2SH (0x05), or
 *                       bech32 v0 (P2WPKH, P2WSH) / bech32m v1 (P2TR) on
 *                       mainnet ("bc"); anything else is refused.
 *   Bitcoin inputs      every UTXO value is read from the previous
 *                       transaction's raw bytes, whose double-SHA-256 must
 *                       equal the txid (legacy sighashes do not commit to
 *                       input values, so an API-reported value is never used).
 */

import { base58check, bech32, bech32m } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { keccak_256 } from '@noble/hashes/sha3';

const base58checkCodec = base58check(sha256);
const textEncoder = new TextEncoder();

export class SendInputError extends Error {
  constructor(message, code = 'INVALID_INPUT') {
    super(message);
    this.name = 'SendInputError';
    this.code = code;
  }
}

function fail(message, code) {
  throw new SendInputError(message, code);
}

export function bytesToHex(bytes) {
  let out = '';
  for (const byte of bytes) out += byte.toString(16).padStart(2, '0');
  return out;
}

export function hexToBytes(hex) {
  if (typeof hex !== 'string' || hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/u.test(hex)) {
    fail('Malformed hex data.', 'MALFORMED_HEX');
  }
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Only ASCII spaces, tabs and line breaks around a paste are dropped. Every
// other character (NUL, a second "0x", a fullwidth digit, an ENS name) fails
// the exact pattern below.
function trimPaste(text) {
  if (typeof text !== 'string') fail('Enter an address.', 'EMPTY');
  return text.replace(/^[ \t\r\n]+|[ \t\r\n]+$/gu, '');
}

// =============================================================================
// Ethereum
// =============================================================================

export const ETH_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/u;
export const ETH_ZERO_ADDRESS = `0x${'0'.repeat(40)}`;
export const ETH_MAINNET_CHAIN_ID = 1n;
export const ETH_TRANSFER_GAS = 21000n;
export const UINT256_MAX = (1n << 256n) - 1n;

/** EIP-55 mixed-case checksum encoding of a 20-byte address. */
export function toChecksumAddress(address) {
  if (typeof address !== 'string' || !ETH_ADDRESS_PATTERN.test(address)) {
    fail('Not an Ethereum address.', 'INVALID_ADDRESS');
  }
  const lower = address.slice(2).toLowerCase();
  const hash = bytesToHex(keccak_256(textEncoder.encode(lower)));
  let out = '0x';
  for (let i = 0; i < 40; i += 1) {
    out += Number.parseInt(hash[i], 16) >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

/**
 * Parse an Ethereum recipient. Returns `{ address, lower }` (EIP-55 form and
 * lowercase form) or throws SendInputError.
 */
export function parseEthRecipient(text) {
  const value = trimPaste(text);
  if (!value) fail('Enter an Ethereum address.', 'EMPTY');
  if (!ETH_ADDRESS_PATTERN.test(value)) {
    fail('An Ethereum address is 0x followed by exactly 40 hex digits. Names (ENS) and other chains’ addresses are not accepted.', 'INVALID_ADDRESS');
  }
  const body = value.slice(2);
  const mixedCase = body !== body.toLowerCase() && body !== body.toUpperCase();
  const checksummed = toChecksumAddress(value);
  if (mixedCase && checksummed !== value) {
    fail('This address fails its EIP-55 checksum: a character was changed or mistyped.', 'BAD_CHECKSUM');
  }
  const lower = `0x${body.toLowerCase()}`;
  if (lower === ETH_ZERO_ADDRESS) {
    fail('The zero address burns whatever is sent to it.', 'ZERO_ADDRESS');
  }
  return Object.freeze({ address: checksummed, lower });
}

// =============================================================================
// Amounts
// =============================================================================

const AMOUNT_PATTERN = /^(\d+)(?:\.(\d+))?$|^\.(\d+)$/u;

/**
 * Parse a decimal amount into integer base units. `decimals` is 18 for ETH
 * and 8 for BTC. Throws SendInputError for anything but a plain decimal
 * number above zero and at most `max` base units.
 */
export function parseDecimalAmount(text, decimals, { max, unit = '' } = {}) {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 77) throw new TypeError('decimals');
  const value = typeof text === 'string' ? text.trim() : '';
  const match = AMOUNT_PATTERN.exec(value);
  if (!match) fail('Enter the amount as a plain number, for example 0.25.', 'INVALID_AMOUNT');
  const whole = match[1] ?? '0';
  const fraction = match[2] ?? match[3] ?? '';
  if (fraction.length > decimals) {
    fail(`${unit || 'This asset'} has at most ${decimals} decimal places.`, 'TOO_PRECISE');
  }
  const units = BigInt(whole) * 10n ** BigInt(decimals) + BigInt((fraction || '0').padEnd(decimals, '0') || '0');
  if (units <= 0n) fail('Enter an amount above zero.', 'ZERO_AMOUNT');
  if (max !== undefined && units > max) fail('This amount is larger than the network allows.', 'AMOUNT_TOO_LARGE');
  return units;
}

/** Exact decimal string of `units` base units (no floating point). */
export function formatUnits(units, decimals) {
  const value = BigInt(units);
  const negative = value < 0n;
  const abs = negative ? -value : value;
  const scale = 10n ** BigInt(decimals);
  const whole = abs / scale;
  let fraction = (abs % scale).toString().padStart(decimals, '0').replace(/0+$/u, '');
  if (decimals === 0) fraction = '';
  return `${negative ? '-' : ''}${whole}${fraction ? `.${fraction}` : ''}`;
}

// =============================================================================
// RLP (strict) and EIP-1559 transactions
// =============================================================================

function rlpDecodeItem(bytes, offset) {
  if (offset >= bytes.length) fail('Truncated transaction.', 'BAD_TX');
  const prefix = bytes[offset];
  if (prefix < 0x80) return { item: bytes.subarray(offset, offset + 1), end: offset + 1, list: false };
  if (prefix <= 0xb7) {
    const length = prefix - 0x80;
    const end = offset + 1 + length;
    if (end > bytes.length) fail('Truncated transaction.', 'BAD_TX');
    if (length === 1 && bytes[offset + 1] < 0x80) fail('Non-canonical RLP.', 'BAD_TX');
    return { item: bytes.subarray(offset + 1, end), end, list: false };
  }
  if (prefix <= 0xbf) {
    const lengthOfLength = prefix - 0xb7;
    const length = readLength(bytes, offset + 1, lengthOfLength);
    if (length < 56) fail('Non-canonical RLP.', 'BAD_TX');
    const start = offset + 1 + lengthOfLength;
    const end = start + length;
    if (end > bytes.length) fail('Truncated transaction.', 'BAD_TX');
    return { item: bytes.subarray(start, end), end, list: false };
  }
  let start;
  let length;
  if (prefix <= 0xf7) {
    length = prefix - 0xc0;
    start = offset + 1;
  } else {
    const lengthOfLength = prefix - 0xf7;
    length = readLength(bytes, offset + 1, lengthOfLength);
    if (length < 56) fail('Non-canonical RLP.', 'BAD_TX');
    start = offset + 1 + lengthOfLength;
  }
  const end = start + length;
  if (end > bytes.length) fail('Truncated transaction.', 'BAD_TX');
  const items = [];
  let cursor = start;
  while (cursor < end) {
    const decoded = rlpDecodeItem(bytes, cursor);
    if (decoded.end > end) fail('Malformed RLP list.', 'BAD_TX');
    items.push(decoded.list ? decoded.items : decoded.item);
    cursor = decoded.end;
  }
  return { items, end, list: true };
}

function readLength(bytes, offset, count) {
  if (count < 1 || count > 4 || offset + count > bytes.length) fail('Malformed RLP length.', 'BAD_TX');
  if (bytes[offset] === 0) fail('Non-canonical RLP.', 'BAD_TX');
  let length = 0;
  for (let i = 0; i < count; i += 1) length = length * 256 + bytes[offset + i];
  return length;
}

function rlpInteger(item, label) {
  if (!(item instanceof Uint8Array)) fail(`${label} is not an integer.`, 'BAD_TX');
  if (item.length > 32) fail(`${label} is out of range.`, 'BAD_TX');
  if (item.length > 0 && item[0] === 0) fail(`${label} has a leading zero.`, 'BAD_TX');
  let value = 0n;
  for (const byte of item) value = (value << 8n) | BigInt(byte);
  return value;
}

/**
 * Decode an EIP-1559 (type 2) transaction, unsigned (9 fields) or signed
 * (12 fields). Throws SendInputError on anything that is not exactly that.
 */
export function decodeEip1559(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 2 || bytes[0] !== 0x02) {
    fail('Not an EIP-1559 transaction.', 'BAD_TX');
  }
  const body = bytes.subarray(1);
  const decoded = rlpDecodeItem(body, 0);
  if (!decoded.list || decoded.end !== body.length) fail('Malformed transaction.', 'BAD_TX');
  const fields = decoded.items;
  if (fields.length !== 9 && fields.length !== 12) fail('Unexpected transaction field count.', 'BAD_TX');
  const [chainId, nonce, maxPriorityFee, maxFee, gasLimit, to, value, data, accessList] = fields;
  if (!(to instanceof Uint8Array) || (to.length !== 20 && to.length !== 0)) fail('Malformed recipient field.', 'BAD_TX');
  if (!(data instanceof Uint8Array)) fail('Malformed data field.', 'BAD_TX');
  if (!Array.isArray(accessList)) fail('Malformed access list.', 'BAD_TX');
  const result = {
    chainId: rlpInteger(chainId, 'chainId'),
    nonce: rlpInteger(nonce, 'nonce'),
    maxPriorityFeePerGas: rlpInteger(maxPriorityFee, 'maxPriorityFeePerGas'),
    maxFeePerGas: rlpInteger(maxFee, 'maxFeePerGas'),
    gasLimit: rlpInteger(gasLimit, 'gasLimit'),
    to: to.length === 20 ? `0x${bytesToHex(to)}` : null,
    value: rlpInteger(value, 'value'),
    data: new Uint8Array(data),
    accessListLength: accessList.length,
    // hd-wallet-wasm serializes an unsigned transaction with empty v/r/s
    // placeholders (12 fields); 9 fields is the EIP-1559 signing payload.
    signed: fields.length === 12
      && !fields.slice(9).every((item) => item instanceof Uint8Array && item.length === 0),
    yParity: null,
    r: null,
    s: null,
  };
  if (result.signed) {
    result.yParity = rlpInteger(fields[9], 'yParity');
    result.r = rlpInteger(fields[10], 'r');
    result.s = rlpInteger(fields[11], 's');
  }
  return Object.freeze(result);
}

export const UINT64_MAX = (1n << 64n) - 1n;

function rlpLength(length, shortBase) {
  if (length < 56) return [shortBase + length];
  const bytes = [];
  for (let n = length; n > 0; n = Math.floor(n / 256)) bytes.unshift(n % 256);
  return [shortBase + 55 + bytes.length, ...bytes];
}

function rlpString(bytes) {
  if (bytes.length === 1 && bytes[0] < 0x80) return [bytes[0]];
  return [...rlpLength(bytes.length, 0x80), ...bytes];
}

function rlpUint(value, label, max) {
  if (typeof value !== 'bigint' || value < 0n || value > max) {
    fail(`${label} is out of range.`, 'BAD_TX');
  }
  if (value === 0n) return rlpString([]);
  let hex = value.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  return rlpString([...hexToBytes(hex)]);
}

/**
 * Encode an UNSIGNED EIP-1559 (type 2) transaction the way hd-wallet-wasm
 * serializes one: the nine payload fields followed by empty v, r and s.
 *
 * This is the Send flow's 256-bit value path. hd-wallet-wasm's
 * `ethereum.tx.parse()` reads the value field into its 32-byte value, so the
 * builder never sees the amount as a 64-bit integer (2.1.0's
 * `createEIP1559` passed it through a uint64 setter, and 20 ETH became about
 * 1.55). Every field is range-checked here: the integer fields the WASM
 * stores as uint64 must fit 64 bits, the value 256 bits, the recipient is
 * exactly 20 bytes (no contract creation) and the access list is empty.
 */
export function encodeUnsignedEip1559(fields) {
  const to = typeof fields?.to === 'string' && /^0x[0-9a-f]{40}$/u.test(fields.to) ? hexToBytes(fields.to.slice(2)) : null;
  if (!to) fail('The recipient must be a lowercase 20-byte address.', 'BAD_TX');
  if (bytesEqual(to, new Uint8Array(20))) fail('The zero address burns whatever is sent to it.', 'ZERO_ADDRESS');
  const data = fields.data ?? new Uint8Array(0);
  if (!(data instanceof Uint8Array)) fail('Malformed data field.', 'BAD_TX');
  const payload = [
    ...rlpUint(fields.chainId, 'chainId', UINT64_MAX),
    ...rlpUint(fields.nonce, 'nonce', UINT64_MAX),
    ...rlpUint(fields.maxPriorityFeePerGas, 'maxPriorityFeePerGas', UINT64_MAX),
    ...rlpUint(fields.maxFeePerGas, 'maxFeePerGas', UINT64_MAX),
    ...rlpUint(fields.gasLimit, 'gasLimit', UINT64_MAX),
    ...rlpString([...to]),
    ...rlpUint(fields.value, 'value', UINT256_MAX),
    ...rlpString([...data]),
    0xc0, // empty access list
    0x80, 0x80, 0x80, // v, r, s: unsigned
  ];
  return Uint8Array.from([0x02, ...rlpLength(payload.length, 0xc0), ...payload]);
}

const SECP256K1_N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

/**
 * Check a decoded transaction against what the user reviewed. Every field
 * must match exactly; a signed transaction must carry a well-formed
 * signature. Throws SendInputError naming the first mismatch.
 */
export function assertEthTransactionMatches(decoded, expected, { signed = false } = {}) {
  const mismatch = (what) => fail(`The built transaction does not match what you reviewed (${what}). Nothing was sent.`, 'TX_MISMATCH');
  if (decoded.chainId !== BigInt(expected.chainId)) mismatch('network');
  if (decoded.to === null || decoded.to !== expected.to) mismatch('recipient');
  if (decoded.to === ETH_ZERO_ADDRESS) mismatch('recipient');
  if (decoded.value !== BigInt(expected.value)) mismatch('amount');
  if (decoded.nonce !== BigInt(expected.nonce)) mismatch('nonce');
  if (decoded.gasLimit !== BigInt(expected.gasLimit)) mismatch('gas limit');
  if (decoded.maxFeePerGas !== BigInt(expected.maxFeePerGas)) mismatch('fee');
  if (decoded.maxPriorityFeePerGas !== BigInt(expected.maxPriorityFeePerGas)) mismatch('fee');
  const data = expected.data ?? new Uint8Array(0);
  if (!bytesEqual(decoded.data, data)) mismatch('data');
  if (decoded.accessListLength !== 0) mismatch('access list');
  if (decoded.signed !== signed) mismatch(signed ? 'signature missing' : 'unexpected signature');
  if (signed) {
    if (decoded.yParity !== 0n && decoded.yParity !== 1n) mismatch('signature');
    if (decoded.r <= 0n || decoded.r >= SECP256K1_N || decoded.s <= 0n || decoded.s >= SECP256K1_N) mismatch('signature');
  }
  return true;
}

// =============================================================================
// Bitcoin
// =============================================================================

export const BTC_DECIMALS = 8;
export const BTC_MAX_SATS = 21_000_000n * 100_000_000n;
export const BTC_DUST_SATS = 546n;

function p2pkhScript(hash) {
  return Uint8Array.from([0x76, 0xa9, 0x14, ...hash, 0x88, 0xac]);
}

function p2shScript(hash) {
  return Uint8Array.from([0xa9, 0x14, ...hash, 0x87]);
}

function witnessScript(version, program) {
  return Uint8Array.from([version === 0 ? 0x00 : 0x50 + version, program.length, ...program]);
}

/**
 * Parse a mainnet Bitcoin recipient into its output script. Returns
 * `{ address, type, script }` or throws SendInputError.
 */
export function parseBtcRecipient(text) {
  const value = trimPaste(text);
  if (!value) fail('Enter a Bitcoin address.', 'EMPTY');
  if (/^[13][1-9A-HJ-NP-Za-km-z]{25,34}$/u.test(value)) {
    let payload;
    try { payload = base58checkCodec.decode(value); } catch { fail('This Bitcoin address fails its checksum.', 'BAD_CHECKSUM'); }
    if (payload.length !== 21) fail('Not a Bitcoin address.', 'INVALID_ADDRESS');
    const hash = payload.subarray(1);
    if (payload[0] === 0x00) return Object.freeze({ address: value, type: 'p2pkh', script: p2pkhScript(hash) });
    if (payload[0] === 0x05) return Object.freeze({ address: value, type: 'p2sh', script: p2shScript(hash) });
    fail('Not a mainnet Bitcoin address.', 'INVALID_ADDRESS');
  }
  if (/^(bc1|BC1)[0-9A-Za-z]{8,87}$/u.test(value)) {
    if (value !== value.toLowerCase() && value !== value.toUpperCase()) {
      fail('A bech32 address is all lowercase or all uppercase.', 'BAD_CHECKSUM');
    }
    const lower = value.toLowerCase();
    let decoded = null;
    let variant = null;
    try { decoded = bech32.decode(lower, 90); variant = 'bech32'; } catch { /* try bech32m */ }
    if (!decoded) {
      try { decoded = bech32m.decode(lower, 90); variant = 'bech32m'; } catch { /* invalid */ }
    }
    if (!decoded || decoded.prefix !== 'bc' || decoded.words.length < 1) fail('This Bitcoin address fails its checksum.', 'BAD_CHECKSUM');
    const version = decoded.words[0];
    let program;
    try { program = Uint8Array.from(bech32.fromWords(decoded.words.slice(1))); } catch { fail('Not a Bitcoin address.', 'INVALID_ADDRESS'); }
    if (version === 0 && variant === 'bech32' && program.length === 20) {
      return Object.freeze({ address: lower, type: 'p2wpkh', script: witnessScript(0, program) });
    }
    if (version === 0 && variant === 'bech32' && program.length === 32) {
      return Object.freeze({ address: lower, type: 'p2wsh', script: witnessScript(0, program) });
    }
    if (version === 1 && variant === 'bech32m' && program.length === 32) {
      return Object.freeze({ address: lower, type: 'p2tr', script: witnessScript(1, program) });
    }
    fail('This kind of Bitcoin address is not supported.', 'INVALID_ADDRESS');
  }
  fail('Not a mainnet Bitcoin address.', 'INVALID_ADDRESS');
}

/** The address an output script pays (for the review screen), or null. */
export function btcScriptToAddress(script) {
  const s = script;
  if (s.length === 25 && s[0] === 0x76 && s[1] === 0xa9 && s[2] === 0x14 && s[23] === 0x88 && s[24] === 0xac) {
    return base58checkCodec.encode(Uint8Array.from([0x00, ...s.subarray(3, 23)]));
  }
  if (s.length === 23 && s[0] === 0xa9 && s[1] === 0x14 && s[22] === 0x87) {
    return base58checkCodec.encode(Uint8Array.from([0x05, ...s.subarray(2, 22)]));
  }
  if ((s.length === 22 || s.length === 34) && s[0] === 0x00 && s[1] === s.length - 2) {
    return bech32.encode('bc', [0, ...bech32.toWords(s.subarray(2))], 90);
  }
  if (s.length === 34 && s[0] === 0x51 && s[1] === 0x20) {
    return bech32m.encode('bc', [1, ...bech32m.toWords(s.subarray(2))], 90);
  }
  return null;
}

function sha256d(bytes) {
  return sha256(sha256(bytes));
}

function readVarInt(bytes, offset) {
  if (offset >= bytes.length) fail('Truncated transaction.', 'BAD_TX');
  const first = bytes[offset];
  if (first < 0xfd) return { value: first, end: offset + 1 };
  const size = first === 0xfd ? 2 : first === 0xfe ? 4 : 8;
  if (offset + 1 + size > bytes.length) fail('Truncated transaction.', 'BAD_TX');
  let value = 0;
  for (let i = size - 1; i >= 0; i -= 1) value = value * 256 + bytes[offset + 1 + i];
  if (!Number.isSafeInteger(value) || value > bytes.length) fail('Oversized count.', 'BAD_TX');
  return { value, end: offset + 1 + size };
}

function readU64(bytes, offset) {
  if (offset + 8 > bytes.length) fail('Truncated transaction.', 'BAD_TX');
  let value = 0n;
  for (let i = 7; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[offset + i]);
  return value;
}

/**
 * Parse a raw Bitcoin transaction. The txid is computed over the
 * witness-stripped serialization, as consensus defines it.
 */
export function parseBtcTransaction(bytes) {
  if (!(bytes instanceof Uint8Array) || bytes.length < 10) fail('Not a Bitcoin transaction.', 'BAD_TX');
  let o = 4;
  let segwit = false;
  if (bytes[o] === 0x00 && bytes[o + 1] === 0x01) {
    segwit = true;
    o += 2;
  }
  const inputsStart = o;
  const inputCount = readVarInt(bytes, o);
  o = inputCount.end;
  if (inputCount.value === 0) fail('A transaction needs inputs.', 'BAD_TX');
  const inputs = [];
  for (let i = 0; i < inputCount.value; i += 1) {
    if (o + 36 > bytes.length) fail('Truncated transaction.', 'BAD_TX');
    const prevTxid = bytesToHex(Uint8Array.from(bytes.subarray(o, o + 32)).reverse());
    const prevVout = (bytes[o + 32] | (bytes[o + 33] << 8) | (bytes[o + 34] << 16) | (bytes[o + 35] << 24)) >>> 0;
    o += 36;
    const scriptLength = readVarInt(bytes, o);
    o = scriptLength.end + scriptLength.value;
    if (o + 4 > bytes.length) fail('Truncated transaction.', 'BAD_TX');
    o += 4;
    inputs.push({ txid: prevTxid, vout: prevVout });
  }
  const outputCount = readVarInt(bytes, o);
  o = outputCount.end;
  const outputs = [];
  for (let i = 0; i < outputCount.value; i += 1) {
    const value = readU64(bytes, o);
    o += 8;
    const scriptLength = readVarInt(bytes, o);
    const start = scriptLength.end;
    const end = start + scriptLength.value;
    if (end > bytes.length) fail('Truncated transaction.', 'BAD_TX');
    outputs.push({ value, script: Uint8Array.from(bytes.subarray(start, end)) });
    o = end;
  }
  const outputsEnd = o;
  if (segwit) {
    for (let i = 0; i < inputs.length; i += 1) {
      const items = readVarInt(bytes, o);
      o = items.end;
      for (let k = 0; k < items.value; k += 1) {
        const length = readVarInt(bytes, o);
        o = length.end + length.value;
        if (o > bytes.length) fail('Truncated transaction.', 'BAD_TX');
      }
    }
  }
  if (o + 4 !== bytes.length) fail('Trailing or missing bytes in transaction.', 'BAD_TX');
  const stripped = segwit
    ? Uint8Array.from([...bytes.subarray(0, 4), ...bytes.subarray(inputsStart, outputsEnd), ...bytes.subarray(o, o + 4)])
    : bytes;
  const txid = bytesToHex(sha256d(stripped).reverse());
  return Object.freeze({ txid, inputs, outputs, segwit });
}

/**
 * Turn an API-listed UTXO into a verified one: the raw previous transaction
 * must hash to the listed txid, the listed output must exist and pay
 * `expectedScript`; the value comes from those bytes, not from the API.
 */
export function verifyUtxo({ txid, vout }, rawTxHex, expectedScript) {
  if (typeof txid !== 'string' || !/^[0-9a-f]{64}$/u.test(txid)) fail('Malformed UTXO txid.', 'BAD_UTXO');
  if (!Number.isInteger(vout) || vout < 0) fail('Malformed UTXO index.', 'BAD_UTXO');
  const parsed = parseBtcTransaction(hexToBytes(String(rawTxHex).trim()));
  if (parsed.txid !== txid) fail('A UTXO’s transaction does not hash to its txid.', 'BAD_UTXO');
  const output = parsed.outputs[vout];
  if (!output) fail('A UTXO’s output index does not exist.', 'BAD_UTXO');
  if (!bytesEqual(output.script, expectedScript)) fail('A UTXO does not belong to this address.', 'BAD_UTXO');
  if (output.value <= 0n || output.value > BTC_MAX_SATS) fail('A UTXO value is out of range.', 'BAD_UTXO');
  return Object.freeze({ txid, vout, value: output.value, scriptpubkey: bytesToHex(output.script) });
}
