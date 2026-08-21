/**
 * Blockchain Trust Transactions
 *
 * KeySpace-inspired trust model: all trust relationships are published
 * as on-chain transactions using OP_RETURN (Bitcoin), memo fields (Solana),
 * or transaction data (Ethereum).
 *
 * Binary encoding format (v2):
 *   Trust:      [0x54][0x01][level][timestamp:4][identity]
 *   Revocation: [0x52][0x01][timestamp:4][txhash:32]          = 38 bytes
 *
 * The trust payload carries the recipient's ADDRESS (ASCII, <= 71 bytes so
 * the record fits the 80-byte OP_RETURN budget) — the address IS the
 * identity this wallet's trust map keys on. KeySpace-style records whose
 * payload is a hex public key still parse (payload looks non-ASCII-safe).
 *
 * Free-RPC policy (owner 2026-08-21): no paid keys in public client source,
 * every scan/publish lane endpoints configurable (configureTrustRpcEndpoints).
 */

import { base58, base58check } from '@scure/base';
import { sha256 } from '@noble/hashes/sha256';
import { secp256k1 } from '@noble/curves/secp256k1';
import { ed25519 } from '@noble/curves/ed25519';
import { apiUrl } from './address-derivation.js';

// @scure/base exports base58check as a factory: base58check(sha256) returns a
// codec with encode/decode that verifies the 4-byte double-sha256 checksum.
// Calling base58check.decode(...) on the factory itself throws "not a function".
const base58checkCodec = base58check(sha256);

// =============================================================================
// Trust Levels (PGP-style)
// =============================================================================

export const TrustLevel = {
  NEVER: 1,      // Blocklist / Do not trust
  UNKNOWN: 2,    // Default / No opinion
  MARGINAL: 3,   // Some trust
  FULL: 4,       // Full trust / Can sign other keys
  ULTIMATE: 5,   // Own keys
};

export const TrustLevelNames = {
  1: 'Never',
  2: 'Unknown',
  3: 'Marginal',
  4: 'Full',
  5: 'Ultimate',
};

// =============================================================================
// Binary Constants
// =============================================================================

const MAGIC_TRUST = 0x54;    // 'T'
const MAGIC_REVOKE = 0x52;   // 'R'
const VERSION = 0x01;

// Legacy ASCII prefixes
const LEGACY_TRUST_PREFIX = 'TRUST';
const LEGACY_REVOKE_PREFIX = 'REVOKE';

// =============================================================================
// Endpoint Configuration (free tiers only — no paid keys in public source)
// =============================================================================

function isAbsoluteUrl(url) {
  return typeof url === 'string' && /^https?:\/\//i.test(url);
}

let solanaTrustRpcEndpoints = [
  'https://solana-rpc.publicnode.com',
  'https://api.mainnet-beta.solana.com',
];
let ethereumTrustRpcEndpoints = [
  'https://ethereum-rpc.publicnode.com',
  'https://cloudflare-eth.com',
];

/**
 * Configure the free-tier RPC endpoints used by the trust scanners and the
 * built-in publish lane. Replaces the lists in full — call before scanning
 * when a deployment pins its own endpoints.
 *
 * @param {{solana?: string[], ethereum?: string[]}} endpoints
 */
export function configureTrustRpcEndpoints({ solana, ethereum } = {}) {
  if (solana !== undefined) {
    const list = Array.isArray(solana) ? solana.filter(isAbsoluteUrl) : [];
    if (list.length === 0) throw new Error('configureTrustRpcEndpoints: solana needs at least one valid endpoint URL');
    solanaTrustRpcEndpoints = list;
  }
  if (ethereum !== undefined) {
    const list = Array.isArray(ethereum) ? ethereum.filter(isAbsoluteUrl) : [];
    if (list.length === 0) throw new Error('configureTrustRpcEndpoints: ethereum needs at least one valid endpoint URL');
    ethereumTrustRpcEndpoints = list;
  }
}

/** The active Solana RPC endpoint list (read-only view). */
export function getSolanaTrustRpcEndpoints() {
  return [...solanaTrustRpcEndpoints];
}

/** The active Ethereum RPC endpoint list (read-only view). */
export function getEthereumTrustRpcEndpoints() {
  return [...ethereumTrustRpcEndpoints];
}

/** Free public solana RPC endpoints usable for the built-in publish lane. */
export function getSolanaPublicRpcEndpoints() {
  return [...solanaTrustRpcEndpoints];
}

const SOLANA_TRUST_MAX_SIGNATURES = 40;
const SOLANA_TRUST_REQUEST_DELAY_MS = 350;
const SOLANA_TRUST_UNAVAILABLE_COOLDOWN_MS = 5 * 60 * 1000;
const SOLANA_MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr';
const SOLANA_MEMO_PROGRAM_ID_BYTES = base58.decode(SOLANA_MEMO_PROGRAM_ID);
const ETH_TRUST_SCAN_BLOCKS = 40;
let _solanaTrustLastRequestAt = 0;
let _solanaTrustUnavailableUntil = 0;

/**
 * Drain-alert policy: a trusted key is flagged when its on-chain balance
 * drops by at least `dropRatio` from the last observed balance.
 */
export const TRUST_DRAIN_DEFAULT_DROP_RATIO = 0.9;
let _trustDrainDropRatio = TRUST_DRAIN_DEFAULT_DROP_RATIO;

/** Configure the drain-alert threshold (0..1, default 0.9 = 90% drop). */
export function configureTrustScanning({ drainDropRatio } = {}) {
  if (drainDropRatio !== undefined) {
    const r = Number(drainDropRatio);
    if (!Number.isFinite(r) || r <= 0 || r > 1) {
      throw new Error(`configureTrustScanning: drainDropRatio must be in (0, 1], got ${r}`);
    }
    _trustDrainDropRatio = r;
  }
}

/** Current drain threshold in effect (read-only view). */
export function getTrustDrainDropRatio() {
  return _trustDrainDropRatio;
}

// =============================================================================
// Binary Encoding Helpers
// =============================================================================

function writeUint32(buf, offset, value) {
  buf[offset]     = (value >>> 24) & 0xff;
  buf[offset + 1] = (value >>> 16) & 0xff;
  buf[offset + 2] = (value >>> 8) & 0xff;
  buf[offset + 3] = value & 0xff;
}

function readUint32(buf, offset) {
  return (
    ((buf[offset] << 24) >>> 0) +
    (buf[offset + 1] << 16) +
    (buf[offset + 2] << 8) +
    buf[offset + 3]
  ) >>> 0;
}

function hexToBytes(hex) {
  const clean = hex.startsWith('0x') ? hex.slice(2) : hex;
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function bytesToBase64(bytes) {
  if (typeof btoa === 'function') {
    return btoa(String.fromCharCode(...bytes));
  }
  return Buffer.from(bytes).toString('base64');
}

function base64ToBytes(b64) {
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes;
  }
  return new Uint8Array(Buffer.from(b64, 'base64'));
}

// =============================================================================
// Binary Trust Encoding (v2)
// =============================================================================

/**
 * Encode trust metadata as compact binary Uint8Array.
 *
 * Format:
 *   Byte [0]:    Magic 0x54 ('T')
 *   Byte [1]:    Version 0x01
 *   Byte [2]:    Trust level (0x01-0x05)
 *   Bytes [3-6]: Timestamp as uint32 (seconds since epoch)
 *   Bytes [7-N]: Recipient identity bytes — the recipient's ADDRESS as
 *                ASCII so the record fits the 80-byte OP_RETURN budget
 *                (max 71 chars; addresses ARE the trust-map identity).
 *                KeySpace-style records that embed a hex pubkey still
 *                parse: payloads of non-printable bytes decode as hex.
 *
 * @param {number} level - Trust level (1-5)
 * @param {string} recipientAddress - Recipient address (BTC/ETH/SOL)
 * @param {number} [timestamp] - Unix timestamp in milliseconds (default: now)
 * @returns {Uint8Array} Binary encoded trust metadata
 */
export function encodeTrustMetadata(level, recipientAddress, timestamp = Date.now()) {
  if (level < 1 || level > 5) {
    throw new Error(`Invalid trust level: ${level}`);
  }

  const identity = String(recipientAddress ?? '').trim();
  if (!identity) {
    throw new Error('encodeTrustMetadata: recipient address is required');
  }
  const textBytes = new TextEncoder().encode(identity);
  if (textBytes.length > 71) {
    throw new Error(`Recipient address too long for the trust record (${textBytes.length} > 71 bytes)`);
  }

  const timeSec = Math.floor(timestamp / 1000);
  const buf = new Uint8Array(7 + textBytes.length);

  buf[0] = MAGIC_TRUST;
  buf[1] = VERSION;
  buf[2] = level;
  writeUint32LE(buf, 3, timeSec);
  buf.set(textBytes, 7);

  return buf;
}

/**
 * Encode revocation metadata as compact binary Uint8Array.
 *
 * Format:
 *   Byte [0]:    Magic 0x52 ('R')
 *   Byte [1]:    Version 0x01
 *   Bytes [2-5]: Timestamp as uint32 (seconds since epoch)
 *   Bytes [6-37]: Original tx hash (32 bytes)
 *
 * @param {string} originalTxHash - Hex-encoded transaction hash
 * @param {number} [timestamp] - Unix timestamp in milliseconds (default: now)
 * @returns {Uint8Array} Binary encoded revocation metadata
 */
export function encodeRevocationMetadata(originalTxHash, timestamp = Date.now()) {
  if (typeof originalTxHash !== 'string' || /^0x/i.test(originalTxHash)) {
    // Tx hashes are stored as bare lowercase hex (64 chars, no 0x prefix); a
    // prefixed hash is a caller bug, not a value to silently strip.
    throw new Error('encodeRevocationMetadata: tx hash must be bare hex (no 0x prefix)');
  }
  const hashBytes = hexToBytes(originalTxHash);
  if (hashBytes.length !== 32) {
    throw new Error(`Expected 32-byte tx hash, got ${hashBytes.length}`);
  }

  const timeSec = Math.floor(timestamp / 1000);
  const buf = new Uint8Array(38);

  buf[0] = MAGIC_REVOKE;
  buf[1] = VERSION;
  writeUint32LE(buf, 2, timeSec);
  buf.set(hashBytes, 6);

  return buf;
}

/**
 * Legacy ASCII encoder for backwards compatibility.
 * Format: TRUST:<version>:<level>:<timestamp>:<recipientAddress>
 */
export function encodeTrustMetadataLegacy(level, recipientAddress, timestamp = Date.now()) {
  if (level < 1 || level > 5) {
    throw new Error(`Invalid trust level: ${level}`);
  }
  return `${LEGACY_TRUST_PREFIX}:1:${level}:${timestamp}:${recipientAddress}`;
}

// =============================================================================
// Payload decode: ASCII addresses come back as text; hex pubkeys as hex.
// =============================================================================

function decodeIdentityPayload(bytes) {
  if (bytes.length === 0) return '';
  let printable = true;
  for (const b of bytes) {
    if (b < 0x20 || b > 0x7e) {
      printable = false;
      break;
    }
  }
  if (printable) {
    return new TextDecoder().decode(bytes);
  }
  return bytesToHex(bytes);
}

// =============================================================================
// Parsing (binary + legacy ASCII)
// =============================================================================

/**
 * Parse trust metadata from either binary (Uint8Array) or legacy ASCII string.
 * Detects format by checking the first byte: 0x54 = binary trust, 0x52 = binary revoke.
 *
 * @param {Uint8Array|string} metadata - Binary buffer or ASCII string
 * @returns {object|null} Parsed trust/revocation object, or null
 */
export function parseTrustMetadata(metadata) {
  // Binary path
  if (metadata instanceof Uint8Array || metadata instanceof ArrayBuffer) {
    const buf = metadata instanceof ArrayBuffer ? new Uint8Array(metadata) : metadata;
    return parseBinaryMetadata(buf);
  }

  // If it's a string, check if the first char signals binary
  if (typeof metadata === 'string') {
    // Could be base64-encoded binary; try legacy ASCII first
    const legacy = parseLegacyMetadata(metadata);
    if (legacy) return legacy;

    // Try base64 decode
    try {
      const bytes = base64ToBytes(metadata);
      if (bytes.length >= 38 && (bytes[0] === MAGIC_TRUST || bytes[0] === MAGIC_REVOKE)) {
        return parseBinaryMetadata(bytes);
      }
    } catch (_) {
      // not base64
    }
  }

  return null;
}

function parseBinaryMetadata(buf) {
  if (!buf || buf.length < 38) return null;

  if (buf[0] === MAGIC_TRUST && buf[1] === VERSION && buf.length >= 39) {
    const level = buf[2];
    if (level < 1 || level > 5) return null;
    const timestamp = readUint32LE(buf, 3) * 1000;
    const identity = decodeIdentityPayload(buf.slice(7));
    if (!identity) return null;

    return {
      type: 'trust',
      version: String(buf[1]),
      level,
      timestamp,
      recipientPubkey: identity,
    };
  }

  if (buf[0] === MAGIC_REVOKE && buf[1] === VERSION && buf.length >= 38) {
    const timestamp = readUint32LE(buf, 2) * 1000;
    const originalTxHash = bytesToHex(buf.slice(6, 38));

    return {
      type: 'revocation',
      version: String(buf[1]),
      originalTxHash,
      timestamp,
    };
  }

  return null;
}

function parseLegacyMetadata(str) {
  const parts = str.split(':');

  if (parts[0] === LEGACY_TRUST_PREFIX && parts.length >= 5) {
    return {
      type: 'trust',
      version: parts[1],
      level: parseInt(parts[2], 10),
      timestamp: parseInt(parts[3], 10),
      recipientPubkey: parts[4],
    };
  }

  if (parts[0] === LEGACY_REVOKE_PREFIX && parts.length >= 4) {
    return {
      type: 'revocation',
      version: parts[1],
      originalTxHash: parts[2],
      timestamp: parseInt(parts[3], 10),
    };
  }

  return null;
}

// =============================================================================
// Bitcoin OP_RETURN Trust Transactions
// =============================================================================

/**
 * Build Bitcoin OP_RETURN output data for trust transaction.
 * Uses compact binary encoding; total payload is 40-41 bytes (well within 80-byte limit).
 */
export function buildBitcoinTrustOpReturn(level, recipientPubkey) {
  const bytes = encodeTrustMetadata(level, recipientPubkey);

  if (bytes.length > 80) {
    throw new Error('Trust metadata exceeds OP_RETURN size limit (80 bytes)');
  }

  // OP_RETURN format: 0x6a (OP_RETURN) + length + data
  return {
    scriptPubKey: `6a${bytes.length.toString(16).padStart(2, '0')}${bytesToHex(bytes)}`,
    metadata: bytes,
  };
}

/**
 * Parse Bitcoin OP_RETURN data from transaction.
 * Handles both binary and legacy ASCII payloads.
 */
export function parseBitcoinOpReturn(scriptPubKey) {
  if (!scriptPubKey.startsWith('6a')) return null;

  const dataHex = scriptPubKey.slice(4);
  const bytes = hexToBytes(dataHex);

  // Try binary first
  if (bytes.length >= 38 && (bytes[0] === MAGIC_TRUST || bytes[0] === MAGIC_REVOKE)) {
    return parseBinaryMetadata(bytes);
  }

  // Fall back to legacy ASCII
  const text = new TextDecoder().decode(bytes);
  return parseLegacyMetadata(text);
}

// =============================================================================
// Solana Memo Trust Transactions
// =============================================================================

/**
 * Build Solana memo instruction for trust transaction.
 * Returns base64-encoded binary for the memo field.
 */
export function buildSolanaTrustMemo(level, recipientPubkey) {
  const bytes = encodeTrustMetadata(level, recipientPubkey);
  return bytesToBase64(bytes);
}

/**
 * Parse Solana memo from transaction.
 * Handles both base64-encoded binary and legacy ASCII memos.
 */
export function parseSolanaMemo(memo) {
  if (!memo) return null;

  // Try base64 decode for binary format
  try {
    const bytes = base64ToBytes(memo);
    if (bytes.length >= 38 && (bytes[0] === MAGIC_TRUST || bytes[0] === MAGIC_REVOKE)) {
      return parseBinaryMetadata(bytes);
    }
  } catch (_) {
    // not valid base64
  }

  // Fall back to legacy ASCII
  return parseLegacyMetadata(memo);
}

// =============================================================================
// Ethereum Data Field Trust Transactions
// =============================================================================

/**
 * Build Ethereum transaction data field for trust transaction.
 * Returns hex-encoded binary with 0x prefix.
 */
export function buildEthereumTrustData(level, recipientPubkey) {
  const bytes = encodeTrustMetadata(level, recipientPubkey);
  return '0x' + bytesToHex(bytes);
}

/**
 * Parse Ethereum transaction data field.
 * Handles both binary and legacy ASCII payloads.
 */
export function parseEthereumData(dataHex) {
  if (!dataHex || dataHex === '0x') return null;

  const bytes = hexToBytes(dataHex);

  // Binary trust format: [0x54][0x01][level][timestamp:4][identity...].
  // The identity is optional in the on-chain data field (a 7-byte prefix is a
  // valid trust record with no recipient), so the floor is 7 bytes, not 38.
  if (bytes[0] === MAGIC_TRUST && bytes[1] === VERSION) {
    if (bytes.length >= 39) return parseBinaryMetadata(bytes); // full record with identity
    if (bytes.length >= 7) {
      const level = bytes[2];
      if (level < TrustLevel.NEVER || level > TrustLevel.ULTIMATE) return null;
      return {
        type: 'trust',
        version: String(bytes[1]),
        level,
        timestamp: readUint32LE(bytes, 3) * 1000,
        recipientPubkey: bytes.length > 7 ? decodeIdentityPayload(bytes.slice(7)) : undefined,
      };
    }
    return null;
  }
  // Revocation is always 38 bytes: [0x52][0x01][timestamp:4][hash:32].
  if (bytes[0] === MAGIC_REVOKE && bytes[1] === VERSION && bytes.length >= 38) {
    return parseBinaryMetadata(bytes);
  }

  // Fall back to legacy ASCII
  const text = new TextDecoder().decode(bytes);
  return parseLegacyMetadata(text);
}

// =============================================================================
// Bitcoin publish lane — OP_RETURN trust tx built + signed in-page
// =============================================================================

const SIGHASH_ALL = 0x01;
const BTC_DUST_SATS = 546n;

function bytesToHexUpper(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

function readUint32LE(bytes, offset) {
  return bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24);
}

function writeUint32LE(bytes, offset, value) {
  bytes[offset] = value & 0xff;
  bytes[offset + 1] = (value >>> 8) & 0xff;
  bytes[offset + 2] = (value >>> 16) & 0xff;
  bytes[offset + 3] = (value >>> 24) & 0xff;
}

function writeUint64LE(bytes, offset, value) {
  const v = BigInt(value);
  for (let i = 0; i < 8; i++) {
    bytes[offset + i] = Number((v >> BigInt(8 * i)) & 0xffn);
  }
}

function writeVarInt(bytes, offset, value) {
  if (value < 0xfd) {
    bytes[offset] = value;
    return offset + 1;
  }
  bytes[offset] = 0xfd;
  writeUint32LE(bytes, offset + 1, value);
  return offset + 4;
}

function sha256d(bytes) {
  return sha256(sha256(bytes));
}

/** Reverse a Uint8Array in place order (BTC little-endian field order). */
function reverseBytes(bytes) {
  const out = new Uint8Array(bytes.length);
  for (let i = 0; i < bytes.length; i++) out[i] = bytes[bytes.length - 1 - i];
  return out;
}

function classifyInputScript(scriptHex) {
  const b = hexToBytes(scriptHex || '');
  if (b.length === 25 && b[0] === 0x76 && b[1] === 0xa9 && b[2] === 0x14 && b[23] === 0x88 && b[24] === 0xac) {
    return { type: 'p2pkh', hashBytes: b.slice(3, 23) };
  }
  if (b.length === 22 && b[0] === 0x00 && b[1] === 0x14) {
    return { type: 'p2wpkh', hashBytes: b.slice(2) };
  }
  return { type: 'other', hashBytes: null };
}

// =============================================================================
// Bech32 (BIP-173) decode — enough for bc1q change addresses.
// =============================================================================

const BECH32_CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32_POLYMOD_EXP = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

function bech32Polymod(values) {
  let chk = 1;
  for (const v of values) {
    const top = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((top >>> i) & 1) chk ^= BECH32_POLYMOD_EXP[i];
    }
  }
  return chk;
}

function bech32HrpExpand(hrp) {
  const out = [];
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) >> 5);
  out.push(0);
  for (let i = 0; i < hrp.length; i++) out.push(hrp.charCodeAt(i) & 31);
  return out;
}

/**
 * Decode a bech32 string. Returns { hrp, program: Uint8Array, version } or
 * null when checksum/encoding fails.
 */
export function decodeBech32(str) {
  const s = String(str ?? '').trim().toLowerCase();
  const pos = s.lastIndexOf('1');
  if (pos < 1 || pos + 7 > s.length) return null;
  const hrp = s.slice(0, pos);
  const data = s.slice(pos + 1);
  if (data.length < 6) return null;
  const values = [];
  for (const ch of data) {
    const v = BECH32_CHARSET.indexOf(ch);
    if (v < 0) return null;
    values.push(v);
  }
  // checksum verify (BIP-173 8-bit separator deducted in polymod)
  const check = bech32Polymod([...bech32HrpExpand(hrp), ...values]);
  if (check !== 1) return null;
  // convertbits 5 -> 8 over the data minus the 6-char checksum
  const payload = values.slice(0, -6);
  const acc = [];
  let bits = 0;
  let accBits = 0;
  for (const v of payload) {
    accBits = (accBits << 5) | v;
    bits += 5;
    if (bits >= 8) {
      acc.push((accBits >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (bits >= 5 || acc.length === 0) return null; // incomplete group
  const version = acc[0];
  return { hrp, version, program: Uint8Array.from(acc.slice(1)) };
}

/** Bitcoin address → scriptPubKey hex (p2pkh and p2wpkh v0 change outputs). */
export function btcAddressToScriptPubKey(address) {
  if (typeof address !== 'string' || address.length === 0) {
    throw new Error('btcAddressToScriptPubKey: address is required');
  }
  if (/^(1|3)[1-9A-HJ-NP-Za-km-z]{25,34}$/.test(address)) {
    const payload = base58checkCodec.decode(address);
    if (payload.length !== 21) {
      throw new Error(`btcAddressToScriptPubKey: unexpected p2pkh payload length ${payload.length}`);
    }
    const hash160 = payload.slice(1, 21);
    return `76a914${bytesToHex(hash160)}88ac`;
  }
  const bech32 = decodeBech32(address);
  if (bech32 && bech32.hrp === 'bc' && bech32.version === 0 && bech32.program.length === 20) {
    return `0014${bytesToHex(bech32.program)}`;
  }
  throw new Error(`btcAddressToScriptPubKey: unsupported address format: ${address.slice(0, 8)}…`);
}

/**
 * Build and sign a Bitcoin transaction that publishes the given trust
 * metadata as an OP_RETURN output (value 0, `6a <len> <data>`), paying the
 * tx fee from `utxos` and returning change to `changeAddress`.
 *
 * Pure and deterministic over its inputs — the exact raw bytes are a
 * testable outcome. Supports p2pkh and p2wpkh v0 inputs (SIGHASH_ALL,
 * low-s ECDSA, DER signatures).
 *
 * @param {{
 *   utxos: Array<{txid: string, vout: number, value: number, scriptpubkey: string}>,
 *   metadataBytes: Uint8Array,
 *   changeAddress: string,
 *   signPrivateKey: Uint8Array,
 *   feeSats?: number,
 * }} opts
 * @returns {{rawHex: string, txid: string}}
 */
export function btcTrustTransaction({ utxos, metadataBytes, changeAddress, signPrivateKey, feeSats = 5000 } = {}) {
  if (!Array.isArray(utxos) || utxos.length === 0) {
    throw new Error('btcTrustTransaction: at least one UTXO is required');
  }
  if (!(metadataBytes instanceof Uint8Array) || metadataBytes.length === 0 || metadataBytes.length > 80) {
    throw new Error('btcTrustTransaction: metadataBytes must be 1..80 bytes');
  }
  if (!(signPrivateKey instanceof Uint8Array) || signPrivateKey.length !== 32) {
    throw new Error('btcTrustTransaction: signPrivateKey must be 32 bytes');
  }

  const totalIn = utxos.reduce((sum, u) => sum + BigInt(Number(u.value) || 0), 0n);
  const fee = BigInt(Number(feeSats) || 0);
  if (totalIn <= fee) throw new Error('btcTrustTransaction: UTXOs do not cover the tx fee');

  const opReturn = new Uint8Array(2 + metadataBytes.length);
  opReturn[0] = 0x6a;
  opReturn[1] = metadataBytes.length;
  opReturn.set(metadataBytes, 2);

  // Outputs: the OP_RETURN, then change (when above dust).
  const outputs = [{ script: opReturn, value: 0n }];
  const change = totalIn - fee;
  if (change >= BTC_DUST_SATS) {
    if (!changeAddress) {
      throw new Error('btcTrustTransaction: a change address is required when inputs exceed the fee by more than dust');
    }
    outputs.push({ script: hexToBytes(btcAddressToScriptPubKey(changeAddress)), value: change });
  }

  // ---- prepare prevout scripts ------------------------------------------
  const prevoutScripts = utxos.map((u, i) => {
    const cls = classifyInputScript(u.scriptpubkey);
    if (cls.type === 'other') {
      throw new Error(`btcTrustTransaction: unsupported input script type at index ${i} (only p2pkh/p2wpkh v0)`);
    }
    return { type: cls.type, script: hexToBytes(u.scriptpubkey), hashBytes: cls.hashBytes };
  });

  const serialized = (sigs, witnesses, withWitness) => {
    const out = new Uint8Array(4096);
    let o = 0;
    writeUint32LE(out, o, 1); o += 4;
    if (withWitness) {
      out[o++] = 0x00; // marker
      out[o++] = 0x01; // flag
    }
    o = writeVarInt(out, o, utxos.length);
    for (let i = 0; i < utxos.length; i++) {
      const txid = hexToBytes(utxos[i].txid);
      for (let k = 0; k < 32; k++) out[o++] = txid[31 - k];
      writeUint32LE(out, o, utxos[i].vout); o += 4;
      const scriptSig = sigs[i]?.scriptSig || new Uint8Array(0);
      o = writeVarInt(out, o, scriptSig.length);
      out.set(scriptSig, o);
      o += scriptSig.length;
      writeUint32LE(out, o, 0xffffffff); o += 4;
    }
    o = writeVarInt(out, o, outputs.length);
    for (const out2 of outputs) {
      writeUint64LE(out, o, out2.value); o += 8;
      o = writeVarInt(out, o, out2.script.length);
      out.set(out2.script, o);
      o += out2.script.length;
    }
    if (withWitness) {
      for (let i = 0; i < utxos.length; i++) {
        const items = witnesses[i] || [];
        o = writeVarInt(out, o, items.length); // BIP-141: item COUNT, not byte length
        for (const item of items) {
          o = writeVarInt(out, o, item.length);
          out.set(item, o);
          o += item.length;
        }
      }
    }
    writeUint32LE(out, o, 0); o += 4;
    return out.slice(0, o);
  };

  // BIP-143 SIGHASH_ALL digests hash EVERY input's outpoint/sequence up
  // front; the p2wpkh digest then re-uses those two 32-byte hashes.
  const hasSegwit = prevoutScripts.some(p => p.type === 'p2wpkh');
  let bip143HashPrevouts = null;
  let bip143HashSequence = null;
  if (hasSegwit) {
    const outpoints = new Uint8Array(36 * utxos.length);
    const sequences = new Uint8Array(4 * utxos.length);
    let po = 0, sq = 0;
    for (const u of utxos) {
      const txid = hexToBytes(u.txid);
      for (let k = 0; k < 32; k++) outpoints[po++] = txid[31 - k];
      writeUint32LE(outpoints, po, u.vout); po += 4;
      writeUint32LE(sequences, sq, 0xffffffff); sq += 4;
    }
    bip143HashPrevouts = sha256d(outpoints);
    bip143HashSequence = sha256d(sequences);
  }

  // Build the base tx (empty scripts) to compute per-input sighashes.
  const legacySighashInputs = [];
  const segwitSighashPreimages = [];
  let withWitness = false;
  for (let i = 0; i < utxos.length; i++) {
    if (prevoutScripts[i].type === 'p2wpkh') {
      withWitness = true;
      // Segwit v0 SIGHASH_ALL digest (BIP-143): version + hashPrevouts +
      // hashSequence + outpoint + scriptCode + amount + sequence +
      // outputs + locktime + sighash type. The scriptCode for a p2wpkh
      // input is the P2PKH script (`76a914 <hash160> 88ac`), NOT the
      // witness program `0014 <hash160>` the UTXO carries.
      const scriptCode = new Uint8Array(25);
      scriptCode[0] = 0x76; scriptCode[1] = 0xa9; scriptCode[2] = 0x14;
      scriptCode.set(prevoutScripts[i].hashBytes, 3);
      scriptCode[23] = 0x88; scriptCode[24] = 0xac;
      const pre = new Uint8Array(320);
      let o = 0;
      writeUint32LE(pre, o, 1); o += 4;                    // version
      pre.set(bip143HashPrevouts, o); o += 32;
      pre.set(bip143HashSequence, o); o += 32;
      const txid = hexToBytes(utxos[i].txid);
      for (let k = 0; k < 32; k++) pre[o++] = txid[31 - k];
      writeUint32LE(pre, o, utxos[i].vout); o += 4;
      o = writeVarInt(pre, o, scriptCode.length);
      pre.set(scriptCode, o);
      o += scriptCode.length;
      writeUint64LE(pre, o, BigInt(utxos[i].value) || 0n); o += 8;
      writeUint32LE(pre, o, 0xffffffff); o += 4;           // sequence
      o = writeVarInt(pre, o, outputs.length);
      for (const out2 of outputs) {
        writeUint64LE(pre, o, out2.value); o += 8;
        o = writeVarInt(pre, o, out2.script.length);
        pre.set(out2.script, o);
        o += out2.script.length;
      }
      writeUint32LE(pre, o, 0); o += 4;                    // locktime
      writeUint32LE(pre, o, SIGHASH_ALL); o += 4;
      segwitSighashPreimages[i] = pre.slice(0, o);
    } else {
      // P2PKH: per-input sighash over a copy of the tx where ONLY this
      // input's scriptSig is the prevout script.
      const inputs = utxos.map(u => ({ txid: u.txid, vout: u.vout, scriptLen: 0, script: null }));
      inputs[i] = {
        txid: utxos[i].txid,
        vout: utxos[i].vout,
        scriptLen: prevoutScripts[i].script.length,
        script: prevoutScripts[i].script,
      };
      legacySighashInputs[i] = inputs;
    }
  }

  const sigs = [];
  const witnesses = [];
  for (let i = 0; i < utxos.length; i++) {
    let hash;
    if (prevoutScripts[i].type === 'p2wpkh') {
      const pre = segwitSighashPreimages[i];
      // BIP-143: the digest double-hashes the FULL preimage INCLUDING
      // the nHashType tail (the preimage already ends with SIGHASH_ALL).
      hash = sha256d(pre);
      let sig = secp256k1.sign(hash, signPrivateKey);
      if (sig.hasHighS()) sig = sig.normalizeS(); // low-s ECDSA (BIP 62 / strict DER)
      const der = sig.toDERRawBytes();
      const sigBytes = new Uint8Array(der.length + 1);
      sigBytes.set(der, 0);
      sigBytes[der.length] = SIGHASH_ALL;
      const pub = secp256k1.getPublicKey(signPrivateKey, true);
      // BIP-141 witness: store the item stack; the serializer writes the item
      // COUNT then per-item varint(length)+bytes (not a flattened byte length).
      witnesses[i] = [sigBytes, pub];
      sigs[i] = { scriptSig: new Uint8Array(0) };
      continue;
    }
    // P2PKH legacy sighash
    const rawInputs = legacySighashInputs[i];
    const partial = new Uint8Array(2048);
    let o = 0;
    writeUint32LE(partial, o, 1); o += 4;
    o = writeVarInt(partial, o, rawInputs.length);
    for (const input of rawInputs) {
      const txid = hexToBytes(input.txid);
      for (let k = 0; k < 32; k++) partial[o++] = txid[31 - k];
      writeUint32LE(partial, o, input.vout); o += 4;
      o = writeVarInt(partial, o, input.scriptLen);
      if (input.script) { partial.set(input.script, o); o += input.script.length; }
      writeUint32LE(partial, o, 0xffffffff); o += 4;
    }
    o = writeVarInt(partial, o, outputs.length);
    for (const out2 of outputs) {
      writeUint64LE(partial, o, out2.value); o += 8;
      o = writeVarInt(partial, o, out2.script.length);
      partial.set(out2.script, o);
      o += out2.script.length;
    }
    writeUint32LE(partial, o, 0); o += 4;
    writeUint32LE(partial, o, SIGHASH_ALL); o += 4;
    const preimage = partial.slice(0, o);
    hash = sha256d(preimage);
    let sig = secp256k1.sign(hash, signPrivateKey);
    if (sig.hasHighS()) sig = sig.normalizeS(); // low-s ECDSA (BIP 62 / strict DER)
    const der = sig.toDERRawBytes();
    const sigBytes = new Uint8Array(der.length + 1);
    sigBytes.set(der, 0);
    sigBytes[der.length] = SIGHASH_ALL;
    const pub = secp256k1.getPublicKey(signPrivateKey, true);
    const scriptSig = new Uint8Array(sigBytes.length + pub.length + 2);
    scriptSig[0] = sigBytes.length;
    scriptSig.set(sigBytes, 1);
    scriptSig[1 + sigBytes.length] = pub.length;
    scriptSig.set(pub, 2 + sigBytes.length);
    sigs[i] = { scriptSig };
  }

  const rawTx = withWitness
    ? serialized(sigs, witnesses, true)
    : serialized(sigs, witnesses, false);

  const txid = bytesToHexUpper(reverseBytes(sha256d(rawTx)));
  return { rawHex: bytesToHexUpper(rawTx), txid };
}

/**
 * Broadcast a raw Bitcoin transaction (hex) via the free blockstream
 * endpoint. Returns the txid.
 */
export async function broadcastBtcRawTx(rawHex) {
  const response = await fetch(apiUrl('https://blockstream.info/api/tx'), {
    method: 'POST',
    body: rawHex,
  });
  if (!response.ok) {
    const text = (await response.text()).slice(0, 300);
    throw new Error(`Bitcoin broadcast failed: ${response.status} ${text}`);
  }
  const txid = (await response.text()).trim();
  if (!/^[0-9a-f]{64}$/i.test(txid)) {
    throw new Error(`Bitcoin broadcast returned an unexpected txid: ${txid}`);
  }
  return txid;
}

/**
 * Encode bytes as base58 (Solana signatures come back as 64-byte
 * Uint8Arrays from external wallets; their display + explorer form is
 * base58, and revocations bind them as 64-hex).
 */
export function base58EncodeBytes(bytes) {
  return base58.encode(bytes);
}

/**
 * Fetch spendable UTXOs for a Bitcoin address (blockstream free API).
 */
export async function fetchBtcUtxos(address) {
  const response = await fetch(apiUrl(`https://blockstream.info/api/address/${address}/utxo`));
  if (!response.ok) {
    throw new Error(`Failed to fetch UTXOs: ${response.status}`);
  }
  const data = await response.json();
  if (!Array.isArray(data)) return [];
  return data
    .filter(u => u.status?.confirmed)
    .sort((a, b) => (b.value || 0) - (a.value || 0))
    .map(u => ({
      txid: u.txid,
      vout: u.vout,
      value: u.value,
      scriptpubkey: u.scriptpubkey || '',
    }));
}

// =============================================================================
// Solana publish lane — memo-program trust tx built + signed in-page
// =============================================================================

function compactLen(n) {
  if (n < 128) return [n];
  if (n < 0x4000) return [(n >> 7) | 0x80, n & 0x7f];
  if (n < 0x200000) return [(n >> 14) | 0x80, ((n >> 7) & 0x7f) | 0x80, n & 0x7f];
  return [(n >> 21) | 0x80, ((n >> 14) & 0x7f) | 0x80, ((n >> 7) & 0x7f) | 0x80, n & 0x7f];
}

function writeCompact(bytes, offset, n) {
  const L = compactLen(n);
  bytes.set(L, offset);
  return offset + L.length;
}

/**
 * Build a Solana legacy transaction that publishes trust metadata through
 * the SPL Memo program. When `signPrivateKey` is given the tx is signed
 * (ed25519 over the message) and `signatureBase58`/`rawBase64` are filled;
 * otherwise the tx comes back UNSIGNED (0 signatures) so a connected
 * external wallet can sign and send it via solana:signAndSendTransaction.
 *
 * Pure and deterministic over its inputs.
 *
 * @param {{
 *   feePayer: string,               // base58 address, signs the tx
 *   recentBlockhash: string,        // base58 blockhash
 *   metadataBytes: Uint8Array,      // trust/revocation record bytes
 *   signPrivateKey?: Uint8Array|null, // ed25519 seed (32 bytes)
 * }} opts
 * @returns {{raw: Uint8Array, rawBase64: string|null, messageBytes: Uint8Array,
 *            signatureBase58: string|null}}
 */
export function buildSolanaTrustTx({ feePayer, recentBlockhash, metadataBytes, signPrivateKey = null } = {}) {
  if (typeof feePayer !== 'string' || feePayer.length === 0) {
    throw new Error('buildSolanaTrustTx: feePayer (base58) is required');
  }
  if (typeof recentBlockhash !== 'string' || recentBlockhash.length !== 44) {
    throw new Error('buildSolanaTrustTx: recentBlockhash (base58, 44 chars) is required');
  }
  if (!(metadataBytes instanceof Uint8Array) || metadataBytes.length === 0) {
    throw new Error('buildSolanaTrustTx: metadataBytes is required');
  }

  const payerBytes = base58.decode(feePayer);
  if (payerBytes.length !== 32) {
    throw new Error('buildSolanaTrustTx: feePayer must be a 32-byte Solana public key');
  }
  const blockhashBytes = base58.decode(recentBlockhash);
  if (blockhashBytes.length !== 32) {
    throw new Error('buildSolanaTrustTx: recentBlockhash must be 32 bytes');
  }

  // Account keys: [0] payer (signer, writable), [1] memo program (read-only).
  const accounts = [payerBytes, SOLANA_MEMO_PROGRAM_ID_BYTES];
  const instrProgramIndex = 1;

  // Instruction: programIdIndex u8, accountCount u8, indices, data.
  const instruction = new Uint8Array(1 + 1 + 1 + 1 + metadataBytes.length);
  let io = 0;
  instruction[io++] = instrProgramIndex;
  instruction[io++] = 1;                       // accounts referenced
  instruction[io++] = 0;                       // payer index
  io = writeCompact(instruction, io, metadataBytes.length);
  instruction.set(metadataBytes, io);

  // Message: header + accounts + blockhash + instructions.
  const message = new Uint8Array(3 + 1 + 64 + 32 + 1 + instruction.length);
  let mo = 0;
  message[mo++] = 1;                           // numRequiredSignatures
  message[mo++] = 0;                           // numReadonlySignedAccounts
  message[mo++] = 1;                           // numReadonlyUnsignedAccounts
  message[mo++] = accounts.length;
  message.set(accounts[0], mo); mo += 32;
  message.set(accounts[1], mo); mo += 32;
  message.set(blockhashBytes, mo); mo += 32;
  message[mo++] = 1;                           // instruction count
  message.set(instruction, mo);

  const messageBytes = message;

  let raw;
  let signatureBase58 = null;
  if (signPrivateKey) {
    if (!(signPrivateKey instanceof Uint8Array) || signPrivateKey.length !== 32) {
      throw new Error('buildSolanaTrustTx: signPrivateKey must be 32 bytes');
    }
    const signature = ed25519.sign(messageBytes, signPrivateKey);
    raw = new Uint8Array(1 + 64 + messageBytes.length);
    raw[0] = 1;
    raw.set(signature, 1);
    raw.set(messageBytes, 65);
    signatureBase58 = base58.encode(signature);
  } else {
    raw = new Uint8Array(1 + messageBytes.length);
    raw[0] = 0;
    raw.set(messageBytes, 1);
  }

  const rawBase64 = typeof btoa === 'function'
    ? btoa(String.fromCharCode(...raw))
    : Buffer.from(raw).toString('base64');

  return { raw, rawBase64, messageBytes, signatureBase58 };
}

/**
 * Get the current Solana blockhash via the free RPC list.
 * @returns {Promise<string>} base58 blockhash
 */
export async function solanaGetLatestBlockhash() {
  let lastError = 'Solana RPC unavailable';
  for (const endpoint of solanaTrustRpcEndpoints) {
    try {
      const response = await fetch(apiUrl(endpoint), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'getLatestBlockhash',
          params: [{ commitment: 'finalized' }],
        }),
      });
      if (!response.ok) {
        lastError = `HTTP ${response.status}`;
        continue;
      }
      const data = await response.json();
      if (data.error) {
        lastError = data.error.message || 'Solana RPC error';
        continue;
      }
      const hash = data?.result?.value?.blockhash;
      if (typeof hash === 'string' && hash.length === 44) return hash;
      lastError = 'Malformed getLatestBlockhash response';
    } catch (e) {
      lastError = e?.message || 'Solana RPC fetch failed';
    }
  }
  throw new Error(`Cannot reach a Solana RPC (${lastError})`);
}

/**
 * Broadcast a signed Solana transaction (base64) over the free RPC list.
 * @returns {Promise<string>} the transaction signature (base58)
 */
export async function broadcastSolanaRawTx(rawBase64) {
  let lastError = 'Solana RPC unavailable';
  for (const endpoint of solanaTrustRpcEndpoints) {
    try {
      const response = await fetch(apiUrl(endpoint), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'sendTransaction',
          params: [rawBase64, { encoding: 'base64', maxRetries: 1, skipPreflight: false }],
        }),
      });
      if (!response.ok) {
        lastError = `HTTP ${response.status}`;
        continue;
      }
      const data = await response.json();
      if (data.error) {
        lastError = data.error.message || 'Solana RPC send error';
        continue;
      }
      if (typeof data.result === 'string' && data.result.length > 0) return data.result;
      lastError = 'Malformed sendTransaction response';
    } catch (e) {
      lastError = e?.message || 'Solana RPC send failed';
    }
  }
  throw new Error(`Cannot broadcast on Solana (${lastError})`);
}

// =============================================================================
// Trust Transaction Scanners
// =============================================================================

/**
 * Scan Bitcoin blockchain for trust transactions.
 * Uses block explorer API to query OP_RETURN transactions.
 */
export async function scanBitcoinTrustTransactions(address) {
  try {
    const response = await fetch(`https://blockstream.info/api/address/${address}/txs`);
    if (!response.ok) throw new Error('Failed to fetch Bitcoin transactions');

    const txs = await response.json();
    const trustTxs = [];

    for (const tx of txs) {
      for (const output of tx.vout) {
        if (output.scriptpubkey_type === 'op_return') {
          const parsed = parseBitcoinOpReturn(output.scriptpubkey);
          if (parsed) {
            trustTxs.push({
              txHash: tx.txid,
              blockHeight: tx.status.block_height,
              timestamp: tx.status.block_time * 1000,
              from: address,
              chain: 'bitcoin',
              ...parsed,
            });
          }
        }
      }
    }

    return trustTxs;
  } catch (err) {
    console.error('Bitcoin trust scan failed:', err);
    return [];
  }
}

/**
 * Scan Solana blockchain for trust transactions.
 * Uses RPC to get transactions with memo instructions.
 */
export async function scanSolanaTrustTransactions(address) {
  const isRateLimited = (msg) => {
    const t = (msg || '').toLowerCase();
    return t.includes('429') || t.includes('rate') || t.includes('limit') || t.includes('too many');
  };
  const isEndpointUnavailable = (msg) => {
    const t = (msg || '').toLowerCase();
    return t.includes('403') || t.includes('404') || t.includes('forbidden') || t.includes('not found');
  };
  const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));
  const waitForThrottle = async () => {
    const elapsed = Date.now() - _solanaTrustLastRequestAt;
    if (elapsed < SOLANA_TRUST_REQUEST_DELAY_MS) {
      await sleep(SOLANA_TRUST_REQUEST_DELAY_MS - elapsed);
    }
    _solanaTrustLastRequestAt = Date.now();
  };
  const solanaRpcCall = async (method, params) => {
    let lastError = 'Unknown Solana RPC error';

    for (const endpoint of solanaTrustRpcEndpoints) {
      try {
        await waitForThrottle();
        const response = await fetch(apiUrl(endpoint), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            jsonrpc: '2.0',
            id: 1,
            method,
            params,
          }),
        });

        if (!response.ok) {
          lastError = `HTTP ${response.status}`;
          continue;
        }

        const data = await response.json();
        if (data.error) {
          lastError = data.error.message || 'Solana RPC returned error';
          continue;
        }

        return { ok: true, result: data.result };
      } catch (e) {
        lastError = e?.message || 'Solana RPC fetch failed';
      }
    }

    return { ok: false, error: lastError };
  };

  try {
    if (Date.now() < _solanaTrustUnavailableUntil) {
      return [];
    }

    const sigResp = await solanaRpcCall('getSignaturesForAddress', [address, { limit: SOLANA_TRUST_MAX_SIGNATURES }]);
    if (!sigResp.ok) {
      if (isRateLimited(sigResp.error) || isEndpointUnavailable(sigResp.error)) {
        _solanaTrustUnavailableUntil = Date.now() + SOLANA_TRUST_UNAVAILABLE_COOLDOWN_MS;
      }
      throw new Error(`Failed to fetch Solana signatures (${sigResp.error})`);
    }

    const signatures = Array.isArray(sigResp.result) ? sigResp.result : [];

    const trustTxs = [];

    for (const sig of signatures) {
      const txResp = await solanaRpcCall('getTransaction', [sig.signature, { encoding: 'jsonParsed' }]);
      if (!txResp.ok) continue;
      const tx = txResp.result;

      if (!tx || !tx.meta) continue;

      const memos = tx.meta.logMessages?.filter(m => m.startsWith('Program log: Memo')) || [];
      for (const memoLog of memos) {
        const memo = memoLog.replace('Program log: Memo (len ', '').split('): "')[1]?.replace('"', '');
        if (memo) {
          const parsed = parseSolanaMemo(memo);
          if (parsed) {
            trustTxs.push({
              txHash: sig.signature,
              slot: tx.slot,
              timestamp: (tx.blockTime || 0) * 1000,
              from: address,
              chain: 'solana',
              ...parsed,
            });
          }
        }
      }
    }

    return trustTxs;
  } catch (err) {
    console.warn('Solana trust scan skipped:', err.message || err);
    return [];
  }
}

/**
 * Pull trust/revocation records out of full Ethereum block transaction
 * objects. A record is any tx sent FROM `address` whose data field starts
 * with the binary trust or revocation magic (0x54 / 0x52). Pure — the
 * scanner's fetch loop is the only untested seam.
 *
 * @param {object[]} txs - Block transactions (eth_getBlockByNumber v2 objects)
 * @param {string} address - Our address (the identity the scan keys on)
 * @param {number|null} blockTimestamp - Seconds since epoch (block base)
 * @returns {object[]} Trust transaction records
 */
export function extractEthereumTrustTxs(txs, address, blockTimestamp = null) {
  const own = String(address ?? '').trim().toLowerCase();
  const out = [];
  for (const tx of (Array.isArray(txs) ? txs : [])) {
    const from = String(tx?.from ?? '').toLowerCase();
    const data = String(tx?.input ?? tx?.data ?? '');
    if (from === own && /^0x(54|52)01/.test(data)) {
      const parsed = parseEthereumData(data);
      if (parsed) {
        out.push({
          txHash: String(tx?.hash ?? ''),
          blockHeight: tx?.blockNumber != null ? Number.parseInt(tx.blockNumber, 16) : null,
          timestamp: blockTimestamp != null ? blockTimestamp * 1000 : Date.now(),
          from: String(tx?.from ?? ''),
          chain: 'ethereum',
          ...parsed,
        });
      }
    }
  }
  return out;
}

/**
 * Scan Ethereum mainnet for trust transactions WITHOUT a paid API key:
 * walks recent blocks over free-tier RPCs (publicnode, cloudflare) and
 * inspects each transaction's data field for the trust/revocation magic.
 * The scan window is `blocks` back from the current tip; configurable via
 * configureTrustRpcEndpoints.
 *
 * @param {string} address - Our Ethereum address
 * @param {{blocks?: number}} [opts]
 * @returns {Promise<object[]>} Trust transaction records
 */
export async function scanEthereumTrustTransactions(address, { blocks = ETH_TRUST_SCAN_BLOCKS } = {}) {
  const rpc = async (method, params) => {
    let lastError = 'ETH RPC unavailable';
    for (const endpoint of ethereumTrustRpcEndpoints) {
      try {
        const response = await fetch(apiUrl(endpoint), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
        });
        if (!response.ok) {
          lastError = `HTTP ${response.status}`;
          continue;
        }
        const data = await response.json();
        if (data.error) {
          lastError = data.error.message || 'ETH RPC error';
          continue;
        }
        return { ok: true, result: data.result };
      } catch (e) {
        lastError = e?.message || 'ETH RPC fetch failed';
      }
    }
    return { ok: false, error: lastError };
  };

  try {
    const tipResp = await rpc('eth_blockNumber', []);
    if (!tipResp.ok) throw new Error(`Cannot reach an Ethereum RPC (${tipResp.error})`);
    const tip = Number.parseInt(tipResp.result, 16);
    if (!Number.isInteger(tip) || tip <= 0) throw new Error('Malformed eth_blockNumber response');

    const depth = Math.max(1, Math.min(Math.floor(Number(blocks) || 1), tip));
    const trustTxs = [];
    for (let i = tip - depth + 1; i <= tip; i++) {
      const blockResp = await rpc('eth_getBlockByNumber', ['0x' + i.toString(16), true]);
      if (!blockResp.ok || !blockResp.result) continue;
      const block = blockResp.result;
      const blockTime = block?.timestamp != null ? Number.parseInt(block.timestamp, 16) : null;
      trustTxs.push(...extractEthereumTrustTxs(block?.transactions, address, blockTime));
    }

    return trustTxs;
  } catch (err) {
    console.warn('Ethereum trust scan skipped:', err.message || err);
    return [];
  }
}

// =============================================================================
// Trust Relationship Analyzer
// =============================================================================

/**
 * Analyze trust relationships from a set of transactions relative to own addresses.
 *
 * Groups transactions by counterparty address and determines direction:
 *   - 'outbound': we sent trust to them
 *   - 'inbound': they sent trust to us
 *   - 'mutual': both directions exist
 *
 * @param {string[]} ownAddresses - Array of addresses belonging to the user
 * @param {object[]} transactions - Array of trust transaction objects (from scanners)
 * @returns {object[]} Array of relationship summaries
 */
export function analyzeTrustRelationships(ownAddresses, transactions) {
  const addrs = Array.isArray(ownAddresses) ? ownAddresses : Object.values(ownAddresses || {}).filter(Boolean);
  const ownSet = new Set(addrs.map(a => a.toLowerCase()));
  const counterparties = new Map(); // address -> { outbound: [], inbound: [] }

  for (const tx of transactions) {
    if (tx.type !== 'trust') continue;

    const fromAddr = (tx.from || '').toLowerCase();
    const toAddr = (tx.recipientPubkey || '').toLowerCase();
    const isFromUs = ownSet.has(fromAddr);
    const isToUs = ownSet.has(toAddr);

    const txRecord = {
      txHash: tx.txHash,
      timestamp: tx.timestamp,
      level: tx.level,
      type: tx.type,
      chain: tx.chain || 'unknown',
    };

    if (isFromUs && !isToUs) {
      // Outbound: we sent trust to them
      const key = tx.recipientPubkey;
      if (!counterparties.has(key)) {
        counterparties.set(key, { outbound: [], inbound: [] });
      }
      counterparties.get(key).outbound.push({ ...txRecord, direction: 'outbound' });
    } else if (!isFromUs && isToUs) {
      // Inbound: they sent trust to us
      const key = tx.from;
      if (!counterparties.has(key)) {
        counterparties.set(key, { outbound: [], inbound: [] });
      }
      counterparties.get(key).inbound.push({ ...txRecord, direction: 'inbound' });
    }
  }

  const results = [];

  for (const [address, data] of counterparties) {
    const allTxs = [...data.outbound, ...data.inbound];
    allTxs.sort((a, b) => b.timestamp - a.timestamp);

    let direction;
    if (data.outbound.length > 0 && data.inbound.length > 0) {
      direction = 'mutual';
    } else if (data.outbound.length > 0) {
      direction = 'outbound';
    } else {
      direction = 'inbound';
    }

    // Use the most recent trust level
    const latest = allTxs[0];

    results.push({
      address,
      chain: latest.chain,
      level: latest.level,
      direction,
      txCount: allTxs.length,
      lastSeen: latest.timestamp,
      transactions: allTxs,
    });
  }

  // Sort by most recently seen
  results.sort((a, b) => b.lastSeen - a.lastSeen);

  return results;
}

// =============================================================================
// Trust Graph Builder
// =============================================================================

/**
 * Build trust graph from scanned transactions.
 * Returns nodes (pubkeys) and edges (trust relationships).
 */
export function buildTrustGraph(trustTxs) {
  const nodes = new Map();
  const edges = [];
  const revocations = new Map();

  // First pass: collect revocations
  for (const tx of trustTxs) {
    if (tx.type === 'revocation') {
      revocations.set(tx.originalTxHash, tx.timestamp);
    }
  }

  // Second pass: build graph
  for (const tx of trustTxs) {
    if (tx.type === 'trust') {
      if (!nodes.has(tx.from)) {
        nodes.set(tx.from, {
          id: tx.from,
          label: truncatePubkey(tx.from),
          ownKey: false,
        });
      }

      if (!nodes.has(tx.recipientPubkey)) {
        nodes.set(tx.recipientPubkey, {
          id: tx.recipientPubkey,
          label: truncatePubkey(tx.recipientPubkey),
          ownKey: false,
        });
      }

      const revoked = revocations.has(tx.txHash);
      edges.push({
        from: tx.from,
        to: tx.recipientPubkey,
        level: tx.level,
        txHash: tx.txHash,
        timestamp: tx.timestamp,
        revoked,
        revokedAt: revoked ? revocations.get(tx.txHash) : null,
      });
    }
  }

  return {
    nodes: Array.from(nodes.values()),
    edges,
  };
}

// =============================================================================
// SDS Export / Import — TRE trust edges + $LOT loss-of-trust records
// (Themis trust-program mapping: level n → WEIGHT (n-1)/4, NEVER → 0.0
// (never DELETED), wallet Revocation [0x52] → $LOT. TX_HASH is the additive
// on-chain provenance field. $LOT is the loss-of-trust event grammar from
// graph/findings/adversarial-security-trust-program.md.)
// =============================================================================

/**
 * Wallet trust level (PGP 1-5) → TRE WEIGHT per the Themis map:
 * level n → (n-1)/4, so NEVER(1) → 0.0, UNKNOWN(2) → 0.25, MARGINAL(3) →
 * 0.5, FULL(4) → 0.75, ULTIMATE(5) → 1.0.
 */
export function trustLevelToWeight(level) {
  const n = Number(level);
  if (!Number.isInteger(n) || n < TrustLevel.NEVER || n > TrustLevel.ULTIMATE) {
    throw new Error(`trustLevelToWeight: invalid trust level ${level}`);
  }
  return (n - 1) / 4;
}

/** TRE WEIGHT → nearest wallet trust level (inverse of trustLevelToWeight). */
export function trustWeightToLevel(weight) {
  const w = Number(weight);
  if (!Number.isFinite(w) || w < 0 || w > 1) {
    throw new Error(`trustWeightToLevel: weight must be in [0, 1], got ${weight}`);
  }
  return Math.min(TrustLevel.ULTIMATE, Math.max(TrustLevel.NEVER, Math.round(w * 4) + 1));
}

/** chain slug (bitcoin/ethereum/solana) → key algorithm for $LOT. */
function keyAlgorithmForChain(chain) {
  if (chain === 'solana') return 'ed25519';
  return 'secp256k1';
}

/**
 * Build the SDS export document for the given wallet trust transactions.
 *
 * - trust records → TRE edges: TRUSTER_ID = sender identity, TRUSTEE_ID =
 *   recipient identity, WEIGHT per the Themis map, UPDATED_AT (ms),
 *   DELETED false, additive TX_HASH provenance, PROVIDER_PEER_ID when given.
 * - revocation records → $LOT loss-of-trust events, each bound to the
 *   original trust edge it revokes (EVIDENCE_TRANSACTION_HASHES =
 *   [revocation tx, original tx]).
 *
 * @param {object[]} transactions - Trust tx records (scanner shape)
 * @param {{xpub?: string, peerId?: string}} [opts]
 * @returns {{exportDate: string, recordTypes: string[], tre: object[], lot: object[]}}
 */
export function buildSdsTrustExport(transactions, { peerId = null } = {}) {
  const txs = Array.isArray(transactions) ? transactions : [];
  const byTxHash = new Map();
  for (const tx of txs) {
    if (tx.txHash) byTxHash.set(String(tx.txHash).toLowerCase(), tx);
  }

  const tre = [];
  const lot = [];
  const revokedHashes = new Set();

  for (const tx of txs) {
    if (tx.type !== 'trust') continue;
    const txHash = String(tx.txHash ?? '');
    const recipient = String(tx.recipientPubkey ?? '');
    // A revocation may bind to the trust edge by its transaction hash OR by the
    // trusted recipient's identity (originalTxHash == recipientPubkey).
    const revokedBy = txs.find(
      r => r.type === 'revocation' &&
        (String(r.originalTxHash ?? '').toLowerCase() === txHash.toLowerCase() ||
         String(r.originalTxHash ?? '').toLowerCase() === recipient.toLowerCase())
    );
    revokedHashes.add(String(tx.originalTxHash ?? '').toLowerCase());
    tre.push({
      EDGE_ID: `${String(tx.from ?? '')}->${String(tx.recipientPubkey ?? '')}`,
      TRUSTER_ID: String(tx.from ?? ''),
      TRUSTEE_ID: String(tx.recipientPubkey ?? ''),
      WEIGHT: trustLevelToWeight(tx.level),
      UPDATED_AT: Number(tx.timestamp) || Date.now(),
      DELETED: revokedBy ? true : false,
      TX_HASH: txHash,
      ...(peerId ? { PROVIDER_PEER_ID: peerId } : {}),
    });
  }

  for (const tx of txs) {
    if (tx.type !== 'revocation') continue;
    const originalTxHash = String(tx.originalTxHash ?? '');
    const original = byTxHash.get(originalTxHash.toLowerCase());
    const key = original?.recipientPubkey || null;
    lot.push({
      LOSS_OF_TRUST_ID: String(tx.txHash ?? ''),
      KEY_PUBLIC_KEY: key || null,
      KEY_ALGORITHM: key === null ? null : keyAlgorithmForChain(original?.chain || tx.chain),
      SCOPE_EPM_CID: null,
      SCOPE_PEER_ID: null,
      EFFECTIVE_FROM: Number(tx.timestamp) || Date.now(),
      REASON: 'Distrust',
      EVIDENCE_CHAIN: tx.chain || null,
      EVIDENCE_TRANSACTION_HASHES: [
        String(tx.txHash ?? ''),
        originalTxHash,
      ].filter(Boolean),
      EVIDENCE_BALANCE_DROP: null,
      EVIDENCE_OBSERVED_AT: Number(tx.timestamp) || Date.now(),
      OBSERVER_PEER_ID: null,
      DECLARER_PUBLIC_KEY: String(tx.from ?? '') || null,
      CREATED_AT: Number(tx.timestamp) || Date.now(),
      PROVIDER_PEER_ID: peerId,
      PROVIDER_SIGNATURE: null,
    });
  }

  return {
    exportDate: new Date().toISOString(),
    recordTypes: [...new Set(['TRE', ...(lot.length ? ['LOT'] : [])])],
    tre,
    lot,
  };
}

/**
 * Parse an SDS trust export document back into wallet trust transactions.
 * Accepts the { tre, lot } document shape. TRE WEIGHT maps back to the
 * nearest wallet level and every TRE edge restores as a trust record (its
 * DELETED flag is provenance, not a type switch — the loss-of-trust event is
 * carried by the paired $LOT record); $LOT records become revocations via
 * their EVIDENCE_TRANSACTION_HASHES[1]/original trust hash.
 *
 * @param {object} doc - Parsed SDS export document
 * @returns {object[]} Trust transaction records (scanner shape)
 */
export function parseSdsTrustImport(doc) {
  if (!doc || typeof doc !== 'object') {
    throw new Error('parseSdsTrustImport: expected an SDS export document');
  }
  const out = [];
  const seen = new Set();
  const push = (tx) => {
    const key = `${tx.type}:${String(tx.txHash ?? '')}`;
    if (!tx.txHash || seen.has(key)) return;
    seen.add(key);
    out.push(tx);
  };

  const tre = Array.isArray(doc.tre) ? doc.tre : [];
  for (const rec of tre) {
    const trustee = String(rec.TRUSTEE_ID ?? '');
    const truster = String(rec.TRUSTER_ID ?? '');
    if (!truster || !trustee) continue;
    const txHash = String(rec.TX_HASH ?? '');
    // A TRE edge (DELETED or not) restores as the trust edge itself: its
    // WEIGHT maps back to a level and the recipient survives. The loss-of-trust
    // event that flagged DELETED is carried by the paired $LOT record, which
    // imports as the revocation below.
    push({
      type: 'trust',
      txHash: txHash || `${truster}->${trustee}@${Number(rec.UPDATED_AT) || 0}`,
      timestamp: Number(rec.UPDATED_AT) || Date.now(),
      from: truster,
      recipientPubkey: trustee,
      chain: 'sds',
      level: trustWeightToLevel(rec.WEIGHT),
    });
  }

  const lot = Array.isArray(doc.lot) ? doc.lot : [];
  for (const rec of lot) {
    const hashes = Array.isArray(rec.EVIDENCE_TRANSACTION_HASHES)
      ? rec.EVIDENCE_TRANSACTION_HASHES.filter(Boolean)
      : [];
    push({
      type: 'revocation',
      txHash: String(rec.LOSS_OF_TRUST_ID ?? ''),
      originalTxHash: hashes[1] || '',
      timestamp: Number(rec.EFFECTIVE_FROM) || Date.now(),
      from: String(rec.DECLARER_PUBLIC_KEY ?? ''),
      recipientPubkey: String(rec.KEY_PUBLIC_KEY ?? ''),
      chain: rec.EVIDENCE_CHAIN || 'sds',
    });
  }

  return out;
}

// =============================================================================
// Drain detection — trusted keys are monitored client-side for balance drops
// =============================================================================

/**
 * Evaluate whether a trusted key's published address has been drained.
 * A drain is a drop of at least `dropRatio` from a previously funded
 * balance. Pure — the balance fetches live in the scan loop.
 *
 * @param {{
 *   previousBalance: number|string|null,
 *   currentBalance: number|string|null,
 *   dropRatio?: number,
 * }} opts
 * @returns {{drained: boolean, previous: number, current: number, dropRatioObserved: number, dropRatio: number}}
 */
export function evaluateTrustDrain({ previousBalance, currentBalance, dropRatio = _trustDrainDropRatio } = {}) {
  const prev = Number(previousBalance);
  const cur = Number(currentBalance);
  if (!Number.isFinite(prev) || !Number.isFinite(cur)) {
    return { drained: false, previous: prev, current: cur, dropRatioObserved: 0, dropRatio };
  }
  if (prev <= 0) {
    // Never observed funded — nothing to detect a drain against.
    return { drained: false, previous: prev, current: cur, dropRatioObserved: 0, dropRatio };
  }
  const ratio = (prev - cur) / prev;
  return {
    drained: ratio >= dropRatio && cur < prev,
    previous: prev,
    current: cur,
    dropRatioObserved: ratio,
    dropRatio,
  };
}

// =============================================================================
// Helpers
// =============================================================================

function truncatePubkey(pubkey, prefixLen = 8, suffixLen = 6) {
  if (pubkey.length <= prefixLen + suffixLen + 3) return pubkey;
  return `${pubkey.slice(0, prefixLen)}...${pubkey.slice(-suffixLen)}`;
}
