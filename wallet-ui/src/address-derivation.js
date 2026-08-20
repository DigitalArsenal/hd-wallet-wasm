/**
 * Address Derivation Module
 *
 * Functions for generating blockchain addresses from public keys:
 * BTC, ETH, SOL, SUI, Monad, Cardano
 */

import { secp256k1 } from '@noble/curves/secp256k1';
import { blake2b } from '@noble/hashes/blake2b';
import { keccak_256 } from '@noble/hashes/sha3';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as sha256Noble } from '@noble/hashes/sha256';
import { base58check, base58 } from '@scure/base';

import { coinTypeToConfig } from './constants.js';

// =============================================================================
// API Proxy (dev mode CORS workaround)
// =============================================================================

const isDev = import.meta.env?.DEV ?? false;

const proxyMap = {
  'https://blockchain.info': '/api/blockchain',
  'https://blockstream.info': '/api/blockstream',
  'https://cloudflare-eth.com': '/api/eth',
  'https://api.mainnet-beta.solana.com': '/api/solana/official',
  'https://solana-rpc.publicnode.com': '/api/solana/publicnode',
  'https://mainnet.helius-rpc.com': '/api/solana/helius',
  /* Commented out — BTC/ETH/SOL only for now
  'https://fullnode.mainnet.sui.io:443': '/api/sui',
  'https://testnet-rpc.monad.xyz': '/api/monad',
  'https://api.koios.rest': '/api/koios',
  'https://s1.ripple.com:51234': '/api/xrp',
  */
  'https://api.coinbase.com': '/api/coinbase',
  'https://api.hiro.so': '/api/hiro',
};

export function apiUrl(url) {
  if (!isDev) return url;
  for (const [origin, proxy] of Object.entries(proxyMap)) {
    if (url.startsWith(origin)) {
      return url.replace(origin, proxy);
    }
  }
  return url;
}

// =============================================================================
// Utility Helpers
// =============================================================================

/**
 * Convert a Uint8Array to a compact hex string (no spaces)
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function toHexCompact(bytes) {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Alias for toHexCompact
 */
export function toHex(bytes) {
  return toHexCompact(bytes);
}

/**
 * Convert hex string to Uint8Array
 * @param {string} hex
 * @returns {Uint8Array}
 */
export function hexToBytes(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Ensure a value is a Uint8Array.
 * Handles localStorage deserialization which produces plain objects.
 * @param {*} value
 * @returns {Uint8Array}
 */
export function ensureUint8Array(value) {
  if (value instanceof Uint8Array) {
    return value;
  }
  if (typeof value === 'object' && value !== null) {
    return new Uint8Array(Object.values(value));
  }
  return new Uint8Array(value);
}

// =============================================================================
// Base58Check encoder for Bitcoin
// =============================================================================

const base58checkBtc = base58check(sha256Noble);

// =============================================================================
// Address Generation Functions
// =============================================================================

/**
 * Generate a Bitcoin P2PKH address from a compressed secp256k1 public key
 * Uses @scure/base for proper Base58Check encoding
 * @param {Uint8Array} publicKey - Compressed secp256k1 public key (33 bytes)
 * @returns {string} Bitcoin address starting with '1'
 */
export function generateBtcAddress(publicKey) {
  const hash160 = ripemd160(sha256Noble(publicKey));
  return base58checkBtc.encode(new Uint8Array([0x00, ...hash160]));
}

/**
 * Generate an Ethereum address from a secp256k1 public key
 * Uses @noble/hashes keccak_256 for proper Ethereum address derivation
 * @param {Uint8Array} publicKey - Compressed secp256k1 public key (33 bytes)
 * @returns {string} Ethereum address with 0x prefix
 */
export function generateEthAddress(publicKey) {
  const point = secp256k1.ProjectivePoint.fromHex(publicKey);
  const uncompressed = point.toRawBytes(false); // 65 bytes: 04 || x || y
  const hash = keccak_256(uncompressed.slice(1));
  return '0x' + toHexCompact(hash.slice(-20));
}

/**
 * Generate a Solana address from an Ed25519 public key
 * Uses @scure/base for proper Base58 encoding
 * @param {Uint8Array} publicKey - Ed25519 public key (32 bytes)
 * @returns {string} Solana address
 */
export function generateSolAddress(publicKey) {
  return base58.encode(publicKey);
}

/**
 * Generate an XRP address from a compressed secp256k1 public key
 * Uses SHA-256 → RIPEMD-160 hash, then Base58Check with version byte 0x00
 * @param {Uint8Array} publicKey - Compressed secp256k1 public key (33 bytes)
 * @returns {string} XRP address starting with 'r'
 */
export function generateXrpAddress(publicKey) {
  const hash160 = ripemd160(sha256Noble(publicKey));
  // XRP uses the same Base58Check as BTC but the alphabet produces 'r' prefix
  return base58checkBtc.encode(new Uint8Array([0x00, ...hash160]));
}

/**
 * Derive an Ethereum/Monad-compatible address from a secp256k1 public key.
 * Handles compressed (33 bytes), uncompressed (65 bytes), and raw (64 bytes) formats.
 * @param {Uint8Array} publicKey
 * @returns {string|null} Ethereum address with 0x prefix, or null on failure
 */
export function deriveEthAddress(publicKey) {
  try {
    if (publicKey.length === 33) {
      const point = secp256k1.ProjectivePoint.fromHex(publicKey);
      const uncompressed = point.toRawBytes(false).slice(1);
      const hash = keccak_256(uncompressed);
      return '0x' + toHex(hash.slice(-20));
    }
    if (publicKey.length === 65) {
      const hash = keccak_256(publicKey.slice(1));
      return '0x' + toHex(hash.slice(-20));
    }
    if (publicKey.length === 64) {
      const hash = keccak_256(publicKey);
      return '0x' + toHex(hash.slice(-20));
    }
    return null;
  } catch (e) {
    return null;
  }
}

/**
 * Derive a SUI address from a public key using BLAKE2b
 * @param {Uint8Array} publicKey - Public key bytes
 * @param {string} scheme - Key scheme: 'ed25519', 'secp256k1', or 'secp256r1'
 * @returns {string} SUI address with 0x prefix
 */
export function deriveSuiAddress(publicKey, scheme = 'ed25519') {
  const schemeFlags = {
    'ed25519': 0x00,
    'secp256k1': 0x01,
    'secp256r1': 0x02,
  };
  const flag = schemeFlags[scheme] ?? 0x00;

  const data = new Uint8Array(1 + publicKey.length);
  data[0] = flag;
  data.set(publicKey, 1);

  const hash = blake2b(data, { dkLen: 32 });
  return '0x' + Array.from(hash).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Derive a Monad address from a secp256k1 public key (same as Ethereum derivation)
 * @param {Uint8Array} publicKey - secp256k1 public key (33 or 65 bytes)
 * @returns {string} Monad address with 0x prefix
 */
export function deriveMonadAddress(publicKey) {
  let uncompressedPubKey;
  if (publicKey.length === 33) {
    const point = secp256k1.ProjectivePoint.fromHex(publicKey);
    uncompressedPubKey = point.toRawBytes(false);
  } else if (publicKey.length === 65) {
    uncompressedPubKey = publicKey;
  } else {
    throw new Error('Invalid public key length for Monad address derivation');
  }

  const hash = keccak_256(uncompressedPubKey.slice(1));
  const address = hash.slice(-20);
  return '0x' + Array.from(address).map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * Derive a Cardano enterprise address from an Ed25519 public key
 * Uses Bech32 encoding with "addr" prefix for mainnet
 * @param {Uint8Array} publicKey - Ed25519 public key (32 bytes)
 * @returns {string} Cardano address in Bech32 format
 */
export function deriveCardanoAddress(publicKey) {
  const keyHash = blake2b(publicKey, { dkLen: 28 }); // 224-bit hash
  const addressBytes = new Uint8Array(29);
  addressBytes[0] = 0x61; // Enterprise address, mainnet
  addressBytes.set(keyHash, 1);
  return bech32Encode('addr', addressBytes);
}

// =============================================================================
// Bech32 Encoding (for Cardano)
// =============================================================================

function bech32Encode(prefix, data) {
  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

  const data5bit = convertBits(data, 8, 5, true);
  const checksumData = expandHrp(prefix).concat(data5bit).concat([0, 0, 0, 0, 0, 0]);
  const polymod = bech32Polymod(checksumData) ^ 1;
  const checksum = [];
  for (let i = 0; i < 6; i++) {
    checksum.push((polymod >> (5 * (5 - i))) & 31);
  }

  let result = prefix + '1';
  for (const d of data5bit.concat(checksum)) {
    result += CHARSET[d];
  }
  return result;
}

function convertBits(data, fromBits, toBits, pad) {
  let acc = 0;
  let bits = 0;
  const ret = [];
  const maxv = (1 << toBits) - 1;
  for (const value of data) {
    acc = (acc << fromBits) | value;
    bits += fromBits;
    while (bits >= toBits) {
      bits -= toBits;
      ret.push((acc >> bits) & maxv);
    }
  }
  if (pad) {
    if (bits > 0) {
      ret.push((acc << (toBits - bits)) & maxv);
    }
  }
  return ret;
}

function expandHrp(hrp) {
  const ret = [];
  for (const c of hrp) {
    ret.push(c.charCodeAt(0) >> 5);
  }
  ret.push(0);
  for (const c of hrp) {
    ret.push(c.charCodeAt(0) & 31);
  }
  return ret;
}

function bech32Polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) {
      if ((b >> i) & 1) {
        chk ^= GEN[i];
      }
    }
  }
  return chk;
}

// =============================================================================
// Composite Address Generation
// =============================================================================

/**
 * Generate BTC, ETH, and SOL addresses from a wallet key set
 * @param {{ secp256k1: { publicKey: Uint8Array }, ed25519: { publicKey: Uint8Array } }} wallet
 * @returns {{ btc: string, eth: string, sol: string }}
 */
export function generateAddresses(wallet) {
  return {
    btc: generateBtcAddress(wallet.secp256k1.publicKey),
    eth: generateEthAddress(wallet.secp256k1.publicKey),
    sol: generateSolAddress(wallet.ed25519.publicKey),
    // xrp: generateXrpAddress(wallet.secp256k1.publicKey), // Commented out — BTC/ETH/SOL only for now
  };
}

/**
 * Generate address from public key based on coin type for HD derivation
 * @param {Uint8Array} publicKey - The derived public key
 * @param {number} coinType - BIP44 coin type
 * @returns {string} The generated address
 */
export function generateAddressForCoin(publicKey, coinType) {
  const config = coinTypeToConfig[coinType];
  if (!config) {
    return toHexCompact(publicKey);
  }

  switch (coinType) {
    case 0:   // Bitcoin
    case 2:   // Litecoin
    case 3:   // Dogecoin
    case 145: // Bitcoin Cash
      return generateBtcAddress(publicKey);

    case 60:  // Ethereum
      return generateEthAddress(publicKey);

    case 501: // Solana - uses ed25519, but we generate from secp256k1 for demo
      return base58.encode(publicKey.slice(0, 32));

    case 144: // XRP
      return generateXrpAddress(publicKey);

    case 118: // Cosmos
    case 330: // Algorand
    case 354: // Polkadot
    case 1815: { // Cardano
      const hash = sha256Noble(publicKey);
      return toHexCompact(hash.slice(0, 20));
    }

    default: {
      const defaultHash = sha256Noble(publicKey);
      return toHexCompact(defaultHash.slice(0, 20));
    }
  }
}

/**
 * Truncate an address for display
 * @param {string} address
 * @returns {string}
 */
export function truncateAddress(address) {
  if (address.length <= 16) return address;
  return address.slice(0, 8) + '...' + address.slice(-6);
}

// =============================================================================
// Balance Fetching
// =============================================================================

/**
 * Fetch Bitcoin balance
 * @param {string} address
 * @returns {Promise<{balance: string, error?: string}>}
 */
export async function fetchBtcBalance(address) {
  let lastError = 'No available endpoint';

  // Primary endpoint: blockchain.info (fast/simple satoshi response)
  try {
    const response = await fetch(apiUrl(`https://blockchain.info/q/addressbalance/${address}?cors=true`));
    if (response.ok) {
      const satoshis = await response.text();
      const satoshisInt = parseInt(satoshis, 10);
      if (Number.isFinite(satoshisInt)) {
        return { balance: (satoshisInt / 1e8).toFixed(8) };
      }
      lastError = 'Invalid BTC balance response from blockchain.info';
    } else {
      lastError = `blockchain.info HTTP ${response.status}`;
    }
  } catch (e) {
    lastError = `blockchain.info ${e.message || 'request failed'}`;
  }

  // Fallback endpoint: blockstream.info (chain_stats + mempool_stats)
  try {
    const response = await fetch(apiUrl(`https://blockstream.info/api/address/${address}`));
    if (response.ok) {
      const data = await response.json();
      const chainFunded = BigInt(data?.chain_stats?.funded_txo_sum ?? 0);
      const chainSpent = BigInt(data?.chain_stats?.spent_txo_sum ?? 0);
      const mempoolFunded = BigInt(data?.mempool_stats?.funded_txo_sum ?? 0);
      const mempoolSpent = BigInt(data?.mempool_stats?.spent_txo_sum ?? 0);
      const satoshis = chainFunded - chainSpent + mempoolFunded - mempoolSpent;
      return { balance: (Number(satoshis) / 1e8).toFixed(8) };
    }
    lastError = `${lastError}; blockstream.info HTTP ${response.status}`;
  } catch (e) {
    lastError = `${lastError}; blockstream.info ${e.message || 'request failed'}`;
  }

  console.debug('BTC balance fetch unavailable:', lastError);
  return { balance: '--', error: lastError };
}

/**
 * Fetch Ethereum balance
 * @param {string} address
 * @returns {Promise<{balance: string, error?: string}>}
 */
export async function fetchEthBalance(address) {
  // Public RPCs fail independently (cloudflare-eth measured returning
  // -32603 while publicnode answered, 2026-08-20) — try each in turn.
  const endpoints = ['https://cloudflare-eth.com', 'https://ethereum-rpc.publicnode.com'];
  let lastError = 'ETH RPC unavailable';
  for (const endpoint of endpoints) {
    try {
      const response = await fetch(apiUrl(endpoint), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'eth_getBalance',
          params: [address, 'latest']
        })
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
      const balanceWei = BigInt(data.result || '0x0');
      const balanceEth = Number(balanceWei) / 1e18;
      return { balance: balanceEth.toFixed(6) };
    } catch (e) {
      console.debug('ETH balance fetch unavailable:', e.message);
      lastError = e.message;
    }
  }
  return { balance: '--', error: lastError };
}

/**
 * Fetch Solana balance
 * @param {string} address
 * @returns {Promise<{balance: string, error?: string}>}
 */
export async function fetchSolBalance(address) {
  const endpoints = [
    'https://solana-rpc.publicnode.com',
    'https://mainnet.helius-rpc.com/?api-key=1d8740dc-e5f4-421c-b823-e1bad1889eda',
    'https://api.mainnet-beta.solana.com',
  ];
  let lastError = 'No available endpoint';

  for (const endpoint of endpoints) {
    try {
      const response = await fetch(apiUrl(endpoint), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'getBalance',
          params: [address]
        })
      });
      if (!response.ok) {
        lastError = `HTTP ${response.status}`;
        continue;
      }
      const data = await response.json();
      if (data.error) {
        lastError = data.error.message || 'SOL RPC error';
        continue;
      }
      const lamports = data.result?.value || 0;
      const sol = lamports / 1e9;
      return { balance: sol.toFixed(6) };
    } catch (e) {
      lastError = e?.message || 'SOL RPC fetch error';
      continue;
    }
  }
  console.debug('SOL balance fetch unavailable: all endpoints failed');
  return { balance: '--', error: lastError };
}

// Commented out — BTC/ETH/SOL only for now
// export async function fetchSuiBalance(address) { ... }
// export async function fetchMonadBalance(address) { ... }
// export async function fetchAdaBalance(address) { ... }
// export async function fetchXrpBalance(address) { ... }
