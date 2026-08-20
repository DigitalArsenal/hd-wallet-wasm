/*
 * The NORMALIZED ACCOUNT CONTRACT — the one read-only shape both identity
 * worlds share.
 *
 * HOME: hd-wallet-ui src/external (owner 2026-08-20: the external-wallet code
 * lives here and every app consumes it as a component). Ported byte-verbatim
 * from spaceaware-ui src/dashboard/src/lib/wallet-external/accounts.js (task
 * sdn-wallet-external-provider-lane; ARACHNE R1/R2) — header relabel only.
 *
 * KEY-ROLE GRAMMAR (IRIS 2026-08-19): an external chain account is VALUE the
 * operator attaches, never AUTHORITY over any node. The HD custody world
 * (this package's wallet core) owns key custody; this file owns the shape a
 * chain account is reduced to before anything else in a consuming app may
 * look at it. Everything here is pure — no DOM, no provider calls, and ZERO
 * imports from the custody world (the two worlds meet ONLY through this
 * read-only shape).
 *
 * ZERO EXTERNAL-ORIGIN BYTES: a wallet's self-declared icon is admitted ONLY
 * as a data: URI (EIP-6963 §Provider Info requires exactly that). Any other
 * scheme would make the page fetch external bytes the moment it rendered, so
 * it is stripped — the wallet stays usable, its icon does not.
 */

/** EIP-6963 requires a data URI; we further require it to declare an image. */
const DATA_IMAGE = /^data:image\/[a-z0-9.+-]+[;,]/i;

/** Reverse-DNS as EIP-6963 `info.rdns` means it: at least two dot-labels. */
const REVERSE_DNS = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/i;

const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

/**
 * The digit-accumulation loop below is O(n²), and the input comes from a
 * WALLET'S OWN connect() result — hostile by assumption. A 32-byte key is at
 * most 44 base58 chars; this bound keeps the worst case trivial while leaving
 * headroom for any future non-address consumer.
 */
const BASE58_MAX_CHARS = 128;

/** A wallet icon survives only as a data:image/* URI; everything else → null. */
export function sanitizeIcon(icon) {
  const value = String(icon ?? '').trim();
  return DATA_IMAGE.test(value) ? value : null;
}

/** EIP-6963 `info.rdns` validity ("com.example.wallet"). */
export function isReverseDns(rdns) {
  const value = String(rdns ?? '').trim();
  return value.length > 0 && value.length <= 255 && REVERSE_DNS.test(value);
}

/** 0x + 40 hex — the only EVM address form this lane admits. */
export function isEvmAddress(address) {
  return EVM_ADDRESS.test(String(address ?? '').trim());
}

/**
 * The IDENTITY form of an EVM address: lowercase hex. EIP-55 checksum casing
 * is a DISPLAY property; two casings of one account must compare equal.
 */
export function evmAddressKey(address) {
  const value = String(address ?? '').trim();
  return isEvmAddress(value) ? value.toLowerCase() : '';
}

/**
 * Base58 (Bitcoin alphabet) → bytes, or null on any invalid character or an
 * input past BASE58_MAX_CHARS. Small and dependency-free on purpose: this
 * page ships zero external bytes, and the only consumer is 32-byte Solana
 * public-key validation.
 */
export function decodeBase58(text) {
  const value = String(text ?? '');
  if (value.length === 0 || value.length > BASE58_MAX_CHARS) return null;
  const bytes = [];
  for (const ch of value) {
    const digit = BASE58_ALPHABET.indexOf(ch);
    if (digit < 0) return null;
    let carry = digit;
    for (let i = 0; i < bytes.length; i += 1) {
      carry += bytes[i] * 58;
      bytes[i] = carry & 0xff;
      carry >>= 8;
    }
    while (carry > 0) {
      bytes.push(carry & 0xff);
      carry >>= 8;
    }
  }
  // Leading '1's are leading zero bytes.
  for (const ch of value) {
    if (ch !== '1') break;
    bytes.push(0);
  }
  return Uint8Array.from(bytes.reverse());
}

/** A Solana address is base58 of EXACTLY 32 bytes (an Ed25519 public key). */
export function isSolanaAddress(address) {
  const value = String(address ?? '').trim();
  // 32 bytes encode to 32–44 base58 chars; skip the decode outside that band.
  if (value.length < 32 || value.length > 44) return false;
  const decoded = decodeBase58(value);
  return decoded !== null && decoded.length === 32;
}

/**
 * Normalize an EIP-6963 `info` object. Returns null when the announce is not
 * admissible (no uuid, no name, bad rdns) — a malformed announce is IGNORED, never
 * partially trusted. A non-data icon costs the wallet its icon, nothing else.
 *
 * @returns {{uuid: string, name: string, rdns: string, icon: string|null}|null}
 */
export function normalizeWalletInfo(info) {
  const uuid = String(info?.uuid ?? '').trim();
  const name = String(info?.name ?? '').trim();
  const rdns = String(info?.rdns ?? '').trim();
  if (!uuid || !name || !isReverseDns(rdns)) return null;
  return Object.freeze({ uuid, name, rdns, icon: sanitizeIcon(info?.icon) });
}

/**
 * The normalized EVM account. `addressKey` is the identity form; `address`
 * keeps the wallet's casing for display.
 *
 * @returns {{lane: 'evm', address: string, addressKey: string,
 *            chainId: number|null, wallet: object|null}|null}
 */
export function normalizeEvmAccount({ address, chainId = null, wallet = null } = {}) {
  const key = evmAddressKey(address);
  if (!key) return null;
  const chain = Number.isInteger(chainId) && chainId > 0 ? chainId : null;
  return Object.freeze({
    lane: 'evm',
    address: String(address).trim(),
    addressKey: key,
    chainId: chain,
    wallet: wallet ?? null,
  });
}

/**
 * The normalized Solana account. The base58 address IS the public key, so the
 * identity form is the address verbatim.
 *
 * @returns {{lane: 'solana', address: string, addressKey: string,
 *            chainId: null, wallet: object|null}|null}
 */
export function normalizeSolanaAccount({ address, wallet = null } = {}) {
  const value = String(address ?? '').trim();
  if (!isSolanaAddress(value)) return null;
  return Object.freeze({
    lane: 'solana',
    address: value,
    addressKey: value,
    chainId: null,
    wallet: wallet ?? null,
  });
}

/**
 * One collision-free identity per account across both lanes — what any list,
 * dedupe, or (later) server binding keys on.
 */
export function accountKey(account) {
  if (!account?.lane || !account?.addressKey) return '';
  return `${account.lane}:${account.addressKey}`;
}
