/*
 * THE PROVIDER HANDSHAKE — EIP-1193 request() on the EVM lane, Wallet
 * Standard features on the Solana lane.
 *
 * HOME: hd-wallet-ui src/external (owner 2026-08-20). Ported byte-verbatim
 * from spaceaware-ui src/dashboard/src/lib/wallet-external/provider.js
 * (task sdn-wallet-external-provider-lane) — header relabel only.
 *
 * CUSTODY: the wallet holds the key; this module only ever sees addresses,
 * public keys and signatures. Nothing here persists anything, and nothing
 * here constructs the MESSAGES that get signed — SIWE/§20 message format is
 * the sign-in surface's contract (sdn-admin-contract-s20-external-wallet).
 * The wire builders are pure and exported so the exact request bytes are a
 * testable outcome, not a source pattern.
 *
 * SIGNATURE BYTES PASS THROUGH VERBATIM. personal_sign yields 65 bytes
 * [R||S||V]; the server's internal/chainsig verifier owns byte-order
 * normalization (dcrd compact is [V||R||S] — the silent wrong-key trap).
 * Reordering here would hide the trap instead of fixing it.
 */

import { normalizeEvmAccount, normalizeSolanaAccount } from './accounts.js';

/** Uint8Array → 0x-prefixed lowercase hex. */
export function bytesToHex(bytes) {
  let out = '0x';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/**
 * The exact personal_sign wire request (EIP-191). Param order is
 * [message, address] — several wallets silently ACCEPT the reversed order and
 * sign the wrong bytes, so the order is pinned here and tested.
 *
 * @param {{address: string, message: Uint8Array}} args
 */
export function toPersonalSignRequest({ address, message }) {
  if (!(message instanceof Uint8Array) || message.length === 0) {
    throw new Error('personal_sign takes the message BYTES — encode before signing.');
  }
  return {
    method: 'personal_sign',
    params: [bytesToHex(message), String(address ?? '').trim()],
  };
}

/**
 * Classify an EIP-1193 provider error into what the UI can act on.
 * Codes: EIP-1193 §Provider Errors + EIP-1474 + MetaMask's -32002 pending.
 */
export function normalizeProviderError(err) {
  const code = Number(err?.code ?? NaN);
  const message = String(err?.message ?? '').trim() || 'The wallet refused the request.';
  const kind =
    code === 4001 ? 'rejected'
    : code === -32002 ? 'pending'
    : code === 4100 ? 'unauthorized'
    : code === 4200 || code === -32601 ? 'unsupported'
    : code === 4900 || code === 4901 ? 'disconnected'
    : code === 4902 ? 'chain-missing'
    : 'other';
  return { kind, code: Number.isNaN(code) ? null : code, message };
}

/** eth_chainId ("0x1") → integer, or null on anything malformed. */
export function parseChainId(value) {
  const raw = String(value ?? '').trim();
  if (!/^0x[0-9a-fA-F]+$/.test(raw)) return null;
  const n = Number.parseInt(raw, 16);
  return Number.isSafeInteger(n) && n > 0 ? n : null;
}

/**
 * Connect on the EVM lane: eth_requestAccounts + eth_chainId, normalized.
 * Only valid addresses survive; an empty result is the wallet's "no".
 *
 * @param {{request: Function}} provider — the EIP-1193 provider
 * @param {object|null} wallet — the normalized EIP-6963 info for attribution
 * @returns {Promise<{accounts: object[], chainId: number|null}>}
 */
export async function connectEvm(provider, wallet = null) {
  if (typeof provider?.request !== 'function') {
    throw new Error('Not an EIP-1193 provider: no request().');
  }
  const addresses = await provider.request({ method: 'eth_requestAccounts' });
  let chainId = null;
  try {
    chainId = parseChainId(await provider.request({ method: 'eth_chainId' }));
  } catch {
    /* a wallet that cannot answer eth_chainId still yields usable accounts */
  }
  const accounts = (Array.isArray(addresses) ? addresses : [])
    .map((address) => normalizeEvmAccount({ address, chainId, wallet }))
    .filter(Boolean);
  return { accounts, chainId };
}

/**
 * EIP-191 personal_sign. Returns the signature EXACTLY as the wallet returned
 * it (0x + 130 hex = 65 bytes [R||S||V]) — see the header for why.
 */
export async function personalSign(provider, { address, message }) {
  const signature = await provider.request(toPersonalSignRequest({ address, message }));
  const value = String(signature ?? '').trim();
  if (!/^0x[0-9a-fA-F]{130}$/.test(value)) {
    throw new Error(`personal_sign returned ${value.length} chars — expected 65 bytes of [R||S||V] hex.`);
  }
  return value;
}

/**
 * Subscribe to the provider's session events, normalizing payloads before
 * any consumer sees them. Providers without .on() (some in-app webviews)
 * yield a no-op unsubscribe — polling is the SURFACE's decision, not ours.
 *
 * @returns {() => void} unsubscribe
 */
export function watchEvmProvider(provider, { onAccounts, onChain, onDisconnect } = {}, wallet = null) {
  if (typeof provider?.on !== 'function') return () => {};
  const off = typeof provider.removeListener === 'function'
    ? (event, fn) => provider.removeListener(event, fn)
    : () => {};
  const accountsChanged = (addresses) => {
    const accounts = (Array.isArray(addresses) ? addresses : [])
      .map((address) => normalizeEvmAccount({ address, wallet }))
      .filter(Boolean);
    onAccounts?.(accounts);
  };
  const chainChanged = (value) => onChain?.(parseChainId(value));
  const disconnect = (err) => onDisconnect?.(normalizeProviderError(err));
  provider.on('accountsChanged', accountsChanged);
  provider.on('chainChanged', chainChanged);
  provider.on('disconnect', disconnect);
  return () => {
    off('accountsChanged', accountsChanged);
    off('chainChanged', chainChanged);
    off('disconnect', disconnect);
  };
}

/**
 * Connect on the Solana lane through Wallet Standard features.
 * The base58 address IS the Ed25519 public key; both are surfaced.
 */
export async function connectSolana(wallet) {
  const connect = wallet?.features?.['standard:connect']?.connect;
  if (typeof connect !== 'function') {
    throw new Error('Not a Wallet Standard wallet: no standard:connect.');
  }
  const result = await connect();
  const accounts = (Array.isArray(result?.accounts) ? result.accounts : [])
    .map((account) => normalizeSolanaAccount({ address: account?.address, wallet: { name: wallet.name } }))
    .filter(Boolean);
  return { accounts };
}

/**
 * solana:signMessage over a Wallet Standard account. Raw Ed25519 — the
 * output is NEVER admissible as an SDN §9.1 signature (the Ed25519
 * coincidence ban); the §20 contract owns domain separation.
 *
 * @returns {Promise<Uint8Array>} the 64-byte signature
 */
export async function signSolanaMessage(wallet, walletAccount, message) {
  const sign = wallet?.features?.['solana:signMessage']?.signMessage;
  if (typeof sign !== 'function') {
    throw new Error('This wallet does not offer solana:signMessage.');
  }
  if (!(message instanceof Uint8Array) || message.length === 0) {
    throw new Error('signMessage takes the message BYTES — encode before signing.');
  }
  const [result] = await sign({ account: walletAccount, message });
  const signature = result?.signature;
  if (!(signature instanceof Uint8Array) || signature.length !== 64) {
    throw new Error('The wallet returned a malformed Ed25519 signature.');
  }
  return signature;
}
