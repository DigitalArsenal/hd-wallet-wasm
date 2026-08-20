/*
 * CHAIN BADGES — the display name for an EVM chain id. Pure data + one
 * lookup so the badge is a computable outcome, not markup. Unknown chains
 * stay honest: the numeric id, never a guess.
 *
 * HOME: hd-wallet-ui src/external (owner 2026-08-20). Ported byte-verbatim
 * from spaceaware-ui src/dashboard/src/lib/wallet-external/chains.js (task
 * sdn-wallet-external-signin-surface) — header relabel only.
 */

const CHAIN_LABELS = Object.freeze({
  1: 'ETHEREUM',
  10: 'OPTIMISM',
  56: 'BNB CHAIN',
  137: 'POLYGON',
  8453: 'BASE',
  42161: 'ARBITRUM',
  43114: 'AVALANCHE',
  11155111: 'SEPOLIA',
});

/** @returns {string} the badge text for a chain id ('' for null/absent). */
export function chainLabel(chainId) {
  if (!Number.isInteger(chainId) || chainId <= 0) return '';
  return CHAIN_LABELS[chainId] ?? `CHAIN ${chainId}`;
}
