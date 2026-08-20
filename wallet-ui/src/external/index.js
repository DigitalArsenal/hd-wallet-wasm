/*
 * hd-wallet-ui/external — the external-wallet component (owner 2026-08-20:
 * this is the ONE copy every app consumes; owner 2026-08-19: external wallet
 * is the FIRST sign-in path, the built-in HD wallet is the backup).
 *
 * ZERO-DEPENDENCY FIREWALL (HERMES/ARACHNE 2026-08-20): nothing under
 * src/external/ imports the HD custody world — no wallet core, no crypto
 * deps, no storage. The two worlds meet ONLY through the read-only
 * normalized account shape in accounts.js. See README.md for the standing
 * refusals (WalletConnect, iframes, UA sniffing, external-origin bytes).
 */

export {
  accountKey,
  decodeBase58,
  evmAddressKey,
  isEvmAddress,
  isReverseDns,
  isSolanaAddress,
  normalizeEvmAccount,
  normalizeSolanaAccount,
  normalizeWalletInfo,
  sanitizeIcon,
} from './accounts.js';

export { chainLabel } from './chains.js';

export {
  ANNOUNCE_SCHEDULE_MS,
  ETHEREUM_INITIALIZED,
  EVM_ANNOUNCE,
  EVM_REQUEST,
  SOLANA_APP_READY,
  SOLANA_REGISTER,
  createDiscovery,
  isSolanaStandardWallet,
} from './discovery.js';

export { truncateMiddle } from './format.js';

export { createExternalWalletPanel } from './panel.js';

export {
  bytesToHex,
  connectEvm,
  connectSolana,
  normalizeProviderError,
  parseChainId,
  personalSign,
  signSolanaMessage,
  toPersonalSignRequest,
  watchEvmProvider,
} from './provider.js';
