/**
 * HD Wallet UI — Pure Library
 *
 * Re-exports all pure (non-DOM) modules for programmatic use.
 * No UI or DOM dependencies.
 */

// Constants & configuration
export {
  cryptoConfig,
  coinTypeToConfig,
  buildSigningPath,
  buildEncryptionPath,
  getSigningKey,
  getEncryptionKey,
  WellKnownCoinType,
  PKI_STORAGE_KEY,
} from './constants.js';

// Address derivation & utilities
export {
  toHexCompact,
  toHex,
  hexToBytes,
  ensureUint8Array,
  generateBtcAddress,
  generateEthAddress,
  generateSolAddress,
  generateXrpAddress,
  deriveEthAddress,
  deriveSuiAddress,
  deriveMonadAddress,
  deriveCardanoAddress,
  generateAddresses,
  generateAddressForCoin,
  truncateAddress,
  fetchBtcBalance,
  fetchEthBalance,
  fetchSolBalance,
  fetchSuiBalance,
  fetchMonadBalance,
  fetchAdaBalance,
  fetchXrpBalance,
} from './address-derivation.js';

// Canonical PRF-only remembered-wallet records and explicit quarantine tools.
// Key derivation and credential ceremony code remains wallet-origin only.
export {
  ACTIVE_REMEMBERED_WALLET_KEY,
  LEGACY_WALLET_QUARANTINE_KEYS,
  MAX_QUARANTINE_EXPORT_CHARACTERS,
  PENDING_REMEMBERED_WALLET_KEY,
  WalletStorageError,
  beginRememberedWalletWrite,
  commitRememberedWalletWrite,
  decodeCanonicalBase64url,
  deleteQuarantinedWalletRecord,
  exportQuarantinedWalletRecord,
  forgetRememberedWallet,
  inspectLegacyWalletQuarantine,
  inspectQuarantinedWalletStorage,
  inspectRememberedWalletStorage,
  parseRememberedWalletRecord,
  serializeRememberedWalletRecord,
  validateRememberedWalletRecord,
} from './wallet-storage.js';
