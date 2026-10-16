/**
 * Wallet Constants
 *
 * Coin type configurations, explorer URLs, and derivation path helpers.
 */

// =============================================================================
// Crypto Configuration
// =============================================================================

export const cryptoConfig = {
  btc: {
    name: 'Bitcoin',
    symbol: 'BTC',
    coinType: 0,
    explorer: 'https://blockstream.info/address/',
    balanceApi: 'https://blockstream.info/api/address/',
    formatBalance: (satoshis) => `${(satoshis / 100000000).toFixed(8)} BTC`,
  },
  eth: {
    name: 'Ethereum',
    symbol: 'ETH',
    coinType: 60,
    explorer: 'https://etherscan.io/address/',
    balanceApi: null,
    formatBalance: (wei) => `${(parseFloat(wei) / 1e18).toFixed(6)} ETH`,
  },
  sol: {
    name: 'Solana',
    symbol: 'SOL',
    coinType: 501,
    explorer: 'https://solscan.io/account/',
    balanceApi: null,
    formatBalance: (lamports) => `${(lamports / 1e9).toFixed(4)} SOL`,
  },
  /* Commented out — BTC/ETH/SOL only for now
  ltc: { name: 'Litecoin', symbol: 'LTC', coinType: 2, explorer: 'https://blockchair.com/litecoin/address/', balanceApi: null, formatBalance: (lits) => `${(lits / 100000000).toFixed(8)} LTC` },
  bch: { name: 'Bitcoin Cash', symbol: 'BCH', coinType: 145, explorer: 'https://blockchair.com/bitcoin-cash/address/', balanceApi: null, formatBalance: (sats) => `${(sats / 100000000).toFixed(8)} BCH` },
  doge: { name: 'Dogecoin', symbol: 'DOGE', coinType: 3, explorer: 'https://dogechain.info/address/', balanceApi: null, formatBalance: (sats) => `${(sats / 100000000).toFixed(4)} DOGE` },
  atom: { name: 'Cosmos', symbol: 'ATOM', coinType: 118, explorer: 'https://www.mintscan.io/cosmos/address/', balanceApi: null, formatBalance: (uatom) => `${(uatom / 1e6).toFixed(6)} ATOM` },
  algo: { name: 'Algorand', symbol: 'ALGO', coinType: 330, explorer: 'https://algoexplorer.io/address/', balanceApi: null, formatBalance: (microalgos) => `${(microalgos / 1e6).toFixed(6)} ALGO` },
  dot: { name: 'Polkadot', symbol: 'DOT', coinType: 354, explorer: 'https://polkascan.io/polkadot/account/', balanceApi: null, formatBalance: (planks) => `${(planks / 1e10).toFixed(4)} DOT` },
  ada: { name: 'Cardano', symbol: 'ADA', coinType: 1815, explorer: 'https://cardanoscan.io/address/', balanceApi: null, formatBalance: (lovelace) => `${(lovelace / 1e6).toFixed(6)} ADA` },
  xrp: { name: 'Ripple', symbol: 'XRP', coinType: 144, explorer: 'https://xrpscan.com/account/', balanceApi: null, formatBalance: (drops) => `${(drops / 1e6).toFixed(6)} XRP` },
  */
};

// Coin type to config mapping
export const coinTypeToConfig = Object.fromEntries(
  Object.entries(cryptoConfig).map(([key, config]) => [config.coinType, { key, ...config }])
);

// =============================================================================
// Derivation Path Helpers (re-exported from hd-wallet-wasm)
// =============================================================================

export { buildSigningPath, buildEncryptionPath, getSigningKey, getEncryptionKey, WellKnownCoinType } from 'hd-wallet-wasm';

// =============================================================================
// Storage keys
// =============================================================================

export const STORED_WALLET_KEY = 'encrypted_wallet';
export const PASSKEY_CREDENTIAL_KEY = 'passkey_credential';
export const PASSKEY_WALLET_KEY = 'passkey_wallet';
