/**
 * @file hd_wallet.h
 * @brief HD Wallet WASM - Main Header
 *
 * This is the main header file for the HD Wallet WASM library.
 * Include this file to get access to all HD wallet functionality.
 *
 * @code
 * #include <hd_wallet/hd_wallet.h>
 *
 * using namespace hd_wallet;
 *
 * // Generate mnemonic
 * auto mnemonic = bip39::generateMnemonic(24);
 *
 * // Create seed
 * auto seed = bip39::mnemonicToSeed(mnemonic.value, "passphrase");
 *
 * // Create master key
 * auto master = bip32::ExtendedKey::fromSeed(seed.value);
 *
 * // Derive key for Ethereum
 * auto ethKey = master.value.derivePath("m/44'/60'/0'/0/0");
 *
 * // Get address
 * auto address = coins::ethereum::getAddress(ethKey.value.publicKey());
 * @endcode
 *
 * Features:
 * - BIP-32 Hierarchical Deterministic key derivation
 * - BIP-39 Mnemonic phrase generation and validation
 * - BIP-44/49/84 standard derivation paths
 * - Multi-curve support (secp256k1, Ed25519, P-256, P-384, X25519)
 * - Multi-chain support (Bitcoin, Ethereum, Cosmos, Solana, Polkadot)
 * - ECDSA/EdDSA signing and verification
 * - ECDH key exchange
 * - Comprehensive hash functions
 * - Secure memory handling
 * - WASI/WebAssembly compatible
 *
 * @see https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 * @see https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki
 * @see https://github.com/satoshilabs/slips/blob/master/slip-0044.md
 */

#ifndef HD_WALLET_HD_WALLET_H
#define HD_WALLET_HD_WALLET_H

// =============================================================================
// Configuration and Types
// =============================================================================

#include "config.h"
#include "types.h"
#include "error.h"

// =============================================================================
// Core Utilities
// =============================================================================

#include "utils.h"
#include "secure_memory.h"

// =============================================================================
// BIP Standards
// =============================================================================

#include "bip39.h"
#include "bip32.h"
#include "bip44.h"
#include "slip44.h"

// =============================================================================
// Cryptography
// =============================================================================

#include "curves.h"
#include "hash.h"
#include "ecdsa.h"
#include "eddsa.h"
#include "ecdh.h"
#include "x509.h"

// =============================================================================
// Chain Support (conditionally included)
// =============================================================================

#if HD_WALLET_ENABLE_BITCOIN
#include "coins/bitcoin.h"
#endif

#if HD_WALLET_ENABLE_ETHEREUM
#include "coins/ethereum.h"
#endif

#if HD_WALLET_ENABLE_COSMOS
#include "coins/cosmos.h"
#endif

#if HD_WALLET_ENABLE_SOLANA
#include "coins/solana.h"
#endif

#if HD_WALLET_ENABLE_POLKADOT
#include "coins/polkadot.h"
#endif

// =============================================================================
// Additional Components
// =============================================================================

#include "keyring.h"
#include "wasi_bridge.h"

// =============================================================================
// Version Information
// =============================================================================

namespace hd_wallet {

/**
 * Get library version as integer
 * Format: MAJOR * 10000 + MINOR * 100 + PATCH
 */
constexpr int getVersion() {
    return HD_WALLET_VERSION_MAJOR * 10000 +
           HD_WALLET_VERSION_MINOR * 100 +
           HD_WALLET_VERSION_PATCH;
}

/**
 * Get library version as string
 */
constexpr const char* getVersionString() {
    return HD_WALLET_VERSION_STRING;
}

/**
 * Check if library was built with Crypto++ support
 */
constexpr bool hasCryptoPP() {
#if HD_WALLET_USE_CRYPTOPP
    return true;
#else
    return false;
#endif
}

/**
 * Check if library is in FIPS mode
 */
constexpr bool isFipsMode() {
#if HD_WALLET_FIPS_MODE
    return true;
#else
    return false;
#endif
}

/**
 * Check if running in WASM environment
 */
constexpr bool isWasm() {
#if HD_WALLET_IS_WASM
    return true;
#else
    return false;
#endif
}

/**
 * Get list of supported curves
 */
inline const char* getSupportedCurves() {
    return "secp256k1"
#if HD_WALLET_ENABLE_ED25519
           ",ed25519"
#endif
#if HD_WALLET_ENABLE_X25519
           ",x25519"
#endif
#if HD_WALLET_ENABLE_P256
           ",p256"
#endif
#if HD_WALLET_ENABLE_P384
           ",p384"
#endif
           ;
}

/**
 * Get list of supported coins
 */
inline const char* getSupportedCoins() {
    return ""
#if HD_WALLET_ENABLE_BITCOIN
           "bitcoin,"
#endif
#if HD_WALLET_ENABLE_ETHEREUM
           "ethereum,"
#endif
#if HD_WALLET_ENABLE_COSMOS
           "cosmos,"
#endif
#if HD_WALLET_ENABLE_SOLANA
           "solana,"
#endif
#if HD_WALLET_ENABLE_POLKADOT
           "polkadot"
#endif
           ;
}

} // namespace hd_wallet

// =============================================================================
// C API - Module Information
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_get_version();

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_get_version_string();

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_has_cryptopp();

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_is_fips_mode();

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_get_supported_coins();

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
const char* hd_get_supported_curves();

#endif // HD_WALLET_HD_WALLET_H
