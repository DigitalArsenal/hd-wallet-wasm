/**
 * @file coin.h
 * @brief Base Coin Interface and Utilities
 *
 * Provides the abstract base class for all coin implementations and common
 * utilities shared across different blockchain networks.
 */

#ifndef HD_WALLET_COIN_H
#define HD_WALLET_COIN_H

#include "../config.h"
#include "../types.h"
#include "../bip32.h"

#include <memory>
#include <string>
#include <vector>

namespace hd_wallet {
namespace coins {

// =============================================================================
// Address Result
// =============================================================================

/**
 * Decoded address information
 */
struct DecodedAddress {
  /// Raw address bytes (typically hash160, hash256, or public key)
  ByteVector data;

  /// Address version or type indicator
  uint8_t version;

  /// Network (mainnet/testnet)
  Network network;

  /// Original address string
  std::string address;
};

// =============================================================================
// Signature Types
// =============================================================================

/**
 * ECDSA signature with recovery ID
 */
struct ECDSASignature {
  Bytes32 r;
  Bytes32 s;
  uint8_t v;  // Recovery ID (0, 1) or (27, 28) depending on format

  /// Convert to 64-byte compact format (r || s)
  Bytes64 toCompact() const;

  /// Convert to 65-byte format with recovery (r || s || v)
  Bytes65 toRecoverable() const;

  /// Parse from 64-byte compact format
  static Result<ECDSASignature> fromCompact(const Bytes64& sig);

  /// Parse from 65-byte recoverable format
  static Result<ECDSASignature> fromRecoverable(const Bytes65& sig);

  /// Convert to DER format
  ByteVector toDER() const;

  /// Parse from DER format
  static Result<ECDSASignature> fromDER(const ByteVector& der);
};

/**
 * Ed25519 signature
 */
struct Ed25519Signature {
  Bytes64 data;

  /// Get raw signature bytes
  const Bytes64& raw() const { return data; }
};

// =============================================================================
// Base Coin Interface
// =============================================================================

/**
 * Abstract base class for coin implementations
 *
 * Each coin implementation provides:
 * - Address generation from public keys
 * - Address validation and decoding
 * - Message signing and verification
 * - Network-specific configuration
 */
class Coin {
public:
  virtual ~Coin() = default;

  // ----- Identification -----

  /// Get coin type (SLIP-44)
  virtual CoinType coinType() const = 0;

  /// Get coin name (e.g., "Bitcoin", "Ethereum")
  virtual const char* name() const = 0;

  /// Get coin ticker symbol (e.g., "BTC", "ETH")
  virtual const char* symbol() const = 0;

  /// Get the curve used by this coin
  virtual Curve curve() const = 0;

  // ----- Network -----

  /// Get current network
  virtual Network network() const = 0;

  /// Set network
  virtual void setNetwork(Network net) = 0;

  // ----- Address Generation -----

  /**
   * Generate address from compressed public key
   * @param public_key 33-byte compressed public key
   * @return Address string
   */
  virtual Result<std::string> addressFromPublicKey(const Bytes33& public_key) const = 0;

  /**
   * Generate address from uncompressed public key
   * @param public_key 65-byte uncompressed public key (with 04 prefix)
   * @return Address string
   */
  virtual Result<std::string> addressFromPublicKeyUncompressed(const Bytes65& public_key) const {
    // Default: compress and use compressed version
    auto compressed = bip32::compressPublicKey(public_key, curve());
    if (!compressed.ok()) return Result<std::string>::fail(compressed.error);
    return addressFromPublicKey(compressed.value);
  }

  /**
   * Generate address from extended key
   * @param key Extended key (uses public key)
   * @return Address string
   */
  virtual Result<std::string> addressFromExtendedKey(const bip32::ExtendedKey& key) const {
    return addressFromPublicKey(key.publicKey());
  }

  // ----- Address Validation -----

  /**
   * Validate an address string
   * @param address Address to validate
   * @return Error::OK if valid, specific error otherwise
   */
  virtual Error validateAddress(const std::string& address) const = 0;

  /**
   * Check if address is valid
   */
  bool isValidAddress(const std::string& address) const {
    return validateAddress(address) == Error::OK;
  }

  /**
   * Decode an address to its components
   * @param address Address string
   * @return Decoded address information
   */
  virtual Result<DecodedAddress> decodeAddress(const std::string& address) const = 0;

  // ----- Message Signing -----

  /**
   * Sign a message with the coin's standard message format
   * @param message Message bytes to sign
   * @param private_key 32-byte private key
   * @return Signature bytes (format depends on coin)
   */
  virtual Result<ByteVector> signMessage(
    const ByteVector& message,
    const Bytes32& private_key
  ) const = 0;

  /**
   * Sign a message string
   */
  Result<ByteVector> signMessage(
    const std::string& message,
    const Bytes32& private_key
  ) const {
    ByteVector msg(message.begin(), message.end());
    return signMessage(msg, private_key);
  }

  /**
   * Verify a message signature
   * @param message Original message bytes
   * @param signature Signature to verify
   * @param public_key Public key (format depends on coin)
   * @return true if signature is valid
   */
  virtual Result<bool> verifyMessage(
    const ByteVector& message,
    const ByteVector& signature,
    const ByteVector& public_key
  ) const = 0;

  // ----- BIP-44 Derivation Path -----

  /**
   * Get default derivation path for this coin
   * @param account Account index
   * @param change Change (0 for external, 1 for internal)
   * @param index Address index
   * @return Derivation path string
   */
  virtual std::string getDerivationPath(
    uint32_t account = 0,
    uint32_t change = 0,
    uint32_t index = 0
  ) const;

  /**
   * Get BIP-44 purpose for this coin
   * Default is 44', but some coins use different purposes (e.g., 84' for SegWit)
   */
  virtual uint32_t defaultPurpose() const { return 44; }
};

// =============================================================================
// Coin Registry
// =============================================================================

/**
 * Get a coin instance by type
 * @param type Coin type
 * @param network Network (default: mainnet)
 * @return Shared pointer to coin instance
 */
std::shared_ptr<Coin> getCoin(CoinType type, Network network = Network::MAINNET);

/**
 * Register a custom coin implementation
 * @param coin Coin instance to register
 */
void registerCoin(std::shared_ptr<Coin> coin);

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Hash160: RIPEMD160(SHA256(data))
 * Used for Bitcoin P2PKH and P2SH addresses
 */
ByteVector hash160(const ByteVector& data);
ByteVector hash160(const uint8_t* data, size_t len);

/**
 * Double SHA256: SHA256(SHA256(data))
 * Used for Bitcoin transaction hashes and checksums
 */
Bytes32 doubleSha256(const ByteVector& data);
Bytes32 doubleSha256(const uint8_t* data, size_t len);

/**
 * Keccak256 hash
 * Used for Ethereum addresses and hashes
 */
Bytes32 keccak256(const ByteVector& data);
Bytes32 keccak256(const uint8_t* data, size_t len);

/**
 * BLAKE2b hash with specified output length
 * Used for Polkadot/Substrate
 */
ByteVector blake2b(const ByteVector& data, size_t output_len = 32);

/**
 * SHA512 hash
 */
Bytes64 sha512(const ByteVector& data);

// =============================================================================
// Encoding Functions
// =============================================================================

/**
 * Base58 encoding (no checksum)
 */
std::string base58Encode(const ByteVector& data);
Result<ByteVector> base58Decode(const std::string& str);

/**
 * Base58Check encoding (with 4-byte checksum)
 * Used for Bitcoin addresses
 */
std::string base58CheckEncode(const ByteVector& data);
Result<ByteVector> base58CheckDecode(const std::string& str);

/**
 * Bech32 encoding
 * Used for Bitcoin SegWit addresses (bc1q...) and Cosmos addresses
 */
std::string bech32Encode(const std::string& hrp, const ByteVector& data, uint8_t witness_version = 0);

/**
 * A decoded SegWit address: lowercase HRP, witness version, witness program.
 */
struct SegwitAddress {
  std::string hrp;
  uint8_t witness_version;
  ByteVector program;
};

/**
 * Decode a SegWit address (BIP-173, BIP-350): one case, at most 90
 * characters, the checksum variant its witness version requires (bech32 for
 * v0, bech32m for v1-v16), a 2-40 byte program (20 or 32 bytes for v0) with
 * at most 4 zero padding bits. INVALID_CHECKSUM when neither checksum holds,
 * INVALID_ADDRESS otherwise.
 */
Result<SegwitAddress> decodeSegwitAddress(const std::string& str);

/**
 * decodeSegwitAddress without the witness version: (hrp, program). A caller
 * that maps an address to a script needs the version; use decodeSegwitAddress.
 */
Result<std::pair<std::string, ByteVector>> bech32Decode(const std::string& str);

/**
 * Bech32m encoding (BIP-350)
 * Used for Bitcoin Taproot addresses (bc1p...)
 */
std::string bech32mEncode(const std::string& hrp, const ByteVector& data, uint8_t witness_version = 1);
Result<std::pair<std::string, ByteVector>> bech32mDecode(const std::string& str);

/**
 * SS58 encoding
 * Used for Polkadot/Substrate addresses
 */
std::string ss58Encode(const ByteVector& public_key, uint16_t network_id);
Result<std::pair<uint16_t, ByteVector>> ss58Decode(const std::string& address);

/**
 * Hex encoding utilities
 */
std::string toHex(const ByteVector& data, bool prefix = false);
std::string toHex(const uint8_t* data, size_t len, bool prefix = false);
Result<ByteVector> fromHex(const std::string& hex);

// =============================================================================
// ECDSA Operations
// =============================================================================

/**
 * Sign data with secp256k1
 * @param hash 32-byte message hash
 * @param private_key 32-byte private key
 * @return ECDSA signature
 */
Result<ECDSASignature> ecdsaSign(const Bytes32& hash, const Bytes32& private_key);

/**
 * Verify ECDSA signature
 * @param hash 32-byte message hash
 * @param signature Signature to verify
 * @param public_key Compressed (33-byte) or uncompressed (65-byte) public key
 * @return true if signature is valid
 */
Result<bool> ecdsaVerify(const Bytes32& hash, const ECDSASignature& signature, const ByteVector& public_key);

/**
 * Recover public key from signature
 * @param hash 32-byte message hash
 * @param signature Signature with recovery ID
 * @return Recovered compressed public key
 */
Result<Bytes33> ecdsaRecover(const Bytes32& hash, const ECDSASignature& signature);

// =============================================================================
// Ed25519 Operations
// =============================================================================

/**
 * Sign data with Ed25519
 * @param message Message to sign (any length)
 * @param private_key 32-byte private key (seed)
 * @return Ed25519 signature
 */
Result<Ed25519Signature> ed25519Sign(const ByteVector& message, const Bytes32& private_key);

/**
 * Verify Ed25519 signature
 * @param message Original message
 * @param signature Signature to verify
 * @param public_key 32-byte public key
 * @return true if signature is valid
 */
Result<bool> ed25519Verify(const ByteVector& message, const Ed25519Signature& signature, const Bytes32& public_key);

/**
 * Derive Ed25519 public key from private key
 * @param private_key 32-byte private key (seed)
 * @return 32-byte public key
 */
Result<Bytes32> ed25519PublicKey(const Bytes32& private_key);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_coin_address_from_pubkey(
  int32_t coin_type,
  int32_t network,
  const uint8_t* public_key,
  size_t pubkey_len,
  char* address_out,
  size_t address_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_coin_validate_address(
  int32_t coin_type,
  int32_t network,
  const char* address
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_coin_sign_message(
  int32_t coin_type,
  const uint8_t* message,
  size_t message_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t* signature_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_coin_verify_message(
  int32_t coin_type,
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  const uint8_t* public_key,
  size_t pubkey_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_base58_encode(
  const uint8_t* data,
  size_t data_len,
  char* output,
  size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_base58_decode(
  const char* str,
  uint8_t* output,
  size_t* output_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_base58check_encode(
  const uint8_t* data,
  size_t data_len,
  char* output,
  size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_base58check_decode(
  const char* str,
  uint8_t* output,
  size_t* output_len
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_bech32_encode(
  const char* hrp,
  const uint8_t* data,
  size_t data_len,
  uint8_t witness_version,
  char* output,
  size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_bech32_decode(
  const char* str,
  char* hrp_out,
  size_t hrp_size,
  uint8_t* data_out,
  size_t* data_len
);

} // namespace coins
} // namespace hd_wallet

#endif // HD_WALLET_COIN_H
