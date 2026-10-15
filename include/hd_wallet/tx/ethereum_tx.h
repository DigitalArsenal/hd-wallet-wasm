/**
 * @file ethereum_tx.h
 * @brief Ethereum Transaction Types
 *
 * Implementation of Ethereum transaction building and signing.
 *
 * Features:
 * - Legacy transactions (pre-EIP-2718)
 * - EIP-2930 transactions (type 1, access lists)
 * - EIP-1559 transactions (type 2, priority fees)
 * - RLP encoding/decoding
 * - Transaction signing with chain ID (EIP-155)
 * - Transaction hash calculation
 *
 * Reference:
 * - EIP-155: Simple replay attack protection
 * - EIP-2718: Typed Transaction Envelope
 * - EIP-2930: Optional access lists
 * - EIP-1559: Fee market change for ETH 1.0 chain
 */

#ifndef HD_WALLET_TX_ETHEREUM_TX_H
#define HD_WALLET_TX_ETHEREUM_TX_H

#include "transaction.h"
#include "../types.h"

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace hd_wallet {
namespace tx {

// =============================================================================
// Constants
// =============================================================================

/// Ethereum mainnet chain ID
constexpr uint64_t ETH_CHAIN_ID_MAINNET = 1;

/// Ethereum testnet chain IDs
constexpr uint64_t ETH_CHAIN_ID_SEPOLIA = 11155111;
constexpr uint64_t ETH_CHAIN_ID_GOERLI = 5;
constexpr uint64_t ETH_CHAIN_ID_HOLESKY = 17000;

/// Other common chain IDs
constexpr uint64_t ETH_CHAIN_ID_POLYGON = 137;
constexpr uint64_t ETH_CHAIN_ID_ARBITRUM = 42161;
constexpr uint64_t ETH_CHAIN_ID_OPTIMISM = 10;
constexpr uint64_t ETH_CHAIN_ID_BSC = 56;
constexpr uint64_t ETH_CHAIN_ID_AVALANCHE = 43114;

/// Transaction type identifiers
constexpr uint8_t ETH_TX_TYPE_LEGACY = 0;
constexpr uint8_t ETH_TX_TYPE_ACCESS_LIST = 1;
constexpr uint8_t ETH_TX_TYPE_EIP1559 = 2;

/// Default gas limit for simple transfers
constexpr uint64_t ETH_DEFAULT_GAS_LIMIT = 21000;

/// Wei per Gwei
constexpr uint64_t WEI_PER_GWEI = 1000000000ULL;

/// Wei per Ether
constexpr uint64_t WEI_PER_ETHER = 1000000000000000000ULL;

// =============================================================================
// Transaction Types
// =============================================================================

/**
 * Ethereum transaction type
 */
enum class EthTxType : uint8_t {
  /// Legacy transaction (pre-EIP-2718)
  LEGACY = 0,

  /// EIP-2930: Access list transaction
  ACCESS_LIST = 1,

  /// EIP-1559: Dynamic fee transaction
  EIP1559 = 2
};

// =============================================================================
// RLP Encoding
// =============================================================================

/**
 * RLP (Recursive Length Prefix) encoding utilities
 *
 * RLP is the serialization format used by Ethereum for encoding
 * structured data and transactions.
 */
namespace rlp {

/**
 * RLP encode a single byte string
 * @param data Byte string to encode
 * @return RLP-encoded data
 */
ByteVector encodeString(const ByteVector& data);

/**
 * RLP encode a single byte
 */
ByteVector encodeByte(uint8_t byte);

/**
 * RLP encode an integer
 * @param value Integer to encode
 * @return RLP-encoded integer (without leading zeros)
 */
ByteVector encodeInteger(uint64_t value);

/**
 * RLP encode a 256-bit integer
 * @param value 32-byte big-endian integer
 * @return RLP-encoded integer
 */
ByteVector encodeInteger256(const Bytes32& value);

/**
 * RLP encode an address (20 bytes)
 * @param address 20-byte Ethereum address
 * @return RLP-encoded address
 */
ByteVector encodeAddress(const std::array<uint8_t, 20>& address);

/**
 * RLP encode a list
 * @param items Vector of RLP-encoded items
 * @return RLP-encoded list
 */
ByteVector encodeList(const std::vector<ByteVector>& items);

/**
 * RLP encode a list from raw items
 * @param items Raw items to encode and wrap in list
 * @return RLP-encoded list
 */
ByteVector encodeListRaw(const std::vector<ByteVector>& items);

/**
 * Get the RLP length prefix
 * @param length Length of data
 * @param offset Offset for type (0x80 for string, 0xc0 for list)
 * @return Length prefix bytes
 */
ByteVector lengthPrefix(size_t length, uint8_t offset);

/**
 * Decode RLP data
 * @param data RLP-encoded data
 * @param offset Current offset (updated after decode)
 * @return Decoded byte vector
 */
std::optional<ByteVector> decode(const ByteVector& data, size_t& offset);

/**
 * Decode RLP list
 * @param data RLP-encoded data
 * @param offset Current offset (updated after decode)
 * @return Vector of decoded items
 */
std::optional<std::vector<ByteVector>> decodeList(const ByteVector& data, size_t& offset);

/**
 * Decode RLP integer
 * @param data RLP-decoded byte string
 * @return Decoded integer
 */
uint64_t decodeInteger(const ByteVector& data);

/**
 * Convert integer to bytes (big-endian, no leading zeros)
 */
ByteVector integerToBytes(uint64_t value);

/**
 * Convert 256-bit integer to bytes (no leading zeros)
 */
ByteVector integer256ToBytes(const Bytes32& value);

} // namespace rlp

// =============================================================================
// Access List Entry
// =============================================================================

/**
 * Access list entry for EIP-2930/EIP-1559 transactions
 */
struct AccessListEntry {
  /// Account address (20 bytes)
  std::array<uint8_t, 20> address;

  /// Storage keys (32 bytes each)
  std::vector<Bytes32> storageKeys;

  AccessListEntry() : address{}, storageKeys() {}
  AccessListEntry(const std::array<uint8_t, 20>& addr)
    : address(addr), storageKeys() {}

  /// RLP encode this entry
  ByteVector encode() const;
};

// =============================================================================
// Ethereum Transaction Class
// =============================================================================

/**
 * Ethereum transaction
 *
 * Supports legacy, EIP-2930, and EIP-1559 transaction types.
 * Provides methods for building, signing, and serializing transactions.
 */
class EthereumTransaction : public Transaction {
public:
  /**
   * Create an empty legacy transaction
   */
  EthereumTransaction();

  /**
   * Create a legacy transaction
   * @param chainId Chain ID for EIP-155 replay protection
   */
  explicit EthereumTransaction(uint64_t chainId);

  /**
   * Create an EIP-1559 transaction
   * @param chainId Chain ID
   * @param maxPriorityFeePerGas Max priority fee (tip) in wei
   * @param maxFeePerGas Max total fee per gas in wei
   */
  static EthereumTransaction createEIP1559(
    uint64_t chainId,
    uint64_t maxPriorityFeePerGas,
    uint64_t maxFeePerGas
  );

  /**
   * Create an EIP-2930 transaction
   * @param chainId Chain ID
   */
  static EthereumTransaction createEIP2930(uint64_t chainId);

  /**
   * Parse transaction from RLP-encoded bytes
   * @param data RLP-encoded transaction
   * @return Parsed transaction or error
   */
  static Result<EthereumTransaction> parse(const ByteVector& data);

  /**
   * Parse transaction from hex string
   * @param hex Hex-encoded RLP transaction
   * @return Parsed transaction or error
   */
  static Result<EthereumTransaction> parseHex(const std::string& hex);

  ~EthereumTransaction() override = default;

  // ----- Transaction Fields -----

  /**
   * Get transaction type
   */
  EthTxType type() const { return type_; }

  /**
   * Get chain ID
   */
  uint64_t chainId() const { return chainId_; }

  /**
   * Set chain ID
   */
  void setChainId(uint64_t chainId) { chainId_ = chainId; }

  /**
   * Get nonce
   */
  uint64_t nonce() const { return nonce_; }

  /**
   * Set nonce
   */
  void setNonce(uint64_t nonce) { nonce_ = nonce; }

  /**
   * Get gas price (legacy transactions)
   */
  uint64_t gasPrice() const { return gasPrice_; }

  /**
   * Set gas price (legacy transactions)
   */
  void setGasPrice(uint64_t gasPrice) { gasPrice_ = gasPrice; }

  /**
   * Get max priority fee per gas (EIP-1559)
   */
  uint64_t maxPriorityFeePerGas() const { return maxPriorityFeePerGas_; }

  /**
   * Set max priority fee per gas (EIP-1559)
   */
  void setMaxPriorityFeePerGas(uint64_t fee) { maxPriorityFeePerGas_ = fee; }

  /**
   * Get max fee per gas (EIP-1559)
   */
  uint64_t maxFeePerGas() const { return maxFeePerGas_; }

  /**
   * Set max fee per gas (EIP-1559)
   */
  void setMaxFeePerGas(uint64_t fee) { maxFeePerGas_ = fee; }

  /**
   * Get gas limit
   */
  uint64_t gasLimit() const { return gasLimit_; }

  /**
   * Set gas limit
   */
  void setGasLimit(uint64_t gasLimit) { gasLimit_ = gasLimit; }

  /**
   * Get recipient address
   */
  const std::array<uint8_t, 20>& to() const { return to_; }

  /**
   * Set recipient address
   */
  void setTo(const std::array<uint8_t, 20>& to);

  /**
   * Set recipient address from hex string
   */
  Error setToFromHex(const std::string& addressHex);

  /**
   * Check if this is a contract creation transaction
   */
  bool isContractCreation() const { return isContractCreation_; }

  /**
   * Set as contract creation (no 'to' address)
   */
  void setContractCreation(bool creation) { isContractCreation_ = creation; }

  /**
   * True when the transaction has a recipient set with setTo/setToFromHex (or
   * parsed), or is an explicit contract creation. A transaction with neither
   * does not serialize or sign: it would otherwise send to 0x00..00.
   */
  bool hasRecipient() const { return isContractCreation_ || hasTo_; }

  /**
   * Get value in wei
   */
  const Bytes32& value() const { return value_; }

  /**
   * Set value in wei (as 256-bit integer)
   */
  void setValue(const Bytes32& value) { value_ = value; }

  /**
   * Set value in wei (as 64-bit integer)
   */
  void setValue(uint64_t value);

  /**
   * Get input data
   */
  const ByteVector& data() const { return data_; }

  /**
   * Set input data
   */
  void setData(const ByteVector& data) { data_ = data; }
  void setData(ByteVector&& data) { data_ = std::move(data); }

  // ----- Access List (EIP-2930/EIP-1559) -----

  /**
   * Get access list
   */
  const std::vector<AccessListEntry>& accessList() const { return accessList_; }

  /**
   * Add access list entry
   */
  void addAccessListEntry(const AccessListEntry& entry);
  void addAccessListEntry(AccessListEntry&& entry);

  /**
   * Clear access list
   */
  void clearAccessList() { accessList_.clear(); }

  // ----- Signature -----

  /**
   * Get signature recovery ID (v)
   */
  uint64_t signatureV() const { return signatureV_; }

  /**
   * Get signature R value
   */
  const Bytes32& signatureR() const { return signatureR_; }

  /**
   * Get signature S value
   */
  const Bytes32& signatureS() const { return signatureS_; }

  /**
   * Check if transaction is signed
   */
  bool hasSignature() const;

  /**
   * Get the sender address from signature
   * @return Sender address or error
   */
  Result<std::array<uint8_t, 20>> getSender() const;

  // ----- Transaction Interface Implementation -----

  TxStatus status() const override { return status_; }

  Result<Bytes32> hash() const override;
  Result<std::string> txid() const override;

  size_t size() const override;

  Result<ByteVector> serialize() const override;

  /**
   * Serialize for signing (before signature applied)
   * @return RLP-encoded transaction for signing
   */
  Result<ByteVector> serializeForSigning() const;

  Error sign(const Bytes32& privateKey, int inputIndex = -1) override;

  bool verify() const override;

  Error validate() const override;

  std::unique_ptr<Transaction> clone() const override;

  // ----- Fee Calculation -----

  /**
   * Calculate maximum possible fee
   * For legacy: gasLimit * gasPrice
   * For EIP-1559: gasLimit * maxFeePerGas
   */
  uint64_t maxFee() const;

  /**
   * Estimate actual fee given base fee
   * For EIP-1559: gasLimit * min(baseFee + maxPriorityFeePerGas, maxFeePerGas)
   */
  uint64_t estimateFee(uint64_t baseFee) const;

private:
  EthTxType type_;
  uint64_t chainId_;
  uint64_t nonce_;
  uint64_t gasPrice_;              // Legacy only
  uint64_t maxPriorityFeePerGas_;  // EIP-1559 only
  uint64_t maxFeePerGas_;          // EIP-1559 only
  uint64_t gasLimit_;
  std::array<uint8_t, 20> to_;
  bool hasTo_;
  bool isContractCreation_;
  Bytes32 value_;
  ByteVector data_;
  std::vector<AccessListEntry> accessList_;

  // Signature components
  uint64_t signatureV_;
  Bytes32 signatureR_;
  Bytes32 signatureS_;

  TxStatus status_;

  // Read an encoded 'to' field into tx (false when it is malformed)
  static bool readRecipient(const ByteVector& field, EthereumTransaction& tx);

  // Encode transaction fields to RLP items
  std::vector<ByteVector> encodeFields() const;
  std::vector<ByteVector> encodeFieldsForSigning() const;

  // Encode access list
  ByteVector encodeAccessList() const;
};

// =============================================================================
// Utility Functions
// =============================================================================

/**
 * Convert wei to gwei
 */
inline uint64_t weiToGwei(uint64_t wei) {
  return wei / WEI_PER_GWEI;
}

/**
 * Convert gwei to wei
 */
inline uint64_t gweiToWei(uint64_t gwei) {
  return gwei * WEI_PER_GWEI;
}

/**
 * Format wei as ETH string
 * @param wei Amount in wei
 * @param decimals Decimal places to show
 * @return Formatted string (e.g., "1.5")
 */
std::string formatEther(uint64_t wei, int decimals = 4);

/**
 * Parse ETH string to wei
 * @param eth ETH amount string (e.g., "1.5")
 * @return Amount in wei, or error
 */
Result<uint64_t> parseEther(const std::string& eth);

/**
 * Derive Ethereum address from public key
 * @param publicKey 65-byte uncompressed public key (with 0x04 prefix)
 * @return 20-byte Ethereum address
 */
std::array<uint8_t, 20> publicKeyToAddress(const Bytes65& publicKey);

/**
 * Derive Ethereum address from compressed public key
 * @param publicKey 33-byte compressed public key
 * @return 20-byte Ethereum address
 */
std::array<uint8_t, 20> publicKeyToAddress(const Bytes33& publicKey);

/**
 * Format address with checksum (EIP-55)
 * @param address 20-byte address
 * @return Checksummed hex address string (with 0x prefix)
 */
std::string addressToChecksumHex(const std::array<uint8_t, 20>& address);

/**
 * Validate and parse address from hex string
 * @param addressHex Hex address string (with or without 0x prefix)
 * @return 20-byte address or error
 */
Result<std::array<uint8_t, 20>> parseAddress(const std::string& addressHex);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

/// Opaque handle for EthereumTransaction
typedef struct eth_tx_t* eth_tx_handle;

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
eth_tx_handle hd_eth_tx_create(uint64_t chain_id);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
eth_tx_handle hd_eth_tx_create_eip1559(
  uint64_t chain_id,
  uint64_t max_priority_fee,
  uint64_t max_fee
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_eth_tx_set_nonce(eth_tx_handle tx, uint64_t nonce);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_eth_tx_set_gas_price(eth_tx_handle tx, uint64_t gas_price);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_eth_tx_set_gas_limit(eth_tx_handle tx, uint64_t gas_limit);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_tx_set_to(eth_tx_handle tx, const uint8_t* address);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_tx_set_to_hex(eth_tx_handle tx, const char* address_hex);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_eth_tx_set_value(eth_tx_handle tx, uint64_t value_wei);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_eth_tx_set_value_256(eth_tx_handle tx, const uint8_t* value);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_eth_tx_set_data(eth_tx_handle tx, const uint8_t* data, size_t data_len);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_tx_sign(eth_tx_handle tx, const uint8_t* privkey);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_tx_serialize(
  eth_tx_handle tx,
  uint8_t* out,
  size_t out_size,
  size_t* actual_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_tx_get_hash(eth_tx_handle tx, uint8_t* hash_out);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_tx_get_hash_hex(eth_tx_handle tx, char* out, size_t out_size);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_tx_get_sender(eth_tx_handle tx, uint8_t* address_out);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
size_t hd_eth_tx_get_size(eth_tx_handle tx);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint64_t hd_eth_tx_get_max_fee(eth_tx_handle tx);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_tx_validate(eth_tx_handle tx);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_eth_tx_destroy(eth_tx_handle tx);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
eth_tx_handle hd_eth_tx_parse(const uint8_t* data, size_t data_len);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
eth_tx_handle hd_eth_tx_parse_hex(const char* hex);

// Address utilities
HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_pubkey_to_address(
  const uint8_t* pubkey,
  size_t pubkey_len,
  uint8_t* address_out
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_address_to_checksum(
  const uint8_t* address,
  char* out,
  size_t out_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_parse_address(
  const char* address_hex,
  uint8_t* address_out
);

} // namespace tx
} // namespace hd_wallet

#endif // HD_WALLET_TX_ETHEREUM_TX_H
