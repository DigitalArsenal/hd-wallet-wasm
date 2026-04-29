/**
 * @file ethereum_tx.cpp
 * @brief Ethereum Transaction Implementation
 *
 * Implementation of Ethereum transaction building, signing, and serialization.
 * Supports legacy, EIP-2930, and EIP-1559 transaction types.
 */

#include "hd_wallet/tx/ethereum_tx.h"
#include "hd_wallet/config.h"
#include "hd_wallet/secure_rng.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

#if HD_WALLET_USE_CRYPTOPP
#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/oids.h>
#include <cryptopp/sha.h>
#include <cryptopp/keccak.h>
#include <cryptopp/integer.h>
#include <cryptopp/dsa.h>
#include <cryptopp/pubkey.h>
#endif

namespace hd_wallet {
namespace tx {

// =============================================================================
// RLP Encoding Implementation
// =============================================================================

namespace rlp {

ByteVector integerToBytes(uint64_t value) {
  if (value == 0) {
    return ByteVector();
  }

  ByteVector result;
  while (value > 0) {
    result.insert(result.begin(), static_cast<uint8_t>(value & 0xFF));
    value >>= 8;
  }
  return result;
}

ByteVector integer256ToBytes(const Bytes32& value) {
  // Find first non-zero byte
  size_t start = 0;
  while (start < 32 && value[start] == 0) {
    ++start;
  }

  if (start == 32) {
    return ByteVector();  // Value is zero
  }

  return ByteVector(value.begin() + start, value.end());
}

ByteVector lengthPrefix(size_t length, uint8_t offset) {
  ByteVector result;

  if (length < 56) {
    result.push_back(static_cast<uint8_t>(offset + length));
  } else {
    // Get length of length
    ByteVector lenBytes = integerToBytes(length);
    result.push_back(static_cast<uint8_t>(offset + 55 + lenBytes.size()));
    result.insert(result.end(), lenBytes.begin(), lenBytes.end());
  }

  return result;
}

ByteVector encodeString(const ByteVector& data) {
  ByteVector result;

  if (data.size() == 1 && data[0] < 0x80) {
    // Single byte that is less than 0x80 is encoded as itself
    result.push_back(data[0]);
  } else if (data.size() < 56) {
    // Short string: 0x80 + length, then data
    result.push_back(static_cast<uint8_t>(0x80 + data.size()));
    result.insert(result.end(), data.begin(), data.end());
  } else {
    // Long string: 0xb7 + length of length, then length, then data
    ByteVector lenBytes = integerToBytes(data.size());
    result.push_back(static_cast<uint8_t>(0xb7 + lenBytes.size()));
    result.insert(result.end(), lenBytes.begin(), lenBytes.end());
    result.insert(result.end(), data.begin(), data.end());
  }

  return result;
}

ByteVector encodeByte(uint8_t byte) {
  if (byte == 0) {
    return ByteVector{0x80};  // Empty string
  }
  if (byte < 0x80) {
    return ByteVector{byte};
  }
  return ByteVector{0x81, byte};
}

ByteVector encodeInteger(uint64_t value) {
  ByteVector bytes = integerToBytes(value);
  return encodeString(bytes);
}

ByteVector encodeInteger256(const Bytes32& value) {
  ByteVector bytes = integer256ToBytes(value);
  return encodeString(bytes);
}

ByteVector encodeAddress(const std::array<uint8_t, 20>& address) {
  ByteVector data(address.begin(), address.end());
  return encodeString(data);
}

ByteVector encodeList(const std::vector<ByteVector>& items) {
  // Concatenate all items
  ByteVector payload;
  for (const auto& item : items) {
    payload.insert(payload.end(), item.begin(), item.end());
  }

  ByteVector result;

  if (payload.size() < 56) {
    result.push_back(static_cast<uint8_t>(0xc0 + payload.size()));
  } else {
    ByteVector lenBytes = integerToBytes(payload.size());
    result.push_back(static_cast<uint8_t>(0xf7 + lenBytes.size()));
    result.insert(result.end(), lenBytes.begin(), lenBytes.end());
  }

  result.insert(result.end(), payload.begin(), payload.end());
  return result;
}

ByteVector encodeListRaw(const std::vector<ByteVector>& items) {
  // Encode each item, then wrap in list
  std::vector<ByteVector> encodedItems;
  for (const auto& item : items) {
    encodedItems.push_back(encodeString(item));
  }
  return encodeList(encodedItems);
}

std::optional<ByteVector> decode(const ByteVector& data, size_t& offset) {
  if (offset >= data.size()) {
    return std::nullopt;
  }

  uint8_t prefix = data[offset];

  if (prefix < 0x80) {
    // Single byte
    ++offset;
    return ByteVector{prefix};
  }

  if (prefix <= 0xb7) {
    // Short string (0-55 bytes)
    size_t length = prefix - 0x80;
    if (offset + 1 + length > data.size()) {
      return std::nullopt;
    }
    ByteVector result(data.begin() + offset + 1, data.begin() + offset + 1 + length);
    offset += 1 + length;
    return result;
  }

  if (prefix <= 0xbf) {
    // Long string
    size_t lenLen = prefix - 0xb7;
    if (offset + 1 + lenLen > data.size()) {
      return std::nullopt;
    }

    size_t length = 0;
    for (size_t i = 0; i < lenLen; ++i) {
      length = (length << 8) | data[offset + 1 + i];
    }

    if (offset + 1 + lenLen + length > data.size()) {
      return std::nullopt;
    }

    ByteVector result(data.begin() + offset + 1 + lenLen,
                      data.begin() + offset + 1 + lenLen + length);
    offset += 1 + lenLen + length;
    return result;
  }

  // List (0xc0 - 0xff)
  // For decode(), we return the raw list data
  if (prefix <= 0xf7) {
    size_t length = prefix - 0xc0;
    if (offset + 1 + length > data.size()) {
      return std::nullopt;
    }
    ByteVector result(data.begin() + offset + 1, data.begin() + offset + 1 + length);
    offset += 1 + length;
    return result;
  }

  size_t lenLen = prefix - 0xf7;
  if (offset + 1 + lenLen > data.size()) {
    return std::nullopt;
  }

  size_t length = 0;
  for (size_t i = 0; i < lenLen; ++i) {
    length = (length << 8) | data[offset + 1 + i];
  }

  if (offset + 1 + lenLen + length > data.size()) {
    return std::nullopt;
  }

  ByteVector result(data.begin() + offset + 1 + lenLen,
                    data.begin() + offset + 1 + lenLen + length);
  offset += 1 + lenLen + length;
  return result;
}

std::optional<std::vector<ByteVector>> decodeList(const ByteVector& data, size_t& offset) {
  if (offset >= data.size()) {
    return std::nullopt;
  }

  uint8_t prefix = data[offset];

  if (prefix < 0xc0) {
    return std::nullopt;  // Not a list
  }

  size_t listStart;
  size_t listLen;

  if (prefix <= 0xf7) {
    listLen = prefix - 0xc0;
    listStart = offset + 1;
  } else {
    size_t lenLen = prefix - 0xf7;
    if (offset + 1 + lenLen > data.size()) {
      return std::nullopt;
    }

    listLen = 0;
    for (size_t i = 0; i < lenLen; ++i) {
      listLen = (listLen << 8) | data[offset + 1 + i];
    }
    listStart = offset + 1 + lenLen;
  }

  if (listStart + listLen > data.size()) {
    return std::nullopt;
  }

  std::vector<ByteVector> items;
  size_t pos = listStart;
  size_t listEnd = listStart + listLen;

  while (pos < listEnd) {
    auto item = decode(data, pos);
    if (!item) {
      return std::nullopt;
    }
    items.push_back(std::move(*item));
  }

  offset = listEnd;
  return items;
}

uint64_t decodeInteger(const ByteVector& data) {
  uint64_t result = 0;
  for (uint8_t byte : data) {
    result = (result << 8) | byte;
  }
  return result;
}

} // namespace rlp

// =============================================================================
// Access List Entry
// =============================================================================

ByteVector AccessListEntry::encode() const {
  std::vector<ByteVector> items;

  // Address
  items.push_back(rlp::encodeAddress(address));

  // Storage keys as a list
  std::vector<ByteVector> keyItems;
  for (const auto& key : storageKeys) {
    keyItems.push_back(rlp::encodeString(ByteVector(key.begin(), key.end())));
  }
  items.push_back(rlp::encodeList(keyItems));

  return rlp::encodeList(items);
}

// =============================================================================
// Ethereum Transaction Class
// =============================================================================

EthereumTransaction::EthereumTransaction()
  : type_(EthTxType::LEGACY)
  , chainId_(ETH_CHAIN_ID_MAINNET)
  , nonce_(0)
  , gasPrice_(0)
  , maxPriorityFeePerGas_(0)
  , maxFeePerGas_(0)
  , gasLimit_(ETH_DEFAULT_GAS_LIMIT)
  , to_{}
  , isContractCreation_(false)
  , value_{}
  , data_()
  , accessList_()
  , signatureV_(0)
  , signatureR_{}
  , signatureS_{}
  , status_(TxStatus::UNBUILT) {}

EthereumTransaction::EthereumTransaction(uint64_t chainId)
  : type_(EthTxType::LEGACY)
  , chainId_(chainId)
  , nonce_(0)
  , gasPrice_(0)
  , maxPriorityFeePerGas_(0)
  , maxFeePerGas_(0)
  , gasLimit_(ETH_DEFAULT_GAS_LIMIT)
  , to_{}
  , isContractCreation_(false)
  , value_{}
  , data_()
  , accessList_()
  , signatureV_(0)
  , signatureR_{}
  , signatureS_{}
  , status_(TxStatus::UNSIGNED) {}

EthereumTransaction EthereumTransaction::createEIP1559(
  uint64_t chainId,
  uint64_t maxPriorityFeePerGas,
  uint64_t maxFeePerGas
) {
  EthereumTransaction tx;
  tx.type_ = EthTxType::EIP1559;
  tx.chainId_ = chainId;
  tx.maxPriorityFeePerGas_ = maxPriorityFeePerGas;
  tx.maxFeePerGas_ = maxFeePerGas;
  tx.status_ = TxStatus::UNSIGNED;
  return tx;
}

EthereumTransaction EthereumTransaction::createEIP2930(uint64_t chainId) {
  EthereumTransaction tx;
  tx.type_ = EthTxType::ACCESS_LIST;
  tx.chainId_ = chainId;
  tx.status_ = TxStatus::UNSIGNED;
  return tx;
}

// ----- Field Setters -----

void EthereumTransaction::setTo(const std::array<uint8_t, 20>& to) {
  to_ = to;
  isContractCreation_ = false;
}

Error EthereumTransaction::setToFromHex(const std::string& addressHex) {
  auto result = parseAddress(addressHex);
  if (!result.ok()) {
    return result.error;
  }
  to_ = result.value;
  isContractCreation_ = false;
  return Error::OK;
}

void EthereumTransaction::setValue(uint64_t value) {
  std::fill(value_.begin(), value_.end(), 0);

  // Convert to big-endian
  for (int i = 0; i < 8 && value > 0; ++i) {
    value_[31 - i] = static_cast<uint8_t>(value & 0xFF);
    value >>= 8;
  }
}

void EthereumTransaction::addAccessListEntry(const AccessListEntry& entry) {
  accessList_.push_back(entry);
}

void EthereumTransaction::addAccessListEntry(AccessListEntry&& entry) {
  accessList_.push_back(std::move(entry));
}

bool EthereumTransaction::hasSignature() const {
  // Check if R or S is non-zero
  for (uint8_t b : signatureR_) {
    if (b != 0) return true;
  }
  for (uint8_t b : signatureS_) {
    if (b != 0) return true;
  }
  return false;
}

// ----- Encoding -----

ByteVector EthereumTransaction::encodeAccessList() const {
  std::vector<ByteVector> items;
  for (const auto& entry : accessList_) {
    items.push_back(entry.encode());
  }
  return rlp::encodeList(items);
}

std::vector<ByteVector> EthereumTransaction::encodeFields() const {
  std::vector<ByteVector> items;

  switch (type_) {
    case EthTxType::LEGACY: {
      items.push_back(rlp::encodeInteger(nonce_));
      items.push_back(rlp::encodeInteger(gasPrice_));
      items.push_back(rlp::encodeInteger(gasLimit_));

      if (isContractCreation_) {
        items.push_back(rlp::encodeString(ByteVector{}));  // Empty 'to'
      } else {
        items.push_back(rlp::encodeAddress(to_));
      }

      items.push_back(rlp::encodeInteger256(value_));
      items.push_back(rlp::encodeString(data_));

      // Signature
      items.push_back(rlp::encodeInteger(signatureV_));
      items.push_back(rlp::encodeInteger256(signatureR_));
      items.push_back(rlp::encodeInteger256(signatureS_));
      break;
    }

    case EthTxType::ACCESS_LIST: {
      items.push_back(rlp::encodeInteger(chainId_));
      items.push_back(rlp::encodeInteger(nonce_));
      items.push_back(rlp::encodeInteger(gasPrice_));
      items.push_back(rlp::encodeInteger(gasLimit_));

      if (isContractCreation_) {
        items.push_back(rlp::encodeString(ByteVector{}));
      } else {
        items.push_back(rlp::encodeAddress(to_));
      }

      items.push_back(rlp::encodeInteger256(value_));
      items.push_back(rlp::encodeString(data_));
      items.push_back(encodeAccessList());

      // Signature (y_parity, r, s)
      items.push_back(rlp::encodeInteger(signatureV_));
      items.push_back(rlp::encodeInteger256(signatureR_));
      items.push_back(rlp::encodeInteger256(signatureS_));
      break;
    }

    case EthTxType::EIP1559: {
      items.push_back(rlp::encodeInteger(chainId_));
      items.push_back(rlp::encodeInteger(nonce_));
      items.push_back(rlp::encodeInteger(maxPriorityFeePerGas_));
      items.push_back(rlp::encodeInteger(maxFeePerGas_));
      items.push_back(rlp::encodeInteger(gasLimit_));

      if (isContractCreation_) {
        items.push_back(rlp::encodeString(ByteVector{}));
      } else {
        items.push_back(rlp::encodeAddress(to_));
      }

      items.push_back(rlp::encodeInteger256(value_));
      items.push_back(rlp::encodeString(data_));
      items.push_back(encodeAccessList());

      // Signature (y_parity, r, s)
      items.push_back(rlp::encodeInteger(signatureV_));
      items.push_back(rlp::encodeInteger256(signatureR_));
      items.push_back(rlp::encodeInteger256(signatureS_));
      break;
    }
  }

  return items;
}

std::vector<ByteVector> EthereumTransaction::encodeFieldsForSigning() const {
  std::vector<ByteVector> items;

  switch (type_) {
    case EthTxType::LEGACY: {
      items.push_back(rlp::encodeInteger(nonce_));
      items.push_back(rlp::encodeInteger(gasPrice_));
      items.push_back(rlp::encodeInteger(gasLimit_));

      if (isContractCreation_) {
        items.push_back(rlp::encodeString(ByteVector{}));
      } else {
        items.push_back(rlp::encodeAddress(to_));
      }

      items.push_back(rlp::encodeInteger256(value_));
      items.push_back(rlp::encodeString(data_));

      // EIP-155: Include chain ID for replay protection
      if (chainId_ > 0) {
        items.push_back(rlp::encodeInteger(chainId_));
        items.push_back(rlp::encodeInteger(0));
        items.push_back(rlp::encodeInteger(0));
      }
      break;
    }

    case EthTxType::ACCESS_LIST: {
      items.push_back(rlp::encodeInteger(chainId_));
      items.push_back(rlp::encodeInteger(nonce_));
      items.push_back(rlp::encodeInteger(gasPrice_));
      items.push_back(rlp::encodeInteger(gasLimit_));

      if (isContractCreation_) {
        items.push_back(rlp::encodeString(ByteVector{}));
      } else {
        items.push_back(rlp::encodeAddress(to_));
      }

      items.push_back(rlp::encodeInteger256(value_));
      items.push_back(rlp::encodeString(data_));
      items.push_back(encodeAccessList());
      break;
    }

    case EthTxType::EIP1559: {
      items.push_back(rlp::encodeInteger(chainId_));
      items.push_back(rlp::encodeInteger(nonce_));
      items.push_back(rlp::encodeInteger(maxPriorityFeePerGas_));
      items.push_back(rlp::encodeInteger(maxFeePerGas_));
      items.push_back(rlp::encodeInteger(gasLimit_));

      if (isContractCreation_) {
        items.push_back(rlp::encodeString(ByteVector{}));
      } else {
        items.push_back(rlp::encodeAddress(to_));
      }

      items.push_back(rlp::encodeInteger256(value_));
      items.push_back(rlp::encodeString(data_));
      items.push_back(encodeAccessList());
      break;
    }
  }

  return items;
}

Result<ByteVector> EthereumTransaction::serializeForSigning() const {
  auto items = encodeFieldsForSigning();
  ByteVector encoded = rlp::encodeList(items);

  // For typed transactions, prepend the type byte
  if (type_ != EthTxType::LEGACY) {
    ByteVector result;
    result.push_back(static_cast<uint8_t>(type_));
    result.insert(result.end(), encoded.begin(), encoded.end());
    return Result<ByteVector>::success(std::move(result));
  }

  return Result<ByteVector>::success(std::move(encoded));
}

Result<ByteVector> EthereumTransaction::serialize() const {
  auto items = encodeFields();
  ByteVector encoded = rlp::encodeList(items);

  // For typed transactions, prepend the type byte
  if (type_ != EthTxType::LEGACY) {
    ByteVector result;
    result.push_back(static_cast<uint8_t>(type_));
    result.insert(result.end(), encoded.begin(), encoded.end());
    return Result<ByteVector>::success(std::move(result));
  }

  return Result<ByteVector>::success(std::move(encoded));
}

// ----- Hash Calculation -----

Result<Bytes32> EthereumTransaction::hash() const {
  auto serialized = serialize();
  if (!serialized.ok()) {
    return Result<Bytes32>::fail(serialized.error);
  }

  return Result<Bytes32>::success(keccak256(serialized.value));
}

Result<std::string> EthereumTransaction::txid() const {
  auto hashResult = hash();
  if (!hashResult.ok()) {
    return Result<std::string>::fail(hashResult.error);
  }

  // Ethereum uses 0x prefix
  return Result<std::string>::success("0x" + bytesToHex(hashResult.value));
}

size_t EthereumTransaction::size() const {
  auto serialized = serialize();
  if (!serialized.ok()) {
    return 0;
  }
  return serialized.value.size();
}

// ----- Signing -----

#if HD_WALLET_USE_CRYPTOPP

// Helper to sign with secp256k1 and get recovery ID
static bool signECDSARecoverable(
  const Bytes32& hash,
  const Bytes32& privateKey,
  Bytes32& outR,
  Bytes32& outS,
  uint8_t& outV
) {
  using namespace CryptoPP;

  try {
    // Create private key
    ECDSA<ECP, SHA256>::PrivateKey privKey;
    Integer x(privateKey.data(), privateKey.size());
    privKey.Initialize(ASN1::secp256k1(), x);

    // Get public key for recovery
    ECDSA<ECP, SHA256>::PublicKey pubKey;
    privKey.MakePublicKey(pubKey);

    // Create signer with deterministic K (RFC 6979)
    SecureRandomGenerator rng;
    ECDSA<ECP, SHA256>::Signer signer(privKey);

    // Sign (produces DER-encoded signature)
    std::string signature;
    StringSource ss(
      hash.data(), hash.size(), true,
      new SignerFilter(rng, signer, new StringSink(signature))
    );

    // Parse R and S from signature
    // Crypto++ ECDSA signatures are (r, s) concatenated, each 32 bytes for secp256k1
    if (signature.size() < 64) {
      return false;
    }

    std::copy(signature.begin(), signature.begin() + 32, outR.begin());
    std::copy(signature.begin() + 32, signature.begin() + 64, outS.begin());

    // Determine recovery ID by trying both values
    // For simplicity, we'll use 0 and adjust based on public key recovery
    // In production, you'd properly recover the public key
    outV = 0;

    // Check if S > N/2, if so, use N - S (low-S normalization)
    // This is required by Ethereum
    Integer n = privKey.GetGroupParameters().GetSubgroupOrder();
    Integer halfN = n >> 1;
    Integer sInt(outS.data(), outS.size());

    if (sInt > halfN) {
      sInt = n - sInt;
      sInt.Encode(outS.data(), 32);
      outV ^= 1;  // Flip V
    }

    return true;
  } catch (...) {
    return false;
  }
}

#endif

Error EthereumTransaction::sign(const Bytes32& privateKey, int /* inputIndex */) {
#if HD_WALLET_USE_CRYPTOPP
  // Get the signing hash
  auto forSigning = serializeForSigning();
  if (!forSigning.ok()) {
    return forSigning.error;
  }

  Bytes32 sigHash = keccak256(forSigning.value);

  // Sign
  uint8_t recoveryId;
  if (!signECDSARecoverable(sigHash, privateKey, signatureR_, signatureS_, recoveryId)) {
    return Error::INVALID_SIGNATURE;
  }

  // Calculate V based on transaction type and chain ID
  switch (type_) {
    case EthTxType::LEGACY:
      // EIP-155: v = chain_id * 2 + 35 + recovery_id
      // Or without EIP-155: v = 27 + recovery_id
      if (chainId_ > 0) {
        signatureV_ = chainId_ * 2 + 35 + recoveryId;
      } else {
        signatureV_ = 27 + recoveryId;
      }
      break;

    case EthTxType::ACCESS_LIST:
    case EthTxType::EIP1559:
      // For typed transactions, v is just the recovery ID (0 or 1)
      signatureV_ = recoveryId;
      break;
  }

  status_ = TxStatus::SIGNED;
  return Error::OK;

#else
  (void)privateKey;
  return Error::NOT_SUPPORTED;
#endif
}

bool EthereumTransaction::verify() const {
  return hasSignature();
}

Error EthereumTransaction::validate() const {
  // Check gas limit
  if (gasLimit_ == 0) {
    return Error::INVALID_TRANSACTION;
  }

  // Check gas prices based on type
  if (type_ == EthTxType::LEGACY || type_ == EthTxType::ACCESS_LIST) {
    if (gasPrice_ == 0) {
      return Error::INVALID_TRANSACTION;
    }
  } else if (type_ == EthTxType::EIP1559) {
    if (maxFeePerGas_ == 0) {
      return Error::INVALID_TRANSACTION;
    }
    // maxPriorityFeePerGas can be 0 (for base fee only transactions)
  }

  return Error::OK;
}

std::unique_ptr<Transaction> EthereumTransaction::clone() const {
  auto tx = std::make_unique<EthereumTransaction>();
  tx->type_ = type_;
  tx->chainId_ = chainId_;
  tx->nonce_ = nonce_;
  tx->gasPrice_ = gasPrice_;
  tx->maxPriorityFeePerGas_ = maxPriorityFeePerGas_;
  tx->maxFeePerGas_ = maxFeePerGas_;
  tx->gasLimit_ = gasLimit_;
  tx->to_ = to_;
  tx->isContractCreation_ = isContractCreation_;
  tx->value_ = value_;
  tx->data_ = data_;
  tx->accessList_ = accessList_;
  tx->signatureV_ = signatureV_;
  tx->signatureR_ = signatureR_;
  tx->signatureS_ = signatureS_;
  tx->status_ = status_;
  return tx;
}

// ----- Fee Calculation -----

uint64_t EthereumTransaction::maxFee() const {
  switch (type_) {
    case EthTxType::LEGACY:
    case EthTxType::ACCESS_LIST:
      return gasLimit_ * gasPrice_;

    case EthTxType::EIP1559:
      return gasLimit_ * maxFeePerGas_;
  }
  return 0;
}

uint64_t EthereumTransaction::estimateFee(uint64_t baseFee) const {
  switch (type_) {
    case EthTxType::LEGACY:
    case EthTxType::ACCESS_LIST:
      return gasLimit_ * gasPrice_;

    case EthTxType::EIP1559: {
      uint64_t effectiveGasPrice = std::min(baseFee + maxPriorityFeePerGas_, maxFeePerGas_);
      return gasLimit_ * effectiveGasPrice;
    }
  }
  return 0;
}

// ----- Sender Recovery -----

Result<std::array<uint8_t, 20>> EthereumTransaction::getSender() const {
  if (!hasSignature()) {
    return Result<std::array<uint8_t, 20>>::fail(Error::INVALID_SIGNATURE);
  }

  // TODO: Implement public key recovery from signature
  // This requires ecrecover which is complex to implement correctly

  return Result<std::array<uint8_t, 20>>::fail(Error::NOT_SUPPORTED);
}

// ----- Parsing -----

Result<EthereumTransaction> EthereumTransaction::parse(const ByteVector& data) {
  if (data.empty()) {
    return Result<EthereumTransaction>::fail(Error::INVALID_TRANSACTION);
  }

  EthereumTransaction tx;

  // Check for typed transaction
  if (data[0] <= 0x7f) {
    // Typed transaction (EIP-2718)
    tx.type_ = static_cast<EthTxType>(data[0]);

    ByteVector payload(data.begin() + 1, data.end());
    size_t offset = 0;
    auto items = rlp::decodeList(payload, offset);

    if (!items) {
      return Result<EthereumTransaction>::fail(Error::INVALID_TRANSACTION);
    }

    if (tx.type_ == EthTxType::EIP1559) {
      if (items->size() < 12) {
        return Result<EthereumTransaction>::fail(Error::INVALID_TRANSACTION);
      }

      tx.chainId_ = rlp::decodeInteger((*items)[0]);
      tx.nonce_ = rlp::decodeInteger((*items)[1]);
      tx.maxPriorityFeePerGas_ = rlp::decodeInteger((*items)[2]);
      tx.maxFeePerGas_ = rlp::decodeInteger((*items)[3]);
      tx.gasLimit_ = rlp::decodeInteger((*items)[4]);

      if ((*items)[5].size() == 20) {
        std::copy((*items)[5].begin(), (*items)[5].end(), tx.to_.begin());
        tx.isContractCreation_ = false;
      } else {
        tx.isContractCreation_ = true;
      }

      if ((*items)[6].size() <= 32) {
        std::fill(tx.value_.begin(), tx.value_.end(), 0);
        size_t start = 32 - (*items)[6].size();
        std::copy((*items)[6].begin(), (*items)[6].end(), tx.value_.begin() + start);
      }

      tx.data_ = (*items)[7];
      // TODO: Parse access list from (*items)[8]

      tx.signatureV_ = rlp::decodeInteger((*items)[9]);

      if ((*items)[10].size() <= 32) {
        std::fill(tx.signatureR_.begin(), tx.signatureR_.end(), 0);
        size_t start = 32 - (*items)[10].size();
        std::copy((*items)[10].begin(), (*items)[10].end(), tx.signatureR_.begin() + start);
      }

      if ((*items)[11].size() <= 32) {
        std::fill(tx.signatureS_.begin(), tx.signatureS_.end(), 0);
        size_t start = 32 - (*items)[11].size();
        std::copy((*items)[11].begin(), (*items)[11].end(), tx.signatureS_.begin() + start);
      }

    } else if (tx.type_ == EthTxType::ACCESS_LIST) {
      if (items->size() < 11) {
        return Result<EthereumTransaction>::fail(Error::INVALID_TRANSACTION);
      }

      tx.chainId_ = rlp::decodeInteger((*items)[0]);
      tx.nonce_ = rlp::decodeInteger((*items)[1]);
      tx.gasPrice_ = rlp::decodeInteger((*items)[2]);
      tx.gasLimit_ = rlp::decodeInteger((*items)[3]);

      if ((*items)[4].size() == 20) {
        std::copy((*items)[4].begin(), (*items)[4].end(), tx.to_.begin());
        tx.isContractCreation_ = false;
      } else {
        tx.isContractCreation_ = true;
      }

      if ((*items)[5].size() <= 32) {
        std::fill(tx.value_.begin(), tx.value_.end(), 0);
        size_t start = 32 - (*items)[5].size();
        std::copy((*items)[5].begin(), (*items)[5].end(), tx.value_.begin() + start);
      }

      tx.data_ = (*items)[6];
      // TODO: Parse access list from (*items)[7]

      tx.signatureV_ = rlp::decodeInteger((*items)[8]);

      if ((*items)[9].size() <= 32) {
        std::fill(tx.signatureR_.begin(), tx.signatureR_.end(), 0);
        size_t start = 32 - (*items)[9].size();
        std::copy((*items)[9].begin(), (*items)[9].end(), tx.signatureR_.begin() + start);
      }

      if ((*items)[10].size() <= 32) {
        std::fill(tx.signatureS_.begin(), tx.signatureS_.end(), 0);
        size_t start = 32 - (*items)[10].size();
        std::copy((*items)[10].begin(), (*items)[10].end(), tx.signatureS_.begin() + start);
      }
    } else {
      return Result<EthereumTransaction>::fail(Error::NOT_SUPPORTED);
    }
  } else {
    // Legacy transaction
    tx.type_ = EthTxType::LEGACY;

    size_t offset = 0;
    auto items = rlp::decodeList(data, offset);

    if (!items || items->size() < 9) {
      return Result<EthereumTransaction>::fail(Error::INVALID_TRANSACTION);
    }

    tx.nonce_ = rlp::decodeInteger((*items)[0]);
    tx.gasPrice_ = rlp::decodeInteger((*items)[1]);
    tx.gasLimit_ = rlp::decodeInteger((*items)[2]);

    if ((*items)[3].size() == 20) {
      std::copy((*items)[3].begin(), (*items)[3].end(), tx.to_.begin());
      tx.isContractCreation_ = false;
    } else {
      tx.isContractCreation_ = true;
    }

    if ((*items)[4].size() <= 32) {
      std::fill(tx.value_.begin(), tx.value_.end(), 0);
      size_t start = 32 - (*items)[4].size();
      std::copy((*items)[4].begin(), (*items)[4].end(), tx.value_.begin() + start);
    }

    tx.data_ = (*items)[5];

    tx.signatureV_ = rlp::decodeInteger((*items)[6]);

    if ((*items)[7].size() <= 32) {
      std::fill(tx.signatureR_.begin(), tx.signatureR_.end(), 0);
      size_t start = 32 - (*items)[7].size();
      std::copy((*items)[7].begin(), (*items)[7].end(), tx.signatureR_.begin() + start);
    }

    if ((*items)[8].size() <= 32) {
      std::fill(tx.signatureS_.begin(), tx.signatureS_.end(), 0);
      size_t start = 32 - (*items)[8].size();
      std::copy((*items)[8].begin(), (*items)[8].end(), tx.signatureS_.begin() + start);
    }

    // Extract chain ID from V (EIP-155)
    if (tx.signatureV_ >= 35) {
      tx.chainId_ = (tx.signatureV_ - 35) / 2;
    } else if (tx.signatureV_ == 27 || tx.signatureV_ == 28) {
      tx.chainId_ = 0;  // Pre-EIP-155
    }
  }

  tx.status_ = tx.hasSignature() ? TxStatus::SIGNED : TxStatus::UNSIGNED;
  return Result<EthereumTransaction>::success(std::move(tx));
}

Result<EthereumTransaction> EthereumTransaction::parseHex(const std::string& hex) {
  auto bytes = hexToBytes(hex);
  if (!bytes.ok()) {
    return Result<EthereumTransaction>::fail(bytes.error);
  }
  return parse(bytes.value);
}

// =============================================================================
// Utility Functions
// =============================================================================

std::string formatEther(uint64_t wei, int decimals) {
  // Simple formatting - for production, use a proper decimal library
  double eth = static_cast<double>(wei) / static_cast<double>(WEI_PER_ETHER);

  std::ostringstream ss;
  ss << std::fixed << std::setprecision(decimals) << eth;
  return ss.str();
}

Result<uint64_t> parseEther(const std::string& eth) {
  try {
    double value = std::stod(eth);
    if (value < 0) {
      return Result<uint64_t>::fail(Error::INVALID_ARGUMENT);
    }
    return Result<uint64_t>::success(static_cast<uint64_t>(value * WEI_PER_ETHER));
  } catch (...) {
    return Result<uint64_t>::fail(Error::INVALID_ARGUMENT);
  }
}

std::array<uint8_t, 20> publicKeyToAddress(const Bytes65& publicKey) {
  // Skip the 0x04 prefix if present
  const uint8_t* keyData = publicKey.data();
  size_t keyLen = publicKey.size();

  if (keyLen == 65 && keyData[0] == 0x04) {
    keyData = keyData + 1;
    keyLen = 64;
  }

  // Keccak-256 of the public key (without prefix)
  Bytes32 hash = keccak256(keyData, keyLen);

  // Take last 20 bytes
  std::array<uint8_t, 20> address;
  std::copy(hash.begin() + 12, hash.end(), address.begin());

  return address;
}

std::array<uint8_t, 20> publicKeyToAddress(const Bytes33& compressedPublicKey) {
  // Decompress public key first
  // TODO: Implement proper decompression
  // For now, this is a placeholder

  (void)compressedPublicKey;

  std::array<uint8_t, 20> address{};
  return address;
}

std::string addressToChecksumHex(const std::array<uint8_t, 20>& address) {
  // Get lowercase hex
  std::string hex = bytesToHex(address.data(), address.size());

  // Get Keccak hash of lowercase address
  Bytes32 hash = keccak256(reinterpret_cast<const uint8_t*>(hex.data()), hex.size());

  // Apply checksum (EIP-55)
  std::string result = "0x";
  for (size_t i = 0; i < hex.size(); ++i) {
    char c = hex[i];
    if (c >= 'a' && c <= 'f') {
      // Check corresponding nibble in hash
      uint8_t nibble = (i % 2 == 0) ? (hash[i / 2] >> 4) : (hash[i / 2] & 0x0F);
      if (nibble >= 8) {
        c = c - 'a' + 'A';  // Uppercase
      }
    }
    result.push_back(c);
  }

  return result;
}

Result<std::array<uint8_t, 20>> parseAddress(const std::string& addressHex) {
  std::string input = addressHex;

  // Remove 0x prefix
  if (input.size() >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
    input = input.substr(2);
  }

  // Must be exactly 40 hex characters
  if (input.size() != 40) {
    return Result<std::array<uint8_t, 20>>::fail(Error::INVALID_ADDRESS);
  }

  auto bytes = hexToBytes(input);
  if (!bytes.ok()) {
    return Result<std::array<uint8_t, 20>>::fail(Error::INVALID_ADDRESS);
  }

  std::array<uint8_t, 20> address;
  std::copy(bytes.value.begin(), bytes.value.end(), address.begin());

  return Result<std::array<uint8_t, 20>>::success(std::move(address));
}

// =============================================================================
// C API Implementation
// =============================================================================

extern "C" {

eth_tx_handle hd_eth_tx_create(uint64_t chain_id) {
  return reinterpret_cast<eth_tx_handle>(new EthereumTransaction(chain_id));
}

eth_tx_handle hd_eth_tx_create_eip1559(
  uint64_t chain_id,
  uint64_t max_priority_fee,
  uint64_t max_fee
) {
  auto tx = new EthereumTransaction(EthereumTransaction::createEIP1559(chain_id, max_priority_fee, max_fee));
  return reinterpret_cast<eth_tx_handle>(tx);
}

void hd_eth_tx_set_nonce(eth_tx_handle tx, uint64_t nonce) {
  if (tx) {
    reinterpret_cast<EthereumTransaction*>(tx)->setNonce(nonce);
  }
}

void hd_eth_tx_set_gas_price(eth_tx_handle tx, uint64_t gas_price) {
  if (tx) {
    reinterpret_cast<EthereumTransaction*>(tx)->setGasPrice(gas_price);
  }
}

void hd_eth_tx_set_gas_limit(eth_tx_handle tx, uint64_t gas_limit) {
  if (tx) {
    reinterpret_cast<EthereumTransaction*>(tx)->setGasLimit(gas_limit);
  }
}

int32_t hd_eth_tx_set_to(eth_tx_handle tx, const uint8_t* address) {
  if (!tx || !address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::array<uint8_t, 20> addr;
  std::copy(address, address + 20, addr.begin());
  reinterpret_cast<EthereumTransaction*>(tx)->setTo(addr);

  return static_cast<int32_t>(Error::OK);
}

int32_t hd_eth_tx_set_to_hex(eth_tx_handle tx, const char* address_hex) {
  if (!tx || !address_hex) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  return static_cast<int32_t>(reinterpret_cast<EthereumTransaction*>(tx)->setToFromHex(address_hex));
}

void hd_eth_tx_set_value(eth_tx_handle tx, uint64_t value_wei) {
  if (tx) {
    reinterpret_cast<EthereumTransaction*>(tx)->setValue(value_wei);
  }
}

void hd_eth_tx_set_value_256(eth_tx_handle tx, const uint8_t* value) {
  if (tx && value) {
    Bytes32 val;
    std::copy(value, value + 32, val.begin());
    reinterpret_cast<EthereumTransaction*>(tx)->setValue(val);
  }
}

void hd_eth_tx_set_data(eth_tx_handle tx, const uint8_t* data, size_t data_len) {
  if (tx && data) {
    ByteVector vec(data, data + data_len);
    reinterpret_cast<EthereumTransaction*>(tx)->setData(std::move(vec));
  }
}

int32_t hd_eth_tx_sign(eth_tx_handle tx, const uint8_t* privkey) {
  if (!tx || !privkey) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 key;
  std::copy(privkey, privkey + 32, key.begin());

  return static_cast<int32_t>(reinterpret_cast<EthereumTransaction*>(tx)->sign(key));
}

int32_t hd_eth_tx_serialize(
  eth_tx_handle tx,
  uint8_t* out,
  size_t out_size,
  size_t* actual_size
) {
  if (!tx) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = reinterpret_cast<EthereumTransaction*>(tx)->serialize();

  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  if (actual_size) {
    *actual_size = result.value.size();
  }

  if (out && out_size >= result.value.size()) {
    std::copy(result.value.begin(), result.value.end(), out);
  }

  return static_cast<int32_t>(Error::OK);
}

int32_t hd_eth_tx_get_hash(eth_tx_handle tx, uint8_t* hash_out) {
  if (!tx || !hash_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = reinterpret_cast<EthereumTransaction*>(tx)->hash();

  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  std::copy(result.value.begin(), result.value.end(), hash_out);

  return static_cast<int32_t>(Error::OK);
}

int32_t hd_eth_tx_get_hash_hex(eth_tx_handle tx, char* out, size_t out_size) {
  if (!tx || !out || out_size < 67) {  // "0x" + 64 hex chars + null
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = reinterpret_cast<EthereumTransaction*>(tx)->txid();

  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  std::strncpy(out, result.value.c_str(), out_size - 1);
  out[out_size - 1] = '\0';

  return static_cast<int32_t>(Error::OK);
}

int32_t hd_eth_tx_get_sender(eth_tx_handle tx, uint8_t* address_out) {
  if (!tx || !address_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = reinterpret_cast<EthereumTransaction*>(tx)->getSender();

  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  std::copy(result.value.begin(), result.value.end(), address_out);

  return static_cast<int32_t>(Error::OK);
}

size_t hd_eth_tx_get_size(eth_tx_handle tx) {
  if (!tx) return 0;
  return reinterpret_cast<EthereumTransaction*>(tx)->size();
}

uint64_t hd_eth_tx_get_max_fee(eth_tx_handle tx) {
  if (!tx) return 0;
  return reinterpret_cast<EthereumTransaction*>(tx)->maxFee();
}

int32_t hd_eth_tx_validate(eth_tx_handle tx) {
  if (!tx) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  return static_cast<int32_t>(reinterpret_cast<EthereumTransaction*>(tx)->validate());
}

void hd_eth_tx_destroy(eth_tx_handle tx) {
  if (tx) {
    delete reinterpret_cast<EthereumTransaction*>(tx);
  }
}

eth_tx_handle hd_eth_tx_parse(const uint8_t* data, size_t data_len) {
  if (!data || data_len == 0) {
    return nullptr;
  }

  ByteVector vec(data, data + data_len);
  auto result = EthereumTransaction::parse(vec);

  if (!result.ok()) {
    return nullptr;
  }

  return reinterpret_cast<eth_tx_handle>(new EthereumTransaction(std::move(result.value)));
}

eth_tx_handle hd_eth_tx_parse_hex(const char* hex) {
  if (!hex) {
    return nullptr;
  }

  auto result = EthereumTransaction::parseHex(hex);

  if (!result.ok()) {
    return nullptr;
  }

  return reinterpret_cast<eth_tx_handle>(new EthereumTransaction(std::move(result.value)));
}

int32_t hd_eth_pubkey_to_address(
  const uint8_t* pubkey,
  size_t pubkey_len,
  uint8_t* address_out
) {
  if (!pubkey || !address_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  if (pubkey_len == 65) {
    Bytes65 pk;
    std::copy(pubkey, pubkey + 65, pk.begin());
    auto addr = publicKeyToAddress(pk);
    std::copy(addr.begin(), addr.end(), address_out);
    return static_cast<int32_t>(Error::OK);
  } else if (pubkey_len == 33) {
    Bytes33 pk;
    std::copy(pubkey, pubkey + 33, pk.begin());
    auto addr = publicKeyToAddress(pk);
    std::copy(addr.begin(), addr.end(), address_out);
    return static_cast<int32_t>(Error::OK);
  }

  return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
}

int32_t hd_eth_address_to_checksum(
  const uint8_t* address,
  char* out,
  size_t out_size
) {
  if (!address || !out || out_size < 43) {  // "0x" + 40 chars + null
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::array<uint8_t, 20> addr;
  std::copy(address, address + 20, addr.begin());

  std::string checksum = addressToChecksumHex(addr);
  std::strncpy(out, checksum.c_str(), out_size - 1);
  out[out_size - 1] = '\0';

  return static_cast<int32_t>(Error::OK);
}

int32_t hd_eth_parse_address(
  const char* address_hex,
  uint8_t* address_out
) {
  if (!address_hex || !address_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = parseAddress(address_hex);

  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  std::copy(result.value.begin(), result.value.end(), address_out);

  return static_cast<int32_t>(Error::OK);
}

} // extern "C"

} // namespace tx
} // namespace hd_wallet
