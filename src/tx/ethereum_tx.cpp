/**
 * @file ethereum_tx.cpp
 * @brief Ethereum Transaction Implementation
 *
 * Implementation of Ethereum transaction building, signing, and serialization.
 * Supports legacy, EIP-2930, and EIP-1559 transaction types.
 */

#include "hd_wallet/tx/ethereum_tx.h"
#include "hd_wallet/config.h"
#include "hd_wallet/ecdsa.h"
#include "hd_wallet/bip32.h"
#include "../key_validation.h"
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

namespace {

// A big-endian length in `count` bytes at data[at]: 1 to sizeof(size_t) bytes,
// no leading zero byte (canonical), within the input.
bool readLength(const ByteVector& data, size_t at, size_t count, size_t& out) {
  if (count == 0 || count > sizeof(size_t) || at > data.size() || count > data.size() - at ||
      data[at] == 0) {
    return false;
  }
  size_t value = 0;
  for (size_t i = 0; i < count; ++i) {
    value = (value << 8) | data[at + i];
  }
  out = value;
  return true;
}

}  // namespace

std::optional<Item> decodeItem(const ByteVector& data, size_t& offset) {
  if (offset >= data.size()) {
    return std::nullopt;
  }
  const uint8_t prefix = data[offset];
  if (prefix < 0x80) {
    ++offset;
    return Item{false, ByteVector{prefix}};
  }

  const bool isList = prefix >= 0xc0;
  const uint8_t base = isList ? 0xc0 : 0x80;
  size_t header = 1;
  size_t length = 0;
  if (prefix <= base + 55) {
    length = prefix - base;
  } else {
    // Long form: the length in 1-8 bytes, only for lengths above 55.
    const size_t count = prefix - base - 55;
    if (!readLength(data, offset + 1, count, length) || length <= 55) {
      return std::nullopt;
    }
    header += count;
  }
  if (header > data.size() - offset || length > data.size() - offset - header) {
    return std::nullopt;
  }
  ByteVector payload(data.begin() + offset + header, data.begin() + offset + header + length);
  // A single byte below 0x80 is its own encoding, never a one-byte string.
  if (!isList && length == 1 && payload[0] < 0x80) {
    return std::nullopt;
  }
  offset += header + length;
  return Item{isList, std::move(payload)};
}

std::optional<std::vector<Item>> decodeListItems(const ByteVector& data, size_t& offset) {
  auto list = decodeItem(data, offset);
  if (!list || !list->isList) {
    return std::nullopt;
  }
  std::vector<Item> items;
  size_t pos = 0;
  while (pos < list->payload.size()) {
    auto item = decodeItem(list->payload, pos);
    if (!item) {
      return std::nullopt;
    }
    items.push_back(std::move(*item));
  }
  return items;
}

std::optional<ByteVector> decode(const ByteVector& data, size_t& offset) {
  auto item = decodeItem(data, offset);
  if (!item) {
    return std::nullopt;
  }
  return std::move(item->payload);
}

std::optional<std::vector<ByteVector>> decodeList(const ByteVector& data, size_t& offset) {
  auto items = decodeListItems(data, offset);
  if (!items) {
    return std::nullopt;
  }
  std::vector<ByteVector> payloads;
  for (auto& item : *items) {
    payloads.push_back(std::move(item.payload));
  }
  return payloads;
}

std::optional<uint64_t> decodeInteger(const ByteVector& data) {
  // Canonical: no leading zero byte (zero is the empty string), at most 8 bytes.
  if (data.size() > 8 || (!data.empty() && data[0] == 0)) {
    return std::nullopt;
  }
  uint64_t result = 0;
  for (uint8_t byte : data) {
    result = (result << 8) | byte;
  }
  return result;
}

std::optional<Bytes32> decodeInteger256(const ByteVector& data) {
  if (data.size() > 32 || (!data.empty() && data[0] == 0)) {
    return std::nullopt;
  }
  Bytes32 result{};
  std::copy(data.begin(), data.end(), result.begin() + (32 - data.size()));
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
  , chainId_(0)
  , nonce_(0)
  , hasNonce_(false)
  , gasPrice_(0)
  , maxPriorityFeePerGas_(0)
  , maxFeePerGas_(0)
  , gasLimit_(ETH_DEFAULT_GAS_LIMIT)
  , to_{}
  , hasTo_(false)
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
  , hasNonce_(false)
  , gasPrice_(0)
  , maxPriorityFeePerGas_(0)
  , maxFeePerGas_(0)
  , gasLimit_(ETH_DEFAULT_GAS_LIMIT)
  , to_{}
  , hasTo_(false)
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

// A recipient is 20 bytes and never 0x00..00: a transaction with no 'to' is
// a contract creation, which is requested with setContractCreation(true) and
// serializes an empty field. A refused recipient leaves the transaction with
// none (and not a contract creation), so it cannot serialize or sign.
Error EthereumTransaction::setTo(const std::array<uint8_t, 20>& to) {
  hasTo_ = false;
  isContractCreation_ = false;
  to_.fill(0);
  if (isZeroAddress(to)) {
    return Error::INVALID_ADDRESS;
  }
  to_ = to;
  hasTo_ = true;
  return Error::OK;
}

Error EthereumTransaction::setToFromHex(const std::string& addressHex) {
  auto result = parseAddress(addressHex);
  if (!result.ok()) {
    hasTo_ = false;
    isContractCreation_ = false;
    to_.fill(0);
    return result.error;
  }
  return setTo(result.value);
}

void EthereumTransaction::setContractCreation(bool creation) {
  isContractCreation_ = creation;
  if (creation) {
    hasTo_ = false;
    to_.fill(0);
  }
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

      if (hasSignature()) {
        items.push_back(rlp::encodeInteger(signatureV_));
        items.push_back(rlp::encodeInteger256(signatureR_));
        items.push_back(rlp::encodeInteger256(signatureS_));
      } else {
        // Unsigned: the EIP-155 signing form (chainId, 0, 0), which parse
        // reads back with its chain ID.
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
  if (!hasRecipient()) {
    return Result<ByteVector>::fail(Error::INVALID_ADDRESS);
  }
  if (!hasNonce_) {
    return Result<ByteVector>::fail(Error::INVALID_TRANSACTION);
  }
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
  if (!hasRecipient()) {
    return Result<ByteVector>::fail(Error::INVALID_ADDRESS);
  }
  if (!hasNonce_) {
    return Result<ByteVector>::fail(Error::INVALID_TRANSACTION);
  }
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

// Sign the Keccak-256 signing hash as given (RFC 6979 deterministic k, low-S)
// and return r, s and the recovery id (0 or 1) that v encodes.
static bool signECDSARecoverable(
  const Bytes32& hash,
  const Bytes32& privateKey,
  Bytes32& outR,
  Bytes32& outS,
  uint8_t& outRecoveryId
) {
  auto signature = ecdsa::secp256k1SignRecoverable(privateKey, hash);
  if (!signature.ok()) {
    return false;
  }
  // secp256k1SignRecoverable returns v (27 + recovery id) || r || s.
  const uint8_t recoveryId = static_cast<uint8_t>(signature.value[0] - 27);
  if (recoveryId > 1) {
    return false;  // r >= n (recovery id 2/3) is not representable in Ethereum's v
  }
  std::copy(signature.value.begin() + 1, signature.value.begin() + 33, outR.begin());
  std::copy(signature.value.begin() + 33, signature.value.end(), outS.begin());
  outRecoveryId = recoveryId;
  return true;
}

#endif

Error EthereumTransaction::sign(const Bytes32& privateKey, int /* inputIndex */) {
#if HD_WALLET_USE_CRYPTOPP
  // Get the signing hash (it needs a recipient and a nonce)
  auto forSigning = serializeForSigning();
  if (!forSigning.ok()) {
    return forSigning.error;
  }
  // Chain ID 0 would sign a pre-EIP-155 transaction, valid on every chain;
  // above EIP-2294's bound, v = 2 * chainId + 36 no longer fits 64 bits.
  if (chainId_ == 0 || chainId_ > ETH_MAX_CHAIN_ID) {
    return Error::INVALID_TRANSACTION;
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
      signatureV_ = chainId_ * 2 + 35 + recoveryId;
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
  // A transfer needs a recipient; only an explicit contract creation has none.
  if (!hasRecipient()) {
    return Error::INVALID_ADDRESS;
  }

  // The nonce has no default.
  if (!hasNonce_) {
    return Error::INVALID_TRANSACTION;
  }

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
  tx->hasNonce_ = hasNonce_;
  tx->gasPrice_ = gasPrice_;
  tx->maxPriorityFeePerGas_ = maxPriorityFeePerGas_;
  tx->maxFeePerGas_ = maxFeePerGas_;
  tx->gasLimit_ = gasLimit_;
  tx->to_ = to_;
  tx->hasTo_ = hasTo_;
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

// The 'to' field of an encoded transaction: 20 bytes is a recipient, empty is
// a contract creation, anything else is malformed.
bool EthereumTransaction::readRecipient(const ByteVector& field, EthereumTransaction& tx) {
  if (field.size() == 20) {
    std::copy(field.begin(), field.end(), tx.to_.begin());
    tx.hasTo_ = true;
    tx.isContractCreation_ = false;
    return true;
  }
  if (field.empty()) {
    tx.hasTo_ = false;
    tx.isContractCreation_ = true;
    return true;
  }
  return false;
}

namespace {

// Typed readers of a decoded field: a string item (never a list) holding a
// canonical integer of at most 8 (uint64) or 32 (uint256) bytes, or bytes.
bool readUint64(const rlp::Item& item, uint64_t& out) {
  if (item.isList) return false;
  auto value = rlp::decodeInteger(item.payload);
  if (!value) return false;
  out = *value;
  return true;
}

bool readUint256(const rlp::Item& item, Bytes32& out) {
  if (item.isList) return false;
  auto value = rlp::decodeInteger256(item.payload);
  if (!value) return false;
  out = *value;
  return true;
}

bool readByteString(const rlp::Item& item, ByteVector& out) {
  if (item.isList) return false;
  out = item.payload;
  return true;
}

// Access lists are not parsed: only the empty list is accepted (a parsed
// transaction that dropped its access list would sign a different transaction).
// A byte string where the list goes is malformed; a non-empty list is
// unsupported.
Error readEmptyAccessList(const rlp::Item& item) {
  if (!item.isList) return Error::INVALID_TRANSACTION;
  return item.payload.empty() ? Error::OK : Error::NOT_SUPPORTED;
}

}  // namespace

Result<EthereumTransaction> EthereumTransaction::parse(const ByteVector& data) {
  using R = Result<EthereumTransaction>;
  if (data.empty()) {
    return R::fail(Error::INVALID_TRANSACTION);
  }

  EthereumTransaction tx;
  ByteVector body;
  if (data[0] >= 0xc0) {
    tx.type_ = EthTxType::LEGACY;
    body = data;
  } else if (data[0] == static_cast<uint8_t>(EthTxType::ACCESS_LIST) ||
             data[0] == static_cast<uint8_t>(EthTxType::EIP1559)) {
    // Typed transaction (EIP-2718): type byte, then one RLP list.
    tx.type_ = static_cast<EthTxType>(data[0]);
    body.assign(data.begin() + 1, data.end());
  } else if (data[0] <= 0x7f) {
    return R::fail(Error::NOT_SUPPORTED);
  } else {
    return R::fail(Error::INVALID_TRANSACTION);
  }

  // Exactly one canonical list, nothing after it.
  size_t offset = 0;
  auto items = rlp::decodeListItems(body, offset);
  if (!items || offset != body.size()) {
    return R::fail(Error::INVALID_TRANSACTION);
  }
  const std::vector<rlp::Item>& f = *items;

  // Every integer field is canonical and within its bound: 8 bytes for the
  // chain ID, nonce, gas and fees (uint64 here), 32 for value, r and s.
  uint64_t v = 0;
  bool ok = false;
  Error accessList = Error::OK;
  switch (tx.type_) {
    case EthTxType::LEGACY:
      ok = f.size() == 9 &&
           readUint64(f[0], tx.nonce_) && readUint64(f[1], tx.gasPrice_) && readUint64(f[2], tx.gasLimit_) &&
           !f[3].isList && readRecipient(f[3].payload, tx) && readUint256(f[4], tx.value_) &&
           readByteString(f[5], tx.data_) &&
           readUint64(f[6], v) && readUint256(f[7], tx.signatureR_) && readUint256(f[8], tx.signatureS_);
      break;
    // A typed transaction has its signature fields (y-parity, r, s; zero
    // when unsigned) or none: the signing payload, as other libraries
    // serialize an unsigned transaction.
    case EthTxType::ACCESS_LIST:
      ok = (f.size() == 11 || f.size() == 8) &&
           readUint64(f[0], tx.chainId_) && readUint64(f[1], tx.nonce_) && readUint64(f[2], tx.gasPrice_) &&
           readUint64(f[3], tx.gasLimit_) && !f[4].isList && readRecipient(f[4].payload, tx) &&
           readUint256(f[5], tx.value_) && readByteString(f[6], tx.data_) &&
           (f.size() == 8 ||
            (readUint64(f[8], v) && readUint256(f[9], tx.signatureR_) && readUint256(f[10], tx.signatureS_)));
      if (ok) accessList = readEmptyAccessList(f[7]);
      break;
    case EthTxType::EIP1559:
      ok = (f.size() == 12 || f.size() == 9) &&
           readUint64(f[0], tx.chainId_) && readUint64(f[1], tx.nonce_) &&
           readUint64(f[2], tx.maxPriorityFeePerGas_) && readUint64(f[3], tx.maxFeePerGas_) &&
           readUint64(f[4], tx.gasLimit_) && !f[5].isList && readRecipient(f[5].payload, tx) &&
           readUint256(f[6], tx.value_) && readByteString(f[7], tx.data_) &&
           (f.size() == 9 ||
            (readUint64(f[9], v) && readUint256(f[10], tx.signatureR_) && readUint256(f[11], tx.signatureS_)));
      if (ok) accessList = readEmptyAccessList(f[8]);
      break;
  }
  if (!ok) {
    return R::fail(Error::INVALID_TRANSACTION);
  }
  if (accessList != Error::OK) {
    return R::fail(accessList);
  }
  tx.hasNonce_ = true;

  const bool isSigned = tx.hasSignature();
  if (tx.type_ == EthTxType::LEGACY) {
    if (!isSigned) {
      // Unsigned: the EIP-155 signing form carries the chain ID where v goes.
      tx.chainId_ = v;
      v = 0;
    } else if (v >= 35) {
      tx.chainId_ = (v - 35) / 2;  // EIP-155
    } else if (v == 27 || v == 28) {
      tx.chainId_ = 0;  // Pre-EIP-155
    } else {
      return R::fail(Error::INVALID_TRANSACTION);
    }
  } else if (v > 1 || (!isSigned && v != 0)) {
    return R::fail(Error::INVALID_TRANSACTION);  // y-parity is 0 or 1
  }
  if (tx.chainId_ > ETH_MAX_CHAIN_ID) {
    return R::fail(Error::INVALID_TRANSACTION);
  }
  tx.signatureV_ = v;

  tx.status_ = isSigned ? TxStatus::SIGNED : TxStatus::UNSIGNED;
  return R::success(std::move(tx));
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

// The address of a secp256k1 public key: the last 20 bytes of Keccak-256 of
// x || y. A key that is not a point of the curve has no address (it used to
// hash whatever bytes it was given, and a compressed key gave 0x00..00).
Result<std::array<uint8_t, 20>> publicKeyToAddress(const Bytes65& publicKey) {
  if (publicKey[0] != 0x04 || !keys::isValidPublicKey(Curve::SECP256K1, publicKey.data(), publicKey.size())) {
    return Result<std::array<uint8_t, 20>>::fail(Error::INVALID_PUBLIC_KEY);
  }

  Bytes32 hash = keccak256(publicKey.data() + 1, 64);
  std::array<uint8_t, 20> address{};
  std::copy(hash.begin() + 12, hash.end(), address.begin());
  return Result<std::array<uint8_t, 20>>::success(std::move(address));
}

Result<std::array<uint8_t, 20>> publicKeyToAddress(const Bytes33& compressedPublicKey) {
  auto uncompressed = bip32::decompressPublicKey(compressedPublicKey, Curve::SECP256K1);
  if (!uncompressed.ok()) {
    return Result<std::array<uint8_t, 20>>::fail(Error::INVALID_PUBLIC_KEY);
  }
  return publicKeyToAddress(uncompressed.value);
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

bool isZeroAddress(const std::array<uint8_t, 20>& address) {
  uint8_t any = 0;
  for (uint8_t b : address) {
    any |= b;
  }
  return any == 0;
}

// An address is exactly 40 ASCII hex digits, after at most one "0x"/"0X".
// Nothing else is accepted: no second prefix, no whitespace or NUL, no other
// script's digits, no other length. Hex digits of mixed case are an EIP-55
// checksum and must match it (a mismatch is a mistyped address).
Result<std::array<uint8_t, 20>> parseAddress(const std::string& addressHex) {
  using AddressResult = Result<std::array<uint8_t, 20>>;
  size_t start = 0;
  if (addressHex.size() >= 2 && addressHex[0] == '0' && (addressHex[1] == 'x' || addressHex[1] == 'X')) {
    start = 2;
  }
  if (addressHex.size() - start != 40) {
    return AddressResult::fail(Error::INVALID_ADDRESS);
  }

  std::array<uint8_t, 20> address{};
  bool hasLower = false;
  bool hasUpper = false;
  for (size_t i = 0; i < 40; ++i) {
    const char c = addressHex[start + i];
    int nibble;
    if (c >= '0' && c <= '9') {
      nibble = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      nibble = c - 'a' + 10;
      hasLower = true;
    } else if (c >= 'A' && c <= 'F') {
      nibble = c - 'A' + 10;
      hasUpper = true;
    } else {
      return AddressResult::fail(Error::INVALID_ADDRESS);
    }
    address[i / 2] = static_cast<uint8_t>(address[i / 2] | (i % 2 == 0 ? nibble << 4 : nibble));
  }

  if (hasLower && hasUpper) {
    const std::string checksummed = addressToChecksumHex(address);
    if (checksummed.compare(2, 40, addressHex, start, 40) != 0) {
      return AddressResult::fail(Error::INVALID_ADDRESS);
    }
  }

  return AddressResult::success(std::move(address));
}

// =============================================================================
// C API Implementation
// =============================================================================

extern "C" {

eth_tx_handle hd_eth_tx_create(uint64_t chain_id) {
  if (chain_id == 0 || chain_id > ETH_MAX_CHAIN_ID) {
    return nullptr;
  }
  return reinterpret_cast<eth_tx_handle>(new EthereumTransaction(chain_id));
}

eth_tx_handle hd_eth_tx_create_eip1559(
  uint64_t chain_id,
  uint64_t max_priority_fee,
  uint64_t max_fee
) {
  if (chain_id == 0 || chain_id > ETH_MAX_CHAIN_ID) {
    return nullptr;
  }
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

  std::array<uint8_t, 20> addr{};
  std::copy(address, address + 20, addr.begin());
  return static_cast<int32_t>(reinterpret_cast<EthereumTransaction*>(tx)->setTo(addr));
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

  Result<std::array<uint8_t, 20>> addr = Result<std::array<uint8_t, 20>>::fail(Error::INVALID_PUBLIC_KEY);
  if (pubkey_len == 65) {
    Bytes65 pk;
    std::copy(pubkey, pubkey + 65, pk.begin());
    addr = publicKeyToAddress(pk);
  } else if (pubkey_len == 33) {
    Bytes33 pk;
    std::copy(pubkey, pubkey + 33, pk.begin());
    addr = publicKeyToAddress(pk);
  }
  if (!addr.ok()) {
    return static_cast<int32_t>(addr.error);
  }

  std::copy(addr.value.begin(), addr.value.end(), address_out);
  return static_cast<int32_t>(Error::OK);
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
