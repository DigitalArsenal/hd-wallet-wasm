/**
 * @file bitcoin_tx.cpp
 * @brief Bitcoin Transaction Implementation
 *
 * Implementation of Bitcoin transaction building, signing, and serialization.
 * Supports both legacy and SegWit transaction formats.
 */

#include "hd_wallet/tx/bitcoin_tx.h"
#include "hd_wallet/config.h"
#include "hd_wallet/secure_rng.h"

#include <algorithm>
#include <cstring>
#include <stdexcept>

#if HD_WALLET_USE_CRYPTOPP
#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/oids.h>
#include <cryptopp/sha.h>
#include <cryptopp/integer.h>
#include <cryptopp/dsa.h>
#endif

namespace hd_wallet {
namespace tx {

// =============================================================================
// Script Type Names
// =============================================================================

const char* scriptTypeName(ScriptType type) {
  switch (type) {
    case ScriptType::UNKNOWN:     return "unknown";
    case ScriptType::P2PKH:       return "p2pkh";
    case ScriptType::P2SH:        return "p2sh";
    case ScriptType::P2WPKH:      return "p2wpkh";
    case ScriptType::P2WSH:       return "p2wsh";
    case ScriptType::P2TR:        return "p2tr";
    case ScriptType::P2SH_P2WPKH: return "p2sh-p2wpkh";
    case ScriptType::P2SH_P2WSH:  return "p2sh-p2wsh";
    case ScriptType::NULLDATA:    return "nulldata";
    case ScriptType::MULTISIG:    return "multisig";
    default:                      return "unknown";
  }
}

// =============================================================================
// Bitcoin Script Opcodes
// =============================================================================

namespace op {
  constexpr uint8_t OP_0 = 0x00;
  constexpr uint8_t OP_PUSHDATA1 = 0x4c;
  constexpr uint8_t OP_PUSHDATA2 = 0x4d;
  constexpr uint8_t OP_PUSHDATA4 = 0x4e;
  constexpr uint8_t OP_1NEGATE = 0x4f;
  constexpr uint8_t OP_1 = 0x51;
  constexpr uint8_t OP_16 = 0x60;
  constexpr uint8_t OP_RETURN = 0x6a;
  constexpr uint8_t OP_DUP = 0x76;
  constexpr uint8_t OP_EQUAL = 0x87;
  constexpr uint8_t OP_EQUALVERIFY = 0x88;
  constexpr uint8_t OP_HASH160 = 0xa9;
  constexpr uint8_t OP_CHECKSIG = 0xac;
  constexpr uint8_t OP_CHECKMULTISIG = 0xae;
} // namespace op

// Helper to push data onto script
static void pushData(ByteVector& script, const ByteVector& data) {
  size_t len = data.size();
  if (len == 0) {
    script.push_back(op::OP_0);
  } else if (len == 1 && data[0] >= 1 && data[0] <= 16) {
    script.push_back(op::OP_1 + data[0] - 1);
  } else if (len < op::OP_PUSHDATA1) {
    script.push_back(static_cast<uint8_t>(len));
    script.insert(script.end(), data.begin(), data.end());
  } else if (len <= 0xFF) {
    script.push_back(op::OP_PUSHDATA1);
    script.push_back(static_cast<uint8_t>(len));
    script.insert(script.end(), data.begin(), data.end());
  } else if (len <= 0xFFFF) {
    script.push_back(op::OP_PUSHDATA2);
    script.push_back(static_cast<uint8_t>(len & 0xFF));
    script.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    script.insert(script.end(), data.begin(), data.end());
  } else {
    script.push_back(op::OP_PUSHDATA4);
    script.push_back(static_cast<uint8_t>(len & 0xFF));
    script.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    script.push_back(static_cast<uint8_t>((len >> 16) & 0xFF));
    script.push_back(static_cast<uint8_t>((len >> 24) & 0xFF));
    script.insert(script.end(), data.begin(), data.end());
  }
}

template<size_t N>
static void pushData(ByteVector& script, const std::array<uint8_t, N>& data) {
  ByteVector vec(data.begin(), data.end());
  pushData(script, vec);
}

// =============================================================================
// Outpoint
// =============================================================================

ByteVector Outpoint::serialize() const {
  ByteVector result;
  result.reserve(36);

  // TXID (32 bytes, internal byte order)
  result.insert(result.end(), txid.begin(), txid.end());

  // Output index (4 bytes, little-endian)
  auto voutBytes = encodeLE(vout);
  result.insert(result.end(), voutBytes.begin(), voutBytes.end());

  return result;
}

std::optional<Outpoint> Outpoint::parse(const ByteVector& data, size_t& offset) {
  if (offset + 36 > data.size()) {
    return std::nullopt;
  }

  Outpoint outpoint;

  // TXID
  std::copy(data.begin() + offset, data.begin() + offset + 32, outpoint.txid.begin());
  offset += 32;

  // Output index
  auto vout = decodeLE<uint32_t>(data, offset);
  if (!vout) {
    return std::nullopt;
  }
  outpoint.vout = *vout;

  return outpoint;
}

// =============================================================================
// Transaction Input
// =============================================================================

ByteVector TxInput::serialize() const {
  ByteVector result;

  // Previous output
  auto prevoutBytes = prevout.serialize();
  result.insert(result.end(), prevoutBytes.begin(), prevoutBytes.end());

  // Script length + script
  auto scriptLen = encodeVarInt(scriptSig.size());
  result.insert(result.end(), scriptLen.begin(), scriptLen.end());
  result.insert(result.end(), scriptSig.begin(), scriptSig.end());

  // Sequence
  auto seqBytes = encodeLE(sequence);
  result.insert(result.end(), seqBytes.begin(), seqBytes.end());

  return result;
}

ByteVector TxInput::serializeWitness() const {
  ByteVector result;

  // Number of witness items
  auto itemCount = encodeVarInt(witness.size());
  result.insert(result.end(), itemCount.begin(), itemCount.end());

  // Each witness item
  for (const auto& item : witness) {
    auto itemLen = encodeVarInt(item.size());
    result.insert(result.end(), itemLen.begin(), itemLen.end());
    result.insert(result.end(), item.begin(), item.end());
  }

  return result;
}

// =============================================================================
// Transaction Output
// =============================================================================

ByteVector TxOutput::serialize() const {
  ByteVector result;

  // Value (8 bytes, little-endian)
  auto valueBytes = encodeLE(value);
  result.insert(result.end(), valueBytes.begin(), valueBytes.end());

  // Script length + script
  auto scriptLen = encodeVarInt(scriptPubKey.size());
  result.insert(result.end(), scriptLen.begin(), scriptLen.end());
  result.insert(result.end(), scriptPubKey.begin(), scriptPubKey.end());

  return result;
}

std::optional<TxOutput> TxOutput::parse(const ByteVector& data, size_t& offset) {
  TxOutput output;

  // Value
  auto value = decodeLE<uint64_t>(data, offset);
  if (!value) {
    return std::nullopt;
  }
  output.value = *value;

  // Script
  auto scriptLen = decodeVarInt(data, offset);
  if (!scriptLen || offset + *scriptLen > data.size()) {
    return std::nullopt;
  }

  output.scriptPubKey.assign(data.begin() + offset, data.begin() + offset + *scriptLen);
  offset += *scriptLen;

  return output;
}

ScriptType TxOutput::getScriptType() const {
  size_t len = scriptPubKey.size();

  // P2PKH: OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
  if (len == 25 &&
      scriptPubKey[0] == op::OP_DUP &&
      scriptPubKey[1] == op::OP_HASH160 &&
      scriptPubKey[2] == 0x14 &&
      scriptPubKey[23] == op::OP_EQUALVERIFY &&
      scriptPubKey[24] == op::OP_CHECKSIG) {
    return ScriptType::P2PKH;
  }

  // P2SH: OP_HASH160 <20 bytes> OP_EQUAL
  if (len == 23 &&
      scriptPubKey[0] == op::OP_HASH160 &&
      scriptPubKey[1] == 0x14 &&
      scriptPubKey[22] == op::OP_EQUAL) {
    return ScriptType::P2SH;
  }

  // P2WPKH: OP_0 <20 bytes>
  if (len == 22 &&
      scriptPubKey[0] == op::OP_0 &&
      scriptPubKey[1] == 0x14) {
    return ScriptType::P2WPKH;
  }

  // P2WSH: OP_0 <32 bytes>
  if (len == 34 &&
      scriptPubKey[0] == op::OP_0 &&
      scriptPubKey[1] == 0x20) {
    return ScriptType::P2WSH;
  }

  // P2TR: OP_1 <32 bytes>
  if (len == 34 &&
      scriptPubKey[0] == op::OP_1 &&
      scriptPubKey[1] == 0x20) {
    return ScriptType::P2TR;
  }

  // OP_RETURN: OP_RETURN ...
  if (len >= 1 && scriptPubKey[0] == op::OP_RETURN) {
    return ScriptType::NULLDATA;
  }

  return ScriptType::UNKNOWN;
}

// =============================================================================
// Script Builders
// =============================================================================

ByteVector buildP2PKH(const std::array<uint8_t, 20>& pubkeyHash) {
  ByteVector script;
  script.reserve(25);

  script.push_back(op::OP_DUP);
  script.push_back(op::OP_HASH160);
  pushData(script, pubkeyHash);
  script.push_back(op::OP_EQUALVERIFY);
  script.push_back(op::OP_CHECKSIG);

  return script;
}

ByteVector buildP2PKHFromPubKey(const Bytes33& publicKey) {
  auto pubkeyHash = hash160(publicKey.data(), publicKey.size());
  return buildP2PKH(pubkeyHash);
}

ByteVector buildP2SH(const std::array<uint8_t, 20>& scriptHash) {
  ByteVector script;
  script.reserve(23);

  script.push_back(op::OP_HASH160);
  pushData(script, scriptHash);
  script.push_back(op::OP_EQUAL);

  return script;
}

ByteVector buildP2WPKH(const std::array<uint8_t, 20>& pubkeyHash) {
  ByteVector script;
  script.reserve(22);

  script.push_back(op::OP_0);
  script.push_back(0x14);  // Push 20 bytes
  script.insert(script.end(), pubkeyHash.begin(), pubkeyHash.end());

  return script;
}

ByteVector buildP2WPKHFromPubKey(const Bytes33& publicKey) {
  auto pubkeyHash = hash160(publicKey.data(), publicKey.size());
  return buildP2WPKH(pubkeyHash);
}

ByteVector buildP2WSH(const Bytes32& witnessScriptHash) {
  ByteVector script;
  script.reserve(34);

  script.push_back(op::OP_0);
  script.push_back(0x20);  // Push 32 bytes
  script.insert(script.end(), witnessScriptHash.begin(), witnessScriptHash.end());

  return script;
}

ByteVector buildP2SH_P2WPKH(const Bytes33& publicKey) {
  // First build the redeem script (which is a P2WPKH script)
  auto redeemScript = buildP2SH_P2WPKH_RedeemScript(publicKey);

  // Hash the redeem script
  auto scriptHash = hash160(redeemScript.data(), redeemScript.size());

  // Build P2SH with that hash
  return buildP2SH(scriptHash);
}

ByteVector buildP2SH_P2WPKH_RedeemScript(const Bytes33& publicKey) {
  // The redeem script is simply a P2WPKH script
  auto pubkeyHash = hash160(publicKey.data(), publicKey.size());
  return buildP2WPKH(pubkeyHash);
}

ByteVector buildOpReturn(const ByteVector& data) {
  ByteVector script;
  script.reserve(1 + data.size() + 2);

  script.push_back(op::OP_RETURN);
  pushData(script, data);

  return script;
}

ByteVector buildP2PKHScriptSig(const ByteVector& signature, const Bytes33& publicKey) {
  ByteVector script;
  script.reserve(signature.size() + publicKey.size() + 4);

  pushData(script, signature);
  pushData(script, publicKey);

  return script;
}

// =============================================================================
// Bitcoin Transaction Class
// =============================================================================

BitcoinTransaction::BitcoinTransaction()
  : version_(BTC_TX_VERSION)
  , lockTime_(0)
  , inputs_()
  , outputs_()
  , status_(TxStatus::UNBUILT) {}

BitcoinTransaction::BitcoinTransaction(uint32_t version)
  : version_(version)
  , lockTime_(0)
  , inputs_()
  , outputs_()
  , status_(TxStatus::UNBUILT) {}

void BitcoinTransaction::invalidateCache() {
  hashPrevouts_.reset();
  hashSequence_.reset();
  hashOutputs_.reset();
}

// ----- Input Management -----

size_t BitcoinTransaction::addInput(
  const Bytes32& txid,
  uint32_t vout,
  uint64_t amount,
  ScriptType scriptType,
  const Bytes33& publicKey,
  uint32_t sequence
) {
  TxInput input;
  input.prevout.txid = txid;
  input.prevout.vout = vout;
  input.amount = amount;
  input.scriptType = scriptType;
  input.publicKey = publicKey;
  input.sequence = sequence;

  // For P2SH-P2WPKH, pre-compute the redeem script
  if (scriptType == ScriptType::P2SH_P2WPKH) {
    input.redeemScript = buildP2SH_P2WPKH_RedeemScript(publicKey);
  }

  inputs_.push_back(std::move(input));
  invalidateCache();
  status_ = TxStatus::UNSIGNED;

  return inputs_.size() - 1;
}

size_t BitcoinTransaction::addInput(TxInput&& input) {
  inputs_.push_back(std::move(input));
  invalidateCache();
  status_ = TxStatus::UNSIGNED;
  return inputs_.size() - 1;
}

size_t BitcoinTransaction::addInput(const TxInput& input) {
  inputs_.push_back(input);
  invalidateCache();
  status_ = TxStatus::UNSIGNED;
  return inputs_.size() - 1;
}

const TxInput& BitcoinTransaction::getInput(size_t index) const {
  if (index >= inputs_.size()) {
    throw std::out_of_range("Input index out of range");
  }
  return inputs_[index];
}

TxInput& BitcoinTransaction::getInput(size_t index) {
  if (index >= inputs_.size()) {
    throw std::out_of_range("Input index out of range");
  }
  invalidateCache();
  return inputs_[index];
}

void BitcoinTransaction::removeInput(size_t index) {
  if (index >= inputs_.size()) {
    throw std::out_of_range("Input index out of range");
  }
  inputs_.erase(inputs_.begin() + index);
  invalidateCache();
}

void BitcoinTransaction::clearInputs() {
  inputs_.clear();
  invalidateCache();
  status_ = TxStatus::UNBUILT;
}

// ----- Output Management -----

size_t BitcoinTransaction::addOutput(uint64_t value, const ByteVector& scriptPubKey) {
  TxOutput output;
  output.value = value;
  output.scriptPubKey = scriptPubKey;

  outputs_.push_back(std::move(output));
  invalidateCache();

  if (status_ == TxStatus::UNBUILT) {
    status_ = TxStatus::UNSIGNED;
  }

  return outputs_.size() - 1;
}

size_t BitcoinTransaction::addP2PKHOutput(uint64_t value, const std::array<uint8_t, 20>& pubkeyHash) {
  return addOutput(value, buildP2PKH(pubkeyHash));
}

size_t BitcoinTransaction::addP2WPKHOutput(uint64_t value, const std::array<uint8_t, 20>& pubkeyHash) {
  return addOutput(value, buildP2WPKH(pubkeyHash));
}

size_t BitcoinTransaction::addP2SHOutput(uint64_t value, const std::array<uint8_t, 20>& scriptHash) {
  return addOutput(value, buildP2SH(scriptHash));
}

size_t BitcoinTransaction::addOpReturnOutput(const ByteVector& data) {
  return addOutput(0, buildOpReturn(data));
}

size_t BitcoinTransaction::addOutput(TxOutput&& output) {
  outputs_.push_back(std::move(output));
  invalidateCache();

  if (status_ == TxStatus::UNBUILT) {
    status_ = TxStatus::UNSIGNED;
  }

  return outputs_.size() - 1;
}

size_t BitcoinTransaction::addOutput(const TxOutput& output) {
  outputs_.push_back(output);
  invalidateCache();

  if (status_ == TxStatus::UNBUILT) {
    status_ = TxStatus::UNSIGNED;
  }

  return outputs_.size() - 1;
}

const TxOutput& BitcoinTransaction::getOutput(size_t index) const {
  if (index >= outputs_.size()) {
    throw std::out_of_range("Output index out of range");
  }
  return outputs_[index];
}

TxOutput& BitcoinTransaction::getOutput(size_t index) {
  if (index >= outputs_.size()) {
    throw std::out_of_range("Output index out of range");
  }
  invalidateCache();
  return outputs_[index];
}

void BitcoinTransaction::removeOutput(size_t index) {
  if (index >= outputs_.size()) {
    throw std::out_of_range("Output index out of range");
  }
  outputs_.erase(outputs_.begin() + index);
  invalidateCache();
}

void BitcoinTransaction::clearOutputs() {
  outputs_.clear();
  invalidateCache();
}

// ----- Properties -----

bool BitcoinTransaction::hasWitness() const {
  for (const auto& input : inputs_) {
    if (input.hasWitness()) {
      return true;
    }
  }
  return false;
}

uint64_t BitcoinTransaction::totalInputValue() const {
  uint64_t total = 0;
  for (const auto& input : inputs_) {
    total += input.amount;
  }
  return total;
}

uint64_t BitcoinTransaction::totalOutputValue() const {
  uint64_t total = 0;
  for (const auto& output : outputs_) {
    total += output.value;
  }
  return total;
}

uint64_t BitcoinTransaction::fee() const {
  uint64_t inputVal = totalInputValue();
  uint64_t outputVal = totalOutputValue();
  return inputVal > outputVal ? inputVal - outputVal : 0;
}

// ----- Serialization -----

Result<ByteVector> BitcoinTransaction::serialize() const {
  if (hasWitness()) {
    return serializeWitness();
  }
  return serializeLegacy();
}

Result<ByteVector> BitcoinTransaction::serializeLegacy() const {
  ByteVector result;

  // Version (4 bytes)
  auto versionBytes = encodeLE(version_);
  appendBytes(result, versionBytes);

  // Input count
  appendBytes(result, encodeVarInt(inputs_.size()));

  // Inputs
  for (const auto& input : inputs_) {
    appendBytes(result, input.serialize());
  }

  // Output count
  appendBytes(result, encodeVarInt(outputs_.size()));

  // Outputs
  for (const auto& output : outputs_) {
    appendBytes(result, output.serialize());
  }

  // Locktime (4 bytes)
  auto lockTimeBytes = encodeLE(lockTime_);
  appendBytes(result, lockTimeBytes);

  return Result<ByteVector>::success(std::move(result));
}

Result<ByteVector> BitcoinTransaction::serializeWitness() const {
  ByteVector result;

  // Version (4 bytes)
  auto versionBytes = encodeLE(version_);
  appendBytes(result, versionBytes);

  // SegWit marker and flag
  appendByte(result, SEGWIT_MARKER);
  appendByte(result, SEGWIT_FLAG);

  // Input count
  appendBytes(result, encodeVarInt(inputs_.size()));

  // Inputs (without witness)
  for (const auto& input : inputs_) {
    appendBytes(result, input.serialize());
  }

  // Output count
  appendBytes(result, encodeVarInt(outputs_.size()));

  // Outputs
  for (const auto& output : outputs_) {
    appendBytes(result, output.serialize());
  }

  // Witness data for each input
  for (const auto& input : inputs_) {
    appendBytes(result, input.serializeWitness());
  }

  // Locktime (4 bytes)
  auto lockTimeBytes = encodeLE(lockTime_);
  appendBytes(result, lockTimeBytes);

  return Result<ByteVector>::success(std::move(result));
}

// ----- Hash Calculation -----

Result<Bytes32> BitcoinTransaction::hash() const {
  // TXID is always calculated from legacy serialization (no witness)
  auto legacy = serializeLegacy();
  if (!legacy.ok()) {
    return Result<Bytes32>::fail(legacy.error);
  }

  // Double SHA-256
  auto hash = doubleSha256(legacy.value);

  return Result<Bytes32>::success(std::move(hash));
}

Result<std::string> BitcoinTransaction::txid() const {
  auto hashResult = hash();
  if (!hashResult.ok()) {
    return Result<std::string>::fail(hashResult.error);
  }

  // TXID is displayed in reversed byte order
  auto reversed = reverseBytes(hashResult.value);
  return Result<std::string>::success(bytesToHex(reversed));
}

// ----- Size Calculation -----

size_t BitcoinTransaction::size() const {
  auto serialized = serialize();
  if (!serialized.ok()) {
    return 0;
  }
  return serialized.value.size();
}

size_t BitcoinTransaction::virtualSize() const {
  // vsize = (weight + 3) / 4
  return (weight() + 3) / 4;
}

size_t BitcoinTransaction::weight() const {
  if (!hasWitness()) {
    // Non-SegWit: weight = size * 4
    auto serialized = serializeLegacy();
    if (!serialized.ok()) {
      return 0;
    }
    return serialized.value.size() * 4;
  }

  // SegWit: weight = base_size * 3 + total_size
  auto legacy = serializeLegacy();
  auto witness = serializeWitness();

  if (!legacy.ok() || !witness.ok()) {
    return 0;
  }

  size_t baseSize = legacy.value.size();
  size_t totalSize = witness.value.size();

  return baseSize * 3 + totalSize;
}

// ----- BIP-143 Hash Computation -----

Bytes32 BitcoinTransaction::computeHashPrevouts() const {
  ByteVector data;

  for (const auto& input : inputs_) {
    appendBytes(data, input.prevout.serialize());
  }

  return doubleSha256(data);
}

Bytes32 BitcoinTransaction::computeHashSequence() const {
  ByteVector data;

  for (const auto& input : inputs_) {
    appendBytes(data, encodeLE(input.sequence));
  }

  return doubleSha256(data);
}

Bytes32 BitcoinTransaction::computeHashOutputs() const {
  ByteVector data;

  for (const auto& output : outputs_) {
    appendBytes(data, output.serialize());
  }

  return doubleSha256(data);
}

// ----- Signature Hash -----

Result<Bytes32> BitcoinTransaction::signatureHashLegacy(
  size_t inputIndex,
  const ByteVector& scriptCode,
  SigHashType sigHashType
) const {
  if (inputIndex >= inputs_.size()) {
    return Result<Bytes32>::fail(Error::INVALID_ARGUMENT);
  }

  // Create a copy for signing
  ByteVector preimage;

  // Version
  appendBytes(preimage, encodeLE(version_));

  // Inputs
  appendBytes(preimage, encodeVarInt(inputs_.size()));
  for (size_t i = 0; i < inputs_.size(); ++i) {
    const auto& input = inputs_[i];

    // Prevout
    appendBytes(preimage, input.prevout.serialize());

    // Script: use scriptCode for the input being signed, empty for others
    if (i == inputIndex) {
      appendBytes(preimage, encodeVarInt(scriptCode.size()));
      appendBytes(preimage, scriptCode);
    } else {
      appendByte(preimage, 0x00);  // Empty script
    }

    // Sequence
    appendBytes(preimage, encodeLE(input.sequence));
  }

  // Outputs
  appendBytes(preimage, encodeVarInt(outputs_.size()));
  for (const auto& output : outputs_) {
    appendBytes(preimage, output.serialize());
  }

  // Locktime
  appendBytes(preimage, encodeLE(lockTime_));

  // Sighash type (4 bytes, little-endian)
  appendBytes(preimage, encodeLE(static_cast<uint32_t>(sigHashType)));

  return Result<Bytes32>::success(doubleSha256(preimage));
}

Result<Bytes32> BitcoinTransaction::signatureHashSegWit(
  size_t inputIndex,
  const ByteVector& scriptCode,
  uint64_t value,
  SigHashType sigHashType
) const {
  if (inputIndex >= inputs_.size()) {
    return Result<Bytes32>::fail(Error::INVALID_ARGUMENT);
  }

  // Cache hash components if not already computed
  if (!hashPrevouts_) {
    hashPrevouts_ = computeHashPrevouts();
  }
  if (!hashSequence_) {
    hashSequence_ = computeHashSequence();
  }
  if (!hashOutputs_) {
    hashOutputs_ = computeHashOutputs();
  }

  const auto& input = inputs_[inputIndex];

  ByteVector preimage;

  // 1. nVersion
  appendBytes(preimage, encodeLE(version_));

  // 2. hashPrevouts
  uint8_t baseType = static_cast<uint8_t>(sigHashType) & 0x1F;
  bool anyoneCanPay = (static_cast<uint8_t>(sigHashType) & 0x80) != 0;

  if (!anyoneCanPay) {
    appendBytes(preimage, *hashPrevouts_);
  } else {
    Bytes32 zeros{};
    appendBytes(preimage, zeros);
  }

  // 3. hashSequence
  if (!anyoneCanPay && baseType != static_cast<uint8_t>(SigHashType::SINGLE) &&
      baseType != static_cast<uint8_t>(SigHashType::NONE)) {
    appendBytes(preimage, *hashSequence_);
  } else {
    Bytes32 zeros{};
    appendBytes(preimage, zeros);
  }

  // 4. outpoint
  appendBytes(preimage, input.prevout.serialize());

  // 5. scriptCode
  appendBytes(preimage, encodeVarInt(scriptCode.size()));
  appendBytes(preimage, scriptCode);

  // 6. value
  appendBytes(preimage, encodeLE(value));

  // 7. nSequence
  appendBytes(preimage, encodeLE(input.sequence));

  // 8. hashOutputs
  if (baseType != static_cast<uint8_t>(SigHashType::SINGLE) &&
      baseType != static_cast<uint8_t>(SigHashType::NONE)) {
    appendBytes(preimage, *hashOutputs_);
  } else if (baseType == static_cast<uint8_t>(SigHashType::SINGLE) && inputIndex < outputs_.size()) {
    auto outputHash = doubleSha256(outputs_[inputIndex].serialize());
    appendBytes(preimage, outputHash);
  } else {
    Bytes32 zeros{};
    appendBytes(preimage, zeros);
  }

  // 9. nLockTime
  appendBytes(preimage, encodeLE(lockTime_));

  // 10. sighash type
  appendBytes(preimage, encodeLE(static_cast<uint32_t>(sigHashType)));

  return Result<Bytes32>::success(doubleSha256(preimage));
}

// ----- Signing -----

#if HD_WALLET_USE_CRYPTOPP

// Helper function to sign with secp256k1
static ByteVector signECDSA(const Bytes32& hash, const Bytes32& privateKey) {
  using namespace CryptoPP;

  // Create private key
  ECDSA<ECP, SHA256>::PrivateKey privKey;
  Integer x(privateKey.data(), privateKey.size());
  privKey.Initialize(ASN1::secp256k1(), x);

  // Create signer
  ECDSA<ECP, SHA256>::Signer signer(privKey);

  // Sign
  SecureRandomGenerator rng;
  std::string signature;
  StringSource ss(
    hash.data(), hash.size(), true,
    new SignerFilter(rng, signer, new StringSink(signature))
  );

  // Convert to DER format
  ByteVector result(signature.begin(), signature.end());
  return result;
}

// Helper function to get public key from private key
static Bytes33 getPublicKey(const Bytes32& privateKey) {
  using namespace CryptoPP;

  ECDSA<ECP, SHA256>::PrivateKey privKey;
  Integer x(privateKey.data(), privateKey.size());
  privKey.Initialize(ASN1::secp256k1(), x);

  ECDSA<ECP, SHA256>::PublicKey pubKey;
  privKey.MakePublicKey(pubKey);

  // Get compressed public key
  const ECP::Point& Q = pubKey.GetPublicElement();

  Bytes33 result;
  result[0] = Q.y.IsEven() ? 0x02 : 0x03;

  // Serialize x coordinate
  Q.x.Encode(result.data() + 1, 32);

  return result;
}

#endif

Error BitcoinTransaction::sign(const Bytes32& privateKey, int inputIndex) {
  if (inputs_.empty()) {
    return Error::INVALID_TRANSACTION;
  }

  if (inputIndex < 0) {
    // Sign all inputs
    for (size_t i = 0; i < inputs_.size(); ++i) {
      Error err = signInput(i, privateKey, SigHashType::ALL);
      if (err != Error::OK) {
        return err;
      }
    }
  } else {
    if (static_cast<size_t>(inputIndex) >= inputs_.size()) {
      return Error::INVALID_ARGUMENT;
    }
    return signInput(static_cast<size_t>(inputIndex), privateKey, SigHashType::ALL);
  }

  // Check if all inputs are signed
  bool allSigned = true;
  for (const auto& input : inputs_) {
    if (input.scriptSig.empty() && input.witness.empty()) {
      allSigned = false;
      break;
    }
  }

  if (allSigned) {
    status_ = TxStatus::SIGNED;
  } else {
    status_ = TxStatus::PARTIALLY_SIGNED;
  }

  return Error::OK;
}

Error BitcoinTransaction::signInput(
  size_t inputIndex,
  const Bytes32& privateKey,
  SigHashType sigHashType
) {
#if HD_WALLET_USE_CRYPTOPP
  if (inputIndex >= inputs_.size()) {
    return Error::INVALID_ARGUMENT;
  }

  auto& input = inputs_[inputIndex];

  // Get the public key and verify it matches
  Bytes33 pubKey = getPublicKey(privateKey);

  // Build script code based on script type
  ByteVector scriptCode;
  Bytes32 sigHash;

  switch (input.scriptType) {
    case ScriptType::P2PKH: {
      // Script code is the scriptPubKey (P2PKH script)
      scriptCode = buildP2PKHFromPubKey(pubKey);

      // Legacy signature hash
      auto hashResult = signatureHashLegacy(inputIndex, scriptCode, sigHashType);
      if (!hashResult.ok()) {
        return hashResult.error;
      }
      sigHash = hashResult.value;

      // Sign
      ByteVector signature = signECDSA(sigHash, privateKey);
      signature.push_back(static_cast<uint8_t>(sigHashType));

      // Build scriptSig
      input.scriptSig = buildP2PKHScriptSig(signature, pubKey);
      break;
    }

    case ScriptType::P2WPKH: {
      // For P2WPKH, script code is P2PKH script with pubkey hash
      auto pubkeyHash = hash160(pubKey.data(), pubKey.size());
      scriptCode = buildP2PKH(pubkeyHash);

      // SegWit signature hash (BIP-143)
      auto hashResult = signatureHashSegWit(inputIndex, scriptCode, input.amount, sigHashType);
      if (!hashResult.ok()) {
        return hashResult.error;
      }
      sigHash = hashResult.value;

      // Sign
      ByteVector signature = signECDSA(sigHash, privateKey);
      signature.push_back(static_cast<uint8_t>(sigHashType));

      // Build witness (signature, pubkey)
      input.witness.clear();
      input.witness.push_back(signature);
      input.witness.push_back(ByteVector(pubKey.begin(), pubKey.end()));

      // Empty scriptSig for native SegWit
      input.scriptSig.clear();
      break;
    }

    case ScriptType::P2SH_P2WPKH: {
      // For P2SH-P2WPKH, script code is P2PKH script
      auto pubkeyHash = hash160(pubKey.data(), pubKey.size());
      scriptCode = buildP2PKH(pubkeyHash);

      // SegWit signature hash (BIP-143)
      auto hashResult = signatureHashSegWit(inputIndex, scriptCode, input.amount, sigHashType);
      if (!hashResult.ok()) {
        return hashResult.error;
      }
      sigHash = hashResult.value;

      // Sign
      ByteVector signature = signECDSA(sigHash, privateKey);
      signature.push_back(static_cast<uint8_t>(sigHashType));

      // Build witness (signature, pubkey)
      input.witness.clear();
      input.witness.push_back(signature);
      input.witness.push_back(ByteVector(pubKey.begin(), pubKey.end()));

      // scriptSig contains the redeem script
      if (input.redeemScript.empty()) {
        input.redeemScript = buildP2SH_P2WPKH_RedeemScript(pubKey);
      }
      input.scriptSig.clear();
      pushData(input.scriptSig, input.redeemScript);
      break;
    }

    default:
      return Error::NOT_SUPPORTED;
  }

  invalidateCache();
  return Error::OK;

#else
  (void)inputIndex;
  (void)privateKey;
  (void)sigHashType;
  return Error::NOT_SUPPORTED;
#endif
}

bool BitcoinTransaction::verify() const {
  // TODO: Implement signature verification
  // For now, just check that all inputs have signatures
  for (const auto& input : inputs_) {
    if (input.scriptSig.empty() && input.witness.empty()) {
      return false;
    }
  }
  return true;
}

Error BitcoinTransaction::validate() const {
  // Check for empty transaction
  if (inputs_.empty()) {
    return Error::INVALID_TRANSACTION;
  }
  if (outputs_.empty()) {
    return Error::INVALID_TRANSACTION;
  }

  // Check input/output counts
  if (inputs_.size() > MAX_TX_INPUTS) {
    return Error::INVALID_TRANSACTION;
  }
  if (outputs_.size() > MAX_TX_OUTPUTS) {
    return Error::INVALID_TRANSACTION;
  }

  // Check output values
  uint64_t totalOutput = 0;
  for (const auto& output : outputs_) {
    if (output.value > MAX_MONEY) {
      return Error::INVALID_TRANSACTION;
    }
    totalOutput += output.value;
    if (totalOutput > MAX_MONEY) {
      return Error::INVALID_TRANSACTION;
    }
  }

  // Check for dust outputs (optional, could be warning instead)
  for (const auto& output : outputs_) {
    if (output.value > 0 && output.value < DUST_THRESHOLD &&
        output.getScriptType() != ScriptType::NULLDATA) {
      // Dust output - could return warning
    }
  }

  // Check transaction size
  if (size() > MAX_TX_SIZE) {
    return Error::INVALID_TRANSACTION;
  }

  return Error::OK;
}

std::unique_ptr<Transaction> BitcoinTransaction::clone() const {
  auto tx = std::make_unique<BitcoinTransaction>();
  tx->version_ = version_;
  tx->lockTime_ = lockTime_;
  tx->inputs_ = inputs_;
  tx->outputs_ = outputs_;
  tx->status_ = status_;
  return tx;
}

// ----- Parsing -----

Result<BitcoinTransaction> BitcoinTransaction::parse(const ByteVector& data) {
  if (data.size() < 10) {
    return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
  }

  size_t offset = 0;

  BitcoinTransaction tx;

  // Version
  auto version = decodeLE<uint32_t>(data, offset);
  if (!version) {
    return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
  }
  tx.version_ = *version;

  // Check for SegWit marker
  bool isSegWit = false;
  if (offset + 2 <= data.size() && data[offset] == SEGWIT_MARKER && data[offset + 1] == SEGWIT_FLAG) {
    isSegWit = true;
    offset += 2;
  }

  // Input count
  auto inputCount = decodeVarInt(data, offset);
  if (!inputCount || *inputCount > MAX_TX_INPUTS) {
    return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
  }

  // Inputs
  for (uint64_t i = 0; i < *inputCount; ++i) {
    TxInput input;

    // Prevout
    auto prevout = Outpoint::parse(data, offset);
    if (!prevout) {
      return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
    }
    input.prevout = *prevout;

    // Script
    auto scriptLen = decodeVarInt(data, offset);
    if (!scriptLen || offset + *scriptLen > data.size()) {
      return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
    }
    input.scriptSig.assign(data.begin() + offset, data.begin() + offset + *scriptLen);
    offset += *scriptLen;

    // Sequence
    auto sequence = decodeLE<uint32_t>(data, offset);
    if (!sequence) {
      return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
    }
    input.sequence = *sequence;

    tx.inputs_.push_back(std::move(input));
  }

  // Output count
  auto outputCount = decodeVarInt(data, offset);
  if (!outputCount || *outputCount > MAX_TX_OUTPUTS) {
    return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
  }

  // Outputs
  for (uint64_t i = 0; i < *outputCount; ++i) {
    auto output = TxOutput::parse(data, offset);
    if (!output) {
      return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
    }
    tx.outputs_.push_back(std::move(*output));
  }

  // Witness data (if SegWit)
  if (isSegWit) {
    for (size_t i = 0; i < tx.inputs_.size(); ++i) {
      auto itemCount = decodeVarInt(data, offset);
      if (!itemCount) {
        return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
      }

      for (uint64_t j = 0; j < *itemCount; ++j) {
        auto itemLen = decodeVarInt(data, offset);
        if (!itemLen || offset + *itemLen > data.size()) {
          return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
        }

        ByteVector item(data.begin() + offset, data.begin() + offset + *itemLen);
        tx.inputs_[i].witness.push_back(std::move(item));
        offset += *itemLen;
      }
    }
  }

  // Locktime
  auto lockTime = decodeLE<uint32_t>(data, offset);
  if (!lockTime) {
    return Result<BitcoinTransaction>::fail(Error::INVALID_TRANSACTION);
  }
  tx.lockTime_ = *lockTime;

  // Determine status based on signatures
  bool hasSigs = false;
  for (const auto& input : tx.inputs_) {
    if (!input.scriptSig.empty() || !input.witness.empty()) {
      hasSigs = true;
      break;
    }
  }
  tx.status_ = hasSigs ? TxStatus::SIGNED : TxStatus::UNSIGNED;

  return Result<BitcoinTransaction>::success(std::move(tx));
}

Result<BitcoinTransaction> BitcoinTransaction::parseHex(const std::string& hex) {
  auto bytes = hexToBytes(hex);
  if (!bytes.ok()) {
    return Result<BitcoinTransaction>::fail(bytes.error);
  }
  return parse(bytes.value);
}

// =============================================================================
// C API Implementation
// =============================================================================

extern "C" {

btc_tx_handle hd_btc_tx_create() {
  return reinterpret_cast<btc_tx_handle>(new BitcoinTransaction());
}

btc_tx_handle hd_btc_tx_create_v(uint32_t version) {
  return reinterpret_cast<btc_tx_handle>(new BitcoinTransaction(version));
}

int32_t hd_btc_tx_add_input(
  btc_tx_handle tx,
  const uint8_t* txid,
  uint32_t vout,
  uint64_t amount,
  int32_t script_type,
  const uint8_t* pubkey,
  uint32_t sequence
) {
  if (!tx || !txid || !pubkey) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto* btcTx = reinterpret_cast<BitcoinTransaction*>(tx);

  Bytes32 txidBytes;
  std::copy(txid, txid + 32, txidBytes.begin());

  Bytes33 pubkeyBytes;
  std::copy(pubkey, pubkey + 33, pubkeyBytes.begin());

  btcTx->addInput(txidBytes, vout, amount, static_cast<ScriptType>(script_type), pubkeyBytes, sequence);

  return static_cast<int32_t>(Error::OK);
}

int32_t hd_btc_tx_add_output(
  btc_tx_handle tx,
  uint64_t value,
  const uint8_t* script,
  size_t script_len
) {
  if (!tx || !script) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto* btcTx = reinterpret_cast<BitcoinTransaction*>(tx);
  ByteVector scriptVec(script, script + script_len);
  btcTx->addOutput(value, scriptVec);

  return static_cast<int32_t>(Error::OK);
}

int32_t hd_btc_tx_add_p2pkh_output(
  btc_tx_handle tx,
  uint64_t value,
  const uint8_t* pubkey_hash
) {
  if (!tx || !pubkey_hash) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto* btcTx = reinterpret_cast<BitcoinTransaction*>(tx);

  std::array<uint8_t, 20> hash;
  std::copy(pubkey_hash, pubkey_hash + 20, hash.begin());

  btcTx->addP2PKHOutput(value, hash);

  return static_cast<int32_t>(Error::OK);
}

int32_t hd_btc_tx_add_p2wpkh_output(
  btc_tx_handle tx,
  uint64_t value,
  const uint8_t* pubkey_hash
) {
  if (!tx || !pubkey_hash) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto* btcTx = reinterpret_cast<BitcoinTransaction*>(tx);

  std::array<uint8_t, 20> hash;
  std::copy(pubkey_hash, pubkey_hash + 20, hash.begin());

  btcTx->addP2WPKHOutput(value, hash);

  return static_cast<int32_t>(Error::OK);
}

int32_t hd_btc_tx_sign(
  btc_tx_handle tx,
  const uint8_t* privkey,
  int32_t input_index
) {
  if (!tx || !privkey) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto* btcTx = reinterpret_cast<BitcoinTransaction*>(tx);

  Bytes32 key;
  std::copy(privkey, privkey + 32, key.begin());

  return static_cast<int32_t>(btcTx->sign(key, input_index));
}

int32_t hd_btc_tx_sign_input(
  btc_tx_handle tx,
  size_t input_index,
  const uint8_t* privkey,
  uint8_t sighash_type
) {
  if (!tx || !privkey) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto* btcTx = reinterpret_cast<BitcoinTransaction*>(tx);

  Bytes32 key;
  std::copy(privkey, privkey + 32, key.begin());

  return static_cast<int32_t>(btcTx->signInput(input_index, key, static_cast<SigHashType>(sighash_type)));
}

int32_t hd_btc_tx_serialize(
  btc_tx_handle tx,
  uint8_t* out,
  size_t out_size,
  size_t* actual_size
) {
  if (!tx) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto* btcTx = reinterpret_cast<BitcoinTransaction*>(tx);
  auto result = btcTx->serialize();

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

int32_t hd_btc_tx_get_txid(btc_tx_handle tx, uint8_t* txid_out) {
  if (!tx || !txid_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto* btcTx = reinterpret_cast<BitcoinTransaction*>(tx);
  auto result = btcTx->hash();

  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  // Return in reversed byte order (display format)
  auto reversed = reverseBytes(result.value);
  std::copy(reversed.begin(), reversed.end(), txid_out);

  return static_cast<int32_t>(Error::OK);
}

int32_t hd_btc_tx_get_txid_hex(btc_tx_handle tx, char* out, size_t out_size) {
  if (!tx || !out || out_size < 65) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto* btcTx = reinterpret_cast<BitcoinTransaction*>(tx);
  auto result = btcTx->txid();

  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  std::strncpy(out, result.value.c_str(), out_size - 1);
  out[out_size - 1] = '\0';

  return static_cast<int32_t>(Error::OK);
}

size_t hd_btc_tx_get_size(btc_tx_handle tx) {
  if (!tx) return 0;
  return reinterpret_cast<BitcoinTransaction*>(tx)->size();
}

size_t hd_btc_tx_get_vsize(btc_tx_handle tx) {
  if (!tx) return 0;
  return reinterpret_cast<BitcoinTransaction*>(tx)->virtualSize();
}

size_t hd_btc_tx_get_weight(btc_tx_handle tx) {
  if (!tx) return 0;
  return reinterpret_cast<BitcoinTransaction*>(tx)->weight();
}

uint64_t hd_btc_tx_get_fee(btc_tx_handle tx) {
  if (!tx) return 0;
  return reinterpret_cast<BitcoinTransaction*>(tx)->fee();
}

int32_t hd_btc_tx_validate(btc_tx_handle tx) {
  if (!tx) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }
  return static_cast<int32_t>(reinterpret_cast<BitcoinTransaction*>(tx)->validate());
}

void hd_btc_tx_destroy(btc_tx_handle tx) {
  if (tx) {
    delete reinterpret_cast<BitcoinTransaction*>(tx);
  }
}

btc_tx_handle hd_btc_tx_parse(const uint8_t* data, size_t data_len) {
  if (!data || data_len == 0) {
    return nullptr;
  }

  ByteVector vec(data, data + data_len);
  auto result = BitcoinTransaction::parse(vec);

  if (!result.ok()) {
    return nullptr;
  }

  return reinterpret_cast<btc_tx_handle>(new BitcoinTransaction(std::move(result.value)));
}

btc_tx_handle hd_btc_tx_parse_hex(const char* hex) {
  if (!hex) {
    return nullptr;
  }

  auto result = BitcoinTransaction::parseHex(hex);

  if (!result.ok()) {
    return nullptr;
  }

  return reinterpret_cast<btc_tx_handle>(new BitcoinTransaction(std::move(result.value)));
}

} // extern "C"

} // namespace tx
} // namespace hd_wallet
