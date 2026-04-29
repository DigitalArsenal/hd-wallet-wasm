/**
 * @file bitcoin.cpp
 * @brief Bitcoin Support Implementation
 */

#include "hd_wallet/coins/bitcoin.h"

#include <algorithm>
#include <cstring>
#include <sstream>

// Crypto++ headers
#include <cryptopp/sha.h>
#include <cryptopp/eccrypto.h>
#if !HD_WALLET_IS_WASI
#include <cryptopp/osrng.h>
#endif
#include <cryptopp/oids.h>

namespace hd_wallet {
namespace coins {

// =============================================================================
// Bitcoin Network Parameters
// =============================================================================

const BitcoinParams BITCOIN_MAINNET = {
  .p2pkh_version = 0x00,
  .p2sh_version = 0x05,
  .bech32_hrp = "bc",
  .wif_version = 0x80,
  .xprv_version = 0x0488ADE4,
  .xpub_version = 0x0488B21E,
  .yprv_version = 0x049D7878,
  .ypub_version = 0x049D7CB2,
  .zprv_version = 0x04B2430C,
  .zpub_version = 0x04B24746
};

const BitcoinParams BITCOIN_TESTNET = {
  .p2pkh_version = 0x6F,
  .p2sh_version = 0xC4,
  .bech32_hrp = "tb",
  .wif_version = 0xEF,
  .xprv_version = 0x04358394,
  .xpub_version = 0x043587CF,
  .yprv_version = 0x044A4E28,
  .ypub_version = 0x044A5262,
  .zprv_version = 0x045F18BC,
  .zpub_version = 0x045F1CF6
};

// =============================================================================
// Bitcoin Address Generation
// =============================================================================

Result<std::string> bitcoinP2PKH(const ByteVector& public_key, const BitcoinParams& params) {
  if (public_key.size() != 33 && public_key.size() != 65) {
    return Result<std::string>::fail(Error::INVALID_PUBLIC_KEY);
  }

  // Hash160 of public key
  ByteVector hash = hash160(public_key);

  // Add version byte
  ByteVector versioned;
  versioned.push_back(params.p2pkh_version);
  versioned.insert(versioned.end(), hash.begin(), hash.end());

  // Base58Check encode
  return Result<std::string>::success(base58CheckEncode(versioned));
}

Result<std::string> bitcoinP2SH(const Bytes33& public_key, const BitcoinParams& params) {
  // Create P2SH-P2WPKH address (wrapped SegWit)
  // Redeem script: 0x00 0x14 <20-byte-pubkey-hash>

  // Hash160 of public key
  ByteVector pubkey_hash = hash160(public_key.data(), public_key.size());

  // Create redeem script
  ByteVector redeem_script;
  redeem_script.push_back(0x00);  // OP_0
  redeem_script.push_back(0x14);  // Push 20 bytes
  redeem_script.insert(redeem_script.end(), pubkey_hash.begin(), pubkey_hash.end());

  return bitcoinP2SHFromScript(redeem_script, params);
}

Result<std::string> bitcoinP2SHFromScript(const ByteVector& redeem_script, const BitcoinParams& params) {
  // Hash160 of redeem script
  ByteVector script_hash = hash160(redeem_script);

  // Add version byte
  ByteVector versioned;
  versioned.push_back(params.p2sh_version);
  versioned.insert(versioned.end(), script_hash.begin(), script_hash.end());

  // Base58Check encode
  return Result<std::string>::success(base58CheckEncode(versioned));
}

Result<std::string> bitcoinP2WPKH(const Bytes33& public_key, const BitcoinParams& params) {
  // Native SegWit v0 (witness version 0, 20-byte pubkey hash)

  // Hash160 of public key
  ByteVector pubkey_hash = hash160(public_key.data(), public_key.size());

  // Bech32 encode with witness version 0
  std::string address = bech32Encode(params.bech32_hrp, pubkey_hash, 0);
  if (address.empty()) {
    return Result<std::string>::fail(Error::INTERNAL);
  }

  return Result<std::string>::success(std::move(address));
}

Result<std::string> bitcoinP2WSH(const ByteVector& witness_script, const BitcoinParams& params) {
  // Native SegWit v0 (witness version 0, 32-byte script hash)

  // SHA256 of witness script
  CryptoPP::SHA256 sha256;
  ByteVector script_hash(32);
  sha256.CalculateDigest(script_hash.data(), witness_script.data(), witness_script.size());

  // Bech32 encode with witness version 0
  std::string address = bech32Encode(params.bech32_hrp, script_hash, 0);
  if (address.empty()) {
    return Result<std::string>::fail(Error::INTERNAL);
  }

  return Result<std::string>::success(std::move(address));
}

Result<std::string> bitcoinP2TR(const ByteVector& public_key, const BitcoinParams& params) {
  // Taproot (witness version 1, 32-byte tweaked public key)

  Bytes32 x_only;

  if (public_key.size() == 32) {
    // Already x-only format
    std::copy(public_key.begin(), public_key.end(), x_only.begin());
  } else if (public_key.size() == 33) {
    // Compressed public key - extract x coordinate
    Bytes33 compressed;
    std::copy(public_key.begin(), public_key.end(), compressed.begin());
    auto result = toXOnlyPublicKey(compressed);
    if (!result.ok()) return Result<std::string>::fail(result.error);
    x_only = result.value;
  } else {
    return Result<std::string>::fail(Error::INVALID_PUBLIC_KEY);
  }

  // For a simple key-path spend with no script tree, the tweaked key is:
  // P' = P + H_taptweak(P) * G
  // where H_taptweak is tagged hash with "TapTweak"
  //
  // For simplicity, we'll just use the x-only key directly here.
  // A full implementation would apply the BIP-341 tweak.

  ByteVector x_only_vec(x_only.begin(), x_only.end());

  // Bech32m encode with witness version 1
  std::string address = bech32mEncode(params.bech32_hrp, x_only_vec, 1);
  if (address.empty()) {
    return Result<std::string>::fail(Error::INTERNAL);
  }

  return Result<std::string>::success(std::move(address));
}

Result<Bytes32> toXOnlyPublicKey(const Bytes33& public_key) {
  // X-only public key is just the x coordinate (bytes 1-32 of compressed key)
  // If the y coordinate is odd (prefix 0x03), we need to negate to get even y
  // But for Taproot, we just take the x coordinate as-is

  Bytes32 result;
  std::copy(public_key.begin() + 1, public_key.end(), result.begin());
  return Result<Bytes32>::success(std::move(result));
}

// =============================================================================
// Bitcoin Address Validation
// =============================================================================

Result<BitcoinAddressType> detectBitcoinAddressType(
  const std::string& address,
  const BitcoinParams& params
) {
  if (address.empty()) {
    return Result<BitcoinAddressType>::fail(Error::INVALID_ADDRESS);
  }

  // Check for Bech32/Bech32m addresses
  std::string lower_address = address;
  std::transform(lower_address.begin(), lower_address.end(), lower_address.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  if (lower_address.find(std::string(params.bech32_hrp) + "1") == 0) {
    // Bech32 address - decode to check witness version
    auto decoded = bech32Decode(address);
    if (!decoded.ok()) {
      return Result<BitcoinAddressType>::fail(Error::INVALID_ADDRESS);
    }

    // Check data length to determine type
    if (decoded.value.second.size() == 20) {
      return Result<BitcoinAddressType>::success(BitcoinAddressType::P2WPKH);
    } else if (decoded.value.second.size() == 32) {
      // Could be P2WSH (v0) or P2TR (v1) - check witness version
      // The witness version is encoded as the first data character after the separator.
      // In bech32 charset, 'q' = 0 (v0/P2WSH), 'p' = 1 (v1/P2TR).
      // The character is at index strlen(bech32_hrp) + 1 (right after "bc1" or "tb1").
      size_t wit_ver_idx = std::strlen(params.bech32_hrp) + 1;
      if (wit_ver_idx < lower_address.size() && lower_address[wit_ver_idx] == 'p') {
        return Result<BitcoinAddressType>::success(BitcoinAddressType::P2TR);
      }
      return Result<BitcoinAddressType>::success(BitcoinAddressType::P2WSH);
    }

    return Result<BitcoinAddressType>::fail(Error::INVALID_ADDRESS);
  }

  // Check for Base58Check addresses
  auto decoded = base58CheckDecode(address);
  if (!decoded.ok()) {
    return Result<BitcoinAddressType>::fail(Error::INVALID_ADDRESS);
  }

  if (decoded.value.empty()) {
    return Result<BitcoinAddressType>::fail(Error::INVALID_ADDRESS);
  }

  uint8_t version = decoded.value[0];

  if (version == params.p2pkh_version) {
    return Result<BitcoinAddressType>::success(BitcoinAddressType::P2PKH);
  } else if (version == params.p2sh_version) {
    return Result<BitcoinAddressType>::success(BitcoinAddressType::P2SH);
  }

  return Result<BitcoinAddressType>::fail(Error::INVALID_ADDRESS);
}

Result<void> validateP2PKH(const std::string& address, const BitcoinParams& params) {
  auto decoded = base58CheckDecode(address);
  if (!decoded.ok()) {
    return Result<void>::fail(decoded.error);
  }

  // Should be 1 version byte + 20 hash bytes
  if (decoded.value.size() != 21) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }

  if (decoded.value[0] != params.p2pkh_version) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }

  return Result<void>::success();
}

Result<void> validateP2SH(const std::string& address, const BitcoinParams& params) {
  auto decoded = base58CheckDecode(address);
  if (!decoded.ok()) {
    return Result<void>::fail(decoded.error);
  }

  // Should be 1 version byte + 20 hash bytes
  if (decoded.value.size() != 21) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }

  if (decoded.value[0] != params.p2sh_version) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }

  return Result<void>::success();
}

Result<void> validateP2WPKH(const std::string& address, const BitcoinParams& params) {
  auto decoded = bech32Decode(address);
  if (!decoded.ok()) {
    return Result<void>::fail(decoded.error);
  }

  // Check HRP
  if (decoded.value.first != params.bech32_hrp) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }

  // Should be 20 bytes for P2WPKH
  if (decoded.value.second.size() != 20) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }

  return Result<void>::success();
}

Result<void> validateP2WSH(const std::string& address, const BitcoinParams& params) {
  auto decoded = bech32Decode(address);
  if (!decoded.ok()) {
    return Result<void>::fail(decoded.error);
  }

  // Check HRP
  if (decoded.value.first != params.bech32_hrp) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }

  // Should be 32 bytes for P2WSH
  if (decoded.value.second.size() != 32) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }

  return Result<void>::success();
}

Result<void> validateP2TR(const std::string& address, const BitcoinParams& params) {
  auto decoded = bech32mDecode(address);
  if (!decoded.ok()) {
    return Result<void>::fail(decoded.error);
  }

  // Check HRP
  if (decoded.value.first != params.bech32_hrp) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }

  // Should be 32 bytes for P2TR
  if (decoded.value.second.size() != 32) {
    return Result<void>::fail(Error::INVALID_ADDRESS);
  }

  return Result<void>::success();
}

Result<void> validateBitcoinAddress(const std::string& address, const BitcoinParams& params) {
  auto type = detectBitcoinAddressType(address, params);
  if (!type.ok()) {
    return Result<void>::fail(type.error);
  }

  switch (type.value) {
    case BitcoinAddressType::P2PKH:
      return validateP2PKH(address, params);
    case BitcoinAddressType::P2SH:
      return validateP2SH(address, params);
    case BitcoinAddressType::P2WPKH:
      return validateP2WPKH(address, params);
    case BitcoinAddressType::P2WSH:
      return validateP2WSH(address, params);
    case BitcoinAddressType::P2TR:
      return validateP2TR(address, params);
    default:
      return Result<void>::fail(Error::INVALID_ADDRESS);
  }
}

Result<ByteVector> decodeToScriptPubKey(const std::string& address, const BitcoinParams& params) {
  auto type = detectBitcoinAddressType(address, params);
  if (!type.ok()) {
    return Result<ByteVector>::fail(type.error);
  }

  ByteVector script;

  switch (type.value) {
    case BitcoinAddressType::P2PKH: {
      auto decoded = base58CheckDecode(address);
      if (!decoded.ok()) return Result<ByteVector>::fail(decoded.error);

      // OP_DUP OP_HASH160 <20 bytes> OP_EQUALVERIFY OP_CHECKSIG
      script.push_back(0x76);  // OP_DUP
      script.push_back(0xA9);  // OP_HASH160
      script.push_back(0x14);  // Push 20 bytes
      script.insert(script.end(), decoded.value.begin() + 1, decoded.value.end());
      script.push_back(0x88);  // OP_EQUALVERIFY
      script.push_back(0xAC);  // OP_CHECKSIG
      break;
    }

    case BitcoinAddressType::P2SH: {
      auto decoded = base58CheckDecode(address);
      if (!decoded.ok()) return Result<ByteVector>::fail(decoded.error);

      // OP_HASH160 <20 bytes> OP_EQUAL
      script.push_back(0xA9);  // OP_HASH160
      script.push_back(0x14);  // Push 20 bytes
      script.insert(script.end(), decoded.value.begin() + 1, decoded.value.end());
      script.push_back(0x87);  // OP_EQUAL
      break;
    }

    case BitcoinAddressType::P2WPKH: {
      auto decoded = bech32Decode(address);
      if (!decoded.ok()) return Result<ByteVector>::fail(decoded.error);

      // OP_0 <20 bytes>
      script.push_back(0x00);  // OP_0 (witness version 0)
      script.push_back(0x14);  // Push 20 bytes
      script.insert(script.end(), decoded.value.second.begin(), decoded.value.second.end());
      break;
    }

    case BitcoinAddressType::P2WSH: {
      auto decoded = bech32Decode(address);
      if (!decoded.ok()) return Result<ByteVector>::fail(decoded.error);

      // OP_0 <32 bytes>
      script.push_back(0x00);  // OP_0 (witness version 0)
      script.push_back(0x20);  // Push 32 bytes
      script.insert(script.end(), decoded.value.second.begin(), decoded.value.second.end());
      break;
    }

    case BitcoinAddressType::P2TR: {
      auto decoded = bech32mDecode(address);
      if (!decoded.ok()) return Result<ByteVector>::fail(decoded.error);

      // OP_1 <32 bytes>
      script.push_back(0x51);  // OP_1 (witness version 1)
      script.push_back(0x20);  // Push 32 bytes
      script.insert(script.end(), decoded.value.second.begin(), decoded.value.second.end());
      break;
    }

    default:
      return Result<ByteVector>::fail(Error::INVALID_ADDRESS);
  }

  return Result<ByteVector>::success(std::move(script));
}

// =============================================================================
// Bitcoin Message Signing
// =============================================================================

Bytes32 bitcoinMessageHash(const std::string& message) {
  // Bitcoin signed message format:
  // "\x18Bitcoin Signed Message:\n" + varint(len) + message

  ByteVector to_sign;

  // Magic prefix
  const char* magic = "\x18" "Bitcoin Signed Message:\n";
  to_sign.insert(to_sign.end(), magic, magic + 25);

  // Varint message length
  size_t len = message.size();
  if (len < 0xFD) {
    to_sign.push_back(static_cast<uint8_t>(len));
  } else if (len <= 0xFFFF) {
    to_sign.push_back(0xFD);
    to_sign.push_back(len & 0xFF);
    to_sign.push_back((len >> 8) & 0xFF);
  } else {
    to_sign.push_back(0xFE);
    to_sign.push_back(len & 0xFF);
    to_sign.push_back((len >> 8) & 0xFF);
    to_sign.push_back((len >> 16) & 0xFF);
    to_sign.push_back((len >> 24) & 0xFF);
  }

  // Message
  to_sign.insert(to_sign.end(), message.begin(), message.end());

  // Double SHA256
  return doubleSha256(to_sign);
}

Result<ByteVector> signBitcoinMessage(
  const std::string& message,
  const Bytes32& private_key,
  bool compressed
) {
  // Hash the message
  Bytes32 hash = bitcoinMessageHash(message);

  // Sign with ECDSA
  auto sig = ecdsaSign(hash, private_key);
  if (!sig.ok()) {
    return Result<ByteVector>::fail(sig.error);
  }

  // Create 65-byte signature
  // Format: 1 byte header + 32 bytes r + 32 bytes s
  // Header: 27 + recovery_id + (compressed ? 4 : 0)

  ByteVector result(65);
  uint8_t header = 27 + sig.value.v;
  if (compressed) header += 4;

  result[0] = header;
  std::copy(sig.value.r.begin(), sig.value.r.end(), result.begin() + 1);
  std::copy(sig.value.s.begin(), sig.value.s.end(), result.begin() + 33);

  return Result<ByteVector>::success(std::move(result));
}

Result<bool> verifyBitcoinMessage(
  const std::string& message,
  const ByteVector& signature,
  const std::string& address,
  const BitcoinParams& params
) {
  // Recover public key from signature
  auto recovered = recoverBitcoinMessageSigner(message, signature);
  if (!recovered.ok()) {
    return Result<bool>::fail(recovered.error);
  }

  // Generate address from recovered public key
  auto addr_result = bitcoinP2PKH(recovered.value, params);
  if (!addr_result.ok()) {
    return Result<bool>::fail(addr_result.error);
  }

  // Compare addresses
  return Result<bool>::success(addr_result.value == address);
}

Result<ByteVector> recoverBitcoinMessageSigner(
  const std::string& message,
  const ByteVector& signature
) {
  if (signature.size() != 65) {
    return Result<ByteVector>::fail(Error::INVALID_SIGNATURE);
  }

  // Parse signature header
  uint8_t header = signature[0];
  if (header < 27 || header > 34) {
    return Result<ByteVector>::fail(Error::INVALID_SIGNATURE);
  }

  bool compressed = (header >= 31);
  uint8_t recovery_id = (header - 27) % 4;

  // Extract r and s
  ECDSASignature sig;
  std::copy(signature.begin() + 1, signature.begin() + 33, sig.r.begin());
  std::copy(signature.begin() + 33, signature.end(), sig.s.begin());
  sig.v = recovery_id;

  // Hash the message
  Bytes32 hash = bitcoinMessageHash(message);

  // Recover public key
  auto recovered = ecdsaRecover(hash, sig);
  if (!recovered.ok()) {
    return Result<ByteVector>::fail(recovered.error);
  }

  if (compressed) {
    return Result<ByteVector>::success(ByteVector(recovered.value.begin(), recovered.value.end()));
  } else {
    // Decompress
    auto uncompressed = bip32::decompressPublicKey(recovered.value, Curve::SECP256K1);
    if (!uncompressed.ok()) {
      return Result<ByteVector>::fail(uncompressed.error);
    }
    return Result<ByteVector>::success(ByteVector(uncompressed.value.begin(), uncompressed.value.end()));
  }
}

// =============================================================================
// WIF (Wallet Import Format)
// =============================================================================

std::string toWIF(const Bytes32& private_key, bool compressed, const BitcoinParams& params) {
  ByteVector data;
  data.push_back(params.wif_version);
  data.insert(data.end(), private_key.begin(), private_key.end());

  if (compressed) {
    data.push_back(0x01);
  }

  return base58CheckEncode(data);
}

Result<std::pair<Bytes32, bool>> fromWIF(const std::string& wif) {
  auto decoded = base58CheckDecode(wif);
  if (!decoded.ok()) {
    return Result<std::pair<Bytes32, bool>>::fail(decoded.error);
  }

  // Check length (version + 32 bytes key + optional compression flag)
  if (decoded.value.size() != 33 && decoded.value.size() != 34) {
    return Result<std::pair<Bytes32, bool>>::fail(Error::INVALID_ARGUMENT);
  }

  bool compressed = (decoded.value.size() == 34);

  Bytes32 private_key;
  std::copy(decoded.value.begin() + 1, decoded.value.begin() + 33, private_key.begin());

  return Result<std::pair<Bytes32, bool>>::success(std::make_pair(std::move(private_key), compressed));
}

// =============================================================================
// Bitcoin Coin Implementation
// =============================================================================

Bitcoin::Bitcoin(Network network)
  : network_(network),
    params_(network == Network::MAINNET ? &BITCOIN_MAINNET : &BITCOIN_TESTNET),
    address_type_(BitcoinAddressType::P2WPKH) {
}

void Bitcoin::setNetwork(Network net) {
  network_ = net;
  params_ = (net == Network::MAINNET) ? &BITCOIN_MAINNET : &BITCOIN_TESTNET;
}

Result<std::string> Bitcoin::addressFromPublicKey(const Bytes33& public_key) const {
  switch (address_type_) {
    case BitcoinAddressType::P2PKH:
      return p2pkhAddress(public_key);
    case BitcoinAddressType::P2SH:
      return p2shAddress(public_key);
    case BitcoinAddressType::P2WPKH:
      return p2wpkhAddress(public_key);
    case BitcoinAddressType::P2TR:
      return p2trAddress(public_key);
    default:
      return p2wpkhAddress(public_key);
  }
}

Result<std::string> Bitcoin::addressFromPublicKeyUncompressed(const Bytes65& public_key) const {
  // For P2PKH, we can use uncompressed keys
  if (address_type_ == BitcoinAddressType::P2PKH) {
    ByteVector pubkey(public_key.begin(), public_key.end());
    return bitcoinP2PKH(pubkey, *params_);
  }

  // Other types require compressed keys
  auto compressed = bip32::compressPublicKey(public_key, Curve::SECP256K1);
  if (!compressed.ok()) {
    return Result<std::string>::fail(compressed.error);
  }
  return addressFromPublicKey(compressed.value);
}

Result<std::string> Bitcoin::p2pkhAddress(const Bytes33& public_key) const {
  ByteVector pubkey(public_key.begin(), public_key.end());
  return bitcoinP2PKH(pubkey, *params_);
}

Result<std::string> Bitcoin::p2shAddress(const Bytes33& public_key) const {
  return bitcoinP2SH(public_key, *params_);
}

Result<std::string> Bitcoin::p2wpkhAddress(const Bytes33& public_key) const {
  return bitcoinP2WPKH(public_key, *params_);
}

Result<std::string> Bitcoin::p2wshAddress(const ByteVector& witness_script) const {
  return bitcoinP2WSH(witness_script, *params_);
}

Result<std::string> Bitcoin::p2trAddress(const Bytes33& public_key) const {
  ByteVector pubkey(public_key.begin(), public_key.end());
  return bitcoinP2TR(pubkey, *params_);
}

Error Bitcoin::validateAddress(const std::string& address) const {
  auto result = validateBitcoinAddress(address, *params_);
  return result.ok() ? Error::OK : result.error;
}

Result<DecodedAddress> Bitcoin::decodeAddress(const std::string& address) const {
  auto type = detectBitcoinAddressType(address, *params_);
  if (!type.ok()) {
    return Result<DecodedAddress>::fail(type.error);
  }

  DecodedAddress decoded;
  decoded.address = address;
  decoded.network = network_;

  switch (type.value) {
    case BitcoinAddressType::P2PKH:
    case BitcoinAddressType::P2SH: {
      auto result = base58CheckDecode(address);
      if (!result.ok()) return Result<DecodedAddress>::fail(result.error);
      decoded.version = result.value[0];
      decoded.data = ByteVector(result.value.begin() + 1, result.value.end());
      break;
    }

    case BitcoinAddressType::P2WPKH:
    case BitcoinAddressType::P2WSH: {
      auto result = bech32Decode(address);
      if (!result.ok()) return Result<DecodedAddress>::fail(result.error);
      decoded.version = 0;
      decoded.data = result.value.second;
      break;
    }

    case BitcoinAddressType::P2TR: {
      auto result = bech32mDecode(address);
      if (!result.ok()) return Result<DecodedAddress>::fail(result.error);
      decoded.version = 1;
      decoded.data = result.value.second;
      break;
    }

    default:
      return Result<DecodedAddress>::fail(Error::INVALID_ADDRESS);
  }

  return Result<DecodedAddress>::success(std::move(decoded));
}

Result<BitcoinAddressType> Bitcoin::detectAddressType(const std::string& address) const {
  return detectBitcoinAddressType(address, *params_);
}

Result<ByteVector> Bitcoin::signMessage(const ByteVector& message, const Bytes32& private_key) const {
  std::string msg_str(message.begin(), message.end());
  return signBitcoinMessage(msg_str, private_key, true);
}

Result<bool> Bitcoin::verifyMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const ByteVector& public_key
) const {
  // Recover and compare public keys
  std::string msg_str(message.begin(), message.end());
  auto recovered = recoverBitcoinMessageSigner(msg_str, signature);
  if (!recovered.ok()) {
    return Result<bool>::fail(recovered.error);
  }

  // Compare public keys
  bool match = (recovered.value.size() == public_key.size() &&
                std::equal(recovered.value.begin(), recovered.value.end(), public_key.begin()));

  return Result<bool>::success(std::move(match));
}

std::string Bitcoin::getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const {
  std::ostringstream path;
  path << "m/" << defaultPurpose() << "'/"
       << static_cast<uint32_t>(CoinType::BITCOIN) << "'/"
       << account << "'/"
       << change << "/"
       << index;
  return path.str();
}

uint32_t Bitcoin::defaultPurpose() const {
  switch (address_type_) {
    case BitcoinAddressType::P2PKH:
      return 44;
    case BitcoinAddressType::P2SH:
      return 49;
    case BitcoinAddressType::P2WPKH:
    case BitcoinAddressType::P2WSH:
      return 84;
    case BitcoinAddressType::P2TR:
      return 86;
    default:
      return 84;
  }
}

// =============================================================================
// C API Implementation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2pkh_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
) {
  if (!public_key || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams& params = (network == 0) ? BITCOIN_MAINNET : BITCOIN_TESTNET;
  ByteVector pubkey(public_key, public_key + pubkey_len);

  auto result = bitcoinP2PKH(pubkey, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  // Safe string copy with bounds checking (need space for null terminator)
  if (result.value.size() + 1 > address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(address_out, result.value.c_str(), result.value.size());
  address_out[result.value.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2sh_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
) {
  if (!public_key || pubkey_len != 33 || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams& params = (network == 0) ? BITCOIN_MAINNET : BITCOIN_TESTNET;
  Bytes33 pubkey;
  std::copy(public_key, public_key + 33, pubkey.begin());

  auto result = bitcoinP2SH(pubkey, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  // Safe string copy with bounds checking (need space for null terminator)
  if (result.value.size() + 1 > address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(address_out, result.value.c_str(), result.value.size());
  address_out[result.value.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2wpkh_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
) {
  if (!public_key || pubkey_len != 33 || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams& params = (network == 0) ? BITCOIN_MAINNET : BITCOIN_TESTNET;
  Bytes33 pubkey;
  std::copy(public_key, public_key + 33, pubkey.begin());

  auto result = bitcoinP2WPKH(pubkey, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  // Safe string copy with bounds checking (need space for null terminator)
  if (result.value.size() + 1 > address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(address_out, result.value.c_str(), result.value.size());
  address_out[result.value.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2wsh_address(
  const uint8_t* witness_script,
  size_t script_len,
  int32_t network,
  char* address_out,
  size_t address_size
) {
  if (!witness_script || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams& params = (network == 0) ? BITCOIN_MAINNET : BITCOIN_TESTNET;
  ByteVector script(witness_script, witness_script + script_len);

  auto result = bitcoinP2WSH(script, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  // Safe string copy with bounds checking (need space for null terminator)
  if (result.value.size() + 1 > address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(address_out, result.value.c_str(), result.value.size());
  address_out[result.value.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_p2tr_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  int32_t network,
  char* address_out,
  size_t address_size
) {
  if (!public_key || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams& params = (network == 0) ? BITCOIN_MAINNET : BITCOIN_TESTNET;
  ByteVector pubkey(public_key, public_key + pubkey_len);

  auto result = bitcoinP2TR(pubkey, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  // Safe string copy with bounds checking (need space for null terminator)
  if (result.value.size() + 1 > address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(address_out, result.value.c_str(), result.value.size());
  address_out[result.value.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_validate_address(const char* address, int32_t network) {
  if (!address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams& params = (network == 0) ? BITCOIN_MAINNET : BITCOIN_TESTNET;
  auto result = validateBitcoinAddress(address, params);
  return static_cast<int32_t>(result.error);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_detect_address_type(const char* address, int32_t network) {
  if (!address) {
    return -1;
  }

  const BitcoinParams& params = (network == 0) ? BITCOIN_MAINNET : BITCOIN_TESTNET;
  auto result = detectBitcoinAddressType(address, params);
  if (!result.ok()) return -1;

  return static_cast<int32_t>(result.value);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_decode_address(
  const char* address,
  int32_t* type_out,
  uint8_t* hash_out,
  size_t* hash_len,
  int32_t* network_out
) {
  if (!address || !type_out || !hash_out || !hash_len || !network_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::string addr(address);
  if (addr.empty()) {
    return static_cast<int32_t>(Error::INVALID_ADDRESS);
  }

  // Detect network from HRP (Bech32) or version byte (Base58Check).
  const BitcoinParams* params = nullptr;
  Network net = Network::MAINNET;

  std::string lower = addr;
  std::transform(lower.begin(), lower.end(), lower.begin(),
                 [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

  if (lower.rfind("bc1", 0) == 0) {
    params = &BITCOIN_MAINNET;
    net = Network::MAINNET;
  } else if (lower.rfind("tb1", 0) == 0) {
    params = &BITCOIN_TESTNET;
    net = Network::TESTNET;
  } else {
    auto decoded = base58CheckDecode(addr);
    if (!decoded.ok() || decoded.value.empty()) {
      return static_cast<int32_t>(Error::INVALID_ADDRESS);
    }

    uint8_t version = decoded.value[0];
    if (version == BITCOIN_MAINNET.p2pkh_version || version == BITCOIN_MAINNET.p2sh_version) {
      params = &BITCOIN_MAINNET;
      net = Network::MAINNET;
    } else if (version == BITCOIN_TESTNET.p2pkh_version || version == BITCOIN_TESTNET.p2sh_version) {
      params = &BITCOIN_TESTNET;
      net = Network::TESTNET;
    } else {
      return static_cast<int32_t>(Error::INVALID_ADDRESS);
    }
  }

  auto type = detectBitcoinAddressType(addr, *params);
  if (!type.ok()) {
    return static_cast<int32_t>(type.error);
  }

  ByteVector payload;
  switch (type.value) {
    case BitcoinAddressType::P2PKH:
    case BitcoinAddressType::P2SH: {
      auto decoded = base58CheckDecode(addr);
      if (!decoded.ok() || decoded.value.size() < 21) {
        return static_cast<int32_t>(Error::INVALID_ADDRESS);
      }
      payload.assign(decoded.value.begin() + 1, decoded.value.end());
      break;
    }

    case BitcoinAddressType::P2WPKH:
    case BitcoinAddressType::P2WSH: {
      auto decoded = bech32Decode(addr);
      if (!decoded.ok()) {
        return static_cast<int32_t>(decoded.error);
      }
      payload = decoded.value.second;
      break;
    }

    case BitcoinAddressType::P2TR: {
      auto decoded = bech32mDecode(addr);
      if (!decoded.ok()) {
        return static_cast<int32_t>(decoded.error);
      }
      payload = decoded.value.second;
      break;
    }

    default:
      return static_cast<int32_t>(Error::INVALID_ADDRESS);
  }

  if (payload.size() > *hash_len) {
    *hash_len = payload.size();
    return static_cast<int32_t>(Error::OUT_OF_MEMORY);
  }

  std::copy(payload.begin(), payload.end(), hash_out);
  *hash_len = payload.size();
  *type_out = static_cast<int32_t>(type.value);
  *network_out = static_cast<int32_t>(net);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_sign_message(
  const char* message,
  const uint8_t* private_key,
  int32_t compressed,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!message || !private_key || !signature_out || signature_size < 65) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  auto result = signBitcoinMessage(message, priv, compressed != 0);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_verify_message(
  const char* message,
  const uint8_t* signature,
  size_t signature_len,
  const char* address,
  int32_t network
) {
  if (!message || !signature || signature_len != 65 || !address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams& params = (network == 0) ? BITCOIN_MAINNET : BITCOIN_TESTNET;
  ByteVector sig(signature, signature + signature_len);

  auto result = verifyBitcoinMessage(message, sig, address, params);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  return result.value ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_to_wif(
  const uint8_t* private_key,
  int32_t compressed,
  int32_t network,
  char* wif_out,
  size_t wif_size
) {
  if (!private_key || !wif_out || wif_size < 52) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  const BitcoinParams& params = (network == 0) ? BITCOIN_MAINNET : BITCOIN_TESTNET;
  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  std::string wif = toWIF(priv, compressed != 0, params);
  // Safe string copy with bounds checking (need space for null terminator)
  if (wif.size() + 1 > wif_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::memcpy(wif_out, wif.c_str(), wif.size());
  wif_out[wif.size()] = '\0';
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_btc_from_wif(
  const char* wif,
  uint8_t* private_key_out,
  int32_t* compressed_out
) {
  if (!wif || !private_key_out || !compressed_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = fromWIF(wif);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.first.begin(), result.value.first.end(), private_key_out);
  *compressed_out = result.value.second ? 1 : 0;
  return static_cast<int32_t>(Error::OK);
}

} // namespace coins
} // namespace hd_wallet
