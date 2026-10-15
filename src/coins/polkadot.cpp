/**
 * @file polkadot.cpp
 * @brief Polkadot/Substrate Support Implementation
 */

#include "hd_wallet/coins/polkadot.h"

#include <algorithm>
#include <cstring>
#include <sstream>

// Crypto++ headers
#include <cryptopp/blake2.h>
#include <cryptopp/xed25519.h>

namespace hd_wallet {
namespace coins {

// =============================================================================
// Substrate Network Parameters
// =============================================================================

const SubstrateNetworkParams POLKADOT = {
  .name = "Polkadot",
  .symbol = "DOT",
  .ss58_prefix = 0,
  .decimals = 10,
  .use_sr25519 = true
};

const SubstrateNetworkParams KUSAMA = {
  .name = "Kusama",
  .symbol = "KSM",
  .ss58_prefix = 2,
  .decimals = 12,
  .use_sr25519 = true
};

const SubstrateNetworkParams WESTEND = {
  .name = "Westend",
  .symbol = "WND",
  .ss58_prefix = 42,
  .decimals = 12,
  .use_sr25519 = true
};

const SubstrateNetworkParams SUBSTRATE_GENERIC = {
  .name = "Substrate",
  .symbol = "SUB",
  .ss58_prefix = 42,
  .decimals = 12,
  .use_sr25519 = false
};

const SubstrateNetworkParams ACALA = {
  .name = "Acala",
  .symbol = "ACA",
  .ss58_prefix = 10,
  .decimals = 12,
  .use_sr25519 = true
};

const SubstrateNetworkParams MOONBEAM = {
  .name = "Moonbeam",
  .symbol = "GLMR",
  .ss58_prefix = 1284,
  .decimals = 18,
  .use_sr25519 = false
};

const SubstrateNetworkParams ASTAR = {
  .name = "Astar",
  .symbol = "ASTR",
  .ss58_prefix = 5,
  .decimals = 18,
  .use_sr25519 = true
};

// =============================================================================
// SS58 Address Encoding
// =============================================================================

namespace {

const uint8_t SS58_PREFIX[] = {'S', 'S', '5', '8', 'P', 'R', 'E'};

ByteVector ss58ChecksumHash(const ByteVector& data) {
  ByteVector to_hash;
  to_hash.insert(to_hash.end(), SS58_PREFIX, SS58_PREFIX + 7);
  to_hash.insert(to_hash.end(), data.begin(), data.end());

  // BLAKE2b-512
  CryptoPP::BLAKE2b blake(false, 64);
  ByteVector hash(64);
  blake.CalculateDigest(hash.data(), to_hash.data(), to_hash.size());

  // Return first 2 bytes as checksum
  return ByteVector(hash.begin(), hash.begin() + 2);
}

}  // namespace

Result<std::string> ss58Encode(const Bytes32& public_key, uint16_t network_prefix) {
  ByteVector data;

  // Encode network ID
  if (network_prefix < 64) {
    // Simple format: single byte
    data.push_back(static_cast<uint8_t>(network_prefix));
  } else if (network_prefix < 16384) {
    // Full format: two bytes
    // Format: 01XXXXXX XXXXXXXX where 14 bits = prefix
    uint8_t byte0 = ((network_prefix & 0x00FC) >> 2) | 0x40;
    uint8_t byte1 = ((network_prefix >> 8) & 0x3F) | ((network_prefix & 0x0003) << 6);
    data.push_back(byte0);
    data.push_back(byte1);
  } else {
    return Result<std::string>::fail(Error::INVALID_ARGUMENT);
  }

  // Add public key
  data.insert(data.end(), public_key.begin(), public_key.end());

  // Calculate and append checksum
  ByteVector checksum = ss58ChecksumHash(data);
  data.insert(data.end(), checksum.begin(), checksum.end());

  // Base58 encode
  return Result<std::string>::success(base58Encode(data));
}

Result<std::string> ss58Encode(const Bytes32& public_key, const SubstrateNetworkParams& params) {
  return ss58Encode(public_key, params.ss58_prefix);
}

Result<std::pair<uint16_t, Bytes32>> ss58DecodeBytes32(const std::string& address) {
  // Base58 decode
  auto decoded = base58Decode(address);
  if (!decoded.ok()) {
    return Result<std::pair<uint16_t, Bytes32>>::fail(decoded.error);
  }

  if (decoded.value.size() < 3) {
    return Result<std::pair<uint16_t, Bytes32>>::fail(Error::INVALID_ADDRESS);
  }

  // Parse network prefix
  uint16_t network_prefix;
  size_t prefix_len;

  if ((decoded.value[0] & 0x40) == 0) {
    // Simple format
    network_prefix = decoded.value[0];
    prefix_len = 1;
  } else {
    // Full format
    if (decoded.value.size() < 4) {
      return Result<std::pair<uint16_t, Bytes32>>::fail(Error::INVALID_ADDRESS);
    }
    network_prefix = ((decoded.value[0] & 0x3F) << 2) | (decoded.value[1] >> 6) |
                     ((decoded.value[1] & 0x3F) << 8);
    prefix_len = 2;
  }

  // Check length
  if (decoded.value.size() != prefix_len + 32 + 2) {
    return Result<std::pair<uint16_t, Bytes32>>::fail(Error::INVALID_ADDRESS);
  }

  // Extract public key
  Bytes32 public_key;
  std::copy(decoded.value.begin() + prefix_len, decoded.value.begin() + prefix_len + 32, public_key.begin());

  // Verify checksum
  ByteVector data_without_checksum(decoded.value.begin(), decoded.value.end() - 2);
  ByteVector expected_checksum = ss58ChecksumHash(data_without_checksum);
  ByteVector provided_checksum(decoded.value.end() - 2, decoded.value.end());

  if (expected_checksum != provided_checksum) {
    return Result<std::pair<uint16_t, Bytes32>>::fail(Error::INVALID_CHECKSUM);
  }

  return Result<std::pair<uint16_t, Bytes32>>::success(
    std::make_pair(network_prefix, std::move(public_key))
  );
}

Result<std::string> convertSS58Prefix(const std::string& address, uint16_t new_prefix) {
  auto decoded = ss58DecodeBytes32(address);
  if (!decoded.ok()) {
    return Result<std::string>::fail(decoded.error);
  }

  // ss58Encode returns Result<std::string>, just return it directly
  return ss58Encode(decoded.value.second, new_prefix);
}

// =============================================================================
// SS58 Address Validation
// =============================================================================

Error validateSS58Address(const std::string& address, int32_t expected_prefix) {
  auto decoded = ss58DecodeBytes32(address);
  if (!decoded.ok()) {
    return decoded.error;
  }

  if (expected_prefix >= 0 && decoded.value.first != static_cast<uint16_t>(expected_prefix)) {
    return Error::INVALID_ADDRESS;
  }

  return Error::OK;
}

Result<uint16_t> extractSS58Prefix(const std::string& address) {
  auto decoded = ss58DecodeBytes32(address);
  if (!decoded.ok()) {
    return Result<uint16_t>::fail(decoded.error);
  }

  uint16_t prefix = decoded.value.first;
  return Result<uint16_t>::success(std::move(prefix));
}

bool isSubstrateNetworkAddress(const std::string& address, const SubstrateNetworkParams& params) {
  auto prefix = extractSS58Prefix(address);
  if (!prefix.ok()) return false;

  return prefix.value == params.ss58_prefix;
}

const SubstrateNetworkParams* getSubstrateNetworkByPrefix(uint16_t prefix) {
  switch (prefix) {
    case 0: return &POLKADOT;
    case 2: return &KUSAMA;
    case 42: return &SUBSTRATE_GENERIC;
    case 5: return &ASTAR;
    case 10: return &ACALA;
    case 1284: return &MOONBEAM;
    default: return nullptr;
  }
}

// =============================================================================
// Polkadot Message Signing
// =============================================================================

namespace {

ByteVector wrapPolkadotMessage(const std::string& message) {
  // Substrate message format: <Bytes> + message + </Bytes>
  ByteVector wrapped;
  const char* prefix = "<Bytes>";
  const char* suffix = "</Bytes>";
  wrapped.insert(wrapped.end(), prefix, prefix + 7);
  wrapped.insert(wrapped.end(), message.begin(), message.end());
  wrapped.insert(wrapped.end(), suffix, suffix + 8);
  return wrapped;
}

}  // namespace

Result<ByteVector> signPolkadotMessage(const std::string& message, const Bytes32& private_key) {
  ByteVector wrapped = wrapPolkadotMessage(message);
  return signPolkadotMessageRaw(wrapped, private_key);
}

Result<ByteVector> signPolkadotMessageRaw(const ByteVector& message, const Bytes32& private_key) {
  auto sig = ed25519Sign(message, private_key);
  if (!sig.ok()) {
    return Result<ByteVector>::fail(sig.error);
  }

  return Result<ByteVector>::success(ByteVector(sig.value.data.begin(), sig.value.data.end()));
}

Result<bool> verifyPolkadotMessage(
  const std::string& message,
  const ByteVector& signature,
  const Bytes32& public_key
) {
  ByteVector wrapped = wrapPolkadotMessage(message);
  return verifyPolkadotMessageRaw(wrapped, signature, public_key);
}

Result<bool> verifyPolkadotMessage(
  const std::string& message,
  const ByteVector& signature,
  const std::string& address
) {
  auto decoded = ss58DecodeBytes32(address);
  if (!decoded.ok()) {
    return Result<bool>::fail(decoded.error);
  }

  return verifyPolkadotMessage(message, signature, decoded.value.second);
}

Result<bool> verifyPolkadotMessageRaw(
  const ByteVector& message,
  const ByteVector& signature,
  const Bytes32& public_key
) {
  if (signature.size() != 64) {
    return Result<bool>::fail(Error::INVALID_SIGNATURE);
  }

  Ed25519Signature sig;
  std::copy(signature.begin(), signature.end(), sig.data.begin());

  return ed25519Verify(message, sig, public_key);
}

// =============================================================================
// Polkadot Transaction Signing
// =============================================================================

Bytes32 hashPayloadForSigning(const ByteVector& payload) {
  // If payload is > 256 bytes, hash it with BLAKE2b-256
  if (payload.size() > 256) {
    CryptoPP::BLAKE2b blake(false, 32);
    Bytes32 hash;
    blake.CalculateDigest(hash.data(), payload.data(), payload.size());
    return hash;
  }

  // Otherwise, use payload directly (padded to 32 bytes if needed)
  Bytes32 result;
  std::fill(result.begin(), result.end(), 0);
  std::copy(payload.begin(), payload.begin() + std::min(payload.size(), size_t(32)), result.begin());
  return result;
}

Result<ByteVector> signExtrinsic(const ByteVector& payload, const Bytes32& private_key) {
  ByteVector to_sign;

  if (payload.size() > 256) {
    // Hash the payload
    Bytes32 hash = hashPayloadForSigning(payload);
    to_sign.assign(hash.begin(), hash.end());
  } else {
    to_sign = payload;
  }

  auto sig = ed25519Sign(to_sign, private_key);
  if (!sig.ok()) {
    return Result<ByteVector>::fail(sig.error);
  }

  return Result<ByteVector>::success(ByteVector(sig.value.data.begin(), sig.value.data.end()));
}

Result<bool> verifyExtrinsicSignature(
  const ByteVector& payload,
  const ByteVector& signature,
  const Bytes32& public_key
) {
  ByteVector to_verify;

  if (payload.size() > 256) {
    Bytes32 hash = hashPayloadForSigning(payload);
    to_verify.assign(hash.begin(), hash.end());
  } else {
    to_verify = payload;
  }

  if (signature.size() != 64) {
    return Result<bool>::fail(Error::INVALID_SIGNATURE);
  }

  Ed25519Signature sig;
  std::copy(signature.begin(), signature.end(), sig.data.begin());

  return ed25519Verify(to_verify, sig, public_key);
}

// =============================================================================
// Multi-Address Support
// =============================================================================

Result<ByteVector> encodeMultiAddress(const std::string& address) {
  auto decoded = ss58DecodeBytes32(address);
  if (!decoded.ok()) {
    return Result<ByteVector>::fail(decoded.error);
  }

  return Result<ByteVector>::success(encodeMultiAddressId(decoded.value.second));
}

ByteVector encodeMultiAddressId(const Bytes32& public_key) {
  // MultiAddress::Id is type 0, followed by 32 bytes
  ByteVector result;
  result.push_back(0x00);  // Id variant
  result.insert(result.end(), public_key.begin(), public_key.end());
  return result;
}

// =============================================================================
// Key Derivation
// =============================================================================

Result<std::pair<Bytes32, Bytes32>> deriveSubstrateKeypair(const Bytes32& seed) {
  auto pubkey = deriveSubstratePublicKey(seed);
  if (!pubkey.ok()) {
    return Result<std::pair<Bytes32, Bytes32>>::fail(pubkey.error);
  }

  return Result<std::pair<Bytes32, Bytes32>>::success(
    std::make_pair(seed, pubkey.value)
  );
}

Result<Bytes32> deriveSubstratePublicKey(const Bytes32& private_key) {
  return ed25519PublicKey(private_key);
}

Result<std::pair<Bytes32, Bytes32>> deriveSubstratePath(
  const Bytes32& seed,
  const std::string& path
) {
  // Substrate path derivation: //hard/soft
  // Hard derivation uses BLAKE2b
  // Soft derivation uses different mechanism
  //
  // For simplicity, we'll use the seed directly for now
  // A full implementation would parse the path and derive accordingly

  // For Ed25519, we just use the seed as the private key
  return deriveSubstrateKeypair(seed);
}

// =============================================================================
// Polkadot Coin Implementation
// =============================================================================

Polkadot::Polkadot(const SubstrateNetworkParams& params)
  : network_(Network::MAINNET),
    params_(params) {
}

Polkadot::Polkadot(uint16_t ss58_prefix)
  : network_(Network::MAINNET),
    params_(SUBSTRATE_GENERIC) {
  params_.ss58_prefix = ss58_prefix;
}

Result<std::string> Polkadot::addressFromPublicKey(const Bytes33& public_key) const {
  // For Polkadot, we expect a 32-byte Ed25519 key
  Bytes32 ed_pubkey;

  // Check if first byte is padding
  if (public_key[0] == 0x00 || public_key[0] == 0x01) {
    std::copy(public_key.begin() + 1, public_key.end(), ed_pubkey.begin());
  } else {
    std::copy(public_key.begin(), public_key.begin() + 32, ed_pubkey.begin());
  }

  return addressFromEd25519PublicKey(ed_pubkey);
}

Result<std::string> Polkadot::addressFromEd25519PublicKey(const Bytes32& public_key) const {
  return ss58Encode(public_key, params_.ss58_prefix);
}

Error Polkadot::validateAddress(const std::string& address) const {
  return validateSS58Address(address, params_.ss58_prefix);
}

Result<DecodedAddress> Polkadot::decodeAddress(const std::string& address) const {
  auto decoded = ss58DecodeBytes32(address);
  if (!decoded.ok()) {
    return Result<DecodedAddress>::fail(decoded.error);
  }

  DecodedAddress result;
  result.address = address;
  result.network = network_;
  result.version = static_cast<uint8_t>(decoded.value.first & 0xFF);
  result.data = ByteVector(decoded.value.second.begin(), decoded.value.second.end());

  return Result<DecodedAddress>::success(std::move(result));
}

Result<ByteVector> Polkadot::signMessage(const ByteVector& message, const Bytes32& private_key) const {
  return signPolkadotMessageRaw(message, private_key);
}

Result<bool> Polkadot::verifyMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const ByteVector& public_key
) const {
  if (public_key.size() != 32) {
    return Result<bool>::fail(Error::INVALID_PUBLIC_KEY);
  }

  Bytes32 pubkey;
  std::copy(public_key.begin(), public_key.end(), pubkey.begin());

  return verifyPolkadotMessageRaw(message, signature, pubkey);
}

Result<ByteVector> Polkadot::signMessageWrapped(const std::string& message, const Bytes32& private_key) const {
  return signPolkadotMessage(message, private_key);
}

Result<bool> Polkadot::verifyMessageWrapped(
  const std::string& message,
  const ByteVector& signature,
  const Bytes32& public_key
) const {
  return verifyPolkadotMessage(message, signature, public_key);
}

std::string Polkadot::getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const {
  // Polkadot uses: m/44'/354'/account'/change'/index'
  // All levels hardened for Ed25519
  std::ostringstream path;
  path << "m/44'/354'/" << account << "'/" << change << "'/" << index << "'";
  return path.str();
}

// =============================================================================
// C API Implementation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  uint16_t ss58_prefix,
  char* address_out,
  size_t address_size
) {
  if (!public_key || pubkey_len != 32 || !address_out || address_size < 48) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 pubkey;
  std::copy(public_key, public_key + 32, pubkey.begin());

  auto result = ss58Encode(pubkey, ss58_prefix);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.size() >= address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(address_out, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_validate_address(
  const char* address,
  int32_t expected_prefix
) {
  if (!address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  return static_cast<int32_t>(validateSS58Address(address, expected_prefix));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_decode_address(
  const char* address,
  uint16_t* prefix_out,
  uint8_t* pubkey_out,
  size_t pubkey_size
) {
  if (!address || !prefix_out || !pubkey_out || pubkey_size < 32) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = ss58DecodeBytes32(address);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  *prefix_out = result.value.first;
  std::copy(result.value.second.begin(), result.value.second.end(), pubkey_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_convert_prefix(
  const char* address,
  uint16_t new_prefix,
  char* output,
  size_t output_size
) {
  if (!address || !output || output_size < 48) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = convertSS58Prefix(address, new_prefix);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.size() >= output_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(output, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_sign_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!message || !private_key || !signature_out || signature_size < 64) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  ByteVector msg(message, message + message_len);
  auto result = signPolkadotMessageRaw(msg, priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_verify_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  const uint8_t* public_key,
  size_t pubkey_len
) {
  if (!message || !signature || signature_len != 64 || !public_key || pubkey_len != 32) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 pubkey;
  std::copy(public_key, public_key + 32, pubkey.begin());

  ByteVector msg(message, message + message_len);
  ByteVector sig(signature, signature + signature_len);

  auto result = verifyPolkadotMessageRaw(msg, sig, pubkey);
  if (!result.ok()) return -static_cast<int32_t>(result.error);

  return result.value ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_sign_extrinsic(
  const uint8_t* payload,
  size_t payload_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!payload || !private_key || !signature_out || signature_size < 64) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  ByteVector pay(payload, payload + payload_len);
  auto result = signExtrinsic(pay, priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_dot_derive_pubkey(
  const uint8_t* private_key,
  uint8_t* pubkey_out,
  size_t pubkey_size
) {
  if (!private_key || !pubkey_out || pubkey_size < 32) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  auto result = deriveSubstratePublicKey(priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), pubkey_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ss58_encode(
  const uint8_t* public_key,
  size_t pubkey_len,
  uint16_t prefix,
  char* address_out,
  size_t address_size
) {
  return hd_dot_address(public_key, pubkey_len, prefix, address_out, address_size);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_ss58_decode(
  const char* address,
  uint16_t* prefix_out,
  uint8_t* pubkey_out,
  size_t pubkey_size
) {
  return hd_dot_decode_address(address, prefix_out, pubkey_out, pubkey_size);
}

} // namespace coins
} // namespace hd_wallet
