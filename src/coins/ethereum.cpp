/**
 * @file ethereum.cpp
 * @brief Ethereum Support Implementation
 */

#include "hd_wallet/coins/ethereum.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <iomanip>

// Crypto++ headers
#include <cryptopp/sha3.h>
#include <cryptopp/eccrypto.h>
#if !HD_WALLET_IS_WASI
#include <cryptopp/osrng.h>
#endif
#include <cryptopp/oids.h>

namespace hd_wallet {
namespace coins {

// =============================================================================
// Ethereum Address Generation
// =============================================================================

Result<std::string> ethereumAddress(const ByteVector& public_key) {
  ByteVector uncompressed_xy;

  if (public_key.size() == 33) {
    // Compressed - need to decompress
    Bytes33 compressed;
    std::copy(public_key.begin(), public_key.end(), compressed.begin());

    auto result = bip32::decompressPublicKey(compressed, Curve::SECP256K1);
    if (!result.ok()) {
      return Result<std::string>::fail(result.error);
    }

    // Use the 64 bytes after the 0x04 prefix
    uncompressed_xy.assign(result.value.begin() + 1, result.value.end());
  } else if (public_key.size() == 64) {
    // Already just the x,y coordinates
    uncompressed_xy = public_key;
  } else if (public_key.size() == 65) {
    // Has 0x04 prefix - remove it
    if (public_key[0] != 0x04) {
      return Result<std::string>::fail(Error::INVALID_PUBLIC_KEY);
    }
    uncompressed_xy.assign(public_key.begin() + 1, public_key.end());
  } else {
    return Result<std::string>::fail(Error::INVALID_PUBLIC_KEY);
  }

  // Keccak256 hash of the 64 bytes (x || y)
  Bytes32 hash = keccak256(uncompressed_xy);

  // Take last 20 bytes
  ByteVector address_bytes(hash.end() - 20, hash.end());

  // Convert to hex with checksum
  std::string hex_address = toHex(address_bytes, false);
  return Result<std::string>::success(applyEIP55Checksum(hex_address));
}

Result<std::string> ethereumAddress(const Bytes33& public_key) {
  ByteVector pubkey(public_key.begin(), public_key.end());
  return ethereumAddress(pubkey);
}

Result<std::string> ethereumAddress(const Bytes65& public_key) {
  ByteVector pubkey(public_key.begin(), public_key.end());
  return ethereumAddress(pubkey);
}

// =============================================================================
// EIP-55 Checksum
// =============================================================================

std::string applyEIP55Checksum(const std::string& address) {
  // Normalize - lowercase and remove 0x prefix
  std::string addr = address;
  if (addr.size() >= 2 && addr[0] == '0' && (addr[1] == 'x' || addr[1] == 'X')) {
    addr = addr.substr(2);
  }
  std::transform(addr.begin(), addr.end(), addr.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  // Should be 40 hex characters
  if (addr.size() != 40) {
    return "";
  }

  // Hash the lowercase address
  ByteVector addr_bytes(addr.begin(), addr.end());
  Bytes32 hash = keccak256(addr_bytes);

  // Apply checksum
  std::string result = "0x";
  for (size_t i = 0; i < 40; i++) {
    uint8_t hash_byte = hash[i / 2];
    uint8_t nibble = (i % 2 == 0) ? (hash_byte >> 4) : (hash_byte & 0x0F);

    if (nibble >= 8 && std::isalpha(static_cast<unsigned char>(addr[i]))) {
      result += std::toupper(static_cast<unsigned char>(addr[i]));
    } else {
      result += addr[i];
    }
  }

  return result;
}

bool verifyEIP55Checksum(const std::string& address) {
  if (address.size() != 42 || address[0] != '0' || address[1] != 'x') {
    return false;
  }

  // EIP-55: Only properly checksummed (mixed-case) addresses pass verification.
  // All-lowercase addresses are NOT checksummed - they are just normalized addresses.
  // All-uppercase addresses are also NOT checksummed.
  // Per the spec, a checksummed address must have the correct mix of upper/lower case
  // as determined by the Keccak256 hash of the lowercase hex.

  // Apply checksum and compare - the address must exactly match the checksummed form
  std::string checksummed = applyEIP55Checksum(address);
  return checksummed == address;
}

std::string normalizeEthereumAddress(const std::string& address) {
  std::string result = address;
  if (result.size() >= 2 && result[0] == '0' && (result[1] == 'x' || result[1] == 'X')) {
    result = result.substr(2);
  }
  std::transform(result.begin(), result.end(), result.begin(),
                 [](unsigned char c) { return std::tolower(c); });
  return "0x" + result;
}

// =============================================================================
// Ethereum Address Validation
// =============================================================================

Error validateEthereumAddress(const std::string& address) {
  std::string addr = address;

  // Handle 0x prefix
  if (addr.size() >= 2 && addr[0] == '0' && (addr[1] == 'x' || addr[1] == 'X')) {
    addr = addr.substr(2);
  }

  // Must be 40 characters
  if (addr.size() != 40) {
    return Error::INVALID_ADDRESS;
  }

  // Check all characters are valid hex
  for (char c : addr) {
    if (!std::isxdigit(static_cast<unsigned char>(c))) {
      return Error::INVALID_ADDRESS;
    }
  }

  // Verify EIP-55 checksum if mixed case
  if (!verifyEIP55Checksum("0x" + addr) && address != normalizeEthereumAddress(address)) {
    return Error::INVALID_CHECKSUM;
  }

  return Error::OK;
}

bool isZeroAddress(const std::string& address) {
  std::string normalized = normalizeEthereumAddress(address);
  return normalized == "0x0000000000000000000000000000000000000000";
}

// =============================================================================
// EIP-191: Personal Message Signing
// =============================================================================

Bytes32 hashEIP191Message(const std::string& message) {
  ByteVector msg(message.begin(), message.end());
  return hashEIP191Message(msg);
}

Bytes32 hashEIP191Message(const ByteVector& message) {
  // Format: "\x19Ethereum Signed Message:\n" + len(message) + message
  std::string prefix = "\x19" "Ethereum Signed Message:\n" + std::to_string(message.size());

  ByteVector to_hash;
  to_hash.insert(to_hash.end(), prefix.begin(), prefix.end());
  to_hash.insert(to_hash.end(), message.begin(), message.end());

  return keccak256(to_hash);
}

Result<ByteVector> signEIP191Message(const std::string& message, const Bytes32& private_key) {
  ByteVector msg(message.begin(), message.end());
  return signEIP191Message(msg, private_key);
}

Result<ByteVector> signEIP191Message(const ByteVector& message, const Bytes32& private_key) {
  Bytes32 hash = hashEIP191Message(message);
  return signHash(hash, private_key);
}

Result<bool> verifyEIP191Message(
  const std::string& message,
  const ByteVector& signature,
  const std::string& address
) {
  auto recovered = recoverEIP191Signer(message, signature);
  if (!recovered.ok()) {
    return Result<bool>::fail(recovered.error);
  }

  // Normalize both addresses for comparison
  std::string recovered_normalized = normalizeEthereumAddress(recovered.value);
  std::string expected_normalized = normalizeEthereumAddress(address);

  return Result<bool>::success(recovered_normalized == expected_normalized);
}

Result<std::string> recoverEIP191Signer(const std::string& message, const ByteVector& signature) {
  Bytes32 hash = hashEIP191Message(message);
  return recoverAddress(hash, signature);
}

// =============================================================================
// EIP-712: Typed Data Signing
// =============================================================================

Bytes32 EIP712Domain::hash() const {
  // Encode domain
  ByteVector encoded;

  // Type hash
  Bytes32 type_hash = typeHash();
  encoded.insert(encoded.end(), type_hash.begin(), type_hash.end());

  // name hash
  if (!name.empty()) {
    Bytes32 name_hash = keccak256(ByteVector(name.begin(), name.end()));
    encoded.insert(encoded.end(), name_hash.begin(), name_hash.end());
  } else {
    Bytes32 empty;
    std::fill(empty.begin(), empty.end(), 0);
    encoded.insert(encoded.end(), empty.begin(), empty.end());
  }

  // version hash
  if (!version.empty()) {
    Bytes32 version_hash = keccak256(ByteVector(version.begin(), version.end()));
    encoded.insert(encoded.end(), version_hash.begin(), version_hash.end());
  } else {
    Bytes32 empty;
    std::fill(empty.begin(), empty.end(), 0);
    encoded.insert(encoded.end(), empty.begin(), empty.end());
  }

  // chainId (uint256)
  Bytes32 chain_bytes;
  std::fill(chain_bytes.begin(), chain_bytes.end(), 0);
  for (int i = 7; i >= 0; i--) {
    chain_bytes[31 - i] = (chainId >> (i * 8)) & 0xFF;
  }
  encoded.insert(encoded.end(), chain_bytes.begin(), chain_bytes.end());

  // verifyingContract (address, padded to 32 bytes)
  {
    Bytes32 padded;
    std::fill(padded.begin(), padded.end(), 0);
    if (!verifyingContract.empty()) {
      auto addr_bytes = fromHex(verifyingContract);
      if (addr_bytes.ok()) {
        size_t offset = 32 - std::min(addr_bytes.value.size(), size_t(32));
        std::copy(addr_bytes.value.begin(), addr_bytes.value.end(), padded.begin() + offset);
      }
    }
    encoded.insert(encoded.end(), padded.begin(), padded.end());
  }

  // salt (optional, already 32 bytes)
  if (!salt.empty()) {
    auto salt_bytes = fromHex(salt);
    if (salt_bytes.ok() && salt_bytes.value.size() == 32) {
      encoded.insert(encoded.end(), salt_bytes.value.begin(), salt_bytes.value.end());
    }
  }

  return keccak256(encoded);
}

Bytes32 EIP712Domain::typeHash() {
  const char* type_string = "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)";
  return keccak256(ByteVector(type_string, type_string + std::strlen(type_string)));
}

Bytes32 hashEIP712Struct(const Bytes32& type_hash, const ByteVector& encoded_data) {
  ByteVector to_hash;
  to_hash.insert(to_hash.end(), type_hash.begin(), type_hash.end());
  to_hash.insert(to_hash.end(), encoded_data.begin(), encoded_data.end());
  return keccak256(to_hash);
}

Bytes32 hashEIP712Type(const std::string& type_string) {
  return keccak256(ByteVector(type_string.begin(), type_string.end()));
}

Bytes32 encodeEIP712(const EIP712Domain& domain, const Bytes32& struct_hash) {
  // Format: "\x19\x01" + domainSeparator + hashStruct(message)
  ByteVector to_hash;
  to_hash.push_back(0x19);
  to_hash.push_back(0x01);

  Bytes32 domain_separator = domain.hash();
  to_hash.insert(to_hash.end(), domain_separator.begin(), domain_separator.end());
  to_hash.insert(to_hash.end(), struct_hash.begin(), struct_hash.end());

  return keccak256(to_hash);
}

Result<ByteVector> signEIP712(
  const EIP712Domain& domain,
  const Bytes32& struct_hash,
  const Bytes32& private_key
) {
  Bytes32 hash = encodeEIP712(domain, struct_hash);
  return signHash(hash, private_key);
}

Result<bool> verifyEIP712(
  const EIP712Domain& domain,
  const Bytes32& struct_hash,
  const ByteVector& signature,
  const std::string& address
) {
  auto recovered = recoverEIP712Signer(domain, struct_hash, signature);
  if (!recovered.ok()) {
    return Result<bool>::fail(recovered.error);
  }

  std::string recovered_normalized = normalizeEthereumAddress(recovered.value);
  std::string expected_normalized = normalizeEthereumAddress(address);

  return Result<bool>::success(recovered_normalized == expected_normalized);
}

Result<std::string> recoverEIP712Signer(
  const EIP712Domain& domain,
  const Bytes32& struct_hash,
  const ByteVector& signature
) {
  Bytes32 hash = encodeEIP712(domain, struct_hash);
  return recoverAddress(hash, signature);
}

// =============================================================================
// Ethereum Signature Utilities
// =============================================================================

uint8_t normalizeV(uint8_t v, uint64_t chainId) {
  if (v == 0 || v == 1) {
    // Already recovery ID
    return v;
  }

  if (v == 27 || v == 28) {
    // Original Ethereum format
    return v - 27;
  }

  // EIP-155 format: 35 + chainId * 2 + recovery
  if (chainId > 0 && v >= 35) {
    return (v - 35 - chainId * 2) % 2;
  }

  return v;
}

EncodedSignature encodeSignature(const ByteVector& signature, uint64_t chainId) {
  EncodedSignature enc;

  if (signature.size() != 65) {
    return enc;
  }

  std::copy(signature.begin(), signature.begin() + 32, enc.r.begin());
  std::copy(signature.begin() + 32, signature.begin() + 64, enc.s.begin());

  uint8_t recovery = signature[64];

  // Convert to EIP-155 if chainId is provided
  if (chainId > 0) {
    enc.v = 35 + chainId * 2 + recovery;
  } else {
    enc.v = 27 + recovery;
  }

  return enc;
}

Result<ByteVector> signHash(const Bytes32& hash, const Bytes32& private_key) {
  // Sign using ECDSA
  auto sig_result = ecdsaSign(hash, private_key);
  if (!sig_result.ok()) {
    return Result<ByteVector>::fail(sig_result.error);
  }

  // Create 65-byte signature: r (32) || s (32) || v (1)
  ByteVector signature(65);
  std::copy(sig_result.value.r.begin(), sig_result.value.r.end(), signature.begin());
  std::copy(sig_result.value.s.begin(), sig_result.value.s.end(), signature.begin() + 32);
  signature[64] = sig_result.value.v;

  return Result<ByteVector>::success(std::move(signature));
}

Result<std::string> recoverAddress(const Bytes32& hash, const ByteVector& signature) {
  if (signature.size() != 65) {
    return Result<std::string>::fail(Error::INVALID_SIGNATURE);
  }

  // Parse signature
  ECDSASignature sig;
  std::copy(signature.begin(), signature.begin() + 32, sig.r.begin());
  std::copy(signature.begin() + 32, signature.begin() + 64, sig.s.begin());

  // Normalize v value
  uint8_t v = signature[64];
  sig.v = normalizeV(v, 0);

  // Recover public key
  auto recovered = ecdsaRecover(hash, sig);
  if (!recovered.ok()) {
    return Result<std::string>::fail(recovered.error);
  }

  // Generate address from recovered public key
  ByteVector pubkey(recovered.value.begin(), recovered.value.end());
  return ethereumAddress(pubkey);
}

// =============================================================================
// Ethereum Coin Implementation
// =============================================================================

Ethereum::Ethereum(Network network)
  : network_(network),
    chain_id_(network == Network::MAINNET ? chain_ids::MAINNET : chain_ids::GOERLI) {
}

Result<std::string> Ethereum::addressFromPublicKey(const Bytes33& public_key) const {
  return ethereumAddress(public_key);
}

Result<std::string> Ethereum::addressFromPublicKeyUncompressed(const Bytes65& public_key) const {
  return ethereumAddress(public_key);
}

Error Ethereum::validateAddress(const std::string& address) const {
  return validateEthereumAddress(address);
}

Result<DecodedAddress> Ethereum::decodeAddress(const std::string& address) const {
  Error err = validateEthereumAddress(address);
  if (err != Error::OK) {
    return Result<DecodedAddress>::fail(err);
  }

  DecodedAddress decoded;
  decoded.address = applyEIP55Checksum(address);
  decoded.network = network_;
  decoded.version = 0;

  auto bytes = fromHex(address);
  if (bytes.ok()) {
    decoded.data = bytes.value;
  }

  return Result<DecodedAddress>::success(std::move(decoded));
}

Result<ByteVector> Ethereum::signMessage(const ByteVector& message, const Bytes32& private_key) const {
  return signEIP191Message(message, private_key);
}

Result<bool> Ethereum::verifyMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const ByteVector& public_key
) const {
  // Generate address from public key
  auto addr_result = ethereumAddress(public_key);
  if (!addr_result.ok()) {
    return Result<bool>::fail(addr_result.error);
  }

  // Verify against address
  std::string msg(message.begin(), message.end());
  return verifyEIP191Message(msg, signature, addr_result.value);
}

Result<bool> Ethereum::verifyMessageByAddress(
  const ByteVector& message,
  const ByteVector& signature,
  const std::string& address
) const {
  std::string msg(message.begin(), message.end());
  return verifyEIP191Message(msg, signature, address);
}

Result<ByteVector> Ethereum::signTypedData(
  const EIP712Domain& domain,
  const Bytes32& struct_hash,
  const Bytes32& private_key
) const {
  return signEIP712(domain, struct_hash, private_key);
}

std::string Ethereum::getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const {
  std::ostringstream path;
  // Ethereum uses m/44'/60'/account'/change/index
  path << "m/44'/60'/" << account << "'/" << change << "/" << index;
  return path.str();
}

// =============================================================================
// C API Implementation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  char* address_out,
  size_t address_size
) {
  if (!public_key || !address_out || address_size < 43) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  ByteVector pubkey(public_key, public_key + pubkey_len);
  auto result = ethereumAddress(pubkey);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.size() >= address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(address_out, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_validate_address(const char* address) {
  if (!address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  return static_cast<int32_t>(validateEthereumAddress(address));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_checksum_address(
  const char* address,
  char* checksummed_out,
  size_t output_size
) {
  if (!address || !checksummed_out || output_size < 43) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::string checksummed = applyEIP55Checksum(address);
  if (checksummed.empty()) {
    return static_cast<int32_t>(Error::INVALID_ADDRESS);
  }

  std::strcpy(checksummed_out, checksummed.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_verify_checksum(const char* address) {
  if (!address) {
    return 0;
  }
  return verifyEIP55Checksum(address) ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_sign_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!message || !private_key || !signature_out || signature_size < 65) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  ByteVector msg(message, message + message_len);
  auto result = signEIP191Message(msg, priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_verify_message(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  const char* address
) {
  if (!message || !signature || signature_len != 65 || !address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::string msg(reinterpret_cast<const char*>(message), message_len);
  ByteVector sig(signature, signature + signature_len);

  auto result = verifyEIP191Message(msg, sig, address);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  return result.value ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_recover_address(
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  char* address_out,
  size_t address_size
) {
  if (!message || !signature || signature_len != 65 || !address_out || address_size < 43) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  std::string msg(reinterpret_cast<const char*>(message), message_len);
  ByteVector sig(signature, signature + signature_len);

  auto result = recoverEIP191Signer(msg, sig);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::strcpy(address_out, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_hash_message(
  const uint8_t* message,
  size_t message_len,
  uint8_t* hash_out
) {
  if (!message || !hash_out) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  ByteVector msg(message, message + message_len);
  Bytes32 hash = hashEIP191Message(msg);
  std::copy(hash.begin(), hash.end(), hash_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_eth_sign_typed_data(
  const char* domain_name,
  const char* domain_version,
  uint64_t chain_id,
  const char* verifying_contract,
  const uint8_t* struct_hash,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!struct_hash || !private_key || !signature_out || signature_size < 65) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  EIP712Domain domain;
  domain.name = domain_name ? domain_name : "";
  domain.version = domain_version ? domain_version : "";
  domain.chainId = chain_id;
  domain.verifyingContract = verifying_contract ? verifying_contract : "";

  Bytes32 hash;
  std::copy(struct_hash, struct_hash + 32, hash.begin());

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  auto result = signEIP712(domain, hash, priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

} // namespace coins
} // namespace hd_wallet
