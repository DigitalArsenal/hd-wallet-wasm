/**
 * @file cosmos.cpp
 * @brief Cosmos/Tendermint Support Implementation
 */

#include "hd_wallet/coins/cosmos.h"

#include <algorithm>
#include <cstring>
#include <sstream>

// Crypto++ headers
#include <cryptopp/sha.h>
#include <cryptopp/ripemd.h>

namespace hd_wallet {
namespace coins {

// =============================================================================
// Cosmos Chain Parameters
// =============================================================================

const CosmosChainParams COSMOS_HUB = {
  .chain_id = "cosmoshub-4",
  .bech32_prefix = "cosmos",
  .bech32_prefix_valoper = "cosmosvaloper",
  .bech32_prefix_pub = "cosmospub",
  .bech32_prefix_valoperpub = "cosmosvaloperpub",
  .denom = "uatom",
  .coin_type = 118,
  .default_gas_price = 0
};

const CosmosChainParams OSMOSIS = {
  .chain_id = "osmosis-1",
  .bech32_prefix = "osmo",
  .bech32_prefix_valoper = "osmovaloper",
  .bech32_prefix_pub = "osmopub",
  .bech32_prefix_valoperpub = "osmovaloperpub",
  .denom = "uosmo",
  .coin_type = 118,
  .default_gas_price = 0
};

const CosmosChainParams TERRA = {
  .chain_id = "phoenix-1",
  .bech32_prefix = "terra",
  .bech32_prefix_valoper = "terravaloper",
  .bech32_prefix_pub = "terrapub",
  .bech32_prefix_valoperpub = "terravalconspub",
  .denom = "uluna",
  .coin_type = 330,
  .default_gas_price = 0
};

const CosmosChainParams JUNO = {
  .chain_id = "juno-1",
  .bech32_prefix = "juno",
  .bech32_prefix_valoper = "junovaloper",
  .bech32_prefix_pub = "junopub",
  .bech32_prefix_valoperpub = "junovaloperpub",
  .denom = "ujuno",
  .coin_type = 118,
  .default_gas_price = 0
};

const CosmosChainParams SECRET = {
  .chain_id = "secret-4",
  .bech32_prefix = "secret",
  .bech32_prefix_valoper = "secretvaloper",
  .bech32_prefix_pub = "secretpub",
  .bech32_prefix_valoperpub = "secretvaloperpub",
  .denom = "uscrt",
  .coin_type = 529,
  .default_gas_price = 0
};

const CosmosChainParams CELESTIA = {
  .chain_id = "celestia",
  .bech32_prefix = "celestia",
  .bech32_prefix_valoper = "celestiavaloper",
  .bech32_prefix_pub = "celestiapub",
  .bech32_prefix_valoperpub = "celestiavalconspub",
  .denom = "utia",
  .coin_type = 118,
  .default_gas_price = 0
};

// =============================================================================
// Cosmos Address Generation
// =============================================================================

namespace {

// Compute SHA256 then RIPEMD160 (different from Bitcoin's hash160 order)
ByteVector cosmosHash160(const uint8_t* data, size_t len) {
  // SHA256
  CryptoPP::SHA256 sha256;
  uint8_t sha256_hash[32];
  sha256.CalculateDigest(sha256_hash, data, len);

  // RIPEMD160
  CryptoPP::RIPEMD160 ripemd160;
  ByteVector result(20);
  ripemd160.CalculateDigest(result.data(), sha256_hash, 32);

  return result;
}

// Bech32 encoding for Cosmos (no witness version, different conversion)
std::string cosmosBech32Encode(const std::string& hrp, const ByteVector& data) {
  // Convert 8-bit to 5-bit groups
  std::vector<uint8_t> converted;
  int acc = 0;
  int bits = 0;

  for (uint8_t value : data) {
    acc = (acc << 8) | value;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      converted.push_back((acc >> bits) & 31);
    }
  }

  if (bits > 0) {
    converted.push_back((acc << (5 - bits)) & 31);
  }

  // Use bech32 encoding with checksum
  // Cosmos uses standard bech32 (not bech32m)
  static const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

  // Polymod helper
  auto polymod = [](const std::vector<uint8_t>& values) -> uint32_t {
    const uint32_t GENERATOR[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t v : values) {
      uint8_t top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (int i = 0; i < 5; i++) {
        chk ^= ((top >> i) & 1) ? GENERATOR[i] : 0;
      }
    }
    return chk;
  };

  // Expand HRP
  std::vector<uint8_t> expanded;
  for (char c : hrp) {
    expanded.push_back(c >> 5);
  }
  expanded.push_back(0);
  for (char c : hrp) {
    expanded.push_back(c & 31);
  }

  // Add data
  expanded.insert(expanded.end(), converted.begin(), converted.end());

  // Add placeholder for checksum
  expanded.resize(expanded.size() + 6);

  // Compute checksum
  uint32_t mod = polymod(expanded) ^ 1;
  std::vector<uint8_t> checksum(6);
  for (size_t i = 0; i < 6; i++) {
    checksum[i] = (mod >> (5 * (5 - i))) & 31;
  }

  // Build result
  std::string result = hrp + "1";
  for (uint8_t c : converted) {
    result += BECH32_CHARSET[c];
  }
  for (uint8_t c : checksum) {
    result += BECH32_CHARSET[c];
  }

  return result;
}

// Bech32 decoding for Cosmos
Result<std::pair<std::string, ByteVector>> cosmosBech32Decode(const std::string& str) {
  // Find separator
  size_t pos = str.rfind('1');
  if (pos == std::string::npos || pos == 0 || pos + 7 > str.size()) {
    return Result<std::pair<std::string, ByteVector>>::fail(Error::INVALID_ADDRESS);
  }

  // Extract HRP
  std::string hrp;
  for (size_t i = 0; i < pos; i++) {
    hrp += std::tolower(static_cast<unsigned char>(str[i]));
  }

  // Decode data
  static const int8_t BECH32_CHARSET_REV[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    15,-1,10,17,21,20,26,30, 7, 5,-1,-1,-1,-1,-1,-1,
    -1,29,-1,24,13,25, 9, 8,23,-1,18,22,31,27,19,-1,
     1, 0, 3,16,11,28,12,14, 6, 4, 2,-1,-1,-1,-1,-1,
    -1,29,-1,24,13,25, 9, 8,23,-1,18,22,31,27,19,-1,
     1, 0, 3,16,11,28,12,14, 6, 4, 2,-1,-1,-1,-1,-1
  };

  std::vector<uint8_t> data;
  for (size_t i = pos + 1; i < str.size(); i++) {
    unsigned char c = static_cast<unsigned char>(str[i]);
    if (c >= 128 || BECH32_CHARSET_REV[c] == -1) {
      return Result<std::pair<std::string, ByteVector>>::fail(Error::INVALID_ADDRESS);
    }
    data.push_back(BECH32_CHARSET_REV[c]);
  }

  // Verify checksum
  auto polymod = [](const std::vector<uint8_t>& values) -> uint32_t {
    const uint32_t GENERATOR[] = {0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3};
    uint32_t chk = 1;
    for (uint8_t v : values) {
      uint8_t top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (int i = 0; i < 5; i++) {
        chk ^= ((top >> i) & 1) ? GENERATOR[i] : 0;
      }
    }
    return chk;
  };

  std::vector<uint8_t> expanded;
  for (char c : hrp) {
    expanded.push_back(c >> 5);
  }
  expanded.push_back(0);
  for (char c : hrp) {
    expanded.push_back(c & 31);
  }
  expanded.insert(expanded.end(), data.begin(), data.end());

  if (polymod(expanded) != 1) {
    return Result<std::pair<std::string, ByteVector>>::fail(Error::INVALID_CHECKSUM);
  }

  // Remove checksum
  data.resize(data.size() - 6);

  // Convert 5-bit to 8-bit
  ByteVector result;
  int acc = 0;
  int bits = 0;

  for (uint8_t value : data) {
    acc = (acc << 5) | value;
    bits += 5;
    while (bits >= 8) {
      bits -= 8;
      result.push_back((acc >> bits) & 255);
    }
  }

  return Result<std::pair<std::string, ByteVector>>::success(
    std::make_pair(hrp, std::move(result))
  );
}

}  // namespace

Result<std::string> cosmosAddress(const Bytes33& public_key, const std::string& prefix) {
  // Hash160 of the compressed public key
  ByteVector addr_bytes = cosmosHash160(public_key.data(), public_key.size());

  // Bech32 encode
  return Result<std::string>::success(cosmosBech32Encode(prefix, addr_bytes));
}

Result<std::string> cosmosAddress(const Bytes33& public_key, const CosmosChainParams& params) {
  return cosmosAddress(public_key, params.bech32_prefix);
}

Result<std::string> cosmosValoperAddress(const Bytes33& public_key, const std::string& prefix) {
  ByteVector addr_bytes = cosmosHash160(public_key.data(), public_key.size());
  return Result<std::string>::success(cosmosBech32Encode(prefix, addr_bytes));
}

Result<std::string> convertCosmosPrefix(const std::string& address, const std::string& new_prefix) {
  auto decoded = cosmosBech32Decode(address);
  if (!decoded.ok()) {
    return Result<std::string>::fail(decoded.error);
  }

  return Result<std::string>::success(cosmosBech32Encode(new_prefix, decoded.value.second));
}

// =============================================================================
// Cosmos Address Validation
// =============================================================================

Error validateCosmosAddress(const std::string& address, const std::string& expected_prefix) {
  auto decoded = cosmosBech32Decode(address);
  if (!decoded.ok()) {
    return decoded.error;
  }

  // Check prefix if specified
  if (!expected_prefix.empty() && decoded.value.first != expected_prefix) {
    return Error::INVALID_ADDRESS;
  }

  // Standard Cosmos address is 20 bytes
  if (decoded.value.second.size() != 20) {
    return Error::INVALID_ADDRESS;
  }

  return Error::OK;
}

Result<std::string> extractCosmosPrefix(const std::string& address) {
  size_t pos = address.find('1');
  if (pos == std::string::npos || pos == 0) {
    return Result<std::string>::fail(Error::INVALID_ADDRESS);
  }

  std::string prefix = address.substr(0, pos);
  std::transform(prefix.begin(), prefix.end(), prefix.begin(),
                 [](unsigned char c) { return std::tolower(c); });

  return Result<std::string>::success(std::move(prefix));
}

bool isCosmosChainAddress(const std::string& address, const CosmosChainParams& params) {
  auto prefix = extractCosmosPrefix(address);
  if (!prefix.ok()) return false;

  return prefix.value == params.bech32_prefix ||
         prefix.value == params.bech32_prefix_valoper;
}

// =============================================================================
// Amino Signing
// =============================================================================

Result<ByteVector> signAmino(const ByteVector& sign_doc, const Bytes32& private_key) {
  // SHA256 hash of the sign document
  CryptoPP::SHA256 sha256;
  Bytes32 hash;
  sha256.CalculateDigest(hash.data(), sign_doc.data(), sign_doc.size());

  // Sign with ECDSA secp256k1
  auto sig = ecdsaSign(hash, private_key);
  if (!sig.ok()) {
    return Result<ByteVector>::fail(sig.error);
  }

  // Return 64-byte signature (r || s)
  ByteVector result(64);
  std::copy(sig.value.r.begin(), sig.value.r.end(), result.begin());
  std::copy(sig.value.s.begin(), sig.value.s.end(), result.begin() + 32);

  return Result<ByteVector>::success(std::move(result));
}

ByteVector createAminoSignDoc(
  const std::string& chain_id,
  uint64_t account_number,
  uint64_t sequence,
  const std::string& fee_json,
  const std::string& msgs_json,
  const std::string& memo
) {
  // Create canonical JSON
  // Format: {"account_number":"..","chain_id":"..","fee":..,"memo":"..","msgs":[..],"sequence":".."}
  std::ostringstream json;
  json << "{\"account_number\":\"" << account_number << "\","
       << "\"chain_id\":\"" << chain_id << "\","
       << "\"fee\":" << fee_json << ","
       << "\"memo\":\"" << memo << "\","
       << "\"msgs\":" << msgs_json << ","
       << "\"sequence\":\"" << sequence << "\"}";

  std::string doc = json.str();
  return ByteVector(doc.begin(), doc.end());
}

Result<ByteVector> signAminoTransaction(
  const std::string& chain_id,
  uint64_t account_number,
  uint64_t sequence,
  const std::string& fee_json,
  const std::string& msgs_json,
  const std::string& memo,
  const Bytes32& private_key
) {
  ByteVector sign_doc = createAminoSignDoc(chain_id, account_number, sequence, fee_json, msgs_json, memo);
  return signAmino(sign_doc, private_key);
}

Result<bool> verifyAminoSignature(
  const ByteVector& sign_doc,
  const ByteVector& signature,
  const Bytes33& public_key
) {
  if (signature.size() != 64) {
    return Result<bool>::fail(Error::INVALID_SIGNATURE);
  }

  // SHA256 hash of the sign document
  CryptoPP::SHA256 sha256;
  Bytes32 hash;
  sha256.CalculateDigest(hash.data(), sign_doc.data(), sign_doc.size());

  // Parse signature
  ECDSASignature sig;
  std::copy(signature.begin(), signature.begin() + 32, sig.r.begin());
  std::copy(signature.begin() + 32, signature.end(), sig.s.begin());
  sig.v = 0;

  // Verify
  ByteVector pubkey(public_key.begin(), public_key.end());
  return ecdsaVerify(hash, sig, pubkey);
}

// =============================================================================
// Direct Signing (Protobuf)
// =============================================================================

Result<ByteVector> signDirect(const ByteVector& sign_doc_bytes, const Bytes32& private_key) {
  // SHA256 hash of the protobuf SignDoc
  CryptoPP::SHA256 sha256;
  Bytes32 hash;
  sha256.CalculateDigest(hash.data(), sign_doc_bytes.data(), sign_doc_bytes.size());

  // Sign with ECDSA secp256k1
  auto sig = ecdsaSign(hash, private_key);
  if (!sig.ok()) {
    return Result<ByteVector>::fail(sig.error);
  }

  // Return 64-byte signature (r || s)
  ByteVector result(64);
  std::copy(sig.value.r.begin(), sig.value.r.end(), result.begin());
  std::copy(sig.value.s.begin(), sig.value.s.end(), result.begin() + 32);

  return Result<ByteVector>::success(std::move(result));
}

ByteVector createDirectSignDoc(
  const ByteVector& body_bytes,
  const ByteVector& auth_info_bytes,
  const std::string& chain_id,
  uint64_t account_number
) {
  // Create protobuf SignDoc
  // This is a simplified version - full implementation would use protobuf
  // SignDoc { body_bytes, auth_info_bytes, chain_id, account_number }

  ByteVector doc;

  // Field 1: body_bytes (bytes)
  doc.push_back(0x0a);  // Field 1, wire type 2 (length-delimited)
  // Varint length
  size_t len = body_bytes.size();
  while (len >= 0x80) {
    doc.push_back((len & 0x7F) | 0x80);
    len >>= 7;
  }
  doc.push_back(len);
  doc.insert(doc.end(), body_bytes.begin(), body_bytes.end());

  // Field 2: auth_info_bytes (bytes)
  doc.push_back(0x12);  // Field 2, wire type 2
  len = auth_info_bytes.size();
  while (len >= 0x80) {
    doc.push_back((len & 0x7F) | 0x80);
    len >>= 7;
  }
  doc.push_back(len);
  doc.insert(doc.end(), auth_info_bytes.begin(), auth_info_bytes.end());

  // Field 3: chain_id (string)
  doc.push_back(0x1a);  // Field 3, wire type 2
  len = chain_id.size();
  while (len >= 0x80) {
    doc.push_back((len & 0x7F) | 0x80);
    len >>= 7;
  }
  doc.push_back(len);
  doc.insert(doc.end(), chain_id.begin(), chain_id.end());

  // Field 4: account_number (uint64)
  doc.push_back(0x20);  // Field 4, wire type 0 (varint)
  uint64_t val = account_number;
  while (val >= 0x80) {
    doc.push_back((val & 0x7F) | 0x80);
    val >>= 7;
  }
  doc.push_back(val);

  return doc;
}

Result<bool> verifyDirectSignature(
  const ByteVector& sign_doc_bytes,
  const ByteVector& signature,
  const Bytes33& public_key
) {
  if (signature.size() != 64) {
    return Result<bool>::fail(Error::INVALID_SIGNATURE);
  }

  // SHA256 hash
  CryptoPP::SHA256 sha256;
  Bytes32 hash;
  sha256.CalculateDigest(hash.data(), sign_doc_bytes.data(), sign_doc_bytes.size());

  // Parse signature
  ECDSASignature sig;
  std::copy(signature.begin(), signature.begin() + 32, sig.r.begin());
  std::copy(signature.begin() + 32, signature.end(), sig.s.begin());
  sig.v = 0;

  // Verify
  ByteVector pubkey(public_key.begin(), public_key.end());
  return ecdsaVerify(hash, sig, pubkey);
}

// =============================================================================
// Arbitrary Message Signing (ADR-036)
// =============================================================================

Result<ByteVector> signArbitrary(
  const std::string& signer,
  const ByteVector& data,
  const Bytes32& private_key
) {
  // ADR-036 format
  // Create sign doc with MsgSignData
  std::string data_base64;  // Would need to base64 encode data here

  // For simplicity, we'll hash the signer + data directly
  // A full implementation would create proper ADR-036 JSON
  ByteVector to_sign;
  to_sign.insert(to_sign.end(), signer.begin(), signer.end());
  to_sign.insert(to_sign.end(), data.begin(), data.end());

  return signAmino(to_sign, private_key);
}

Result<bool> verifyArbitrary(
  const std::string& signer,
  const ByteVector& data,
  const ByteVector& signature,
  const Bytes33& public_key
) {
  ByteVector to_verify;
  to_verify.insert(to_verify.end(), signer.begin(), signer.end());
  to_verify.insert(to_verify.end(), data.begin(), data.end());

  return verifyAminoSignature(to_verify, signature, public_key);
}

// =============================================================================
// Public Key Encoding
// =============================================================================

ByteVector encodeCosmosPublicKey(const Bytes33& public_key) {
  // Amino encoding for secp256k1 public key
  // Type prefix: eb5ae987 + length byte + public key
  ByteVector encoded;

  // Amino type prefix for secp256k1 pubkey
  encoded.push_back(0xeb);
  encoded.push_back(0x5a);
  encoded.push_back(0xe9);
  encoded.push_back(0x87);

  // Length (33 bytes)
  encoded.push_back(0x21);

  // Public key
  encoded.insert(encoded.end(), public_key.begin(), public_key.end());

  return encoded;
}

std::string cosmosPublicKeyBech32(const Bytes33& public_key, const std::string& prefix) {
  ByteVector encoded = encodeCosmosPublicKey(public_key);
  return cosmosBech32Encode(prefix, encoded);
}

// =============================================================================
// Cosmos Coin Implementation
// =============================================================================

Cosmos::Cosmos(const CosmosChainParams& params)
  : network_(Network::MAINNET),
    params_(params),
    prefix_(params.bech32_prefix),
    slip44_coin_type_(params.coin_type) {
}

Cosmos::Cosmos(const std::string& prefix, uint32_t coin_type)
  : network_(Network::MAINNET),
    params_(COSMOS_HUB),
    prefix_(prefix),
    slip44_coin_type_(coin_type) {
}

Result<std::string> Cosmos::addressFromPublicKey(const Bytes33& public_key) const {
  return cosmosAddress(public_key, prefix_);
}

Result<std::string> Cosmos::valoperAddressFromPublicKey(const Bytes33& public_key) const {
  return cosmosValoperAddress(public_key, params_.bech32_prefix_valoper);
}

Error Cosmos::validateAddress(const std::string& address) const {
  return validateCosmosAddress(address, prefix_);
}

Result<DecodedAddress> Cosmos::decodeAddress(const std::string& address) const {
  auto decoded = cosmosBech32Decode(address);
  if (!decoded.ok()) {
    return Result<DecodedAddress>::fail(decoded.error);
  }

  DecodedAddress result;
  result.address = address;
  result.network = network_;
  result.version = 0;
  result.data = decoded.value.second;

  return Result<DecodedAddress>::success(std::move(result));
}

Result<ByteVector> Cosmos::signMessage(const ByteVector& message, const Bytes32& private_key) const {
  // Generate address for ADR-036 signing
  // First derive public key
  auto pubkey = bip32::publicKeyFromPrivate(private_key, Curve::SECP256K1);
  if (!pubkey.ok()) {
    return Result<ByteVector>::fail(pubkey.error);
  }

  auto addr = addressFromPublicKey(pubkey.value);
  if (!addr.ok()) {
    return Result<ByteVector>::fail(addr.error);
  }

  return signArbitrary(addr.value, message, private_key);
}

Result<bool> Cosmos::verifyMessage(
  const ByteVector& message,
  const ByteVector& signature,
  const ByteVector& public_key
) const {
  if (public_key.size() != 33) {
    return Result<bool>::fail(Error::INVALID_PUBLIC_KEY);
  }

  Bytes33 pubkey;
  std::copy(public_key.begin(), public_key.end(), pubkey.begin());

  auto addr = addressFromPublicKey(pubkey);
  if (!addr.ok()) {
    return Result<bool>::fail(addr.error);
  }

  return verifyArbitrary(addr.value, message, signature, pubkey);
}

Result<ByteVector> Cosmos::signAminoTx(const ByteVector& sign_doc, const Bytes32& private_key) const {
  return signAmino(sign_doc, private_key);
}

Result<ByteVector> Cosmos::signDirectTx(const ByteVector& sign_doc_bytes, const Bytes32& private_key) const {
  return signDirect(sign_doc_bytes, private_key);
}

std::string Cosmos::getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const {
  std::ostringstream path;
  path << "m/44'/" << slip44_coin_type_ << "'/" << account << "'/" << change << "/" << index;
  return path.str();
}

// =============================================================================
// C API Implementation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_address(
  const uint8_t* public_key,
  size_t pubkey_len,
  const char* prefix,
  char* address_out,
  size_t address_size
) {
  if (!public_key || pubkey_len != 33 || !prefix || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes33 pubkey;
  std::copy(public_key, public_key + 33, pubkey.begin());

  auto result = cosmosAddress(pubkey, prefix);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.size() >= address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(address_out, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_validate_address(
  const char* address,
  const char* expected_prefix
) {
  if (!address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  return static_cast<int32_t>(validateCosmosAddress(address, expected_prefix ? expected_prefix : ""));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_convert_prefix(
  const char* address,
  const char* new_prefix,
  char* output,
  size_t output_size
) {
  if (!address || !new_prefix || !output || output_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = convertCosmosPrefix(address, new_prefix);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  if (result.value.size() >= output_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(output, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_sign_amino(
  const uint8_t* sign_doc,
  size_t sign_doc_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!sign_doc || !private_key || !signature_out || signature_size < 64) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  ByteVector doc(sign_doc, sign_doc + sign_doc_len);
  auto result = signAmino(doc, priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_sign_direct(
  const uint8_t* sign_doc_bytes,
  size_t sign_doc_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!sign_doc_bytes || !private_key || !signature_out || signature_size < 64) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  ByteVector doc(sign_doc_bytes, sign_doc_bytes + sign_doc_len);
  auto result = signDirect(doc, priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_verify_signature(
  const uint8_t* sign_doc,
  size_t sign_doc_len,
  const uint8_t* signature,
  size_t signature_len,
  const uint8_t* public_key,
  size_t pubkey_len
) {
  if (!sign_doc || !signature || signature_len != 64 || !public_key || pubkey_len != 33) {
    return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes33 pubkey;
  std::copy(public_key, public_key + 33, pubkey.begin());

  ByteVector doc(sign_doc, sign_doc + sign_doc_len);
  ByteVector sig(signature, signature + signature_len);

  auto result = verifyAminoSignature(doc, sig, pubkey);
  if (!result.ok()) return -static_cast<int32_t>(result.error);

  return result.value ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_cosmos_sign_arbitrary(
  const char* signer,
  const uint8_t* data,
  size_t data_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t signature_size
) {
  if (!signer || !data || !private_key || !signature_out || signature_size < 64) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  ByteVector msg(data, data + data_len);
  auto result = signArbitrary(signer, msg, priv);
  if (!result.ok()) return static_cast<int32_t>(result.error);

  std::copy(result.value.begin(), result.value.end(), signature_out);
  return static_cast<int32_t>(Error::OK);
}

} // namespace coins
} // namespace hd_wallet
