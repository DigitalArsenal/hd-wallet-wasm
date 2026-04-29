/**
 * @file coin.cpp
 * @brief Base Coin Interface and Utilities Implementation
 */

#include "hd_wallet/coins/coin.h"
#include "hd_wallet/coins/bitcoin.h"
#include "hd_wallet/coins/cosmos.h"
#include "hd_wallet/coins/ethereum.h"
#include "hd_wallet/coins/polkadot.h"
#include "hd_wallet/coins/solana.h"
#include "hd_wallet/secure_rng.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <iomanip>
#include <map>
#include <mutex>

// Crypto++ headers
#include <cryptopp/sha.h>
#include <cryptopp/keccak.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/blake2.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/hex.h>
#include <cryptopp/xed25519.h>

#ifdef HD_WALLET_USE_LIBSECP256K1
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#endif

namespace hd_wallet {
namespace coins {

// =============================================================================
// ECDSASignature Implementation
// =============================================================================

Bytes64 ECDSASignature::toCompact() const {
  Bytes64 result;
  std::copy(r.begin(), r.end(), result.begin());
  std::copy(s.begin(), s.end(), result.begin() + 32);
  return result;
}

Bytes65 ECDSASignature::toRecoverable() const {
  Bytes65 result;
  std::copy(r.begin(), r.end(), result.begin());
  std::copy(s.begin(), s.end(), result.begin() + 32);
  result[64] = v;
  return result;
}

Result<ECDSASignature> ECDSASignature::fromCompact(const Bytes64& sig) {
  ECDSASignature result;
  std::copy(sig.begin(), sig.begin() + 32, result.r.begin());
  std::copy(sig.begin() + 32, sig.end(), result.s.begin());
  result.v = 0;
  return Result<ECDSASignature>::success(std::move(result));
}

Result<ECDSASignature> ECDSASignature::fromRecoverable(const Bytes65& sig) {
  ECDSASignature result;
  std::copy(sig.begin(), sig.begin() + 32, result.r.begin());
  std::copy(sig.begin() + 32, sig.begin() + 64, result.s.begin());
  result.v = sig[64];
  return Result<ECDSASignature>::success(std::move(result));
}

ByteVector ECDSASignature::toDER() const {
  // DER encoding of ECDSA signature
  // 0x30 <total-len> 0x02 <r-len> <r> 0x02 <s-len> <s>
  ByteVector der;

  auto encodeInteger = [](const Bytes32& val) -> ByteVector {
    ByteVector result;
    size_t start = 0;

    // Skip leading zeros
    while (start < 32 && val[start] == 0) start++;

    // Add leading zero if high bit is set (to keep positive)
    if (start < 32 && (val[start] & 0x80)) {
      result.push_back(0x00);
    }

    // Copy remaining bytes
    for (size_t i = start; i < 32; i++) {
      result.push_back(val[i]);
    }

    // Handle zero value
    if (result.empty()) {
      result.push_back(0x00);
    }

    return result;
  };

  ByteVector r_encoded = encodeInteger(r);
  ByteVector s_encoded = encodeInteger(s);

  // Build DER structure
  der.push_back(0x30);  // SEQUENCE
  der.push_back(static_cast<uint8_t>(2 + r_encoded.size() + 2 + s_encoded.size()));

  der.push_back(0x02);  // INTEGER
  der.push_back(static_cast<uint8_t>(r_encoded.size()));
  der.insert(der.end(), r_encoded.begin(), r_encoded.end());

  der.push_back(0x02);  // INTEGER
  der.push_back(static_cast<uint8_t>(s_encoded.size()));
  der.insert(der.end(), s_encoded.begin(), s_encoded.end());

  return der;
}

Result<ECDSASignature> ECDSASignature::fromDER(const ByteVector& der) {
  if (der.size() < 8 || der[0] != 0x30) {
    return Result<ECDSASignature>::fail(Error::INVALID_SIGNATURE);
  }

  size_t pos = 2;  // Skip SEQUENCE tag and length

  auto decodeInteger = [&der, &pos](Bytes32& out) -> bool {
    if (pos >= der.size() || der[pos] != 0x02) return false;
    pos++;

    if (pos >= der.size()) return false;
    size_t len = der[pos++];

    if (pos + len > der.size()) return false;

    // Skip leading zeros
    while (len > 0 && der[pos] == 0) {
      pos++;
      len--;
    }

    // Copy to output (right-aligned)
    std::fill(out.begin(), out.end(), 0);
    size_t copy_len = std::min(len, size_t(32));
    size_t offset = 32 - copy_len;
    for (size_t i = 0; i < copy_len; i++) {
      out[offset + i] = der[pos + i];
    }
    pos += len;

    return true;
  };

  ECDSASignature sig;
  if (!decodeInteger(sig.r) || !decodeInteger(sig.s)) {
    return Result<ECDSASignature>::fail(Error::INVALID_SIGNATURE);
  }

  sig.v = 0;
  return Result<ECDSASignature>::success(std::move(sig));
}

// =============================================================================
// Hash Functions
// =============================================================================

ByteVector hash160(const ByteVector& data) {
  return hash160(data.data(), data.size());
}

ByteVector hash160(const uint8_t* data, size_t len) {
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

Bytes32 doubleSha256(const ByteVector& data) {
  return doubleSha256(data.data(), data.size());
}

Bytes32 doubleSha256(const uint8_t* data, size_t len) {
  CryptoPP::SHA256 sha256;
  Bytes32 result;

  uint8_t first_hash[32];
  sha256.CalculateDigest(first_hash, data, len);
  sha256.CalculateDigest(result.data(), first_hash, 32);

  return result;
}

Bytes32 keccak256(const ByteVector& data) {
  return keccak256(data.data(), data.size());
}

Bytes32 keccak256(const uint8_t* data, size_t len) {
  CryptoPP::Keccak_256 keccak;
  Bytes32 result;
  keccak.CalculateDigest(result.data(), data, len);
  return result;
}

ByteVector blake2b(const ByteVector& data, size_t output_len) {
  ByteVector result(output_len);
  CryptoPP::BLAKE2b blake(static_cast<unsigned int>(output_len));
  blake.CalculateDigest(result.data(), data.data(), data.size());
  return result;
}

Bytes64 sha512(const ByteVector& data) {
  CryptoPP::SHA512 sha;
  Bytes64 result;
  sha.CalculateDigest(result.data(), data.data(), data.size());
  return result;
}

// =============================================================================
// Base58 Implementation
// =============================================================================

namespace {

const char BASE58_ALPHABET[] = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const int8_t BASE58_MAP[] = {
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
  -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
  22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
  -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
  47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1,
};

}  // namespace

std::string base58Encode(const ByteVector& data) {
  if (data.empty()) return "";

  // Count leading zeros
  size_t zeroes = 0;
  for (auto b : data) {
    if (b != 0) break;
    zeroes++;
  }

  // Allocate enough space
  size_t size = (data.size() - zeroes) * 138 / 100 + 1;
  std::vector<uint8_t> b58(size);

  // Process bytes
  for (size_t i = zeroes; i < data.size(); i++) {
    int carry = data[i];
    size_t j = 0;
    for (auto it = b58.rbegin(); (carry != 0 || j < size) && it != b58.rend(); ++it, ++j) {
      carry += 256 * (*it);
      *it = carry % 58;
      carry /= 58;
    }
    size = j;
  }

  // Skip leading zeros in base58 result
  auto it = b58.begin() + (b58.size() - size);
  while (it != b58.end() && *it == 0) ++it;

  // Build result
  std::string result;
  result.reserve(zeroes + (b58.end() - it));
  result.assign(zeroes, '1');
  while (it != b58.end()) {
    result += BASE58_ALPHABET[*it++];
  }

  return result;
}

Result<ByteVector> base58Decode(const std::string& str) {
  if (str.empty()) return Result<ByteVector>::success(ByteVector{});

  // Count leading '1's
  size_t zeroes = 0;
  for (char c : str) {
    if (c != '1') break;
    zeroes++;
  }

  // Allocate enough space
  size_t size = str.size() * 733 / 1000 + 1;
  std::vector<uint8_t> b256(size);

  // Process characters
  for (size_t i = zeroes; i < str.size(); i++) {
    unsigned char c = static_cast<unsigned char>(str[i]);
    if (c >= 128 || BASE58_MAP[c] == -1) {
      return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
    }

    int carry = BASE58_MAP[c];
    size_t j = 0;
    for (auto it = b256.rbegin(); (carry != 0 || j < size) && it != b256.rend(); ++it, ++j) {
      carry += 58 * (*it);
      *it = carry % 256;
      carry /= 256;
    }
    size = j;
  }

  // Skip leading zeros in result
  auto it = b256.begin() + (b256.size() - size);
  while (it != b256.end() && *it == 0) ++it;

  // Build result
  ByteVector result;
  result.reserve(zeroes + (b256.end() - it));
  result.assign(zeroes, 0x00);
  while (it != b256.end()) {
    result.push_back(*it++);
  }

  return Result<ByteVector>::success(std::move(result));
}

std::string base58CheckEncode(const ByteVector& data) {
  // Append checksum (first 4 bytes of double SHA256)
  Bytes32 hash = doubleSha256(data);
  ByteVector with_checksum = data;
  with_checksum.insert(with_checksum.end(), hash.begin(), hash.begin() + 4);

  return base58Encode(with_checksum);
}

Result<ByteVector> base58CheckDecode(const std::string& str) {
  auto decoded = base58Decode(str);
  if (!decoded.ok()) return decoded;

  if (decoded.value.size() < 4) {
    return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
  }

  // Split data and checksum
  ByteVector data(decoded.value.begin(), decoded.value.end() - 4);
  ByteVector checksum(decoded.value.end() - 4, decoded.value.end());

  // Verify checksum
  Bytes32 hash = doubleSha256(data);
  if (!std::equal(checksum.begin(), checksum.end(), hash.begin())) {
    return Result<ByteVector>::fail(Error::INVALID_CHECKSUM);
  }

  return Result<ByteVector>::success(std::move(data));
}

// =============================================================================
// Bech32 Implementation
// =============================================================================

namespace {

const char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

const int8_t BECH32_CHARSET_REV[] = {
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
  15,-1,10,17,21,20,26,30, 7, 5,-1,-1,-1,-1,-1,-1,
  -1,29,-1,24,13,25, 9, 8,23,-1,18,22,31,27,19,-1,
   1, 0, 3,16,11,28,12,14, 6, 4, 2,-1,-1,-1,-1,-1,
  -1,29,-1,24,13,25, 9, 8,23,-1,18,22,31,27,19,-1,
   1, 0, 3,16,11,28,12,14, 6, 4, 2,-1,-1,-1,-1,-1
};

// Bech32 polymod
uint32_t bech32Polymod(const std::vector<uint8_t>& values) {
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
}

// Expand HRP for checksum
std::vector<uint8_t> bech32HrpExpand(const std::string& hrp) {
  std::vector<uint8_t> ret;
  ret.reserve(hrp.size() * 2 + 1);
  for (char c : hrp) {
    ret.push_back(c >> 5);
  }
  ret.push_back(0);
  for (char c : hrp) {
    ret.push_back(c & 31);
  }
  return ret;
}

// Create checksum
std::vector<uint8_t> bech32CreateChecksum(const std::string& hrp, const std::vector<uint8_t>& values, bool bech32m) {
  std::vector<uint8_t> enc = bech32HrpExpand(hrp);
  enc.insert(enc.end(), values.begin(), values.end());
  enc.resize(enc.size() + 6);

  uint32_t mod = bech32Polymod(enc) ^ (bech32m ? 0x2bc830a3 : 1);
  std::vector<uint8_t> ret(6);
  for (size_t i = 0; i < 6; i++) {
    ret[i] = (mod >> (5 * (5 - i))) & 31;
  }
  return ret;
}

// Verify checksum
bool bech32VerifyChecksum(const std::string& hrp, const std::vector<uint8_t>& data, bool& is_bech32m) {
  std::vector<uint8_t> enc = bech32HrpExpand(hrp);
  enc.insert(enc.end(), data.begin(), data.end());
  uint32_t check = bech32Polymod(enc);
  if (check == 1) {
    is_bech32m = false;
    return true;
  }
  if (check == 0x2bc830a3) {
    is_bech32m = true;
    return true;
  }
  return false;
}

// Convert bits
std::vector<uint8_t> convertBits(const std::vector<uint8_t>& data, int frombits, int tobits, bool pad) {
  int acc = 0;
  int bits = 0;
  std::vector<uint8_t> ret;
  int maxv = (1 << tobits) - 1;
  int max_acc = (1 << (frombits + tobits - 1)) - 1;

  for (uint8_t value : data) {
    if (value >> frombits) return {};  // Invalid value
    acc = ((acc << frombits) | value) & max_acc;
    bits += frombits;
    while (bits >= tobits) {
      bits -= tobits;
      ret.push_back((acc >> bits) & maxv);
    }
  }

  if (pad) {
    if (bits) {
      ret.push_back((acc << (tobits - bits)) & maxv);
    }
  } else if (bits >= frombits || ((acc << (tobits - bits)) & maxv)) {
    return {};  // Invalid padding
  }

  return ret;
}

}  // namespace

std::string bech32Encode(const std::string& hrp, const ByteVector& data, uint8_t witness_version) {
  // Convert 8-bit to 5-bit groups
  std::vector<uint8_t> data5 = convertBits(
    std::vector<uint8_t>(data.begin(), data.end()), 8, 5, true
  );
  if (data5.empty() && !data.empty()) return "";

  // Prepend witness version
  data5.insert(data5.begin(), witness_version);

  // Create checksum (bech32 for v0, bech32m for v1+)
  bool bech32m = witness_version > 0;
  std::vector<uint8_t> checksum = bech32CreateChecksum(hrp, data5, bech32m);
  data5.insert(data5.end(), checksum.begin(), checksum.end());

  // Encode
  std::string result = hrp + "1";
  for (uint8_t c : data5) {
    result += BECH32_CHARSET[c];
  }

  return result;
}

Result<std::pair<std::string, ByteVector>> bech32Decode(const std::string& str) {
  // Find separator
  size_t pos = str.rfind('1');
  if (pos == std::string::npos || pos == 0 || pos + 7 > str.size()) {
    return Result<std::pair<std::string, ByteVector>>::fail(Error::INVALID_ADDRESS);
  }

  // Extract HRP (lowercase)
  std::string hrp;
  for (size_t i = 0; i < pos; i++) {
    hrp += std::tolower(static_cast<unsigned char>(str[i]));
  }

  // Decode data
  std::vector<uint8_t> data;
  for (size_t i = pos + 1; i < str.size(); i++) {
    unsigned char c = static_cast<unsigned char>(str[i]);
    if (c >= 128 || BECH32_CHARSET_REV[c] == -1) {
      return Result<std::pair<std::string, ByteVector>>::fail(Error::INVALID_ADDRESS);
    }
    data.push_back(BECH32_CHARSET_REV[c]);
  }

  // Verify checksum
  bool is_bech32m;
  if (!bech32VerifyChecksum(hrp, data, is_bech32m)) {
    return Result<std::pair<std::string, ByteVector>>::fail(Error::INVALID_CHECKSUM);
  }

  // Remove checksum and convert back to 8-bit
  data.resize(data.size() - 6);

  // First byte is witness version
  if (data.empty()) {
    return Result<std::pair<std::string, ByteVector>>::fail(Error::INVALID_ADDRESS);
  }

  uint8_t witness_version = data[0];
  data.erase(data.begin());

  // Check bech32m requirement
  if (witness_version > 0 && !is_bech32m) {
    return Result<std::pair<std::string, ByteVector>>::fail(Error::INVALID_ADDRESS);
  }
  if (witness_version == 0 && is_bech32m) {
    return Result<std::pair<std::string, ByteVector>>::fail(Error::INVALID_ADDRESS);
  }

  // Convert 5-bit to 8-bit
  std::vector<uint8_t> conv = convertBits(data, 5, 8, false);
  if (conv.empty() && !data.empty()) {
    return Result<std::pair<std::string, ByteVector>>::fail(Error::INVALID_ADDRESS);
  }

  return Result<std::pair<std::string, ByteVector>>::success(
    std::make_pair(hrp, ByteVector(conv.begin(), conv.end()))
  );
}

std::string bech32mEncode(const std::string& hrp, const ByteVector& data, uint8_t witness_version) {
  return bech32Encode(hrp, data, witness_version);
}

Result<std::pair<std::string, ByteVector>> bech32mDecode(const std::string& str) {
  return bech32Decode(str);
}

// =============================================================================
// SS58 Implementation
// =============================================================================

namespace {

const uint8_t SS58_PREFIX[] = {'S', 'S', '5', '8', 'P', 'R', 'E'};

ByteVector ss58Checksum(const ByteVector& data) {
  ByteVector to_hash;
  to_hash.insert(to_hash.end(), SS58_PREFIX, SS58_PREFIX + 7);
  to_hash.insert(to_hash.end(), data.begin(), data.end());

  auto hash = blake2b(to_hash, 64);
  return ByteVector(hash.begin(), hash.begin() + 2);
}

}  // namespace

std::string ss58Encode(const ByteVector& public_key, uint16_t network_id) {
  if (public_key.size() != 32) return "";

  ByteVector data;

  // Encode network ID (simple format for 0-63, full format for 64-16383)
  if (network_id < 64) {
    data.push_back(static_cast<uint8_t>(network_id));
  } else {
    // Full format: 01XXXXXX XXXXXXXX (14-bit network ID)
    data.push_back(((network_id & 0x00FC) >> 2) | 0x40);
    data.push_back((network_id >> 8) | ((network_id & 0x0003) << 6));
  }

  // Add public key
  data.insert(data.end(), public_key.begin(), public_key.end());

  // Add checksum
  ByteVector checksum = ss58Checksum(data);
  data.insert(data.end(), checksum.begin(), checksum.end());

  return base58Encode(data);
}

Result<std::pair<uint16_t, ByteVector>> ss58Decode(const std::string& address) {
  auto decoded = base58Decode(address);
  if (!decoded.ok()) return Result<std::pair<uint16_t, ByteVector>>::fail(decoded.error);

  if (decoded.value.size() < 3) {
    return Result<std::pair<uint16_t, ByteVector>>::fail(Error::INVALID_ADDRESS);
  }

  // Decode network ID
  uint16_t network_id;
  size_t prefix_len;

  if ((decoded.value[0] & 0x40) == 0) {
    // Simple format
    network_id = decoded.value[0];
    prefix_len = 1;
  } else {
    // Full format
    if (decoded.value.size() < 4) {
      return Result<std::pair<uint16_t, ByteVector>>::fail(Error::INVALID_ADDRESS);
    }
    network_id = ((decoded.value[0] & 0x3F) << 2) | (decoded.value[1] >> 6) |
                 ((decoded.value[1] & 0x3F) << 8);
    prefix_len = 2;
  }

  // Extract public key and checksum
  if (decoded.value.size() < prefix_len + 32 + 2) {
    return Result<std::pair<uint16_t, ByteVector>>::fail(Error::INVALID_ADDRESS);
  }

  ByteVector public_key(decoded.value.begin() + prefix_len, decoded.value.begin() + prefix_len + 32);
  ByteVector provided_checksum(decoded.value.end() - 2, decoded.value.end());

  // Verify checksum
  ByteVector data_without_checksum(decoded.value.begin(), decoded.value.end() - 2);
  ByteVector expected_checksum = ss58Checksum(data_without_checksum);

  if (provided_checksum != expected_checksum) {
    return Result<std::pair<uint16_t, ByteVector>>::fail(Error::INVALID_CHECKSUM);
  }

  return Result<std::pair<uint16_t, ByteVector>>::success(
    std::make_pair(network_id, std::move(public_key))
  );
}

// =============================================================================
// Hex Encoding
// =============================================================================

std::string toHex(const ByteVector& data, bool prefix) {
  return toHex(data.data(), data.size(), prefix);
}

std::string toHex(const uint8_t* data, size_t len, bool prefix) {
  static const char hex_chars[] = "0123456789abcdef";
  std::string result;
  result.reserve(len * 2 + (prefix ? 2 : 0));

  if (prefix) {
    result += "0x";
  }

  for (size_t i = 0; i < len; i++) {
    result += hex_chars[(data[i] >> 4) & 0x0F];
    result += hex_chars[data[i] & 0x0F];
  }

  return result;
}

Result<ByteVector> fromHex(const std::string& hex) {
  std::string str = hex;

  // Remove 0x prefix if present
  if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
    str = str.substr(2);
  }

  // Must be even length
  if (str.size() % 2 != 0) {
    return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
  }

  ByteVector result;
  result.reserve(str.size() / 2);

  for (size_t i = 0; i < str.size(); i += 2) {
    char c1 = str[i];
    char c2 = str[i + 1];

    uint8_t b1, b2;

    if (c1 >= '0' && c1 <= '9') b1 = c1 - '0';
    else if (c1 >= 'a' && c1 <= 'f') b1 = c1 - 'a' + 10;
    else if (c1 >= 'A' && c1 <= 'F') b1 = c1 - 'A' + 10;
    else return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);

    if (c2 >= '0' && c2 <= '9') b2 = c2 - '0';
    else if (c2 >= 'a' && c2 <= 'f') b2 = c2 - 'a' + 10;
    else if (c2 >= 'A' && c2 <= 'F') b2 = c2 - 'A' + 10;
    else return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);

    result.push_back((b1 << 4) | b2);
  }

  return Result<ByteVector>::success(std::move(result));
}

// =============================================================================
// ECDSA Operations (secp256k1)
// =============================================================================

#ifdef HD_WALLET_USE_LIBSECP256K1

namespace {
/**
 * Get libsecp256k1 context for ECDSA operations (lazy init)
 * Uses SIGN | VERIFY for recoverable signature support
 */
static secp256k1_context* coin_secp256k1_ctx() {
    static secp256k1_context* ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return ctx;
}
} // anonymous namespace

Result<ECDSASignature> ecdsaSign(const Bytes32& hash, const Bytes32& private_key) {
    secp256k1_context* ctx = coin_secp256k1_ctx();

    // Use recoverable signing to get the recovery ID
    secp256k1_ecdsa_recoverable_signature rec_sig;
    if (secp256k1_ecdsa_sign_recoverable(ctx, &rec_sig, hash.data(), private_key.data(), NULL, NULL) != 1) {
        return Result<ECDSASignature>::fail(Error::INVALID_PRIVATE_KEY);
    }

    // Serialize to compact form (r || s) + recid
    uint8_t compact[64];
    int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, compact, &recid, &rec_sig);

    ECDSASignature sig;
    std::copy(compact, compact + 32, sig.r.begin());
    std::copy(compact + 32, compact + 64, sig.s.begin());
    sig.v = static_cast<uint8_t>(recid);

    return Result<ECDSASignature>::success(std::move(sig));
}

Result<bool> ecdsaVerify(const Bytes32& hash, const ECDSASignature& signature, const ByteVector& public_key) {
    secp256k1_context* ctx = coin_secp256k1_ctx();

    if (public_key.size() != 33 && public_key.size() != 65) {
        return Result<bool>::fail(Error::INVALID_PUBLIC_KEY);
    }

    // Parse public key
    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_parse(ctx, &pubkey, public_key.data(), public_key.size()) != 1) {
        return Result<bool>::fail(Error::INVALID_PUBLIC_KEY);
    }

    // Build compact signature from r || s
    uint8_t compact[64];
    std::copy(signature.r.begin(), signature.r.end(), compact);
    std::copy(signature.s.begin(), signature.s.end(), compact + 32);

    // Parse as normal (non-recoverable) signature
    secp256k1_ecdsa_signature sig;
    if (secp256k1_ecdsa_signature_parse_compact(ctx, &sig, compact) != 1) {
        return Result<bool>::fail(Error::INVALID_SIGNATURE);
    }

    // Normalize to low-S
    secp256k1_ecdsa_signature_normalize(ctx, &sig, &sig);

    bool valid = secp256k1_ecdsa_verify(ctx, &sig, hash.data(), &pubkey) == 1;
    return Result<bool>::success(std::move(valid));
}

Result<Bytes33> ecdsaRecover(const Bytes32& hash, const ECDSASignature& signature) {
    secp256k1_context* ctx = coin_secp256k1_ctx();

    int recid = signature.v % 4;

    // Build compact signature from r || s
    uint8_t compact[64];
    std::copy(signature.r.begin(), signature.r.end(), compact);
    std::copy(signature.s.begin(), signature.s.end(), compact + 32);

    // Parse recoverable signature
    secp256k1_ecdsa_recoverable_signature rec_sig;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &rec_sig, compact, recid) != 1) {
        return Result<Bytes33>::fail(Error::INVALID_SIGNATURE);
    }

    // Recover public key
    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(ctx, &pubkey, &rec_sig, hash.data()) != 1) {
        return Result<Bytes33>::fail(Error::INVALID_SIGNATURE);
    }

    // Serialize compressed
    Bytes33 result;
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, result.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED);

    return Result<Bytes33>::success(std::move(result));
}

#else // !HD_WALLET_USE_LIBSECP256K1 - Crypto++ fallback for native builds

Result<ECDSASignature> ecdsaSign(const Bytes32& hash, const Bytes32& private_key) {
  try {
    using namespace CryptoPP;

    // Initialize secp256k1
    ECDSA<ECP, SHA256>::PrivateKey key;
    key.Initialize(ASN1::secp256k1(), Integer(private_key.data(), 32));

    // Create signer with deterministic k (RFC 6979)
    ECDSA<ECP, SHA256>::Signer signer(key);

    // Sign
    SecureRandomGenerator rng;
    size_t sig_len = signer.MaxSignatureLength();
    std::vector<uint8_t> signature(sig_len);
    sig_len = signer.SignMessage(rng, hash.data(), 32, signature.data());
    signature.resize(sig_len);

    // Parse DER signature
    auto parsed = ECDSASignature::fromDER(ByteVector(signature.begin(), signature.end()));
    if (!parsed.ok()) {
      return Result<ECDSASignature>::fail(Error::INVALID_SIGNATURE);
    }

    // Try to determine recovery ID by trying both
    for (uint8_t v = 0; v < 2; v++) {
      parsed.value.v = v;
      auto recovered = ecdsaRecover(hash, parsed.value);
      if (recovered.ok()) {
        // Verify this matches our public key
        Bytes33 our_pubkey;
        const DL_GroupParameters_EC<ECP>& params = key.GetGroupParameters();
        ECP::Point Q = params.ExponentiateBase(key.GetPrivateExponent());
        our_pubkey[0] = Q.y.IsOdd() ? 0x03 : 0x02;
        Q.x.Encode(our_pubkey.data() + 1, 32);

        if (recovered.value == our_pubkey) {
          return parsed;
        }
      }
    }

    // Default to v=0 if we couldn't determine
    parsed.value.v = 0;
    return parsed;
  } catch (const std::exception& e) {
    return Result<ECDSASignature>::fail(Error::INVALID_PRIVATE_KEY);
  }
}

Result<bool> ecdsaVerify(const Bytes32& hash, const ECDSASignature& signature, const ByteVector& public_key) {
  try {
    using namespace CryptoPP;

    if (public_key.size() != 33 && public_key.size() != 65) {
      return Result<bool>::fail(Error::INVALID_PUBLIC_KEY);
    }

    // Initialize secp256k1
    ECDSA<ECP, SHA256>::PublicKey key;
    const DL_GroupParameters_EC<ECP>& params = ECDSA<ECP, SHA256>::PrivateKey().AccessGroupParameters();
    key.AccessGroupParameters().Initialize(ASN1::secp256k1());

    // Decode public key
    ECP::Point Q;
    if (public_key.size() == 33) {
      // Compressed
      bool y_odd = public_key[0] == 0x03;
      Integer x(public_key.data() + 1, 32);
      key.GetGroupParameters().GetCurve().DecodePoint(Q, public_key.data(), public_key.size());
    } else {
      // Uncompressed
      if (public_key[0] != 0x04) {
        return Result<bool>::fail(Error::INVALID_PUBLIC_KEY);
      }
      Integer x(public_key.data() + 1, 32);
      Integer y(public_key.data() + 33, 32);
      Q = ECP::Point(x, y);
    }

    key.SetPublicElement(Q);

    // Create verifier
    ECDSA<ECP, SHA256>::Verifier verifier(key);

    // Convert signature to DER
    ByteVector der_sig = signature.toDER();

    // Verify
    bool valid = verifier.VerifyMessage(hash.data(), 32, der_sig.data(), der_sig.size());
    return Result<bool>::success(std::move(valid));
  } catch (const std::exception& e) {
    return Result<bool>::fail(Error::VERIFICATION_FAILED);
  }
}

Result<Bytes33> ecdsaRecover(const Bytes32& hash, const ECDSASignature& signature) {
  try {
    using namespace CryptoPP;

    // Get curve parameters
    DL_GroupParameters_EC<ECP> params;
    params.Initialize(ASN1::secp256k1());

    Integer p = params.GetCurve().GetField().GetModulus();
    Integer n = params.GetGroupOrder();
    Integer a = params.GetCurve().GetA();
    Integer b = params.GetCurve().GetB();
    ECP::Point G = params.GetSubgroupGenerator();

    // Parse signature components
    Integer r(signature.r.data(), 32);
    Integer s(signature.s.data(), 32);
    uint8_t recid = signature.v % 2;

    if (r.IsZero() || r >= n || s.IsZero() || s >= n) {
      return Result<Bytes33>::fail(Error::INVALID_SIGNATURE);
    }

    // Calculate x coordinate of R
    Integer x = r;

    // Calculate y^2 = x^3 + ax + b (mod p)
    Integer y_squared = (a_exp_b_mod_c(x, 3, p) + a * x + b) % p;

    // Calculate y using modular square root
    Integer y = a_exp_b_mod_c(y_squared, (p + 1) / 4, p);

    // Verify we got a valid y
    if (a_exp_b_mod_c(y, 2, p) != y_squared) {
      return Result<Bytes33>::fail(Error::INVALID_SIGNATURE);
    }

    // Choose correct y based on recovery id
    if ((y.IsOdd() ? 1 : 0) != recid) {
      y = p - y;
    }

    ECP::Point R(x, y);

    // Calculate public key: Q = r^-1 * (s*R - e*G)
    Integer e(hash.data(), 32);
    Integer r_inv = r.InverseMod(n);

    ECP ecp(p, a, b);
    ECP::Point sR = ecp.ScalarMultiply(R, s);
    ECP::Point eG = ecp.ScalarMultiply(G, e);
    ECP::Point diff = ecp.Subtract(sR, eG);
    ECP::Point Q = ecp.ScalarMultiply(diff, r_inv);

    // Encode compressed public key
    Bytes33 result;
    result[0] = Q.y.IsOdd() ? 0x03 : 0x02;
    Q.x.Encode(result.data() + 1, 32);

    return Result<Bytes33>::success(std::move(result));
  } catch (const std::exception& e) {
    return Result<Bytes33>::fail(Error::INVALID_SIGNATURE);
  }
}

#endif // HD_WALLET_USE_LIBSECP256K1

// =============================================================================
// Ed25519 Operations
// =============================================================================

Result<Ed25519Signature> ed25519Sign(const ByteVector& message, const Bytes32& private_key) {
  try {
    using namespace CryptoPP;

    ed25519Signer signer(private_key.data());

    Ed25519Signature sig;
    signer.SignMessage(NullRNG(), message.data(), message.size(), sig.data.data());

    return Result<Ed25519Signature>::success(std::move(sig));
  } catch (const std::exception& e) {
    return Result<Ed25519Signature>::fail(Error::INVALID_PRIVATE_KEY);
  }
}

Result<bool> ed25519Verify(const ByteVector& message, const Ed25519Signature& signature, const Bytes32& public_key) {
  try {
    using namespace CryptoPP;

    ed25519Verifier verifier(public_key.data());
    bool valid = verifier.VerifyMessage(message.data(), message.size(),
                                        signature.data.data(), signature.data.size());
    return Result<bool>::success(std::move(valid));
  } catch (const std::exception& e) {
    return Result<bool>::fail(Error::VERIFICATION_FAILED);
  }
}

Result<Bytes32> ed25519PublicKey(const Bytes32& private_key) {
  try {
    CryptoPP::ed25519Signer signer(private_key.data());
    CryptoPP::ed25519Verifier verifier(signer);

    Bytes32 public_key;
    // Get the public key from the verifier
    const CryptoPP::ed25519PublicKey& pk =
        static_cast<const CryptoPP::ed25519PublicKey&>(verifier.GetPublicKey());
    std::memcpy(public_key.data(), pk.GetPublicKeyBytePtr(), 32);

    return Result<Bytes32>::success(std::move(public_key));
  } catch (const std::exception& e) {
    return Result<Bytes32>::fail(Error::INVALID_PRIVATE_KEY);
  }
}

// =============================================================================
// Coin Base Class Implementation
// =============================================================================

std::string Coin::getDerivationPath(uint32_t account, uint32_t change, uint32_t index) const {
  std::ostringstream path;
  path << "m/" << defaultPurpose() << "'/"
       << static_cast<uint32_t>(coinType()) << "'/"
       << account << "'/"
       << change << "/"
       << index;
  return path.str();
}

// =============================================================================
// Coin Registry
// =============================================================================

namespace {

std::mutex g_coin_registry_mutex;
std::map<std::pair<CoinType, Network>, std::shared_ptr<Coin>> g_coin_registry;

}  // namespace

std::shared_ptr<Coin> getCoin(CoinType type, Network network) {
  std::lock_guard<std::mutex> lock(g_coin_registry_mutex);

  auto key = std::make_pair(type, network);
  auto it = g_coin_registry.find(key);
  if (it != g_coin_registry.end()) {
    return it->second;
  }

  // Create and cache a default instance for supported coins.
  //
  // This enables the generic C APIs (hd_coin_*) to work without requiring
  // callers to explicitly register coin instances at runtime.
  std::shared_ptr<Coin> coin;
  switch (type) {
    case CoinType::BITCOIN:
      coin = std::make_shared<Bitcoin>(network);
      break;

    case CoinType::BITCOIN_TESTNET:
      coin = std::make_shared<Bitcoin>(Network::TESTNET);
      break;

    case CoinType::ETHEREUM:
      coin = std::make_shared<Ethereum>(network);
      break;

    case CoinType::SOLANA:
      coin = std::make_shared<Solana>(network);
      break;

    case CoinType::COSMOS:
      coin = std::make_shared<Cosmos>();
      coin->setNetwork(network);
      break;

    case CoinType::POLKADOT:
      coin = std::make_shared<Polkadot>();
      coin->setNetwork(network);
      break;

    default:
      break;
  }

  if (!coin) {
    return nullptr;
  }

  g_coin_registry[key] = coin;
  return coin;
}

void registerCoin(std::shared_ptr<Coin> coin) {
  if (!coin) return;

  std::lock_guard<std::mutex> lock(g_coin_registry_mutex);
  auto key = std::make_pair(coin->coinType(), coin->network());
  g_coin_registry[key] = coin;
}

// =============================================================================
// C API Implementation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_coin_address_from_pubkey(
  int32_t coin_type,
  int32_t network,
  const uint8_t* public_key,
  size_t pubkey_len,
  char* address_out,
  size_t address_size
) {
  if (!public_key || !address_out || address_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto coin = getCoin(static_cast<CoinType>(coin_type), static_cast<Network>(network));
  if (!coin) {
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
  }

  if (pubkey_len != 33) {
    return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
  }

  Bytes33 pubkey;
  std::copy(public_key, public_key + 33, pubkey.begin());

  auto result = coin->addressFromPublicKey(pubkey);
  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  if (result.value.size() >= address_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(address_out, result.value.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_coin_validate_address(
  int32_t coin_type,
  int32_t network,
  const char* address
) {
  if (!address) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto coin = getCoin(static_cast<CoinType>(coin_type), static_cast<Network>(network));
  if (!coin) {
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
  }

  return static_cast<int32_t>(coin->validateAddress(address));
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_coin_sign_message(
  int32_t coin_type,
  const uint8_t* message,
  size_t message_len,
  const uint8_t* private_key,
  uint8_t* signature_out,
  size_t* signature_len
) {
  if (!message || !private_key || !signature_out || !signature_len) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto coin = getCoin(static_cast<CoinType>(coin_type), Network::MAINNET);
  if (!coin) {
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
  }

  Bytes32 priv;
  std::copy(private_key, private_key + 32, priv.begin());

  ByteVector msg(message, message + message_len);
  auto result = coin->signMessage(msg, priv);
  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  if (result.value.size() > *signature_len) {
    *signature_len = result.value.size();
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::copy(result.value.begin(), result.value.end(), signature_out);
  *signature_len = result.value.size();
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_coin_verify_message(
  int32_t coin_type,
  const uint8_t* message,
  size_t message_len,
  const uint8_t* signature,
  size_t signature_len,
  const uint8_t* public_key,
  size_t pubkey_len
) {
  if (!message || !signature || !public_key) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto coin = getCoin(static_cast<CoinType>(coin_type), Network::MAINNET);
  if (!coin) {
    return static_cast<int32_t>(Error::NOT_SUPPORTED);
  }

  ByteVector msg(message, message + message_len);
  ByteVector sig(signature, signature + signature_len);
  ByteVector pub(public_key, public_key + pubkey_len);

  auto result = coin->verifyMessage(msg, sig, pub);
  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  return result.value ? 1 : 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_base58_encode(
  const uint8_t* data,
  size_t data_len,
  char* output,
  size_t output_size
) {
  if (!data || !output || output_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  ByteVector bytes(data, data + data_len);
  std::string encoded = base58Encode(bytes);

  if (encoded.size() >= output_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(output, encoded.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_base58_decode(
  const char* str,
  uint8_t* output,
  size_t* output_len
) {
  if (!str || !output || !output_len) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = base58Decode(str);
  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  if (result.value.size() > *output_len) {
    *output_len = result.value.size();
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::copy(result.value.begin(), result.value.end(), output);
  *output_len = result.value.size();
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_base58check_encode(
  const uint8_t* data,
  size_t data_len,
  char* output,
  size_t output_size
) {
  if (!data || !output || output_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  ByteVector bytes(data, data + data_len);
  std::string encoded = base58CheckEncode(bytes);

  if (encoded.size() >= output_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(output, encoded.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_base58check_decode(
  const char* str,
  uint8_t* output,
  size_t* output_len
) {
  if (!str || !output || !output_len) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = base58CheckDecode(str);
  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  if (result.value.size() > *output_len) {
    *output_len = result.value.size();
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::copy(result.value.begin(), result.value.end(), output);
  *output_len = result.value.size();
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_bech32_encode(
  const char* hrp,
  const uint8_t* data,
  size_t data_len,
  uint8_t witness_version,
  char* output,
  size_t output_size
) {
  if (!hrp || !data || !output || output_size == 0) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  ByteVector bytes(data, data + data_len);
  std::string encoded = bech32Encode(hrp, bytes, witness_version);

  if (encoded.empty() || encoded.size() >= output_size) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(output, encoded.c_str());
  return static_cast<int32_t>(Error::OK);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_bech32_decode(
  const char* str,
  char* hrp_out,
  size_t hrp_size,
  uint8_t* data_out,
  size_t* data_len
) {
  if (!str || !hrp_out || hrp_size == 0 || !data_out || !data_len) {
    return static_cast<int32_t>(Error::INVALID_ARGUMENT);
  }

  auto result = bech32Decode(str);
  if (!result.ok()) {
    return static_cast<int32_t>(result.error);
  }

  if (result.value.first.size() >= hrp_size || result.value.second.size() > *data_len) {
    return static_cast<int32_t>(Error::INSUFFICIENT_ENTROPY);
  }

  std::strcpy(hrp_out, result.value.first.c_str());
  std::copy(result.value.second.begin(), result.value.second.end(), data_out);
  *data_len = result.value.second.size();
  return static_cast<int32_t>(Error::OK);
}

} // namespace coins
} // namespace hd_wallet
