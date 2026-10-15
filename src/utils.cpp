/**
 * @file utils.cpp
 * @brief Encoding Utilities Implementation
 *
 * Provides encoding/decoding functions for various formats used in cryptocurrency:
 * - Base58/Base58Check (Bitcoin addresses, extended keys)
 * - Bech32/Bech32m (SegWit and Taproot addresses)
 * - Hex encoding
 * - Base64 encoding
 */

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace hd_wallet {
namespace utils {

// =============================================================================
// Base58 Encoding/Decoding
// =============================================================================

namespace {

/// Base58 alphabet (Bitcoin style - no 0, O, I, l)
constexpr char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Reverse lookup table for Base58 decoding
constexpr int8_t BASE58_MAP[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8, -1, -1, -1, -1, -1, -1,
    -1,  9, 10, 11, 12, 13, 14, 15, 16, -1, 17, 18, 19, 20, 21, -1,
    22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, -1, -1, -1, -1, -1,
    -1, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, -1, 44, 45, 46,
    47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

/**
 * Compute double SHA-256 hash (for Base58Check checksum)
 * Returns first 4 bytes as checksum
 */
std::array<uint8_t, 4> doubleSha256Checksum(const uint8_t* data, size_t len);

} // anonymous namespace

/**
 * Encode bytes to Base58
 */
std::string base58Encode(const uint8_t* data, size_t len) {
    if (len == 0) {
        return "";
    }

    // Count leading zeros
    size_t leading_zeros = 0;
    while (leading_zeros < len && data[leading_zeros] == 0) {
        ++leading_zeros;
    }

    // Allocate enough space for the result
    // log(256) / log(58) ~ 1.37, so we need ~1.37x the input size
    size_t output_size = (len - leading_zeros) * 138 / 100 + 1;
    std::vector<uint8_t> output(output_size, 0);

    // Process each byte
    for (size_t i = leading_zeros; i < len; ++i) {
        uint32_t carry = data[i];
        size_t j = 0;

        // Apply "b58 = b58 * 256 + ch"
        for (auto it = output.rbegin(); (carry != 0 || j < output_size) && it != output.rend(); ++it, ++j) {
            carry += 256 * static_cast<uint32_t>(*it);
            *it = static_cast<uint8_t>(carry % 58);
            carry /= 58;
        }
        output_size = j;
    }

    // Skip leading zeros in output
    auto it = output.begin();
    while (it != output.end() && *it == 0) {
        ++it;
    }

    // Build result string
    std::string result;
    result.reserve(leading_zeros + (output.end() - it));

    // Add '1' for each leading zero byte
    result.assign(leading_zeros, '1');

    // Convert to Base58 characters
    while (it != output.end()) {
        result.push_back(BASE58_ALPHABET[*it]);
        ++it;
    }

    return result;
}

std::string base58Encode(const std::vector<uint8_t>& data) {
    return base58Encode(data.data(), data.size());
}

/**
 * Decode Base58 string to bytes
 */
std::vector<uint8_t> base58Decode(const std::string& str) {
    if (str.empty()) {
        return {};
    }

    // Count leading '1's (zeros in output)
    size_t leading_ones = 0;
    while (leading_ones < str.size() && str[leading_ones] == '1') {
        ++leading_ones;
    }

    // Allocate output buffer
    // Each Base58 digit represents log2(58) ~ 5.86 bits
    size_t output_size = (str.size() - leading_ones) * 733 / 1000 + 1;
    std::vector<uint8_t> output(output_size, 0);

    // Process each character
    size_t length = 0;
    for (size_t i = leading_ones; i < str.size(); ++i) {
        uint8_t ch = static_cast<uint8_t>(str[i]);
        int8_t digit = BASE58_MAP[ch];

        if (digit < 0) {
            // Invalid character
            return {};
        }

        uint32_t carry = static_cast<uint32_t>(digit);
        size_t j = 0;

        // Apply "bin = bin * 58 + digit"
        for (auto it = output.rbegin(); (carry != 0 || j < length) && it != output.rend(); ++it, ++j) {
            carry += 58 * static_cast<uint32_t>(*it);
            *it = static_cast<uint8_t>(carry & 0xFF);
            carry >>= 8;
        }
        length = j;
    }

    // Skip leading zeros in output buffer
    auto it = output.begin();
    while (it != output.end() && *it == 0) {
        ++it;
    }

    // Build result with leading zeros
    std::vector<uint8_t> result;
    result.reserve(leading_ones + (output.end() - it));
    result.insert(result.end(), leading_ones, 0);
    result.insert(result.end(), it, output.end());

    return result;
}

// =============================================================================
// Base58Check Encoding/Decoding
// =============================================================================

namespace {

// Forward declaration - implementation uses SHA256 from crypto library
std::array<uint8_t, 4> doubleSha256Checksum(const uint8_t* data, size_t len) {
    // Double SHA-256 implementation
    // We need to compute SHA256(SHA256(data))
    // For now, using a simple implementation - in production, use Crypto++

    // SHA-256 constants
    static constexpr uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    auto rightRotate = [](uint32_t x, uint32_t n) -> uint32_t {
        return (x >> n) | (x << (32 - n));
    };

    auto sha256Hash = [&rightRotate](const uint8_t* message, size_t length) -> std::array<uint8_t, 32> {
        // Initial hash values
        uint32_t h0 = 0x6a09e667, h1 = 0xbb67ae85, h2 = 0x3c6ef372, h3 = 0xa54ff53a;
        uint32_t h4 = 0x510e527f, h5 = 0x9b05688c, h6 = 0x1f83d9ab, h7 = 0x5be0cd19;

        // Pre-processing: adding padding bits
        size_t original_bit_len = length * 8;
        size_t padded_len = ((length + 8) / 64 + 1) * 64;
        std::vector<uint8_t> padded(padded_len, 0);
        std::memcpy(padded.data(), message, length);
        padded[length] = 0x80;

        // Append length in bits as 64-bit big-endian
        for (int i = 0; i < 8; ++i) {
            padded[padded_len - 1 - i] = static_cast<uint8_t>(original_bit_len >> (i * 8));
        }

        // Process each 512-bit chunk
        for (size_t chunk = 0; chunk < padded_len; chunk += 64) {
            uint32_t w[64];

            // Copy chunk into first 16 words
            for (int i = 0; i < 16; ++i) {
                w[i] = (static_cast<uint32_t>(padded[chunk + i * 4]) << 24) |
                       (static_cast<uint32_t>(padded[chunk + i * 4 + 1]) << 16) |
                       (static_cast<uint32_t>(padded[chunk + i * 4 + 2]) << 8) |
                       (static_cast<uint32_t>(padded[chunk + i * 4 + 3]));
            }

            // Extend the first 16 words into the remaining 48 words
            for (int i = 16; i < 64; ++i) {
                uint32_t s0 = rightRotate(w[i-15], 7) ^ rightRotate(w[i-15], 18) ^ (w[i-15] >> 3);
                uint32_t s1 = rightRotate(w[i-2], 17) ^ rightRotate(w[i-2], 19) ^ (w[i-2] >> 10);
                w[i] = w[i-16] + s0 + w[i-7] + s1;
            }

            // Initialize working variables
            uint32_t a = h0, b = h1, c = h2, d = h3;
            uint32_t e = h4, f = h5, g = h6, h = h7;

            // Main loop
            for (int i = 0; i < 64; ++i) {
                uint32_t S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
                uint32_t ch = (e & f) ^ (~e & g);
                uint32_t temp1 = h + S1 + ch + K[i] + w[i];
                uint32_t S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
                uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
                uint32_t temp2 = S0 + maj;

                h = g;
                g = f;
                f = e;
                e = d + temp1;
                d = c;
                c = b;
                b = a;
                a = temp1 + temp2;
            }

            // Add compressed chunk to current hash value
            h0 += a; h1 += b; h2 += c; h3 += d;
            h4 += e; h5 += f; h6 += g; h7 += h;
        }

        // Produce the final hash value (big-endian)
        std::array<uint8_t, 32> hash;
        auto writeWord = [&hash](size_t offset, uint32_t word) {
            hash[offset] = static_cast<uint8_t>(word >> 24);
            hash[offset + 1] = static_cast<uint8_t>(word >> 16);
            hash[offset + 2] = static_cast<uint8_t>(word >> 8);
            hash[offset + 3] = static_cast<uint8_t>(word);
        };
        writeWord(0, h0);
        writeWord(4, h1);
        writeWord(8, h2);
        writeWord(12, h3);
        writeWord(16, h4);
        writeWord(20, h5);
        writeWord(24, h6);
        writeWord(28, h7);

        return hash;
    };

    // First SHA-256
    auto hash1 = sha256Hash(data, len);

    // Second SHA-256
    auto hash2 = sha256Hash(hash1.data(), hash1.size());

    // Return first 4 bytes
    return {hash2[0], hash2[1], hash2[2], hash2[3]};
}

} // anonymous namespace

/**
 * Encode bytes with Base58Check (appends 4-byte checksum)
 */
std::string base58CheckEncode(const uint8_t* data, size_t len) {
    // Compute checksum
    auto checksum = doubleSha256Checksum(data, len);

    // Create payload with checksum appended
    std::vector<uint8_t> payload(len + 4);
    std::memcpy(payload.data(), data, len);
    std::memcpy(payload.data() + len, checksum.data(), 4);

    return base58Encode(payload);
}

std::string base58CheckEncode(const std::vector<uint8_t>& data) {
    return base58CheckEncode(data.data(), data.size());
}

/**
 * Decode Base58Check string, verifying checksum
 * Returns empty vector on failure
 */
std::vector<uint8_t> base58CheckDecode(const std::string& str) {
    auto decoded = base58Decode(str);

    // Must have at least 4 bytes for checksum
    if (decoded.size() < 4) {
        return {};
    }

    // Split data and checksum
    size_t data_len = decoded.size() - 4;
    auto expected_checksum = doubleSha256Checksum(decoded.data(), data_len);

    // Verify checksum
    if (std::memcmp(decoded.data() + data_len, expected_checksum.data(), 4) != 0) {
        return {};
    }

    // Return data without checksum
    decoded.resize(data_len);
    return decoded;
}

// =============================================================================
// Bech32/Bech32m Encoding/Decoding
// =============================================================================

namespace {

/// Bech32 character set
constexpr char BECH32_CHARSET[] = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

/// Bech32 reverse lookup
constexpr int8_t BECH32_REVERSE[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    15, -1, 10, 17, 21, 20, 26, 30,  7,  5, -1, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
    -1, 29, -1, 24, 13, 25,  9,  8, 23, -1, 18, 22, 31, 27, 19, -1,
     1,  0,  3, 16, 11, 28, 12, 14,  6,  4,  2, -1, -1, -1, -1, -1,
};

/// Constants for Bech32 and Bech32m
constexpr uint32_t BECH32_CONST = 1;
constexpr uint32_t BECH32M_CONST = 0x2bc830a3;

/**
 * Compute Bech32 checksum
 */
uint32_t bech32Polymod(const std::vector<uint8_t>& values) {
    static constexpr uint32_t GENERATOR[] = {
        0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3
    };

    uint32_t chk = 1;
    for (uint8_t v : values) {
        uint32_t top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (int i = 0; i < 5; ++i) {
            if ((top >> i) & 1) {
                chk ^= GENERATOR[i];
            }
        }
    }
    return chk;
}

/**
 * Expand HRP for checksum calculation
 */
std::vector<uint8_t> bech32HrpExpand(const std::string& hrp) {
    std::vector<uint8_t> result;
    result.reserve(hrp.size() * 2 + 1);

    for (char c : hrp) {
        result.push_back(static_cast<uint8_t>(c) >> 5);
    }
    result.push_back(0);
    for (char c : hrp) {
        result.push_back(static_cast<uint8_t>(c) & 31);
    }

    return result;
}

/**
 * Create Bech32 checksum
 */
std::vector<uint8_t> bech32CreateChecksum(const std::string& hrp,
                                           const std::vector<uint8_t>& data,
                                           uint32_t spec) {
    auto values = bech32HrpExpand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.insert(values.end(), 6, 0);

    uint32_t polymod = bech32Polymod(values) ^ spec;

    std::vector<uint8_t> checksum(6);
    for (int i = 0; i < 6; ++i) {
        checksum[i] = (polymod >> (5 * (5 - i))) & 31;
    }
    return checksum;
}

/**
 * Verify Bech32 checksum
 */
bool bech32VerifyChecksum(const std::string& hrp,
                          const std::vector<uint8_t>& data,
                          uint32_t& spec) {
    auto values = bech32HrpExpand(hrp);
    values.insert(values.end(), data.begin(), data.end());

    uint32_t polymod = bech32Polymod(values);
    if (polymod == BECH32_CONST) {
        spec = BECH32_CONST;
        return true;
    }
    if (polymod == BECH32M_CONST) {
        spec = BECH32M_CONST;
        return true;
    }
    return false;
}

/**
 * Convert bits for Bech32 encoding
 */
std::vector<uint8_t> convertBits(const std::vector<uint8_t>& data,
                                  int from_bits, int to_bits, bool pad) {
    std::vector<uint8_t> result;
    int acc = 0;
    int bits = 0;
    int maxv = (1 << to_bits) - 1;

    for (uint8_t value : data) {
        if (value < 0 || (value >> from_bits) != 0) {
            return {};
        }
        acc = (acc << from_bits) | value;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            result.push_back((acc >> bits) & maxv);
        }
    }

    if (pad) {
        if (bits > 0) {
            result.push_back((acc << (to_bits - bits)) & maxv);
        }
    } else if (bits >= from_bits || ((acc << (to_bits - bits)) & maxv) != 0) {
        return {};
    }

    return result;
}

} // anonymous namespace

/**
 * Bech32 encoding type
 */
enum class Bech32Type {
    BECH32,
    BECH32M
};

/**
 * Encode data as Bech32/Bech32m
 */
std::string bech32Encode(const std::string& hrp,
                         const std::vector<uint8_t>& data,
                         Bech32Type type) {
    // Convert 8-bit data to 5-bit values
    auto values = convertBits(data, 8, 5, true);
    if (values.empty() && !data.empty()) {
        return "";
    }

    uint32_t spec = (type == Bech32Type::BECH32M) ? BECH32M_CONST : BECH32_CONST;
    auto checksum = bech32CreateChecksum(hrp, values, spec);

    std::string result = hrp + "1";
    result.reserve(result.size() + values.size() + checksum.size());

    for (uint8_t v : values) {
        result.push_back(BECH32_CHARSET[v]);
    }
    for (uint8_t v : checksum) {
        result.push_back(BECH32_CHARSET[v]);
    }

    return result;
}

/**
 * Decode Bech32/Bech32m string
 * Returns empty pair on failure
 */
std::pair<std::string, std::vector<uint8_t>> bech32Decode(const std::string& str,
                                                           Bech32Type* type_out) {
    if (str.empty()) {
        return {"", {}};
    }

    // Check for valid characters and mixed case
    bool has_lower = false, has_upper = false;
    for (char c : str) {
        if (c >= 'a' && c <= 'z') has_lower = true;
        if (c >= 'A' && c <= 'Z') has_upper = true;
        if (c < 33 || c > 126) {
            return {"", {}};
        }
    }
    if (has_lower && has_upper) {
        return {"", {}};
    }

    // Convert to lowercase for processing
    std::string lower = str;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

    // Find separator
    size_t pos = lower.rfind('1');
    if (pos == std::string::npos || pos == 0 || pos + 7 > lower.size()) {
        return {"", {}};
    }

    std::string hrp = lower.substr(0, pos);
    std::string data_part = lower.substr(pos + 1);

    // Decode data part
    std::vector<uint8_t> data;
    data.reserve(data_part.size());
    for (char c : data_part) {
        int8_t v = (static_cast<uint8_t>(c) < sizeof(BECH32_REVERSE))
                       ? BECH32_REVERSE[static_cast<uint8_t>(c)]
                       : -1;
        if (v < 0) {
            return {"", {}};
        }
        data.push_back(static_cast<uint8_t>(v));
    }

    // Verify checksum
    uint32_t spec;
    if (!bech32VerifyChecksum(hrp, data, spec)) {
        return {"", {}};
    }

    if (type_out) {
        *type_out = (spec == BECH32M_CONST) ? Bech32Type::BECH32M : Bech32Type::BECH32;
    }

    // Remove checksum and convert back to 8-bit
    data.resize(data.size() - 6);
    auto result = convertBits(data, 5, 8, false);

    return {hrp, result};
}

/**
 * Encode SegWit address
 */
std::string segwitEncode(const std::string& hrp, int witness_version,
                         const std::vector<uint8_t>& program) {
    if (witness_version < 0 || witness_version > 16) {
        return "";
    }

    // Convert program to 5-bit values
    auto values = convertBits(program, 8, 5, true);
    if (values.empty() && !program.empty()) {
        return "";
    }

    // Prepend witness version
    values.insert(values.begin(), static_cast<uint8_t>(witness_version));

    // Use Bech32m for witness version 1+ (Taproot), Bech32 for version 0
    uint32_t spec = (witness_version == 0) ? BECH32_CONST : BECH32M_CONST;
    auto checksum = bech32CreateChecksum(hrp, values, spec);

    std::string result = hrp + "1";
    for (uint8_t v : values) {
        result.push_back(BECH32_CHARSET[v]);
    }
    for (uint8_t v : checksum) {
        result.push_back(BECH32_CHARSET[v]);
    }

    return result;
}

// =============================================================================
// Hex Encoding/Decoding
// =============================================================================

namespace {

constexpr char HEX_CHARS[] = "0123456789abcdef";

constexpr int8_t HEX_VALUES[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
     0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
};

} // anonymous namespace

/**
 * Encode bytes as hex string
 */
std::string hexEncode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(len * 2);

    for (size_t i = 0; i < len; ++i) {
        result.push_back(HEX_CHARS[data[i] >> 4]);
        result.push_back(HEX_CHARS[data[i] & 0x0F]);
    }

    return result;
}

std::string hexEncode(const std::vector<uint8_t>& data) {
    return hexEncode(data.data(), data.size());
}

/**
 * Decode hex string to bytes
 * Returns empty vector on invalid input
 */
std::vector<uint8_t> hexDecode(const std::string& str) {
    // Handle optional 0x prefix
    size_t start = 0;
    if (str.size() >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        start = 2;
    }

    size_t len = str.size() - start;
    if (len % 2 != 0) {
        return {};
    }

    std::vector<uint8_t> result;
    result.reserve(len / 2);

    for (size_t i = start; i < str.size(); i += 2) {
        uint8_t c1 = static_cast<uint8_t>(str[i]);
        uint8_t c2 = static_cast<uint8_t>(str[i + 1]);

        int8_t v1 = (c1 < sizeof(HEX_VALUES)) ? HEX_VALUES[c1] : -1;
        int8_t v2 = (c2 < sizeof(HEX_VALUES)) ? HEX_VALUES[c2] : -1;

        if (v1 < 0 || v2 < 0) {
            return {};
        }

        result.push_back(static_cast<uint8_t>((v1 << 4) | v2));
    }

    return result;
}

// =============================================================================
// Base64 Encoding/Decoding
// =============================================================================

namespace {

constexpr char BASE64_CHARS[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

constexpr int8_t BASE64_VALUES[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1,
};

} // anonymous namespace

/**
 * Encode bytes as Base64 string
 */
std::string base64Encode(const uint8_t* data, size_t len) {
    std::string result;
    result.reserve(((len + 2) / 3) * 4);

    size_t i = 0;
    while (i + 2 < len) {
        uint32_t val = (static_cast<uint32_t>(data[i]) << 16) |
                       (static_cast<uint32_t>(data[i + 1]) << 8) |
                       static_cast<uint32_t>(data[i + 2]);

        result.push_back(BASE64_CHARS[(val >> 18) & 0x3F]);
        result.push_back(BASE64_CHARS[(val >> 12) & 0x3F]);
        result.push_back(BASE64_CHARS[(val >> 6) & 0x3F]);
        result.push_back(BASE64_CHARS[val & 0x3F]);

        i += 3;
    }

    // Handle remaining bytes
    if (i < len) {
        uint32_t val = static_cast<uint32_t>(data[i]) << 16;
        if (i + 1 < len) {
            val |= static_cast<uint32_t>(data[i + 1]) << 8;
        }

        result.push_back(BASE64_CHARS[(val >> 18) & 0x3F]);
        result.push_back(BASE64_CHARS[(val >> 12) & 0x3F]);

        if (i + 1 < len) {
            result.push_back(BASE64_CHARS[(val >> 6) & 0x3F]);
            result.push_back('=');
        } else {
            result.push_back('=');
            result.push_back('=');
        }
    }

    return result;
}

std::string base64Encode(const std::vector<uint8_t>& data) {
    return base64Encode(data.data(), data.size());
}

/**
 * Decode Base64 string to bytes
 * Returns empty vector on invalid input
 */
std::vector<uint8_t> base64Decode(const std::string& str) {
    if (str.empty()) {
        return {};
    }

    // Remove whitespace
    std::string clean;
    clean.reserve(str.size());
    for (char c : str) {
        if (c != ' ' && c != '\n' && c != '\r' && c != '\t') {
            clean.push_back(c);
        }
    }

    if (clean.size() % 4 != 0) {
        return {};
    }

    // Count padding
    size_t padding = 0;
    if (!clean.empty() && clean.back() == '=') {
        ++padding;
        if (clean.size() >= 2 && clean[clean.size() - 2] == '=') {
            ++padding;
        }
    }

    size_t output_len = (clean.size() / 4) * 3 - padding;
    std::vector<uint8_t> result;
    result.reserve(output_len);

    for (size_t i = 0; i < clean.size(); i += 4) {
        uint32_t val = 0;
        int valid = 0;

        for (int j = 0; j < 4; ++j) {
            char c = clean[i + j];
            if (c == '=') {
                break;
            }

            uint8_t ch = static_cast<uint8_t>(c);
            int8_t v = (ch < sizeof(BASE64_VALUES)) ? BASE64_VALUES[ch] : -1;
            if (v < 0) {
                return {};
            }

            val = (val << 6) | static_cast<uint32_t>(v);
            ++valid;
        }

        // Shift remaining bits
        val <<= (4 - valid) * 6;

        if (valid >= 2) {
            result.push_back(static_cast<uint8_t>((val >> 16) & 0xFF));
        }
        if (valid >= 3) {
            result.push_back(static_cast<uint8_t>((val >> 8) & 0xFF));
        }
        if (valid >= 4) {
            result.push_back(static_cast<uint8_t>(val & 0xFF));
        }
    }

    return result;
}

/**
 * Encode bytes as URL-safe Base64 (no padding, + -> -, / -> _)
 */
std::string base64UrlEncode(const uint8_t* data, size_t len) {
    std::string result = base64Encode(data, len);

    // Replace + with -, / with _
    for (char& c : result) {
        if (c == '+') c = '-';
        else if (c == '/') c = '_';
    }

    // Remove padding
    while (!result.empty() && result.back() == '=') {
        result.pop_back();
    }

    return result;
}

std::string base64UrlEncode(const std::vector<uint8_t>& data) {
    return base64UrlEncode(data.data(), data.size());
}

/**
 * Decode URL-safe Base64 string
 */
std::vector<uint8_t> base64UrlDecode(const std::string& str) {
    // Convert back to standard Base64
    std::string standard = str;
    for (char& c : standard) {
        if (c == '-') c = '+';
        else if (c == '_') c = '/';
    }

    // Add padding if needed
    while (standard.size() % 4 != 0) {
        standard.push_back('=');
    }

    return base64Decode(standard);
}

} // namespace utils
} // namespace hd_wallet
