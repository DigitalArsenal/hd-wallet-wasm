/**
 * @file utils.h
 * @brief Encoding Utilities for HD Wallet
 *
 * Common encoding/decoding utilities used throughout the library:
 * - Base58 and Base58Check (Bitcoin addresses, xprv/xpub)
 * - Bech32 and Bech32m (SegWit addresses)
 * - Hexadecimal encoding
 * - Base64 encoding
 */

#ifndef HD_WALLET_UTILS_H
#define HD_WALLET_UTILS_H

#include "config.h"
#include "types.h"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace hd_wallet {
namespace utils {

// =============================================================================
// Base58 Encoding
// =============================================================================

/**
 * Base58 character set (Bitcoin standard)
 * Excludes: 0, O, I, l to avoid visual ambiguity
 */
constexpr const char* BASE58_ALPHABET =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/**
 * Encode bytes to Base58
 *
 * @param data Input bytes
 * @return Base58-encoded string
 *
 * @example
 * ```cpp
 * ByteVector data = {0x00, 0x01, 0x02};
 * std::string encoded = base58Encode(data);
 * ```
 */
std::string base58Encode(const ByteVector& data);
std::string base58Encode(const uint8_t* data, size_t length);

/**
 * Decode Base58 string to bytes
 *
 * @param str Base58-encoded string
 * @return Result containing decoded bytes or error
 */
Result<ByteVector> base58Decode(const std::string& str);

// =============================================================================
// Base58Check Encoding
// =============================================================================

/**
 * Encode bytes to Base58Check (with version byte and checksum)
 *
 * Format: [version][data][checksum]
 * Checksum: first 4 bytes of SHA256(SHA256(version + data))
 *
 * @param version Version byte (e.g., 0x00 for P2PKH, 0x80 for WIF)
 * @param data Input bytes
 * @return Base58Check-encoded string
 *
 * @example
 * ```cpp
 * // Encode as Bitcoin address (version 0x00)
 * std::string address = base58CheckEncode(0x00, pubkeyHash);
 * ```
 */
std::string base58CheckEncode(uint8_t version, const ByteVector& data);
std::string base58CheckEncode(uint8_t version, const uint8_t* data, size_t length);

/**
 * Encode bytes to Base58Check with 4-byte version prefix
 * Used for extended keys (xprv, xpub, etc.)
 *
 * @param version 4-byte version prefix
 * @param data Input bytes
 * @return Base58Check-encoded string
 */
std::string base58CheckEncode(uint32_t version, const ByteVector& data);

/**
 * Decode Base58Check string
 *
 * @param str Base58Check-encoded string
 * @return Result containing tuple of (version, data) or error
 */
Result<std::pair<uint8_t, ByteVector>> base58CheckDecode(const std::string& str);

/**
 * Verify Base58Check checksum
 *
 * @param str Base58Check-encoded string
 * @return true if checksum is valid
 */
bool base58CheckVerify(const std::string& str);

// =============================================================================
// Bech32 Encoding
// =============================================================================

/**
 * Bech32 encoding variant
 */
enum class Bech32Variant {
    /// Original Bech32 (BIP-173) - SegWit v0
    BECH32 = 1,

    /// Bech32m (BIP-350) - SegWit v1+ (Taproot)
    BECH32M = 2
};

/**
 * Encode data to Bech32/Bech32m
 *
 * @param hrp Human-readable part (e.g., "bc" for Bitcoin mainnet)
 * @param data Witness program (5-bit values)
 * @param variant Bech32 or Bech32m
 * @return Bech32-encoded string
 *
 * @example
 * ```cpp
 * // Encode SegWit v0 address
 * std::string addr = bech32Encode("bc", witnessProgram, Bech32Variant::BECH32);
 * ```
 */
std::string bech32Encode(
    const std::string& hrp,
    const ByteVector& data,
    Bech32Variant variant = Bech32Variant::BECH32
);

/**
 * Decode Bech32/Bech32m string
 *
 * @param str Bech32-encoded string
 * @return Result containing tuple of (hrp, data, variant) or error
 */
struct Bech32DecodeResult {
    std::string hrp;
    ByteVector data;
    Bech32Variant variant;
};
Result<Bech32DecodeResult> bech32Decode(const std::string& str);

/**
 * Encode SegWit address
 *
 * @param hrp Human-readable part ("bc" for mainnet, "tb" for testnet)
 * @param version Witness version (0-16)
 * @param program Witness program (8-bit bytes)
 * @return Bech32-encoded address
 */
Result<std::string> segwitEncode(
    const std::string& hrp,
    uint8_t version,
    const ByteVector& program
);


/**
 * Convert 8-bit bytes to 5-bit groups for Bech32
 */
Result<ByteVector> convertBits(
    const ByteVector& data,
    int fromBits,
    int toBits,
    bool pad = true
);

// =============================================================================
// Hexadecimal Encoding
// =============================================================================

/**
 * Encode bytes to hexadecimal string
 *
 * @param data Input bytes
 * @param uppercase Use uppercase letters (default: false)
 * @return Hexadecimal string
 *
 * @example
 * ```cpp
 * ByteVector data = {0xde, 0xad, 0xbe, 0xef};
 * std::string hex = hexEncode(data);  // "deadbeef"
 * ```
 */
std::string hexEncode(const ByteVector& data, bool uppercase = false);
std::string hexEncode(const uint8_t* data, size_t length, bool uppercase = false);

template<size_t N>
std::string hexEncode(const std::array<uint8_t, N>& data, bool uppercase = false) {
    return hexEncode(data.data(), N, uppercase);
}

/**
 * Decode hexadecimal string to bytes
 *
 * @param str Hexadecimal string (with or without "0x" prefix)
 * @return Result containing decoded bytes or error
 */
Result<ByteVector> hexDecode(const std::string& str);

/**
 * Check if string is valid hexadecimal
 */
bool isValidHex(const std::string& str);

// =============================================================================
// Base64 Encoding
// =============================================================================

/**
 * Base64 encoding variant
 */
enum class Base64Variant {
    /// Standard Base64 (RFC 4648)
    STANDARD = 0,

    /// URL-safe Base64 (RFC 4648 Section 5)
    URL_SAFE = 1
};

/**
 * Encode bytes to Base64
 *
 * @param data Input bytes
 * @param variant Encoding variant (default: standard)
 * @param padding Include padding characters (default: true)
 * @return Base64-encoded string
 *
 * @example
 * ```cpp
 * ByteVector data = {0x01, 0x02, 0x03};
 * std::string b64 = base64Encode(data);  // "AQID"
 * ```
 */
std::string base64Encode(
    const ByteVector& data,
    Base64Variant variant = Base64Variant::STANDARD,
    bool padding = true
);
std::string base64Encode(
    const uint8_t* data,
    size_t length,
    Base64Variant variant = Base64Variant::STANDARD,
    bool padding = true
);

/**
 * Decode Base64 string to bytes
 *
 * @param str Base64-encoded string
 * @param variant Encoding variant (default: standard)
 * @return Result containing decoded bytes or error
 */
Result<ByteVector> base64Decode(
    const std::string& str,
    Base64Variant variant = Base64Variant::STANDARD
);

/**
 * Check if string is valid Base64
 */
bool isValidBase64(const std::string& str, Base64Variant variant = Base64Variant::STANDARD);

// =============================================================================
// Byte Utilities
// =============================================================================

/**
 * Constant-time comparison of byte arrays
 * Prevents timing attacks when comparing sensitive data
 *
 * @param a First byte array
 * @param b Second byte array
 * @param length Length to compare
 * @return true if arrays are equal
 */
bool constantTimeCompare(const uint8_t* a, const uint8_t* b, size_t length);

/**
 * XOR two byte arrays
 *
 * @param a First byte array (modified in place)
 * @param b Second byte array
 * @param length Length to XOR
 */
void xorBytes(uint8_t* a, const uint8_t* b, size_t length);

/**
 * Concatenate byte vectors
 */
ByteVector concat(const ByteVector& a, const ByteVector& b);

/**
 * Slice byte vector
 */
ByteVector slice(const ByteVector& data, size_t start, size_t length);

// =============================================================================
// C API for WASM Bindings
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_encode_base58(
    const uint8_t* data,
    size_t data_len,
    char* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_decode_base58(
    const char* str,
    uint8_t* output,
    size_t* output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_encode_base58check(
    uint8_t version,
    const uint8_t* data,
    size_t data_len,
    char* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_decode_base58check(
    const char* str,
    uint8_t* version_out,
    uint8_t* data_out,
    size_t* data_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_encode_bech32(
    const char* hrp,
    const uint8_t* data,
    size_t data_len,
    int32_t variant,
    char* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_decode_bech32(
    const char* str,
    char* hrp_out,
    size_t hrp_size,
    uint8_t* data_out,
    size_t* data_size,
    int32_t* variant_out
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_encode_hex(
    const uint8_t* data,
    size_t data_len,
    char* output,
    size_t output_size,
    int32_t uppercase
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_decode_hex(
    const char* str,
    uint8_t* output,
    size_t* output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_encode_base64(
    const uint8_t* data,
    size_t data_len,
    int32_t variant,
    int32_t padding,
    char* output,
    size_t output_size
);

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_decode_base64(
    const char* str,
    int32_t variant,
    uint8_t* output,
    size_t* output_size
);

} // namespace utils
} // namespace hd_wallet

#endif // HD_WALLET_UTILS_H
