/**
 * @file bip32.cpp
 * @brief BIP-32 Hierarchical Deterministic Keys Implementation
 *
 * Implementation of BIP-32: Hierarchical Deterministic Wallets.
 * https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
 */

#include "hd_wallet/bip32.h"

#include <algorithm>
#include <atomic>
#include <cstring>
#include <sstream>
#include <stdexcept>

#if HD_WALLET_USE_CRYPTOPP
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/eccrypto.h>
#if !HD_WALLET_IS_WASI
#include <cryptopp/osrng.h>
#endif
#include <cryptopp/oids.h>
#include <cryptopp/asn.h>
#include <cryptopp/integer.h>
#include <cryptopp/modarith.h>
#include <cryptopp/secblock.h>
#endif

#if HD_WALLET_USE_LIBSECP256K1
#include <secp256k1.h>
#endif

namespace hd_wallet {
namespace bip32 {

// =============================================================================
// Forward Declarations
// =============================================================================

static void secureWipe(void* ptr, size_t size);
static ByteVector hmacSha512(const ByteVector& key, const ByteVector& data);
static CryptoPP::SecByteBlock hmacSha512Secure(const ByteVector& key, const ByteVector& data);
static Bytes32 sha256(const uint8_t* data, size_t size);
static Bytes32 doubleSha256(const uint8_t* data, size_t size);
static ByteVector hash160(const uint8_t* data, size_t size);
static std::string base58EncodeOptimized(const ByteVector& data);
static ByteVector base58Decode(const std::string& str);
static std::string base58CheckEncode(const ByteVector& data);
static Result<ByteVector> base58CheckDecode(const std::string& str);
static bool isValidPrivateKey(const Bytes32& key);
static Result<Bytes32> addPrivateKeys(const Bytes32& key1, const Bytes32& key2);
static Result<Bytes33> addPublicKeys(const Bytes33& pubkey1, const Bytes33& pubkey2);

// secp256k1 curve order (n)
static const uint8_t SECP256K1_ORDER[] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B,
    0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41
};

// Base58 alphabet
static const char BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Reverse lookup for Base58 decoding
static const int8_t BASE58_MAP[] = {
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8,-1,-1,-1,-1,-1,-1,
    -1, 9,10,11,12,13,14,15,16,-1,17,18,19,20,21,-1,
    22,23,24,25,26,27,28,29,30,31,32,-1,-1,-1,-1,-1,
    -1,33,34,35,36,37,38,39,40,41,42,43,-1,44,45,46,
    47,48,49,50,51,52,53,54,55,56,57,-1,-1,-1,-1,-1
};

// =============================================================================
// Secure Memory Wiping
// =============================================================================

/**
 * Securely wipe memory to prevent sensitive data from remaining in RAM
 * Uses volatile pointer to prevent compiler optimization
 */
static void secureWipe(void* ptr, size_t size) {
    if (ptr == nullptr || size == 0) return;

#if HD_WALLET_SECURE_WIPE
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    while (size--) {
        *p++ = 0;
    }
    // Memory barrier to ensure wipe is complete
    std::atomic_thread_fence(std::memory_order_seq_cst);
#else
    std::memset(ptr, 0, size);
#endif
}

/**
 * SECURITY FIX [HIGH-03]: Constant-time memory comparison
 *
 * Compares two memory regions in constant time to prevent timing attacks.
 * Traditional memcmp/std::equal return early on first difference, which can
 * leak information about the comparison through timing side-channels.
 *
 * @param a First memory region
 * @param b Second memory region
 * @param size Number of bytes to compare
 * @return true if equal, false otherwise
 */
static bool secureCompare(const void* a, const void* b, size_t size) {
    if (size == 0) return true;
    if (a == nullptr || b == nullptr) return false;

    const volatile uint8_t* va = static_cast<const volatile uint8_t*>(a);
    const volatile uint8_t* vb = static_cast<const volatile uint8_t*>(b);

    volatile uint8_t diff = 0;

    // XOR all bytes together - any difference will show up in diff
    for (size_t i = 0; i < size; ++i) {
        diff |= va[i] ^ vb[i];
    }

    // Return true only if no differences found
    return diff == 0;
}

// =============================================================================
// Cryptographic Primitives using Crypto++
// =============================================================================

#if HD_WALLET_USE_CRYPTOPP

/**
 * HMAC-SHA512 using Crypto++
 *
 * SECURITY FIX [VULN-06]: Use CryptoPP::SecByteBlock instead of plain ByteVector
 * for the result, since bytes 0-31 contain child private keys during BIP-32
 * derivation. SecByteBlock auto-wipes on destruction.
 */
static CryptoPP::SecByteBlock hmacSha512Secure(const ByteVector& key, const ByteVector& data) {
    CryptoPP::SecByteBlock result(64);
    CryptoPP::HMAC<CryptoPP::SHA512> hmac(key.data(), key.size());
    hmac.Update(data.data(), data.size());
    hmac.Final(result.data());
    return result;
}

// Backward-compatible wrapper that returns ByteVector (for non-sensitive uses)
static ByteVector hmacSha512(const ByteVector& key, const ByteVector& data) {
    auto secure = hmacSha512Secure(key, data);
    ByteVector result(secure.begin(), secure.end());
    return result;
}

/**
 * SHA256 hash using Crypto++
 */
static Bytes32 sha256(const uint8_t* data, size_t size) {
    Bytes32 result;
    CryptoPP::SHA256 hash;
    hash.Update(data, size);
    hash.Final(result.data());
    return result;
}

/**
 * Double SHA256 (SHA256(SHA256(data)))
 */
static Bytes32 doubleSha256(const uint8_t* data, size_t size) {
    Bytes32 first = sha256(data, size);
    return sha256(first.data(), first.size());
}

/**
 * RIPEMD160(SHA256(data)) - HASH160
 */
static ByteVector hash160(const uint8_t* data, size_t size) {
    // First SHA256
    Bytes32 sha256Hash = sha256(data, size);

    // Then RIPEMD160
    ByteVector result(20);
    CryptoPP::RIPEMD160 ripemd;
    ripemd.Update(sha256Hash.data(), sha256Hash.size());
    ripemd.Final(result.data());
    return result;
}

#if HD_WALLET_USE_LIBSECP256K1

// =============================================================================
// secp256k1 EC Operations via libsecp256k1 (Bitcoin Core)
//
// Replaces Crypto++ ECP in WASM builds. Crypto++ ScalarMultiply is unreliable
// in 32-bit WASM due to exception-handling being disabled (-fignore-exceptions).
// libsecp256k1 is pure C, exception-free, and the gold standard for secp256k1.
// =============================================================================

/**
 * Get secp256k1 context (lazy init, safe in single-threaded WASM)
 */
static secp256k1_context* secp256k1_ctx() {
    static secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    return ctx;
}

/**
 * Check if a 32-byte value is a valid secp256k1 private key
 */
static bool isValidPrivateKey(const Bytes32& key) {
    return secp256k1_ec_seckey_verify(secp256k1_ctx(), key.data()) == 1;
}

/**
 * Add two private keys modulo curve order
 * result = (key1 + key2) mod n
 */
static Result<Bytes32> addPrivateKeys(const Bytes32& key1, const Bytes32& key2) {
    Bytes32 result = key1;
    if (secp256k1_ec_seckey_tweak_add(secp256k1_ctx(), result.data(), key2.data()) != 1) {
        return Result<Bytes32>::fail(Error::KEY_DERIVATION_FAILED);
    }
    return Result<Bytes32>::success(std::move(result));
}

/**
 * Derive public key from private key using secp256k1
 */
Result<Bytes33> publicKeyFromPrivate(const Bytes32& private_key, Curve curve) {
    if (curve != Curve::SECP256K1) {
        return Result<Bytes33>::fail(Error::NOT_SUPPORTED);
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_create(secp256k1_ctx(), &pubkey, private_key.data()) != 1) {
        return Result<Bytes33>::fail(Error::INVALID_PRIVATE_KEY);
    }

    Bytes33 result;
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_ctx(), result.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED);
    return Result<Bytes33>::success(std::move(result));
}

/**
 * Add two public key points (point addition on secp256k1)
 */
static Result<Bytes33> addPublicKeys(const Bytes33& pubkey1, const Bytes33& pubkey2) {
    secp256k1_pubkey pk1, pk2;
    if (secp256k1_ec_pubkey_parse(secp256k1_ctx(), &pk1, pubkey1.data(), 33) != 1) {
        return Result<Bytes33>::fail(Error::INVALID_PUBLIC_KEY);
    }
    if (secp256k1_ec_pubkey_parse(secp256k1_ctx(), &pk2, pubkey2.data(), 33) != 1) {
        return Result<Bytes33>::fail(Error::INVALID_PUBLIC_KEY);
    }

    const secp256k1_pubkey* pubkeys[2] = {&pk1, &pk2};
    secp256k1_pubkey combined;
    if (secp256k1_ec_pubkey_combine(secp256k1_ctx(), &combined, pubkeys, 2) != 1) {
        return Result<Bytes33>::fail(Error::KEY_DERIVATION_FAILED);
    }

    Bytes33 result;
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_ctx(), result.data(), &len, &combined, SECP256K1_EC_COMPRESSED);
    return Result<Bytes33>::success(std::move(result));
}

/**
 * Compress a 65-byte uncompressed public key to 33-byte compressed form
 */
Result<Bytes33> compressPublicKey(const Bytes65& uncompressed, Curve curve) {
    if (curve != Curve::SECP256K1) {
        return Result<Bytes33>::fail(Error::NOT_SUPPORTED);
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_parse(secp256k1_ctx(), &pubkey, uncompressed.data(), 65) != 1) {
        return Result<Bytes33>::fail(Error::INVALID_PUBLIC_KEY);
    }

    Bytes33 result;
    size_t len = 33;
    secp256k1_ec_pubkey_serialize(secp256k1_ctx(), result.data(), &len, &pubkey, SECP256K1_EC_COMPRESSED);
    return Result<Bytes33>::success(std::move(result));
}

/**
 * Decompress a 33-byte compressed public key to 65-byte uncompressed form
 */
Result<Bytes65> decompressPublicKey(const Bytes33& compressed, Curve curve) {
    if (curve != Curve::SECP256K1) {
        return Result<Bytes65>::fail(Error::NOT_SUPPORTED);
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ec_pubkey_parse(secp256k1_ctx(), &pubkey, compressed.data(), 33) != 1) {
        return Result<Bytes65>::fail(Error::INVALID_PUBLIC_KEY);
    }

    Bytes65 result;
    size_t len = 65;
    secp256k1_ec_pubkey_serialize(secp256k1_ctx(), result.data(), &len, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    return Result<Bytes65>::success(std::move(result));
}

#else // !HD_WALLET_USE_LIBSECP256K1 — use Crypto++ EC operations

/**
 * Compare two big-endian byte arrays in constant time
 * Returns: -1 if a < b, 0 if a == b, 1 if a > b
 *
 * SECURITY FIX [VULN-10]: Previous implementation used early-return which
 * leaked information about private key values via timing side channels.
 * This version processes all bytes regardless of differences found.
 */
static int compareBytes(const uint8_t* a, const uint8_t* b, size_t size) {
    volatile int result = 0;
    volatile int decided = 0;

    for (size_t i = 0; i < size; ++i) {
        int diff = static_cast<int>(a[i]) - static_cast<int>(b[i]);
        // Only set result on the first differing byte (decided == 0)
        int not_decided = (decided == 0) ? 1 : 0;
        int has_diff = (diff != 0) ? 1 : 0;
        // Update result only if not yet decided and bytes differ
        int update = not_decided & has_diff;
        // Branchless conditional: result = update ? (diff < 0 ? -1 : 1) : result
        int sign = (diff < 0) ? -1 : 1;
        result = update * sign + (1 - update) * result;
        decided |= has_diff;
    }

    return result;
}

/**
 * Check if a 32-byte value is a valid secp256k1 private key
 * Must be: 0 < key < n (curve order)
 *
 * SECURITY FIX [HIGH-03]: This function is now constant-time.
 * Previous implementation used early-return which leaked timing information
 * about the position of the first non-zero byte.
 */
static bool isValidPrivateKey(const Bytes32& key) {
    // SECURITY FIX: Constant-time zero check using accumulator
    // Process all bytes regardless of value to prevent timing attacks
    volatile uint8_t accumulator = 0;
    for (size_t i = 0; i < 32; ++i) {
        accumulator |= key[i];
    }
    // If accumulator is 0, all bytes were zero
    bool allZero = (accumulator == 0);

    // Check < curve order (compareBytes is already constant-time)
    bool lessThanOrder = compareBytes(key.data(), SECP256K1_ORDER, 32) < 0;

    // Both conditions must be met: not zero AND less than order
    return !allZero && lessThanOrder;
}

/**
 * Add two private keys modulo curve order
 * result = (key1 + key2) mod n
 */
static Result<Bytes32> addPrivateKeys(const Bytes32& key1, const Bytes32& key2) {
    using namespace CryptoPP;

    // Convert to Integer
    Integer k1(key1.data(), key1.size());
    Integer k2(key2.data(), key2.size());
    Integer n(SECP256K1_ORDER, 32);

    // Add modulo n
    ModularArithmetic mod(n);
    Integer sum = mod.Add(k1, k2);

    // Check result is valid (not zero)
    if (sum.IsZero()) {
        return Result<Bytes32>::fail(Error::KEY_DERIVATION_FAILED);
    }

    // Convert back to bytes
    Bytes32 result;
    sum.Encode(result.data(), 32);
    return Result<Bytes32>::success(std::move(result));
}

/**
 * Derive public key from private key using secp256k1
 */
Result<Bytes33> publicKeyFromPrivate(const Bytes32& private_key, Curve curve) {
    if (curve != Curve::SECP256K1) {
        return Result<Bytes33>::fail(Error::NOT_SUPPORTED);
    }

    if (!isValidPrivateKey(private_key)) {
        return Result<Bytes33>::fail(Error::INVALID_PRIVATE_KEY);
    }

    using namespace CryptoPP;

    try {
        // Initialize secp256k1 curve
        DL_GroupParameters_EC<ECP> params;
        params.Initialize(ASN1::secp256k1());

        // Get base point G
        const ECP::Point& G = params.GetSubgroupGenerator();
        const ECP& curve_obj = params.GetCurve();

        // Convert private key to Integer
        Integer privKey(private_key.data(), private_key.size());

        // Compute public key: Q = privKey * G
        ECP::Point Q = curve_obj.ScalarMultiply(G, privKey);

        // Serialize as compressed point
        Bytes33 result;

        // Determine prefix based on Y coordinate parity
        if (Q.y.IsOdd()) {
            result[0] = 0x03;
        } else {
            result[0] = 0x02;
        }

        // Encode X coordinate
        Q.x.Encode(result.data() + 1, 32);

        return Result<Bytes33>::success(std::move(result));
    } catch (const std::exception&) {
        return Result<Bytes33>::fail(Error::KEY_DERIVATION_FAILED);
    }
}

/**
 * Add a public key point to a tweaked scalar
 * result = pubkey1 + pubkey2 (point addition)
 */
static Result<Bytes33> addPublicKeys(const Bytes33& pubkey1, const Bytes33& pubkey2) {
    using namespace CryptoPP;

    try {
        // Initialize secp256k1 curve
        DL_GroupParameters_EC<ECP> params;
        params.Initialize(ASN1::secp256k1());
        const ECP& curve_obj = params.GetCurve();

        // Decode compressed points
        auto decodeCompressedPoint = [&curve_obj](const Bytes33& compressed) -> ECP::Point {
            Integer x(compressed.data() + 1, 32);
            bool yOdd = (compressed[0] == 0x03);

            // Get curve parameters: y^2 = x^3 + 7 (mod p)
            const Integer& p = curve_obj.GetField().GetModulus();

            // Calculate y^2 = x^3 + 7 mod p
            Integer xCubed = a_exp_b_mod_c(x, Integer(3), p);
            Integer y2 = (xCubed + 7) % p;

            // Calculate modular square root
            // p = 3 mod 4, so sqrt(y2) = y2^((p+1)/4) mod p
            Integer exp = (p + 1) / 4;
            Integer y = a_exp_b_mod_c(y2, exp, p);

            // Check parity and adjust
            if (y.IsOdd() != yOdd) {
                y = p - y;
            }

            return ECP::Point(x, y);
        };

        ECP::Point P1 = decodeCompressedPoint(pubkey1);
        ECP::Point P2 = decodeCompressedPoint(pubkey2);

        // Add points
        ECP::Point R = curve_obj.Add(P1, P2);

        // Check for point at infinity
        if (R.identity) {
            return Result<Bytes33>::fail(Error::KEY_DERIVATION_FAILED);
        }

        // Encode result as compressed point
        Bytes33 result;
        result[0] = R.y.IsOdd() ? 0x03 : 0x02;
        R.x.Encode(result.data() + 1, 32);

        return Result<Bytes33>::success(std::move(result));
    } catch (const std::exception&) {
        return Result<Bytes33>::fail(Error::KEY_DERIVATION_FAILED);
    }
}

/**
 * Compress a 65-byte uncompressed public key to 33-byte compressed form
 */
Result<Bytes33> compressPublicKey(const Bytes65& uncompressed, Curve curve) {
    if (curve != Curve::SECP256K1) {
        return Result<Bytes33>::fail(Error::NOT_SUPPORTED);
    }

    // Validate prefix
    if (uncompressed[0] != 0x04) {
        return Result<Bytes33>::fail(Error::INVALID_PUBLIC_KEY);
    }

    Bytes33 result;

    // Check Y coordinate parity (last byte)
    bool yOdd = (uncompressed[64] & 0x01) != 0;
    result[0] = yOdd ? 0x03 : 0x02;

    // Copy X coordinate
    std::copy(uncompressed.begin() + 1, uncompressed.begin() + 33, result.begin() + 1);

    return Result<Bytes33>::success(std::move(result));
}

/**
 * Decompress a 33-byte compressed public key to 65-byte uncompressed form
 */
Result<Bytes65> decompressPublicKey(const Bytes33& compressed, Curve curve) {
    if (curve != Curve::SECP256K1) {
        return Result<Bytes65>::fail(Error::NOT_SUPPORTED);
    }

    // Validate prefix
    if (compressed[0] != 0x02 && compressed[0] != 0x03) {
        return Result<Bytes65>::fail(Error::INVALID_PUBLIC_KEY);
    }

    using namespace CryptoPP;

    try {
        // Initialize secp256k1 curve
        DL_GroupParameters_EC<ECP> params;
        params.Initialize(ASN1::secp256k1());
        const ECP& curve_obj = params.GetCurve();

        // Get X coordinate
        Integer x(compressed.data() + 1, 32);
        bool yOdd = (compressed[0] == 0x03);

        // Get field modulus p
        const Integer& p = curve_obj.GetField().GetModulus();

        // Calculate y^2 = x^3 + 7 mod p
        Integer xCubed = a_exp_b_mod_c(x, Integer(3), p);
        Integer y2 = (xCubed + 7) % p;

        // Calculate modular square root
        // For secp256k1, p = 3 mod 4, so sqrt(y2) = y2^((p+1)/4) mod p
        Integer exp = (p + 1) / 4;
        Integer y = a_exp_b_mod_c(y2, exp, p);

        // Verify we got a valid root
        if (a_exp_b_mod_c(y, Integer(2), p) != y2) {
            return Result<Bytes65>::fail(Error::INVALID_PUBLIC_KEY);
        }

        // Check parity and adjust if needed
        if (y.IsOdd() != yOdd) {
            y = p - y;
        }

        // Build uncompressed point
        Bytes65 result;
        result[0] = 0x04;
        x.Encode(result.data() + 1, 32);
        y.Encode(result.data() + 33, 32);

        return Result<Bytes65>::success(std::move(result));
    } catch (const std::exception&) {
        return Result<Bytes65>::fail(Error::INVALID_PUBLIC_KEY);
    }
}

#endif // !HD_WALLET_USE_LIBSECP256K1

#endif // HD_WALLET_USE_CRYPTOPP

// =============================================================================
// Base58 Encoding/Decoding
// =============================================================================

/**
 * Optimized Base58 encoding without using big integer library
 */
static std::string base58EncodeOptimized(const ByteVector& data) {
    if (data.empty()) return "";

    // Count leading zeros
    size_t leadingZeros = 0;
    while (leadingZeros < data.size() && data[leadingZeros] == 0) {
        ++leadingZeros;
    }

    // SECURITY FIX [MEDIUM-01]: Check for integer overflow before multiplication
    // Extended keys are 78 bytes max, but check anyway for defense in depth
    size_t nonZeroBytes = data.size() - leadingZeros;
    if (nonZeroBytes > SIZE_MAX / 138) {
        // Would overflow - return empty string (invalid input)
        return "";
    }

    // Allocate enough space for result
    size_t size = nonZeroBytes * 138 / 100 + 1;
    std::vector<uint8_t> b58(size);

    // Process the bytes
    for (size_t i = leadingZeros; i < data.size(); ++i) {
        int carry = data[i];
        int j = 0;
        for (auto it = b58.rbegin(); (carry != 0 || j < static_cast<int>(size)) && it != b58.rend(); ++it, ++j) {
            carry += 256 * (*it);
            *it = carry % 58;
            carry /= 58;
        }
        size = j;
    }

    // Skip leading zeros in b58
    auto it = b58.begin() + (b58.size() - size);
    while (it != b58.end() && *it == 0) {
        ++it;
    }

    // Build result
    std::string result(leadingZeros, '1');
    while (it != b58.end()) {
        result += BASE58_ALPHABET[*it++];
    }

    return result;
}

/**
 * Decode Base58 string to bytes
 */
static ByteVector base58Decode(const std::string& str) {
    if (str.empty()) return {};

    // Count leading '1' characters
    size_t leadingOnes = 0;
    while (leadingOnes < str.size() && str[leadingOnes] == '1') {
        ++leadingOnes;
    }

    // SECURITY FIX [MEDIUM-01]: Check for integer overflow before multiplication
    size_t nonOneChars = str.size() - leadingOnes;
    if (nonOneChars > SIZE_MAX / 733) {
        // Would overflow - return empty (invalid input)
        return {};
    }

    // Allocate enough space
    size_t size = nonOneChars * 733 / 1000 + 1;
    std::vector<uint8_t> bin(size);

    // Process the string
    for (size_t i = leadingOnes; i < str.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(str[i]);
        if (c >= sizeof(BASE58_MAP) || BASE58_MAP[c] == -1) {
            return {}; // Invalid character
        }
        int carry = BASE58_MAP[c];
        int j = 0;
        for (auto it = bin.rbegin(); (carry != 0 || j < static_cast<int>(size)) && it != bin.rend(); ++it, ++j) {
            carry += 58 * (*it);
            *it = carry % 256;
            carry /= 256;
        }
        size = j;
    }

    // Skip leading zeros in bin
    auto it = bin.begin() + (bin.size() - size);
    while (it != bin.end() && *it == 0) {
        ++it;
    }

    // Build result with leading zeros
    ByteVector result(leadingOnes, 0);
    while (it != bin.end()) {
        result.push_back(*it++);
    }

    return result;
}

/**
 * Encode bytes with Base58Check (append 4-byte checksum)
 */
static std::string base58CheckEncode(const ByteVector& data) {
    // Calculate checksum: first 4 bytes of double SHA256
    Bytes32 checksum = doubleSha256(data.data(), data.size());

    // Append checksum
    ByteVector dataWithChecksum = data;
    dataWithChecksum.insert(dataWithChecksum.end(), checksum.begin(), checksum.begin() + 4);

    return base58EncodeOptimized(dataWithChecksum);
}

/**
 * Decode Base58Check string and verify checksum
 */
static Result<ByteVector> base58CheckDecode(const std::string& str) {
    ByteVector decoded = base58Decode(str);

    if (decoded.size() < 4) {
        return Result<ByteVector>::fail(Error::INVALID_EXTENDED_KEY);
    }

    // Extract payload and checksum
    ByteVector payload(decoded.begin(), decoded.end() - 4);
    ByteVector checksum(decoded.end() - 4, decoded.end());

    // Verify checksum using constant-time comparison (SECURITY FIX [HIGH-03])
    Bytes32 calculatedChecksum = doubleSha256(payload.data(), payload.size());

    if (!secureCompare(checksum.data(), calculatedChecksum.data(), 4)) {
        return Result<ByteVector>::fail(Error::INVALID_CHECKSUM);
    }

    return Result<ByteVector>::success(std::move(payload));
}

// =============================================================================
// DerivationPath Implementation
// =============================================================================

/**
 * Parse a derivation path string like "m/44'/60'/0'/0/0"
 */
Result<DerivationPath> DerivationPath::parse(const std::string& path) {
    DerivationPath result;

    if (path.empty()) {
        return Result<DerivationPath>::fail(Error::INVALID_PATH);
    }

    // Normalize path
    std::string normalized = path;

    // Start parsing
    size_t pos = 0;

    // Require 'm' or 'M' prefix (master key indicator)
    bool afterSlash = false;
    if (normalized[0] == 'm' || normalized[0] == 'M') {
        pos = 1;
        if (pos < normalized.size() && normalized[pos] == '/') {
            pos++;
            afterSlash = true;
        }
    } else {
        return Result<DerivationPath>::fail(Error::INVALID_PATH);
    }

    // Parse components
    bool expectComponent = afterSlash;
    while (pos < normalized.size()) {
        // Expect a single slash separator between components
        if (normalized[pos] == '/') {
            if (expectComponent) {
                // Double slash or trailing slash with no component
                return Result<DerivationPath>::fail(Error::INVALID_PATH);
            }
            pos++;
            expectComponent = true;
            continue;
        }
        expectComponent = false;

        // Parse number
        size_t numStart = pos;
        while (pos < normalized.size() && normalized[pos] >= '0' && normalized[pos] <= '9') {
            pos++;
        }

        if (pos == numStart) {
            // No number found
            return Result<DerivationPath>::fail(Error::INVALID_PATH);
        }

        // Convert to index (without std::stoull to avoid exceptions in WASI)
        std::string numStr = normalized.substr(numStart, pos - numStart);
        if (numStr.empty() || numStr.size() > 10) {
            // Max valid index is 2^31-1 = 2147483647 (10 digits)
            return Result<DerivationPath>::fail(Error::INVALID_PATH);
        }
        uint64_t index = 0;
        for (char c : numStr) {
            if (c < '0' || c > '9') {
                return Result<DerivationPath>::fail(Error::INVALID_PATH);
            }
            index = index * 10 + static_cast<uint64_t>(c - '0');
            if (index > 0xFFFFFFFF) {
                return Result<DerivationPath>::fail(Error::INVALID_CHILD_INDEX);
            }
        }

        // Check for overflow
        if (index > 0xFFFFFFFF) {
            return Result<DerivationPath>::fail(Error::INVALID_CHILD_INDEX);
        }

        // Check for hardened indicator
        bool hardened = false;
        if (pos < normalized.size() && (normalized[pos] == '\'' || normalized[pos] == 'h' || normalized[pos] == 'H')) {
            hardened = true;
            pos++;
        }

        // Validate index for hardened
        if (index >= HARDENED_OFFSET) {
            return Result<DerivationPath>::fail(Error::INVALID_CHILD_INDEX);
        }

        result.components.emplace_back(static_cast<uint32_t>(index), hardened);

        // Check depth limit
        if (result.components.size() > HD_WALLET_MAX_PATH_DEPTH) {
            return Result<DerivationPath>::fail(Error::INVALID_PATH);
        }
    }

    // Trailing slash with no component
    if (expectComponent) {
        return Result<DerivationPath>::fail(Error::INVALID_PATH);
    }

    return Result<DerivationPath>::success(std::move(result));
}

/**
 * Convert derivation path to string representation
 */
std::string DerivationPath::toString() const {
    std::ostringstream ss;
    ss << "m";

    for (const auto& comp : components) {
        ss << "/" << comp.index;
        if (comp.hardened) {
            ss << "'";
        }
    }

    return ss.str();
}

/**
 * Create BIP-44 path: m/44'/coin'/account'/change/index
 */
DerivationPath DerivationPath::bip44(
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index
) {
    DerivationPath path;
    path.components = {
        {44, true},           // purpose (hardened)
        {coin_type, true},    // coin_type (hardened)
        {account, true},      // account (hardened)
        {change, false},      // change
        {index, false}        // address_index
    };
    return path;
}

/**
 * Create BIP-49 path: m/49'/coin'/account'/change/index
 */
DerivationPath DerivationPath::bip49(
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index
) {
    DerivationPath path;
    path.components = {
        {49, true},           // purpose (hardened)
        {coin_type, true},    // coin_type (hardened)
        {account, true},      // account (hardened)
        {change, false},      // change
        {index, false}        // address_index
    };
    return path;
}

/**
 * Create BIP-84 path: m/84'/coin'/account'/change/index
 */
DerivationPath DerivationPath::bip84(
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index
) {
    DerivationPath path;
    path.components = {
        {84, true},           // purpose (hardened)
        {coin_type, true},    // coin_type (hardened)
        {account, true},      // account (hardened)
        {change, false},      // change
        {index, false}        // address_index
    };
    return path;
}

// =============================================================================
// ExtendedKey Implementation
// =============================================================================

/**
 * Default constructor - creates invalid key
 */
ExtendedKey::ExtendedKey()
    : curve_(Curve::SECP256K1)
    , depth_(0)
    , parent_fingerprint_(0)
    , child_index_(0)
    , chain_code_{}
    , public_key_{}
    , private_key_{}
    , has_private_key_(false)
{
}

/**
 * Internal constructor
 */
ExtendedKey::ExtendedKey(
    Curve curve,
    uint8_t depth,
    uint32_t parent_fp,
    uint32_t child_idx,
    const Bytes32& chain_code,
    const Bytes33& public_key,
    const Bytes32& private_key,
    bool has_private
)
    : curve_(curve)
    , depth_(depth)
    , parent_fingerprint_(parent_fp)
    , child_index_(child_idx)
    , chain_code_(chain_code)
    , public_key_(public_key)
    , private_key_(private_key)
    , has_private_key_(has_private)
{
}

/**
 * Destructor - securely wipe private key
 */
ExtendedKey::~ExtendedKey() {
    wipe();
}

/**
 * Move constructor
 */
ExtendedKey::ExtendedKey(ExtendedKey&& other) noexcept
    : curve_(other.curve_)
    , depth_(other.depth_)
    , parent_fingerprint_(other.parent_fingerprint_)
    , child_index_(other.child_index_)
    , chain_code_(other.chain_code_)
    , public_key_(other.public_key_)
    , private_key_(other.private_key_)
    , has_private_key_(other.has_private_key_)
{
    // Wipe the source
    other.wipe();
}

/**
 * Move assignment
 */
ExtendedKey& ExtendedKey::operator=(ExtendedKey&& other) noexcept {
    if (this != &other) {
        // Wipe current private key
        wipe();

        // Move data
        curve_ = other.curve_;
        depth_ = other.depth_;
        parent_fingerprint_ = other.parent_fingerprint_;
        child_index_ = other.child_index_;
        chain_code_ = other.chain_code_;
        public_key_ = other.public_key_;
        private_key_ = other.private_key_;
        has_private_key_ = other.has_private_key_;

        // Wipe the source
        other.wipe();
    }
    return *this;
}

/**
 * Copy constructor
 */
ExtendedKey::ExtendedKey(const ExtendedKey& other)
    : curve_(other.curve_)
    , depth_(other.depth_)
    , parent_fingerprint_(other.parent_fingerprint_)
    , child_index_(other.child_index_)
    , chain_code_(other.chain_code_)
    , public_key_(other.public_key_)
    , private_key_(other.private_key_)
    , has_private_key_(other.has_private_key_)
{
}

/**
 * Copy assignment
 */
ExtendedKey& ExtendedKey::operator=(const ExtendedKey& other) {
    if (this != &other) {
        // Wipe current private key first
        wipe();

        curve_ = other.curve_;
        depth_ = other.depth_;
        parent_fingerprint_ = other.parent_fingerprint_;
        child_index_ = other.child_index_;
        chain_code_ = other.chain_code_;
        public_key_ = other.public_key_;
        private_key_ = other.private_key_;
        has_private_key_ = other.has_private_key_;
    }
    return *this;
}

/**
 * Securely wipe private key from memory
 */
void ExtendedKey::wipe() {
    secureWipe(private_key_.data(), private_key_.size());
    has_private_key_ = false;
}

/**
 * Clone this key (creates independent copy)
 */
ExtendedKey ExtendedKey::clone() const {
    return ExtendedKey(*this);
}

/**
 * Create master extended key from seed using HMAC-SHA512
 * Key: "Bitcoin seed"
 * Data: seed bytes
 */
Result<ExtendedKey> ExtendedKey::fromSeed(const Bytes64& seed, Curve curve) {
    ByteVector seedVec(seed.begin(), seed.end());
    return fromSeed(seedVec, curve);
}

/**
 * Create master extended key from seed vector
 */
Result<ExtendedKey> ExtendedKey::fromSeed(const ByteVector& seed, Curve curve) {
    // Validate seed size (BIP-32 recommends 128-512 bits)
    if (seed.size() < 16 || seed.size() > 64) {
        return Result<ExtendedKey>::fail(Error::INVALID_SEED);
    }

    // Only secp256k1 supported for now
    if (curve != Curve::SECP256K1) {
        return Result<ExtendedKey>::fail(Error::NOT_SUPPORTED);
    }

    // HMAC-SHA512 with key "Bitcoin seed"
    const std::string key = "Bitcoin seed";
    ByteVector keyBytes(key.begin(), key.end());

    // SECURITY FIX [VULN-06]: Use secure variant to auto-wipe HMAC output
    CryptoPP::SecByteBlock hmacResult = hmacSha512Secure(keyBytes, seed);

    // Split result: IL = private key, IR = chain code
    Bytes32 privateKey;
    Bytes32 chainCode;
    std::copy(hmacResult.begin(), hmacResult.begin() + 32, privateKey.begin());
    std::copy(hmacResult.begin() + 32, hmacResult.end(), chainCode.begin());

    // Validate private key
    if (!isValidPrivateKey(privateKey)) {
        // BIP-32: If IL is 0 or >= n, the master key is invalid
        return Result<ExtendedKey>::fail(Error::INVALID_PRIVATE_KEY);
    }

    // Derive public key
    auto pubKeyResult = publicKeyFromPrivate(privateKey, curve);
    if (!pubKeyResult.ok()) {
        secureWipe(privateKey.data(), privateKey.size());
        return Result<ExtendedKey>::fail(pubKeyResult.error);
    }

    // Create master key
    ExtendedKey masterKey(
        curve,
        0,                  // depth
        0,                  // parent fingerprint (0 for master)
        0,                  // child index (0 for master)
        chainCode,
        pubKeyResult.value,
        privateKey,
        true                // has private key
    );

    // Wipe temporary private key
    secureWipe(privateKey.data(), privateKey.size());
    secureWipe(hmacResult.data(), hmacResult.size());

    return Result<ExtendedKey>::success(std::move(masterKey));
}

/**
 * Create extended key from raw components
 * Used by aligned API for zero-copy key reconstruction
 */
ExtendedKey ExtendedKey::fromRawData(
    Curve curve,
    uint8_t depth,
    uint32_t parentFingerprint,
    uint32_t childIndex,
    const Bytes32& chainCode,
    const Bytes33& publicKey,
    const Bytes32& privateKey,
    bool hasPrivateKey
) {
    return ExtendedKey(
        curve,
        depth,
        parentFingerprint,
        childIndex,
        chainCode,
        publicKey,
        privateKey,
        hasPrivateKey
    );
}

/**
 * Parse extended key from Base58Check encoded string (xprv/xpub)
 */
Result<ExtendedKey> ExtendedKey::fromString(const std::string& str) {
    // Decode Base58Check
    auto decoded = base58CheckDecode(str);
    if (!decoded.ok()) {
        return Result<ExtendedKey>::fail(decoded.error);
    }

    const ByteVector& data = decoded.value;

    // Extended key format: 78 bytes
    // 4 bytes: version
    // 1 byte: depth
    // 4 bytes: parent fingerprint
    // 4 bytes: child index
    // 32 bytes: chain code
    // 33 bytes: key (0x00 + 32 bytes private, or compressed public)
    if (data.size() != 78) {
        return Result<ExtendedKey>::fail(Error::INVALID_EXTENDED_KEY);
    }

    // Parse version
    uint32_t version = (static_cast<uint32_t>(data[0]) << 24) |
                       (static_cast<uint32_t>(data[1]) << 16) |
                       (static_cast<uint32_t>(data[2]) << 8) |
                       static_cast<uint32_t>(data[3]);

    // Determine if private or public
    bool isPrivate = false;
    switch (version) {
        case XPRV_VERSION:
        case TPRV_VERSION:
        case YPRV_VERSION:
        case ZPRV_VERSION:
            isPrivate = true;
            break;
        case XPUB_VERSION:
        case TPUB_VERSION:
        case YPUB_VERSION:
        case ZPUB_VERSION:
            isPrivate = false;
            break;
        default:
            return Result<ExtendedKey>::fail(Error::INVALID_EXTENDED_KEY);
    }

    // Parse depth
    uint8_t depth = data[4];

    // Parse parent fingerprint
    uint32_t parentFp = (static_cast<uint32_t>(data[5]) << 24) |
                        (static_cast<uint32_t>(data[6]) << 16) |
                        (static_cast<uint32_t>(data[7]) << 8) |
                        static_cast<uint32_t>(data[8]);

    // Parse child index
    uint32_t childIdx = (static_cast<uint32_t>(data[9]) << 24) |
                        (static_cast<uint32_t>(data[10]) << 16) |
                        (static_cast<uint32_t>(data[11]) << 8) |
                        static_cast<uint32_t>(data[12]);

    // Parse chain code
    Bytes32 chainCode;
    std::copy(data.begin() + 13, data.begin() + 45, chainCode.begin());

    Bytes32 privateKey{};
    Bytes33 publicKey{};

    if (isPrivate) {
        // Private key: first byte must be 0x00
        if (data[45] != 0x00) {
            return Result<ExtendedKey>::fail(Error::INVALID_EXTENDED_KEY);
        }

        // Copy private key
        std::copy(data.begin() + 46, data.end(), privateKey.begin());

        // Validate private key
        if (!isValidPrivateKey(privateKey)) {
            secureWipe(privateKey.data(), privateKey.size());
            return Result<ExtendedKey>::fail(Error::INVALID_PRIVATE_KEY);
        }

        // Derive public key
        auto pubKeyResult = publicKeyFromPrivate(privateKey, Curve::SECP256K1);
        if (!pubKeyResult.ok()) {
            secureWipe(privateKey.data(), privateKey.size());
            return Result<ExtendedKey>::fail(pubKeyResult.error);
        }
        publicKey = pubKeyResult.value;
    } else {
        // Public key: should be compressed (0x02 or 0x03)
        if (data[45] != 0x02 && data[45] != 0x03) {
            return Result<ExtendedKey>::fail(Error::INVALID_PUBLIC_KEY);
        }

        // Copy public key
        std::copy(data.begin() + 45, data.end(), publicKey.begin());
    }

    ExtendedKey key(
        Curve::SECP256K1,
        depth,
        parentFp,
        childIdx,
        chainCode,
        publicKey,
        privateKey,
        isPrivate
    );

    // Wipe temporary private key
    secureWipe(privateKey.data(), privateKey.size());

    return Result<ExtendedKey>::success(std::move(key));
}

/**
 * Get fingerprint of this key
 * First 4 bytes of HASH160(public_key)
 */
uint32_t ExtendedKey::fingerprint() const {
    ByteVector hash = hash160(public_key_.data(), public_key_.size());

    return (static_cast<uint32_t>(hash[0]) << 24) |
           (static_cast<uint32_t>(hash[1]) << 16) |
           (static_cast<uint32_t>(hash[2]) << 8) |
           static_cast<uint32_t>(hash[3]);
}

/**
 * Get private key (if available)
 */
Result<Bytes32> ExtendedKey::privateKey() const {
    if (!has_private_key_) {
        return Result<Bytes32>::fail(Error::KEY_DERIVATION_FAILED);
    }
    return Result<Bytes32>::success(Bytes32(private_key_));
}

/**
 * Get uncompressed public key
 */
Result<Bytes65> ExtendedKey::publicKeyUncompressed() const {
    return decompressPublicKey(public_key_, curve_);
}

/**
 * Derive child key at index
 *
 * For hardened derivation (index >= 2^31):
 *   data = 0x00 || private_key || index
 * For normal derivation:
 *   data = public_key || index
 *
 * I = HMAC-SHA512(Key = chain_code, Data = data)
 * IL = child key addition value
 * IR = child chain code
 *
 * Child private key = IL + parent_private_key (mod n)
 * Child public key = point(IL) + parent_public_key
 */
Result<ExtendedKey> ExtendedKey::deriveChild(uint32_t index) const {
    bool hardened = isHardened(index);

    // Hardened derivation requires private key
    if (hardened && !has_private_key_) {
        return Result<ExtendedKey>::fail(Error::HARDENED_FROM_PUBLIC);
    }

    // Prepare HMAC data
    ByteVector data;
    data.reserve(37); // 1 + 32 + 4 or 33 + 4

    if (hardened) {
        // Hardened: 0x00 || private_key || index
        data.push_back(0x00);
        data.insert(data.end(), private_key_.begin(), private_key_.end());
    } else {
        // Normal: compressed_public_key || index
        data.insert(data.end(), public_key_.begin(), public_key_.end());
    }

    // Append index (big-endian)
    data.push_back(static_cast<uint8_t>((index >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((index >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((index >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(index & 0xFF));

    // HMAC-SHA512
    ByteVector chainCodeVec(chain_code_.begin(), chain_code_.end());
    // SECURITY FIX [VULN-06]: Use secure variant to auto-wipe HMAC output
    CryptoPP::SecByteBlock hmacResult = hmacSha512Secure(chainCodeVec, data);

    // Split: IL (32 bytes), IR (32 bytes)
    Bytes32 il;
    Bytes32 childChainCode;
    std::copy(hmacResult.begin(), hmacResult.begin() + 32, il.begin());
    std::copy(hmacResult.begin() + 32, hmacResult.end(), childChainCode.begin());

    // Validate IL
    if (!isValidPrivateKey(il)) {
        // IL >= n, try next index per BIP-32
        secureWipe(il.data(), il.size());
        return Result<ExtendedKey>::fail(Error::KEY_DERIVATION_FAILED);
    }

    Bytes32 childPrivateKey{};
    Bytes33 childPublicKey;
    bool childHasPrivate = has_private_key_;

    if (has_private_key_) {
        // Child private key = IL + parent private key (mod n)
        auto addResult = addPrivateKeys(il, private_key_);
        if (!addResult.ok()) {
            secureWipe(il.data(), il.size());
            secureWipe(hmacResult.data(), hmacResult.size());
            return Result<ExtendedKey>::fail(addResult.error);
        }
        childPrivateKey = addResult.value;

        // Derive public key from child private key
        auto pubKeyResult = publicKeyFromPrivate(childPrivateKey, curve_);
        if (!pubKeyResult.ok()) {
            secureWipe(childPrivateKey.data(), childPrivateKey.size());
            secureWipe(il.data(), il.size());
            secureWipe(hmacResult.data(), hmacResult.size());
            return Result<ExtendedKey>::fail(pubKeyResult.error);
        }
        childPublicKey = pubKeyResult.value;
    } else {
        // Public key derivation: child_public = point(IL) + parent_public
        auto ilPubKeyResult = publicKeyFromPrivate(il, curve_);
        if (!ilPubKeyResult.ok()) {
            secureWipe(il.data(), il.size());
            secureWipe(hmacResult.data(), hmacResult.size());
            return Result<ExtendedKey>::fail(ilPubKeyResult.error);
        }

        auto addResult = addPublicKeys(ilPubKeyResult.value, public_key_);
        if (!addResult.ok()) {
            secureWipe(il.data(), il.size());
            secureWipe(hmacResult.data(), hmacResult.size());
            return Result<ExtendedKey>::fail(addResult.error);
        }
        childPublicKey = addResult.value;
        childHasPrivate = false;
    }

    // Calculate parent fingerprint
    uint32_t parentFp = fingerprint();

    // Create child key
    ExtendedKey childKey(
        curve_,
        static_cast<uint8_t>(depth_ + 1),
        parentFp,
        index,
        childChainCode,
        childPublicKey,
        childPrivateKey,
        childHasPrivate
    );

    // Wipe sensitive data
    secureWipe(il.data(), il.size());
    secureWipe(hmacResult.data(), hmacResult.size());
    secureWipe(childPrivateKey.data(), childPrivateKey.size());

    return Result<ExtendedKey>::success(std::move(childKey));
}

/**
 * Derive key at path string
 */
Result<ExtendedKey> ExtendedKey::derivePath(const std::string& path) const {
    auto parsedPath = DerivationPath::parse(path);
    if (!parsedPath.ok()) {
        return Result<ExtendedKey>::fail(parsedPath.error);
    }
    return derivePath(parsedPath.value);
}

/**
 * Derive key through full path
 */
Result<ExtendedKey> ExtendedKey::derivePath(const DerivationPath& path) const {
    if (path.components.empty()) {
        // Empty path means return this key
        return Result<ExtendedKey>::success(clone());
    }

    ExtendedKey current = clone();

    for (const auto& component : path.components) {
        auto result = current.deriveChild(component.fullIndex());
        if (!result.ok()) {
            return Result<ExtendedKey>::fail(result.error);
        }
        current = std::move(result.value);
    }

    return Result<ExtendedKey>::success(std::move(current));
}

/**
 * Create neutered (public-only) version of this key
 */
ExtendedKey ExtendedKey::neutered() const {
    ExtendedKey result = clone();
    result.wipe(); // Removes private key
    return result;
}

/**
 * Serialize as extended private key (xprv)
 */
Result<std::string> ExtendedKey::serializePrivate(uint32_t version) const {
    if (!has_private_key_) {
        return Result<std::string>::fail(Error::HARDENED_FROM_PUBLIC);
    }

    // Build 78-byte payload
    ByteVector data;
    data.reserve(78);

    // Version (4 bytes)
    data.push_back(static_cast<uint8_t>((version >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((version >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(version & 0xFF));

    // Depth (1 byte)
    data.push_back(depth_);

    // Parent fingerprint (4 bytes)
    data.push_back(static_cast<uint8_t>((parent_fingerprint_ >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((parent_fingerprint_ >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((parent_fingerprint_ >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(parent_fingerprint_ & 0xFF));

    // Child index (4 bytes)
    data.push_back(static_cast<uint8_t>((child_index_ >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((child_index_ >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((child_index_ >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(child_index_ & 0xFF));

    // Chain code (32 bytes)
    data.insert(data.end(), chain_code_.begin(), chain_code_.end());

    // Private key (1 + 32 bytes: 0x00 prefix + key)
    data.push_back(0x00);
    data.insert(data.end(), private_key_.begin(), private_key_.end());

    std::string result = base58CheckEncode(data);

    // Wipe sensitive data
    secureWipe(data.data(), data.size());

    return Result<std::string>::success(std::move(result));
}

/**
 * Serialize as extended public key (xpub)
 */
std::string ExtendedKey::serializePublic(uint32_t version) const {
    // Build 78-byte payload
    ByteVector data;
    data.reserve(78);

    // Version (4 bytes)
    data.push_back(static_cast<uint8_t>((version >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((version >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((version >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(version & 0xFF));

    // Depth (1 byte)
    data.push_back(depth_);

    // Parent fingerprint (4 bytes)
    data.push_back(static_cast<uint8_t>((parent_fingerprint_ >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((parent_fingerprint_ >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((parent_fingerprint_ >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(parent_fingerprint_ & 0xFF));

    // Child index (4 bytes)
    data.push_back(static_cast<uint8_t>((child_index_ >> 24) & 0xFF));
    data.push_back(static_cast<uint8_t>((child_index_ >> 16) & 0xFF));
    data.push_back(static_cast<uint8_t>((child_index_ >> 8) & 0xFF));
    data.push_back(static_cast<uint8_t>(child_index_ & 0xFF));

    // Chain code (32 bytes)
    data.insert(data.end(), chain_code_.begin(), chain_code_.end());

    // Public key (33 bytes compressed)
    data.insert(data.end(), public_key_.begin(), public_key_.end());

    return base58CheckEncode(data);
}

// =============================================================================
// C API Implementation
// =============================================================================

/// Internal struct to hold ExtendedKey for C API
struct hd_key_t {
    ExtendedKey key;
};

hd_key_handle hd_key_from_seed(
    const uint8_t* seed,
    size_t seed_size,
    int32_t curve
) {
    if (seed == nullptr || seed_size == 0) {
        return nullptr;
    }

    ByteVector seedVec(seed, seed + seed_size);
    auto result = ExtendedKey::fromSeed(seedVec, static_cast<Curve>(curve));

    // Wipe seed copy
    secureWipe(seedVec.data(), seedVec.size());

    if (!result.ok()) {
        return nullptr;
    }

    auto* handle = new (std::nothrow) hd_key_t;
    if (handle == nullptr) {
        return nullptr;
    }

    handle->key = std::move(result.value);
    return handle;
}

hd_key_handle hd_key_from_xprv(const char* xprv) {
    if (xprv == nullptr) {
        return nullptr;
    }

    auto result = ExtendedKey::fromString(xprv);
    if (!result.ok()) {
        return nullptr;
    }

    auto* handle = new (std::nothrow) hd_key_t;
    if (handle == nullptr) {
        return nullptr;
    }

    handle->key = std::move(result.value);
    return handle;
}

hd_key_handle hd_key_from_xpub(const char* xpub) {
    // Same as xprv - the fromString function handles both
    return hd_key_from_xprv(xpub);
}

hd_key_handle hd_key_derive_path(hd_key_handle key, const char* path) {
    if (key == nullptr || path == nullptr) {
        return nullptr;
    }

    auto result = key->key.derivePath(path);
    if (!result.ok()) {
        return nullptr;
    }

    auto* handle = new (std::nothrow) hd_key_t;
    if (handle == nullptr) {
        return nullptr;
    }

    handle->key = std::move(result.value);
    return handle;
}

hd_key_handle hd_key_derive_child(hd_key_handle key, uint32_t index) {
    if (key == nullptr) {
        return nullptr;
    }

    auto result = key->key.deriveChild(index);
    if (!result.ok()) {
        return nullptr;
    }

    auto* handle = new (std::nothrow) hd_key_t;
    if (handle == nullptr) {
        return nullptr;
    }

    handle->key = std::move(result.value);
    return handle;
}

hd_key_handle hd_key_derive_hardened(hd_key_handle key, uint32_t index) {
    return hd_key_derive_child(key, harden(index));
}

int32_t hd_key_get_private(hd_key_handle key, uint8_t* out, size_t out_size) {
    if (key == nullptr || out == nullptr || out_size < 32) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    auto result = key->key.privateKey();
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    std::copy(result.value.begin(), result.value.end(), out);
    return static_cast<int32_t>(Error::OK);
}

int32_t hd_key_get_public(hd_key_handle key, uint8_t* out, size_t out_size) {
    if (key == nullptr || out == nullptr || out_size < 33) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    auto pubkey = key->key.publicKey();
    std::copy(pubkey.begin(), pubkey.end(), out);
    return static_cast<int32_t>(Error::OK);
}

int32_t hd_key_get_chain_code(hd_key_handle key, uint8_t* out, size_t out_size) {
    if (key == nullptr || out == nullptr || out_size < 32) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    auto chainCode = key->key.chainCode();
    std::copy(chainCode.begin(), chainCode.end(), out);
    return static_cast<int32_t>(Error::OK);
}

uint32_t hd_key_get_fingerprint(hd_key_handle key) {
    if (key == nullptr) {
        return 0;
    }
    return key->key.fingerprint();
}

uint32_t hd_key_get_parent_fingerprint(hd_key_handle key) {
    if (key == nullptr) {
        return 0;
    }
    return key->key.parentFingerprint();
}

uint8_t hd_key_get_depth(hd_key_handle key) {
    if (key == nullptr) {
        return 0;
    }
    return key->key.depth();
}

uint32_t hd_key_get_child_index(hd_key_handle key) {
    if (key == nullptr) {
        return 0;
    }
    return key->key.childIndex();
}

int32_t hd_key_serialize_xprv(hd_key_handle key, char* out, size_t out_size) {
    if (key == nullptr || out == nullptr || out_size < 112) { // xprv is 111 chars + null
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    auto result = key->key.serializePrivate();
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    if (result.value.size() >= out_size) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    std::strcpy(out, result.value.c_str());
    return static_cast<int32_t>(Error::OK);
}

int32_t hd_key_serialize_xpub(hd_key_handle key, char* out, size_t out_size) {
    if (key == nullptr || out == nullptr || out_size < 112) { // xpub is 111 chars + null
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    auto result = key->key.serializePublic();

    if (result.size() >= out_size) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    std::strcpy(out, result.c_str());
    return static_cast<int32_t>(Error::OK);
}

hd_key_handle hd_key_neutered(hd_key_handle key) {
    if (key == nullptr) {
        return nullptr;
    }

    auto* handle = new (std::nothrow) hd_key_t;
    if (handle == nullptr) {
        return nullptr;
    }

    handle->key = key->key.neutered();
    return handle;
}

int32_t hd_key_is_neutered(hd_key_handle key) {
    if (key == nullptr) {
        return -1;
    }
    return key->key.isNeutered() ? 1 : 0;
}

void hd_key_wipe(hd_key_handle key) {
    if (key != nullptr) {
        key->key.wipe();
    }
}

hd_key_handle hd_key_clone(hd_key_handle key) {
    if (key == nullptr) {
        return nullptr;
    }

    auto* handle = new (std::nothrow) hd_key_t;
    if (handle == nullptr) {
        return nullptr;
    }

    handle->key = key->key.clone();
    return handle;
}

void hd_key_destroy(hd_key_handle key) {
    if (key != nullptr) {
        key->key.wipe();
        delete key;
    }
}

// Note: hd_path_build and hd_path_parse are defined in bip44.cpp

} // namespace bip32
} // namespace hd_wallet
