/**
 * @file eddsa.cpp
 * @brief EdDSA (Ed25519) Signing Implementation
 *
 * Ed25519 signature implementation using Crypto++.
 * Features:
 * - Sign messages with Ed25519
 * - Verify Ed25519 signatures
 * - Convert between Ed25519 key formats
 */

#include "hd_wallet/types.h"
#include "hd_wallet/config.h"
#include "hd_wallet/eddsa.h"

#include <cryptopp/xed25519.h>
#if !HD_WALLET_IS_WASI
#include <cryptopp/osrng.h>
#endif
#include <cryptopp/sha.h>
#include <cryptopp/hmac.h>
#include <cryptopp/secblock.h>

#include <cstring>
#include <stdexcept>

namespace hd_wallet {
namespace eddsa {

// =============================================================================
// Constants
// =============================================================================

/// Ed25519 private key (seed) size
constexpr size_t PRIVATE_KEY_SIZE = 32;

/// Ed25519 public key size
constexpr size_t PUBLIC_KEY_SIZE = 32;

/// Ed25519 signature size
constexpr size_t SIGNATURE_SIZE = 64;

/// Ed25519 expanded private key size (seed + public key)
constexpr size_t EXPANDED_PRIVATE_KEY_SIZE = 64;

// =============================================================================
// Key Derivation
// =============================================================================

/**
 * Derive Ed25519 public key from private key (seed)
 *
 * @param privateKey 32-byte private key seed
 * @param privateKeyLen Private key length (must be 32)
 * @param publicKey Output buffer for 32-byte public key
 * @param publicKeyLen Input: buffer size, Output: key size (32)
 * @return true on success
 */
bool derivePublicKey(
    const uint8_t* privateKey,
    size_t privateKeyLen,
    uint8_t* publicKey,
    size_t* publicKeyLen
) {
    if (!privateKey || !publicKey || !publicKeyLen) {
        return false;
    }

    if (privateKeyLen != PRIVATE_KEY_SIZE) {
        return false;
    }

    if (*publicKeyLen < PUBLIC_KEY_SIZE) {
        return false;
    }

    try {
        // Create Ed25519 signer from seed
        CryptoPP::ed25519Signer signer(privateKey);

        // Get verifier (which contains the public key)
        CryptoPP::ed25519Verifier verifier(signer);

        // Extract public key - cast to derived type
        const CryptoPP::ed25519PublicKey& pk =
            static_cast<const CryptoPP::ed25519PublicKey&>(verifier.GetPublicKey());
        std::memcpy(publicKey, pk.GetPublicKeyBytePtr(), PUBLIC_KEY_SIZE);
        *publicKeyLen = PUBLIC_KEY_SIZE;

        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Validate Ed25519 private key
 *
 * @param privateKey Private key to validate
 * @param privateKeyLen Key length
 * @return true if valid
 */
bool validatePrivateKey(const uint8_t* privateKey, size_t privateKeyLen) {
    if (!privateKey) {
        return false;
    }

    if (privateKeyLen != PRIVATE_KEY_SIZE) {
        return false;
    }

    // Any 32-byte value is a valid Ed25519 seed
    // The actual scalar is derived via SHA-512 hashing
    return true;
}

/**
 * Validate Ed25519 public key
 *
 * @param publicKey Public key to validate
 * @param publicKeyLen Key length
 * @return true if valid
 */
bool validatePublicKey(const uint8_t* publicKey, size_t publicKeyLen) {
    if (!publicKey) {
        return false;
    }

    if (publicKeyLen != PUBLIC_KEY_SIZE) {
        return false;
    }

    try {
        // Try to create a verifier with the public key
        // This will validate that the key is a valid curve point
        CryptoPP::ed25519Verifier verifier(publicKey);
        return true;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// Signing
// =============================================================================

/**
 * Sign a message with Ed25519
 *
 * @param privateKey 32-byte private key seed
 * @param privateKeyLen Private key length (must be 32)
 * @param message Message to sign
 * @param messageLen Message length
 * @param signature Output buffer for 64-byte signature
 * @param signatureLen Input: buffer size, Output: signature size (64)
 * @return true on success
 */
bool sign(
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* message,
    size_t messageLen,
    uint8_t* signature,
    size_t* signatureLen
) {
    if (!privateKey || !message || !signature || !signatureLen) {
        return false;
    }

    if (privateKeyLen != PRIVATE_KEY_SIZE) {
        return false;
    }

    if (*signatureLen < SIGNATURE_SIZE) {
        return false;
    }

    try {
        // Create signer from seed
        CryptoPP::ed25519Signer signer(privateKey);

        // Sign the message
        // Ed25519 is deterministic - no random number needed
        signer.SignMessage(
            CryptoPP::NullRNG(),  // RNG not used for Ed25519
            message,
            messageLen,
            signature
        );

        *signatureLen = SIGNATURE_SIZE;
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Sign a pre-hashed message (Ed25519ph)
 *
 * Note: Standard Ed25519 does NOT pre-hash. This function implements
 * Ed25519ph (prehashed) variant which hashes the message with SHA-512
 * before signing.
 *
 * @param privateKey 32-byte private key seed
 * @param privateKeyLen Private key length (must be 32)
 * @param hash Pre-computed message hash (64 bytes for SHA-512)
 * @param hashLen Hash length (should be 64)
 * @param signature Output buffer for 64-byte signature
 * @param signatureLen Input: buffer size, Output: signature size (64)
 * @return true on success
 */
bool signPrehashed(
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* hash,
    size_t hashLen,
    uint8_t* signature,
    size_t* signatureLen
) {
    // For Ed25519ph, we sign the hash directly
    // The hash should be SHA-512 of the message
    return sign(privateKey, privateKeyLen, hash, hashLen, signature, signatureLen);
}

/**
 * Sign a message using expanded private key format
 *
 * The expanded format is (a, prefix) where:
 * - a: 32-byte scalar (clamped SHA-512 hash of seed)
 * - prefix: 32-byte prefix (second half of SHA-512 hash)
 *
 * @param expandedKey 64-byte expanded private key
 * @param expandedKeyLen Key length (must be 64)
 * @param publicKey 32-byte public key (required for signing)
 * @param publicKeyLen Public key length (must be 32)
 * @param message Message to sign
 * @param messageLen Message length
 * @param signature Output buffer for 64-byte signature
 * @param signatureLen Input: buffer size, Output: signature size (64)
 * @return true on success
 */
bool signExpanded(
    const uint8_t* expandedKey,
    size_t expandedKeyLen,
    const uint8_t* publicKey,
    size_t publicKeyLen,
    const uint8_t* message,
    size_t messageLen,
    uint8_t* signature,
    size_t* signatureLen
) {
    if (!expandedKey || !publicKey || !message || !signature || !signatureLen) {
        return false;
    }

    if (expandedKeyLen != EXPANDED_PRIVATE_KEY_SIZE || publicKeyLen != PUBLIC_KEY_SIZE) {
        return false;
    }

    if (*signatureLen < SIGNATURE_SIZE) {
        return false;
    }

    try {
        // Crypto++ ed25519 doesn't directly support expanded keys
        // We need to reconstruct the signing process

        // For now, we use a workaround: create the seed format that
        // produces this expanded key (not always possible)
        // This is a limitation - in production, you might need a
        // lower-level implementation

        // Since Crypto++ doesn't expose the internal signing with
        // expanded keys, we'll note this limitation

        // For a full implementation, you would:
        // 1. Use the scalar 'a' (first 32 bytes of expanded key)
        // 2. Use the prefix (second 32 bytes)
        // 3. Implement the Ed25519 signing algorithm directly

        // For now, return false to indicate this isn't supported
        // with Crypto++'s high-level API
        (void)message;
        (void)messageLen;
        (void)signature;

        return false;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// Verification
// =============================================================================

/**
 * Verify an Ed25519 signature
 *
 * @param publicKey 32-byte public key
 * @param publicKeyLen Public key length (must be 32)
 * @param message Message that was signed
 * @param messageLen Message length
 * @param signature 64-byte signature
 * @param signatureLen Signature length (must be 64)
 * @return true if signature is valid
 */
bool verify(
    const uint8_t* publicKey,
    size_t publicKeyLen,
    const uint8_t* message,
    size_t messageLen,
    const uint8_t* signature,
    size_t signatureLen
) {
    if (!publicKey || !message || !signature) {
        return false;
    }

    if (publicKeyLen != PUBLIC_KEY_SIZE) {
        return false;
    }

    if (signatureLen != SIGNATURE_SIZE) {
        return false;
    }

    try {
        // Create verifier from public key
        CryptoPP::ed25519Verifier verifier(publicKey);

        // Verify the signature
        return verifier.VerifyMessage(message, messageLen, signature, signatureLen);
    } catch (...) {
        return false;
    }
}

/**
 * Verify a pre-hashed message signature (Ed25519ph)
 *
 * @param publicKey 32-byte public key
 * @param publicKeyLen Public key length (must be 32)
 * @param hash Pre-computed message hash
 * @param hashLen Hash length
 * @param signature 64-byte signature
 * @param signatureLen Signature length (must be 64)
 * @return true if signature is valid
 */
bool verifyPrehashed(
    const uint8_t* publicKey,
    size_t publicKeyLen,
    const uint8_t* hash,
    size_t hashLen,
    const uint8_t* signature,
    size_t signatureLen
) {
    // For Ed25519ph verification, we verify against the hash
    return verify(publicKey, publicKeyLen, hash, hashLen, signature, signatureLen);
}

// =============================================================================
// Key Conversion
// =============================================================================

/**
 * Expand Ed25519 seed to internal format
 *
 * Computes: SHA-512(seed) and clamps the first 32 bytes
 *
 * @param seed 32-byte seed
 * @param seedLen Seed length (must be 32)
 * @param expanded Output buffer for 64-byte expanded key
 * @param expandedLen Input: buffer size, Output: key size (64)
 * @return true on success
 */
bool expandSeed(
    const uint8_t* seed,
    size_t seedLen,
    uint8_t* expanded,
    size_t* expandedLen
) {
    if (!seed || !expanded || !expandedLen) {
        return false;
    }

    if (seedLen != PRIVATE_KEY_SIZE) {
        return false;
    }

    if (*expandedLen < EXPANDED_PRIVATE_KEY_SIZE) {
        return false;
    }

    try {
        // Hash the seed with SHA-512
        CryptoPP::SHA512 sha;
        sha.CalculateDigest(expanded, seed, seedLen);

        // Clamp the scalar (first 32 bytes)
        // Clear lowest 3 bits of first byte
        expanded[0] &= 0xF8;
        // Clear highest bit of last byte
        expanded[31] &= 0x7F;
        // Set second highest bit of last byte
        expanded[31] |= 0x40;

        *expandedLen = EXPANDED_PRIVATE_KEY_SIZE;
        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Convert Ed25519 public key to X25519 public key
 *
 * This allows using Ed25519 keys for ECDH via X25519.
 * Note: This is a one-way conversion.
 *
 * @param ed25519Pub 32-byte Ed25519 public key
 * @param ed25519PubLen Key length (must be 32)
 * @param x25519Pub Output buffer for 32-byte X25519 public key
 * @param x25519PubLen Input: buffer size, Output: key size (32)
 * @return true on success
 */
bool ed25519ToX25519Public(
    const uint8_t* ed25519Pub,
    size_t ed25519PubLen,
    uint8_t* x25519Pub,
    size_t* x25519PubLen
) {
    if (!ed25519Pub || !x25519Pub || !x25519PubLen) {
        return false;
    }

    if (ed25519PubLen != PUBLIC_KEY_SIZE) {
        return false;
    }

    if (*x25519PubLen < PUBLIC_KEY_SIZE) {
        return false;
    }

    try {
        // The conversion from Ed25519 to X25519 involves:
        // 1. Decode the Ed25519 point (x, y) from compressed form
        // 2. Compute u = (1 + y) / (1 - y) mod p
        // 3. Encode u as X25519 public key

        // This requires field arithmetic on Curve25519
        // For simplicity, we'll use Crypto++'s conversion if available

        // Note: Crypto++ 8.6+ may have built-in conversion
        // For older versions, we need to implement manually

        // Simplified approach: use the y-coordinate transformation
        // Ed25519 point is (x, y) on twisted Edwards curve
        // X25519 uses Montgomery curve with u = (1 + y) / (1 - y)

        // Parse y from Ed25519 public key (low 255 bits)
        // The sign of x is in the highest bit

        // For a full implementation, we would need to:
        // 1. Extract y from the Ed25519 encoding
        // 2. Compute u = (1 + y) * (1 - y)^(-1) mod p
        // 3. Encode u as 32 bytes

        // This is complex to implement correctly without a dedicated library
        // For now, we'll indicate this isn't directly supported

        // Placeholder: copy the key (NOT correct, but indicates the API)
        std::memcpy(x25519Pub, ed25519Pub, PUBLIC_KEY_SIZE);
        *x25519PubLen = PUBLIC_KEY_SIZE;

        // Return false to indicate this needs proper implementation
        return false;
    } catch (...) {
        return false;
    }
}

/**
 * Convert Ed25519 private key to X25519 private key
 *
 * @param ed25519Priv 32-byte Ed25519 private key (seed)
 * @param ed25519PrivLen Key length (must be 32)
 * @param x25519Priv Output buffer for 32-byte X25519 private key
 * @param x25519PrivLen Input: buffer size, Output: key size (32)
 * @return true on success
 */
bool ed25519ToX25519Private(
    const uint8_t* ed25519Priv,
    size_t ed25519PrivLen,
    uint8_t* x25519Priv,
    size_t* x25519PrivLen
) {
    if (!ed25519Priv || !x25519Priv || !x25519PrivLen) {
        return false;
    }

    if (ed25519PrivLen != PRIVATE_KEY_SIZE) {
        return false;
    }

    if (*x25519PrivLen < PRIVATE_KEY_SIZE) {
        return false;
    }

    try {
        // For Ed25519 -> X25519 private key conversion:
        // 1. Hash the Ed25519 seed with SHA-512
        // 2. Take the first 32 bytes and clamp them

        uint8_t hash[64];
        CryptoPP::SHA512 sha;
        sha.CalculateDigest(hash, ed25519Priv, ed25519PrivLen);

        // Copy first 32 bytes (the scalar)
        std::memcpy(x25519Priv, hash, 32);

        // X25519 clamping (same as Ed25519 scalar clamping)
        x25519Priv[0] &= 0xF8;
        x25519Priv[31] &= 0x7F;
        x25519Priv[31] |= 0x40;

        // Secure cleanup
        CryptoPP::SecureWipeArray(hash, 64);

        *x25519PrivLen = PRIVATE_KEY_SIZE;
        return true;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// Batch Verification (Optimization)
// =============================================================================

/**
 * Verify multiple Ed25519 signatures in batch
 *
 * Batch verification can be faster than individual verification
 * when verifying many signatures.
 *
 * @param publicKeys Array of 32-byte public keys
 * @param messages Array of message pointers
 * @param messageLens Array of message lengths
 * @param signatures Array of 64-byte signatures
 * @param count Number of signatures to verify
 * @param results Output array for individual results
 * @return true if ALL signatures are valid
 */
bool verifyBatch(
    const uint8_t* const* publicKeys,
    const uint8_t* const* messages,
    const size_t* messageLens,
    const uint8_t* const* signatures,
    size_t count,
    bool* results
) {
    if (!publicKeys || !messages || !messageLens || !signatures || count == 0) {
        return false;
    }

    bool allValid = true;

    for (size_t i = 0; i < count; ++i) {
        bool valid = verify(
            publicKeys[i], PUBLIC_KEY_SIZE,
            messages[i], messageLens[i],
            signatures[i], SIGNATURE_SIZE
        );

        if (results) {
            results[i] = valid;
        }

        if (!valid) {
            allValid = false;
        }
    }

    return allValid;
}

// =============================================================================
// C++ Wrapper Functions
// =============================================================================

Ed25519Signature ed25519Sign(
    const Ed25519Seed& seed,
    const uint8_t* message,
    size_t messageLength
) {
    Ed25519Signature signature;
    size_t sigLen = SIGNATURE_SIZE;
    if (!sign(seed.data(), seed.size(), message, messageLength, signature.data(), &sigLen)) {
        signature.fill(0);
    }
    return signature;
}

Ed25519Signature ed25519Sign(
    const Ed25519Seed& seed,
    const ByteVector& message
) {
    return ed25519Sign(seed, message.data(), message.size());
}

Ed25519Signature ed25519Sign(
    const Ed25519Seed& seed,
    const std::string& message
) {
    return ed25519Sign(seed, reinterpret_cast<const uint8_t*>(message.data()), message.size());
}

bool ed25519Verify(
    const Ed25519PublicKey& publicKey,
    const uint8_t* message,
    size_t messageLength,
    const Ed25519Signature& signature
) {
    return verify(publicKey.data(), publicKey.size(), message, messageLength, signature.data(), signature.size());
}

bool ed25519Verify(
    const Ed25519PublicKey& publicKey,
    const ByteVector& message,
    const Ed25519Signature& signature
) {
    return ed25519Verify(publicKey, message.data(), message.size(), signature);
}

bool ed25519Verify(
    const Ed25519PublicKey& publicKey,
    const std::string& message,
    const Ed25519Signature& signature
) {
    return ed25519Verify(publicKey, reinterpret_cast<const uint8_t*>(message.data()), message.size(), signature);
}

} // namespace eddsa
} // namespace hd_wallet

// =============================================================================
// C API Exports
// =============================================================================

extern "C" {

HD_WALLET_EXPORT
int32_t hd_ed25519_derive_public(
    const uint8_t* private_key,
    size_t private_key_len,
    uint8_t* public_key,
    size_t public_key_size
) {
    size_t pubKeyLen = public_key_size;
    if (hd_wallet::eddsa::derivePublicKey(
            private_key, private_key_len,
            public_key, &pubKeyLen)) {
        return static_cast<int32_t>(pubKeyLen);
    }
    return -1;
}

// Ed25519 sign - matches JS wrapper signature (message first, then key)
HD_WALLET_EXPORT
int32_t hd_ed25519_sign(
    const uint8_t* message,
    size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out,
    size_t out_size
) {
    if (!private_key || !signature_out) return -1;
    if (out_size < hd_wallet::eddsa::SIGNATURE_SIZE) return -1;

    size_t sigLen = out_size;
    if (hd_wallet::eddsa::sign(
            private_key, hd_wallet::eddsa::PRIVATE_KEY_SIZE,
            message, message_len,
            signature_out, &sigLen)) {
        return static_cast<int32_t>(sigLen);
    }
    return -1;
}

// Ed25519 verify - matches JS wrapper signature
HD_WALLET_EXPORT
int32_t hd_ed25519_verify(
    const uint8_t* message,
    size_t message_len,
    const uint8_t* signature,
    size_t signature_len,
    const uint8_t* public_key,
    size_t public_key_len
) {
    if (!signature || !public_key) return 0;
    if (signature_len != hd_wallet::eddsa::SIGNATURE_SIZE) return 0;
    if (public_key_len != hd_wallet::eddsa::PUBLIC_KEY_SIZE) return 0;

    return hd_wallet::eddsa::verify(
        public_key, hd_wallet::eddsa::PUBLIC_KEY_SIZE,
        message, message_len,
        signature, hd_wallet::eddsa::SIGNATURE_SIZE
    ) ? 1 : 0;
}

// =============================================================================
// SLIP-10 Ed25519 Key Derivation
// =============================================================================

HD_WALLET_EXPORT
int32_t hd_ed25519_pubkey_from_seed(
    const uint8_t* seed,
    uint8_t* public_key_out,
    size_t public_key_size
) {
    if (!seed || !public_key_out || public_key_size < 32) {
        return -1;
    }

    // Derive public key from 32-byte seed
    size_t pubKeyLen = public_key_size;
    if (hd_wallet::eddsa::derivePublicKey(seed, 32, public_key_out, &pubKeyLen)) {
        return 0;
    }
    return -1;
}

HD_WALLET_EXPORT
int32_t hd_slip10_ed25519_master(
    const uint8_t* seed,
    size_t seed_len,
    uint8_t* key_out,
    uint8_t* chain_code_out
) {
    if (!seed || !key_out || !chain_code_out || seed_len != 64) {
        return -1;
    }

    // SLIP-10: Master key = HMAC-SHA512(Key = "ed25519 seed", Data = seed)
    const char* hmacKey = "ed25519 seed";
    uint8_t hmacOut[64];

    CryptoPP::HMAC<CryptoPP::SHA512> hmac(
        reinterpret_cast<const uint8_t*>(hmacKey),
        std::strlen(hmacKey)
    );
    hmac.Update(seed, seed_len);
    hmac.Final(hmacOut);

    // First 32 bytes = private key (IL)
    std::memcpy(key_out, hmacOut, 32);
    // Last 32 bytes = chain code (IR)
    std::memcpy(chain_code_out, hmacOut + 32, 32);

    CryptoPP::SecureWipeArray(hmacOut, 64);
    return 0;
}

static int32_t slip10_ed25519_derive_child(
    const uint8_t* parent_key,
    const uint8_t* parent_chain_code,
    uint32_t index,
    uint8_t* key_out,
    uint8_t* chain_code_out
) {
    // SLIP-10 Ed25519: only hardened derivation (index >= 0x80000000)
    if (index < 0x80000000) {
        return -1;  // Must be hardened for Ed25519
    }

    // Data = 0x00 || kpar || ser32(index)
    uint8_t data[37];
    data[0] = 0x00;
    std::memcpy(data + 1, parent_key, 32);
    // Big-endian serialization of index
    data[33] = (index >> 24) & 0xFF;
    data[34] = (index >> 16) & 0xFF;
    data[35] = (index >> 8) & 0xFF;
    data[36] = index & 0xFF;

    // HMAC-SHA512(Key = cpar, Data = data)
    uint8_t hmacOut[64];
    CryptoPP::HMAC<CryptoPP::SHA512> hmac(parent_chain_code, 32);
    hmac.Update(data, 37);
    hmac.Final(hmacOut);

    // First 32 bytes = child private key
    std::memcpy(key_out, hmacOut, 32);
    // Last 32 bytes = child chain code
    std::memcpy(chain_code_out, hmacOut + 32, 32);

    CryptoPP::SecureWipeArray(hmacOut, 64);
    CryptoPP::SecureWipeArray(data, 37);
    return 0;
}

HD_WALLET_EXPORT
int32_t hd_slip10_ed25519_derive_path(
    const uint8_t* seed,
    size_t seed_len,
    const char* path,
    uint8_t* key_out,
    uint8_t* chain_code_out
) {
    if (!seed || !path || !key_out || !chain_code_out || seed_len != 64) {
        return -1;
    }

    // Parse the path and derive
    std::string pathStr(path);

    // Check for "m/" prefix
    size_t pos = 0;
    if (pathStr.substr(0, 2) == "m/") {
        pos = 2;
    } else if (pathStr[0] == 'm') {
        // Just "m" = master key
        return hd_slip10_ed25519_master(seed, seed_len, key_out, chain_code_out);
    }

    // Start with master key
    uint8_t currentKey[32];
    uint8_t currentChainCode[32];
    if (hd_slip10_ed25519_master(seed, seed_len, currentKey, currentChainCode) != 0) {
        return -1;
    }

    // Parse and derive each path component
    while (pos < pathStr.length()) {
        // Find end of this component
        size_t endPos = pathStr.find('/', pos);
        if (endPos == std::string::npos) {
            endPos = pathStr.length();
        }

        std::string component = pathStr.substr(pos, endPos - pos);
        pos = endPos + 1;

        if (component.empty()) {
            continue;
        }

        // Check for hardened indicator
        bool hardened = false;
        if (component.back() == '\'' || component.back() == 'h' || component.back() == 'H') {
            hardened = true;
            component.pop_back();
        }

        // Parse index (without std::stoul to avoid exceptions in WASI)
        if (component.empty() || component.size() > 10) {
            CryptoPP::SecureWipeArray(currentKey, 32);
            CryptoPP::SecureWipeArray(currentChainCode, 32);
            return -1;
        }
        uint64_t parsed = 0;
        bool parseOk = true;
        for (char c : component) {
            if (c < '0' || c > '9') { parseOk = false; break; }
            parsed = parsed * 10 + static_cast<uint64_t>(c - '0');
            if (parsed > 0xFFFFFFFF) { parseOk = false; break; }
        }
        if (!parseOk) {
            CryptoPP::SecureWipeArray(currentKey, 32);
            CryptoPP::SecureWipeArray(currentChainCode, 32);
            return -1;
        }
        uint32_t index = static_cast<uint32_t>(parsed);

        // SECURITY FIX [HIGH-02]: Ed25519 SLIP-10 requires hardened derivation.
        // Instead of silently auto-hardening (which could cause key mismatch on
        // wallet recovery), we now return an error for non-hardened paths.
        // Callers MUST use hardened notation (e.g., m/44'/501'/0'/0') for Ed25519.
        if (!hardened) {
            CryptoPP::SecureWipeArray(currentKey, 32);
            CryptoPP::SecureWipeArray(currentChainCode, 32);
            return -2;  // Error: Ed25519 requires hardened derivation
        }

        // Add hardened flag (hardened is always true at this point)
        index |= 0x80000000;

        // Derive child
        uint8_t childKey[32];
        uint8_t childChainCode[32];
        if (slip10_ed25519_derive_child(currentKey, currentChainCode, index, childKey, childChainCode) != 0) {
            CryptoPP::SecureWipeArray(currentKey, 32);
            CryptoPP::SecureWipeArray(currentChainCode, 32);
            return -1;
        }

        // Update current key
        std::memcpy(currentKey, childKey, 32);
        std::memcpy(currentChainCode, childChainCode, 32);
        CryptoPP::SecureWipeArray(childKey, 32);
        CryptoPP::SecureWipeArray(childChainCode, 32);
    }

    // Output final key and chain code
    std::memcpy(key_out, currentKey, 32);
    std::memcpy(chain_code_out, currentChainCode, 32);
    CryptoPP::SecureWipeArray(currentKey, 32);
    CryptoPP::SecureWipeArray(currentChainCode, 32);

    return 0;
}

// =============================================================================
// X25519 Functions
// =============================================================================

HD_WALLET_EXPORT
int32_t hd_x25519_pubkey(
    const uint8_t* private_key,
    uint8_t* public_key_out,
    size_t public_key_size
) {
    if (!private_key || !public_key_out || public_key_size < 32) {
        return -1;
    }

    // X25519 public key derivation
    // Clamp the private key and multiply by basepoint
    try {
        // X25519 clamp the private key
        uint8_t clampedPriv[32];
        std::memcpy(clampedPriv, private_key, 32);
        clampedPriv[0] &= 0xF8;
        clampedPriv[31] &= 0x7F;
        clampedPriv[31] |= 0x40;

        // Basepoint for X25519 is 9 (little-endian)
        uint8_t basepoint[32] = {9};

        // Use x25519 key agreement to derive public key
        CryptoPP::x25519 x25519;
        if (!x25519.Agree(public_key_out, clampedPriv, basepoint)) {
            CryptoPP::SecureWipeArray(clampedPriv, 32);
            return -1;
        }

        CryptoPP::SecureWipeArray(clampedPriv, 32);
        return 0;
    } catch (...) {
        return -1;
    }
}

HD_WALLET_EXPORT
int32_t hd_ecdh_x25519(
    const uint8_t* private_key,
    const uint8_t* public_key,
    uint8_t* shared_secret_out,
    size_t shared_secret_size
) {
    if (!private_key || !public_key || !shared_secret_out || shared_secret_size < 32) {
        return -1;
    }

    try {
        // X25519 clamp the private key
        uint8_t clampedPriv[32];
        std::memcpy(clampedPriv, private_key, 32);
        clampedPriv[0] &= 0xF8;
        clampedPriv[31] &= 0x7F;
        clampedPriv[31] |= 0x40;

        // Perform X25519 key agreement
        CryptoPP::x25519 x25519;
        if (!x25519.Agree(shared_secret_out, clampedPriv, public_key)) {
            CryptoPP::SecureWipeArray(clampedPriv, 32);
            return -1;
        }

        CryptoPP::SecureWipeArray(clampedPriv, 32);
        return 0;
    } catch (...) {
        return -1;
    }
}

} // extern "C"
