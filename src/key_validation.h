/**
 * @file key_validation.h
 * @brief Key and encoding checks shared by the exports (internal)
 *
 * One definition of "a valid key" for every curve, used by the
 * hd_curve_validate_* exports (which the JS wrappers call before any key
 * reaches another export), by libp2p peer IDs and by Ed25519 verification.
 *
 * Public keys:
 * - secp256k1, P-256, P-384: SEC1 compressed (02/03 || x) or uncompressed
 *   (04 || x || y) at the curve's size, decoding to a point of the curve with
 *   x, y < p. Hybrid (06/07) encodings and the point at infinity are refused.
 *   secp256k1 is parsed by libsecp256k1 and P-256/P-384 by OpenSSL when the
 *   build has them, by Crypto++ otherwise.
 * - Ed25519: 32 bytes, y < p (canonical), decoding to a curve point, and not
 *   one of the eight points of small order.
 * - X25519: 32 bytes (low-order peer keys fail in the key agreement itself).
 *
 * Private keys: the curve's scalar size; for secp256k1, P-256 and P-384 also
 * 0 < d < n, compared in constant time. Any 32 bytes are an Ed25519 seed or
 * an X25519 scalar (both are hashed or clamped before use).
 */

#ifndef HD_WALLET_KEY_VALIDATION_H
#define HD_WALLET_KEY_VALIDATION_H

#include "hd_wallet/types.h"

#include <cstddef>
#include <cstdint>

namespace hd_wallet::keys {

bool isValidPublicKey(Curve curve, const uint8_t* key, size_t length) noexcept;
bool isValidPrivateKey(Curve curve, const uint8_t* key, size_t length) noexcept;

/// Ed25519 point encoding check for RFC 8032 strict verification: y < p
/// (canonical) and not a point of small order. Says nothing about whether the
/// encoding decodes; verification itself rejects one that does not.
bool ed25519EncodingIsStrict(const uint8_t encoded[32]) noexcept;

/// Ed25519 signature scalar check: S < L (RFC 8032 section 5.1.7).
bool ed25519ScalarIsCanonical(const uint8_t s[32]) noexcept;

/// Both strict-verification checks on a 32-byte public key and a 64-byte
/// signature R || S: A and R strict encodings, S < L.
bool ed25519SignatureIsStrict(const uint8_t publicKey[32], const uint8_t signature[64]) noexcept;

} // namespace hd_wallet::keys

#endif // HD_WALLET_KEY_VALIDATION_H
