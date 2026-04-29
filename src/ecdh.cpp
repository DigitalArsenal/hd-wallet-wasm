/**
 * @file ecdh.cpp
 * @brief ECDH Key Exchange Implementation
 *
 * Elliptic Curve Diffie-Hellman key exchange for:
 * - secp256k1 (Bitcoin, Ethereum)
 * - P-256 (NIST)
 * - P-384 (NIST)
 * - X25519 (Curve25519)
 */

#include "hd_wallet/types.h"
#include "hd_wallet/config.h"
#include "hd_wallet/error.h"
#include "hd_wallet/ecdh.h"
#include "hd_wallet/secure_rng.h"

#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#include <cryptopp/integer.h>
#include <cryptopp/sha.h>
#include <cryptopp/xed25519.h>
#include <cryptopp/secblock.h>

#include <cstring>
#include <stdexcept>

namespace hd_wallet {
namespace ecdh {

// =============================================================================
// Internal Helpers
// =============================================================================

namespace {

/**
 * Decompress a public key point on an elliptic curve
 */
template<typename Curve>
CryptoPP::ECPPoint decompressPoint(
    const Curve& curve,
    const uint8_t* compressed,
    size_t compressedLen,
    size_t coordSize
) {
    if (compressedLen != coordSize + 1) {
        throw std::invalid_argument("Invalid compressed key length");
    }

    bool yOdd = (compressed[0] == 0x03);
    CryptoPP::Integer x(compressed + 1, coordSize);

    const CryptoPP::ECP& ec = curve.GetCurve();
    CryptoPP::Integer p = ec.GetField().GetModulus();
    CryptoPP::Integer a = ec.GetA();
    CryptoPP::Integer b = ec.GetB();

    // y^2 = x^3 + ax + b mod p
    CryptoPP::Integer y2 = (a_exp_b_mod_c(x, 3, p) + a * x + b) % p;

    // Compute modular square root (works when p = 3 mod 4)
    CryptoPP::Integer y = a_exp_b_mod_c(y2, (p + 1) / 4, p);

    if (y.IsOdd() != yOdd) {
        y = p - y;
    }

    return CryptoPP::ECPPoint(x, y);
}

/**
 * Parse a public key (compressed or uncompressed) into a point
 */
template<typename Curve>
CryptoPP::ECPPoint parsePublicKey(
    const Curve& curve,
    const uint8_t* key,
    size_t keyLen,
    size_t coordSize
) {
    CryptoPP::ECPPoint point;

    if (keyLen == coordSize + 1) {
        // Compressed format
        if (key[0] != 0x02 && key[0] != 0x03) {
            throw std::invalid_argument("Invalid compressed key prefix");
        }
        return decompressPoint(curve, key, keyLen, coordSize);
    } else if (keyLen == 2 * coordSize + 1) {
        // Uncompressed format
        if (key[0] != 0x04) {
            throw std::invalid_argument("Invalid uncompressed key prefix");
        }
        point.x.Decode(key + 1, coordSize);
        point.y.Decode(key + 1 + coordSize, coordSize);
        point.identity = false;
    } else {
        throw std::invalid_argument("Invalid public key length");
    }

    return point;
}

/**
 * Perform ECDH on a Weierstrass curve
 */
bool ecdhWeierstrass(
    const CryptoPP::OID& oid,
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* publicKey,
    size_t publicKeyLen,
    uint8_t* sharedSecret,
    size_t* sharedSecretLen,
    size_t coordSize
) {
    if (!privateKey || !publicKey || !sharedSecret || !sharedSecretLen) {
        return false;
    }

    if (privateKeyLen != coordSize) {
        return false;
    }

    if (*sharedSecretLen < coordSize) {
        return false;
    }

    try {
        // Initialize curve parameters
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve;
        curve.Initialize(oid);

        // Parse private key as integer
        CryptoPP::Integer d(privateKey, privateKeyLen);

        // Validate private key
        CryptoPP::Integer order = curve.GetGroupOrder();
        if (d <= 0 || d >= order) {
            return false;
        }

        // Parse public key point
        CryptoPP::ECPPoint Q = parsePublicKey(curve, publicKey, publicKeyLen, coordSize);

        // Validate public key is on curve
        if (!curve.GetCurve().VerifyPoint(Q)) {
            return false;
        }

        // Compute shared secret: S = d * Q
        CryptoPP::ECPPoint S = curve.GetCurve().ScalarMultiply(Q, d);

        // Check for point at infinity
        if (S.identity) {
            return false;
        }

        // Output the x-coordinate as the shared secret
        S.x.Encode(sharedSecret, coordSize);
        *sharedSecretLen = coordSize;

        return true;
    } catch (...) {
        return false;
    }
}

} // anonymous namespace

// =============================================================================
// ECDH for secp256k1, P-256, P-384
// =============================================================================

/**
 * Perform ECDH key exchange
 *
 * Computes the shared secret from a private key and peer's public key.
 * The shared secret is the x-coordinate of the resulting point.
 *
 * @param curve Elliptic curve (SECP256K1, P256, or P384)
 * @param privateKey Own private key
 * @param privateKeyLen Private key length
 * @param publicKey Peer's public key (compressed or uncompressed)
 * @param publicKeyLen Public key length
 * @param sharedSecret Output buffer for shared secret
 * @param sharedSecretLen Input: buffer size, Output: secret size
 * @return true on success
 */
bool ecdh(
    Curve curve,
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* publicKey,
    size_t publicKeyLen,
    uint8_t* sharedSecret,
    size_t* sharedSecretLen
) {
    switch (curve) {
        case Curve::SECP256K1:
            return ecdhWeierstrass(
                CryptoPP::ASN1::secp256k1(),
                privateKey, privateKeyLen,
                publicKey, publicKeyLen,
                sharedSecret, sharedSecretLen,
                32
            );

        case Curve::P256:
            return ecdhWeierstrass(
                CryptoPP::ASN1::secp256r1(),
                privateKey, privateKeyLen,
                publicKey, publicKeyLen,
                sharedSecret, sharedSecretLen,
                32
            );

        case Curve::P384:
            return ecdhWeierstrass(
                CryptoPP::ASN1::secp384r1(),
                privateKey, privateKeyLen,
                publicKey, publicKeyLen,
                sharedSecret, sharedSecretLen,
                48
            );

        default:
            return false;
    }
}

/**
 * Perform ECDH with hash derivation
 *
 * Computes ECDH and then hashes the shared secret with SHA-256.
 * This is a common pattern for deriving symmetric keys.
 *
 * @param curve Elliptic curve
 * @param privateKey Own private key
 * @param privateKeyLen Private key length
 * @param publicKey Peer's public key
 * @param publicKeyLen Public key length
 * @param derivedKey Output buffer for 32-byte derived key
 * @param derivedKeyLen Input: buffer size, Output: key size (32)
 * @return true on success
 */
bool ecdhSha256(
    Curve curve,
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* publicKey,
    size_t publicKeyLen,
    uint8_t* derivedKey,
    size_t* derivedKeyLen
) {
    if (!derivedKey || !derivedKeyLen || *derivedKeyLen < 32) {
        return false;
    }

    // Get the raw shared secret
    size_t secretSize = (curve == Curve::P384) ? 48 : 32;
    CryptoPP::SecByteBlock secret(secretSize);
    size_t actualSecretLen = secretSize;

    if (!ecdh(curve, privateKey, privateKeyLen, publicKey, publicKeyLen,
              secret.data(), &actualSecretLen)) {
        return false;
    }

    // Hash with SHA-256
    try {
        CryptoPP::SHA256 sha;
        sha.CalculateDigest(derivedKey, secret.data(), actualSecretLen);
        *derivedKeyLen = 32;

        return true;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// X25519 Key Exchange
// =============================================================================

/**
 * Perform X25519 key exchange
 *
 * X25519 is Diffie-Hellman on Curve25519 using Montgomery coordinates.
 * It provides 128-bit security and is resistant to timing attacks.
 *
 * @param privateKey 32-byte X25519 private key
 * @param privateKeyLen Private key length (must be 32)
 * @param publicKey 32-byte X25519 public key
 * @param publicKeyLen Public key length (must be 32)
 * @param sharedSecret Output buffer for 32-byte shared secret
 * @param sharedSecretLen Input: buffer size, Output: secret size (32)
 * @return true on success
 */
bool x25519(
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* publicKey,
    size_t publicKeyLen,
    uint8_t* sharedSecret,
    size_t* sharedSecretLen
) {
#if !HD_WALLET_ENABLE_X25519
    (void)privateKey;
    (void)privateKeyLen;
    (void)publicKey;
    (void)publicKeyLen;
    (void)sharedSecret;
    (void)sharedSecretLen;
    return false;
#else
    if (!privateKey || !publicKey || !sharedSecret || !sharedSecretLen) {
        return false;
    }

    if (privateKeyLen != 32 || publicKeyLen != 32) {
        return false;
    }

    if (*sharedSecretLen < 32) {
        return false;
    }

    try {
        // Create X25519 object with private key
        CryptoPP::x25519 x25519_ctx(privateKey);

        // Compute shared secret - Agree needs (output, privateKey, otherPublicKey)
        if (!x25519_ctx.Agree(sharedSecret, privateKey, publicKey)) {
            return false;
        }

        *sharedSecretLen = 32;

        // X25519 can produce an all-zero result for some invalid inputs
        // Check for this case
        bool allZero = true;
        for (size_t i = 0; i < 32; ++i) {
            if (sharedSecret[i] != 0) {
                allZero = false;
                break;
            }
        }

        if (allZero) {
            return false;
        }

        return true;
    } catch (...) {
        return false;
    }
#endif
}

/**
 * Generate X25519 public key from private key
 *
 * @param privateKey 32-byte X25519 private key
 * @param privateKeyLen Private key length (must be 32)
 * @param publicKey Output buffer for 32-byte public key
 * @param publicKeyLen Input: buffer size, Output: key size (32)
 * @return true on success
 */
bool x25519PublicKey(
    const uint8_t* privateKey,
    size_t privateKeyLen,
    uint8_t* publicKey,
    size_t* publicKeyLen
) {
#if !HD_WALLET_ENABLE_X25519
    (void)privateKey;
    (void)privateKeyLen;
    (void)publicKey;
    (void)publicKeyLen;
    return false;
#else
    if (!privateKey || !publicKey || !publicKeyLen) {
        return false;
    }

    if (privateKeyLen != 32) {
        return false;
    }

    if (*publicKeyLen < 32) {
        return false;
    }

    try {
        // Create X25519 object and generate public key
        CryptoPP::x25519 x25519_ctx(privateKey);

        // Get the public key
        x25519_ctx.GeneratePublicKey(
            CryptoPP::NullRNG(),
            privateKey,
            publicKey
        );

        *publicKeyLen = 32;
        return true;
    } catch (...) {
        return false;
    }
#endif
}

/**
 * Perform X25519 with SHA-256 key derivation
 *
 * @param privateKey 32-byte X25519 private key
 * @param privateKeyLen Private key length (must be 32)
 * @param publicKey 32-byte X25519 public key
 * @param publicKeyLen Public key length (must be 32)
 * @param derivedKey Output buffer for 32-byte derived key
 * @param derivedKeyLen Input: buffer size, Output: key size (32)
 * @return true on success
 */
bool x25519Sha256(
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* publicKey,
    size_t publicKeyLen,
    uint8_t* derivedKey,
    size_t* derivedKeyLen
) {
    if (!derivedKey || !derivedKeyLen || *derivedKeyLen < 32) {
        return false;
    }

    // Get the raw shared secret
    CryptoPP::SecByteBlock secret(32);
    size_t secretLen = 32;

    if (!x25519(privateKey, privateKeyLen, publicKey, publicKeyLen,
                secret.data(), &secretLen)) {
        return false;
    }

    // Hash with SHA-256
    try {
        CryptoPP::SHA256 sha;
        sha.CalculateDigest(derivedKey, secret.data(), secretLen);
        *derivedKeyLen = 32;

        return true;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// Key Validation
// =============================================================================

/**
 * Validate an X25519 public key
 *
 * Checks that the key is not a low-order point that would result
 * in a zero shared secret.
 *
 * @param publicKey 32-byte X25519 public key
 * @param publicKeyLen Public key length (must be 32)
 * @return true if the key is valid for ECDH
 */
bool validateX25519PublicKey(const uint8_t* publicKey, size_t publicKeyLen) {
    if (!publicKey || publicKeyLen != 32) {
        return false;
    }

    // List of low-order points on Curve25519 that should be rejected
    // These produce all-zero shared secrets and are potential attacks

    // Point at infinity (all zeros)
    static const uint8_t zero[32] = {0};
    if (std::memcmp(publicKey, zero, 32) == 0) {
        return false;
    }

    // Other low-order points
    // Point of order 2
    static const uint8_t order2[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
    };
    if (std::memcmp(publicKey, order2, 32) == 0) {
        return false;
    }

    // Points of order 4
    static const uint8_t order4_1[32] = {
        0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    if (std::memcmp(publicKey, order4_1, 32) == 0) {
        return false;
    }

    // Point of order 8 (several of these exist)
    // These are less commonly checked but can be added for extra security

    return true;
}

/**
 * Validate an ECDH public key for a given curve
 *
 * @param curve Elliptic curve
 * @param publicKey Public key
 * @param publicKeyLen Public key length
 * @return true if the key is valid for ECDH
 */
bool validatePublicKey(Curve curve, const uint8_t* publicKey, size_t publicKeyLen) {
    if (!publicKey) {
        return false;
    }

    switch (curve) {
        case Curve::SECP256K1: {
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params;
            params.Initialize(CryptoPP::ASN1::secp256k1());
            try {
                CryptoPP::ECPPoint point = parsePublicKey(params, publicKey, publicKeyLen, 32);
                return params.GetCurve().VerifyPoint(point);
            } catch (...) {
                return false;
            }
        }

        case Curve::P256: {
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params;
            params.Initialize(CryptoPP::ASN1::secp256r1());
            try {
                CryptoPP::ECPPoint point = parsePublicKey(params, publicKey, publicKeyLen, 32);
                return params.GetCurve().VerifyPoint(point);
            } catch (...) {
                return false;
            }
        }

        case Curve::P384: {
            CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params;
            params.Initialize(CryptoPP::ASN1::secp384r1());
            try {
                CryptoPP::ECPPoint point = parsePublicKey(params, publicKey, publicKeyLen, 48);
                return params.GetCurve().VerifyPoint(point);
            } catch (...) {
                return false;
            }
        }

        case Curve::X25519:
            return validateX25519PublicKey(publicKey, publicKeyLen);

        default:
            return false;
    }
}

// =============================================================================
// HKDF Key Derivation (for use with ECDH)
// =============================================================================

/**
 * HKDF-Extract using SHA-256
 *
 * Extracts a pseudorandom key from input keying material.
 *
 * @param salt Optional salt (can be nullptr for default)
 * @param saltLen Salt length
 * @param ikm Input keying material (e.g., ECDH shared secret)
 * @param ikmLen IKM length
 * @param prk Output pseudorandom key (32 bytes)
 * @param prkLen Input: buffer size, Output: key size (32)
 * @return true on success
 */
bool hkdfExtract(
    const uint8_t* salt,
    size_t saltLen,
    const uint8_t* ikm,
    size_t ikmLen,
    uint8_t* prk,
    size_t* prkLen
) {
    if (!ikm || !prk || !prkLen || *prkLen < 32) {
        return false;
    }

    try {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac;

        // If salt is empty, use zeros
        if (!salt || saltLen == 0) {
            uint8_t zeroSalt[32] = {0};
            hmac.SetKey(zeroSalt, 32);
        } else {
            hmac.SetKey(salt, saltLen);
        }

        hmac.CalculateDigest(prk, ikm, ikmLen);
        *prkLen = 32;

        return true;
    } catch (...) {
        return false;
    }
}

/**
 * HKDF-Expand using SHA-256
 *
 * Expands a pseudorandom key into output keying material.
 *
 * @param prk Pseudorandom key from HKDF-Extract
 * @param prkLen PRK length
 * @param info Context and application-specific info
 * @param infoLen Info length
 * @param okm Output keying material
 * @param okmLen Desired OKM length (max 255 * 32 bytes)
 * @return true on success
 */
bool hkdfExpand(
    const uint8_t* prk,
    size_t prkLen,
    const uint8_t* info,
    size_t infoLen,
    uint8_t* okm,
    size_t okmLen
) {
    if (!prk || !okm || okmLen == 0) {
        return false;
    }

    if (okmLen > 255 * 32) {
        return false;  // Max output length
    }

    try {
        CryptoPP::HMAC<CryptoPP::SHA256> hmac;
        hmac.SetKey(prk, prkLen);

        size_t n = (okmLen + 31) / 32;  // Number of iterations
        CryptoPP::SecByteBlock t(32);
        CryptoPP::SecByteBlock prevT;

        for (size_t i = 1; i <= n; ++i) {
            hmac.Restart();

            // T(i) = HMAC(PRK, T(i-1) | info | i)
            if (i > 1) {
                hmac.Update(prevT.data(), prevT.size());
            }
            if (info && infoLen > 0) {
                hmac.Update(info, infoLen);
            }
            uint8_t counter = static_cast<uint8_t>(i);
            hmac.Update(&counter, 1);
            hmac.Final(t.data());

            // Copy to output
            size_t copyLen = std::min(static_cast<size_t>(32), okmLen - (i - 1) * 32);
            std::memcpy(okm + (i - 1) * 32, t.data(), copyLen);

            prevT = t;
        }

        return true;
    } catch (...) {
        return false;
    }
}

/**
 * HKDF (Extract-then-Expand) using SHA-256
 *
 * Combines Extract and Expand for convenience.
 *
 * @param salt Optional salt
 * @param saltLen Salt length
 * @param ikm Input keying material
 * @param ikmLen IKM length
 * @param info Context info
 * @param infoLen Info length
 * @param okm Output keying material
 * @param okmLen Desired OKM length
 * @return true on success
 */
bool hkdf(
    const uint8_t* salt,
    size_t saltLen,
    const uint8_t* ikm,
    size_t ikmLen,
    const uint8_t* info,
    size_t infoLen,
    uint8_t* okm,
    size_t okmLen
) {
    CryptoPP::SecByteBlock prk(32);
    size_t prkLen = 32;

    if (!hkdfExtract(salt, saltLen, ikm, ikmLen, prk.data(), &prkLen)) {
        return false;
    }

    return hkdfExpand(prk.data(), prkLen, info, infoLen, okm, okmLen);
}

// =============================================================================
// ECDH + HKDF Combined Key Derivation
// =============================================================================

Result<ByteVector> ecdhDeriveKey(
    Curve curve,
    const ByteVector& privateKey,
    const ByteVector& publicKey,
    const ByteVector& salt,
    const ByteVector& info,
    size_t keyLength
) {
    if (keyLength == 0 || keyLength > 255 * 32) {
        return Result<ByteVector>::fail(Error::INVALID_ARGUMENT);
    }

    // Step 1: Compute ECDH shared secret
    size_t secretSize = (curve == Curve::P384) ? 48 : 32;
    CryptoPP::SecByteBlock sharedSecret(secretSize);
    size_t actualSecretLen = secretSize;

    bool ecdhOk;
    if (curve == Curve::X25519) {
        ecdhOk = x25519(
            privateKey.data(), privateKey.size(),
            publicKey.data(), publicKey.size(),
            sharedSecret.data(), &actualSecretLen);
    } else {
        ecdhOk = ecdh(
            curve,
            privateKey.data(), privateKey.size(),
            publicKey.data(), publicKey.size(),
            sharedSecret.data(), &actualSecretLen);
    }

    if (!ecdhOk) {
        return Result<ByteVector>::fail(Error::INTERNAL);
    }

    // Step 2: Derive key via HKDF
    ByteVector derivedKey(keyLength);
    if (!hkdf(
            salt.empty() ? nullptr : salt.data(), salt.size(),
            sharedSecret.data(), actualSecretLen,
            info.empty() ? nullptr : info.data(), info.size(),
            derivedKey.data(), keyLength)) {
        return Result<ByteVector>::fail(Error::INTERNAL);
    }

    return Result<ByteVector>::success(std::move(derivedKey));
}

// =============================================================================
// Ephemeral Key Pair Generation
// =============================================================================

Result<KeyPair> generateEphemeralKeyPair(Curve curve) {
#if HD_WALLET_FIPS_MODE
    if (curve != Curve::P256 && curve != Curve::P384) {
        return Result<KeyPair>::fail(Error::FIPS_NOT_ALLOWED);
    }
#endif

    try {
        SecureRandomGenerator rng;
        KeyPair kp;

        switch (curve) {
            case Curve::SECP256K1: {
                kp.privateKey.resize(32);
                rng.GenerateBlock(kp.privateKey.data(), 32);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;
                CryptoPP::Integer d(kp.privateKey.data(), 32);
                privKey.Initialize(CryptoPP::ASN1::secp256k1(), d);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;
                privKey.MakePublicKey(pubKey);
                const auto& point = pubKey.GetPublicElement();
                kp.publicKey.resize(33);
                kp.publicKey[0] = point.y.IsOdd() ? 0x03 : 0x02;
                point.x.Encode(kp.publicKey.data() + 1, 32);
                break;
            }
            case Curve::P256: {
                kp.privateKey.resize(32);
                rng.GenerateBlock(kp.privateKey.data(), 32);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;
                CryptoPP::Integer d(kp.privateKey.data(), 32);
                privKey.Initialize(CryptoPP::ASN1::secp256r1(), d);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;
                privKey.MakePublicKey(pubKey);
                const auto& point = pubKey.GetPublicElement();
                kp.publicKey.resize(33);
                kp.publicKey[0] = point.y.IsOdd() ? 0x03 : 0x02;
                point.x.Encode(kp.publicKey.data() + 1, 32);
                break;
            }
            case Curve::P384: {
                kp.privateKey.resize(48);
                rng.GenerateBlock(kp.privateKey.data(), 48);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;
                CryptoPP::Integer d(kp.privateKey.data(), 48);
                privKey.Initialize(CryptoPP::ASN1::secp384r1(), d);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;
                privKey.MakePublicKey(pubKey);
                const auto& point = pubKey.GetPublicElement();
                kp.publicKey.resize(49);
                kp.publicKey[0] = point.y.IsOdd() ? 0x03 : 0x02;
                point.x.Encode(kp.publicKey.data() + 1, 48);
                break;
            }
            case Curve::X25519: {
#if !HD_WALLET_ENABLE_X25519
                return Result<KeyPair>::fail(Error::FIPS_NOT_ALLOWED);
#else
                kp.privateKey.resize(32);
                rng.GenerateBlock(kp.privateKey.data(), 32);
                kp.publicKey.resize(32);
                size_t pubLen = 32;
                if (!x25519PublicKey(kp.privateKey.data(), 32, kp.publicKey.data(), &pubLen)) {
                    return Result<KeyPair>::fail(Error::INTERNAL);
                }
                break;
#endif
            }
            default:
                return Result<KeyPair>::fail(Error::INVALID_ARGUMENT);
        }

        return Result<KeyPair>::success(std::move(kp));
    } catch (...) {
        return Result<KeyPair>::fail(Error::INTERNAL);
    }
}

} // namespace ecdh
} // namespace hd_wallet

// =============================================================================
// C API Exports
// =============================================================================

extern "C" {

HD_WALLET_EXPORT
int32_t hd_ecdh(
    int32_t curve,
    const uint8_t* private_key,
    size_t private_key_len,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_size
) {
    size_t secretLen = shared_secret_size;
    if (hd_wallet::ecdh::ecdh(
            static_cast<hd_wallet::Curve>(curve),
            private_key, private_key_len,
            public_key, public_key_len,
            shared_secret, &secretLen)) {
        return static_cast<int32_t>(secretLen);
    }
    return -1;
}

HD_WALLET_EXPORT
int32_t hd_x25519(
    const uint8_t* private_key,
    size_t private_key_len,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_size
) {
    size_t secretLen = shared_secret_size;
    if (hd_wallet::ecdh::x25519(
            private_key, private_key_len,
            public_key, public_key_len,
            shared_secret, &secretLen)) {
        return static_cast<int32_t>(secretLen);
    }
    return -1;
}

HD_WALLET_EXPORT
int32_t hd_x25519_public_key(
    const uint8_t* private_key,
    size_t private_key_len,
    uint8_t* public_key,
    size_t public_key_size
) {
    size_t pubKeyLen = public_key_size;
    if (hd_wallet::ecdh::x25519PublicKey(
            private_key, private_key_len,
            public_key, &pubKeyLen)) {
        return static_cast<int32_t>(pubKeyLen);
    }
    return -1;
}

HD_WALLET_EXPORT
int32_t hd_hkdf_sha256(
    const uint8_t* salt,
    size_t salt_len,
    const uint8_t* ikm,
    size_t ikm_len,
    const uint8_t* info,
    size_t info_len,
    uint8_t* okm,
    size_t okm_len
) {
    if (hd_wallet::ecdh::hkdf(
            salt, salt_len,
            ikm, ikm_len,
            info, info_len,
            okm, okm_len)) {
        return static_cast<int32_t>(okm_len);
    }
    return -1;
}

} // extern "C"
