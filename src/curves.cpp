/**
 * @file curves.cpp
 * @brief Curve Abstraction and Utilities
 *
 * Multi-curve cryptography support including secp256k1, P-256, P-384,
 * Ed25519, and X25519. Provides curve metadata and operations factory.
 */

#include "hd_wallet/types.h"
#include "hd_wallet/config.h"

#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#if !HD_WALLET_IS_WASI
#include <cryptopp/osrng.h>
#endif
#include <cryptopp/integer.h>
#include <cryptopp/secblock.h>
#include <cryptopp/xed25519.h>

#include <cryptopp/modarith.h>
#include <cryptopp/nbtheory.h>

#include "key_validation.h"

#ifdef HD_WALLET_USE_LIBSECP256K1
#include <secp256k1.h>
#include "secp256k1_context.h"
#endif

#if HD_WALLET_USE_OPENSSL
#include <openssl/obj_mac.h>
#include "hd_wallet/crypto_openssl.h"
#endif

#include <cstring>
#include <memory>
#include <stdexcept>

namespace hd_wallet {

// =============================================================================
// Curve Metadata Functions
// =============================================================================

// Note: curveToString is defined in error.cpp

size_t curvePrivateKeySize(Curve curve) {
    switch (curve) {
        case Curve::SECP256K1:
        case Curve::P256:
        case Curve::ED25519:
        case Curve::X25519:
            return 32;
        case Curve::P384:
            return 48;
        default:
            return 0;
    }
}

size_t curvePublicKeyCompressedSize(Curve curve) {
    switch (curve) {
        case Curve::SECP256K1:
        case Curve::P256:
            return 33;
        case Curve::P384:
            return 49;
        case Curve::ED25519:
        case Curve::X25519:
            return 32;  // Ed25519/X25519 keys are always 32 bytes
        default:
            return 0;
    }
}

size_t curvePublicKeyUncompressedSize(Curve curve) {
    switch (curve) {
        case Curve::SECP256K1:
        case Curve::P256:
            return 65;  // 0x04 + 32 + 32
        case Curve::P384:
            return 97;  // 0x04 + 48 + 48
        case Curve::ED25519:
        case Curve::X25519:
            return 32;  // Ed25519/X25519 keys are always 32 bytes (no compression)
        default:
            return 0;
    }
}

// =============================================================================
// CurveOperations Base Class
// =============================================================================

/**
 * Abstract base class for curve-specific cryptographic operations
 */
class CurveOperations {
public:
    virtual ~CurveOperations() = default;

    /// Get the curve type
    virtual Curve curve() const = 0;

    /// Validate a private key
    virtual bool validatePrivateKey(const uint8_t* key, size_t length) const = 0;

    /// Derive public key from private key
    virtual bool derivePublicKey(
        const uint8_t* privateKey,
        size_t privateKeyLen,
        uint8_t* publicKey,
        size_t* publicKeyLen,
        bool compressed = true
    ) const = 0;

    /// Validate a public key
    virtual bool validatePublicKey(const uint8_t* key, size_t length) const = 0;

    /// Compress a public key
    virtual bool compressPublicKey(
        const uint8_t* uncompressed,
        size_t uncompressedLen,
        uint8_t* compressed,
        size_t* compressedLen
    ) const = 0;

    /// Decompress a public key
    virtual bool decompressPublicKey(
        const uint8_t* compressed,
        size_t compressedLen,
        uint8_t* uncompressed,
        size_t* uncompressedLen
    ) const = 0;

    /// Add a scalar to a private key (for BIP-32 derivation)
    virtual bool privateKeyTweakAdd(
        uint8_t* key,
        size_t keyLen,
        const uint8_t* tweak,
        size_t tweakLen
    ) const = 0;

    /// Add a point to a public key (for BIP-32 public derivation)
    virtual bool publicKeyTweakAdd(
        uint8_t* key,
        size_t keyLen,
        const uint8_t* tweak,
        size_t tweakLen
    ) const = 0;
};

// =============================================================================
// Secp256k1 Implementation
// =============================================================================

class Secp256k1Operations : public CurveOperations {
public:
    Secp256k1Operations() {
        // Initialize secp256k1 curve parameters
        curve_.Initialize(CryptoPP::ASN1::secp256k1());
    }

    Curve curve() const override {
        return Curve::SECP256K1;
    }

    bool validatePrivateKey(const uint8_t* key, size_t length) const override {
        if (length != 32) return false;

        // Private key must be in range [1, n-1]
        CryptoPP::Integer privKey(key, length);
        CryptoPP::Integer order = curve_.GetGroupOrder();

        return privKey > 0 && privKey < order;
    }

    bool derivePublicKey(
        const uint8_t* privateKey,
        size_t privateKeyLen,
        uint8_t* publicKey,
        size_t* publicKeyLen,
        bool compressed
    ) const override {
        if (privateKeyLen != 32) return false;

        try {
            CryptoPP::Integer privKey(privateKey, privateKeyLen);

            // Validate private key
            CryptoPP::Integer order = curve_.GetGroupOrder();
            if (privKey <= 0 || privKey >= order) return false;

            // Compute public key point: P = privKey * G
            CryptoPP::ECPPoint publicPoint = curve_.GetCurve().ScalarMultiply(
                curve_.GetSubgroupGenerator(),
                privKey
            );

            if (compressed) {
                if (*publicKeyLen < 33) return false;
                *publicKeyLen = 33;

                // Compressed format: 02/03 prefix + x-coordinate
                publicKey[0] = publicPoint.y.IsOdd() ? 0x03 : 0x02;
                publicPoint.x.Encode(publicKey + 1, 32);
            } else {
                if (*publicKeyLen < 65) return false;
                *publicKeyLen = 65;

                // Uncompressed format: 04 prefix + x + y
                publicKey[0] = 0x04;
                publicPoint.x.Encode(publicKey + 1, 32);
                publicPoint.y.Encode(publicKey + 33, 32);
            }

            return true;
        } catch (...) {
            return false;
        }
    }

    bool validatePublicKey(const uint8_t* key, size_t length) const override {
        if (length != 33 && length != 65) return false;

        try {
            CryptoPP::ECPPoint point;

            if (length == 33) {
                // Compressed format
                if (key[0] != 0x02 && key[0] != 0x03) return false;

                CryptoPP::Integer x(key + 1, 32);
                // Check if x^3 + ax + b is a quadratic residue (has a square root)
                CryptoPP::Integer p = curve_.GetCurve().GetField().GetModulus();
                CryptoPP::Integer a = curve_.GetCurve().GetA();
                CryptoPP::Integer b = curve_.GetCurve().GetB();
                CryptoPP::Integer y2 = (a_exp_b_mod_c(x, 3, p) + a * x % p + b) % p;
                // Use Euler's criterion: y2^((p-1)/2) == 1 mod p means y2 is a quadratic residue
                CryptoPP::Integer exp = (p - 1) / 2;
                if (a_exp_b_mod_c(y2, exp, p) != 1) return false;

                // Decompress to validate
                point = decompressPoint(key, length);
            } else {
                // Uncompressed format
                if (key[0] != 0x04) return false;

                point.x.Decode(key + 1, 32);
                point.y.Decode(key + 33, 32);
                point.identity = false;
            }

            // Verify point is on curve
            return curve_.GetCurve().VerifyPoint(point);
        } catch (...) {
            return false;
        }
    }

    bool compressPublicKey(
        const uint8_t* uncompressed,
        size_t uncompressedLen,
        uint8_t* compressed,
        size_t* compressedLen
    ) const override {
        if (uncompressedLen != 65 || uncompressed[0] != 0x04) return false;
        if (*compressedLen < 33) return false;

        try {
            CryptoPP::Integer y(uncompressed + 33, 32);

            compressed[0] = y.IsOdd() ? 0x03 : 0x02;
            std::memcpy(compressed + 1, uncompressed + 1, 32);
            *compressedLen = 33;

            return true;
        } catch (...) {
            return false;
        }
    }

    bool decompressPublicKey(
        const uint8_t* compressed,
        size_t compressedLen,
        uint8_t* uncompressed,
        size_t* uncompressedLen
    ) const override {
        if (compressedLen != 33) return false;
        if (compressed[0] != 0x02 && compressed[0] != 0x03) return false;
        if (*uncompressedLen < 65) return false;

        try {
            CryptoPP::ECPPoint point = decompressPoint(compressed, compressedLen);

            uncompressed[0] = 0x04;
            point.x.Encode(uncompressed + 1, 32);
            point.y.Encode(uncompressed + 33, 32);
            *uncompressedLen = 65;

            return true;
        } catch (...) {
            return false;
        }
    }

    bool privateKeyTweakAdd(
        uint8_t* key,
        size_t keyLen,
        const uint8_t* tweak,
        size_t tweakLen
    ) const override {
        if (keyLen != 32 || tweakLen != 32) return false;

        try {
            CryptoPP::Integer privKey(key, keyLen);
            CryptoPP::Integer tweakVal(tweak, tweakLen);
            CryptoPP::Integer order = curve_.GetGroupOrder();

            // new_key = (key + tweak) mod n
            CryptoPP::Integer result = (privKey + tweakVal) % order;

            // Result must be valid (non-zero)
            if (result.IsZero()) return false;

            result.Encode(key, 32);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool publicKeyTweakAdd(
        uint8_t* key,
        size_t keyLen,
        const uint8_t* tweak,
        size_t tweakLen
    ) const override {
        if (tweakLen != 32) return false;
        if (keyLen != 33 && keyLen != 65) return false;

        try {
            // Parse the public key point
            CryptoPP::ECPPoint pubPoint;
            bool compressed = (keyLen == 33);

            if (compressed) {
                pubPoint = decompressPoint(key, keyLen);
            } else {
                if (key[0] != 0x04) return false;
                pubPoint.x.Decode(key + 1, 32);
                pubPoint.y.Decode(key + 33, 32);
            }

            // Compute tweak point: tweakPoint = tweak * G
            CryptoPP::Integer tweakVal(tweak, tweakLen);
            CryptoPP::ECPPoint tweakPoint = curve_.GetCurve().ScalarMultiply(
                curve_.GetSubgroupGenerator(),
                tweakVal
            );

            // Add points: result = pubPoint + tweakPoint
            CryptoPP::ECPPoint result = curve_.GetCurve().Add(pubPoint, tweakPoint);

            // Verify result is valid (not point at infinity)
            if (result.identity) return false;

            // Encode result
            if (compressed) {
                key[0] = result.y.IsOdd() ? 0x03 : 0x02;
                result.x.Encode(key + 1, 32);
            } else {
                key[0] = 0x04;
                result.x.Encode(key + 1, 32);
                result.y.Encode(key + 33, 32);
            }

            return true;
        } catch (...) {
            return false;
        }
    }

private:
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;

    CryptoPP::ECPPoint decompressPoint(const uint8_t* compressed, size_t len) const {
        if (len != 33) throw std::invalid_argument("Invalid compressed key length");

        bool yOdd = (compressed[0] == 0x03);
        CryptoPP::Integer x(compressed + 1, 32);

        // y^2 = x^3 + ax + b (for secp256k1, a = 0, b = 7)
        const CryptoPP::ECP& ec = curve_.GetCurve();
        CryptoPP::Integer p = ec.GetField().GetModulus();
        CryptoPP::Integer a = ec.GetA();
        CryptoPP::Integer b = ec.GetB();

        // y^2 = x^3 + 7 mod p
        CryptoPP::Integer y2 = (a_exp_b_mod_c(x, 3, p) + b) % p;

        // Compute modular square root
        CryptoPP::Integer y = a_exp_b_mod_c(y2, (p + 1) / 4, p);

        // Select correct y based on parity
        if (y.IsOdd() != yOdd) {
            y = p - y;
        }

        return CryptoPP::ECPPoint(x, y);
    }
};

// =============================================================================
// P-256 (secp256r1) Implementation
// =============================================================================

class P256Operations : public CurveOperations {
public:
    P256Operations() {
        curve_.Initialize(CryptoPP::ASN1::secp256r1());
    }

    Curve curve() const override {
        return Curve::P256;
    }

    bool validatePrivateKey(const uint8_t* key, size_t length) const override {
        if (length != 32) return false;

        CryptoPP::Integer privKey(key, length);
        CryptoPP::Integer order = curve_.GetGroupOrder();

        return privKey > 0 && privKey < order;
    }

    bool derivePublicKey(
        const uint8_t* privateKey,
        size_t privateKeyLen,
        uint8_t* publicKey,
        size_t* publicKeyLen,
        bool compressed
    ) const override {
        if (privateKeyLen != 32) return false;

        try {
            CryptoPP::Integer privKey(privateKey, privateKeyLen);

            CryptoPP::Integer order = curve_.GetGroupOrder();
            if (privKey <= 0 || privKey >= order) return false;

            CryptoPP::ECPPoint publicPoint = curve_.GetCurve().ScalarMultiply(
                curve_.GetSubgroupGenerator(),
                privKey
            );

            if (compressed) {
                if (*publicKeyLen < 33) return false;
                *publicKeyLen = 33;

                publicKey[0] = publicPoint.y.IsOdd() ? 0x03 : 0x02;
                publicPoint.x.Encode(publicKey + 1, 32);
            } else {
                if (*publicKeyLen < 65) return false;
                *publicKeyLen = 65;

                publicKey[0] = 0x04;
                publicPoint.x.Encode(publicKey + 1, 32);
                publicPoint.y.Encode(publicKey + 33, 32);
            }

            return true;
        } catch (...) {
            return false;
        }
    }

    bool validatePublicKey(const uint8_t* key, size_t length) const override {
        if (length != 33 && length != 65) return false;

        try {
            CryptoPP::ECPPoint point;

            if (length == 33) {
                if (key[0] != 0x02 && key[0] != 0x03) return false;
                point = decompressPoint(key, length);
            } else {
                if (key[0] != 0x04) return false;
                point.x.Decode(key + 1, 32);
                point.y.Decode(key + 33, 32);
                point.identity = false;
            }

            return curve_.GetCurve().VerifyPoint(point);
        } catch (...) {
            return false;
        }
    }

    bool compressPublicKey(
        const uint8_t* uncompressed,
        size_t uncompressedLen,
        uint8_t* compressed,
        size_t* compressedLen
    ) const override {
        if (uncompressedLen != 65 || uncompressed[0] != 0x04) return false;
        if (*compressedLen < 33) return false;

        try {
            CryptoPP::Integer y(uncompressed + 33, 32);

            compressed[0] = y.IsOdd() ? 0x03 : 0x02;
            std::memcpy(compressed + 1, uncompressed + 1, 32);
            *compressedLen = 33;

            return true;
        } catch (...) {
            return false;
        }
    }

    bool decompressPublicKey(
        const uint8_t* compressed,
        size_t compressedLen,
        uint8_t* uncompressed,
        size_t* uncompressedLen
    ) const override {
        if (compressedLen != 33) return false;
        if (compressed[0] != 0x02 && compressed[0] != 0x03) return false;
        if (*uncompressedLen < 65) return false;

        try {
            CryptoPP::ECPPoint point = decompressPoint(compressed, compressedLen);

            uncompressed[0] = 0x04;
            point.x.Encode(uncompressed + 1, 32);
            point.y.Encode(uncompressed + 33, 32);
            *uncompressedLen = 65;

            return true;
        } catch (...) {
            return false;
        }
    }

    bool privateKeyTweakAdd(
        uint8_t* key,
        size_t keyLen,
        const uint8_t* tweak,
        size_t tweakLen
    ) const override {
        if (keyLen != 32 || tweakLen != 32) return false;

        try {
            CryptoPP::Integer privKey(key, keyLen);
            CryptoPP::Integer tweakVal(tweak, tweakLen);
            CryptoPP::Integer order = curve_.GetGroupOrder();

            CryptoPP::Integer result = (privKey + tweakVal) % order;
            if (result.IsZero()) return false;

            result.Encode(key, 32);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool publicKeyTweakAdd(
        uint8_t* key,
        size_t keyLen,
        const uint8_t* tweak,
        size_t tweakLen
    ) const override {
        if (tweakLen != 32) return false;
        if (keyLen != 33 && keyLen != 65) return false;

        try {
            CryptoPP::ECPPoint pubPoint;
            bool compressed = (keyLen == 33);

            if (compressed) {
                pubPoint = decompressPoint(key, keyLen);
            } else {
                if (key[0] != 0x04) return false;
                pubPoint.x.Decode(key + 1, 32);
                pubPoint.y.Decode(key + 33, 32);
            }

            CryptoPP::Integer tweakVal(tweak, tweakLen);
            CryptoPP::ECPPoint tweakPoint = curve_.GetCurve().ScalarMultiply(
                curve_.GetSubgroupGenerator(),
                tweakVal
            );

            CryptoPP::ECPPoint result = curve_.GetCurve().Add(pubPoint, tweakPoint);
            if (result.identity) return false;

            if (compressed) {
                key[0] = result.y.IsOdd() ? 0x03 : 0x02;
                result.x.Encode(key + 1, 32);
            } else {
                key[0] = 0x04;
                result.x.Encode(key + 1, 32);
                result.y.Encode(key + 33, 32);
            }

            return true;
        } catch (...) {
            return false;
        }
    }

private:
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;

    CryptoPP::ECPPoint decompressPoint(const uint8_t* compressed, size_t len) const {
        if (len != 33) throw std::invalid_argument("Invalid compressed key length");

        bool yOdd = (compressed[0] == 0x03);
        CryptoPP::Integer x(compressed + 1, 32);

        const CryptoPP::ECP& ec = curve_.GetCurve();
        CryptoPP::Integer p = ec.GetField().GetModulus();
        CryptoPP::Integer a = ec.GetA();
        CryptoPP::Integer b = ec.GetB();

        // y^2 = x^3 + ax + b mod p
        CryptoPP::Integer y2 = (a_exp_b_mod_c(x, 3, p) + a * x + b) % p;

        // For P-256, p = 3 mod 4, so sqrt can be computed as y^((p+1)/4)
        CryptoPP::Integer y = a_exp_b_mod_c(y2, (p + 1) / 4, p);

        if (y.IsOdd() != yOdd) {
            y = p - y;
        }

        return CryptoPP::ECPPoint(x, y);
    }
};

// =============================================================================
// P-384 (secp384r1) Implementation
// =============================================================================

class P384Operations : public CurveOperations {
public:
    P384Operations() {
        curve_.Initialize(CryptoPP::ASN1::secp384r1());
    }

    Curve curve() const override {
        return Curve::P384;
    }

    bool validatePrivateKey(const uint8_t* key, size_t length) const override {
        if (length != 48) return false;

        CryptoPP::Integer privKey(key, length);
        CryptoPP::Integer order = curve_.GetGroupOrder();

        return privKey > 0 && privKey < order;
    }

    bool derivePublicKey(
        const uint8_t* privateKey,
        size_t privateKeyLen,
        uint8_t* publicKey,
        size_t* publicKeyLen,
        bool compressed
    ) const override {
        if (privateKeyLen != 48) return false;

        try {
            CryptoPP::Integer privKey(privateKey, privateKeyLen);

            CryptoPP::Integer order = curve_.GetGroupOrder();
            if (privKey <= 0 || privKey >= order) return false;

            CryptoPP::ECPPoint publicPoint = curve_.GetCurve().ScalarMultiply(
                curve_.GetSubgroupGenerator(),
                privKey
            );

            if (compressed) {
                if (*publicKeyLen < 49) return false;
                *publicKeyLen = 49;

                publicKey[0] = publicPoint.y.IsOdd() ? 0x03 : 0x02;
                publicPoint.x.Encode(publicKey + 1, 48);
            } else {
                if (*publicKeyLen < 97) return false;
                *publicKeyLen = 97;

                publicKey[0] = 0x04;
                publicPoint.x.Encode(publicKey + 1, 48);
                publicPoint.y.Encode(publicKey + 49, 48);
            }

            return true;
        } catch (...) {
            return false;
        }
    }

    bool validatePublicKey(const uint8_t* key, size_t length) const override {
        if (length != 49 && length != 97) return false;

        try {
            CryptoPP::ECPPoint point;

            if (length == 49) {
                if (key[0] != 0x02 && key[0] != 0x03) return false;
                point = decompressPoint(key, length);
            } else {
                if (key[0] != 0x04) return false;
                point.x.Decode(key + 1, 48);
                point.y.Decode(key + 49, 48);
                point.identity = false;
            }

            return curve_.GetCurve().VerifyPoint(point);
        } catch (...) {
            return false;
        }
    }

    bool compressPublicKey(
        const uint8_t* uncompressed,
        size_t uncompressedLen,
        uint8_t* compressed,
        size_t* compressedLen
    ) const override {
        if (uncompressedLen != 97 || uncompressed[0] != 0x04) return false;
        if (*compressedLen < 49) return false;

        try {
            CryptoPP::Integer y(uncompressed + 49, 48);

            compressed[0] = y.IsOdd() ? 0x03 : 0x02;
            std::memcpy(compressed + 1, uncompressed + 1, 48);
            *compressedLen = 49;

            return true;
        } catch (...) {
            return false;
        }
    }

    bool decompressPublicKey(
        const uint8_t* compressed,
        size_t compressedLen,
        uint8_t* uncompressed,
        size_t* uncompressedLen
    ) const override {
        if (compressedLen != 49) return false;
        if (compressed[0] != 0x02 && compressed[0] != 0x03) return false;
        if (*uncompressedLen < 97) return false;

        try {
            CryptoPP::ECPPoint point = decompressPoint(compressed, compressedLen);

            uncompressed[0] = 0x04;
            point.x.Encode(uncompressed + 1, 48);
            point.y.Encode(uncompressed + 49, 48);
            *uncompressedLen = 97;

            return true;
        } catch (...) {
            return false;
        }
    }

    bool privateKeyTweakAdd(
        uint8_t* key,
        size_t keyLen,
        const uint8_t* tweak,
        size_t tweakLen
    ) const override {
        if (keyLen != 48 || tweakLen != 48) return false;

        try {
            CryptoPP::Integer privKey(key, keyLen);
            CryptoPP::Integer tweakVal(tweak, tweakLen);
            CryptoPP::Integer order = curve_.GetGroupOrder();

            CryptoPP::Integer result = (privKey + tweakVal) % order;
            if (result.IsZero()) return false;

            result.Encode(key, 48);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool publicKeyTweakAdd(
        uint8_t* key,
        size_t keyLen,
        const uint8_t* tweak,
        size_t tweakLen
    ) const override {
        if (tweakLen != 48) return false;
        if (keyLen != 49 && keyLen != 97) return false;

        try {
            CryptoPP::ECPPoint pubPoint;
            bool compressed = (keyLen == 49);

            if (compressed) {
                pubPoint = decompressPoint(key, keyLen);
            } else {
                if (key[0] != 0x04) return false;
                pubPoint.x.Decode(key + 1, 48);
                pubPoint.y.Decode(key + 49, 48);
            }

            CryptoPP::Integer tweakVal(tweak, tweakLen);
            CryptoPP::ECPPoint tweakPoint = curve_.GetCurve().ScalarMultiply(
                curve_.GetSubgroupGenerator(),
                tweakVal
            );

            CryptoPP::ECPPoint result = curve_.GetCurve().Add(pubPoint, tweakPoint);
            if (result.identity) return false;

            if (compressed) {
                key[0] = result.y.IsOdd() ? 0x03 : 0x02;
                result.x.Encode(key + 1, 48);
            } else {
                key[0] = 0x04;
                result.x.Encode(key + 1, 48);
                result.y.Encode(key + 49, 48);
            }

            return true;
        } catch (...) {
            return false;
        }
    }

private:
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;

    CryptoPP::ECPPoint decompressPoint(const uint8_t* compressed, size_t len) const {
        if (len != 49) throw std::invalid_argument("Invalid compressed key length");

        bool yOdd = (compressed[0] == 0x03);
        CryptoPP::Integer x(compressed + 1, 48);

        const CryptoPP::ECP& ec = curve_.GetCurve();
        CryptoPP::Integer p = ec.GetField().GetModulus();
        CryptoPP::Integer a = ec.GetA();
        CryptoPP::Integer b = ec.GetB();

        // y^2 = x^3 + ax + b mod p
        CryptoPP::Integer y2 = (a_exp_b_mod_c(x, 3, p) + a * x + b) % p;

        // For P-384, p = 3 mod 4
        CryptoPP::Integer y = a_exp_b_mod_c(y2, (p + 1) / 4, p);

        if (y.IsOdd() != yOdd) {
            y = p - y;
        }

        return CryptoPP::ECPPoint(x, y);
    }
};

// =============================================================================
// Ed25519 Operations (Placeholder - actual signing in eddsa.cpp)
// =============================================================================

class Ed25519Operations : public CurveOperations {
public:
    Curve curve() const override {
        return Curve::ED25519;
    }

    bool validatePrivateKey(const uint8_t* key, size_t length) const override {
        // Ed25519 private keys are 32 bytes (seed form)
        if (length != 32) return false;

        // Any 32-byte value is a valid Ed25519 private key seed
        // The actual scalar is derived via SHA-512 hashing
        return true;
    }

    bool derivePublicKey(
        const uint8_t* privateKey,
        size_t privateKeyLen,
        uint8_t* publicKey,
        size_t* publicKeyLen,
        bool /* compressed - Ed25519 is always 32 bytes */
    ) const override {
        if (privateKeyLen != 32) return false;
        if (*publicKeyLen < 32) return false;

        try {
            CryptoPP::ed25519Signer signer(privateKey);
            CryptoPP::ed25519Verifier verifier(signer);

            const CryptoPP::ed25519PublicKey& pk =
                static_cast<const CryptoPP::ed25519PublicKey&>(verifier.GetPublicKey());
            std::memcpy(publicKey, pk.GetPublicKeyBytePtr(), 32);
            *publicKeyLen = 32;

            return true;
        } catch (...) {
            return false;
        }
    }

    bool validatePublicKey(const uint8_t* key, size_t length) const override {
        if (length != 32) return false;

        try {
            CryptoPP::ed25519Verifier verifier(key);
            return true;
        } catch (...) {
            return false;
        }
    }

    bool compressPublicKey(
        const uint8_t* uncompressed,
        size_t uncompressedLen,
        uint8_t* compressed,
        size_t* compressedLen
    ) const override {
        // Ed25519 public keys are always 32 bytes
        if (uncompressedLen != 32) return false;
        if (*compressedLen < 32) return false;

        std::memcpy(compressed, uncompressed, 32);
        *compressedLen = 32;
        return true;
    }

    bool decompressPublicKey(
        const uint8_t* compressed,
        size_t compressedLen,
        uint8_t* uncompressed,
        size_t* uncompressedLen
    ) const override {
        // Ed25519 public keys are always 32 bytes
        if (compressedLen != 32) return false;
        if (*uncompressedLen < 32) return false;

        std::memcpy(uncompressed, compressed, 32);
        *uncompressedLen = 32;
        return true;
    }

    bool privateKeyTweakAdd(
        uint8_t* /* key */,
        size_t /* keyLen */,
        const uint8_t* /* tweak */,
        size_t /* tweakLen */
    ) const override {
        // Ed25519 doesn't support standard BIP-32 style derivation
        // Use SLIP-10 for Ed25519 derivation
        return false;
    }

    bool publicKeyTweakAdd(
        uint8_t* /* key */,
        size_t /* keyLen */,
        const uint8_t* /* tweak */,
        size_t /* tweakLen */
    ) const override {
        // Ed25519 doesn't support public key derivation
        return false;
    }
};

// =============================================================================
// X25519 Operations
// =============================================================================

class X25519Operations : public CurveOperations {
public:
    Curve curve() const override {
        return Curve::X25519;
    }

    bool validatePrivateKey(const uint8_t* key, size_t length) const override {
        // X25519 private keys are 32 bytes
        if (length != 32) return false;

        // Any 32-byte value is valid (will be clamped during operations)
        return true;
    }

    bool derivePublicKey(
        const uint8_t* privateKey,
        size_t privateKeyLen,
        uint8_t* publicKey,
        size_t* publicKeyLen,
        bool /* compressed - X25519 is always 32 bytes */
    ) const override {
        if (privateKeyLen != 32) return false;
        if (*publicKeyLen < 32) return false;

        try {
            // X25519 public key derivation using the SimpleKeyAgreementDomain interface
            CryptoPP::x25519 x25519;
            CryptoPP::SecByteBlock pub(32);
            x25519.GeneratePublicKey(
                CryptoPP::NullRNG(),
                privateKey,
                pub
            );

            std::memcpy(publicKey, pub.data(), 32);
            *publicKeyLen = 32;

            return true;
        } catch (...) {
            return false;
        }
    }

    bool validatePublicKey(const uint8_t* key, size_t length) const override {
        // X25519 public keys are 32 bytes
        if (length != 32) return false;

        // Basic validation: non-zero
        bool allZero = true;
        for (size_t i = 0; i < 32; ++i) {
            if (key[i] != 0) {
                allZero = false;
                break;
            }
        }

        return !allZero;
    }

    bool compressPublicKey(
        const uint8_t* uncompressed,
        size_t uncompressedLen,
        uint8_t* compressed,
        size_t* compressedLen
    ) const override {
        if (uncompressedLen != 32) return false;
        if (*compressedLen < 32) return false;

        std::memcpy(compressed, uncompressed, 32);
        *compressedLen = 32;
        return true;
    }

    bool decompressPublicKey(
        const uint8_t* compressed,
        size_t compressedLen,
        uint8_t* uncompressed,
        size_t* uncompressedLen
    ) const override {
        if (compressedLen != 32) return false;
        if (*uncompressedLen < 32) return false;

        std::memcpy(uncompressed, compressed, 32);
        *uncompressedLen = 32;
        return true;
    }

    bool privateKeyTweakAdd(
        uint8_t* /* key */,
        size_t /* keyLen */,
        const uint8_t* /* tweak */,
        size_t /* tweakLen */
    ) const override {
        // X25519 doesn't support key tweaking
        return false;
    }

    bool publicKeyTweakAdd(
        uint8_t* /* key */,
        size_t /* keyLen */,
        const uint8_t* /* tweak */,
        size_t /* tweakLen */
    ) const override {
        // X25519 doesn't support key tweaking
        return false;
    }
};

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Get curve operations for a specific curve type
 *
 * @param curve The curve type
 * @return Shared pointer to curve operations, or nullptr if not supported
 */
std::shared_ptr<CurveOperations> getCurveOperations(Curve curve) {
    switch (curve) {
        case Curve::SECP256K1:
            return std::make_shared<Secp256k1Operations>();
        case Curve::P256:
            return std::make_shared<P256Operations>();
        case Curve::P384:
            return std::make_shared<P384Operations>();
        case Curve::ED25519:
#if HD_WALLET_ENABLE_ED25519
            return std::make_shared<Ed25519Operations>();
#else
            return nullptr;
#endif
        case Curve::X25519:
#if HD_WALLET_ENABLE_X25519
            return std::make_shared<X25519Operations>();
#else
            return nullptr;
#endif
        default:
            return nullptr;
    }
}

// Note: errorToString is defined in error.cpp

// =============================================================================
// Coin Type Helpers
// =============================================================================

const char* coinTypeToString(CoinType coin) {
    switch (coin) {
        case CoinType::BITCOIN:
            return "bitcoin";
        case CoinType::BITCOIN_TESTNET:
            return "bitcoin_testnet";
        case CoinType::LITECOIN:
            return "litecoin";
        case CoinType::DOGECOIN:
            return "dogecoin";
        case CoinType::ETHEREUM:
            return "ethereum";
        case CoinType::ETHEREUM_CLASSIC:
            return "ethereum_classic";
        case CoinType::ROOTSTOCK:
            return "rootstock";
        case CoinType::BITCOIN_CASH:
            return "bitcoin_cash";
        case CoinType::BINANCE:
            return "binance";
        case CoinType::SOLANA:
            return "solana";
        case CoinType::STELLAR:
            return "stellar";
        case CoinType::CARDANO:
            return "cardano";
        case CoinType::POLKADOT:
            return "polkadot";
        case CoinType::KUSAMA:
            return "kusama";
        case CoinType::TEZOS:
            return "tezos";
        case CoinType::COSMOS:
            return "cosmos";
        case CoinType::TERRA:
            return "terra";
        case CoinType::NIST_P256:
            return "nist_p256";
        case CoinType::NIST_P384:
            return "nist_p384";
        case CoinType::X25519:
            return "x25519";
        default:
            return "unknown";
    }
}

Curve coinTypeToCurve(CoinType coin) {
    switch (coin) {
        case CoinType::BITCOIN:
        case CoinType::BITCOIN_TESTNET:
        case CoinType::LITECOIN:
        case CoinType::DOGECOIN:
        case CoinType::ETHEREUM:
        case CoinType::ETHEREUM_CLASSIC:
        case CoinType::ROOTSTOCK:
        case CoinType::BITCOIN_CASH:
        case CoinType::BINANCE:
        case CoinType::COSMOS:
        case CoinType::TERRA:
            return Curve::SECP256K1;

        case CoinType::SOLANA:
        case CoinType::STELLAR:
        case CoinType::CARDANO:
        case CoinType::POLKADOT:
        case CoinType::KUSAMA:
        case CoinType::TEZOS:
            return Curve::ED25519;

        case CoinType::NIST_P256:
            return Curve::P256;

        case CoinType::NIST_P384:
            return Curve::P384;

        case CoinType::X25519:
            return Curve::X25519;

        default:
            return Curve::SECP256K1;
    }
}

// =============================================================================
// Key validation (key_validation.h)
// =============================================================================

namespace keys {
namespace {

// Group orders n, big-endian.
constexpr uint8_t kSecp256k1Order[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
};
constexpr uint8_t kP256Order[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
};
constexpr uint8_t kP384Order[48] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC7, 0x63, 0x4D, 0x81, 0xF4, 0x37, 0x2D, 0xDF,
    0x58, 0x1A, 0x0D, 0xB2, 0x48, 0xB0, 0xA7, 0x7A, 0xEC, 0xEC, 0x19, 0x6A, 0xCC, 0xC5, 0x29, 0x73,
};

// 0 < key < order, over every byte whatever the key is (no early exit on
// secret data).
bool scalarInRange(const uint8_t* key, const uint8_t* order, size_t size) noexcept {
    uint32_t nonzero = 0;
    uint32_t borrow = 0;
    for (size_t i = size; i-- > 0;) {
        nonzero |= key[i];
        const uint32_t difference = static_cast<uint32_t>(key[i]) - order[i] - borrow;
        borrow = (difference >> 8) & 1U;
    }
    return nonzero != 0 && borrow == 1;  // key - n borrows: key < n
}

bool sec1Encoding(const uint8_t* key, size_t length, size_t fieldSize) noexcept {
    return (length == fieldSize + 1 && (key[0] == 0x02 || key[0] == 0x03)) ||
           (length == 2 * fieldSize + 1 && key[0] == 0x04);
}

#if !defined(HD_WALLET_USE_LIBSECP256K1) || !HD_WALLET_USE_OPENSSL
// Crypto++ fallback for builds without libsecp256k1 or OpenSSL.
bool cryptoppPointValid(const CryptoPP::OID& oid, const uint8_t* key, size_t length) noexcept {
    try {
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> params;
        params.Initialize(oid);
        const CryptoPP::ECP& ec = params.GetCurve();
        CryptoPP::ECP::Point point;
        if (!ec.DecodePoint(point, key, length) || point.identity) return false;
        return ec.VerifyPoint(point);  // also x, y < p
    } catch (...) {
        return false;
    }
}
#endif

// Ed25519 y-coordinates (low 255 bits, little-endian) of the eight points of
// small order: 0 (order 4), 1 (identity), p - 1 (order 2) and the two order-8
// y values; each with either sign bit.
constexpr uint8_t kEd25519SmallOrderY[5][32] = {
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
    {0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
    {0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98, 0xf0,
     0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53, 0xfc, 0x05},
    {0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67, 0x0f,
     0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac, 0x03, 0x7a},
};

// L = 2^252 + 27742317777372353535851937790883648493, little-endian.
constexpr uint8_t kEd25519Order[32] = {
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
};

// a < b for 32-byte little-endian integers.
bool lessThanLe(const uint8_t* a, const uint8_t* b) noexcept {
    for (size_t i = 32; i-- > 0;) {
        if (a[i] != b[i]) return a[i] < b[i];
    }
    return false;
}

// The encoded y (sign bit cleared) is below p = 2^255 - 19.
bool ed25519YCanonical(const uint8_t encoded[32]) noexcept {
    // y >= p only when bytes 1..30 are 0xff, byte 31 (masked) is 0x7f and
    // byte 0 >= 0xed.
    if ((encoded[31] & 0x7f) != 0x7f) return true;
    for (size_t i = 1; i < 31; ++i) {
        if (encoded[i] != 0xff) return true;
    }
    return encoded[0] < 0xed;
}

// The encoding decodes to a curve point: x^2 = (y^2 - 1) / (d y^2 + 1) has a
// root, and x = 0 carries sign bit 0.
bool ed25519Decodes(const uint8_t encoded[32]) noexcept {
    try {
        uint8_t bigEndian[32];
        for (size_t i = 0; i < 32; ++i) bigEndian[i] = encoded[31 - i];
        bigEndian[0] &= 0x7f;
        const CryptoPP::Integer p = CryptoPP::Integer::Power2(255) - CryptoPP::Integer(19);
        const CryptoPP::Integer y(bigEndian, sizeof(bigEndian));
        if (y >= p) return false;
        const CryptoPP::ModularArithmetic field(p);
        const CryptoPP::Integer d = field.Multiply(
            p - CryptoPP::Integer(121665), CryptoPP::Integer(121666).InverseMod(p));
        const CryptoPP::Integer y2 = field.Square(y);
        const CryptoPP::Integer u = field.Subtract(y2, CryptoPP::Integer::One());
        const CryptoPP::Integer v = field.Add(field.Multiply(d, y2), CryptoPP::Integer::One());
        const CryptoPP::Integer uv = field.Multiply(u, v);
        if (uv.IsZero()) return (encoded[31] & 0x80) == 0;
        return CryptoPP::Jacobi(uv, p) == 1;
    } catch (...) {
        return false;
    }
}

} // anonymous namespace

bool ed25519EncodingIsStrict(const uint8_t encoded[32]) noexcept {
    if (encoded == nullptr || !ed25519YCanonical(encoded)) return false;
    for (const auto& y : kEd25519SmallOrderY) {
        uint8_t difference = static_cast<uint8_t>((encoded[31] & 0x7f) ^ y[31]);
        for (size_t i = 0; i < 31; ++i) difference |= static_cast<uint8_t>(encoded[i] ^ y[i]);
        if (difference == 0) return false;
    }
    return true;
}

bool ed25519ScalarIsCanonical(const uint8_t s[32]) noexcept {
    return s != nullptr && lessThanLe(s, kEd25519Order);
}

bool ed25519SignatureIsStrict(const uint8_t publicKey[32], const uint8_t signature[64]) noexcept {
    return publicKey != nullptr && signature != nullptr &&
           ed25519EncodingIsStrict(publicKey) &&
           ed25519EncodingIsStrict(signature) &&
           ed25519ScalarIsCanonical(signature + 32);
}

bool isValidPublicKey(Curve curve, const uint8_t* key, size_t length) noexcept {
    if (key == nullptr) return false;
    switch (curve) {
        case Curve::SECP256K1: {
            if (!sec1Encoding(key, length, 32)) return false;
#ifdef HD_WALLET_USE_LIBSECP256K1
            secp256k1_pubkey parsed;
            return secp256k1_ec_pubkey_parse(internal::secp256k1Context(), &parsed, key, length) == 1;
#else
            return cryptoppPointValid(CryptoPP::ASN1::secp256k1(), key, length);
#endif
        }
        case Curve::P256:
            if (!sec1Encoding(key, length, 32)) return false;
#if HD_WALLET_USE_OPENSSL
            return hd_ossl_ec_pubkey_check(NID_X9_62_prime256v1, key, length) == 0;
#else
            return cryptoppPointValid(CryptoPP::ASN1::secp256r1(), key, length);
#endif
        case Curve::P384:
            if (!sec1Encoding(key, length, 48)) return false;
#if HD_WALLET_USE_OPENSSL
            return hd_ossl_ec_pubkey_check(NID_secp384r1, key, length) == 0;
#else
            return cryptoppPointValid(CryptoPP::ASN1::secp384r1(), key, length);
#endif
        case Curve::ED25519:
            return length == 32 && ed25519EncodingIsStrict(key) && ed25519Decodes(key);
        case Curve::X25519:
            return length == 32;
        default:
            return false;
    }
}

bool isValidPrivateKey(Curve curve, const uint8_t* key, size_t length) noexcept {
    if (key == nullptr) return false;
    switch (curve) {
        case Curve::SECP256K1:
            return length == 32 && scalarInRange(key, kSecp256k1Order, 32);
        case Curve::P256:
            return length == 32 && scalarInRange(key, kP256Order, 32);
        case Curve::P384:
            return length == 48 && scalarInRange(key, kP384Order, 48);
        case Curve::ED25519:
        case Curve::X25519:
            return length == 32;
        default:
            return false;
    }
}

} // namespace keys

} // namespace hd_wallet
