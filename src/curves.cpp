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

} // namespace hd_wallet
