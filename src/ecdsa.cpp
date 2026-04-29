/**
 * @file ecdsa.cpp
 * @brief ECDSA Signing Implementation
 *
 * ECDSA signing for secp256k1, P-256, and P-384 curves using Crypto++.
 * Features:
 * - Sign with low-S normalization (BIP-62/BIP-146 for secp256k1)
 * - Sign with recovery ID for public key recovery
 * - Signature verification
 * - Public key recovery from signature
 */

#include "hd_wallet/types.h"
#include "hd_wallet/config.h"
#include "hd_wallet/ecdsa.h"

#include <cryptopp/eccrypto.h>
#include <cryptopp/ecp.h>
#include <cryptopp/asn.h>
#include <cryptopp/oids.h>
#if !HD_WALLET_IS_WASI
#include <cryptopp/osrng.h>
#endif
#include <cryptopp/integer.h>
#include <cryptopp/dsa.h>
#include <cryptopp/sha.h>
#include <cryptopp/secblock.h>
#include <cryptopp/modarith.h>

#include <cstring>
#include <algorithm>
#include <stdexcept>
#include <utility>

namespace hd_wallet {
namespace ecdsa {

// =============================================================================
// Internal Helper Classes
// =============================================================================

namespace {

/**
 * ECDSA curve context with precomputed values
 */
class ECDSACurve {
public:
    ECDSACurve(const CryptoPP::OID& oid) {
        curve_.Initialize(oid);
        n_ = curve_.GetGroupOrder();
        halfN_ = n_ >> 1;  // n/2 for low-S check
    }

    const CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP>& params() const {
        return curve_;
    }

    const CryptoPP::Integer& order() const { return n_; }
    const CryptoPP::Integer& halfOrder() const { return halfN_; }

    const CryptoPP::ECP& ec() const { return curve_.GetCurve(); }
    const CryptoPP::ECPPoint& generator() const { return curve_.GetSubgroupGenerator(); }

    size_t keySize() const { return curve_.GetGroupOrder().ByteCount(); }

private:
    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;
    CryptoPP::Integer n_;
    CryptoPP::Integer halfN_;
};

// Curve singletons
static ECDSACurve& secp256k1() {
    static ECDSACurve instance(CryptoPP::ASN1::secp256k1());
    return instance;
}

static ECDSACurve& p256() {
    static ECDSACurve instance(CryptoPP::ASN1::secp256r1());
    return instance;
}

static ECDSACurve& p384() {
    static ECDSACurve instance(CryptoPP::ASN1::secp384r1());
    return instance;
}

/**
 * Decompress a point on the curve
 */
template<typename CurveType>
CryptoPP::ECPPoint decompressPoint(
    const CurveType& curve,
    const uint8_t* compressed,
    size_t compressedLen
) {
    size_t keySize = curve.keySize();
    if (compressedLen != keySize + 1) {
        throw std::invalid_argument("Invalid compressed key length");
    }

    bool yOdd = (compressed[0] == 0x03);
    CryptoPP::Integer x(compressed + 1, keySize);

    const CryptoPP::ECP& ec = curve.ec();
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
template<typename CurveType>
CryptoPP::ECPPoint parsePublicKey(
    const CurveType& curve,
    const uint8_t* key,
    size_t keyLen
) {
    size_t coordSize = curve.keySize();
    CryptoPP::ECPPoint point;

    if (keyLen == coordSize + 1) {
        // Compressed format
        if (key[0] != 0x02 && key[0] != 0x03) {
            throw std::invalid_argument("Invalid compressed key prefix");
        }
        return decompressPoint(curve, key, keyLen);
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

} // anonymous namespace

// =============================================================================
// Signature Structure
// =============================================================================

/**
 * Internal ECDSA signature representation with optional recovery ID
 * Named SignatureData to avoid conflict with public Signature struct in header
 */
struct SignatureData {
    ByteVector r;
    ByteVector s;
    int recoveryId;  // -1 if not available

    SignatureData() : recoveryId(-1) {}

    /**
     * Encode as DER format
     */
    ByteVector toDER() const {
        // DER encoding: SEQUENCE { INTEGER r, INTEGER s }
        ByteVector der;

        // Helper to encode integer with DER rules
        auto encodeInteger = [](const ByteVector& val) -> ByteVector {
            ByteVector encoded;

            // Find first non-zero byte
            size_t start = 0;
            while (start < val.size() && val[start] == 0) {
                start++;
            }

            // If all zeros, encode as single zero
            if (start == val.size()) {
                encoded.push_back(0x02);  // INTEGER tag
                encoded.push_back(0x01);  // length
                encoded.push_back(0x00);  // value
                return encoded;
            }

            // Check if high bit is set (need padding)
            bool needPad = (val[start] & 0x80) != 0;
            size_t len = val.size() - start + (needPad ? 1 : 0);

            encoded.push_back(0x02);  // INTEGER tag
            encoded.push_back(static_cast<uint8_t>(len));  // length
            if (needPad) {
                encoded.push_back(0x00);  // padding byte
            }
            encoded.insert(encoded.end(), val.begin() + start, val.end());

            return encoded;
        };

        ByteVector rEncoded = encodeInteger(r);
        ByteVector sEncoded = encodeInteger(s);

        der.push_back(0x30);  // SEQUENCE tag
        der.push_back(static_cast<uint8_t>(rEncoded.size() + sEncoded.size()));
        der.insert(der.end(), rEncoded.begin(), rEncoded.end());
        der.insert(der.end(), sEncoded.begin(), sEncoded.end());

        return der;
    }

    /**
     * Encode as compact format (r || s, fixed size)
     */
    ByteVector toCompact(size_t coordSize = 32) const {
        ByteVector compact(coordSize * 2, 0);

        // Pad r to coordSize
        size_t rOffset = coordSize - std::min(r.size(), coordSize);
        std::memcpy(compact.data() + rOffset, r.data() + (r.size() > coordSize ? r.size() - coordSize : 0),
                    std::min(r.size(), coordSize));

        // Pad s to coordSize
        size_t sOffset = coordSize - std::min(s.size(), coordSize);
        std::memcpy(compact.data() + coordSize + sOffset, s.data() + (s.size() > coordSize ? s.size() - coordSize : 0),
                    std::min(s.size(), coordSize));

        return compact;
    }

    /**
     * Encode as recoverable format (recovery byte + r || s)
     */
    ByteVector toRecoverable(size_t coordSize = 32) const {
        ByteVector rec(1 + coordSize * 2);
        rec[0] = static_cast<uint8_t>(27 + recoveryId);  // Bitcoin convention

        ByteVector compact = toCompact(coordSize);
        std::memcpy(rec.data() + 1, compact.data(), compact.size());

        return rec;
    }

    /**
     * Parse from DER format
     */
    static SignatureData fromDER(const uint8_t* der, size_t derLen) {
        SignatureData sig;

        if (derLen < 8) throw std::invalid_argument("DER too short");
        if (der[0] != 0x30) throw std::invalid_argument("Invalid DER sequence tag");

        size_t seqLen = der[1];
        if (seqLen + 2 > derLen) throw std::invalid_argument("Invalid DER length");

        size_t pos = 2;

        // Parse r
        if (der[pos] != 0x02) throw std::invalid_argument("Invalid r tag");
        size_t rLen = der[pos + 1];
        pos += 2;
        sig.r.assign(der + pos, der + pos + rLen);
        pos += rLen;

        // Parse s
        if (der[pos] != 0x02) throw std::invalid_argument("Invalid s tag");
        size_t sLen = der[pos + 1];
        pos += 2;
        sig.s.assign(der + pos, der + pos + sLen);

        return sig;
    }

    /**
     * Parse from compact format
     */
    static SignatureData fromCompact(const uint8_t* compact, size_t compactLen, size_t coordSize = 32) {
        if (compactLen != coordSize * 2) {
            throw std::invalid_argument("Invalid compact signature length");
        }

        SignatureData sig;
        sig.r.assign(compact, compact + coordSize);
        sig.s.assign(compact + coordSize, compact + compactLen);

        return sig;
    }

    /**
     * Parse from recoverable format
     */
    static SignatureData fromRecoverable(const uint8_t* rec, size_t recLen, size_t coordSize = 32) {
        if (recLen != 1 + coordSize * 2) {
            throw std::invalid_argument("Invalid recoverable signature length");
        }

        SignatureData sig = fromCompact(rec + 1, recLen - 1, coordSize);

        // Extract recovery ID
        uint8_t v = rec[0];
        if (v >= 27 && v <= 30) {
            sig.recoveryId = v - 27;
        } else if (v >= 31 && v <= 34) {
            sig.recoveryId = v - 31;  // Compressed public key indicator
        } else {
            throw std::invalid_argument("Invalid recovery byte");
        }

        return sig;
    }
};

// =============================================================================
// ECDSA Sign Implementation
// =============================================================================

namespace {

/**
 * RFC 6979 deterministic k generation
 */
template<typename HashType>
CryptoPP::Integer generateDeterministicK(
    const CryptoPP::Integer& privateKey,
    const uint8_t* hash,
    size_t hashLen,
    const CryptoPP::Integer& order
) {
    // RFC 6979 deterministic nonce generation
    size_t qLen = order.ByteCount();

    CryptoPP::SecByteBlock v(hashLen);  // V = 0x01...01
    std::memset(v.data(), 0x01, hashLen);
    CryptoPP::SecByteBlock k(hashLen);  // K = 0x00...00
    std::memset(k.data(), 0x00, hashLen);

    // Encode private key
    CryptoPP::SecByteBlock x(qLen);
    privateKey.Encode(x.data(), qLen);

    // K = HMAC_K(V || 0x00 || int2octets(x) || bits2octets(h1))
    CryptoPP::HMAC<HashType> hmac;

    ByteVector hmacInput;
    hmacInput.insert(hmacInput.end(), v.begin(), v.end());
    hmacInput.push_back(0x00);
    hmacInput.insert(hmacInput.end(), x.begin(), x.end());
    hmacInput.insert(hmacInput.end(), hash, hash + hashLen);

    hmac.SetKey(k.data(), k.size());
    hmac.CalculateDigest(k.data(), hmacInput.data(), hmacInput.size());

    // V = HMAC_K(V)
    hmac.SetKey(k.data(), k.size());
    hmac.CalculateDigest(v.data(), v.data(), v.size());

    // K = HMAC_K(V || 0x01 || int2octets(x) || bits2octets(h1))
    hmacInput.clear();
    hmacInput.insert(hmacInput.end(), v.begin(), v.end());
    hmacInput.push_back(0x01);
    hmacInput.insert(hmacInput.end(), x.begin(), x.end());
    hmacInput.insert(hmacInput.end(), hash, hash + hashLen);

    hmac.SetKey(k.data(), k.size());
    hmac.CalculateDigest(k.data(), hmacInput.data(), hmacInput.size());

    // V = HMAC_K(V)
    hmac.SetKey(k.data(), k.size());
    hmac.CalculateDigest(v.data(), v.data(), v.size());

    // Generate k candidates
    while (true) {
        CryptoPP::SecByteBlock t;

        while (t.size() < qLen) {
            // V = HMAC_K(V)
            hmac.SetKey(k.data(), k.size());
            hmac.CalculateDigest(v.data(), v.data(), v.size());
            t.Grow(t.size() + v.size());
            std::memcpy(t.data() + t.size() - v.size(), v.data(), v.size());
        }

        CryptoPP::Integer candidate(t.data(), qLen);

        if (candidate >= 1 && candidate < order) {
            return candidate;
        }

        // K = HMAC_K(V || 0x00)
        hmacInput.clear();
        hmacInput.insert(hmacInput.end(), v.begin(), v.end());
        hmacInput.push_back(0x00);

        hmac.SetKey(k.data(), k.size());
        hmac.CalculateDigest(k.data(), hmacInput.data(), hmacInput.size());

        // V = HMAC_K(V)
        hmac.SetKey(k.data(), k.size());
        hmac.CalculateDigest(v.data(), v.data(), v.size());
    }
}

/**
 * Core ECDSA signing with recovery ID computation
 */
template<typename CurveType>
SignatureData signWithRecovery(
    const CurveType& curve,
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* hash,
    size_t hashLen,
    bool lowS = true
) {
    size_t coordSize = curve.keySize();
    if (privateKeyLen != coordSize) {
        throw std::invalid_argument("Invalid private key length");
    }

    CryptoPP::Integer d(privateKey, privateKeyLen);
    CryptoPP::Integer n = curve.order();

    // Validate private key
    if (d <= 0 || d >= n) {
        throw std::invalid_argument("Invalid private key value");
    }

    // Generate deterministic k (RFC 6979)
    CryptoPP::Integer k = generateDeterministicK<CryptoPP::SHA256>(d, hash, hashLen, n);

    // Compute R = k * G
    CryptoPP::ECPPoint R = curve.ec().ScalarMultiply(curve.generator(), k);

    // r = R.x mod n
    CryptoPP::Integer r = R.x % n;
    if (r.IsZero()) {
        throw std::runtime_error("Invalid signature: r is zero");
    }

    // Compute recovery ID
    int recoveryId = 0;
    if (R.x >= n) {
        recoveryId |= 2;  // x >= n
    }
    if (R.y.IsOdd()) {
        recoveryId |= 1;  // y is odd
    }

    // z = hash (interpreted as integer)
    CryptoPP::Integer z(hash, hashLen);

    // s = k^-1 * (z + r*d) mod n
    CryptoPP::Integer kInv = k.InverseMod(n);
    CryptoPP::Integer s = (kInv * (z + r * d)) % n;

    if (s.IsZero()) {
        throw std::runtime_error("Invalid signature: s is zero");
    }

    // Low-S normalization (BIP-62 for secp256k1)
    if (lowS && s > curve.halfOrder()) {
        s = n - s;
        recoveryId ^= 1;  // Flip y parity
    }

    SignatureData sig;
    sig.r.resize(coordSize);
    sig.s.resize(coordSize);
    r.Encode(sig.r.data(), coordSize);
    s.Encode(sig.s.data(), coordSize);
    sig.recoveryId = recoveryId;

    return sig;
}

} // anonymous namespace

// =============================================================================
// Forward Declarations
// =============================================================================

// Forward declaration for verifyCompact used by verify()
bool verifyCompact(
    Curve curve,
    const uint8_t* publicKey,
    size_t publicKeyLen,
    const uint8_t* hash,
    size_t hashLen,
    const uint8_t* signature,
    size_t signatureLen
);

// =============================================================================
// Public API: Sign
// =============================================================================

/**
 * Sign a message hash using ECDSA
 *
 * @param curve Elliptic curve to use
 * @param privateKey Private key bytes
 * @param privateKeyLen Private key length
 * @param hash Message hash (typically 32 bytes)
 * @param hashLen Hash length
 * @param signature Output signature buffer (DER format)
 * @param signatureLen Input: buffer size, Output: signature length
 * @param lowS Apply low-S normalization (default: true for secp256k1)
 * @return true on success
 */
bool sign(
    Curve curve,
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* hash,
    size_t hashLen,
    uint8_t* signature,
    size_t* signatureLen,
    bool lowS
) {
    if (!privateKey || !hash || !signature || !signatureLen) {
        return false;
    }

    try {
        SignatureData sig;

        switch (curve) {
            case Curve::SECP256K1:
                sig = signWithRecovery(secp256k1(), privateKey, privateKeyLen, hash, hashLen, lowS);
                break;
            case Curve::P256:
                sig = signWithRecovery(p256(), privateKey, privateKeyLen, hash, hashLen, lowS);
                break;
            case Curve::P384:
                sig = signWithRecovery(p384(), privateKey, privateKeyLen, hash, hashLen, lowS);
                break;
            default:
                return false;
        }

        ByteVector der = sig.toDER();
        if (der.size() > *signatureLen) {
            return false;
        }

        std::memcpy(signature, der.data(), der.size());
        *signatureLen = der.size();

        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Sign a message hash with recovery ID
 *
 * @param curve Elliptic curve to use
 * @param privateKey Private key bytes
 * @param privateKeyLen Private key length
 * @param hash Message hash (typically 32 bytes)
 * @param hashLen Hash length
 * @param signature Output signature buffer (65 bytes: v + r + s)
 * @param signatureLen Input: buffer size, Output: signature length
 * @return true on success
 */
bool signRecoverable(
    Curve curve,
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* hash,
    size_t hashLen,
    uint8_t* signature,
    size_t* signatureLen
) {
    if (!privateKey || !hash || !signature || !signatureLen) {
        return false;
    }

    try {
        SignatureData sig;
        size_t coordSize;

        switch (curve) {
            case Curve::SECP256K1:
                sig = signWithRecovery(secp256k1(), privateKey, privateKeyLen, hash, hashLen, true);
                coordSize = 32;
                break;
            case Curve::P256:
                sig = signWithRecovery(p256(), privateKey, privateKeyLen, hash, hashLen, false);
                coordSize = 32;
                break;
            case Curve::P384:
                sig = signWithRecovery(p384(), privateKey, privateKeyLen, hash, hashLen, false);
                coordSize = 48;
                break;
            default:
                return false;
        }

        ByteVector rec = sig.toRecoverable(coordSize);
        if (rec.size() > *signatureLen) {
            return false;
        }

        std::memcpy(signature, rec.data(), rec.size());
        *signatureLen = rec.size();

        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Sign and return compact signature (r || s without recovery byte)
 */
bool signCompact(
    Curve curve,
    const uint8_t* privateKey,
    size_t privateKeyLen,
    const uint8_t* hash,
    size_t hashLen,
    uint8_t* signature,
    size_t* signatureLen,
    int* recoveryId
) {
    if (!privateKey || !hash || !signature || !signatureLen) {
        return false;
    }

    try {
        SignatureData sig;
        size_t coordSize;

        switch (curve) {
            case Curve::SECP256K1:
                sig = signWithRecovery(secp256k1(), privateKey, privateKeyLen, hash, hashLen, true);
                coordSize = 32;
                break;
            case Curve::P256:
                sig = signWithRecovery(p256(), privateKey, privateKeyLen, hash, hashLen, false);
                coordSize = 32;
                break;
            case Curve::P384:
                sig = signWithRecovery(p384(), privateKey, privateKeyLen, hash, hashLen, false);
                coordSize = 48;
                break;
            default:
                return false;
        }

        ByteVector compact = sig.toCompact(coordSize);
        if (compact.size() > *signatureLen) {
            return false;
        }

        std::memcpy(signature, compact.data(), compact.size());
        *signatureLen = compact.size();

        if (recoveryId) {
            *recoveryId = sig.recoveryId;
        }

        return true;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// Public API: Verify
// =============================================================================

/**
 * Verify an ECDSA signature
 *
 * @param curve Elliptic curve
 * @param publicKey Public key (compressed or uncompressed)
 * @param publicKeyLen Public key length
 * @param hash Message hash
 * @param hashLen Hash length
 * @param signature Signature (DER format)
 * @param signatureLen Signature length
 * @return true if signature is valid
 */
bool verify(
    Curve curve,
    const uint8_t* publicKey,
    size_t publicKeyLen,
    const uint8_t* hash,
    size_t hashLen,
    const uint8_t* signature,
    size_t signatureLen
) {
    if (!publicKey || !hash || !signature) {
        return false;
    }

    try {
        SignatureData sig = SignatureData::fromDER(signature, signatureLen);
        return verifyCompact(curve, publicKey, publicKeyLen, hash, hashLen,
                            sig.toCompact(curve == Curve::P384 ? 48 : 32).data(),
                            sig.toCompact(curve == Curve::P384 ? 48 : 32).size());
    } catch (...) {
        return false;
    }
}

/**
 * Verify a compact ECDSA signature
 *
 * @param curve Elliptic curve
 * @param publicKey Public key (compressed or uncompressed)
 * @param publicKeyLen Public key length
 * @param hash Message hash
 * @param hashLen Hash length
 * @param signature Signature (compact: r || s)
 * @param signatureLen Signature length
 * @return true if signature is valid
 */
bool verifyCompact(
    Curve curve,
    const uint8_t* publicKey,
    size_t publicKeyLen,
    const uint8_t* hash,
    size_t hashLen,
    const uint8_t* signature,
    size_t signatureLen
) {
    if (!publicKey || !hash || !signature) {
        return false;
    }

    try {
        size_t coordSize;
        CryptoPP::Integer n;
        CryptoPP::ECPPoint G;
        CryptoPP::ECPPoint Q;
        const CryptoPP::ECP* ec;

        switch (curve) {
            case Curve::SECP256K1: {
                coordSize = 32;
                n = secp256k1().order();
                G = secp256k1().generator();
                ec = &secp256k1().ec();
                Q = parsePublicKey(secp256k1(), publicKey, publicKeyLen);
                break;
            }
            case Curve::P256: {
                coordSize = 32;
                n = p256().order();
                G = p256().generator();
                ec = &p256().ec();
                Q = parsePublicKey(p256(), publicKey, publicKeyLen);
                break;
            }
            case Curve::P384: {
                coordSize = 48;
                n = p384().order();
                G = p384().generator();
                ec = &p384().ec();
                Q = parsePublicKey(p384(), publicKey, publicKeyLen);
                break;
            }
            default:
                return false;
        }

        if (signatureLen != coordSize * 2) {
            return false;
        }

        // Parse r and s
        CryptoPP::Integer r(signature, coordSize);
        CryptoPP::Integer s(signature + coordSize, coordSize);

        // Validate r and s are in range [1, n-1]
        if (r <= 0 || r >= n || s <= 0 || s >= n) {
            return false;
        }

        // z = hash
        CryptoPP::Integer z(hash, hashLen);

        // w = s^-1 mod n
        CryptoPP::Integer w = s.InverseMod(n);

        // u1 = z * w mod n
        // u2 = r * w mod n
        CryptoPP::Integer u1 = (z * w) % n;
        CryptoPP::Integer u2 = (r * w) % n;

        // (x, y) = u1 * G + u2 * Q
        CryptoPP::ECPPoint point1 = ec->ScalarMultiply(G, u1);
        CryptoPP::ECPPoint point2 = ec->ScalarMultiply(Q, u2);
        CryptoPP::ECPPoint R = ec->Add(point1, point2);

        if (R.identity) {
            return false;
        }

        // v = x mod n
        CryptoPP::Integer v = R.x % n;

        // Signature is valid if v == r
        return v == r;
    } catch (...) {
        return false;
    }
}

// =============================================================================
// Public API: Recover
// =============================================================================

/**
 * Recover public key from signature and message hash
 *
 * @param curve Elliptic curve
 * @param hash Message hash
 * @param hashLen Hash length
 * @param signature Recoverable signature (65 bytes: v + r + s)
 * @param signatureLen Signature length
 * @param publicKey Output public key buffer
 * @param publicKeyLen Input: buffer size, Output: key length
 * @param compressed Output compressed format
 * @return true on success
 */
bool recover(
    Curve curve,
    const uint8_t* hash,
    size_t hashLen,
    const uint8_t* signature,
    size_t signatureLen,
    uint8_t* publicKey,
    size_t* publicKeyLen,
    bool compressed
) {
    if (!hash || !signature || !publicKey || !publicKeyLen) {
        return false;
    }

    try {
        size_t coordSize;
        CryptoPP::Integer n;
        CryptoPP::ECPPoint G;
        const CryptoPP::ECP* ec;
        CryptoPP::Integer p;

        switch (curve) {
            case Curve::SECP256K1:
                coordSize = 32;
                n = secp256k1().order();
                G = secp256k1().generator();
                ec = &secp256k1().ec();
                p = ec->GetField().GetModulus();
                break;
            case Curve::P256:
                coordSize = 32;
                n = p256().order();
                G = p256().generator();
                ec = &p256().ec();
                p = ec->GetField().GetModulus();
                break;
            case Curve::P384:
                coordSize = 48;
                n = p384().order();
                G = p384().generator();
                ec = &p384().ec();
                p = ec->GetField().GetModulus();
                break;
            default:
                return false;
        }

        if (signatureLen != 1 + coordSize * 2) {
            return false;
        }

        // Parse recovery ID
        uint8_t v = signature[0];
        int recoveryId;
        if (v >= 27 && v <= 30) {
            recoveryId = v - 27;
        } else if (v >= 31 && v <= 34) {
            recoveryId = v - 31;
        } else {
            return false;
        }

        // Parse r and s
        CryptoPP::Integer r(signature + 1, coordSize);
        CryptoPP::Integer s(signature + 1 + coordSize, coordSize);

        // Validate r and s
        if (r <= 0 || r >= n || s <= 0 || s >= n) {
            return false;
        }

        // Calculate R.x
        CryptoPP::Integer rx = r;
        if (recoveryId & 2) {
            rx += n;
        }

        // Check rx is valid field element
        if (rx >= p) {
            return false;
        }

        // Calculate R.y from R.x
        CryptoPP::Integer a = ec->GetA();
        CryptoPP::Integer b = ec->GetB();

        // y^2 = x^3 + ax + b mod p
        CryptoPP::Integer y2 = (a_exp_b_mod_c(rx, 3, p) + a * rx + b) % p;
        CryptoPP::Integer ry = a_exp_b_mod_c(y2, (p + 1) / 4, p);

        // Adjust y parity based on recovery ID
        bool yOdd = (recoveryId & 1) != 0;
        if (ry.IsOdd() != yOdd) {
            ry = p - ry;
        }

        CryptoPP::ECPPoint R;
        R.x = rx;
        R.y = ry;

        // Verify R is on curve
        if (!ec->VerifyPoint(R)) {
            return false;
        }

        // z = hash
        CryptoPP::Integer z(hash, hashLen);

        // rInv = r^-1 mod n
        CryptoPP::Integer rInv = r.InverseMod(n);

        // Q = rInv * (s * R - z * G)
        CryptoPP::ECPPoint sR = ec->ScalarMultiply(R, s);
        CryptoPP::ECPPoint zG = ec->ScalarMultiply(G, z);
        CryptoPP::ECPPoint zGNeg;
        zGNeg.x = zG.x;
        zGNeg.y = p - zG.y;  // Negate the point

        CryptoPP::ECPPoint diff = ec->Add(sR, zGNeg);
        CryptoPP::ECPPoint Q = ec->ScalarMultiply(diff, rInv);

        if (Q.identity) {
            return false;
        }

        // Encode public key
        if (compressed) {
            if (*publicKeyLen < coordSize + 1) {
                return false;
            }
            publicKey[0] = Q.y.IsOdd() ? 0x03 : 0x02;
            Q.x.Encode(publicKey + 1, coordSize);
            *publicKeyLen = coordSize + 1;
        } else {
            if (*publicKeyLen < coordSize * 2 + 1) {
                return false;
            }
            publicKey[0] = 0x04;
            Q.x.Encode(publicKey + 1, coordSize);
            Q.y.Encode(publicKey + 1 + coordSize, coordSize);
            *publicKeyLen = coordSize * 2 + 1;
        }

        return true;
    } catch (...) {
        return false;
    }
}

/**
 * Recover public key with specific recovery ID
 *
 * @param curve Elliptic curve
 * @param hash Message hash
 * @param hashLen Hash length
 * @param signature Compact signature (r || s)
 * @param signatureLen Signature length
 * @param recoveryId Recovery ID (0-3)
 * @param publicKey Output public key buffer
 * @param publicKeyLen Input: buffer size, Output: key length
 * @param compressed Output compressed format
 * @return true on success
 */
bool recoverWithId(
    Curve curve,
    const uint8_t* hash,
    size_t hashLen,
    const uint8_t* signature,
    size_t signatureLen,
    int recoveryId,
    uint8_t* publicKey,
    size_t* publicKeyLen,
    bool compressed
) {
    if (recoveryId < 0 || recoveryId > 3) {
        return false;
    }

    size_t coordSize = (curve == Curve::P384) ? 48 : 32;
    if (signatureLen != coordSize * 2) {
        return false;
    }

    // Build recoverable signature
    ByteVector recSig(1 + signatureLen);
    recSig[0] = static_cast<uint8_t>(27 + recoveryId);
    std::memcpy(recSig.data() + 1, signature, signatureLen);

    return recover(curve, hash, hashLen, recSig.data(), recSig.size(),
                   publicKey, publicKeyLen, compressed);
}

// =============================================================================
// Signature Utility Conversions
// =============================================================================

Result<CompactSignature> derToCompact(const ByteVector& der) {
    try {
        SignatureData sig = SignatureData::fromDER(der.data(), der.size());
        ByteVector compact = sig.toCompact(32);
        if (compact.size() != 64) {
            return Result<CompactSignature>::fail(Error::INVALID_SIGNATURE);
        }

        CompactSignature out{};
        std::memcpy(out.data(), compact.data(), out.size());
        return Result<CompactSignature>::success(std::move(out));
    } catch (...) {
        return Result<CompactSignature>::fail(Error::INVALID_SIGNATURE);
    }
}

ByteVector compactToDer(const CompactSignature& compact) {
    SignatureData sig = SignatureData::fromCompact(compact.data(), compact.size(), 32);
    return sig.toDER();
}

// =============================================================================
// C++ Wrapper Functions
// =============================================================================

Result<CompactSignature> secp256k1Sign(
    const Bytes32& privateKey,
    const Bytes32& messageHash
) {
    CompactSignature signature;
    size_t sigLen = signature.size();
    int recoveryId;

    if (signCompact(Curve::SECP256K1, privateKey.data(), privateKey.size(),
                    messageHash.data(), messageHash.size(),
                    signature.data(), &sigLen, &recoveryId)) {
        return Result<CompactSignature>::success(std::move(signature));
    }
    return Result<CompactSignature>::fail(Error::INVALID_SIGNATURE);
}

Result<RecoverableSignature> secp256k1SignRecoverable(
    const Bytes32& privateKey,
    const Bytes32& messageHash
) {
    RecoverableSignature signature;
    size_t sigLen = signature.size();

    if (signRecoverable(Curve::SECP256K1, privateKey.data(), privateKey.size(),
                        messageHash.data(), messageHash.size(),
                        signature.data(), &sigLen)) {
        return Result<RecoverableSignature>::success(std::move(signature));
    }
    return Result<RecoverableSignature>::fail(Error::INVALID_SIGNATURE);
}

bool secp256k1Verify(
    const ByteVector& publicKey,
    const Bytes32& messageHash,
    const CompactSignature& signature
) {
    return verifyCompact(Curve::SECP256K1, publicKey.data(), publicKey.size(),
                         messageHash.data(), messageHash.size(),
                         signature.data(), signature.size());
}

bool secp256k1Verify(
    const Bytes33& publicKey,
    const Bytes32& messageHash,
    const CompactSignature& signature
) {
    return verifyCompact(Curve::SECP256K1, publicKey.data(), publicKey.size(),
                         messageHash.data(), messageHash.size(),
                         signature.data(), signature.size());
}

Result<CompactSignature> p256Sign(
    const Bytes32& privateKey,
    const Bytes32& messageHash
) {
    CompactSignature signature;
    size_t sigLen = signature.size();
    int recoveryId;

    if (signCompact(Curve::P256, privateKey.data(), privateKey.size(),
                    messageHash.data(), messageHash.size(),
                    signature.data(), &sigLen, &recoveryId)) {
        return Result<CompactSignature>::success(std::move(signature));
    }
    return Result<CompactSignature>::fail(Error::INVALID_SIGNATURE);
}

bool p256Verify(
    const ByteVector& publicKey,
    const Bytes32& messageHash,
    const CompactSignature& signature
) {
    return verifyCompact(Curve::P256, publicKey.data(), publicKey.size(),
                         messageHash.data(), messageHash.size(),
                         signature.data(), signature.size());
}

bool p256Verify(
    const Bytes33& publicKey,
    const Bytes32& messageHash,
    const CompactSignature& signature
) {
    return verifyCompact(Curve::P256, publicKey.data(), publicKey.size(),
                         messageHash.data(), messageHash.size(),
                         signature.data(), signature.size());
}

Result<P384Signature> p384Sign(
    const P384PrivateKey& privateKey,
    const std::array<uint8_t, 48>& messageHash
) {
    P384Signature signature;
    size_t sigLen = signature.size();
    int recoveryId;

    if (signCompact(Curve::P384, privateKey.data(), privateKey.size(),
                    messageHash.data(), messageHash.size(),
                    signature.data(), &sigLen, &recoveryId)) {
        return Result<P384Signature>::success(std::move(signature));
    }
    return Result<P384Signature>::fail(Error::INVALID_SIGNATURE);
}

bool p384Verify(
    const ByteVector& publicKey,
    const std::array<uint8_t, 48>& messageHash,
    const P384Signature& signature
) {
    return verifyCompact(Curve::P384, publicKey.data(), publicKey.size(),
                         messageHash.data(), messageHash.size(),
                         signature.data(), signature.size());
}

} // namespace ecdsa
} // namespace hd_wallet
