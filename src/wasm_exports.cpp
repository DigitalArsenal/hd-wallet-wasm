/**
 * WASM-specific C API exports
 *
 * This file contains C wrappers for functions that are NOT already exported
 * from the main library source files (bip32.cpp, bip39.cpp, bip44.cpp, eddsa.cpp).
 *
 * Functions that ARE already exported from main sources:
 * - BIP-39: hd_mnemonic_* (from bip39.cpp)
 * - BIP-32: hd_key_* (from bip32.cpp)
 * - BIP-44: hd_path_* (from bip44.cpp)
 * - Ed25519: hd_ed25519_* (from eddsa.cpp)
 * - X25519: hd_ecdh_x25519, hd_x25519_pubkey (from eddsa.cpp)
 *
 * Functions exported HERE (unique to this file):
 * - Hash: hd_hash_sha256, hd_hash_sha512, hd_hash_keccak256, hd_hash_ripemd160, hd_hash_hash160, hd_hash_blake2b, hd_hash_blake2s
 * - KDF: hd_kdf_hkdf, hd_kdf_pbkdf2, hd_kdf_scrypt
 * - Curves: hd_curve_pubkey_from_privkey
 * - secp256k1: hd_secp256k1_sign, hd_secp256k1_verify, hd_ecdh_secp256k1
 * - P-256/P-384: hd_p256_sign, hd_p256_verify, hd_ecdh_p256, hd_p384_sign, hd_p384_verify, hd_ecdh_p384
 */

#include "hd_wallet/config.h"
#include "hd_wallet/types.h"
#include "hd_wallet/error.h"
#include "hd_wallet/bip32.h"

// Forward declaration of C function from ecdh.cpp
extern "C" int32_t hd_ecdh(
    int32_t curve,
    const uint8_t* private_key,
    size_t private_key_len,
    const uint8_t* public_key,
    size_t public_key_len,
    uint8_t* shared_secret,
    size_t shared_secret_size
);

#include <cryptopp/sha.h>
#include <cryptopp/sha3.h>
#include <cryptopp/keccak.h>
#include <cryptopp/ripemd.h>
#include <cryptopp/blake2.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/eccrypto.h>
#include <cryptopp/oids.h>
#include <cryptopp/nbtheory.h>
#include <cryptopp/filters.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/secblock.h>

#if HD_WALLET_USE_OPENSSL
#include "hd_wallet/crypto_openssl.h"
#endif

#ifdef HD_WALLET_USE_LIBSECP256K1
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#endif

#include <cstring>
#include <array>
#include <vector>
#include <string>

namespace hd_wallet::ecdsa {
using CompactSignature = std::array<uint8_t, 64>;
using P384PrivateKey = std::array<uint8_t, 48>;
using P384Signature = std::array<uint8_t, 96>;

Result<CompactSignature> secp256k1Sign(
    const Bytes32& privateKey,
    const Bytes32& messageHash
);
Result<CompactSignature> p256Sign(
    const Bytes32& privateKey,
    const Bytes32& messageHash
);
Result<P384Signature> p384Sign(
    const P384PrivateKey& privateKey,
    const std::array<uint8_t, 48>& messageHash
);

Result<CompactSignature> derToCompact(const ByteVector& der);
bool secp256k1Verify(
    const ByteVector& publicKey,
    const Bytes32& messageHash,
    const CompactSignature& signature
);
bool p256Verify(
    const ByteVector& publicKey,
    const Bytes32& messageHash,
    const CompactSignature& signature
);
bool p384Verify(
    const ByteVector& publicKey,
    const std::array<uint8_t, 48>& messageHash,
    const P384Signature& signature
);
} // namespace hd_wallet::ecdsa

namespace hd_wallet {

using Error = hd_wallet::Error;

// =============================================================================
// Hash Functions
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_sha256(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::SHA256 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 32;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_sha512(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::SHA512 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 64;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_keccak256(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::Keccak_256 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 32;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_ripemd160(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 20) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::RIPEMD160 hash;
    hash.CalculateDigest(hash_out, data, data_len);
    return 20;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_hash160(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < 20) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    // Hash160 = RIPEMD160(SHA256(data))
    uint8_t sha_out[32];
    CryptoPP::SHA256 sha;
    sha.CalculateDigest(sha_out, data, data_len);
    CryptoPP::RIPEMD160 ripemd;
    ripemd.CalculateDigest(hash_out, sha_out, 32);
    // Wipe intermediate hash
    std::memset(sha_out, 0, sizeof(sha_out));
    return 20;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_blake2b(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size, size_t digest_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < digest_size || digest_size > 64 || digest_size == 0) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::BLAKE2b hash(false, digest_size);
    hash.CalculateDigest(hash_out, data, data_len);
    return static_cast<int32_t>(digest_size);
}

extern "C" HD_WALLET_EXPORT
int32_t hd_hash_blake2s(const uint8_t* data, size_t data_len, uint8_t* hash_out, size_t out_size, size_t digest_size) {
    if (data == nullptr || hash_out == nullptr) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (out_size < digest_size || digest_size > 32 || digest_size == 0) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    CryptoPP::BLAKE2s hash(false, digest_size);
    hash.CalculateDigest(hash_out, data, data_len);
    return static_cast<int32_t>(digest_size);
}

// =============================================================================
// Key Derivation Functions
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_kdf_hkdf(
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* salt, size_t salt_len,
    const uint8_t* info, size_t info_len,
    uint8_t* okm_out, size_t okm_len
) {
    try {
        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        hkdf.DeriveKey(okm_out, okm_len, ikm, ikm_len, salt, salt_len, info, info_len);
        return static_cast<int32_t>(okm_len);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_kdf_pbkdf2(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint32_t iterations,
    uint8_t* key_out, size_t key_len
) {
    try {
        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf2;
        pbkdf2.DeriveKey(key_out, key_len, 0, password, password_len, salt, salt_len, iterations);
        return static_cast<int32_t>(key_len);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_kdf_scrypt(
    const uint8_t* password, size_t password_len,
    const uint8_t* salt, size_t salt_len,
    uint64_t N, uint32_t r, uint32_t p,
    uint8_t* key_out, size_t key_len
) {
    try {
        CryptoPP::Scrypt scrypt;
        scrypt.DeriveKey(key_out, key_len, password, password_len, salt, salt_len, N, r, p);
        return static_cast<int32_t>(key_len);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// Curve Operations
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_curve_pubkey_from_privkey(
    const uint8_t* private_key,
    int32_t curve_type,
    uint8_t* public_key_out,
    size_t out_size
) {
    try {
        auto curve = static_cast<Curve>(curve_type);

        switch (curve) {
            case Curve::SECP256K1: {
                if (out_size < 33) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;
                CryptoPP::Integer privKeyInt(private_key, 32);
                privKey.Initialize(CryptoPP::ASN1::secp256k1(), privKeyInt);

                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;
                privKey.MakePublicKey(pubKey);

                const auto& point = pubKey.GetPublicElement();
                // Compressed format: 0x02/0x03 + x coordinate
                public_key_out[0] = point.y.IsOdd() ? 0x03 : 0x02;
                point.x.Encode(public_key_out + 1, 32);
                return 33;
            }
            case Curve::P256: {
                if (out_size < 33) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey privKey;
                CryptoPP::Integer privKeyInt(private_key, 32);
                privKey.Initialize(CryptoPP::ASN1::secp256r1(), privKeyInt);

                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey pubKey;
                privKey.MakePublicKey(pubKey);

                const auto& point = pubKey.GetPublicElement();
                public_key_out[0] = point.y.IsOdd() ? 0x03 : 0x02;
                point.x.Encode(public_key_out + 1, 32);
                return 33;
            }
            case Curve::P384: {
                if (out_size < 49) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PrivateKey privKey;
                CryptoPP::Integer privKeyInt(private_key, 48);
                privKey.Initialize(CryptoPP::ASN1::secp384r1(), privKeyInt);

                CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>::PublicKey pubKey;
                privKey.MakePublicKey(pubKey);

                const auto& point = pubKey.GetPublicElement();
                public_key_out[0] = point.y.IsOdd() ? 0x03 : 0x02;
                point.x.Encode(public_key_out + 1, 48);
                return 49;
            }
            case Curve::ED25519:
            case Curve::X25519:
                // These are handled by the Ed25519/X25519 specific functions in eddsa.cpp
                return static_cast<int32_t>(Error::NOT_SUPPORTED);
            default:
                return static_cast<int32_t>(Error::NOT_SUPPORTED);
        }
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// secp256k1 Signing (RFC 6979 Deterministic)
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    // Return compact R||S format (64 bytes) for consistency with blockchain usage
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    if (message == nullptr || private_key == nullptr || signature_out == nullptr) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    try {
        Bytes32 msgHash{};
        CryptoPP::SHA256 sha;
        sha.CalculateDigest(msgHash.data(), message, message_len);

        Bytes32 privateKey{};
        std::memcpy(privateKey.data(), private_key, privateKey.size());

        auto signResult = ecdsa::secp256k1Sign(privateKey, msgHash);
        if (!signResult.ok()) {
            return static_cast<int32_t>(Error::INVALID_SIGNATURE);
        }

        std::memcpy(signature_out, signResult.value.data(), signResult.value.size());

        // Securely clear stack buffers.
        std::memset(msgHash.data(), 0, msgHash.size());
        std::memset(privateKey.data(), 0, privateKey.size());

        return 64;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* signature, size_t signature_len,
    const uint8_t* public_key, size_t public_key_len
) {
    if (message == nullptr || signature == nullptr || public_key == nullptr) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    if (public_key_len != 33 && public_key_len != 65) {
        return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
    }

    try {
        // Hash message (SHA-256) to match signing path.
        Bytes32 msgHash{};
        CryptoPP::SHA256 sha;
        sha.CalculateDigest(msgHash.data(), message, message_len);

        // Accept compact (64-byte) or DER signatures.
        ecdsa::CompactSignature compactSig{};
        if (signature_len == compactSig.size()) {
            std::memcpy(compactSig.data(), signature, compactSig.size());
        } else {
            ByteVector derSig(signature, signature + signature_len);
            auto compactResult = ecdsa::derToCompact(derSig);
            if (!compactResult.ok()) {
                return static_cast<int32_t>(Error::INVALID_SIGNATURE);
            }
            compactSig = compactResult.value;
        }

        ByteVector publicKeyVec(public_key, public_key + public_key_len);
        bool valid = ecdsa::secp256k1Verify(publicKeyVec, msgHash, compactSig);
        return valid ? 1 : 0;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// secp256k1 Recoverable Signing (for Bitcoin/Ethereum message signing)
// =============================================================================

#ifdef HD_WALLET_USE_LIBSECP256K1

namespace {
/**
 * Get libsecp256k1 context for recoverable signatures (lazy init)
 */
static secp256k1_context* wasm_secp256k1_ctx() {
    static secp256k1_context* ctx = secp256k1_context_create(
        SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    return ctx;
}
} // anonymous namespace

extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_sign_recoverable(
    const uint8_t* hash, size_t hash_len,
    const uint8_t* privkey,
    uint8_t* out_sig65
) {
    if (!hash || hash_len != 32 || !privkey || !out_sig65) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    secp256k1_context* ctx = wasm_secp256k1_ctx();

    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_sign_recoverable(ctx, &sig, hash, privkey, NULL, NULL) != 1) {
        return static_cast<int32_t>(Error::INVALID_SIGNATURE);
    }

    int recid;
    secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, out_sig65, &recid, &sig);
    out_sig65[64] = static_cast<uint8_t>(recid);

    return 65;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_recover(
    const uint8_t* hash, size_t hash_len,
    const uint8_t* sig65,
    uint8_t* out_pubkey33
) {
    if (!hash || hash_len != 32 || !sig65 || !out_pubkey33) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    secp256k1_context* ctx = wasm_secp256k1_ctx();

    int recid = sig65[64];
    if (recid < 0 || recid > 3) {
        return static_cast<int32_t>(Error::INVALID_SIGNATURE);
    }

    secp256k1_ecdsa_recoverable_signature sig;
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, sig65, recid) != 1) {
        return static_cast<int32_t>(Error::INVALID_SIGNATURE);
    }

    secp256k1_pubkey pubkey;
    if (secp256k1_ecdsa_recover(ctx, &pubkey, &sig, hash) != 1) {
        return static_cast<int32_t>(Error::INVALID_SIGNATURE);
    }

    size_t len = 33;
    secp256k1_ec_pubkey_serialize(ctx, out_pubkey33, &len, &pubkey, SECP256K1_EC_COMPRESSED);

    return 33;
}

#else // !HD_WALLET_USE_LIBSECP256K1

extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_sign_recoverable(
    const uint8_t* hash, size_t hash_len,
    const uint8_t* privkey,
    uint8_t* out_sig65
) {
    if (!hash || hash_len != 32 || !privkey || !out_sig65) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    // Fallback to Crypto++ recoverable signing
    Bytes32 msgHash{};
    std::memcpy(msgHash.data(), hash, 32);

    Bytes32 privateKey{};
    std::memcpy(privateKey.data(), privkey, 32);

    auto signResult = ecdsa::secp256k1SignRecoverable(privateKey, msgHash);
    if (!signResult.ok()) {
        return static_cast<int32_t>(Error::INVALID_SIGNATURE);
    }

    // signResult.value is 65 bytes: v[1] + r[32] + s[32]
    // We need r[32] + s[32] + v[1] format
    std::memcpy(out_sig65, signResult.value.data() + 1, 64);  // r + s
    out_sig65[64] = signResult.value[0] - 27;  // Convert from Bitcoin convention to recid

    std::memset(msgHash.data(), 0, msgHash.size());
    std::memset(privateKey.data(), 0, privateKey.size());

    return 65;
}

extern "C" HD_WALLET_EXPORT
int32_t hd_secp256k1_recover(
    const uint8_t* hash, size_t hash_len,
    const uint8_t* sig65,
    uint8_t* out_pubkey33
) {
    if (!hash || hash_len != 32 || !sig65 || !out_pubkey33) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    // Build recoverable signature in Bitcoin convention: v[1] + r[32] + s[32]
    ecdsa::RecoverableSignature recSig;
    recSig[0] = 27 + sig65[64];  // Convert recid to Bitcoin convention
    std::memcpy(recSig.data() + 1, sig65, 64);  // r + s

    Bytes32 msgHash{};
    std::memcpy(msgHash.data(), hash, 32);

    auto result = ecdsa::secp256k1RecoverCompressed(msgHash, recSig);
    if (!result.ok()) {
        return static_cast<int32_t>(Error::INVALID_SIGNATURE);
    }

    std::memcpy(out_pubkey33, result.value.data(), 33);
    return 33;
}

#endif // HD_WALLET_USE_LIBSECP256K1

extern "C" HD_WALLET_EXPORT
int32_t hd_curve_decompress_pubkey(
    const uint8_t* compressed,
    int32_t curve,
    uint8_t* uncompressed_out,
    size_t out_size
) {
    if (out_size < 65) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    if (curve != static_cast<int32_t>(Curve::SECP256K1)) {
        return static_cast<int32_t>(Error::NOT_SUPPORTED);
    }

    Bytes33 pubkey;
    std::memcpy(pubkey.data(), compressed, 33);

    auto result = bip32::decompressPublicKey(pubkey, static_cast<Curve>(curve));
    if (!result.ok()) {
        return static_cast<int32_t>(result.error);
    }

    std::memcpy(uncompressed_out, result.value.data(), 65);
    return 0;
}

// Static singleton for secp256k1 curve (same pattern as ecdsa.cpp)
namespace {
class Secp256k1Curve {
public:
    static Secp256k1Curve& instance() {
        static Secp256k1Curve inst;
        return inst;
    }

    const CryptoPP::ECP& ec() const { return curve_.GetCurve(); }
    const CryptoPP::Integer& order() const { return n_; }

private:
    Secp256k1Curve() {
        curve_.Initialize(CryptoPP::ASN1::secp256k1());
        n_ = curve_.GetGroupOrder();
    }

    CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curve_;
    CryptoPP::Integer n_;
};
} // anonymous namespace

extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_secp256k1(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_len,
    uint8_t* shared_secret_out, size_t out_size
) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    // Validate public key format
    if (public_key_len != 33 && public_key_len != 65) {
        return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
    }

    try {
        // Use static singleton curve (same pattern as working ECDSA code)
        const CryptoPP::ECP& ec = Secp256k1Curve::instance().ec();
        const CryptoPP::Integer& order = Secp256k1Curve::instance().order();

        // Parse private key as integer
        CryptoPP::Integer d(private_key, 32);

        // Validate private key range
        if (d <= 0 || d >= order) {
            return static_cast<int32_t>(Error::INVALID_PRIVATE_KEY);
        }

        // Parse public key point using DecodePoint for proper initialization
        // NOTE: Must use DecodePoint instead of manual x/y decoding for ScalarMultiply to work
        CryptoPP::ECP::Point Q;
        Q.identity = false;

        if (public_key_len == 65) {
            if (public_key[0] != 0x04) {
                return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            }
            if (!ec.DecodePoint(Q, public_key, 65)) {
                return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            }
        } else {
            if (public_key[0] != 0x02 && public_key[0] != 0x03) {
                return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            }
            if (!ec.DecodePoint(Q, public_key, 33)) {
                return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            }
        }

        // Validate public key is on curve
        if (!ec.VerifyPoint(Q)) {
            return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        }

        // Compute shared secret: S = d * Q (scalar multiplication)
        CryptoPP::ECP::Point S = ec.ScalarMultiply(Q, d);

        // Check for point at infinity
        if (S.identity) {
            return static_cast<int32_t>(Error::INTERNAL);
        }

        // Output the x-coordinate as the shared secret (32 bytes)
        S.x.Encode(shared_secret_out, 32);
        return 32;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// P-256 (NIST secp256r1) - RFC 6979 Deterministic
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_p256_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    if (out_size < 64) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    if (message == nullptr || private_key == nullptr || signature_out == nullptr) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    try {
        Bytes32 msgHash{};
        CryptoPP::SHA256 sha;
        sha.CalculateDigest(msgHash.data(), message, message_len);

        Bytes32 privateKey{};
        std::memcpy(privateKey.data(), private_key, privateKey.size());

        auto signResult = ecdsa::p256Sign(privateKey, msgHash);
        if (!signResult.ok()) {
            return static_cast<int32_t>(Error::INVALID_SIGNATURE);
        }

        std::memcpy(signature_out, signResult.value.data(), signResult.value.size());

        // Securely clear stack buffers.
        std::memset(msgHash.data(), 0, msgHash.size());
        std::memset(privateKey.data(), 0, privateKey.size());

        return 64;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_p256_verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* public_key, size_t public_key_len,
    const uint8_t* signature
) {
    if (message == nullptr || public_key == nullptr || signature == nullptr) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    if (public_key_len != 33 && public_key_len != 65) {
        return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
    }

    try {
        Bytes32 msgHash{};
        CryptoPP::SHA256 sha;
        sha.CalculateDigest(msgHash.data(), message, message_len);

        ecdsa::CompactSignature compactSig{};
        std::memcpy(compactSig.data(), signature, compactSig.size());

        ByteVector publicKeyVec(public_key, public_key + public_key_len);
        bool valid = ecdsa::p256Verify(publicKeyVec, msgHash, compactSig);
        return valid ? 0 : static_cast<int32_t>(Error::INVALID_SIGNATURE);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_p256(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_len,
    uint8_t* shared_secret_out, size_t out_size
) {
    if (out_size < 32) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    // Accept compressed (33) or uncompressed (65) public keys
    if (public_key_len != 33 && public_key_len != 65) {
        return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
    }

    try {
        // Use manual DecodePoint + ScalarMultiply instead of ECDH::Domain::Agree()
        // which produces incorrect results in 32-bit Emscripten WASM builds.
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curveParams;
        curveParams.Initialize(CryptoPP::ASN1::secp256r1());
        const CryptoPP::ECP& ec = curveParams.GetCurve();
        const CryptoPP::Integer& order = curveParams.GetGroupOrder();

        CryptoPP::Integer d(private_key, 32);
        if (d <= 0 || d >= order) {
            return static_cast<int32_t>(Error::INVALID_PRIVATE_KEY);
        }

        CryptoPP::ECP::Point Q;
        if (public_key_len == 65) {
            if (public_key[0] != 0x04) return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            if (!ec.DecodePoint(Q, public_key, 65)) return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        } else {
            if (public_key[0] != 0x02 && public_key[0] != 0x03) return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            if (!ec.DecodePoint(Q, public_key, 33)) return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        }

        if (!ec.VerifyPoint(Q)) {
            return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        }

        CryptoPP::ECP::Point S = ec.ScalarMultiply(Q, d);
        if (S.identity) {
            return static_cast<int32_t>(Error::INTERNAL);
        }

        // SECURITY FIX [VULN-12]: Output only x-coordinate as shared secret
        S.x.Encode(shared_secret_out, 32);
        return 32;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// P-384 (NIST secp384r1) - RFC 6979 Deterministic
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_p384_sign(
    const uint8_t* message, size_t message_len,
    const uint8_t* private_key,
    uint8_t* signature_out, size_t out_size
) {
    if (out_size < 96) return static_cast<int32_t>(Error::OUT_OF_MEMORY);
    if (message == nullptr || private_key == nullptr || signature_out == nullptr) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    try {
        std::array<uint8_t, 48> msgHash{};
        CryptoPP::SHA384 sha;
        sha.CalculateDigest(msgHash.data(), message, message_len);

        ecdsa::P384PrivateKey privateKey{};
        std::memcpy(privateKey.data(), private_key, privateKey.size());

        auto signResult = ecdsa::p384Sign(privateKey, msgHash);
        if (!signResult.ok()) {
            return static_cast<int32_t>(Error::INVALID_SIGNATURE);
        }

        std::memcpy(signature_out, signResult.value.data(), signResult.value.size());

        // Securely clear stack buffers.
        std::memset(msgHash.data(), 0, msgHash.size());
        std::memset(privateKey.data(), 0, privateKey.size());

        return 96;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_p384_verify(
    const uint8_t* message, size_t message_len,
    const uint8_t* public_key, size_t public_key_len,
    const uint8_t* signature
) {
    if (message == nullptr || public_key == nullptr || signature == nullptr) {
        return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    if (public_key_len != 49 && public_key_len != 97) {
        return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
    }

    try {
        std::array<uint8_t, 48> msgHash{};
        CryptoPP::SHA384 sha;
        sha.CalculateDigest(msgHash.data(), message, message_len);

        ecdsa::P384Signature compactSig{};
        std::memcpy(compactSig.data(), signature, compactSig.size());

        ByteVector publicKeyVec(public_key, public_key + public_key_len);
        bool valid = ecdsa::p384Verify(publicKeyVec, msgHash, compactSig);
        return valid ? 0 : static_cast<int32_t>(Error::INVALID_SIGNATURE);
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

extern "C" HD_WALLET_EXPORT
int32_t hd_ecdh_p384(
    const uint8_t* private_key,
    const uint8_t* public_key, size_t public_key_len,
    uint8_t* shared_secret_out, size_t out_size
) {
    if (out_size < 48) return static_cast<int32_t>(Error::OUT_OF_MEMORY);

    // Accept compressed (49) or uncompressed (97) public keys
    if (public_key_len != 49 && public_key_len != 97) {
        return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
    }

    try {
        // Use manual DecodePoint + ScalarMultiply instead of ECDH::Domain::Agree()
        // which produces incorrect results in 32-bit Emscripten WASM builds.
        CryptoPP::DL_GroupParameters_EC<CryptoPP::ECP> curveParams;
        curveParams.Initialize(CryptoPP::ASN1::secp384r1());
        const CryptoPP::ECP& ec = curveParams.GetCurve();
        const CryptoPP::Integer& order = curveParams.GetGroupOrder();

        CryptoPP::Integer d(private_key, 48);
        if (d <= 0 || d >= order) {
            return static_cast<int32_t>(Error::INVALID_PRIVATE_KEY);
        }

        CryptoPP::ECP::Point Q;
        if (public_key_len == 97) {
            if (public_key[0] != 0x04) return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            if (!ec.DecodePoint(Q, public_key, 97)) return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        } else {
            if (public_key[0] != 0x02 && public_key[0] != 0x03) return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
            if (!ec.DecodePoint(Q, public_key, 49)) return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        }

        if (!ec.VerifyPoint(Q)) {
            return static_cast<int32_t>(Error::INVALID_PUBLIC_KEY);
        }

        CryptoPP::ECP::Point S = ec.ScalarMultiply(Q, d);
        if (S.identity) {
            return static_cast<int32_t>(Error::INTERNAL);
        }

        // SECURITY FIX [VULN-12]: Output only x-coordinate as shared secret
        S.x.Encode(shared_secret_out, 48);
        return 48;
    } catch (...) {
        return static_cast<int32_t>(Error::INTERNAL);
    }
}

// =============================================================================
// AES-GCM Encryption
// =============================================================================

extern "C" HD_WALLET_EXPORT
int32_t hd_aes_gcm_encrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, size_t pt_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    uint8_t* ciphertext,
    uint8_t* tag
) {
    if (key_len != 32) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (iv_len != 12) return static_cast<int32_t>(Error::INVALID_ARGUMENT);

#if HD_WALLET_USE_OPENSSL
    return hd_ossl_aes_gcm_encrypt(key, key_len, plaintext, pt_len,
                                   iv, iv_len, aad, aad_len, ciphertext, tag);
#else
    // Use non-throwing API due to WASM -fignore-exceptions
    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, key_len, iv, iv_len);

    // Set data lengths for authentication (AAD length, plaintext length, footer length)
    enc.SpecifyDataLengths(aad_len, pt_len, 0);

    // Process AAD
    if (aad && aad_len > 0) {
        enc.Update(aad, aad_len);
    }

    // Encrypt plaintext
    enc.ProcessData(ciphertext, plaintext, pt_len);

    // Generate authentication tag
    enc.TruncatedFinal(tag, 16);

    return static_cast<int32_t>(pt_len);
#endif
}

extern "C" HD_WALLET_EXPORT
int32_t hd_aes_gcm_decrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* ciphertext, size_t ct_len,
    const uint8_t* iv, size_t iv_len,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag,
    uint8_t* plaintext
) {
    if (key_len != 32) return static_cast<int32_t>(Error::INVALID_ARGUMENT);
    if (iv_len != 12) return static_cast<int32_t>(Error::INVALID_ARGUMENT);

#if HD_WALLET_USE_OPENSSL
    return hd_ossl_aes_gcm_decrypt(key, key_len, ciphertext, ct_len,
                                   iv, iv_len, aad, aad_len, tag, plaintext);
#else
    // Use non-throwing API due to WASM -fignore-exceptions
    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, key_len, iv, iv_len);

    // For GCM, we need to:
    // 1. Process AAD
    // 2. Decrypt ciphertext
    // 3. Verify the authentication tag

    // Set data lengths for authentication
    dec.SpecifyDataLengths(aad_len, ct_len, 0);

    // Process AAD
    if (aad && aad_len > 0) {
        dec.Update(aad, aad_len);
    }

    // Decrypt ciphertext
    dec.ProcessData(plaintext, ciphertext, ct_len);

    // Verify the tag (TruncatedVerify returns true if tag matches)
    if (!dec.TruncatedVerify(tag, 16)) {
        // Authentication failed - zero out plaintext for safety
        std::memset(plaintext, 0, ct_len);
        return -static_cast<int32_t>(Error::VERIFICATION_FAILED);
    }

    return static_cast<int32_t>(ct_len);
#endif
}

} // namespace hd_wallet
