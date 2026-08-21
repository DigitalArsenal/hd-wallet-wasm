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

#if defined(HD_WALLET_SDN_TYPED_API) && HD_WALLET_SDN_TYPED_API
#include "hd_wallet/sdn_identity.h"
#include "hd_wallet/secure_memory.h"
#include "canonical_json.h"

#include <emscripten/heap.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <initializer_list>
#include <limits>
#include <new>
#include <optional>
#include <span>
#include <string_view>
#include <utility>
#include <variant>
#endif

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

#if defined(HD_WALLET_SDN_TYPED_API) && HD_WALLET_SDN_TYPED_API

namespace hd_wallet::sdn::wasm_adapter {
namespace {

using jcs::Value;

constexpr uint32_t kMaximumOutputBytes = 131072;
constexpr uint32_t kMaximumModernCredentialBytes = 256;
constexpr uint32_t kMaximumLegacyCredentialBytes = 4096;
constexpr uint32_t kMaximumMnemonicBytes = 1024;
constexpr uint32_t kMaximumAadBytes = 4096;
constexpr uint32_t kMinimumRememberedCiphertextBytes = 16;
constexpr uint32_t kMaximumRememberedCiphertextBytes = 1024;

uint16_t status(IdentityError error) noexcept {
    return static_cast<uint16_t>(error);
}

template <typename Function>
uint16_t guarded(Function&& function) noexcept {
    try {
        return function();
    } catch (const std::bad_alloc&) {
        return status(IdentityError::OutOfMemory);
    } catch (...) {
        return status(IdentityError::CryptoFailure);
    }
}

bool validRange(const void* pointer, uint32_t length) noexcept {
    if (pointer == nullptr) return false;
    const uintptr_t start = reinterpret_cast<uintptr_t>(pointer);
    const size_t heap_size = emscripten_get_heap_size();
    if (start == 0 || start > heap_size) return false;
    return static_cast<size_t>(length) <= heap_size - start;
}

template <typename T>
bool validScalar(const T* pointer) noexcept {
    return validRange(pointer, static_cast<uint32_t>(sizeof(T)));
}

template <typename T>
void storeScalar(T* pointer, T value) noexcept {
    std::memcpy(pointer, &value, sizeof(value));
}

class WipeOnExit {
public:
    WipeOnExit(uint8_t* pointer, uint32_t length) noexcept
        : pointer_(pointer), length_(length) {}
    WipeOnExit(const WipeOnExit&) = delete;
    WipeOnExit& operator=(const WipeOnExit&) = delete;
    ~WipeOnExit() { secureWipe(pointer_, length_); }

private:
    uint8_t* pointer_;
    uint32_t length_;
};

class PendingHandle {
public:
    explicit PendingHandle(IdentityHandle handle) noexcept : handle_(handle) {}
    PendingHandle(const PendingHandle&) = delete;
    PendingHandle& operator=(const PendingHandle&) = delete;
    ~PendingHandle() {
        if (handle_ != 0) destroy_identity(handle_);
    }
    void release() noexcept { handle_ = 0; }

private:
    IdentityHandle handle_;
};

bool prepareOutput(uint8_t* output, uint32_t capacity,
                   uint32_t* out_required) noexcept {
    if (!validScalar(out_required)) return false;
    storeScalar(out_required, uint32_t{0});
    if (capacity > kMaximumOutputBytes || !validRange(output, capacity)) {
        return false;
    }
    if (capacity != 0) std::memset(output, 0, capacity);
    return true;
}

bool prepareDerivedOutput(uint64_t* out_handle, uint8_t* output,
                          uint32_t capacity,
                          uint32_t* out_required) noexcept {
    const bool handle_valid = validScalar(out_handle);
    if (handle_valid) storeScalar(out_handle, uint64_t{0});
    const bool output_valid = prepareOutput(output, capacity, out_required);
    return handle_valid && output_valid;
}

bool lowerHex(std::string_view value, size_t length) noexcept {
    if (value.size() != length) return false;
    return std::all_of(value.begin(), value.end(), [](char byte) {
        return (byte >= '0' && byte <= '9') ||
               (byte >= 'a' && byte <= 'f');
    });
}

bool validKeyId(std::string_view value) noexcept {
    return value.size() == 71 && value.rfind("sha256:", 0) == 0 &&
           lowerHex(value.substr(7), 64);
}

std::string hex(std::span<const uint8_t> bytes) {
    static constexpr char alphabet[] = "0123456789abcdef";
    std::string result(bytes.size() * 2, '\0');
    for (size_t index = 0; index < bytes.size(); ++index) {
        result[index * 2] = alphabet[bytes[index] >> 4];
        result[index * 2 + 1] = alphabet[bytes[index] & 0x0f];
    }
    return result;
}

std::optional<std::string> purposeName(Purpose purpose) {
    switch (purpose) {
        case Purpose::AssetReviewApproval:
            return "asset-review-approval";
        case Purpose::ContactEncryption:
            return "contact-encryption";
        case Purpose::SdnAuthentication:
            return "sdn-authentication";
    }
    return std::nullopt;
}

std::optional<std::string> curveName(Curve curve) {
    switch (curve) {
        case Curve::ED25519:
            return "ed25519";
        case Curve::X25519:
            return "x25519";
        default:
            return std::nullopt;
    }
}

std::optional<std::string> derivationName(KeyDerivation derivation) {
    switch (derivation) {
        case KeyDerivation::Slip10Ed25519:
        case KeyDerivation::Slip10X25519:
            return "slip10";
        case KeyDerivation::LegacyBip32ScalarAsEd25519Seed:
            return "bip32-scalar-as-ed25519-seed";
        default:
            return std::nullopt;
    }
}

bool descriptorMatches(const PublicKeyDescriptor& descriptor,
                       std::string_view scheme,
                       std::string_view profile,
                       Purpose purpose,
                       Curve curve,
                       KeyDerivation derivation,
                       std::string_view path,
                       std::optional<std::string_view> signature_profile) {
    if (descriptor.purpose != purpose || descriptor.identity_scheme != scheme ||
        descriptor.seed_profile != profile || descriptor.curve != curve ||
        descriptor.derivation != derivation || descriptor.path != path ||
        descriptor.encoding != KeyEncoding::Raw ||
        descriptor.public_key.size() != 32 ||
        descriptor.bip32_fingerprint.has_value() ||
        !validKeyId(descriptor.key_id)) {
        return false;
    }
    if (signature_profile.has_value()) {
        return descriptor.signature_profile.has_value() &&
               *descriptor.signature_profile == *signature_profile;
    }
    return !descriptor.signature_profile.has_value();
}

using StringOutcome = std::variant<std::string, IdentityError>;

StringOutcome serializeValue(Value value) {
    auto serialized = jcs::serialize_jcs(value, jcs::Limits{});
    if (std::holds_alternative<jcs::JcsError>(serialized)) {
        return std::get<jcs::JcsError>(serialized) == jcs::JcsError::OutOfMemory
                   ? IdentityError::OutOfMemory
                   : IdentityError::CryptoFailure;
    }
    auto text = std::get<std::string>(std::move(serialized));
    if (text.empty() || text.size() > kMaximumOutputBytes) {
        return IdentityError::CryptoFailure;
    }
    return text;
}

StringOutcome serializeIdentity(const PublicIdentity& identity) {
    if (identity.schema_version != 1 || identity.account_index > 1 ||
        identity.account_label.has_value() || identity.account_xpub.empty() ||
        identity.account_peer_id.empty()) {
        return IdentityError::CryptoFailure;
    }
    const bool modern = identity.identity_scheme == kIdentityScheme &&
                        identity.seed_profile == kPasswordProfile;
    const bool legacy_fast =
        identity.identity_scheme == kLegacyFastIdentityScheme &&
        identity.seed_profile == kLegacyPasswordProfile;
    const bool legacy_mnemonic =
        identity.identity_scheme == kLegacyMnemonicIdentityScheme &&
        identity.seed_profile == kLegacyMnemonicSeedProfile;
    if (!modern && !legacy_fast && !legacy_mnemonic) {
        return IdentityError::CryptoFailure;
    }
    const std::string prefix = "m/44'/0'/" +
                               std::to_string(identity.account_index) + "'/";
    if (modern) {
        if (identity.keys.size() != 3 ||
            !descriptorMatches(
                identity.keys[0], kIdentityScheme, kPasswordProfile,
                Purpose::AssetReviewApproval, Curve::ED25519,
                KeyDerivation::Slip10Ed25519, prefix + "2'/0'",
                "ed25519-over-sha256-jcs-v1") ||
            !descriptorMatches(
                identity.keys[1], kIdentityScheme, kPasswordProfile,
                Purpose::ContactEncryption, Curve::X25519,
                KeyDerivation::Slip10X25519, prefix + "1'/0'", std::nullopt) ||
            !descriptorMatches(
                identity.keys[2], kIdentityScheme, kPasswordProfile,
                Purpose::SdnAuthentication, Curve::ED25519,
                KeyDerivation::Slip10Ed25519, prefix + "0'/0'",
                "ed25519-over-sha256-jcs-v1")) {
            return IdentityError::CryptoFailure;
        }
    } else {
        const std::string_view scheme = legacy_fast
                                            ? kLegacyFastIdentityScheme
                                            : kLegacyMnemonicIdentityScheme;
        const std::string_view profile = legacy_fast
                                             ? kLegacyPasswordProfile
                                             : kLegacyMnemonicSeedProfile;
        if (identity.keys.size() != 1 ||
            !descriptorMatches(
                identity.keys[0], scheme, profile, Purpose::SdnAuthentication,
                Curve::ED25519,
                KeyDerivation::LegacyBip32ScalarAsEd25519Seed,
                prefix + "0/0", "ed25519-raw-32-v1")) {
            return IdentityError::CryptoFailure;
        }
    }

    Value::Array keys;
    keys.reserve(identity.keys.size());
    for (const auto& descriptor : identity.keys) {
        const auto purpose = purposeName(descriptor.purpose);
        const auto curve = curveName(descriptor.curve);
        const auto derivation = derivationName(descriptor.derivation);
        if (!purpose || !curve || !derivation) {
            return IdentityError::CryptoFailure;
        }
        Value::Members members{
            {"bip32Fingerprint", Value(nullptr)},
            {"curve", *curve},
            {"derivation", *derivation},
            {"encoding", std::string("raw")},
            {"identityScheme", descriptor.identity_scheme},
            {"keyId", descriptor.key_id},
            {"path", descriptor.path},
            {"publicKeyHex", hex(descriptor.public_key)},
            {"purpose", *purpose},
            {"seedProfile", descriptor.seed_profile},
            {"signatureProfile", descriptor.signature_profile
                                     ? Value(*descriptor.signature_profile)
                                     : Value(nullptr)},
        };
        keys.emplace_back(std::move(members));
    }
    Value::Members root{
        {"accountFingerprint", hex(identity.account_fingerprint)},
        {"accountIndex", static_cast<double>(identity.account_index)},
        {"accountLabel", Value(nullptr)},
        {"accountPeerId", identity.account_peer_id},
        {"accountXpub", identity.account_xpub},
        {"identityScheme", identity.identity_scheme},
        {"keys", Value(std::move(keys))},
        {"schemaVersion", 1.0},
        {"seedProfile", identity.seed_profile},
    };
    return serializeValue(Value(std::move(root)));
}

StringOutcome serializeRawSignature(const RawSignature& signature) {
    const bool legacy_scheme =
        signature.identity_scheme == kLegacyFastIdentityScheme ||
        signature.identity_scheme == kLegacyMnemonicIdentityScheme;
    if (signature.schema_version != 1 || !legacy_scheme ||
        !validKeyId(signature.key_id) ||
        signature.algorithm != "ed25519" ||
        signature.encoding != KeyEncoding::Raw ||
        signature.signature_profile != "ed25519-raw-32-v1") {
        return IdentityError::CryptoFailure;
    }
    Value::Members value{
        {"algorithm", signature.algorithm},
        {"encoding", std::string("raw")},
        {"identityScheme", signature.identity_scheme},
        {"keyId", signature.key_id},
        {"schemaVersion", 1.0},
        {"signatureHex", hex(signature.signature)},
        {"signatureProfile", signature.signature_profile},
    };
    return serializeValue(Value(std::move(value)));
}

StringOutcome serializeCanonicalSignature(const CanonicalSignature& signature) {
    if (signature.schema_version != 1 ||
        signature.identity_scheme != kIdentityScheme ||
        !validKeyId(signature.key_id) ||
        signature.algorithm != "ed25519" ||
        signature.encoding != KeyEncoding::Raw ||
        signature.signature_profile != "ed25519-over-sha256-jcs-v1" ||
        signature.canonical_envelope.empty()) {
        return IdentityError::CryptoFailure;
    }
    Value::Members value{
        {"algorithm", signature.algorithm},
        {"canonicalEnvelope", signature.canonical_envelope},
        {"encoding", std::string("raw")},
        {"identityScheme", signature.identity_scheme},
        {"keyId", signature.key_id},
        {"schemaVersion", 1.0},
        {"signatureHex", hex(signature.signature)},
        {"signatureProfile", signature.signature_profile},
        {"signedDigestSha256", hex(signature.signed_digest)},
    };
    return serializeValue(Value(std::move(value)));
}

uint16_t copyTextResult(const StringOutcome& outcome, uint8_t* output,
                        uint32_t capacity, uint32_t* out_required) {
    if (std::holds_alternative<IdentityError>(outcome)) {
        return status(std::get<IdentityError>(outcome));
    }
    const std::string& text = std::get<std::string>(outcome);
    if (text.empty() || text.size() > kMaximumOutputBytes ||
        text.size() > std::numeric_limits<uint32_t>::max()) {
        return status(IdentityError::CryptoFailure);
    }
    const uint32_t required = static_cast<uint32_t>(text.size());
    storeScalar(out_required, required);
    if (capacity < required) return status(IdentityError::InvalidRequest);
    std::memcpy(output, text.data(), text.size());
    return 0;
}

uint16_t finishDerived(IdentityOutcome<IdentityHandle>&& outcome,
                       uint64_t* out_handle, uint8_t* output,
                       uint32_t capacity, uint32_t* out_required) {
    if (std::holds_alternative<IdentityError>(outcome)) {
        return status(std::get<IdentityError>(outcome));
    }
    const IdentityHandle handle = std::get<IdentityHandle>(outcome);
    PendingHandle pending(handle);
    auto described = describe_identity(handle);
    if (std::holds_alternative<IdentityError>(described)) {
        return status(std::get<IdentityError>(described));
    }
    const auto serialized = serializeIdentity(std::get<PublicIdentity>(described));
    const uint16_t result = copyTextResult(serialized, output, capacity, out_required);
    if (result != 0) return result;
    storeScalar(out_handle, static_cast<uint64_t>(handle));
    pending.release();
    return 0;
}

const Value* member(const Value& object, std::string_view name) {
    if (object.kind() != Value::Kind::Object) return nullptr;
    for (const auto& entry : object.members()) {
        if (entry.first == name) return &entry.second;
    }
    return nullptr;
}

bool exactMembers(const Value& object,
                  std::initializer_list<std::string_view> expected) {
    if (object.kind() != Value::Kind::Object ||
        object.members().size() != expected.size()) {
        return false;
    }
    return std::all_of(object.members().begin(), object.members().end(),
                       [expected](const auto& entry) {
                           return std::find(expected.begin(), expected.end(),
                                            entry.first) != expected.end();
                       });
}

bool stringMember(const Value& object, std::string_view name,
                  std::string& result) {
    const Value* value = member(object, name);
    if (value == nullptr || value->kind() != Value::Kind::String) return false;
    result = value->string();
    return true;
}

bool numberMember(const Value& object, std::string_view name, double& result) {
    const Value* value = member(object, name);
    if (value == nullptr || value->kind() != Value::Kind::Number) return false;
    result = value->number();
    return std::isfinite(result);
}

bool uint32Member(const Value& object, std::string_view name,
                  uint32_t& result) {
    double value = 0;
    if (!numberMember(object, name, value) || value < 0 ||
        value > std::numeric_limits<uint32_t>::max() ||
        std::floor(value) != value) {
        return false;
    }
    result = static_cast<uint32_t>(value);
    return true;
}

bool uint64Member(const Value& object, std::string_view name,
                  uint64_t& result) {
    double value = 0;
    constexpr double kMaximumSafeInteger = 9007199254740991.0;
    if (!numberMember(object, name, value) || value < 0 ||
        value > kMaximumSafeInteger || std::floor(value) != value) {
        return false;
    }
    result = static_cast<uint64_t>(value);
    return true;
}

bool nullableStringMember(const Value& object, std::string_view name,
                          std::optional<std::string>& result) {
    const Value* value = member(object, name);
    if (value == nullptr) return false;
    if (value->kind() == Value::Kind::Null) {
        result.reset();
        return true;
    }
    if (value->kind() != Value::Kind::String) return false;
    result = value->string();
    return true;
}

std::variant<Value, IdentityError> parseRequest(const uint8_t* bytes,
                                                uint32_t length) {
    jcs::Limits limits;
    limits.max_bytes = kMaximumOutputBytes;
    auto parsed = jcs::parse_json(std::span<const uint8_t>(bytes, length), limits);
    if (std::holds_alternative<jcs::JcsError>(parsed)) {
        return std::get<jcs::JcsError>(parsed) == jcs::JcsError::OutOfMemory
                   ? IdentityError::OutOfMemory
                   : IdentityError::InvalidRequest;
    }
    return std::get<Value>(std::move(parsed));
}

bool decodeBase64Url32(std::string_view encoded,
                       std::array<uint8_t, 32>& output) noexcept {
    static constexpr std::string_view alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    if (encoded.size() != 43 || encoded.find('=') != std::string_view::npos) {
        return false;
    }
    uint32_t buffer = 0;
    unsigned bits = 0;
    size_t output_index = 0;
    for (const char byte : encoded) {
        const size_t position = alphabet.find(byte);
        if (position == std::string_view::npos) return false;
        buffer = (buffer << 6) | static_cast<uint32_t>(position);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (output_index >= output.size()) return false;
            output[output_index++] =
                static_cast<uint8_t>((buffer >> bits) & 0xff);
            buffer = bits == 0 ? 0 : buffer & ((1U << bits) - 1U);
        }
    }
    return output_index == output.size() && bits == 2 && buffer == 0;
}

std::variant<SdnLoginV2Fields, IdentityError> parseLoginV2(
    const uint8_t* bytes, uint32_t length) {
    auto parsed = parseRequest(bytes, length);
    if (std::holds_alternative<IdentityError>(parsed)) {
        return std::get<IdentityError>(parsed);
    }
    const Value& value = std::get<Value>(parsed);
    if (!exactMembers(value, {"audience", "challengeBase64url", "expiresAt",
                              "issuedAt", "nonce", "protocolVersion"})) {
        return IdentityError::InvalidRequest;
    }
    SdnLoginV2Fields result{};
    std::string challenge;
    if (!uint32Member(value, "protocolVersion", result.protocol_version) ||
        !stringMember(value, "audience", result.audience) ||
        !stringMember(value, "challengeBase64url", challenge) ||
        !decodeBase64Url32(challenge, result.challenge) ||
        !stringMember(value, "nonce", result.nonce) ||
        !stringMember(value, "issuedAt", result.issued_at) ||
        !stringMember(value, "expiresAt", result.expires_at)) {
        return IdentityError::InvalidRequest;
    }
    return result;
}

std::variant<AuthorityActivationFields, IdentityError> parseActivation(
    const uint8_t* bytes, uint32_t length) {
    auto parsed = parseRequest(bytes, length);
    if (std::holds_alternative<IdentityError>(parsed)) {
        return std::get<IdentityError>(parsed);
    }
    const Value& value = std::get<Value>(parsed);
    if (!exactMembers(value, {
            "protocolVersion", "audience", "requestOrigin", "clientId",
            "serviceInstance", "purpose", "nonce", "issuedAt", "expiresAt",
            "publicKeyHex", "keyId", "identityScheme", "signatureProfile"})) {
        return IdentityError::InvalidRequest;
    }
    AuthorityActivationFields result{};
    if (!uint32Member(value, "protocolVersion", result.protocol_version) ||
        !stringMember(value, "audience", result.audience) ||
        !stringMember(value, "requestOrigin", result.request_origin) ||
        !stringMember(value, "clientId", result.client_id) ||
        !stringMember(value, "serviceInstance", result.service_instance) ||
        !stringMember(value, "purpose", result.purpose) ||
        !stringMember(value, "nonce", result.nonce) ||
        !stringMember(value, "issuedAt", result.issued_at) ||
        !stringMember(value, "expiresAt", result.expires_at) ||
        !stringMember(value, "publicKeyHex", result.public_key_hex) ||
        !stringMember(value, "keyId", result.key_id) ||
        !stringMember(value, "identityScheme", result.identity_scheme) ||
        !stringMember(value, "signatureProfile", result.signature_profile)) {
        return IdentityError::InvalidRequest;
    }
    return result;
}

template <size_t Size>
bool numberArray(const Value& object, std::string_view name,
                 std::array<double, Size>& output) {
    const Value* value = member(object, name);
    if (value == nullptr || value->kind() != Value::Kind::Array ||
        value->array().size() != Size) {
        return false;
    }
    for (size_t index = 0; index < Size; ++index) {
        const Value& element = value->array()[index];
        if (element.kind() != Value::Kind::Number ||
            !std::isfinite(element.number())) {
            return false;
        }
        output[index] = element.number();
    }
    return true;
}

bool parseTransform(const Value& value, ReviewedTransform& result) {
    return exactMembers(value, {"translation", "rotation", "scale", "upAxis",
                                "sourceUnits", "metersPerSourceUnit"}) &&
           numberArray(value, "translation", result.translation) &&
           numberArray(value, "rotation", result.rotation) &&
           numberArray(value, "scale", result.scale) &&
           stringMember(value, "upAxis", result.up_axis) &&
           stringMember(value, "sourceUnits", result.source_units) &&
           numberMember(value, "metersPerSourceUnit",
                        result.meters_per_source_unit);
}

std::variant<AssetReviewDecisionFields, IdentityError> parseDecision(
    const uint8_t* bytes, uint32_t length) {
    auto parsed = parseRequest(bytes, length);
    if (std::holds_alternative<IdentityError>(parsed)) {
        return std::get<IdentityError>(parsed);
    }
    const Value& value = std::get<Value>(parsed);
    std::string decision;
    if (!stringMember(value, "decision", decision)) {
        return IdentityError::InvalidRequest;
    }
    const bool approve = decision == "approve";
    const bool disapprove = decision == "disapprove";
    if ((!approve && !disapprove) ||
        (approve && !exactMembers(value, {
            "protocolVersion", "audience", "requestOrigin", "clientId",
            "challengeId", "nonce", "issuedAt", "expiresAt", "candidateKey",
            "modelCid", "modelSha256", "modelBytes", "metadataSha256",
            "previousDecisionHead", "decision", "reviewedTransform", "note"})) ||
        (disapprove && !exactMembers(value, {
            "protocolVersion", "audience", "requestOrigin", "clientId",
            "challengeId", "nonce", "issuedAt", "expiresAt", "candidateKey",
            "modelCid", "modelSha256", "modelBytes", "metadataSha256",
            "previousDecisionHead", "decision", "reason"}))) {
        return IdentityError::InvalidRequest;
    }
    AssetReviewDecisionFields result{};
    result.decision = approve ? ReviewDecision::Approve
                              : ReviewDecision::Disapprove;
    if (!uint32Member(value, "protocolVersion", result.protocol_version) ||
        !stringMember(value, "audience", result.audience) ||
        !stringMember(value, "requestOrigin", result.request_origin) ||
        !stringMember(value, "clientId", result.client_id) ||
        !stringMember(value, "challengeId", result.challenge_id) ||
        !stringMember(value, "nonce", result.nonce) ||
        !stringMember(value, "issuedAt", result.issued_at) ||
        !stringMember(value, "expiresAt", result.expires_at) ||
        !stringMember(value, "candidateKey", result.candidate_key) ||
        !stringMember(value, "modelCid", result.model_cid) ||
        !stringMember(value, "modelSha256", result.model_sha256) ||
        !uint64Member(value, "modelBytes", result.model_bytes) ||
        !stringMember(value, "metadataSha256", result.metadata_sha256) ||
        !nullableStringMember(value, "previousDecisionHead",
                              result.previous_decision_head)) {
        return IdentityError::InvalidRequest;
    }
    if (approve) {
        const Value* transform = member(value, "reviewedTransform");
        ReviewedTransform parsed_transform{};
        if (transform == nullptr || !parseTransform(*transform, parsed_transform) ||
            !nullableStringMember(value, "note", result.note)) {
            return IdentityError::InvalidRequest;
        }
        result.reviewed_transform = std::move(parsed_transform);
    } else if (!stringMember(value, "reason", result.reason.emplace())) {
        return IdentityError::InvalidRequest;
    }
    return result;
}

uint16_t finishRawSignature(IdentityOutcome<RawSignature>&& outcome,
                            uint8_t* output, uint32_t capacity,
                            uint32_t* out_required) {
    if (std::holds_alternative<IdentityError>(outcome)) {
        return status(std::get<IdentityError>(outcome));
    }
    return copyTextResult(serializeRawSignature(std::get<RawSignature>(outcome)),
                          output, capacity, out_required);
}

uint16_t finishCanonicalSignature(
    IdentityOutcome<CanonicalSignature>&& outcome, uint8_t* output,
    uint32_t capacity, uint32_t* out_required) {
    if (std::holds_alternative<IdentityError>(outcome)) {
        return status(std::get<IdentityError>(outcome));
    }
    return copyTextResult(
        serializeCanonicalSignature(std::get<CanonicalSignature>(outcome)),
        output, capacity, out_required);
}

} // namespace

extern "C" HD_WALLET_EXPORT
uint16_t hd_sdn_derive_password_identity(
    const uint8_t* username, uint32_t username_len,
    uint8_t* password, uint32_t password_len, uint32_t account_index,
    uint64_t* out_handle, uint8_t* out_json, uint32_t out_capacity,
    uint32_t* out_required) {
    return guarded([&] {
        const bool output_ready = prepareDerivedOutput(
            out_handle, out_json, out_capacity, out_required);
        if (!validRange(password, password_len)) {
            return status(IdentityError::InvalidRequest);
        }
        WipeOnExit wipe_password(password, password_len);
        if (!output_ready ||
            !validRange(username, username_len)) {
            return status(IdentityError::InvalidRequest);
        }
        if (username_len > kMaximumModernCredentialBytes) {
            return status(IdentityError::InvalidUsername);
        }
        if (password_len > kMaximumModernCredentialBytes) {
            return status(IdentityError::InvalidPassword);
        }
        return finishDerived(
            derive_password_identity(
                std::span<const uint8_t>(username, username_len),
                std::span<const uint8_t>(password, password_len), account_index),
            out_handle, out_json, out_capacity, out_required);
    });
}

extern "C" HD_WALLET_EXPORT
uint16_t hd_sdn_derive_legacy_password_identity(
    const uint8_t* username, uint32_t username_len,
    uint8_t* password, uint32_t password_len, uint32_t account_index,
    uint64_t* out_handle, uint8_t* out_json, uint32_t out_capacity,
    uint32_t* out_required) {
    return guarded([&] {
        const bool output_ready = prepareDerivedOutput(
            out_handle, out_json, out_capacity, out_required);
        if (!validRange(password, password_len)) {
            return status(IdentityError::InvalidRequest);
        }
        WipeOnExit wipe_password(password, password_len);
        if (!output_ready ||
            !validRange(username, username_len)) {
            return status(IdentityError::InvalidRequest);
        }
        if (username_len > kMaximumLegacyCredentialBytes) {
            return status(IdentityError::InvalidUsername);
        }
        if (password_len > kMaximumLegacyCredentialBytes) {
            return status(IdentityError::InvalidPassword);
        }
        return finishDerived(
            derive_legacy_password_identity(
                std::span<const uint8_t>(username, username_len),
                std::span<const uint8_t>(password, password_len), account_index),
            out_handle, out_json, out_capacity, out_required);
    });
}

extern "C" HD_WALLET_EXPORT
uint16_t hd_sdn_import_legacy_mnemonic_identity(
    uint8_t* mnemonic, uint32_t mnemonic_len, uint32_t account_index,
    uint64_t* out_handle, uint8_t* out_json, uint32_t out_capacity,
    uint32_t* out_required) {
    return guarded([&] {
        const bool output_ready = prepareDerivedOutput(
            out_handle, out_json, out_capacity, out_required);
        if (!validRange(mnemonic, mnemonic_len)) {
            return status(IdentityError::InvalidRequest);
        }
        WipeOnExit wipe_mnemonic(mnemonic, mnemonic_len);
        if (!output_ready ||
            mnemonic_len > kMaximumMnemonicBytes) {
            return status(IdentityError::InvalidRequest);
        }
        return finishDerived(
            import_legacy_mnemonic_identity(
                std::span<const uint8_t>(mnemonic, mnemonic_len), account_index),
            out_handle, out_json, out_capacity, out_required);
    });
}

extern "C" HD_WALLET_EXPORT
uint16_t hd_sdn_import_remembered_identity(
    const uint8_t* ciphertext, uint32_t ciphertext_len,
    uint8_t* prf_output, uint32_t prf_output_len,
    const uint8_t* hkdf_salt, uint32_t hkdf_salt_len,
    const uint8_t* nonce, uint32_t nonce_len,
    const uint8_t* username, uint32_t username_len,
    const uint8_t* aad, uint32_t aad_len,
    uint64_t* out_handle, uint8_t* out_json, uint32_t out_capacity,
    uint32_t* out_required) {
    return guarded([&] {
        const bool output_ready = prepareDerivedOutput(
            out_handle, out_json, out_capacity, out_required);
        if (!validRange(prf_output, prf_output_len)) {
            return status(IdentityError::InvalidRequest);
        }
        WipeOnExit wipe_prf(prf_output, prf_output_len);
        if (!output_ready ||
            !validRange(ciphertext, ciphertext_len) ||
            !validRange(hkdf_salt, hkdf_salt_len) ||
            !validRange(nonce, nonce_len) || !validRange(username, username_len) ||
            !validRange(aad, aad_len) || prf_output_len != 32 ||
            hkdf_salt_len != 32 || nonce_len != 12 ||
            ciphertext_len < kMinimumRememberedCiphertextBytes ||
            ciphertext_len > kMaximumRememberedCiphertextBytes ||
            username_len > kMaximumModernCredentialBytes ||
            aad_len > kMaximumAadBytes) {
            return status(IdentityError::InvalidRequest);
        }
        auto opened = remember_wallet_open(
            std::span<const uint8_t>(ciphertext, ciphertext_len),
            std::span<const uint8_t, 32>(prf_output, 32),
            std::span<const uint8_t, 32>(hkdf_salt, 32),
            std::span<const uint8_t, 12>(nonce, 12),
            std::span<const uint8_t>(username, username_len),
            std::span<const uint8_t>(aad, aad_len));
        if (std::holds_alternative<IdentityError>(opened)) {
            return status(std::get<IdentityError>(opened));
        }
        ImportedIdentity imported = std::get<ImportedIdentity>(std::move(opened));
        PendingHandle pending(imported.handle);
        const auto serialized = serializeIdentity(imported.identity);
        const uint16_t result =
            copyTextResult(serialized, out_json, out_capacity, out_required);
        if (result != 0) return result;
        storeScalar(out_handle, static_cast<uint64_t>(imported.handle));
        pending.release();
        return uint16_t{0};
    });
}

extern "C" HD_WALLET_EXPORT
uint16_t hd_sdn_sign_login_v1(
    uint64_t handle, const uint8_t* challenge, uint32_t challenge_len,
    uint8_t* out_json, uint32_t out_capacity, uint32_t* out_required) {
    return guarded([&] {
        if (!prepareOutput(out_json, out_capacity, out_required) ||
            !validRange(challenge, challenge_len) || challenge_len != 32) {
            return status(IdentityError::InvalidRequest);
        }
        return finishRawSignature(
            sign_sdn_login_v1(
                handle, std::span<const uint8_t, 32>(challenge, 32)),
            out_json, out_capacity, out_required);
    });
}

extern "C" HD_WALLET_EXPORT
uint16_t hd_sdn_sign_login_v2(
    uint64_t handle, const uint8_t* request_json, uint32_t request_len,
    uint8_t registry_row, uint8_t* out_json, uint32_t out_capacity,
    uint32_t* out_required) {
    return guarded([&] {
        if (!prepareOutput(out_json, out_capacity, out_required) ||
            !validRange(request_json, request_len) ||
            request_len > kMaximumOutputBytes) {
            return status(IdentityError::InvalidRequest);
        }
        if (registry_row !=
            static_cast<uint8_t>(RegistryRowId::SdnNodeConsoleV2)) {
            return status(IdentityError::OperationNotAllowed);
        }
        auto parsed = parseLoginV2(request_json, request_len);
        if (std::holds_alternative<IdentityError>(parsed)) {
            return status(std::get<IdentityError>(parsed));
        }
        return finishCanonicalSignature(
            sign_sdn_login_v2(
                handle, std::get<SdnLoginV2Fields>(parsed),
                RegistryRowId::SdnNodeConsoleV2),
            out_json, out_capacity, out_required);
    });
}

extern "C" HD_WALLET_EXPORT
uint16_t hd_sdn_sign_asset_review_authority_activation(
    uint64_t handle, const uint8_t* request_json, uint32_t request_len,
    uint8_t registry_row, uint8_t* out_json, uint32_t out_capacity,
    uint32_t* out_required) {
    return guarded([&] {
        if (!prepareOutput(out_json, out_capacity, out_required) ||
            !validRange(request_json, request_len) ||
            request_len > kMaximumOutputBytes) {
            return status(IdentityError::InvalidRequest);
        }
        if (registry_row != static_cast<uint8_t>(
                                RegistryRowId::AssetReviewAuthorityActivation)) {
            return status(IdentityError::OperationNotAllowed);
        }
        auto parsed = parseActivation(request_json, request_len);
        if (std::holds_alternative<IdentityError>(parsed)) {
            return status(std::get<IdentityError>(parsed));
        }
        return finishCanonicalSignature(
            sign_asset_review_authority_activation(
                handle, std::get<AuthorityActivationFields>(parsed),
                RegistryRowId::AssetReviewAuthorityActivation),
            out_json, out_capacity, out_required);
    });
}

extern "C" HD_WALLET_EXPORT
uint16_t hd_sdn_sign_asset_review_decision(
    uint64_t handle, const uint8_t* request_json, uint32_t request_len,
    uint8_t registry_row, uint8_t* out_json, uint32_t out_capacity,
    uint32_t* out_required) {
    return guarded([&] {
        if (!prepareOutput(out_json, out_capacity, out_required) ||
            !validRange(request_json, request_len) ||
            request_len > kMaximumOutputBytes) {
            return status(IdentityError::InvalidRequest);
        }
        if (registry_row !=
            static_cast<uint8_t>(RegistryRowId::AssetReviewDecision)) {
            return status(IdentityError::OperationNotAllowed);
        }
        auto parsed = parseDecision(request_json, request_len);
        if (std::holds_alternative<IdentityError>(parsed)) {
            return status(std::get<IdentityError>(parsed));
        }
        return finishCanonicalSignature(
            sign_asset_review_decision(
                handle, std::get<AssetReviewDecisionFields>(parsed),
                RegistryRowId::AssetReviewDecision),
            out_json, out_capacity, out_required);
    });
}

extern "C" HD_WALLET_EXPORT
uint16_t hd_sdn_seal_remembered_identity(
    uint64_t handle, uint8_t* password, uint32_t password_len,
    uint8_t* prf_output, uint32_t prf_output_len,
    const uint8_t* hkdf_salt, uint32_t hkdf_salt_len,
    const uint8_t* nonce, uint32_t nonce_len,
    const uint8_t* aad, uint32_t aad_len,
    uint8_t* out_bytes, uint32_t out_capacity, uint32_t* out_required) {
    return guarded([&] {
        const bool output_ready =
            prepareOutput(out_bytes, out_capacity, out_required);
        const bool password_valid = validRange(password, password_len);
        const bool prf_valid = validRange(prf_output, prf_output_len);
        if (!password_valid) {
            if (prf_valid) secureWipe(prf_output, prf_output_len);
            return status(IdentityError::InvalidRequest);
        }
        WipeOnExit wipe_password(password, password_len);
        if (!prf_valid) return status(IdentityError::InvalidRequest);
        WipeOnExit wipe_prf(prf_output, prf_output_len);
        if (!output_ready ||
            !validRange(hkdf_salt, hkdf_salt_len) ||
            !validRange(nonce, nonce_len) || !validRange(aad, aad_len) ||
            password_len > kMaximumModernCredentialBytes || prf_output_len != 32 ||
            hkdf_salt_len != 32 || nonce_len != 12 ||
            aad_len > kMaximumAadBytes) {
            return status(IdentityError::InvalidRequest);
        }
        auto sealed = remember_wallet_seal(
            handle, std::span<const uint8_t>(password, password_len),
            std::span<const uint8_t, 32>(prf_output, 32),
            std::span<const uint8_t, 32>(hkdf_salt, 32),
            std::span<const uint8_t, 12>(nonce, 12),
            std::span<const uint8_t>(aad, aad_len));
        if (std::holds_alternative<IdentityError>(sealed)) {
            return status(std::get<IdentityError>(sealed));
        }
        const std::vector<uint8_t>& bytes = std::get<std::vector<uint8_t>>(sealed);
        if (bytes.size() <= 16 ||
            bytes.size() > kMaximumRememberedCiphertextBytes) {
            return status(IdentityError::CryptoFailure);
        }
        const uint32_t required = static_cast<uint32_t>(bytes.size());
        storeScalar(out_required, required);
        if (out_capacity < required) {
            return status(IdentityError::InvalidRequest);
        }
        std::memcpy(out_bytes, bytes.data(), bytes.size());
        return uint16_t{0};
    });
}

extern "C" HD_WALLET_EXPORT
void hd_sdn_destroy_identity(uint64_t handle) noexcept {
    try {
        destroy_identity(handle);
    } catch (...) {
    }
}

} // namespace hd_wallet::sdn::wasm_adapter

#endif
