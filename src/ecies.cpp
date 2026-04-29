/**
 * @file ecies.cpp
 * @brief ECIES Implementation
 *
 * Unified ECIES: ECDH + HKDF-SHA256 + AES-256-GCM
 * Routes HKDF and AES-GCM through OpenSSL when HD_WALLET_USE_OPENSSL is active.
 *
 * All crypto operations use C++ APIs directly (not C API wrappers) so this
 * compiles in both native and WASM builds.
 */

#include "hd_wallet/ecies.h"
#include "hd_wallet/config.h"
#include "hd_wallet/types.h"
#include "hd_wallet/error.h"
#include "hd_wallet/ecdh.h"
#include "hd_wallet/secure_rng.h"

#if HD_WALLET_USE_OPENSSL
#include "hd_wallet/crypto_openssl.h"
#endif

#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/hmac.h>
#include <cryptopp/modes.h>

#include <cstring>

// Forward declarations from ecdh.cpp (internal C++ functions)
namespace hd_wallet { namespace ecdh {
    bool ecdh(Curve curve, const uint8_t* privateKey, size_t privateKeyLen,
              const uint8_t* publicKey, size_t publicKeyLen,
              uint8_t* sharedSecret, size_t* sharedSecretLen);
    bool x25519(const uint8_t* privateKey, size_t privateKeyLen,
                const uint8_t* publicKey, size_t publicKeyLen,
                uint8_t* sharedSecret, size_t* sharedSecretLen);
    bool x25519PublicKey(const uint8_t* privateKey, size_t privateKeyLen,
                         uint8_t* publicKey, size_t* publicKeyLen);
    bool hkdf(const uint8_t* salt, size_t saltLen,
              const uint8_t* ikm, size_t ikmLen,
              const uint8_t* info, size_t infoLen,
              uint8_t* okm, size_t okmLen);
}}

namespace hd_wallet {
namespace ecies {

// =============================================================================
// Internal Helpers
// =============================================================================

namespace {

size_t privateKeySize(Curve curve) {
    switch (curve) {
        case Curve::SECP256K1: return 32;
        case Curve::P256:      return 32;
        case Curve::P384:      return 48;
        case Curve::X25519:    return 32;
        default:               return 0;
    }
}

size_t sharedSecretSize(Curve curve) {
    switch (curve) {
        case Curve::SECP256K1: return 32;
        case Curve::P256:      return 32;
        case Curve::P384:      return 48;
        case Curve::X25519:    return 32;
        default:               return 0;
    }
}

const char* curveInfo(Curve curve) {
    switch (curve) {
        case Curve::SECP256K1: return "ecies-secp256k1";
        case Curve::P256:      return "ecies-p256";
        case Curve::P384:      return "ecies-p384";
        case Curve::X25519:    return "ecies-x25519";
        default:               return "ecies";
    }
}

void secureWipe(uint8_t* buf, size_t len) {
    volatile uint8_t* p = buf;
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }
}

/**
 * Generate ephemeral key pair using the C++ ecdh::generateEphemeralKeyPair()
 */
bool generateEphemeral(
    Curve curve,
    uint8_t* privOut, size_t privSize,
    uint8_t* pubOut, size_t* pubSize
) {
    auto result = ecdh::generateEphemeralKeyPair(curve);
    if (!result.ok()) return false;

    auto& kp = result.value;
    size_t privLen = kp.privateKey.size();
    size_t pubLen = kp.publicKey.size();

    if (privSize < privLen || *pubSize < pubLen) return false;

    std::memcpy(privOut, kp.privateKey.data(), privLen);
    std::memcpy(pubOut, kp.publicKey.data(), pubLen);
    *pubSize = pubLen;

    // Wipe the KeyPair's private key
    secureWipe(kp.privateKey.data(), privLen);

    return true;
}

bool computeSharedSecret(
    Curve curve,
    const uint8_t* privKey, size_t privKeyLen,
    const uint8_t* pubKey, size_t pubKeyLen,
    uint8_t* secret, size_t* secretLen
) {
    if (curve == Curve::X25519) {
        return ecdh::x25519(privKey, privKeyLen, pubKey, pubKeyLen, secret, secretLen);
    } else {
        return ecdh::ecdh(curve, privKey, privKeyLen, pubKey, pubKeyLen, secret, secretLen);
    }
}

/**
 * Derive AES key from shared secret via HKDF-SHA256
 * Routes through OpenSSL FIPS when available
 */
bool deriveAesKey(
    Curve curve,
    const uint8_t* sharedSecret, size_t secretLen,
    uint8_t* aesKey
) {
    const char* salt = ECIES_HKDF_SALT;
    size_t saltLen = std::strlen(salt);
    const char* info = curveInfo(curve);
    size_t infoLen = std::strlen(info);

#if HD_WALLET_USE_OPENSSL
    int32_t result = hd_ossl_hkdf_sha256(
        sharedSecret, secretLen,
        reinterpret_cast<const uint8_t*>(salt), saltLen,
        reinterpret_cast<const uint8_t*>(info), infoLen,
        aesKey, ECIES_KEY_SIZE);
    return result >= 0;
#else
    return ecdh::hkdf(
        reinterpret_cast<const uint8_t*>(salt), saltLen,
        sharedSecret, secretLen,
        reinterpret_cast<const uint8_t*>(info), infoLen,
        aesKey, ECIES_KEY_SIZE);
#endif
}

/**
 * AES-256-GCM Encrypt (self-contained, routes through OpenSSL when available)
 */
int32_t aesGcmEncrypt(
    const uint8_t* key, size_t keyLen,
    const uint8_t* plaintext, size_t ptLen,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* aad, size_t aadLen,
    uint8_t* ciphertext, uint8_t* tag
) {
    if (keyLen != 32 || ivLen != 12) return -static_cast<int32_t>(Error::INVALID_ARGUMENT);

#if HD_WALLET_USE_OPENSSL
    return hd_ossl_aes_gcm_encrypt(key, keyLen, plaintext, ptLen,
                                   iv, ivLen, aad, aadLen, ciphertext, tag);
#else
    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, keyLen, iv, ivLen);
    enc.SpecifyDataLengths(aadLen, ptLen, 0);
    if (aad && aadLen > 0) {
        enc.Update(aad, aadLen);
    }
    if (plaintext && ptLen > 0) {
        enc.ProcessData(ciphertext, plaintext, ptLen);
    }
    enc.TruncatedFinal(tag, 16);
    return static_cast<int32_t>(ptLen);
#endif
}

/**
 * AES-256-GCM Decrypt (self-contained, routes through OpenSSL when available)
 */
int32_t aesGcmDecrypt(
    const uint8_t* key, size_t keyLen,
    const uint8_t* ciphertext, size_t ctLen,
    const uint8_t* iv, size_t ivLen,
    const uint8_t* aad, size_t aadLen,
    const uint8_t* tag, uint8_t* plaintext
) {
    if (keyLen != 32 || ivLen != 12) return -static_cast<int32_t>(Error::INVALID_ARGUMENT);

#if HD_WALLET_USE_OPENSSL
    return hd_ossl_aes_gcm_decrypt(key, keyLen, ciphertext, ctLen,
                                   iv, ivLen, aad, aadLen, tag, plaintext);
#else
    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, keyLen, iv, ivLen);
    dec.SpecifyDataLengths(aadLen, ctLen, 0);
    if (aad && aadLen > 0) {
        dec.Update(aad, aadLen);
    }
    if (ciphertext && ctLen > 0) {
        dec.ProcessData(plaintext, ciphertext, ctLen);
    }
    if (!dec.TruncatedVerify(tag, 16)) {
        std::memset(plaintext, 0, ctLen);
        return -static_cast<int32_t>(Error::VERIFICATION_FAILED);
    }
    return static_cast<int32_t>(ctLen);
#endif
}

} // anonymous namespace

// =============================================================================
// Public API
// =============================================================================

size_t eciesEphemeralKeySize(Curve curve) {
    switch (curve) {
        case Curve::SECP256K1: return 33;
        case Curve::P256:      return 33;
        case Curve::P384:      return 49;
        case Curve::X25519:    return 32;
        default:               return 0;
    }
}

size_t eciesOverhead(Curve curve) {
    size_t keySize = eciesEphemeralKeySize(curve);
    if (keySize == 0) return 0;
    return keySize + ECIES_IV_SIZE + ECIES_TAG_SIZE;
}

int32_t eciesEncrypt(
    Curve curve,
    const uint8_t* recipientPubKey,
    size_t recipientPubKeyLen,
    const uint8_t* plaintext,
    size_t plaintextLen,
    const uint8_t* aad,
    size_t aadLen,
    uint8_t* out,
    size_t outSize
) {
    if (!recipientPubKey || !out) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

#if HD_WALLET_FIPS_MODE
    if (curve != Curve::P256 && curve != Curve::P384) {
        return -static_cast<int32_t>(Error::FIPS_NOT_ALLOWED);
    }
#endif

    size_t overhead = eciesOverhead(curve);
    if (overhead == 0) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    size_t totalSize = plaintextLen + overhead;
    if (outSize < totalSize) {
        return -static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    size_t ephKeySize = eciesEphemeralKeySize(curve);
    size_t privKeyLen = privateKeySize(curve);
    size_t ssLen = sharedSecretSize(curve);

    // Generate ephemeral key pair
    uint8_t ephPriv[48] = {0};
    size_t ephPubSize = ephKeySize;
    uint8_t* ephPubOut = out;  // Write directly to output

    if (!generateEphemeral(curve, ephPriv, sizeof(ephPriv), ephPubOut, &ephPubSize)) {
        secureWipe(ephPriv, sizeof(ephPriv));
        return -static_cast<int32_t>(Error::INTERNAL);
    }

    // ECDH shared secret
    uint8_t sharedSecret[48] = {0};
    size_t actualSSLen = ssLen;
    if (!computeSharedSecret(curve, ephPriv, privKeyLen,
                             recipientPubKey, recipientPubKeyLen,
                             sharedSecret, &actualSSLen)) {
        secureWipe(ephPriv, sizeof(ephPriv));
        secureWipe(sharedSecret, sizeof(sharedSecret));
        return -static_cast<int32_t>(Error::INTERNAL);
    }

    secureWipe(ephPriv, sizeof(ephPriv));

    // HKDF → AES key
    uint8_t aesKey[ECIES_KEY_SIZE] = {0};
    if (!deriveAesKey(curve, sharedSecret, actualSSLen, aesKey)) {
        secureWipe(sharedSecret, sizeof(sharedSecret));
        secureWipe(aesKey, sizeof(aesKey));
        return -static_cast<int32_t>(Error::INTERNAL);
    }

    secureWipe(sharedSecret, sizeof(sharedSecret));

    // Random IV
    uint8_t* ivOut = out + ephKeySize;
    try {
        SecureRandomGenerator rng;
        rng.GenerateBlock(ivOut, ECIES_IV_SIZE);
    } catch (...) {
        secureWipe(aesKey, sizeof(aesKey));
        return -static_cast<int32_t>(Error::NO_ENTROPY);
    }

    // AES-256-GCM Encrypt
    uint8_t* ctOut = out + ephKeySize + ECIES_IV_SIZE;
    uint8_t* tagOut = out + ephKeySize + ECIES_IV_SIZE + plaintextLen;

    int32_t encResult = aesGcmEncrypt(
        aesKey, ECIES_KEY_SIZE,
        plaintext, plaintextLen,
        ivOut, ECIES_IV_SIZE,
        aad, aadLen,
        ctOut, tagOut);

    secureWipe(aesKey, sizeof(aesKey));

    if (encResult < 0) {
        return encResult;
    }

    return static_cast<int32_t>(totalSize);
}

int32_t eciesDecrypt(
    Curve curve,
    const uint8_t* recipientPrivKey,
    size_t recipientPrivKeyLen,
    const uint8_t* message,
    size_t messageLen,
    const uint8_t* aad,
    size_t aadLen,
    uint8_t* out,
    size_t outSize
) {
    if (!recipientPrivKey || !message || !out) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

#if HD_WALLET_FIPS_MODE
    if (curve != Curve::P256 && curve != Curve::P384) {
        return -static_cast<int32_t>(Error::FIPS_NOT_ALLOWED);
    }
#endif

    size_t overhead = eciesOverhead(curve);
    if (overhead == 0 || messageLen < overhead) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }

    size_t ephKeySize = eciesEphemeralKeySize(curve);
    size_t plaintextLen = messageLen - overhead;

    if (plaintextLen > 0 && outSize < plaintextLen) {
        return -static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }

    // Parse wire format
    const uint8_t* ephPubKey = message;
    const uint8_t* iv = message + ephKeySize;
    const uint8_t* ciphertext = message + ephKeySize + ECIES_IV_SIZE;
    const uint8_t* tag = message + ephKeySize + ECIES_IV_SIZE + plaintextLen;

    // ECDH shared secret
    size_t ssLen = sharedSecretSize(curve);
    uint8_t sharedSecret[48] = {0};
    size_t actualSSLen = ssLen;
    if (!computeSharedSecret(curve, recipientPrivKey, recipientPrivKeyLen,
                             ephPubKey, ephKeySize,
                             sharedSecret, &actualSSLen)) {
        secureWipe(sharedSecret, sizeof(sharedSecret));
        return -static_cast<int32_t>(Error::INTERNAL);
    }

    // HKDF → AES key
    uint8_t aesKey[ECIES_KEY_SIZE] = {0};
    if (!deriveAesKey(curve, sharedSecret, actualSSLen, aesKey)) {
        secureWipe(sharedSecret, sizeof(sharedSecret));
        secureWipe(aesKey, sizeof(aesKey));
        return -static_cast<int32_t>(Error::INTERNAL);
    }

    secureWipe(sharedSecret, sizeof(sharedSecret));

    // AES-256-GCM Decrypt
    int32_t decResult = aesGcmDecrypt(
        aesKey, ECIES_KEY_SIZE,
        ciphertext, plaintextLen,
        iv, ECIES_IV_SIZE,
        aad, aadLen,
        tag, out);

    secureWipe(aesKey, sizeof(aesKey));

    if (decResult < 0) {
        return decResult;
    }

    return static_cast<int32_t>(plaintextLen);
}

// =============================================================================
// AES-CTR
// =============================================================================

int32_t aesCtrEncrypt(
    const uint8_t* key, size_t keyLen,
    const uint8_t* plaintext, size_t plaintextLen,
    const uint8_t* iv, size_t ivLen,
    uint8_t* out, size_t outSize
) {
    if (!key || !iv || ivLen != AES_CTR_IV_SIZE) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    if (plaintextLen > 0 && (!plaintext || !out)) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    if (outSize < plaintextLen) {
        return -static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }
    if (plaintextLen == 0) return 0;

#if HD_WALLET_USE_OPENSSL
    return hd_ossl_aes_ctr_encrypt(key, keyLen, plaintext, plaintextLen,
                                   iv, ivLen, out);
#else
    CryptoPP::CTR_Mode<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key, keyLen, iv, ivLen);
    enc.ProcessData(out, plaintext, plaintextLen);
    return static_cast<int32_t>(plaintextLen);
#endif
}

int32_t aesCtrDecrypt(
    const uint8_t* key, size_t keyLen,
    const uint8_t* ciphertext, size_t ciphertextLen,
    const uint8_t* iv, size_t ivLen,
    uint8_t* out, size_t outSize
) {
    if (!key || !iv || ivLen != AES_CTR_IV_SIZE) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    if (keyLen != 16 && keyLen != 24 && keyLen != 32) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    if (ciphertextLen > 0 && (!ciphertext || !out)) {
        return -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    }
    if (outSize < ciphertextLen) {
        return -static_cast<int32_t>(Error::OUT_OF_MEMORY);
    }
    if (ciphertextLen == 0) return 0;

#if HD_WALLET_USE_OPENSSL
    return hd_ossl_aes_ctr_decrypt(key, keyLen, ciphertext, ciphertextLen,
                                   iv, ivLen, out);
#else
    CryptoPP::CTR_Mode<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key, keyLen, iv, ivLen);
    dec.ProcessData(out, ciphertext, ciphertextLen);
    return static_cast<int32_t>(ciphertextLen);
#endif
}

} // namespace ecies
} // namespace hd_wallet

// =============================================================================
// C API
// =============================================================================

extern "C" {

HD_WALLET_EXPORT
int32_t hd_ecies_encrypt(
    int32_t curve,
    const uint8_t* recipient_pubkey,
    size_t pubkey_len,
    const uint8_t* plaintext,
    size_t plaintext_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* out,
    size_t out_size
) {
    return hd_wallet::ecies::eciesEncrypt(
        static_cast<hd_wallet::Curve>(curve),
        recipient_pubkey, pubkey_len,
        plaintext, plaintext_len,
        aad, aad_len,
        out, out_size);
}

HD_WALLET_EXPORT
int32_t hd_ecies_decrypt(
    int32_t curve,
    const uint8_t* recipient_privkey,
    size_t privkey_len,
    const uint8_t* message,
    size_t message_len,
    const uint8_t* aad,
    size_t aad_len,
    uint8_t* out,
    size_t out_size
) {
    return hd_wallet::ecies::eciesDecrypt(
        static_cast<hd_wallet::Curve>(curve),
        recipient_privkey, privkey_len,
        message, message_len,
        aad, aad_len,
        out, out_size);
}

HD_WALLET_EXPORT
int32_t hd_ecies_overhead(int32_t curve) {
    size_t overhead = hd_wallet::ecies::eciesOverhead(
        static_cast<hd_wallet::Curve>(curve));
    return (overhead > 0) ? static_cast<int32_t>(overhead) : -1;
}

HD_WALLET_EXPORT
int32_t hd_aes_ctr_encrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* plaintext, size_t plaintext_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* out, size_t out_size
) {
    return hd_wallet::ecies::aesCtrEncrypt(
        key, key_len, plaintext, plaintext_len,
        iv, iv_len, out, out_size);
}

HD_WALLET_EXPORT
int32_t hd_aes_ctr_decrypt(
    const uint8_t* key, size_t key_len,
    const uint8_t* ciphertext, size_t ciphertext_len,
    const uint8_t* iv, size_t iv_len,
    uint8_t* out, size_t out_size
) {
    return hd_wallet::ecies::aesCtrDecrypt(
        key, key_len, ciphertext, ciphertext_len,
        iv, iv_len, out, out_size);
}

} // extern "C"
