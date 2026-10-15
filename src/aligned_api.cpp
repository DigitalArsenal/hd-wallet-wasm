/**
 * @file aligned_api.cpp
 * @brief Implementation of Aligned Binary Format API
 *
 * Provides efficient batch operations using aligned, fixed-size structs
 * for zero-copy WASM interop.
 */

#include "hd_wallet/aligned_api.h"
#include "hd_wallet/bip32.h"
#include "hd_wallet/ecdsa.h"
#include "hd_wallet/eddsa.h"
#include "hd_wallet/secure_memory.h"

#include <algorithm>
#include <cstring>
#include <memory>
#include <vector>

// Use type aliases to avoid namespace conflicts
namespace aligned = HdWallet::Aligned;

namespace hd_wallet {
namespace aligned_impl {

// =============================================================================
// Helper Functions
// =============================================================================

namespace {

/**
 * Convert between library Curve enum and aligned Curve enum
 */
hd_wallet::Curve fromAlignedCurve(aligned::Curve c) {
    switch (c) {
        case aligned::Curve::SECP256K1: return hd_wallet::Curve::SECP256K1;
        case aligned::Curve::ED25519: return hd_wallet::Curve::ED25519;
        case aligned::Curve::P256: return hd_wallet::Curve::P256;
        case aligned::Curve::P384: return hd_wallet::Curve::P384;
        case aligned::Curve::X25519: return hd_wallet::Curve::X25519;
        default: return hd_wallet::Curve::SECP256K1;
    }
}

aligned::Curve toAlignedCurve(hd_wallet::Curve c) {
    switch (c) {
        case hd_wallet::Curve::SECP256K1: return aligned::Curve::SECP256K1;
        case hd_wallet::Curve::ED25519: return aligned::Curve::ED25519;
        case hd_wallet::Curve::P256: return aligned::Curve::P256;
        case hd_wallet::Curve::P384: return aligned::Curve::P384;
        case hd_wallet::Curve::X25519: return aligned::Curve::X25519;
        default: return aligned::Curve::SECP256K1;
    }
}

/**
 * Convert library error to aligned error
 */
aligned::Error toAlignedError(hd_wallet::Error e) {
    return static_cast<aligned::Error>(static_cast<int32_t>(e));
}

/**
 * Copy ExtendedKey data to aligned struct
 */
void copyKeyToAligned(const bip32::ExtendedKey& key, aligned::ExtendedKeyData* out) {
    std::memset(out, 0, sizeof(aligned::ExtendedKeyData));

    out->curve = toAlignedCurve(key.curve());
    out->depth = key.depth();
    out->parent_fingerprint = key.parentFingerprint();
    out->child_index = key.childIndex();

    // Copy chain code (flattened field name)
    auto chainCode = key.chainCode();
    std::memcpy(out->chain_code_data, chainCode.data(), 32);

    // Copy public key (flattened field name)
    auto pubKey = key.publicKey();
    std::memcpy(out->public_key_data, pubKey.data(), 33);

    // Copy private key if available
    out->has_private_key = key.isNeutered() ? 0 : 1;
    if (!key.isNeutered()) {
        auto privKeyResult = key.privateKey();
        if (privKeyResult.ok()) {
            std::memcpy(out->private_key_data, privKeyResult.value.data(), 32);
        }
    }
}

/**
 * Create ExtendedKey from aligned struct using raw data reconstruction
 */
bip32::ExtendedKey keyFromAligned(const aligned::ExtendedKeyData* data) {
    hd_wallet::Curve curve = fromAlignedCurve(data->curve);
    bool hasPrivate = data->has_private_key != 0;

    // Copy chain code
    hd_wallet::Bytes32 chainCode;
    std::memcpy(chainCode.data(), data->chain_code_data, 32);

    // Copy public key
    hd_wallet::Bytes33 publicKey;
    std::memcpy(publicKey.data(), data->public_key_data, 33);

    // Copy private key
    hd_wallet::Bytes32 privateKey;
    if (hasPrivate) {
        std::memcpy(privateKey.data(), data->private_key_data, 32);
    } else {
        std::memset(privateKey.data(), 0, 32);
    }

    return bip32::ExtendedKey::fromRawData(
        curve,
        data->depth,
        data->parent_fingerprint,
        data->child_index,
        chainCode,
        publicKey,
        privateKey,
        hasPrivate
    );
}

/**
 * Create ExtendedKey from BatchDeriveRequest's embedded base_key
 */
bip32::ExtendedKey keyFromBatchRequest(const aligned::BatchDeriveRequest* req) {
    hd_wallet::Curve curve = fromAlignedCurve(req->base_key_curve);
    bool hasPrivate = req->base_key_has_private_key != 0;

    // Copy chain code
    hd_wallet::Bytes32 chainCode;
    std::memcpy(chainCode.data(), req->base_key_chain_code_data, 32);

    // Copy public key
    hd_wallet::Bytes33 publicKey;
    std::memcpy(publicKey.data(), req->base_key_public_key_data, 33);

    // Copy private key
    hd_wallet::Bytes32 privateKey;
    if (hasPrivate) {
        std::memcpy(privateKey.data(), req->base_key_private_key_data, 32);
    } else {
        std::memset(privateKey.data(), 0, 32);
    }

    return bip32::ExtendedKey::fromRawData(
        curve,
        req->base_key_depth,
        req->base_key_parent_fingerprint,
        req->base_key_child_index,
        chainCode,
        publicKey,
        privateKey,
        hasPrivate
    );
}

/**
 * Create ExtendedKey from StreamDeriveConfig's embedded base_key
 */
bip32::ExtendedKey keyFromStreamConfig(const aligned::StreamDeriveConfig* cfg) {
    hd_wallet::Curve curve = fromAlignedCurve(cfg->base_key_curve);
    bool hasPrivate = cfg->base_key_has_private_key != 0;

    // Copy chain code
    hd_wallet::Bytes32 chainCode;
    std::memcpy(chainCode.data(), cfg->base_key_chain_code_data, 32);

    // Copy public key
    hd_wallet::Bytes33 publicKey;
    std::memcpy(publicKey.data(), cfg->base_key_public_key_data, 33);

    // Copy private key
    hd_wallet::Bytes32 privateKey;
    if (hasPrivate) {
        std::memcpy(privateKey.data(), cfg->base_key_private_key_data, 32);
    } else {
        std::memset(privateKey.data(), 0, 32);
    }

    return bip32::ExtendedKey::fromRawData(
        curve,
        cfg->base_key_depth,
        cfg->base_key_parent_fingerprint,
        cfg->base_key_child_index,
        chainCode,
        publicKey,
        privateKey,
        hasPrivate
    );
}

} // anonymous namespace

// =============================================================================
// Streaming Context
// =============================================================================

struct StreamContext {
    bip32::ExtendedKey baseKey;
    uint32_t currentIndex;
    uint32_t batchSize;
    bool hardened;
    bool complete;
    aligned::Error lastError;

    StreamContext(bip32::ExtendedKey&& key, uint32_t startIndex,
                  uint32_t batch, bool hard)
        : baseKey(std::move(key))
        , currentIndex(startIndex)
        , batchSize(batch)
        , hardened(hard)
        , complete(false)
        , lastError(aligned::Error::OK)
    {}
};

} // namespace aligned_impl
} // namespace hd_wallet

// Use C linkage for exported functions
extern "C" {

using namespace hd_wallet;
using namespace hd_wallet::aligned_impl;

// =============================================================================
// Batch Key Derivation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_derive_batch(
    const aligned::BatchDeriveRequest* request,
    aligned::DerivedKeyEntry* results,
    uint32_t results_capacity
) {
    // Count-returning: failure is -Error, never a positive code that could be
    // read as a count.
    if (!request) {
        return -static_cast<int32_t>(hd_wallet::Error::INVALID_ARGUMENT);
    }

    // Zero count is a valid request: derive zero keys, return zero.
    if (request->count == 0) {
        return 0;
    }

    if (!results || results_capacity == 0) {
        return -static_cast<int32_t>(hd_wallet::Error::INVALID_ARGUMENT);
    }

    uint32_t count = std::min(request->count, results_capacity);
    bool hardened = request->hardened != 0;

    // Check if base key has private key for hardened derivation
    bool hasPrivate = request->base_key_has_private_key != 0;
    if (hardened && !hasPrivate) {
        // Can't do hardened derivation without private key
        for (uint32_t i = 0; i < count; i++) {
            results[i].index = request->start_index + i;
            results[i].error = aligned::Error::HARDENED_FROM_PUBLIC;
            std::memset(results[i].public_key_data, 0, 33);
            std::memset(results[i].private_key_data, 0, 32);
        }
        return static_cast<int32_t>(count);
    }

    // Reconstruct base key from request
    bip32::ExtendedKey baseKey = keyFromBatchRequest(request);

    for (uint32_t i = 0; i < count; i++) {
        uint32_t childIndex = request->start_index + i;
        if (hardened) {
            childIndex |= bip32::HARDENED_OFFSET;
        }

        results[i].index = request->start_index + i;

        auto childResult = baseKey.deriveChild(childIndex);
        if (childResult.ok()) {
            const auto& child = childResult.value;
            results[i].error = aligned::Error::OK;

            auto pubKey = child.publicKey();
            std::memcpy(results[i].public_key_data, pubKey.data(), 33);

            if (!child.isNeutered()) {
                auto privKeyResult = child.privateKey();
                if (privKeyResult.ok()) {
                    std::memcpy(results[i].private_key_data,
                                privKeyResult.value.data(), 32);
                }
            } else {
                std::memset(results[i].private_key_data, 0, 32);
            }
        } else {
            results[i].error = toAlignedError(childResult.error);
            std::memset(results[i].public_key_data, 0, 33);
            std::memset(results[i].private_key_data, 0, 32);
        }
    }

    return static_cast<int32_t>(count);
}

// =============================================================================
// Batch Signing
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_sign_batch(
    const aligned::BatchSignRequest* request,
    const aligned::HashEntry* hashes,
    uint32_t hashes_count,
    aligned::SignatureEntry* results,
    uint32_t results_capacity
) {
    if (!request) {
        return -static_cast<int32_t>(hd_wallet::Error::INVALID_ARGUMENT);
    }

    uint32_t count = std::min({request->count, hashes_count, results_capacity});
    // Zero count is a valid request: sign nothing, return zero.
    if (count == 0) {
        return 0;
    }
    if (!hashes || !results) {
        return -static_cast<int32_t>(hd_wallet::Error::INVALID_ARGUMENT);
    }
    hd_wallet::Curve curve = fromAlignedCurve(request->curve);

    // Extract private key
    hd_wallet::Bytes32 privKey;
    std::memcpy(privKey.data(), request->private_key_data, 32);

    for (uint32_t i = 0; i < count; i++) {
        results[i].index = hashes[i].index;

        // Extract hash
        hd_wallet::Bytes32 hash;
        std::memcpy(hash.data(), hashes[i].hash_data, 32);

        // Sign based on curve type
        if (curve == hd_wallet::Curve::SECP256K1) {
            auto sigResult = ecdsa::secp256k1SignRecoverable(privKey, hash);
            if (sigResult.ok()) {
                // RecoverableSignature wire format is V(1) || R(32) || S(32).
                const uint8_t recoveryByte = sigResult.value[0];
                int recoveryId = -1;
                if (recoveryByte >= 27 && recoveryByte <= 30) {
                    recoveryId = static_cast<int>(recoveryByte - 27);
                } else if (recoveryByte >= 31 && recoveryByte <= 34) {
                    recoveryId = static_cast<int>(recoveryByte - 31);
                }

                if (recoveryId < 0 || recoveryId > 3) {
                    std::memset(results[i].signature_data, 0, 64);
                    results[i].recovery_id = -1;
                    results[i].error = aligned::Error::INVALID_SIGNATURE;
                } else {
                    std::memcpy(results[i].signature_data, sigResult.value.data() + 1, 64);
                    results[i].recovery_id = static_cast<int8_t>(recoveryId);
                    results[i].error = aligned::Error::OK;
                }
            } else {
                std::memset(results[i].signature_data, 0, 64);
                results[i].recovery_id = -1;
                results[i].error = toAlignedError(sigResult.error);
            }
        } else if (curve == hd_wallet::Curve::ED25519) {
            // Ed25519 signs the raw message, not a hash
            // For batch operations we treat the "hash" as the message
            auto sig = eddsa::ed25519Sign(privKey, hash.data(), 32);
            std::memcpy(results[i].signature_data, sig.data(), 64);
            results[i].recovery_id = -1;  // No recovery for Ed25519
            results[i].error = aligned::Error::OK;
        } else if (curve == hd_wallet::Curve::P256) {
            auto sigResult = ecdsa::p256Sign(privKey, hash);
            if (sigResult.ok()) {
                std::memcpy(results[i].signature_data, sigResult.value.data(), 64);
                results[i].recovery_id = -1;
                results[i].error = aligned::Error::OK;
            } else {
                std::memset(results[i].signature_data, 0, 64);
                results[i].recovery_id = -1;
                results[i].error = toAlignedError(sigResult.error);
            }
        } else if (curve == hd_wallet::Curve::P384) {
            // P-384 signatures are 96 bytes, but we only have 64 bytes
            // This is a limitation of the aligned format
            results[i].error = aligned::Error::NOT_SUPPORTED;
            std::memset(results[i].signature_data, 0, 64);
            results[i].recovery_id = -1;
        } else {
            results[i].error = aligned::Error::NOT_SUPPORTED;
            std::memset(results[i].signature_data, 0, 64);
            results[i].recovery_id = -1;
        }
    }

    hd_wallet::secureWipe(privKey);
    return static_cast<int32_t>(count);
}

// =============================================================================
// Batch Verification
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_verify_batch(
    const aligned::BatchVerifyRequest* request,
    const aligned::VerifyEntry* entries,
    uint32_t entries_count,
    aligned::VerifyResultEntry* results,
    uint32_t results_capacity
) {
    if (!request) {
        return -static_cast<int32_t>(hd_wallet::Error::INVALID_ARGUMENT);
    }

    uint32_t count = std::min({request->count, entries_count, results_capacity});
    // Zero count is a valid request: verify nothing, return zero.
    if (count == 0) {
        return 0;
    }
    if (!entries || !results) {
        return -static_cast<int32_t>(hd_wallet::Error::INVALID_ARGUMENT);
    }
    hd_wallet::Curve curve = fromAlignedCurve(request->curve);

    // Extract public key
    hd_wallet::Bytes33 pubKey;
    std::memcpy(pubKey.data(), request->public_key_data, 33);

    for (uint32_t i = 0; i < count; i++) {
        results[i].index = entries[i].index;

        // Extract hash and signature
        hd_wallet::Bytes32 hash;
        std::memcpy(hash.data(), entries[i].hash_data, 32);

        ecdsa::CompactSignature sig;
        std::memcpy(sig.data(), entries[i].signature_data, 64);

        // Verify based on curve type
        if (curve == hd_wallet::Curve::SECP256K1) {
            bool valid = ecdsa::secp256k1Verify(pubKey, hash, sig);
            results[i].error = valid ? aligned::Error::OK : aligned::Error::VERIFICATION_FAILED;
        } else if (curve == hd_wallet::Curve::ED25519) {
            // Ed25519 uses 32-byte public keys, need to extract from 33-byte
            hd_wallet::Bytes32 ed25519PubKey;
            std::memcpy(ed25519PubKey.data(), pubKey.data() + 1, 32);
            eddsa::Ed25519Signature ed25519Sig;
            std::memcpy(ed25519Sig.data(), entries[i].signature_data, 64);
            bool valid = eddsa::ed25519Verify(ed25519PubKey, hash.data(), 32, ed25519Sig);
            results[i].error = valid ? aligned::Error::OK : aligned::Error::VERIFICATION_FAILED;
        } else if (curve == hd_wallet::Curve::P256) {
            bool valid = ecdsa::p256Verify(pubKey, hash, sig);
            results[i].error = valid ? aligned::Error::OK : aligned::Error::VERIFICATION_FAILED;
        } else {
            results[i].error = aligned::Error::NOT_SUPPORTED;
        }
    }

    return static_cast<int32_t>(count);
}

// =============================================================================
// Streaming Key Derivation
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
hd_aligned_stream_handle hd_aligned_stream_create(
    const aligned::StreamDeriveConfig* config
) {
    if (!config) {
        return nullptr;
    }

    // Reconstruct base key from raw components
    bip32::ExtendedKey baseKey = keyFromStreamConfig(config);

    try {
        return reinterpret_cast<hd_aligned_stream_handle>(new StreamContext(
            std::move(baseKey),
            config->start_index,
            config->batch_size > 0 ? config->batch_size : 100,
            config->hardened != 0
        ));
    } catch (...) {
        return nullptr;
    }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_stream_next(
    hd_aligned_stream_handle stream,
    aligned::DerivedKeyEntry* results,
    uint32_t results_capacity
) {
    auto* s = reinterpret_cast<StreamContext*>(stream);
    if (!s || !results || results_capacity == 0) {
        return -static_cast<int32_t>(hd_wallet::Error::INVALID_ARGUMENT);
    }

    if (s->complete) {
        return 0;
    }

    uint32_t count = std::min(s->batchSize, results_capacity);

    for (uint32_t i = 0; i < count; i++) {
        uint32_t childIndex = s->currentIndex;
        if (s->hardened) {
            childIndex |= bip32::HARDENED_OFFSET;
        }

        results[i].index = s->currentIndex;

        auto childResult = s->baseKey.deriveChild(childIndex);
        if (childResult.ok()) {
            const auto& child = childResult.value;
            results[i].error = aligned::Error::OK;

            auto pubKey = child.publicKey();
            std::memcpy(results[i].public_key_data, pubKey.data(), 33);

            if (!child.isNeutered()) {
                auto privKeyResult = child.privateKey();
                if (privKeyResult.ok()) {
                    std::memcpy(results[i].private_key_data,
                                privKeyResult.value.data(), 32);
                }
            } else {
                std::memset(results[i].private_key_data, 0, 32);
            }
        } else {
            results[i].error = toAlignedError(childResult.error);
            std::memset(results[i].public_key_data, 0, 33);
            std::memset(results[i].private_key_data, 0, 32);
            s->lastError = results[i].error;
        }

        s->currentIndex++;

        // Check for overflow (wraparound)
        if (s->currentIndex == 0) {
            s->complete = true;
            return static_cast<int32_t>(i + 1);
        }
    }

    return static_cast<int32_t>(count);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_stream_status(
    hd_aligned_stream_handle stream,
    aligned::StreamStatus* status
) {
    auto* s = reinterpret_cast<StreamContext*>(stream);
    if (!s || !status) {
        return -static_cast<int32_t>(hd_wallet::Error::INVALID_ARGUMENT);
    }

    status->derived_count = s->currentIndex;
    status->current_index = s->currentIndex;
    status->error = s->lastError;
    status->complete = s->complete ? 1 : 0;

    return 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
void hd_aligned_stream_destroy(
    hd_aligned_stream_handle stream
) {
    delete reinterpret_cast<StreamContext*>(stream);
}

// =============================================================================
// Conversion Utilities
// =============================================================================

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
int32_t hd_aligned_from_extended_key(
    bip32::hd_key_handle key,
    aligned::ExtendedKeyData* out
) {
    if (!key || !out) {
        return -static_cast<int32_t>(hd_wallet::Error::INVALID_ARGUMENT);
    }

    auto* extKey = reinterpret_cast<bip32::ExtendedKey*>(key);
    copyKeyToAligned(*extKey, out);

    return 0;
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
bip32::hd_key_handle hd_aligned_to_extended_key(
    const aligned::ExtendedKeyData* data
) {
    if (!data) {
        return nullptr;
    }

    try {
        auto key = keyFromAligned(data);
        auto* keyPtr = new bip32::ExtendedKey(std::move(key));
        return reinterpret_cast<bip32::hd_key_handle>(keyPtr);
    } catch (...) {
        return nullptr;
    }
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_aligned_derived_key_entry_size(void) {
    return sizeof(aligned::DerivedKeyEntry);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_aligned_signature_entry_size(void) {
    return sizeof(aligned::SignatureEntry);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_aligned_extended_key_data_size(void) {
    return sizeof(aligned::ExtendedKeyData);
}

HD_WALLET_C_EXPORT HD_WALLET_EXPORT
uint32_t hd_aligned_batch_derive_request_size(void) {
    return sizeof(aligned::BatchDeriveRequest);
}

} // extern "C"
