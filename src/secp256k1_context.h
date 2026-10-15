/**
 * @file secp256k1_context.h
 * @brief The one libsecp256k1 context the WASM builds share (internal)
 *
 * BIP-32, the coin signers and the recoverable-signature exports all use this
 * context. It is blinded with secp256k1_context_randomize, as upstream
 * recommends against side channels, from 32 bytes of the library's secure
 * RNG (WasiBridge::getEntropy, the source BIP-39 generation uses). Blinding
 * changes no output: signatures stay RFC 6979 deterministic.
 *
 * The seed is taken the first time entropy is available. Until then (a WASI
 * host with no entropy yet) the context works unblinded, as before; the next
 * call tries again. WASM is single-threaded, so no lock is needed.
 */

#ifndef HD_WALLET_SECP256K1_CONTEXT_H
#define HD_WALLET_SECP256K1_CONTEXT_H

#include "hd_wallet/wasi_bridge.h"

#include <secp256k1.h>

#include <cstddef>
#include <cstdint>

namespace hd_wallet::internal {

inline secp256k1_context* secp256k1Context() noexcept {
    static secp256k1_context* const ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    static bool blinded = false;
    if (!blinded) {
        uint8_t seed[32];
        if (WasiBridge::instance().getEntropy(seed, sizeof(seed)) ==
            static_cast<int32_t>(sizeof(seed))) {
            blinded = secp256k1_context_randomize(ctx, seed) == 1;
        }
        volatile uint8_t* wipe = seed;
        for (size_t i = 0; i < sizeof(seed); ++i) wipe[i] = 0;
    }
    return ctx;
}

} // namespace hd_wallet::internal

#endif // HD_WALLET_SECP256K1_CONTEXT_H
