/**
 * @file secure_rng.h
 * @brief Build-environment secure RNG adapter.
 */

#ifndef HD_WALLET_SECURE_RNG_H
#define HD_WALLET_SECURE_RNG_H

#include "hd_wallet/config.h"

#if HD_WALLET_IS_WASI
#include "hd_wallet/wasi_bridge.h"

#include <cryptopp/cryptlib.h>

namespace hd_wallet {

class SecureRandomGenerator final : public CryptoPP::RandomNumberGenerator {
public:
  void GenerateBlock(CryptoPP::byte* output, size_t size) override {
    if (output == nullptr || size == 0) {
      return;
    }

    auto& bridge = WasiBridge::instance();
    int32_t written = bridge.getEntropy(reinterpret_cast<uint8_t*>(output), size);
    if (written < 0 || static_cast<size_t>(written) != size) {
      throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "WASI entropy unavailable");
    }
  }

  CryptoPP::byte GenerateByte() override {
    CryptoPP::byte value = 0;
    GenerateBlock(&value, 1);
    return value;
  }
};

} // namespace hd_wallet

#else
#include <cryptopp/osrng.h>

namespace hd_wallet {
using SecureRandomGenerator = CryptoPP::AutoSeededRandomPool;
} // namespace hd_wallet
#endif

#endif // HD_WALLET_SECURE_RNG_H
