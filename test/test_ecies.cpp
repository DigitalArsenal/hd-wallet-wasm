/**
 * @file test_ecies.cpp
 * @brief ECIES Test Suite
 *
 * Tests for the unified ECIES encrypt/decrypt API across all supported curves.
 * Tests both the C++ API and C API (WASM exports).
 */

#include "test_framework.h"
#include "hd_wallet/ecies.h"
#include "hd_wallet/ecdh.h"
#include "hd_wallet/types.h"
#include "hd_wallet/error.h"

#include <cryptopp/osrng.h>

#include <cstring>
#include <string>
#include <vector>
#include <array>
#include <algorithm>

using namespace hd_wallet;
using namespace hd_wallet::ecies;
using namespace hd_wallet::ecdh;

// =============================================================================
// Helper
// =============================================================================

static std::string toHex(const uint8_t* data, size_t len) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out += hex[data[i] >> 4];
        out += hex[data[i] & 0x0f];
    }
    return out;
}

// =============================================================================
// Overhead Tests
// =============================================================================

TEST_CASE(ECIES, Overhead_Secp256k1) {
    ASSERT_EQ(eciesOverhead(Curve::SECP256K1), 61u);
    ASSERT_EQ(eciesEphemeralKeySize(Curve::SECP256K1), 33u);
}

TEST_CASE(ECIES, Overhead_P256) {
    ASSERT_EQ(eciesOverhead(Curve::P256), 61u);
    ASSERT_EQ(eciesEphemeralKeySize(Curve::P256), 33u);
}

TEST_CASE(ECIES, Overhead_P384) {
    ASSERT_EQ(eciesOverhead(Curve::P384), 77u);
    ASSERT_EQ(eciesEphemeralKeySize(Curve::P384), 49u);
}

TEST_CASE(ECIES, Overhead_X25519) {
    ASSERT_EQ(eciesOverhead(Curve::X25519), 60u);
    ASSERT_EQ(eciesEphemeralKeySize(Curve::X25519), 32u);
}

TEST_CASE(ECIES, Overhead_Invalid) {
    ASSERT_EQ(eciesOverhead(Curve::ED25519), 0u);
    ASSERT_EQ(eciesEphemeralKeySize(Curve::ED25519), 0u);
}

// =============================================================================
// Round-Trip Tests (encrypt then decrypt)
// =============================================================================

TEST_CASE(ECIES, RoundTrip_Secp256k1) {
    // Generate a recipient key pair
    auto kpResult = generateEphemeralKeyPair(Curve::SECP256K1);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    // Plaintext
    const char* msg = "Hello, ECIES secp256k1!";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    // Encrypt
    size_t overhead = eciesOverhead(Curve::SECP256K1);
    std::vector<uint8_t> ciphertext(msgLen + overhead);

    int32_t encResult = eciesEncrypt(
        Curve::SECP256K1,
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen,
        nullptr, 0,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);
    ASSERT_EQ(static_cast<size_t>(encResult), msgLen + overhead);

    // Decrypt
    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = eciesDecrypt(
        Curve::SECP256K1,
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        nullptr, 0,
        decrypted.data(), decrypted.size());

    ASSERT_TRUE(decResult > 0);
    ASSERT_EQ(static_cast<size_t>(decResult), msgLen);
    ASSERT_TRUE(std::memcmp(decrypted.data(), pt, msgLen) == 0);
}

TEST_CASE(ECIES, RoundTrip_P256) {
    auto kpResult = generateEphemeralKeyPair(Curve::P256);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    const char* msg = "Hello, ECIES P-256!";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    size_t overhead = eciesOverhead(Curve::P256);
    std::vector<uint8_t> ciphertext(msgLen + overhead);

    int32_t encResult = eciesEncrypt(
        Curve::P256,
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen, nullptr, 0,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);

    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = eciesDecrypt(
        Curve::P256,
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        nullptr, 0,
        decrypted.data(), decrypted.size());

    ASSERT_TRUE(decResult > 0);
    ASSERT_EQ(static_cast<size_t>(decResult), msgLen);
    ASSERT_TRUE(std::memcmp(decrypted.data(), pt, msgLen) == 0);
}

TEST_CASE(ECIES, RoundTrip_P384) {
    auto kpResult = generateEphemeralKeyPair(Curve::P384);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    const char* msg = "Hello, ECIES P-384!";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    size_t overhead = eciesOverhead(Curve::P384);
    std::vector<uint8_t> ciphertext(msgLen + overhead);

    int32_t encResult = eciesEncrypt(
        Curve::P384,
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen, nullptr, 0,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);

    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = eciesDecrypt(
        Curve::P384,
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        nullptr, 0,
        decrypted.data(), decrypted.size());

    ASSERT_TRUE(decResult > 0);
    ASSERT_EQ(static_cast<size_t>(decResult), msgLen);
    ASSERT_TRUE(std::memcmp(decrypted.data(), pt, msgLen) == 0);
}

TEST_CASE(ECIES, RoundTrip_X25519) {
    auto kpResult = generateEphemeralKeyPair(Curve::X25519);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    const char* msg = "Hello, ECIES X25519!";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    size_t overhead = eciesOverhead(Curve::X25519);
    std::vector<uint8_t> ciphertext(msgLen + overhead);

    int32_t encResult = eciesEncrypt(
        Curve::X25519,
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen, nullptr, 0,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);

    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = eciesDecrypt(
        Curve::X25519,
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        nullptr, 0,
        decrypted.data(), decrypted.size());

    ASSERT_TRUE(decResult > 0);
    ASSERT_EQ(static_cast<size_t>(decResult), msgLen);
    ASSERT_TRUE(std::memcmp(decrypted.data(), pt, msgLen) == 0);
}

// =============================================================================
// AAD (Additional Authenticated Data) Tests
// =============================================================================

TEST_CASE(ECIES, AAD_RoundTrip) {
    auto kpResult = generateEphemeralKeyPair(Curve::SECP256K1);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    const char* msg = "Secret payload with AAD";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    const char* aadStr = "associated-context-data";
    auto* aad = reinterpret_cast<const uint8_t*>(aadStr);
    size_t aadLen = std::strlen(aadStr);

    size_t overhead = eciesOverhead(Curve::SECP256K1);
    std::vector<uint8_t> ciphertext(msgLen + overhead);

    int32_t encResult = eciesEncrypt(
        Curve::SECP256K1,
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen,
        aad, aadLen,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);

    // Decrypt with correct AAD
    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = eciesDecrypt(
        Curve::SECP256K1,
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        aad, aadLen,
        decrypted.data(), decrypted.size());

    ASSERT_TRUE(decResult > 0);
    ASSERT_TRUE(std::memcmp(decrypted.data(), pt, msgLen) == 0);
}

TEST_CASE(ECIES, AAD_Mismatch_Fails) {
    auto kpResult = generateEphemeralKeyPair(Curve::SECP256K1);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    const char* msg = "Secret payload";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    const char* aadStr = "correct-aad";
    auto* aad = reinterpret_cast<const uint8_t*>(aadStr);
    size_t aadLen = std::strlen(aadStr);

    size_t overhead = eciesOverhead(Curve::SECP256K1);
    std::vector<uint8_t> ciphertext(msgLen + overhead);

    int32_t encResult = eciesEncrypt(
        Curve::SECP256K1,
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen, aad, aadLen,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);

    // Decrypt with wrong AAD should fail
    const char* wrongAad = "wrong-aad";
    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = eciesDecrypt(
        Curve::SECP256K1,
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        reinterpret_cast<const uint8_t*>(wrongAad), std::strlen(wrongAad),
        decrypted.data(), decrypted.size());

    ASSERT_TRUE(decResult < 0);
}

// =============================================================================
// Tamper Tests
// =============================================================================

TEST_CASE(ECIES, Tampered_Ciphertext_Fails) {
    auto kpResult = generateEphemeralKeyPair(Curve::P256);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    const char* msg = "Tamper test data";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    size_t overhead = eciesOverhead(Curve::P256);
    std::vector<uint8_t> ciphertext(msgLen + overhead);

    int32_t encResult = eciesEncrypt(
        Curve::P256,
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen, nullptr, 0,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);

    // Tamper with the ciphertext portion (after ephKey + iv, before tag)
    size_t ephKeySize = eciesEphemeralKeySize(Curve::P256);
    size_t ctStart = ephKeySize + ECIES_IV_SIZE;
    ciphertext[ctStart] ^= 0xFF;

    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = eciesDecrypt(
        Curve::P256,
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        nullptr, 0,
        decrypted.data(), decrypted.size());

    ASSERT_TRUE(decResult < 0);
}

TEST_CASE(ECIES, Tampered_Tag_Fails) {
    auto kpResult = generateEphemeralKeyPair(Curve::P256);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    const char* msg = "Tag tamper test";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    size_t overhead = eciesOverhead(Curve::P256);
    std::vector<uint8_t> ciphertext(msgLen + overhead);

    int32_t encResult = eciesEncrypt(
        Curve::P256,
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen, nullptr, 0,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);

    // Tamper with the last byte (tag)
    ciphertext[static_cast<size_t>(encResult) - 1] ^= 0x01;

    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = eciesDecrypt(
        Curve::P256,
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        nullptr, 0,
        decrypted.data(), decrypted.size());

    ASSERT_TRUE(decResult < 0);
}

TEST_CASE(ECIES, Tampered_Tag_ZeroesOutput) {
    // A tag mismatch reports VERIFICATION_FAILED and leaves no unauthenticated
    // plaintext in the caller's buffer.
    auto kpResult = generateEphemeralKeyPair(Curve::P256);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    const char* msg = "plaintext that must not come back";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    std::vector<uint8_t> ciphertext(msgLen + eciesOverhead(Curve::P256));
    int32_t encResult = eciesEncrypt(
        Curve::P256,
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen, nullptr, 0,
        ciphertext.data(), ciphertext.size());
    ASSERT_TRUE(encResult > 0);
    ciphertext[static_cast<size_t>(encResult) - 1] ^= 0x01;

    std::vector<uint8_t> decrypted(msgLen, 0xa5);
    int32_t decResult = eciesDecrypt(
        Curve::P256,
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        nullptr, 0,
        decrypted.data(), decrypted.size());

    ASSERT_EQ(-static_cast<int32_t>(Error::VERIFICATION_FAILED), decResult);
    ASSERT_TRUE(std::all_of(decrypted.begin(), decrypted.end(), [](uint8_t b) { return b == 0; }));
}

TEST_CASE(ECIES, Wrong_PrivateKey_Fails) {
    auto kp1Result = generateEphemeralKeyPair(Curve::SECP256K1);
    auto kp2Result = generateEphemeralKeyPair(Curve::SECP256K1);
    ASSERT_TRUE(kp1Result.ok());
    ASSERT_TRUE(kp2Result.ok());

    const char* msg = "Wrong key test";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    size_t overhead = eciesOverhead(Curve::SECP256K1);
    std::vector<uint8_t> ciphertext(msgLen + overhead);

    // Encrypt for kp1
    int32_t encResult = eciesEncrypt(
        Curve::SECP256K1,
        kp1Result.value.publicKey.data(), kp1Result.value.publicKey.size(),
        pt, msgLen, nullptr, 0,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);

    // Try to decrypt with kp2's private key (should fail)
    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = eciesDecrypt(
        Curve::SECP256K1,
        kp2Result.value.privateKey.data(), kp2Result.value.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        nullptr, 0,
        decrypted.data(), decrypted.size());

    ASSERT_TRUE(decResult < 0);
}

// =============================================================================
// Edge Cases
// =============================================================================

TEST_CASE(ECIES, Empty_Plaintext) {
    auto kpResult = generateEphemeralKeyPair(Curve::P256);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    size_t overhead = eciesOverhead(Curve::P256);
    std::vector<uint8_t> ciphertext(overhead);

    // Encrypt empty plaintext
    int32_t encResult = eciesEncrypt(
        Curve::P256,
        kp.publicKey.data(), kp.publicKey.size(),
        nullptr, 0,
        nullptr, 0,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);
    ASSERT_EQ(static_cast<size_t>(encResult), overhead);

    // Decrypt — should succeed with 0 bytes of plaintext
    uint8_t dummy;
    int32_t decResult = eciesDecrypt(
        Curve::P256,
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        nullptr, 0,
        &dummy, 1);

    ASSERT_EQ(decResult, 0);
}

TEST_CASE(ECIES, Buffer_Too_Small) {
    auto kpResult = generateEphemeralKeyPair(Curve::SECP256K1);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    const char* msg = "Buffer test";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    // Output buffer too small
    std::vector<uint8_t> tooSmall(10);
    int32_t encResult = eciesEncrypt(
        Curve::SECP256K1,
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen, nullptr, 0,
        tooSmall.data(), tooSmall.size());

    ASSERT_TRUE(encResult < 0);
}

// =============================================================================
// C API Tests
// =============================================================================

TEST_CASE(ECIES, CAPI_RoundTrip) {
    auto kpResult = generateEphemeralKeyPair(Curve::SECP256K1);
    ASSERT_TRUE(kpResult.ok());
    auto& kp = kpResult.value;

    const char* msg = "C API test message";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    int32_t overhead = hd_ecies_overhead(static_cast<int32_t>(Curve::SECP256K1));
    ASSERT_EQ(overhead, 61);

    std::vector<uint8_t> ciphertext(msgLen + static_cast<size_t>(overhead));

    int32_t encResult = hd_ecies_encrypt(
        static_cast<int32_t>(Curve::SECP256K1),
        kp.publicKey.data(), kp.publicKey.size(),
        pt, msgLen, nullptr, 0,
        ciphertext.data(), ciphertext.size());

    ASSERT_TRUE(encResult > 0);

    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = hd_ecies_decrypt(
        static_cast<int32_t>(Curve::SECP256K1),
        kp.privateKey.data(), kp.privateKey.size(),
        ciphertext.data(), static_cast<size_t>(encResult),
        nullptr, 0,
        decrypted.data(), decrypted.size());

    ASSERT_TRUE(decResult > 0);
    ASSERT_EQ(static_cast<size_t>(decResult), msgLen);
    ASSERT_TRUE(std::memcmp(decrypted.data(), pt, msgLen) == 0);
}

TEST_CASE(ECIES, CAPI_Overhead_Invalid) {
    int32_t overhead = hd_ecies_overhead(static_cast<int32_t>(Curve::ED25519));
    ASSERT_EQ(overhead, -1);
}

// =============================================================================
// Ephemeral Key Generation Tests
// =============================================================================

TEST_CASE(ECIES, EphemeralKeyPair_Secp256k1) {
    auto kpResult = generateEphemeralKeyPair(Curve::SECP256K1);
    ASSERT_TRUE(kpResult.ok());
    ASSERT_EQ(kpResult.value.privateKey.size(), 32u);
    ASSERT_EQ(kpResult.value.publicKey.size(), 33u);
    // Compressed key starts with 0x02 or 0x03
    ASSERT_TRUE(kpResult.value.publicKey[0] == 0x02 || kpResult.value.publicKey[0] == 0x03);
}

TEST_CASE(ECIES, EphemeralKeyPair_P256) {
    auto kpResult = generateEphemeralKeyPair(Curve::P256);
    ASSERT_TRUE(kpResult.ok());
    ASSERT_EQ(kpResult.value.privateKey.size(), 32u);
    ASSERT_EQ(kpResult.value.publicKey.size(), 33u);
    ASSERT_TRUE(kpResult.value.publicKey[0] == 0x02 || kpResult.value.publicKey[0] == 0x03);
}

TEST_CASE(ECIES, EphemeralKeyPair_P384) {
    auto kpResult = generateEphemeralKeyPair(Curve::P384);
    ASSERT_TRUE(kpResult.ok());
    ASSERT_EQ(kpResult.value.privateKey.size(), 48u);
    ASSERT_EQ(kpResult.value.publicKey.size(), 49u);
    ASSERT_TRUE(kpResult.value.publicKey[0] == 0x02 || kpResult.value.publicKey[0] == 0x03);
}

TEST_CASE(ECIES, EphemeralKeyPair_X25519) {
    auto kpResult = generateEphemeralKeyPair(Curve::X25519);
    ASSERT_TRUE(kpResult.ok());
    ASSERT_EQ(kpResult.value.privateKey.size(), 32u);
    ASSERT_EQ(kpResult.value.publicKey.size(), 32u);
}

// =============================================================================
// ECDH + HKDF Combined Key Derivation Tests
// =============================================================================

TEST_CASE(ECIES, EcdhDeriveKey_Secp256k1) {
    auto kp1 = generateEphemeralKeyPair(Curve::SECP256K1);
    auto kp2 = generateEphemeralKeyPair(Curve::SECP256K1);
    ASSERT_TRUE(kp1.ok());
    ASSERT_TRUE(kp2.ok());

    // Derive key: Alice using Bob's public key
    auto key1 = ecdhDeriveKey(
        Curve::SECP256K1,
        kp1.value.privateKey, kp2.value.publicKey,
        {}, {}, 32);
    ASSERT_TRUE(key1.ok());
    ASSERT_EQ(key1.value.size(), 32u);

    // Derive key: Bob using Alice's public key
    auto key2 = ecdhDeriveKey(
        Curve::SECP256K1,
        kp2.value.privateKey, kp1.value.publicKey,
        {}, {}, 32);
    ASSERT_TRUE(key2.ok());
    ASSERT_EQ(key2.value.size(), 32u);

    // Both should derive the same key
    ASSERT_TRUE(std::memcmp(key1.value.data(), key2.value.data(), 32) == 0);
}

TEST_CASE(ECIES, EcdhDeriveKey_X25519) {
    auto kp1 = generateEphemeralKeyPair(Curve::X25519);
    auto kp2 = generateEphemeralKeyPair(Curve::X25519);
    ASSERT_TRUE(kp1.ok());
    ASSERT_TRUE(kp2.ok());

    auto key1 = ecdhDeriveKey(
        Curve::X25519,
        kp1.value.privateKey, kp2.value.publicKey,
        {}, {}, 32);
    ASSERT_TRUE(key1.ok());

    auto key2 = ecdhDeriveKey(
        Curve::X25519,
        kp2.value.privateKey, kp1.value.publicKey,
        {}, {}, 32);
    ASSERT_TRUE(key2.ok());

    ASSERT_TRUE(std::memcmp(key1.value.data(), key2.value.data(), 32) == 0);
}

// =============================================================================
// AES-CTR Tests
// =============================================================================

TEST_CASE(ECIES, AesCtr256_RoundTrip) {
    uint8_t key[32];
    uint8_t iv[16];
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key, sizeof(key));
    rng.GenerateBlock(iv, sizeof(iv));

    const char* msg = "Hello AES-CTR 256!";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    std::vector<uint8_t> ct(msgLen);
    int32_t encResult = aesCtrEncrypt(key, 32, pt, msgLen, iv, 16, ct.data(), ct.size());
    ASSERT_EQ(encResult, static_cast<int32_t>(msgLen));

    // Ciphertext should differ from plaintext
    ASSERT_TRUE(std::memcmp(ct.data(), pt, msgLen) != 0);

    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = aesCtrDecrypt(key, 32, ct.data(), msgLen, iv, 16, decrypted.data(), decrypted.size());
    ASSERT_EQ(decResult, static_cast<int32_t>(msgLen));
    ASSERT_TRUE(std::memcmp(decrypted.data(), pt, msgLen) == 0);
}

TEST_CASE(ECIES, AesCtr128_RoundTrip) {
    uint8_t key[16];
    uint8_t iv[16];
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key, sizeof(key));
    rng.GenerateBlock(iv, sizeof(iv));

    const char* msg = "Hello AES-CTR 128!";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    std::vector<uint8_t> ct(msgLen);
    int32_t encResult = aesCtrEncrypt(key, 16, pt, msgLen, iv, 16, ct.data(), ct.size());
    ASSERT_EQ(encResult, static_cast<int32_t>(msgLen));

    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = aesCtrDecrypt(key, 16, ct.data(), msgLen, iv, 16, decrypted.data(), decrypted.size());
    ASSERT_EQ(decResult, static_cast<int32_t>(msgLen));
    ASSERT_TRUE(std::memcmp(decrypted.data(), pt, msgLen) == 0);
}

TEST_CASE(ECIES, AesCtr192_RoundTrip) {
    uint8_t key[24];
    uint8_t iv[16];
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key, sizeof(key));
    rng.GenerateBlock(iv, sizeof(iv));

    const char* msg = "Hello AES-CTR 192!";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    std::vector<uint8_t> ct(msgLen);
    int32_t encResult = aesCtrEncrypt(key, 24, pt, msgLen, iv, 16, ct.data(), ct.size());
    ASSERT_EQ(encResult, static_cast<int32_t>(msgLen));

    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = aesCtrDecrypt(key, 24, ct.data(), msgLen, iv, 16, decrypted.data(), decrypted.size());
    ASSERT_EQ(decResult, static_cast<int32_t>(msgLen));
    ASSERT_TRUE(std::memcmp(decrypted.data(), pt, msgLen) == 0);
}

TEST_CASE(ECIES, AesCtr_InvalidKeySize) {
    uint8_t key[15];  // Invalid
    uint8_t iv[16];
    uint8_t pt[16] = {0};
    uint8_t ct[16];

    int32_t result = aesCtrEncrypt(key, 15, pt, 16, iv, 16, ct, 16);
    ASSERT_TRUE(result < 0);
}

TEST_CASE(ECIES, AesCtr_InvalidIvSize) {
    uint8_t key[32];
    uint8_t iv[12];  // Wrong size for CTR (needs 16)
    uint8_t pt[16] = {0};
    uint8_t ct[16];

    int32_t result = aesCtrEncrypt(key, 32, pt, 16, iv, 12, ct, 16);
    ASSERT_TRUE(result < 0);
}

TEST_CASE(ECIES, AesCtr_BufferTooSmall) {
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t pt[32] = {0};
    uint8_t ct[16];  // Too small for 32 bytes

    int32_t result = aesCtrEncrypt(key, 32, pt, 32, iv, 16, ct, 16);
    ASSERT_TRUE(result < 0);
}

TEST_CASE(ECIES, AesCtr_EmptyPlaintext) {
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t ct[1];

    int32_t result = aesCtrEncrypt(key, 32, nullptr, 0, iv, 16, ct, 0);
    ASSERT_EQ(result, 0);
}

TEST_CASE(ECIES, AesCtr_WrongKey_DifferentOutput) {
    uint8_t key1[32], key2[32];
    uint8_t iv[16];
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key1, sizeof(key1));
    rng.GenerateBlock(key2, sizeof(key2));
    rng.GenerateBlock(iv, sizeof(iv));

    const char* msg = "Secret message";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    std::vector<uint8_t> ct1(msgLen), ct2(msgLen);
    aesCtrEncrypt(key1, 32, pt, msgLen, iv, 16, ct1.data(), ct1.size());
    aesCtrEncrypt(key2, 32, pt, msgLen, iv, 16, ct2.data(), ct2.size());

    // Different keys should produce different ciphertexts
    ASSERT_TRUE(std::memcmp(ct1.data(), ct2.data(), msgLen) != 0);
}

TEST_CASE(ECIES, AesCtr_CAPI_RoundTrip) {
    uint8_t key[32];
    uint8_t iv[16];
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(key, sizeof(key));
    rng.GenerateBlock(iv, sizeof(iv));

    const char* msg = "C API CTR test";
    size_t msgLen = std::strlen(msg);
    auto* pt = reinterpret_cast<const uint8_t*>(msg);

    std::vector<uint8_t> ct(msgLen);
    int32_t encResult = hd_aes_ctr_encrypt(key, 32, pt, msgLen, iv, 16, ct.data(), ct.size());
    ASSERT_EQ(encResult, static_cast<int32_t>(msgLen));

    std::vector<uint8_t> decrypted(msgLen);
    int32_t decResult = hd_aes_ctr_decrypt(key, 32, ct.data(), msgLen, iv, 16, decrypted.data(), decrypted.size());
    ASSERT_EQ(decResult, static_cast<int32_t>(msgLen));
    ASSERT_TRUE(std::memcmp(decrypted.data(), pt, msgLen) == 0);
}
