/**
 * @file test_coin_addresses.cpp
 * @brief End-to-end coin address derivation tests for BTC, ETH, SOL
 *
 * Tests the full pipeline: mnemonic -> seed -> key derivation -> address generation
 * using well-known test vectors from the "abandon...about" mnemonic.
 */

#include "test_framework.h"
#include "hd_wallet/types.h"
#include "hd_wallet/bip32.h"
#include "hd_wallet/bip39.h"
#include "hd_wallet/eddsa.h"
#include "hd_wallet/coins/bitcoin.h"
#include "hd_wallet/coins/coin.h"
#include "hd_wallet/coins/cosmos.h"
#include "hd_wallet/coins/ethereum.h"
#include "hd_wallet/coins/polkadot.h"
#include "hd_wallet/coins/solana.h"

#include <array>
#include <cctype>
#include <cstring>
#include <string>

using namespace hd_wallet;
using namespace hd_wallet::bip32;
using namespace hd_wallet::coins;
using namespace hd_wallet::eddsa;

// =============================================================================
// Standard test mnemonic and seed
// =============================================================================

static const char* TEST_MNEMONIC =
    "abandon abandon abandon abandon abandon abandon "
    "abandon abandon abandon abandon abandon about";

static const char* TEST_SEED_HEX =
    "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc1"
    "9a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4";

// =============================================================================
// Bitcoin Test Vectors (BIP-84 native SegWit: m/84'/0'/0'/0/0)
// =============================================================================

static const char* BTC_BIP84_PUBKEY_HEX =
    "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c";
static const char* BTC_BIP84_P2WPKH_ADDRESS =
    "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu";

// BIP-44 legacy: m/44'/0'/0'/0/0
static const char* BTC_BIP44_PUBKEY_HEX =
    "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e";
static const char* BTC_BIP44_P2PKH_ADDRESS =
    "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA";

// =============================================================================
// Ethereum Test Vectors (BIP-44: m/44'/60'/0'/0/0)
// =============================================================================

static const char* ETH_BIP44_PUBKEY_HEX =
    "0237b0bb7a8288d38ed49a524b5dc98cff3eb5ca824c9f9dc0dfdb3d9cd600f299";
static const char* ETH_BIP44_ADDRESS =
    "0x9858EfFD232B4033E47d90003D41EC34EcaEda94";

// =============================================================================
// Solana Test Vectors (SLIP-10 Ed25519: m/44'/501'/0'/0')
// =============================================================================

static const char* SOL_ADDRESS =
    "HAgk14JpMQLgt6rVgv7cBQFJWFto5Dqxi472uT3DKpqk";

// =============================================================================
// Helper: derive seed from mnemonic
// =============================================================================

static Bytes64 getTestSeed() {
    auto seedResult = bip39::mnemonicToSeed(TEST_MNEMONIC, "");
    if (!seedResult.ok()) {
        throw std::runtime_error("Failed to derive test seed");
    }
    return seedResult.value;
}

static std::string toLower(const std::string& s) {
    std::string result;
    result.reserve(s.size());
    for (char c : s) result += static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return result;
}

// =============================================================================
// Test: Seed derivation matches known hex
// =============================================================================

TEST_CASE(CoinAddresses, SeedFromMnemonic) {
    auto seed = getTestSeed();
    auto seedHex = test::bytesToHex(seed);
    ASSERT_STR_EQ(TEST_SEED_HEX, seedHex);
}

// =============================================================================
// Bitcoin Tests
// =============================================================================

TEST_CASE(CoinAddresses, BTC_BIP84_PublicKey) {
    auto seed = getTestSeed();
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    // BIP-84: m/84'/0'/0'/0/0
    auto derivedResult = masterResult.value.derivePath("m/84'/0'/0'/0/0");
    ASSERT_OK(derivedResult);

    auto pubkey = derivedResult.value.publicKey();
    ASSERT_EQ(33u, pubkey.size());

    auto pubkeyHex = test::bytesToHex(pubkey);
    ASSERT_STR_EQ(BTC_BIP84_PUBKEY_HEX, pubkeyHex);
}

TEST_CASE(CoinAddresses, BTC_BIP84_P2WPKH_Address) {
    auto seed = getTestSeed();
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    auto derivedResult = masterResult.value.derivePath("m/84'/0'/0'/0/0");
    ASSERT_OK(derivedResult);

    auto pubkey = derivedResult.value.publicKey();

    // Generate P2WPKH address using C++ API
    auto addrResult = bitcoinP2WPKH(pubkey);
    ASSERT_OK(addrResult);
    ASSERT_STR_EQ(BTC_BIP84_P2WPKH_ADDRESS, addrResult.value);
}

TEST_CASE(CoinAddresses, BTC_BIP84_P2WPKH_Address_CAPI) {
    auto seed = getTestSeed();
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    auto derivedResult = masterResult.value.derivePath("m/84'/0'/0'/0/0");
    ASSERT_OK(derivedResult);

    auto pubkey = derivedResult.value.publicKey();

    // Generate P2WPKH address using C API (same path as WASM)
    char address[128] = {0};
    int32_t rc = hd_btc_p2wpkh_address(
        pubkey.data(), pubkey.size(),
        0,  // mainnet
        address, sizeof(address)
    );
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);
    ASSERT_STR_EQ(BTC_BIP84_P2WPKH_ADDRESS, std::string(address));
}

TEST_CASE(CoinAddresses, BTC_BIP44_PublicKey) {
    auto seed = getTestSeed();
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    // BIP-44: m/44'/0'/0'/0/0
    auto derivedResult = masterResult.value.derivePath("m/44'/0'/0'/0/0");
    ASSERT_OK(derivedResult);

    auto pubkey = derivedResult.value.publicKey();
    ASSERT_EQ(33u, pubkey.size());

    auto pubkeyHex = test::bytesToHex(pubkey);
    ASSERT_STR_EQ(BTC_BIP44_PUBKEY_HEX, pubkeyHex);
}

TEST_CASE(CoinAddresses, BTC_BIP44_P2PKH_Address) {
    auto seed = getTestSeed();
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    auto derivedResult = masterResult.value.derivePath("m/44'/0'/0'/0/0");
    ASSERT_OK(derivedResult);

    auto pubkey = derivedResult.value.publicKey();

    // Generate P2PKH address
    ByteVector pubkeyVec(pubkey.begin(), pubkey.end());
    auto addrResult = bitcoinP2PKH(pubkeyVec);
    ASSERT_OK(addrResult);
    ASSERT_STR_EQ(BTC_BIP44_P2PKH_ADDRESS, addrResult.value);
}

TEST_CASE(CoinAddresses, BTC_BIP44_P2PKH_Address_CAPI) {
    auto seed = getTestSeed();
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    auto derivedResult = masterResult.value.derivePath("m/44'/0'/0'/0/0");
    ASSERT_OK(derivedResult);

    auto pubkey = derivedResult.value.publicKey();

    // C API
    char address[128] = {0};
    int32_t rc = hd_btc_p2pkh_address(
        pubkey.data(), pubkey.size(),
        0,  // mainnet
        address, sizeof(address)
    );
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);
    ASSERT_STR_EQ(BTC_BIP44_P2PKH_ADDRESS, std::string(address));
}

// =============================================================================
// Ethereum Tests
// =============================================================================

TEST_CASE(CoinAddresses, ETH_BIP44_PublicKey) {
    auto seed = getTestSeed();
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    // m/44'/60'/0'/0/0
    auto derivedResult = masterResult.value.derivePath("m/44'/60'/0'/0/0");
    ASSERT_OK(derivedResult);

    auto pubkey = derivedResult.value.publicKey();
    ASSERT_EQ(33u, pubkey.size());

    auto pubkeyHex = test::bytesToHex(pubkey);
    ASSERT_STR_EQ(ETH_BIP44_PUBKEY_HEX, pubkeyHex);
}

TEST_CASE(CoinAddresses, ETH_BIP44_Address) {
    auto seed = getTestSeed();
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    auto derivedResult = masterResult.value.derivePath("m/44'/60'/0'/0/0");
    ASSERT_OK(derivedResult);

    auto pubkey = derivedResult.value.publicKey();

    // Generate Ethereum address from compressed pubkey (C++ API)
    auto addrResult = ethereumAddress(pubkey);
    ASSERT_OK(addrResult);

    // Compare case-insensitively (EIP-55 checksum may differ in case)
    ASSERT_STR_EQ(toLower(ETH_BIP44_ADDRESS), toLower(addrResult.value));
}

TEST_CASE(CoinAddresses, ETH_BIP44_Address_CAPI) {
    auto seed = getTestSeed();
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    auto derivedResult = masterResult.value.derivePath("m/44'/60'/0'/0/0");
    ASSERT_OK(derivedResult);

    auto pubkey = derivedResult.value.publicKey();

    // C API
    char address[128] = {0};
    int32_t rc = hd_eth_address(
        pubkey.data(), pubkey.size(),
        address, sizeof(address)
    );
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);

    // Compare case-insensitively
    ASSERT_STR_EQ(toLower(ETH_BIP44_ADDRESS), toLower(std::string(address)));
}

TEST_CASE(CoinAddresses, ETH_MultipleAccounts) {
    auto seed = getTestSeed();
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    std::string addresses[3];
    for (uint32_t account = 0; account < 3; ++account) {
        std::string path = "m/44'/60'/" + std::to_string(account) + "'/0/0";
        auto derivedResult = masterResult.value.derivePath(path);
        ASSERT_OK(derivedResult);

        auto pubkey = derivedResult.value.publicKey();
        auto addrResult = ethereumAddress(pubkey);
        ASSERT_OK(addrResult);
        addresses[account] = addrResult.value;
    }

    // All addresses must be different
    ASSERT_NE(addresses[0], addresses[1]);
    ASSERT_NE(addresses[1], addresses[2]);
    ASSERT_NE(addresses[0], addresses[2]);
}

// =============================================================================
// Solana Tests (using C API — C++ wrappers not yet implemented)
// =============================================================================

TEST_CASE(CoinAddresses, SOL_SLIP10_FullPipeline_CAPI) {
    auto seed = getTestSeed();

    // SLIP-10 Ed25519 derivation via C API: m/44'/501'/0'/0'
    uint8_t key_out[32] = {0};
    uint8_t chain_code_out[32] = {0};
    int32_t rc = hd_slip10_ed25519_derive_path(
        seed.data(), seed.size(),
        "m/44'/501'/0'/0'",
        key_out, chain_code_out
    );
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);

    // Derive Ed25519 pubkey from the derived key
    uint8_t pubkey_out[32] = {0};
    rc = hd_ed25519_pubkey_from_seed(key_out, pubkey_out, 32);
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);

    // Generate Solana address (C++ API)
    Bytes32 pubkey32;
    std::copy(pubkey_out, pubkey_out + 32, pubkey32.begin());
    auto addrResult = solanaAddress(pubkey32);
    ASSERT_OK(addrResult);
    ASSERT_STR_EQ(SOL_ADDRESS, addrResult.value);
}

TEST_CASE(CoinAddresses, SOL_Address_CAPI) {
    auto seed = getTestSeed();

    // Full C API pipeline
    uint8_t key_out[32] = {0};
    uint8_t chain_code_out[32] = {0};
    int32_t rc = hd_slip10_ed25519_derive_path(
        seed.data(), seed.size(),
        "m/44'/501'/0'/0'",
        key_out, chain_code_out
    );
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);

    uint8_t pubkey_out[32] = {0};
    rc = hd_ed25519_pubkey_from_seed(key_out, pubkey_out, 32);
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);

    // C API for address
    char address[128] = {0};
    rc = hd_sol_address(pubkey_out, 32, address, sizeof(address));
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);
    ASSERT_STR_EQ(SOL_ADDRESS, std::string(address));
}

TEST_CASE(CoinAddresses, SOL_MultipleAccounts_CAPI) {
    auto seed = getTestSeed();

    std::string addresses[3];
    for (uint32_t account = 0; account < 3; ++account) {
        std::string path = "m/44'/501'/" + std::to_string(account) + "'/0'";

        uint8_t key_out[32] = {0};
        uint8_t chain_code_out[32] = {0};
        int32_t rc = hd_slip10_ed25519_derive_path(
            seed.data(), seed.size(),
            path.c_str(),
            key_out, chain_code_out
        );
        ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);

        uint8_t pubkey_out[32] = {0};
        rc = hd_ed25519_pubkey_from_seed(key_out, pubkey_out, 32);
        ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);

        char address[128] = {0};
        rc = hd_sol_address(pubkey_out, 32, address, sizeof(address));
        ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);
        addresses[account] = std::string(address);
    }

    // All addresses must be different
    ASSERT_NE(addresses[0], addresses[1]);
    ASSERT_NE(addresses[1], addresses[2]);
    ASSERT_NE(addresses[0], addresses[2]);
}

// =============================================================================
// Cross-chain: all three from same mnemonic
// =============================================================================

TEST_CASE(CoinAddresses, AllChains_FromSameMnemonic) {
    auto seed = getTestSeed();

    // BTC: m/84'/0'/0'/0/0 -> P2WPKH
    auto masterResult = ExtendedKey::fromSeed(seed);
    ASSERT_OK(masterResult);

    auto btcDerived = masterResult.value.derivePath("m/84'/0'/0'/0/0");
    ASSERT_OK(btcDerived);
    auto btcPubkey = btcDerived.value.publicKey();
    auto btcAddr = bitcoinP2WPKH(btcPubkey);
    ASSERT_OK(btcAddr);
    ASSERT_STR_EQ(BTC_BIP84_P2WPKH_ADDRESS, btcAddr.value);

    // ETH: m/44'/60'/0'/0/0
    auto ethDerived = masterResult.value.derivePath("m/44'/60'/0'/0/0");
    ASSERT_OK(ethDerived);
    auto ethPubkey = ethDerived.value.publicKey();
    auto ethAddr = ethereumAddress(ethPubkey);
    ASSERT_OK(ethAddr);
    ASSERT_STR_EQ(toLower(ETH_BIP44_ADDRESS), toLower(ethAddr.value));

    // SOL: m/44'/501'/0'/0' (SLIP-10 via C API)
    uint8_t sol_key[32] = {0};
    uint8_t sol_cc[32] = {0};
    int32_t rc = hd_slip10_ed25519_derive_path(
        seed.data(), seed.size(),
        "m/44'/501'/0'/0'",
        sol_key, sol_cc
    );
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);

    uint8_t sol_pubkey[32] = {0};
    rc = hd_ed25519_pubkey_from_seed(sol_key, sol_pubkey, 32);
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);

    char sol_addr[128] = {0};
    rc = hd_sol_address(sol_pubkey, 32, sol_addr, sizeof(sol_addr));
    ASSERT_EQ(static_cast<int32_t>(Error::OK), rc);
    ASSERT_STR_EQ(SOL_ADDRESS, std::string(sol_addr));
}

// =============================================================================
// C ABI error convention (2.1.1): an export whose success is a value (1/0 for
// a verify, a word index, a count) fails with a negative -Error code, never a
// positive one a caller could read as "valid" or as a count.
// =============================================================================

TEST_CASE(CoinAddresses, VerifyExports_FailWithNegativeCodes) {
    const int32_t invalidArgument = -static_cast<int32_t>(Error::INVALID_ARGUMENT);
    const uint8_t message[4] = {'t', 'e', 's', 't'};
    const uint8_t signature[65] = {0};
    const uint8_t publicKey[33] = {0x02};

    ASSERT_EQ(invalidArgument, hd_btc_verify_message(nullptr, signature, 65, "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2", 0));
    ASSERT_EQ(invalidArgument, hd_eth_verify_message(nullptr, 0, signature, 65, "0x0000000000000000000000000000000000000000"));
    ASSERT_EQ(invalidArgument, hd_coin_verify_message(0, nullptr, 0, signature, 65, publicKey, 33));
    ASSERT_EQ(invalidArgument, hd_cosmos_verify_signature(nullptr, 0, signature, 64, publicKey, 33));
    ASSERT_EQ(invalidArgument, hd_dot_verify_message(nullptr, 0, signature, 64, publicKey, 32));
    ASSERT_EQ(invalidArgument, hd_sol_verify_message(nullptr, 0, signature, 64, publicKey, 32));

    // An unknown coin type is an error, not "valid" (1) or "invalid" (0).
    ASSERT_TRUE(hd_coin_verify_message(0x7fffffff, message, sizeof(message), signature, 65, publicKey, 33) < 0);

}

TEST_CASE(CoinAddresses, MnemonicWordExports_FailWithNegativeCodes) {
    char suggestions[256] = {0};

    // Index of a known word; -1 for an unknown word; -Error otherwise.
    ASSERT_EQ(0, bip39::hd_mnemonic_check_word("abandon", 0));
    ASSERT_EQ(-1, bip39::hd_mnemonic_check_word("notaword", 0));
    ASSERT_EQ(-static_cast<int32_t>(Error::NOT_SUPPORTED), bip39::hd_mnemonic_check_word("abandon", 99));
    ASSERT_EQ(-static_cast<int32_t>(Error::INVALID_ARGUMENT), bip39::hd_mnemonic_check_word(nullptr, 0));

    // A count of suggestions, or -Error.
    ASSERT_TRUE(bip39::hd_mnemonic_suggest_word("aban", 0, suggestions, sizeof(suggestions), 5) >= 1);
    ASSERT_EQ(-static_cast<int32_t>(Error::NOT_SUPPORTED),
              bip39::hd_mnemonic_suggest_word("aban", 99, suggestions, sizeof(suggestions), 5));
    ASSERT_EQ(-static_cast<int32_t>(Error::INVALID_ARGUMENT),
              bip39::hd_mnemonic_suggest_word("a", 0, suggestions, 2, 50));
}
