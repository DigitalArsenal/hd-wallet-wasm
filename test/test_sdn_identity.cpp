#include "test_framework.h"

#include "hd_wallet/sdn_identity.h"
#include "password_profile_internal.h"
#include "sdn_identity_internal.h"

#include <cryptopp/cryptlib.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <fstream>
#include <limits>
#include <new>
#include <span>
#include <string>
#include <thread>
#include <type_traits>
#include <variant>
#include <vector>

#ifndef TEST_VECTORS_PATH
#define TEST_VECTORS_PATH "."
#endif

namespace {

using namespace hd_wallet::sdn;

std::span<const uint8_t> bytes(const std::string& value) {
    return {reinterpret_cast<const uint8_t*>(value.data()), value.size()};
}

std::span<const uint8_t> bytes(const std::vector<uint8_t>& value) {
    return {value.data(), value.size()};
}

std::vector<uint8_t> hex(const std::string& value) {
    return test::hexToBytes(value);
}

template <typename T>
T take(IdentityOutcome<T>&& outcome) {
    ASSERT_TRUE(std::holds_alternative<T>(outcome));
    return std::move(std::get<T>(outcome));
}

template <typename T>
void assertError(IdentityError expected, const IdentityOutcome<T>& outcome) {
    ASSERT_TRUE(std::holds_alternative<IdentityError>(outcome));
    ASSERT_EQ(static_cast<uint16_t>(expected),
              static_cast<uint16_t>(std::get<IdentityError>(outcome)));
}

IdentityHandle deriveNew(uint32_t account = 0) {
    return take(derive_password_identity(
        bytes(std::string("  ALICE_01  ")),
        bytes(std::string("Correct Horse Battery Staple!")), account));
}

IdentityHandle deriveLegacy(uint32_t account = 0) {
    return take(derive_legacy_password_identity(
        bytes(std::string("fixture-legacy-user")),
        bytes(std::string("Fixture-Only-Legacy-Secret-0001!")), account));
}

IdentityHandle deriveMnemonic(uint32_t account = 0) {
    return take(import_legacy_mnemonic_identity(bytes(std::string(
        "abandon abandon abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon about")), account));
}

std::array<uint8_t, 32> array32(const std::string& value) {
    const auto decoded = hex(value);
    ASSERT_EQ(size_t{32}, decoded.size());
    std::array<uint8_t, 32> result{};
    std::copy(decoded.begin(), decoded.end(), result.begin());
    return result;
}

std::array<uint8_t, 12> array12(const std::string& value) {
    const auto decoded = hex(value);
    ASSERT_EQ(size_t{12}, decoded.size());
    std::array<uint8_t, 12> result{};
    std::copy(decoded.begin(), decoded.end(), result.begin());
    return result;
}

std::string readFixture(const std::string& name) {
    const std::string path = std::string(TEST_VECTORS_PATH) + "/" + name;
    std::ifstream input(path, std::ios::binary);
    if (!input) throw std::runtime_error("required fixture missing: " + path);
    return std::string(std::istreambuf_iterator<char>(input),
                       std::istreambuf_iterator<char>());
}

void assertDescriptor(const PublicKeyDescriptor& descriptor,
                      Purpose purpose,
                      hd_wallet::Curve curve,
                      KeyDerivation derivation,
                      const std::string& path,
                      const std::string& publicHex,
                      const std::string& keyId,
                      const std::optional<std::string>& signatureProfile) {
    ASSERT_EQ(static_cast<int>(purpose), static_cast<int>(descriptor.purpose));
    ASSERT_STR_EQ(std::string(kIdentityScheme), descriptor.identity_scheme);
    ASSERT_STR_EQ(std::string(kPasswordProfile), descriptor.seed_profile);
    ASSERT_EQ(static_cast<int>(curve), static_cast<int>(descriptor.curve));
    ASSERT_EQ(static_cast<int>(derivation), static_cast<int>(descriptor.derivation));
    ASSERT_EQ(static_cast<int>(KeyEncoding::Raw), static_cast<int>(descriptor.encoding));
    ASSERT_STR_EQ(path, descriptor.path);
    const auto expected = hex(publicHex);
    ASSERT_EQ(expected.size(), descriptor.public_key.size());
    ASSERT_BYTES_EQ(expected.data(), descriptor.public_key.data(), expected.size());
    ASSERT_STR_EQ(keyId, descriptor.key_id);
    ASSERT_TRUE(descriptor.signature_profile == signatureProfile);
    ASSERT_FALSE(descriptor.bip32_fingerprint.has_value());
}

void partialCryptoOutput(std::span<uint8_t> output) {
    std::fill_n(output.begin(), std::min<size_t>(7, output.size()), uint8_t{0xa5});
    throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "injected");
}

void partialAllocationOutput(std::span<uint8_t> output) {
    std::fill_n(output.begin(), std::min<size_t>(11, output.size()), uint8_t{0x5a});
    throw std::bad_alloc();
}

void partialDerivationCrypto(std::span<const uint8_t>,
                             std::span<const uint8_t>,
                             std::span<uint8_t, 64> output) {
    partialCryptoOutput(output);
}

void partialDerivationAllocation(std::span<const uint8_t>,
                                 std::span<const uint8_t>,
                                 std::span<uint8_t, 64> output) {
    partialAllocationOutput(output);
}

void partialSigningCrypto(std::span<const uint8_t, 32>,
                          std::span<const uint8_t>,
                          std::span<uint8_t, 64> output) {
    partialCryptoOutput(output);
}

void partialSigningAllocation(std::span<const uint8_t, 32>,
                              std::span<const uint8_t>,
                              std::span<uint8_t, 64> output) {
    partialAllocationOutput(output);
}

void partialHkdfCrypto(std::span<const uint8_t>,
                       std::span<const uint8_t>,
                       std::span<const uint8_t>,
                       std::span<uint8_t> output) {
    partialCryptoOutput(output);
}

void partialHkdfAllocation(std::span<const uint8_t>,
                           std::span<const uint8_t>,
                           std::span<const uint8_t>,
                           std::span<uint8_t> output) {
    partialAllocationOutput(output);
}

void partialPasswordCrypto(std::span<const uint8_t>,
                           std::span<const uint8_t>,
                           std::span<uint8_t> output) {
    partialCryptoOutput(output);
}

void partialPasswordAllocation(std::span<const uint8_t>,
                               std::span<const uint8_t>,
                               std::span<uint8_t> output) {
    partialAllocationOutput(output);
}

void partialAeadSealCrypto(std::span<const uint8_t, 32>,
                           std::span<const uint8_t, 12>,
                           std::span<const uint8_t>,
                           std::span<const uint8_t>,
                           std::span<uint8_t> output) {
    partialCryptoOutput(output);
}

void partialAeadSealAllocation(std::span<const uint8_t, 32>,
                               std::span<const uint8_t, 12>,
                               std::span<const uint8_t>,
                               std::span<const uint8_t>,
                               std::span<uint8_t> output) {
    partialAllocationOutput(output);
}

bool partialAeadOpenCrypto(std::span<const uint8_t, 32>,
                           std::span<const uint8_t, 12>,
                           std::span<const uint8_t>,
                           std::span<const uint8_t>,
                           std::span<uint8_t> output) {
    partialCryptoOutput(output);
    return false;
}

bool partialAeadOpenAllocation(std::span<const uint8_t, 32>,
                               std::span<const uint8_t, 12>,
                               std::span<const uint8_t>,
                               std::span<const uint8_t>,
                               std::span<uint8_t> output) {
    partialAllocationOutput(output);
    return false;
}

std::atomic<size_t> wipeCalls{0};
std::atomic<size_t> wipedCapacity{0};
std::atomic<bool> wipesWereZero{true};
std::atomic<size_t> passwordWipeCalls{0};
std::atomic<size_t> passwordWipedCapacity{0};
std::atomic<bool> passwordWipesWereZero{true};

void observeWipe(size_t capacity, bool allZero) {
    wipeCalls.fetch_add(1, std::memory_order_relaxed);
    wipedCapacity.fetch_add(capacity, std::memory_order_relaxed);
    if (!allZero) wipesWereZero.store(false, std::memory_order_relaxed);
}

void observePasswordWipe(size_t capacity, bool allZero) {
    passwordWipeCalls.fetch_add(1, std::memory_order_relaxed);
    passwordWipedCapacity.fetch_add(capacity, std::memory_order_relaxed);
    if (!allZero) passwordWipesWereZero.store(false, std::memory_order_relaxed);
}

} // namespace

TEST_CASE(SdnIdentity, PublicAbiConstantsAndOpaqueTypesAreFrozen) {
    static_assert(std::is_same_v<IdentityHandle, uint64_t>);
    static_assert(static_cast<uint8_t>(Purpose::SdnAuthentication) == 1);
    static_assert(static_cast<uint8_t>(Purpose::ContactEncryption) == 2);
    static_assert(static_cast<uint8_t>(Purpose::AssetReviewApproval) == 3);
    static_assert(static_cast<uint8_t>(RegisteredOperation::SdnLoginV2) == 1);
    static_assert(static_cast<uint8_t>(RegisteredOperation::AssetReviewAuthorityActivation) == 2);
    static_assert(static_cast<uint8_t>(RegisteredOperation::AssetReviewDecision) == 3);
    static_assert(static_cast<uint8_t>(RegistryRowId::SdnNodeConsoleV2) == 1);
    static_assert(static_cast<uint8_t>(RegistryRowId::AssetReviewAuthorityActivation) == 2);
    static_assert(static_cast<uint8_t>(RegistryRowId::AssetReviewDecision) == 3);
    static_assert(static_cast<uint16_t>(IdentityError::InvalidUsername) == 1);
    static_assert(static_cast<uint16_t>(IdentityError::InvalidPassword) == 2);
    static_assert(static_cast<uint16_t>(IdentityError::CommonPassword) == 3);
    static_assert(static_cast<uint16_t>(IdentityError::KdfFailure) == 4);
    static_assert(static_cast<uint16_t>(IdentityError::InvalidMnemonic) == 5);
    static_assert(static_cast<uint16_t>(IdentityError::InvalidAccountIndex) == 6);
    static_assert(static_cast<uint16_t>(IdentityError::StaleHandle) == 7);
    static_assert(static_cast<uint16_t>(IdentityError::OperationNotAllowed) == 8);
    static_assert(static_cast<uint16_t>(IdentityError::InvalidRequest) == 9);
    static_assert(static_cast<uint16_t>(IdentityError::AuthenticationFailed) == 10);
    static_assert(static_cast<uint16_t>(IdentityError::CapacityExceeded) == 11);
    static_assert(static_cast<uint16_t>(IdentityError::CryptoFailure) == 12);
    static_assert(static_cast<uint16_t>(IdentityError::OutOfMemory) == 13);
    static_assert(static_cast<uint16_t>(IdentityError::FipsNotAllowed) == 14);
    static_assert(!std::is_copy_constructible_v<hd_wallet::sdn::internal::SecretBuffer>);
    static_assert(!std::is_copy_assignable_v<hd_wallet::sdn::internal::SecretBuffer>);
    static_assert(std::is_nothrow_move_constructible_v<hd_wallet::sdn::internal::SecretBuffer>);
    static_assert(std::is_nothrow_move_assignable_v<hd_wallet::sdn::internal::SecretBuffer>);
    static_assert(!std::is_copy_constructible_v<hd_wallet::sdn::internal::DerivedIdentityMaterial>);
    static_assert(!std::is_copy_assignable_v<hd_wallet::sdn::internal::DerivedIdentityMaterial>);
    static_assert(std::is_nothrow_move_constructible_v<hd_wallet::sdn::internal::DerivedIdentityMaterial>);
    static_assert(std::is_nothrow_move_assignable_v<hd_wallet::sdn::internal::DerivedIdentityMaterial>);
    static_assert(!std::is_copy_constructible_v<PasswordSeed>);
    static_assert(!std::is_copy_assignable_v<PasswordSeed>);
    static_assert(std::is_nothrow_move_constructible_v<PasswordSeed>);
    static_assert(std::is_nothrow_move_assignable_v<PasswordSeed>);

    ASSERT_STR_EQ("sdn-bip32-slip10-purpose-v1", std::string(kIdentityScheme));
    ASSERT_STR_EQ("sdn-fast-password-auth-v1-legacy",
                  std::string(kLegacyFastIdentityScheme));
    ASSERT_STR_EQ("sdn-bip39-auth-v1-legacy",
                  std::string(kLegacyMnemonicIdentityScheme));
    ASSERT_STR_EQ("bip39-mnemonic-v1-legacy",
                  std::string(kLegacyMnemonicSeedProfile));
}

TEST_CASE(SdnIdentity, NewAccountsExposeExactPurposeSeparatedDescriptors) {
#if HD_WALLET_FIPS_MODE
    assertError(IdentityError::FipsNotAllowed,
                derive_password_identity(bytes(std::string("alice_01")),
                                         bytes(std::string("Correct Horse Battery Staple!")), 0));
#else
    const std::array<std::string, 2> xpubs = {
        "xpub6D9SXNXfAWtnHw8uWqUwMCBFh4R5bvzzWWemXtzwNhojQnYXyQARwhphkvtN4AJ93QFhzzHQZHj7MYQ7KuQ8vsXiTEwUq6MiF7iaLXTPFRT",
        "xpub6D9SXNXfAWtnLsmiHP7yjWHAmZoYMgp6yWLMr42BWdpgyE6mTNAukCm2PW5AdEG33RTxNgKg42cUE69zrundhquxbWj8sHe2jxtDb3VFoT4",
    };
    const std::array<std::string, 2> peers = {
        "16Uiu2HAkzgWPa6HTtNTU8WQi1kppaRsYUDBxNKygQNYUk7N73CMA",
        "16Uiu2HAm4ZJR19pVznz3KFcQYjjnyCwcspueFV19m7ca5CVPWy3b",
    };
    const std::array<std::string, 2> fingerprints = {"9b582711", "e8214de1"};
    const std::array<std::string, 2> auth = {
        "f5b8e91319472049d552f37d58f528eecefd68cfc4c462c6fcff279c76afb319",
        "999b912a96fde6be3e718f573c29f16cc97d13fd128c2eb6a7d089af7c0fc2b0",
    };
    const std::array<std::string, 2> authIds = {
        "sha256:d997ad2bf7dbf21c490695eba54d3054628d7f7fb9037fb8145ea32b4e384b7c",
        "sha256:72a40224fc9ba6c1ddeaa4f6da6cd53ab6015f591b76f77c984a6b7d4573b9ef",
    };
    const std::array<std::string, 2> contact = {
        "1349c6136a8765e4b2a8795037cc6233e22d31a08c76e328ad247daf836c6c0c",
        "d03c2cd449e689c1f93c17f53bc08cb3f55ecb5c3accf6c1e86b14e9bdf6a610",
    };
    const std::array<std::string, 2> contactIds = {
        "sha256:289fa9392a192258ac096b8596d8625d5824b5e5b5368072a5adf5d31c369e2b",
        "sha256:dbbdd815d1069051cc3e634923d9bc18483ca7274863734da4d21a8431f4951c",
    };
    const std::array<std::string, 2> approval = {
        "9210df41afc82babe9f512d781d6d7a8452060515117c00a28a12ce85ae1c6ff",
        "8225fc858d41aa082ac813b8b613dcc282e285090363de2ff80bff182eeb18d0",
    };
    const std::array<std::string, 2> approvalIds = {
        "sha256:150b5f54946e1a16d50eaadaaa5f6f12611a19bfbfcbec03157bdcebd4b2e27d",
        "sha256:791e490a08f2a1616fc7fd610e4a9a1f28fdfd0205c429ddeb7902420ec9ad14",
    };

    for (uint32_t account = 0; account < 2; ++account) {
        const auto handle = deriveNew(account);
        const PublicIdentity identity = take(describe_identity(handle));
        ASSERT_EQ(uint32_t{1}, identity.schema_version);
        ASSERT_STR_EQ(std::string(kIdentityScheme), identity.identity_scheme);
        ASSERT_STR_EQ(std::string(kPasswordProfile), identity.seed_profile);
        ASSERT_EQ(account, identity.account_index);
        ASSERT_FALSE(identity.account_label.has_value());
        ASSERT_STR_EQ(xpubs[account], identity.account_xpub);
        ASSERT_STR_EQ(peers[account], identity.account_peer_id);
        ASSERT_STR_EQ(fingerprints[account], test::bytesToHex(identity.account_fingerprint));
        ASSERT_EQ(size_t{3}, identity.keys.size());
        assertDescriptor(identity.keys[0], Purpose::AssetReviewApproval,
                         hd_wallet::Curve::ED25519, KeyDerivation::Slip10Ed25519,
                         "m/44'/0'/" + std::to_string(account) + "'/2'/0'",
                         approval[account], approvalIds[account],
                         std::string("ed25519-over-sha256-jcs-v1"));
        assertDescriptor(identity.keys[1], Purpose::ContactEncryption,
                         hd_wallet::Curve::X25519, KeyDerivation::Slip10X25519,
                         "m/44'/0'/" + std::to_string(account) + "'/1'/0'",
                         contact[account], contactIds[account],
                         std::nullopt);
        assertDescriptor(identity.keys[2], Purpose::SdnAuthentication,
                         hd_wallet::Curve::ED25519, KeyDerivation::Slip10Ed25519,
                         "m/44'/0'/" + std::to_string(account) + "'/0'/0'",
                         auth[account], authIds[account],
                         std::string("ed25519-over-sha256-jcs-v1"));
        destroy_identity(handle);
        assertError(IdentityError::StaleHandle, describe_identity(handle));
    }
#endif
}

TEST_CASE(SdnIdentity, LegacyFactoriesPreserveFrozenRootAndAuthOnlyShape) {
#if HD_WALLET_FIPS_MODE
    assertError(IdentityError::FipsNotAllowed,
                derive_legacy_password_identity(bytes(std::string("user")),
                                                bytes(std::string("password")), 0));
    assertError(IdentityError::FipsNotAllowed,
                import_legacy_mnemonic_identity(bytes(std::string("abandon")), 0));
#else
    struct Expected {
        bool mnemonic;
        uint32_t account;
        const char* scheme;
        const char* profile;
        const char* xpub;
        const char* peer;
        const char* fingerprint;
        const char* public_key;
        const char* key_id;
    };
    const Expected rows[] = {
        {false, 0, "sdn-fast-password-auth-v1-legacy", "password-fast-v1-legacy",
         "xpub661MyMwAqRbcEfyzy7yani8iGiX4LEVVYDjA2na9Lo9mxsi1jLShZ5Z6wM5KaCWVZ1sUDR9m1qLU7QpehwBTRMQqgLRVZwCTMPfTihVSmHj",
         "16Uiu2HAmFp8YKnXBybMTpeRaxrVL8R6xu8nPTsigvijdCRwi4FsC", "21e59eba",
         "019a0da9799107657f72d4ae3d5e483b51e7b46b0428f8695fc5412efdb178b4",
         "sha256:0d5b0e5c9371eea56a7c20ff27e6c0759d93c26794a4cea91c25f0ffafc4c1da"},
        {false, 1, "sdn-fast-password-auth-v1-legacy", "password-fast-v1-legacy",
         "xpub661MyMwAqRbcEfyzy7yani8iGiX4LEVVYDjA2na9Lo9mxsi1jLShZ5Z6wM5KaCWVZ1sUDR9m1qLU7QpehwBTRMQqgLRVZwCTMPfTihVSmHj",
         "16Uiu2HAmFp8YKnXBybMTpeRaxrVL8R6xu8nPTsigvijdCRwi4FsC", "21e59eba",
         "9128643341847661c3f05bc20245a9719bc98b29ea784ebe512ca2636b0c744b",
         "sha256:f39aaef64b015de3c01bbfd6561c86ea5cb9d4a822b0c982093646da353aafd5"},
        {true, 0, "sdn-bip39-auth-v1-legacy", "bip39-mnemonic-v1-legacy",
         "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8",
         "16Uiu2HAmTG7RvuHZSbFpFugPwQdSKG9weCGNvTaiJFbrUqiXZyMm", "73c5da0a",
         "3c35d187ea9428787cb3343d4a724fc961902012bbce5ce4f43369861e19127f",
         "sha256:840c4084865fc7153bcef07c5458e1bae11370539f3b9106542db552dcc10115"},
        {true, 1, "sdn-bip39-auth-v1-legacy", "bip39-mnemonic-v1-legacy",
         "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8",
         "16Uiu2HAmTG7RvuHZSbFpFugPwQdSKG9weCGNvTaiJFbrUqiXZyMm", "73c5da0a",
         "3525c32858ce80473ee9bdc1d580fde43bd6e640b8c19583f9160b2efc116e91",
         "sha256:b8aece28623ce188040068c43558930c6fe4eee83c6730ea680831c64cfd1072"},
    };
    for (const auto& row : rows) {
        const auto handle = row.mnemonic ? deriveMnemonic(row.account) : deriveLegacy(row.account);
        const auto identity = take(describe_identity(handle));
        ASSERT_EQ(uint32_t{1}, identity.schema_version);
        ASSERT_STR_EQ(row.scheme, identity.identity_scheme);
        ASSERT_STR_EQ(row.profile, identity.seed_profile);
        ASSERT_EQ(row.account, identity.account_index);
        ASSERT_FALSE(identity.account_label.has_value());
        ASSERT_STR_EQ(row.xpub, identity.account_xpub);
        ASSERT_STR_EQ(row.peer, identity.account_peer_id);
        ASSERT_STR_EQ(row.fingerprint, test::bytesToHex(identity.account_fingerprint));
        ASSERT_EQ(size_t{1}, identity.keys.size());
        const auto& descriptor = identity.keys.front();
        ASSERT_EQ(static_cast<int>(Purpose::SdnAuthentication),
                  static_cast<int>(descriptor.purpose));
        ASSERT_STR_EQ(row.scheme, descriptor.identity_scheme);
        ASSERT_STR_EQ(row.profile, descriptor.seed_profile);
        ASSERT_TRUE(descriptor.signature_profile ==
                    std::optional<std::string>("ed25519-raw-32-v1"));
        ASSERT_EQ(static_cast<int>(hd_wallet::Curve::ED25519),
                  static_cast<int>(descriptor.curve));
        ASSERT_EQ(static_cast<int>(KeyDerivation::LegacyBip32ScalarAsEd25519Seed),
                  static_cast<int>(descriptor.derivation));
        ASSERT_EQ(static_cast<int>(KeyEncoding::Raw),
                  static_cast<int>(descriptor.encoding));
        ASSERT_FALSE(descriptor.bip32_fingerprint.has_value());
        ASSERT_STR_EQ("m/44'/0'/" + std::to_string(row.account) + "'/0/0",
                      descriptor.path);
        ASSERT_STR_EQ(row.public_key, test::bytesToHex(descriptor.public_key));
        ASSERT_STR_EQ(row.key_id, descriptor.key_id);
        destroy_identity(handle);
    }

    const std::string oddSpacing =
        "\tABANDON\n abandon  abandon abandon abandon abandon abandon abandon "
        "abandon abandon abandon ABOUT\r\n";
    const auto normalized = take(import_legacy_mnemonic_identity(bytes(oddSpacing), 0));
    ASSERT_STR_EQ(rows[2].xpub, take(describe_identity(normalized)).account_xpub);
    destroy_identity(normalized);
#endif
}

TEST_CASE(SdnIdentity, FactoriesFailClosedWithDeterministicErrors) {
#if HD_WALLET_FIPS_MODE
    assertError(IdentityError::FipsNotAllowed,
                derive_password_identity(bytes(std::string("x")), bytes(std::string("x")), 99));
#else
    assertError(IdentityError::InvalidAccountIndex,
                derive_password_identity(bytes(std::string("alice_01")),
                                         bytes(std::string("Correct Horse Battery Staple!")), 2));
    assertError(IdentityError::InvalidUsername,
                derive_password_identity(bytes(std::string("x")),
                                         bytes(std::string("Correct Horse Battery Staple!")), 0));
    assertError(IdentityError::InvalidPassword,
                derive_password_identity(bytes(std::string("alice_01")),
                                         bytes(std::string("short")), 0));
    assertError(IdentityError::CommonPassword,
                derive_password_identity(bytes(std::string("alice_01")),
                                         bytes(std::string("  PASSWORD  ")), 0));
    const std::vector<uint8_t> malformedPassword = {0xc0, 0xaf};
    assertError(IdentityError::InvalidPassword,
                derive_password_identity(bytes(std::string("alice_01")),
                                         bytes(malformedPassword), 0));
    assertError(IdentityError::InvalidAccountIndex,
                derive_legacy_password_identity(bytes(std::string("u")),
                                                bytes(std::string("p")), 2));
    assertError(IdentityError::InvalidPassword,
                derive_legacy_password_identity(bytes(std::string("legacy-user")),
                                                bytes(malformedPassword), 0));
    assertError(IdentityError::InvalidMnemonic,
                import_legacy_mnemonic_identity(bytes(std::string(
                    "abandon abandon abandon abandon abandon abandon abandon abandon "
                    "abandon abandon abandon abandon")), 0));
    std::string nonAscii =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ";
    nonAscii += "\xc3\xa9";
    assertError(IdentityError::InvalidMnemonic,
                import_legacy_mnemonic_identity(bytes(nonAscii), 0));
    assertError(IdentityError::InvalidMnemonic,
                import_legacy_mnemonic_identity(bytes(std::string(1025, 'a')), 0));
#endif
}

TEST_CASE(SdnIdentity, HandleTableIsBoundedGenerationCheckedAndIdempotent) {
#if HD_WALLET_FIPS_MODE
    destroy_identity(0);
    assertError(IdentityError::StaleHandle, describe_identity(0));
#else
    std::vector<IdentityHandle> handles;
    handles.reserve(16);
    for (size_t i = 0; i < 16; ++i) handles.push_back(deriveLegacy(i % 2));
    assertError(IdentityError::CapacityExceeded,
                derive_legacy_password_identity(bytes(std::string("fixture-legacy-user")),
                                                bytes(std::string("Fixture-Only-Legacy-Secret-0001!")), 0));

    const IdentityHandle stale = handles[3];
    destroy_identity(stale);
    destroy_identity(stale);
    assertError(IdentityError::StaleHandle, describe_identity(stale));
    const IdentityHandle replacement = deriveLegacy(0);
    ASSERT_NE(stale, replacement);
    assertError(IdentityError::StaleHandle, describe_identity(stale));
    ASSERT_TRUE(std::holds_alternative<PublicIdentity>(describe_identity(replacement)));

    for (const auto handle : handles) destroy_identity(handle);
    destroy_identity(replacement);
    destroy_identity(UINT64_MAX);
#endif
}

TEST_CASE(SdnIdentity, ConcurrentDescribeAndDestroyNeverAliasesStaleState) {
#if !HD_WALLET_FIPS_MODE
    const IdentityHandle handle = deriveLegacy();
    std::array<uint8_t, 32> challenge{};
    std::atomic<bool> start{false};
    std::atomic<size_t> successes{0};
    std::atomic<size_t> stale{0};
    std::thread reader([&] {
        while (!start.load(std::memory_order_acquire)) {}
        for (size_t i = 0; i < 2000; ++i) {
            auto outcome = describe_identity(handle);
            if (std::holds_alternative<PublicIdentity>(outcome)) {
                ++successes;
            } else if (std::get<IdentityError>(outcome) == IdentityError::StaleHandle) {
                ++stale;
            } else {
                throw std::runtime_error("unexpected concurrent outcome");
            }
            auto signedOutcome = sign_sdn_login_v1(handle, challenge);
            if (std::holds_alternative<RawSignature>(signedOutcome)) {
                ++successes;
            } else if (std::get<IdentityError>(signedOutcome) ==
                       IdentityError::StaleHandle) {
                ++stale;
            } else {
                throw std::runtime_error("unexpected concurrent signing outcome");
            }
        }
    });
    start.store(true, std::memory_order_release);
    destroy_identity(handle);
    reader.join();
    ASSERT_TRUE(successes.load() + stale.load() == 4000);
    assertError(IdentityError::StaleHandle, describe_identity(handle));
#endif
}

TEST_CASE(SdnIdentity, RememberedWalletMatchesFrozenPositiveKatAndRestoresAtomically) {
    const std::string fixture = readFixture("sdn-remember-wallet-v2.json");
    ASSERT_TRUE(fixture.find("webauthn-prf-hkdf-sha256-aes256gcm-v2") != std::string::npos);
#if HD_WALLET_FIPS_MODE
    const auto prf = array32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto salt = array32("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    const auto nonce = array12("404142434445464748494a4b");
    const std::vector<uint8_t> empty;
    assertError(IdentityError::FipsNotAllowed,
                remember_wallet_seal(0, bytes(empty), prf, salt, nonce,
                                     bytes(std::string("{}"))));
    assertError(IdentityError::FipsNotAllowed,
                remember_wallet_open(bytes(empty), prf, salt, nonce,
                                     bytes(std::string("alice_01")), bytes(std::string("{}"))));
#else
    const auto prf = array32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto salt = array32("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    const auto nonce = array12("404142434445464748494a4b");
    const std::string aad =
        "{\"credentialIdBase64url\":\"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8\","
        "\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"schemaVersion\":2,"
        "\"seedProfile\":\"password-scrypt-v2\",\"storageProfile\":"
        "\"webauthn-prf-hkdf-sha256-aes256gcm-v2\",\"usernameSha256\":"
        "\"661eac7c194c79f1d07fb7f1570303d615debd059051059a1326344f748a727b\"}";
    const std::string expectedCiphertext =
        "097cf85a7e2500ce6b4038905bd0bcdf8d169729c9941622ecee486424ebddc8"
        "9780e4c6ede8f3fd701a341eaa1954d73cc5d47fb170b503e48df9e5ea01aec9"
        "b8610b95905eadbe66ab2456eae2e210037f6481b8b2e9ead5ed4f2dfe90583d3"
        "9cb96a50caedc4eb960539cdb24e350b504ac71c1d64726084a758791ba59faab"
        "02dccfcb41cc3cddcf4c897f7d9e67429322763e3ca8e9086a18c6f6bb15e9ca"
        "7c24814313b5d53f29aa892804660f11129655fe787b";

    const IdentityHandle handle = deriveNew();
    auto sealed = take(remember_wallet_seal(
        handle, bytes(std::string("Correct Horse Battery Staple!")), prf, salt,
        nonce, bytes(aad)));
    ASSERT_STR_EQ(expectedCiphertext, test::bytesToHex(sealed));
    destroy_identity(handle);

#if HD_WALLET_SDN_IDENTITY_TESTING
    wipeCalls = 0;
    wipedCapacity = 0;
    wipesWereZero = true;
    hd_wallet::sdn::internal::testing_set_wipe_observer(observeWipe);
#endif
    ImportedIdentity restored = take(remember_wallet_open(
        bytes(sealed), prf, salt, nonce, bytes(std::string("alice_01")), bytes(aad)));
#if HD_WALLET_SDN_IDENTITY_TESTING
    hd_wallet::sdn::internal::testing_set_wipe_observer(nullptr);
    ASSERT_TRUE(wipeCalls.load() >= 2);
    ASSERT_TRUE(wipedCapacity.load() >=
                sealed.size() - 16 + std::string("Correct Horse Battery Staple!").size());
    ASSERT_TRUE(wipesWereZero.load());
#endif
    ASSERT_NE(IdentityHandle{0}, restored.handle);
    ASSERT_STR_EQ(std::string(kIdentityScheme), restored.identity.identity_scheme);
    ASSERT_STR_EQ(std::string(kPasswordProfile), restored.identity.seed_profile);
    ASSERT_EQ(uint32_t{0}, restored.identity.account_index);
    ASSERT_STR_EQ(
        "xpub6D9SXNXfAWtnHw8uWqUwMCBFh4R5bvzzWWemXtzwNhojQnYXyQARwhphkvtN4AJ93QFhzzHQZHj7MYQ7KuQ8vsXiTEwUq6MiF7iaLXTPFRT",
        restored.identity.account_xpub);
    ASSERT_STR_EQ(restored.identity.account_xpub,
                  take(describe_identity(restored.handle)).account_xpub);
    destroy_identity(restored.handle);

    auto tampered = sealed;
    tampered.front() ^= 1;
    assertError(IdentityError::AuthenticationFailed,
                remember_wallet_open(bytes(tampered), prf, salt, nonce,
                                     bytes(std::string("alice_01")), bytes(aad)));
    const IdentityHandle wrongPasswordHandle = deriveNew();
    assertError(IdentityError::AuthenticationFailed,
                remember_wallet_seal(wrongPasswordHandle,
                                     bytes(std::string("Wrong Password Value!")),
                                     prf, salt, nonce, bytes(aad)));
    destroy_identity(wrongPasswordHandle);
#endif
}

TEST_CASE(SdnIdentity, RememberedWalletRejectsEveryBindingAndShapeConfusion) {
#if !HD_WALLET_FIPS_MODE
    const auto prf = array32("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto salt = array32("202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    const auto nonce = array12("404142434445464748494a4b");
    const std::string aad =
        "{\"credentialIdBase64url\":\"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8\","
        "\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"schemaVersion\":2,"
        "\"seedProfile\":\"password-scrypt-v2\",\"storageProfile\":"
        "\"webauthn-prf-hkdf-sha256-aes256gcm-v2\",\"usernameSha256\":"
        "\"661eac7c194c79f1d07fb7f1570303d615debd059051059a1326344f748a727b\"}";
    const auto ciphertext = hex(
        "097cf85a7e2500ce6b4038905bd0bcdf8d169729c9941622ecee486424ebddc89780e4c6ede8f3fd701a341eaa1954d73cc5d47fb170b503e48df9e5ea01aec9b8610b95905eadbe66ab2456eae2e210037f6481b8b2e9ead5ed4f2dfe90583d39cb96a50caedc4eb960539cdb24e350b504ac71c1d64726084a758791ba59faab02dccfcb41cc3cddcf4c897f7d9e67429322763e3ca8e9086a18c6f6bb15e9ca7c24814313b5d53f29aa892804660f11129655fe787b");

    auto wrongPrf = prf;
    wrongPrf[0] ^= 1;
    assertError(IdentityError::AuthenticationFailed,
                remember_wallet_open(bytes(ciphertext), wrongPrf, salt, nonce,
                                     bytes(std::string("alice_01")), bytes(aad)));
    auto wrongSalt = salt;
    wrongSalt[0] ^= 1;
    assertError(IdentityError::AuthenticationFailed,
                remember_wallet_open(bytes(ciphertext), prf, wrongSalt, nonce,
                                     bytes(std::string("alice_01")), bytes(aad)));
    auto wrongNonce = nonce;
    wrongNonce[0] ^= 1;
    assertError(IdentityError::AuthenticationFailed,
                remember_wallet_open(bytes(ciphertext), prf, salt, wrongNonce,
                                     bytes(std::string("alice_01")), bytes(aad)));
    auto wrongTag = ciphertext;
    wrongTag.back() ^= 1;
    assertError(IdentityError::AuthenticationFailed,
                remember_wallet_open(bytes(wrongTag), prf, salt, nonce,
                                     bytes(std::string("alice_01")), bytes(aad)));
    const std::string reboundAad =
        "{\"credentialIdBase64url\":\"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr0\","
        "\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"schemaVersion\":2,"
        "\"seedProfile\":\"password-scrypt-v2\",\"storageProfile\":"
        "\"webauthn-prf-hkdf-sha256-aes256gcm-v2\",\"usernameSha256\":"
        "\"661eac7c194c79f1d07fb7f1570303d615debd059051059a1326344f748a727b\"}";
    assertError(IdentityError::AuthenticationFailed,
                remember_wallet_open(bytes(ciphertext), prf, salt, nonce,
                                     bytes(std::string("alice_01")),
                                     bytes(reboundAad)));
    assertError(IdentityError::InvalidRequest,
                remember_wallet_open(bytes(ciphertext), prf, salt, nonce,
                                     bytes(std::string("ALICE_01")), bytes(aad)));
    assertError(IdentityError::InvalidRequest,
                remember_wallet_open(bytes(ciphertext), prf, salt, nonce,
                                     bytes(std::string("alice_01")), bytes(std::string("{}"))));
    const std::string noncanonicalAad = " " + aad;
    assertError(IdentityError::InvalidRequest,
                remember_wallet_open(bytes(ciphertext), prf, salt, nonce,
                                     bytes(std::string("alice_01")),
                                     bytes(noncanonicalAad)));
    const std::string badCredentialTail =
        "{\"credentialIdBase64url\":\"AB\","
        "\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"schemaVersion\":2,"
        "\"seedProfile\":\"password-scrypt-v2\",\"storageProfile\":"
        "\"webauthn-prf-hkdf-sha256-aes256gcm-v2\",\"usernameSha256\":"
        "\"661eac7c194c79f1d07fb7f1570303d615debd059051059a1326344f748a727b\"}";
    assertError(IdentityError::InvalidRequest,
                remember_wallet_open(bytes(ciphertext), prf, salt, nonce,
                                     bytes(std::string("alice_01")),
                                     bytes(badCredentialTail)));
    assertError(IdentityError::InvalidRequest,
                remember_wallet_open(std::span<const uint8_t>{}, prf, salt, nonce,
                                     bytes(std::string("alice_01")), bytes(aad)));
    const std::vector<uint8_t> tooLarge(1025, 0);
    assertError(IdentityError::InvalidRequest,
                remember_wallet_open(bytes(tooLarge), prf, salt, nonce,
                                     bytes(std::string("alice_01")), bytes(aad)));

    const IdentityHandle legacy = deriveLegacy();
    assertError(IdentityError::OperationNotAllowed,
                remember_wallet_seal(legacy, bytes(std::string("Fixture-Only-Legacy-Secret-0001!")),
                                     prf, salt, nonce, bytes(aad)));
    destroy_identity(legacy);
    const IdentityHandle accountOne = deriveNew(1);
    assertError(IdentityError::OperationNotAllowed,
                remember_wallet_seal(accountOne,
                                     bytes(std::string("Correct Horse Battery Staple!")),
                                     prf, salt, nonce, bytes(aad)));
    destroy_identity(accountOne);

#if HD_WALLET_SDN_IDENTITY_TESTING
    const auto wrappingKey = hex(
        "8f7504aae664d8ec10d03b4d3875012f28b176f3b1d31de97ddc308c51f1f78f");
    const auto forge = [&](const std::string& plaintext) {
        return take(hd_wallet::sdn::internal::testing_aes256_gcm_seal(
            bytes(wrappingKey),
            std::span<const uint8_t>(nonce.data(), nonce.size()),
            bytes(plaintext), bytes(aad)));
    };
    const std::array<std::string, 6> malformedPlaintexts = {
        " {\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"passwordBase64url\":\"Q29ycmVjdCBIb3JzZSBCYXR0ZXJ5IFN0YXBsZSE\",\"seedProfile\":\"password-scrypt-v2\",\"username\":\"alice_01\"}",
        "{\"extra\":null,\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"passwordBase64url\":\"Q29ycmVjdCBIb3JzZSBCYXR0ZXJ5IFN0YXBsZSE\",\"seedProfile\":\"password-scrypt-v2\",\"username\":\"alice_01\"}",
        "{\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"passwordBase64url\":\"Q29ycmVjdCBIb3JzZSBCYXR0ZXJ5IFN0YXBsZSE\",\"seedProfile\":\"password-scrypt-v2\",\"username\":\"alice_01\"}",
        "{\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"seedBase64url\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"seedProfile\":\"password-scrypt-v2\",\"username\":\"alice_01\"}",
        "{\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"passwordBase64url\":\"AB\",\"seedProfile\":\"password-scrypt-v2\",\"username\":\"alice_01\"}",
        "{\"identityScheme\":\"sdn-fast-password-auth-v1-legacy\",\"passwordBase64url\":\"Q29ycmVjdCBIb3JzZSBCYXR0ZXJ5IFN0YXBsZSE\",\"seedProfile\":\"password-fast-v1-legacy\",\"username\":\"alice_01\"}",
    };
    for (const auto& plaintext : malformedPlaintexts) {
        const auto forged = forge(plaintext);
        assertError(IdentityError::InvalidRequest,
                    remember_wallet_open(bytes(forged), prf, salt, nonce,
                                         bytes(std::string("alice_01")),
                                         bytes(aad)));
    }
#endif

    std::vector<IdentityHandle> fullTable;
    fullTable.reserve(16);
    for (size_t i = 0; i < 16; ++i) fullTable.push_back(deriveLegacy(i % 2));
    assertError(IdentityError::CapacityExceeded,
                remember_wallet_open(bytes(ciphertext), prf, salt, nonce,
                                     bytes(std::string("alice_01")), bytes(aad)));
    for (const auto occupied : fullTable) destroy_identity(occupied);
#endif
}

TEST_CASE(SdnIdentity, InjectedSecretFailuresWipeFullAllocationsAndNeverEscape) {
#if HD_WALLET_SDN_IDENTITY_TESTING && !HD_WALLET_FIPS_MODE
    using namespace hd_wallet::sdn::internal;
    const auto prf = array32(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
    const auto salt = array32(
        "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f");
    const auto nonce = array12("404142434445464748494a4b");
    const std::string username = "alice_01";
    const std::string password = "Correct Horse Battery Staple!";
    const std::string aad =
        "{\"credentialIdBase64url\":\"oKGio6SlpqeoqaqrrK2ur7CxsrO0tba3uLm6u7y9vr8\","
        "\"identityScheme\":\"sdn-bip32-slip10-purpose-v1\",\"schemaVersion\":2,"
        "\"seedProfile\":\"password-scrypt-v2\",\"storageProfile\":"
        "\"webauthn-prf-hkdf-sha256-aes256gcm-v2\",\"usernameSha256\":"
        "\"661eac7c194c79f1d07fb7f1570303d615debd059051059a1326344f748a727b\"}";
    const auto ciphertext = hex(
        "097cf85a7e2500ce6b4038905bd0bcdf8d169729c9941622ecee486424ebddc89780e4c6ede8f3fd701a341eaa1954d73cc5d47fb170b503e48df9e5ea01aec9b8610b95905eadbe66ab2456eae2e210037f6481b8b2e9ead5ed4f2dfe90583d39cb96a50caedc4eb960539cdb24e350b504ac71c1d64726084a758791ba59faab02dccfcb41cc3cddcf4c897f7d9e67429322763e3ca8e9086a18c6f6bb15e9ca7c24814313b5d53f29aa892804660f11129655fe787b");

    wipeCalls = 0;
    wipedCapacity = 0;
    wipesWereZero = true;
    testing_set_wipe_observer(observeWipe);
    const auto assertPasswordKdfFailure = [&](IdentityError expected,
                                              auto&& operation) {
        passwordWipeCalls = 0;
        passwordWipedCapacity = 0;
        passwordWipesWereZero = true;
        testing_set_password_wipe_observer(observePasswordWipe);
        auto outcome = operation();
        testing_set_password_wipe_observer(nullptr);
        assertError(expected, outcome);
        ASSERT_EQ(size_t{1}, passwordWipeCalls.load());
        ASSERT_EQ(size_t{64}, passwordWipedCapacity.load());
        ASSERT_TRUE(passwordWipesWereZero.load());
    };

    assertError(
        IdentityError::CryptoFailure,
        testing_derive_legacy_password_identity(
            bytes(std::string("fixture-legacy-user")),
            bytes(std::string("Fixture-Only-Legacy-Secret-0001!")), 0,
            partialDerivationCrypto));
    assertError(
        IdentityError::OutOfMemory,
        testing_derive_legacy_password_identity(
            bytes(std::string("fixture-legacy-user")),
            bytes(std::string("Fixture-Only-Legacy-Secret-0001!")), 0,
            partialDerivationAllocation));

    const IdentityHandle legacy = deriveLegacy();
    const std::array<uint8_t, 32> challenge{};
    assertError(IdentityError::CryptoFailure,
                testing_sign_sdn_login_v1(legacy, challenge,
                                          partialSigningCrypto));
    assertError(IdentityError::OutOfMemory,
                testing_sign_sdn_login_v1(legacy, challenge,
                                          partialSigningAllocation));
    ASSERT_TRUE(std::holds_alternative<PublicIdentity>(describe_identity(legacy)));
    destroy_identity(legacy);

    const IdentityHandle modern = deriveNew();
    assertPasswordKdfFailure(IdentityError::CryptoFailure, [&] {
        return testing_remember_wallet_seal_with_password_kdf(
            modern, bytes(password), prf, salt, nonce, bytes(aad),
            partialPasswordCrypto);
    });
    assertPasswordKdfFailure(IdentityError::OutOfMemory, [&] {
        return testing_remember_wallet_seal_with_password_kdf(
            modern, bytes(password), prf, salt, nonce, bytes(aad),
            partialPasswordAllocation);
    });
    assertError(IdentityError::CryptoFailure,
                testing_remember_wallet_seal_with_hkdf(
                    modern, bytes(password), prf, salt, nonce, bytes(aad),
                    partialHkdfCrypto));
    assertError(IdentityError::OutOfMemory,
                testing_remember_wallet_seal_with_hkdf(
                    modern, bytes(password), prf, salt, nonce, bytes(aad),
                    partialHkdfAllocation));
    assertError(IdentityError::CryptoFailure,
                testing_remember_wallet_seal_with_aead(
                    modern, bytes(password), prf, salt, nonce, bytes(aad),
                    partialAeadSealCrypto));
    assertError(IdentityError::OutOfMemory,
                testing_remember_wallet_seal_with_aead(
                    modern, bytes(password), prf, salt, nonce, bytes(aad),
                    partialAeadSealAllocation));
    ASSERT_TRUE(std::holds_alternative<PublicIdentity>(describe_identity(modern)));
    destroy_identity(modern);

    assertError(IdentityError::CryptoFailure,
                testing_remember_wallet_open_with_aead(
                    bytes(ciphertext), prf, salt, nonce, bytes(username), bytes(aad),
                    partialAeadOpenCrypto));
    assertError(IdentityError::OutOfMemory,
                testing_remember_wallet_open_with_aead(
                    bytes(ciphertext), prf, salt, nonce, bytes(username), bytes(aad),
                    partialAeadOpenAllocation));
    assertPasswordKdfFailure(IdentityError::CryptoFailure, [&] {
        return testing_remember_wallet_open_with_password_kdf(
            bytes(ciphertext), prf, salt, nonce, bytes(username), bytes(aad),
            partialPasswordCrypto);
    });
    assertPasswordKdfFailure(IdentityError::OutOfMemory, [&] {
        return testing_remember_wallet_open_with_password_kdf(
            bytes(ciphertext), prf, salt, nonce, bytes(username), bytes(aad),
            partialPasswordAllocation);
    });

    testing_set_wipe_observer(nullptr);
    ASSERT_TRUE(wipeCalls.load() >= 14);
    ASSERT_TRUE(wipedCapacity.load() >= 14 * 32);
    ASSERT_TRUE(wipesWereZero.load());

    // Every injected factory/open failed before publishing a table record.
    std::vector<IdentityHandle> handles;
    handles.reserve(16);
    for (size_t i = 0; i < 16; ++i) handles.push_back(deriveLegacy(i % 2));
    assertError(IdentityError::CapacityExceeded,
                derive_legacy_password_identity(
                    bytes(std::string("fixture-legacy-user")),
                    bytes(std::string("Fixture-Only-Legacy-Secret-0001!")), 0));
    for (const auto handle : handles) destroy_identity(handle);
#endif
}

TEST_CASE(SdnIdentity, ShortSecretTextNeverReliesOnStringInlineStorage) {
#if HD_WALLET_SDN_IDENTITY_TESTING && !HD_WALLET_FIPS_MODE
    using namespace hd_wallet::sdn::internal;
    wipeCalls = 0;
    wipedCapacity = 0;
    wipesWereZero = true;
    testing_set_wipe_observer(observeWipe);
    assertError(IdentityError::InvalidMnemonic,
                import_legacy_mnemonic_identity(bytes(std::string("abandon")), 0));
    testing_set_wipe_observer(nullptr);
    ASSERT_TRUE(wipeCalls.load() >= 1);
    ASSERT_TRUE(wipedCapacity.load() >= 7);
    ASSERT_TRUE(wipesWereZero.load());

    wipeCalls = 0;
    wipedCapacity = 0;
    wipesWereZero = true;
    testing_set_wipe_observer(observeWipe);
    const std::vector<uint8_t> minimumPassword(12, 'a');
    ASSERT_EQ(size_t{16}, testing_secret_base64url_lifecycle(bytes(minimumPassword)));
    testing_set_wipe_observer(nullptr);
    ASSERT_TRUE(wipeCalls.load() >= 1);
    ASSERT_TRUE(wipedCapacity.load() >= 16);
    ASSERT_TRUE(wipesWereZero.load());
#endif
}

TEST_CASE(SdnIdentity, GenerationOverflowRetiresSlotAndDestroyWipesLiveRecord) {
#if HD_WALLET_SDN_IDENTITY_TESTING && !HD_WALLET_FIPS_MODE
    using namespace hd_wallet::sdn::internal;
    const size_t retired_before = testing_retired_slot_count();
    ASSERT_TRUE(testing_set_empty_slot_generation(
        0, std::numeric_limits<uint32_t>::max()));
    const IdentityHandle terminal = deriveLegacy();
    ASSERT_EQ(uint32_t{1}, static_cast<uint32_t>(terminal));
    ASSERT_EQ(std::numeric_limits<uint32_t>::max(),
              static_cast<uint32_t>(terminal >> 32));

    wipeCalls = 0;
    wipedCapacity = 0;
    wipesWereZero = true;
    testing_set_wipe_observer(observeWipe);
    destroy_identity(terminal);
    testing_set_wipe_observer(nullptr);
    ASSERT_TRUE(wipeCalls.load() >= 2);
    ASSERT_TRUE(wipedCapacity.load() >= 96);
    ASSERT_TRUE(wipesWereZero.load());
    ASSERT_EQ(retired_before + 1, testing_retired_slot_count());
    assertError(IdentityError::StaleHandle, describe_identity(terminal));

    const IdentityHandle replacement = deriveLegacy();
    ASSERT_NE(uint32_t{1}, static_cast<uint32_t>(replacement));
    destroy_identity(replacement);
#endif
}
