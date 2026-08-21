#include "test_framework.h"

#include "hd_wallet/password_profile.h"
#include "password_profile_internal.h"

#include <cryptopp/cryptlib.h>

#include <algorithm>
#include <cstdint>
#include <new>
#include <span>
#include <string>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace {

using hd_wallet::sdn::PasswordError;
using hd_wallet::sdn::PasswordSeed;

std::span<const uint8_t> asBytes(const std::string& value) {
    return {reinterpret_cast<const uint8_t*>(value.data()), value.size()};
}

std::span<const uint8_t> asBytes(const std::vector<uint8_t>& value) {
    return {value.data(), value.size()};
}

std::vector<uint8_t> bytes(std::initializer_list<uint8_t> value) {
    return std::vector<uint8_t>(value);
}

PasswordError errorOf(const std::variant<std::string, PasswordError>& result) {
    ASSERT_TRUE(std::holds_alternative<PasswordError>(result));
    return std::get<PasswordError>(result);
}

PasswordError errorOf(const std::variant<PasswordSeed, PasswordError>& result) {
    ASSERT_TRUE(std::holds_alternative<PasswordError>(result));
    return std::get<PasswordError>(result);
}

void assertError(PasswordError expected,
                 const std::variant<std::string, PasswordError>& result) {
    ASSERT_TRUE(errorOf(result) == expected);
}

void assertError(PasswordError expected,
                 const std::variant<PasswordSeed, PasswordError>& result) {
    ASSERT_TRUE(errorOf(result) == expected);
}

std::string scalarUtf8(uint32_t scalar) {
    std::string result;
    if (scalar <= 0x7f) {
        result.push_back(static_cast<char>(scalar));
    } else if (scalar <= 0x7ff) {
        result.push_back(static_cast<char>(0xc0 | (scalar >> 6)));
        result.push_back(static_cast<char>(0x80 | (scalar & 0x3f)));
    } else if (scalar <= 0xffff) {
        result.push_back(static_cast<char>(0xe0 | (scalar >> 12)));
        result.push_back(static_cast<char>(0x80 | ((scalar >> 6) & 0x3f)));
        result.push_back(static_cast<char>(0x80 | (scalar & 0x3f)));
    } else {
        result.push_back(static_cast<char>(0xf0 | (scalar >> 18)));
        result.push_back(static_cast<char>(0x80 | ((scalar >> 12) & 0x3f)));
        result.push_back(static_cast<char>(0x80 | ((scalar >> 6) & 0x3f)));
        result.push_back(static_cast<char>(0x80 | (scalar & 0x3f)));
    }
    return result;
}

void deterministicScrypt(std::span<const uint8_t> password,
                         std::span<const uint8_t> salt,
                         std::span<uint8_t> output) {
    const std::string expectedPrefix = "sdn-hd-wallet/password-scrypt-v2";
    ASSERT_EQ(expectedPrefix.size() + 1 + std::string("alice_01").size(), salt.size());
    ASSERT_BYTES_EQ(expectedPrefix.data(), salt.data(), expectedPrefix.size());
    ASSERT_EQ(0, salt[expectedPrefix.size()]);
    ASSERT_BYTES_EQ("alice_01", salt.data() + expectedPrefix.size() + 1, 8);
    ASSERT_STR_EQ("Correct Horse Battery Staple!",
                  std::string(reinterpret_cast<const char*>(password.data()), password.size()));
    std::fill(output.begin(), output.end(), uint8_t{0x5a});
}

void deterministicLegacy(std::span<const uint8_t>,
                         std::span<const uint8_t>,
                         std::span<uint8_t> output) {
    std::fill(output.begin(), output.end(), uint8_t{0xa5});
}

void partialScryptCryptoFailure(std::span<const uint8_t>,
                                std::span<const uint8_t>,
                                std::span<uint8_t> output) {
    std::fill_n(output.begin(), std::min<size_t>(7, output.size()), uint8_t{0xee});
    throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "injected scrypt failure");
}

void partialScryptAllocationFailure(std::span<const uint8_t>,
                                    std::span<const uint8_t>,
                                    std::span<uint8_t> output) {
    std::fill_n(output.begin(), std::min<size_t>(7, output.size()), uint8_t{0xee});
    throw std::bad_alloc();
}

void partialLegacyCryptoFailure(std::span<const uint8_t>,
                                std::span<const uint8_t>,
                                std::span<uint8_t> output) {
    std::fill_n(output.begin(), std::min<size_t>(11, output.size()), uint8_t{0xdd});
    throw CryptoPP::Exception(CryptoPP::Exception::OTHER_ERROR, "injected legacy failure");
}

void partialLegacyAllocationFailure(std::span<const uint8_t>,
                                    std::span<const uint8_t>,
                                    std::span<uint8_t> output) {
    std::fill_n(output.begin(), std::min<size_t>(11, output.size()), uint8_t{0xdd});
    throw std::bad_alloc();
}

void backendMustNotRun(std::span<const uint8_t>,
                       std::span<const uint8_t>,
                       std::span<uint8_t>) {
    throw std::runtime_error("backend invoked in FIPS mode");
}

} // namespace

TEST_CASE(PasswordProfile, ConstantsAreFrozen) {
    ASSERT_STR_EQ("password-scrypt-v2", std::string(hd_wallet::sdn::kPasswordProfile));
    ASSERT_STR_EQ("password-fast-v1-legacy",
                  std::string(hd_wallet::sdn::kLegacyPasswordProfile));
    ASSERT_EQ(uint64_t{65536}, hd_wallet::sdn::kScryptN);
    ASSERT_EQ(uint32_t{8}, hd_wallet::sdn::kScryptR);
    ASSERT_EQ(uint32_t{1}, hd_wallet::sdn::kScryptP);
    ASSERT_EQ(size_t{64}, hd_wallet::sdn::kSeedBytes);
}

TEST_CASE(PasswordProfile, PasswordSeedIsMoveOnlyAndNothrowMovable) {
    static_assert(!std::is_copy_constructible_v<PasswordSeed>);
    static_assert(!std::is_copy_assignable_v<PasswordSeed>);
    static_assert(std::is_nothrow_move_constructible_v<PasswordSeed>);
    static_assert(std::is_nothrow_move_assignable_v<PasswordSeed>);

    hd_wallet::SecureVector<uint8_t> firstBytes{1, 2, 3, 4};
    PasswordSeed first{"first", std::move(firstBytes)};
    PasswordSeed second{std::move(first)};
    ASSERT_STR_EQ("first", second.canonical_username);
    ASSERT_EQ(size_t{4}, second.bytes.size());
    ASSERT_TRUE(first.canonical_username.empty());
    ASSERT_TRUE(first.bytes.empty());

    hd_wallet::SecureVector<uint8_t> replacementBytes{9, 8, 7};
    PasswordSeed replacement{"replacement", std::move(replacementBytes)};
    replacement = std::move(second);
    ASSERT_STR_EQ("first", replacement.canonical_username);
    ASSERT_EQ(size_t{4}, replacement.bytes.size());
    ASSERT_EQ(uint8_t{1}, replacement.bytes[0]);
    ASSERT_TRUE(second.canonical_username.empty());
    ASSERT_TRUE(second.bytes.empty());
}

TEST_CASE(PasswordProfile, UsernameCanonicalizationIsAsciiOnlyAndGrammarBounded) {
    auto canonical = hd_wallet::sdn::canonicalize_username(asBytes(std::string("  ALICE_01  ")));
    ASSERT_TRUE(std::holds_alternative<std::string>(canonical));
    ASSERT_STR_EQ("alice_01", std::get<std::string>(canonical));

    for (const std::string& accepted : {std::string("abc"), std::string(64, 'a'),
                                        std::string("a.b-c_d9")}) {
        ASSERT_TRUE(std::holds_alternative<std::string>(
            hd_wallet::sdn::canonicalize_username(asBytes(accepted))));
    }
    for (const std::string& rejected : {std::string("ab"), std::string(65, 'a'),
                                        std::string("-abc"), std::string("a+b"),
                                        std::string("a bc"), std::string("abc\t")}) {
        assertError(PasswordError::InvalidUsername,
                    hd_wallet::sdn::canonicalize_username(asBytes(rejected)));
    }

    const auto leadingNbsp = bytes({0xc2, 0xa0, 'a', 'b', 'c'});
    assertError(PasswordError::InvalidUsername,
                hd_wallet::sdn::canonicalize_username(asBytes(leadingNbsp)));
}

TEST_CASE(PasswordProfile, UsernameValidationIsStrictAndByteCapHasPrecedence) {
    const std::string atRawByteLimit = std::string(192, ' ') + std::string(64, 'A');
    auto atLimit = hd_wallet::sdn::canonicalize_username(asBytes(atRawByteLimit));
    ASSERT_TRUE(std::holds_alternative<std::string>(atLimit));
    ASSERT_STR_EQ(std::string(64, 'a'), std::get<std::string>(atLimit));

    const auto malformed = bytes({0xc0, 0xaf});
    assertError(PasswordError::InvalidUtf8,
                hd_wallet::sdn::canonicalize_username(asBytes(malformed)));

    std::vector<uint8_t> oversized(257, 'a');
    oversized[255] = 0xc0;
    oversized[256] = 0xaf;
    assertError(PasswordError::InvalidUsername,
                hd_wallet::sdn::canonicalize_username(asBytes(oversized)));
    assertError(PasswordError::InvalidUsername,
                hd_wallet::sdn::derive_password_seed(asBytes(oversized),
                                                      asBytes(std::string("Valid-Password-0001!"))));
}

TEST_CASE(PasswordProfile, V2ValidationOrderIsFrozen) {
    const std::string username = "review-owner";
    std::vector<uint8_t> oversizedPassword(257, 'x');
    oversizedPassword[255] = 0xc0;
    oversizedPassword[256] = 0xaf;
    assertError(PasswordError::PasswordByteLength,
                hd_wallet::sdn::derive_password_seed(asBytes(username),
                                                      asBytes(oversizedPassword)));

    std::string shortNul("A!\0xxxxxxxx", 11);
    assertError(PasswordError::InvalidPasswordScalar,
                hd_wallet::sdn::derive_password_seed(asBytes(username), asBytes(shortNul)));
    assertError(PasswordError::PasswordLength,
                hd_wallet::sdn::derive_password_seed(asBytes(username),
                                                      asBytes(std::string(11, ' '))));
    assertError(PasswordError::PasswordLength,
                hd_wallet::sdn::derive_password_seed(asBytes(username),
                                                      asBytes(std::string("PASSWORD"))));
}

TEST_CASE(PasswordProfile, PasswordRejectsMalformedUtf8AndForbiddenScalars) {
    const std::string username = "review-owner";
    auto malformed = bytes({'A', '!', 0xc0, 0xaf, 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x'});
    assertError(PasswordError::InvalidUtf8,
                hd_wallet::sdn::derive_password_seed(asBytes(username), asBytes(malformed)));

    const std::vector<uint32_t> forbidden = {
        0x0000, 0x0001, 0x001f, 0x007f, 0x0080, 0x009f
    };
    for (uint32_t scalar : forbidden) {
        std::string password = "Valid-Password";
        password += scalarUtf8(scalar);
        assertError(PasswordError::InvalidPasswordScalar,
                    hd_wallet::sdn::derive_password_seed(asBytes(username), asBytes(password)));
    }
}

TEST_CASE(PasswordProfile, PasswordScalarAndByteBoundsAreInclusive) {
    const std::string username = "review-owner";
    assertError(PasswordError::PasswordLength,
                hd_wallet::sdn::derive_password_seed(asBytes(username),
                                                      asBytes(std::string("A!") + std::string(9, 'x'))));
    assertError(PasswordError::PasswordLength,
                hd_wallet::sdn::derive_password_seed(asBytes(username),
                                                      asBytes(std::string("A!") + std::string(127, 'x'))));

#if !HD_WALLET_FIPS_MODE
    for (const size_t count : {size_t{12}, size_t{128}}) {
        const std::string password = "A!" + std::string(count - 2, 'x');
        auto result = hd_wallet::sdn::internal::derive_password_seed(
            asBytes(username), asBytes(password), deterministicLegacy);
        ASSERT_TRUE(std::holds_alternative<PasswordSeed>(result));
    }
#endif
}

TEST_CASE(PasswordProfile, ExactWhitespaceSetAndCommonCorpusAreEnforced) {
    const std::string username = "review-owner";
    const std::vector<uint32_t> whitespace = {
        0x0020, 0x00a0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003,
        0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
        0x2028, 0x2029, 0x202f, 0x205f, 0x3000
    };
    for (uint32_t scalar : whitespace) {
        std::string password;
        for (size_t i = 0; i < 12; ++i) password += scalarUtf8(scalar);
        assertError(PasswordError::PasswordAllWhitespace,
                    hd_wallet::sdn::derive_password_seed(asBytes(username), asBytes(password)));
    }

    assertError(PasswordError::CommonPassword,
                hd_wallet::sdn::derive_password_seed(asBytes(username),
                                                      asBytes(std::string("  PASSWORD  "))));
}

TEST_CASE(PasswordProfile, ScryptBackendReceivesExactPasswordSaltAndSeedSize) {
#if HD_WALLET_FIPS_MODE
    SKIP_TEST("non-FIPS backend contract");
#else
    auto result = hd_wallet::sdn::internal::derive_password_seed(
        asBytes(std::string("  ALICE_01  ")),
        asBytes(std::string("Correct Horse Battery Staple!")),
        deterministicScrypt);
    ASSERT_TRUE(std::holds_alternative<PasswordSeed>(result));
    auto& seed = std::get<PasswordSeed>(result);
    ASSERT_STR_EQ("alice_01", seed.canonical_username);
    ASSERT_EQ(hd_wallet::sdn::kSeedBytes, seed.bytes.size());
    ASSERT_TRUE(std::all_of(seed.bytes.begin(), seed.bytes.end(),
                            [](uint8_t byte) { return byte == 0x5a; }));
#endif
}

TEST_CASE(PasswordProfile, BackendExceptionsBecomeKdfFailureWithoutOutput) {
    const std::string username = "review-owner";
    const std::string password = "Valid-Password-0001!";
#if HD_WALLET_FIPS_MODE
    assertError(PasswordError::KdfFailure,
                hd_wallet::sdn::internal::derive_password_seed(
                    asBytes(username), asBytes(password), backendMustNotRun));
    assertError(PasswordError::KdfFailure,
                hd_wallet::sdn::internal::derive_legacy_password_seed(
                    asBytes(username), asBytes(password), backendMustNotRun));
#else
    for (auto backend : {partialScryptCryptoFailure, partialScryptAllocationFailure}) {
        auto result = hd_wallet::sdn::internal::derive_password_seed(
            asBytes(username), asBytes(password), backend);
        assertError(PasswordError::KdfFailure, result);
        ASSERT_FALSE(std::holds_alternative<PasswordSeed>(result));
    }
    for (auto backend : {partialLegacyCryptoFailure, partialLegacyAllocationFailure}) {
        auto result = hd_wallet::sdn::internal::derive_legacy_password_seed(
            asBytes(username), asBytes(password), backend);
        assertError(PasswordError::KdfFailure, result);
        ASSERT_FALSE(std::holds_alternative<PasswordSeed>(result));
    }
#endif
}

TEST_CASE(PasswordProfile, LegacyBoundsAndValidationPrecedenceAreFrozen) {
    const std::string validPassword = "legacy-password";
    const std::string validUsername = "legacy-user";
    const std::string maxBytes(4096, 'a');
    const std::string overBytes(4097, 'a');

#if !HD_WALLET_FIPS_MODE
    ASSERT_TRUE(std::holds_alternative<PasswordSeed>(
        hd_wallet::sdn::internal::derive_legacy_password_seed(
            asBytes(maxBytes), asBytes(validPassword), deterministicLegacy)));
    ASSERT_TRUE(std::holds_alternative<PasswordSeed>(
        hd_wallet::sdn::internal::derive_legacy_password_seed(
            asBytes(validUsername), asBytes(maxBytes), deterministicLegacy)));
#endif
    assertError(PasswordError::InvalidUsername,
                hd_wallet::sdn::internal::derive_legacy_password_seed(
                    asBytes(overBytes), asBytes(validPassword), backendMustNotRun));
    assertError(PasswordError::InvalidUsername,
                hd_wallet::sdn::internal::derive_legacy_password_seed(
                    asBytes(overBytes), asBytes(overBytes), backendMustNotRun));
    assertError(PasswordError::PasswordByteLength,
                hd_wallet::sdn::internal::derive_legacy_password_seed(
                    asBytes(validUsername), asBytes(overBytes), backendMustNotRun));

    std::vector<uint8_t> oversizedMalformed(4097, 'a');
    oversizedMalformed[4095] = 0xc0;
    oversizedMalformed[4096] = 0xaf;
    assertError(PasswordError::InvalidUsername,
                hd_wallet::sdn::internal::derive_legacy_password_seed(
                    asBytes(oversizedMalformed), asBytes(validPassword), backendMustNotRun));
    assertError(PasswordError::PasswordByteLength,
                hd_wallet::sdn::internal::derive_legacy_password_seed(
                    asBytes(validUsername), asBytes(oversizedMalformed), backendMustNotRun));

    const auto malformed = bytes({0xc0, 0xaf});
    assertError(PasswordError::PasswordByteLength,
                hd_wallet::sdn::internal::derive_legacy_password_seed(
                    asBytes(malformed), asBytes(overBytes), backendMustNotRun));
    assertError(PasswordError::InvalidUtf8,
                hd_wallet::sdn::internal::derive_legacy_password_seed(
                    asBytes(malformed), asBytes(validPassword), backendMustNotRun));
    assertError(PasswordError::InvalidUtf8,
                hd_wallet::sdn::internal::derive_legacy_password_seed(
                    asBytes(validUsername), asBytes(malformed), backendMustNotRun));
}

TEST_CASE(PasswordProfile, LegacyUsernameBytesArePreservedExactly) {
#if HD_WALLET_FIPS_MODE
    SKIP_TEST("legacy backend disabled in FIPS mode");
#else
    std::string username("  MiXeD\0", 8);
    username += scalarUtf8(0xfffe);
    username += "  ";
    auto result = hd_wallet::sdn::internal::derive_legacy_password_seed(
        asBytes(username), asBytes(std::string("legacy-password")), deterministicLegacy);
    ASSERT_TRUE(std::holds_alternative<PasswordSeed>(result));
    const auto& seed = std::get<PasswordSeed>(result);
    ASSERT_EQ(username.size(), seed.canonical_username.size());
    ASSERT_BYTES_EQ(username.data(), seed.canonical_username.data(), username.size());
#endif
}

TEST_CASE(PasswordProfile, LegacyEmptyCredentialsRemainValidUtf8) {
#if HD_WALLET_FIPS_MODE
    SKIP_TEST("legacy backend disabled in FIPS mode");
#else
    const std::string empty;
    auto result = hd_wallet::sdn::internal::derive_legacy_password_seed(
        asBytes(empty), asBytes(empty), deterministicLegacy);
    ASSERT_TRUE(std::holds_alternative<PasswordSeed>(result));
    const auto& seed = std::get<PasswordSeed>(result);
    ASSERT_TRUE(seed.canonical_username.empty());
    ASSERT_EQ(hd_wallet::sdn::kSeedBytes, seed.bytes.size());
#endif
}
