#include "hd_wallet/password_profile.h"

#if defined(HD_WALLET_PASSWORD_PROFILE_TESTING) && HD_WALLET_PASSWORD_PROFILE_TESTING
#include "password_profile_internal.h"
#endif

#include <cryptopp/cryptlib.h>
#include <cryptopp/hkdf.h>
#include <cryptopp/scrypt.h>
#include <cryptopp/sha.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <new>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace hd_wallet::sdn {
namespace {

using Backend = void (*)(std::span<const uint8_t>,
                         std::span<const uint8_t>,
                         std::span<uint8_t>);

constexpr size_t kUsernameMaxBytes = 256;
constexpr size_t kPasswordMaxBytes = 256;
constexpr size_t kPasswordMinScalars = 12;
constexpr size_t kPasswordMaxScalars = 128;
constexpr size_t kLegacyMaxBytes = 4096;
#if !HD_WALLET_FIPS_MODE
constexpr std::string_view kScryptSaltLabel =
    "sdn-hd-wallet/password-scrypt-v2";
#endif

#include "common_passwords_sdn_v1.inc"

void wipeSeed(SecureVector<uint8_t>& seed) noexcept {
    if (!seed.empty()) secureWipe(seed.data(), seed.size());
}

bool decodeStrictUtf8(std::span<const uint8_t> input,
                      SecureVector<uint32_t>& scalars) {
    scalars.clear();
    scalars.reserve(input.size());
    size_t position = 0;
    while (position < input.size()) {
        const uint8_t first = input[position++];
        uint32_t scalar = 0;
        size_t continuationCount = 0;

        if (first <= 0x7f) {
            scalar = first;
        } else if (first >= 0xc2 && first <= 0xdf) {
            scalar = first & 0x1f;
            continuationCount = 1;
        } else if (first >= 0xe0 && first <= 0xef) {
            if (position >= input.size()) return false;
            const uint8_t second = input[position];
            if ((first == 0xe0 && second < 0xa0) ||
                (first == 0xed && second >= 0xa0)) return false;
            scalar = first & 0x0f;
            continuationCount = 2;
        } else if (first >= 0xf0 && first <= 0xf4) {
            if (position >= input.size()) return false;
            const uint8_t second = input[position];
            if ((first == 0xf0 && second < 0x90) ||
                (first == 0xf4 && second >= 0x90)) return false;
            scalar = first & 0x07;
            continuationCount = 3;
        } else {
            return false;
        }

        if (input.size() - position < continuationCount) return false;
        for (size_t i = 0; i < continuationCount; ++i) {
            const uint8_t continuation = input[position++];
            if ((continuation & 0xc0) != 0x80) return false;
            scalar = (scalar << 6) | (continuation & 0x3f);
        }
        scalars.push_back(scalar);
    }
    return true;
}

bool isUsernameFirst(uint8_t byte) {
    return (byte >= 'a' && byte <= 'z') || (byte >= '0' && byte <= '9');
}

bool isUsernameRest(uint8_t byte) {
    return isUsernameFirst(byte) || byte == '.' || byte == '_' || byte == '-';
}

bool isForbiddenPasswordScalar(uint32_t scalar) {
    return scalar <= 0x1f || (scalar >= 0x7f && scalar <= 0x9f);
}

bool isPasswordWhitespace(uint32_t scalar) {
    return scalar == 0x0020 || scalar == 0x00a0 || scalar == 0x1680 ||
           (scalar >= 0x2000 && scalar <= 0x200a) || scalar == 0x2028 ||
           scalar == 0x2029 || scalar == 0x202f || scalar == 0x205f ||
           scalar == 0x3000;
}

bool isCommonAsciiPassword(std::span<const uint8_t> password) {
    if (std::any_of(password.begin(), password.end(),
                    [](uint8_t byte) { return byte > 0x7f; })) return false;

    size_t begin = 0;
    size_t end = password.size();
    while (begin < end && password[begin] == 0x20) ++begin;
    while (end > begin && password[end - 1] == 0x20) --end;

    SecureVector<uint8_t> folded;
    folded.reserve(end - begin);
    for (size_t i = begin; i < end; ++i) {
        uint8_t byte = password[i];
        if (byte >= 'A' && byte <= 'Z') byte = static_cast<uint8_t>(byte + ('a' - 'A'));
        folded.push_back(byte);
    }
    if (folded.empty()) return false;
    const std::string_view candidate(
        reinterpret_cast<const char*>(folded.data()), folded.size());
    return std::binary_search(kCommonPasswordsSdnV1.begin(),
                              kCommonPasswordsSdnV1.end(), candidate);
}

void realScrypt(std::span<const uint8_t> password,
                std::span<const uint8_t> salt,
                std::span<uint8_t> output) {
    CryptoPP::Scrypt kdf;
    kdf.DeriveKey(output.data(), output.size(), password.data(), password.size(),
                  salt.data(), salt.size(), kScryptN, kScryptR, kScryptP);
}

const uint8_t* nonNullData(std::span<const uint8_t> input,
                           const uint8_t& emptyByte) {
    return input.empty() ? &emptyByte : input.data();
}

void realLegacy(std::span<const uint8_t> username,
                std::span<const uint8_t> password,
                std::span<uint8_t> output) {
    SecureBytes32 initial;
    SecureBytes32 master;
    CryptoPP::SHA256 hash;
    if (!username.empty()) hash.Update(username.data(), username.size());
    if (!password.empty()) hash.Update(password.data(), password.size());
    hash.Final(initial.data());

    const uint8_t emptyByte = 0;
    constexpr std::string_view masterInfo = "master-key";
    constexpr std::string_view seedInfo = "hd-wallet-seed";
    CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
    hkdf.DeriveKey(master.data(), master.size(), initial.data(), initial.size(),
                   nonNullData(username, emptyByte), username.size(),
                   reinterpret_cast<const uint8_t*>(masterInfo.data()), masterInfo.size());
    hkdf.DeriveKey(output.data(), output.size(), master.data(), master.size(),
                   &emptyByte, 0,
                   reinterpret_cast<const uint8_t*>(seedInfo.data()), seedInfo.size());
}

std::variant<PasswordSeed, PasswordError> derivePasswordSeedImpl(
    std::span<const uint8_t> username,
    std::span<const uint8_t> password,
    Backend backend) {
    auto canonicalResult = canonicalize_username(username);
    if (std::holds_alternative<PasswordError>(canonicalResult)) {
        return std::get<PasswordError>(canonicalResult);
    }

    if (password.size() > kPasswordMaxBytes) {
        return PasswordError::PasswordByteLength;
    }

    try {
        SecureVector<uint32_t> scalars;
        if (!decodeStrictUtf8(password, scalars)) return PasswordError::InvalidUtf8;
        if (std::any_of(scalars.begin(), scalars.end(), isForbiddenPasswordScalar)) {
            return PasswordError::InvalidPasswordScalar;
        }
        if (scalars.size() < kPasswordMinScalars || scalars.size() > kPasswordMaxScalars) {
            return PasswordError::PasswordLength;
        }
        if (std::all_of(scalars.begin(), scalars.end(), isPasswordWhitespace)) {
            return PasswordError::PasswordAllWhitespace;
        }
        if (isCommonAsciiPassword(password)) return PasswordError::CommonPassword;

#if defined(HD_WALLET_FIPS_MODE) && HD_WALLET_FIPS_MODE
        (void)backend;
        return PasswordError::KdfFailure;
#else
        std::string canonical = std::move(std::get<std::string>(canonicalResult));
        SecureVector<uint8_t> salt(kScryptSaltLabel.begin(), kScryptSaltLabel.end());
        salt.push_back(0);
        salt.insert(salt.end(), canonical.begin(), canonical.end());
        PasswordSeed result{std::move(canonical), SecureVector<uint8_t>(kSeedBytes)};
        backend(password, salt, result.bytes);
        return std::move(result);
#endif
    } catch (const CryptoPP::Exception&) {
        return PasswordError::KdfFailure;
    } catch (const std::bad_alloc&) {
        return PasswordError::KdfFailure;
    }
}

std::variant<PasswordSeed, PasswordError> deriveLegacyPasswordSeedImpl(
    std::span<const uint8_t> username,
    std::span<const uint8_t> password,
    Backend backend) {
    if (username.size() > kLegacyMaxBytes) return PasswordError::InvalidUsername;
    if (password.size() > kLegacyMaxBytes) return PasswordError::PasswordByteLength;

    try {
        SecureVector<uint32_t> usernameScalars;
        SecureVector<uint32_t> passwordScalars;
        if (!decodeStrictUtf8(username, usernameScalars)) return PasswordError::InvalidUtf8;
        if (!decodeStrictUtf8(password, passwordScalars)) return PasswordError::InvalidUtf8;

#if defined(HD_WALLET_FIPS_MODE) && HD_WALLET_FIPS_MODE
        (void)backend;
        return PasswordError::KdfFailure;
#else
        std::string exactUsername;
        if (!username.empty()) {
            exactUsername.assign(reinterpret_cast<const char*>(username.data()), username.size());
        }
        PasswordSeed result{std::move(exactUsername), SecureVector<uint8_t>(kSeedBytes)};
        backend(username, password, result.bytes);
        return std::move(result);
#endif
    } catch (const CryptoPP::Exception&) {
        return PasswordError::KdfFailure;
    } catch (const std::bad_alloc&) {
        return PasswordError::KdfFailure;
    }
}

} // namespace

PasswordSeed::PasswordSeed(std::string canonicalUsername,
                           SecureVector<uint8_t>&& seedBytes)
    : canonical_username(std::move(canonicalUsername)), bytes(std::move(seedBytes)) {}

PasswordSeed::PasswordSeed(PasswordSeed&& other) noexcept
    : canonical_username(std::move(other.canonical_username)),
      bytes(std::move(other.bytes)) {
    other.canonical_username.clear();
    other.bytes.clear();
}

PasswordSeed& PasswordSeed::operator=(PasswordSeed&& other) noexcept {
    if (this != &other) {
        wipeSeed(bytes);
        bytes.clear();
        canonical_username = std::move(other.canonical_username);
        bytes = std::move(other.bytes);
        other.canonical_username.clear();
        other.bytes.clear();
    }
    return *this;
}

PasswordSeed::~PasswordSeed() {
    wipeSeed(bytes);
}

std::variant<std::string, PasswordError>
canonicalize_username(std::span<const uint8_t> rawUtf8) {
    if (rawUtf8.size() > kUsernameMaxBytes) return PasswordError::InvalidUsername;
    try {
        SecureVector<uint32_t> scalars;
        if (!decodeStrictUtf8(rawUtf8, scalars)) return PasswordError::InvalidUtf8;

        size_t begin = 0;
        size_t end = rawUtf8.size();
        while (begin < end && rawUtf8[begin] == 0x20) ++begin;
        while (end > begin && rawUtf8[end - 1] == 0x20) --end;
        if (end - begin < 3 || end - begin > 64) return PasswordError::InvalidUsername;

        std::string canonical;
        canonical.reserve(end - begin);
        for (size_t i = begin; i < end; ++i) {
            uint8_t byte = rawUtf8[i];
            if (byte >= 'A' && byte <= 'Z') byte = static_cast<uint8_t>(byte + ('a' - 'A'));
            if ((i == begin && !isUsernameFirst(byte)) ||
                (i != begin && !isUsernameRest(byte))) {
                return PasswordError::InvalidUsername;
            }
            canonical.push_back(static_cast<char>(byte));
        }
        return std::move(canonical);
    } catch (const std::bad_alloc&) {
        return PasswordError::KdfFailure;
    }
}

std::variant<PasswordSeed, PasswordError> derive_password_seed(
    std::span<const uint8_t> usernameUtf8,
    std::span<const uint8_t> exactPasswordUtf8) {
    return derivePasswordSeedImpl(usernameUtf8, exactPasswordUtf8, realScrypt);
}

std::variant<PasswordSeed, PasswordError> derive_legacy_password_seed(
    std::span<const uint8_t> exactLegacyUsernameUtf8,
    std::span<const uint8_t> exactLegacyPasswordUtf8) {
    return deriveLegacyPasswordSeedImpl(exactLegacyUsernameUtf8,
                                        exactLegacyPasswordUtf8, realLegacy);
}

#if defined(HD_WALLET_PASSWORD_PROFILE_TESTING) && HD_WALLET_PASSWORD_PROFILE_TESTING
namespace internal {

std::variant<PasswordSeed, PasswordError> derive_password_seed(
    std::span<const uint8_t> usernameUtf8,
    std::span<const uint8_t> exactPasswordUtf8,
    ScryptBackend backend) {
    return derivePasswordSeedImpl(usernameUtf8, exactPasswordUtf8, backend);
}

std::variant<PasswordSeed, PasswordError> derive_legacy_password_seed(
    std::span<const uint8_t> exactLegacyUsernameUtf8,
    std::span<const uint8_t> exactLegacyPasswordUtf8,
    LegacyBackend backend) {
    return deriveLegacyPasswordSeedImpl(exactLegacyUsernameUtf8,
                                        exactLegacyPasswordUtf8, backend);
}

} // namespace internal
#endif

} // namespace hd_wallet::sdn
