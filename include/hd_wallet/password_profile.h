/**
 * @file password_profile.h
 * @brief Frozen SDN password credential derivation profiles.
 */

#ifndef HD_WALLET_PASSWORD_PROFILE_H
#define HD_WALLET_PASSWORD_PROFILE_H

#include "secure_memory.h"

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <variant>

namespace hd_wallet::sdn {

inline constexpr std::string_view kPasswordProfile = "password-scrypt-v2";
inline constexpr std::string_view kLegacyPasswordProfile =
    "password-fast-v1-legacy";
inline constexpr uint64_t kScryptN = 65536;
inline constexpr uint32_t kScryptR = 8;
inline constexpr uint32_t kScryptP = 1;
inline constexpr size_t kSeedBytes = 64;

enum class PasswordError {
    InvalidUtf8,
    InvalidUsername,
    InvalidPasswordScalar,
    PasswordLength,
    PasswordByteLength,
    PasswordAllWhitespace,
    CommonPassword,
    KdfFailure
};

struct PasswordSeed {
    std::string canonical_username;
    SecureVector<uint8_t> bytes;

    PasswordSeed(std::string canonical_username,
                 SecureVector<uint8_t>&& bytes);
    PasswordSeed(const PasswordSeed&) = delete;
    PasswordSeed& operator=(const PasswordSeed&) = delete;
    PasswordSeed(PasswordSeed&& other) noexcept;
    PasswordSeed& operator=(PasswordSeed&& other) noexcept;
    ~PasswordSeed();
};

std::variant<std::string, PasswordError>
canonicalize_username(std::span<const uint8_t> raw_utf8);

std::variant<PasswordSeed, PasswordError> derive_password_seed(
    std::span<const uint8_t> username_utf8,
    std::span<const uint8_t> exact_password_utf8);

std::variant<PasswordSeed, PasswordError> derive_legacy_password_seed(
    std::span<const uint8_t> exact_legacy_username_utf8,
    std::span<const uint8_t> exact_legacy_password_utf8);

} // namespace hd_wallet::sdn

#endif // HD_WALLET_PASSWORD_PROFILE_H
