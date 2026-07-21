/**
 * @file password_profile_internal.h
 * @brief Source-private password KDF injection seam for focused native tests.
 */

#ifndef HD_WALLET_PASSWORD_PROFILE_INTERNAL_H
#define HD_WALLET_PASSWORD_PROFILE_INTERNAL_H

#if defined(HD_WALLET_PASSWORD_PROFILE_TESTING) && HD_WALLET_PASSWORD_PROFILE_TESTING

#include "hd_wallet/password_profile.h"

#include <span>
#include <variant>

namespace hd_wallet::sdn::internal {

using ScryptBackend = void (*)(std::span<const uint8_t> password,
                               std::span<const uint8_t> salt,
                               std::span<uint8_t> output);
using LegacyBackend = void (*)(std::span<const uint8_t> username,
                               std::span<const uint8_t> password,
                               std::span<uint8_t> output);

std::variant<PasswordSeed, PasswordError> derive_password_seed(
    std::span<const uint8_t> username_utf8,
    std::span<const uint8_t> exact_password_utf8,
    ScryptBackend backend);

std::variant<PasswordSeed, PasswordError> derive_legacy_password_seed(
    std::span<const uint8_t> exact_legacy_username_utf8,
    std::span<const uint8_t> exact_legacy_password_utf8,
    LegacyBackend backend);

} // namespace hd_wallet::sdn::internal

#endif
#endif // HD_WALLET_PASSWORD_PROFILE_INTERNAL_H
