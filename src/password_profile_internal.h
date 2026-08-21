/**
 * @file password_profile_internal.h
 * @brief Source-private password KDF injection seam for focused native tests.
 */

#ifndef HD_WALLET_PASSWORD_PROFILE_INTERNAL_H
#define HD_WALLET_PASSWORD_PROFILE_INTERNAL_H

#include "hd_wallet/password_profile.h"

#include <span>
#include <variant>

namespace hd_wallet::sdn::internal {

enum class PasswordDerivationFailureKind : uint8_t {
    Policy,
    CryptoFailure,
    OutOfMemory,
};

struct PasswordDerivationFailure {
    PasswordError password_error;
    PasswordDerivationFailureKind kind;
};

using DetailedPasswordOutcome =
    std::variant<PasswordSeed, PasswordDerivationFailure>;

DetailedPasswordOutcome derive_password_seed_detailed(
    std::span<const uint8_t> username_utf8,
    std::span<const uint8_t> exact_password_utf8);

#if defined(HD_WALLET_PASSWORD_PROFILE_TESTING) && HD_WALLET_PASSWORD_PROFILE_TESTING

using ScryptBackend = void (*)(std::span<const uint8_t> password,
                               std::span<const uint8_t> salt,
                               std::span<uint8_t> output);
using LegacyBackend = void (*)(std::span<const uint8_t> username,
                               std::span<const uint8_t> password,
                               std::span<uint8_t> output);
using TestingPasswordWipeObserver = void (*)(size_t capacity, bool all_zero);

void testing_set_password_wipe_observer(
    TestingPasswordWipeObserver observer) noexcept;

std::variant<PasswordSeed, PasswordError> derive_password_seed(
    std::span<const uint8_t> username_utf8,
    std::span<const uint8_t> exact_password_utf8,
    ScryptBackend backend);

std::variant<PasswordSeed, PasswordError> derive_legacy_password_seed(
    std::span<const uint8_t> exact_legacy_username_utf8,
    std::span<const uint8_t> exact_legacy_password_utf8,
    LegacyBackend backend);

DetailedPasswordOutcome testing_derive_password_seed_detailed(
    std::span<const uint8_t> username_utf8,
    std::span<const uint8_t> exact_password_utf8,
    ScryptBackend backend);

#endif

} // namespace hd_wallet::sdn::internal

#endif // HD_WALLET_PASSWORD_PROFILE_INTERNAL_H
