/** Source-private secret ownership and primitive boundary for SDN identities. */

#ifndef HD_WALLET_SDN_IDENTITY_INTERNAL_H
#define HD_WALLET_SDN_IDENTITY_INTERNAL_H

#include "hd_wallet/sdn_identity.h"
#include "hd_wallet/secure_memory.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

namespace hd_wallet::sdn::internal {

class SecretBuffer {
public:
    SecretBuffer() noexcept = default;
    explicit SecretBuffer(size_t size);
    explicit SecretBuffer(SecureVector<uint8_t>&& bytes) noexcept;
    SecretBuffer(const SecretBuffer&) = delete;
    SecretBuffer& operator=(const SecretBuffer&) = delete;
    SecretBuffer(SecretBuffer&& other) noexcept;
    SecretBuffer& operator=(SecretBuffer&& other) noexcept;
    ~SecretBuffer();

    uint8_t* data() noexcept { return bytes_.data(); }
    const uint8_t* data() const noexcept { return bytes_.data(); }
    size_t size() const noexcept { return bytes_.size(); }
    size_t capacity() const noexcept { return bytes_.capacity(); }
    bool empty() const noexcept { return bytes_.empty(); }
    std::span<uint8_t> span() noexcept { return bytes_; }
    std::span<const uint8_t> span() const noexcept { return bytes_; }
    void resize(size_t size) { bytes_.resize(size); }
    void reserve(size_t size) { bytes_.reserve(size); }
    void push_back(uint8_t byte) { bytes_.push_back(byte); }

private:
    void wipe() noexcept;
    SecureVector<uint8_t> bytes_;
};

enum class IdentityKind : uint8_t {
    PasswordV2,
    LegacyPassword,
    LegacyMnemonic,
};

struct DerivedIdentityMaterial {
    IdentityKind kind{IdentityKind::PasswordV2};
    uint32_t account_index{0};
    SecretBuffer seed;
    SecretBuffer authentication_private;
    SecretBuffer contact_private;
    SecretBuffer approval_private;
    std::array<uint8_t, 32> authentication_public{};
    std::array<uint8_t, 32> contact_public{};
    std::array<uint8_t, 32> approval_public{};
    std::array<uint8_t, 33> account_public{};
    std::array<uint8_t, 4> account_fingerprint{};
    std::string account_xpub;
    std::string account_peer_id;

    DerivedIdentityMaterial() = default;
    DerivedIdentityMaterial(const DerivedIdentityMaterial&) = delete;
    DerivedIdentityMaterial& operator=(const DerivedIdentityMaterial&) = delete;
    DerivedIdentityMaterial(DerivedIdentityMaterial&&) noexcept = default;
    DerivedIdentityMaterial& operator=(DerivedIdentityMaterial&&) noexcept = default;
};

DerivedIdentityMaterial derive_identity_material(SecretBuffer&& seed,
                                                  IdentityKind kind,
                                                  uint32_t account_index);
IdentityOutcome<SecretBuffer> derive_legacy_mnemonic_seed(
    std::span<const uint8_t> mnemonic_utf8);

std::array<uint8_t, 32> sha256_public(std::span<const uint8_t> bytes);
void sha256_secret(std::span<const uint8_t> bytes,
                   std::span<uint8_t, 32> output);
std::array<uint8_t, 64> sign_ed25519(std::span<const uint8_t, 32> seed,
                                     std::span<const uint8_t> message);
SecretBuffer hkdf_sha256(std::span<const uint8_t> input_key_material,
                         std::span<const uint8_t> salt,
                         std::span<const uint8_t> info,
                         size_t output_size);
std::vector<uint8_t> aes256_gcm_seal(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad);
IdentityOutcome<SecretBuffer> aes256_gcm_open(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t> aad);
bool constant_time_equal(std::span<const uint8_t> left,
                         std::span<const uint8_t> right) noexcept;

#if defined(HD_WALLET_SDN_IDENTITY_TESTING) && HD_WALLET_SDN_IDENTITY_TESTING
using TestingDerivationBackend = void (*)(
    std::span<const uint8_t> key,
    std::span<const uint8_t> data,
    std::span<uint8_t, 64> output);
using TestingSigningBackend = void (*)(
    std::span<const uint8_t, 32> seed,
    std::span<const uint8_t> message,
    std::span<uint8_t, 64> output);
using TestingHkdfBackend = void (*)(
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    std::span<uint8_t> output);
using TestingPasswordKdfBackend = void (*)(
    std::span<const uint8_t> password,
    std::span<const uint8_t> salt,
    std::span<uint8_t> output);
using TestingAeadSealBackend = void (*)(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    std::span<uint8_t> ciphertext_and_tag);
using TestingAeadOpenBackend = bool (*)(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t> aad,
    std::span<uint8_t> plaintext);
using TestingWipeObserver = void (*)(size_t capacity, bool all_zero);

void testing_set_wipe_observer(TestingWipeObserver observer) noexcept;
bool testing_set_empty_slot_generation(size_t zero_based_slot,
                                       uint32_t generation) noexcept;
size_t testing_retired_slot_count() noexcept;
DerivedIdentityMaterial testing_derive_identity_material(
    SecretBuffer&& seed,
    IdentityKind kind,
    uint32_t account_index,
    TestingDerivationBackend backend);
std::array<uint8_t, 64> testing_sign_ed25519(
    std::span<const uint8_t, 32> seed,
    std::span<const uint8_t> message,
    TestingSigningBackend backend);
SecretBuffer testing_hkdf_sha256_with_backend(
    std::span<const uint8_t> input_key_material,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_size,
    TestingHkdfBackend backend);
std::vector<uint8_t> testing_aes256_gcm_seal_with_backend(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad,
    TestingAeadSealBackend backend);
IdentityOutcome<SecretBuffer> testing_aes256_gcm_open_with_backend(
    std::span<const uint8_t, 32> key,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t> aad,
    TestingAeadOpenBackend backend);

IdentityOutcome<IdentityHandle> testing_derive_legacy_password_identity(
    std::span<const uint8_t> exact_legacy_username_utf8,
    std::span<const uint8_t> exact_legacy_password_utf8,
    uint32_t account_index,
    TestingDerivationBackend backend);
IdentityOutcome<RawSignature> testing_sign_sdn_login_v1(
    IdentityHandle handle,
    std::span<const uint8_t, 32> challenge,
    TestingSigningBackend backend);
IdentityOutcome<std::vector<uint8_t>> testing_remember_wallet_seal_with_hkdf(
    IdentityHandle handle,
    std::span<const uint8_t> exact_password_utf8,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_aad_utf8,
    TestingHkdfBackend backend);
IdentityOutcome<std::vector<uint8_t>> testing_remember_wallet_seal_with_password_kdf(
    IdentityHandle handle,
    std::span<const uint8_t> exact_password_utf8,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_aad_utf8,
    TestingPasswordKdfBackend backend);
IdentityOutcome<std::vector<uint8_t>> testing_remember_wallet_seal_with_aead(
    IdentityHandle handle,
    std::span<const uint8_t> exact_password_utf8,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_aad_utf8,
    TestingAeadSealBackend backend);
IdentityOutcome<ImportedIdentity> testing_remember_wallet_open_with_aead(
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_username_utf8,
    std::span<const uint8_t> canonical_aad_utf8,
    TestingAeadOpenBackend backend);
IdentityOutcome<ImportedIdentity> testing_remember_wallet_open_with_password_kdf(
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_username_utf8,
    std::span<const uint8_t> canonical_aad_utf8,
    TestingPasswordKdfBackend backend);
IdentityOutcome<std::vector<uint8_t>> testing_hkdf_sha256(
    std::span<const uint8_t> ikm,
    std::span<const uint8_t> salt,
    std::span<const uint8_t> info,
    size_t output_size);
IdentityOutcome<std::vector<uint8_t>> testing_aes256_gcm_seal(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad);
IdentityOutcome<std::vector<uint8_t>> testing_aes256_gcm_open(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t> aad);
size_t testing_secret_base64url_lifecycle(
    std::span<const uint8_t> secret_input);
#endif

} // namespace hd_wallet::sdn::internal

#endif // HD_WALLET_SDN_IDENTITY_INTERNAL_H
