/**
 * @file sdn_identity.h
 * @brief Opaque, purpose-separated SDN identity capabilities.
 *
 * This API intentionally exposes only registered operations.  It contains no
 * raw seed import and no generic signing function.
 */

#ifndef HD_WALLET_SDN_IDENTITY_H
#define HD_WALLET_SDN_IDENTITY_H

#include "config.h"
#include "password_profile.h"
#include "types.h"

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace hd_wallet::sdn {

inline constexpr std::string_view kIdentityScheme =
    "sdn-bip32-slip10-purpose-v1";
inline constexpr std::string_view kLegacyFastIdentityScheme =
    "sdn-fast-password-auth-v1-legacy";
inline constexpr std::string_view kLegacyMnemonicIdentityScheme =
    "sdn-bip39-auth-v1-legacy";
inline constexpr std::string_view kLegacyMnemonicSeedProfile =
    "bip39-mnemonic-v1-legacy";

using IdentityHandle = uint64_t;

enum class Purpose : uint8_t {
    SdnAuthentication = 1,
    ContactEncryption = 2,
    AssetReviewApproval = 3,
};

enum class RegisteredOperation : uint8_t {
    SdnLoginV2 = 1,
    AssetReviewAuthorityActivation = 2,
    AssetReviewDecision = 3,
};

enum class RegistryRowId : uint8_t {
    SdnNodeConsoleV2 = 1,
    AssetReviewAuthorityActivation = 2,
    AssetReviewDecision = 3,
};

enum class ReviewDecision : uint8_t {
    Approve = 1,
    Disapprove = 2,
};

enum class KeyDerivation : uint8_t {
    Bip32Secp256k1 = 1,
    Slip10Ed25519 = 2,
    Slip10X25519 = 3,
    LegacyBip32ScalarAsEd25519Seed = 4,
};

enum class KeyEncoding : uint8_t {
    Raw = 1,
    Sec1Compressed = 2,
    Sec1Uncompressed = 3,
};

// These numeric values are the stable native/WASM error ABI.
enum class IdentityError : uint16_t {
    InvalidUsername = 1,
    InvalidPassword = 2,
    CommonPassword = 3,
    KdfFailure = 4,
    InvalidMnemonic = 5,
    InvalidAccountIndex = 6,
    StaleHandle = 7,
    OperationNotAllowed = 8,
    InvalidRequest = 9,
    AuthenticationFailed = 10,
    CapacityExceeded = 11,
    CryptoFailure = 12,
    OutOfMemory = 13,
    FipsNotAllowed = 14,
};

template <class T>
using IdentityOutcome = std::variant<T, IdentityError>;

struct PublicKeyDescriptor {
    Purpose purpose;
    std::string identity_scheme;
    std::string seed_profile;
    std::optional<std::string> signature_profile;
    Curve curve;
    KeyDerivation derivation;
    std::string path;
    KeyEncoding encoding;
    std::vector<uint8_t> public_key;
    std::optional<std::array<uint8_t, 4>> bip32_fingerprint;
    std::string key_id;
};

struct PublicIdentity {
    uint32_t schema_version;
    std::string identity_scheme;
    std::string seed_profile;
    uint32_t account_index;
    std::optional<std::string> account_label;
    std::string account_xpub;
    std::string account_peer_id;
    std::array<uint8_t, 4> account_fingerprint;
    std::vector<PublicKeyDescriptor> keys;
};

struct ImportedIdentity {
    IdentityHandle handle;
    PublicIdentity identity;
};

struct RawSignature {
    uint32_t schema_version;
    std::string key_id;
    std::string identity_scheme;
    std::string algorithm;
    KeyEncoding encoding;
    std::string signature_profile;
    std::array<uint8_t, 64> signature;
};

struct CanonicalSignature {
    uint32_t schema_version;
    std::string key_id;
    std::string identity_scheme;
    std::string algorithm;
    KeyEncoding encoding;
    std::string signature_profile;
    std::string canonical_envelope;
    std::array<uint8_t, 32> signed_digest;
    std::array<uint8_t, 64> signature;
};

struct SdnLoginV2Fields {
    uint32_t protocol_version;
    std::string audience;
    std::array<uint8_t, 32> challenge;
    std::string nonce;
    std::string issued_at;
    std::string expires_at;
};

struct AuthorityActivationFields {
    uint32_t protocol_version;
    std::string audience;
    std::string request_origin;
    std::string client_id;
    std::string service_instance;
    std::string purpose;
    std::string nonce;
    std::string issued_at;
    std::string expires_at;
    std::string public_key_hex;
    std::string key_id;
    std::string identity_scheme;
    std::string signature_profile;
};

struct ReviewedTransform {
    std::array<double, 3> translation;
    std::array<double, 4> rotation;
    std::array<double, 3> scale;
    std::string up_axis;
    std::string source_units;
    double meters_per_source_unit;
};

struct AssetReviewDecisionFields {
    uint32_t protocol_version;
    std::string audience;
    std::string request_origin;
    std::string client_id;
    std::string challenge_id;
    std::string nonce;
    std::string issued_at;
    std::string expires_at;
    std::string candidate_key;
    std::string model_cid;
    std::string model_sha256;
    uint64_t model_bytes;
    std::string metadata_sha256;
    std::optional<std::string> previous_decision_head;
    ReviewDecision decision;
    std::optional<ReviewedTransform> reviewed_transform;
    std::optional<std::string> note;
    std::optional<std::string> reason;
};

IdentityOutcome<IdentityHandle> derive_password_identity(
    std::span<const uint8_t> username_utf8,
    std::span<const uint8_t> exact_password_utf8,
    uint32_t account_index);

IdentityOutcome<IdentityHandle> derive_legacy_password_identity(
    std::span<const uint8_t> exact_legacy_username_utf8,
    std::span<const uint8_t> exact_legacy_password_utf8,
    uint32_t account_index);

IdentityOutcome<IdentityHandle> import_legacy_mnemonic_identity(
    std::span<const uint8_t> mnemonic_utf8,
    uint32_t account_index);

IdentityOutcome<PublicIdentity> describe_identity(IdentityHandle handle);

IdentityOutcome<RawSignature> sign_sdn_login_v1(
    IdentityHandle handle,
    std::span<const uint8_t, 32> challenge);

IdentityOutcome<CanonicalSignature> sign_sdn_login_v2(
    IdentityHandle handle,
    const SdnLoginV2Fields& request,
    RegistryRowId registry_row);

IdentityOutcome<CanonicalSignature> sign_asset_review_authority_activation(
    IdentityHandle handle,
    const AuthorityActivationFields& request,
    RegistryRowId registry_row);

IdentityOutcome<CanonicalSignature> sign_asset_review_decision(
    IdentityHandle handle,
    const AssetReviewDecisionFields& request,
    RegistryRowId registry_row);

IdentityOutcome<std::vector<uint8_t>> remember_wallet_seal(
    IdentityHandle handle,
    std::span<const uint8_t> exact_password_utf8,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_aad_utf8);

IdentityOutcome<ImportedIdentity> remember_wallet_open(
    std::span<const uint8_t> ciphertext_and_tag,
    std::span<const uint8_t, 32> prf_output,
    std::span<const uint8_t, 32> hkdf_salt,
    std::span<const uint8_t, 12> nonce,
    std::span<const uint8_t> canonical_username_utf8,
    std::span<const uint8_t> canonical_aad_utf8);

void destroy_identity(IdentityHandle handle) noexcept;

} // namespace hd_wallet::sdn

#endif // HD_WALLET_SDN_IDENTITY_H
