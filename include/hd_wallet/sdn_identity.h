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
    SdnPublishRequest = 4,
    ModuleDeliveryKey = 5,
    FieldOpen = 6,
    KeyUnwrap = 7,
};

enum class RegistryRowId : uint8_t {
    SdnNodeConsoleV2 = 1,
    AssetReviewAuthorityActivation = 2,
    AssetReviewDecision = 3,
    SpaceAwarePublishRequest = 4,
    SpaceAwareModuleDeliveryKey = 5,
    FlatbuffersFieldOpen = 6,
    FlatsqlKeyUnwrap = 7,
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

// The isolated wallet obtains the challenge from the confirmed provider.
// Metadata is confirmation text, not an assertion about the hashed body.
struct SdnPublishRequestFields {
    uint32_t protocol_version;
    std::string provider_origin;
    std::string method;
    std::string request_uri;
    std::string body_sha256;
    uint32_t body_bytes;
    std::string challenge_id;
    std::array<uint8_t, 32> challenge;
    std::string schema;
    std::string entity_id;
    std::string entity_name;
    uint32_t document_count;
};

struct SdnPublishSignature {
    uint32_t schema_version;
    std::string key_id;
    std::string identity_scheme;
    std::string algorithm;
    KeyEncoding encoding;
    std::string signature_profile;
    std::array<uint8_t, 32> public_key;
    std::array<uint8_t, 64> signature;
    std::array<uint8_t, 32> request_digest;
};

/// "This session key may fetch paid modules for this account": the session's
/// Ed25519 module-delivery key, the page origin and an expiry (unix seconds).
struct ModuleDeliveryKeyFields {
    uint32_t protocol_version;
    std::string origin;
    std::array<uint8_t, 32> session_public;
    uint64_t expires_at;
};

/// The account key's ECDSA (DER, over sha256) signature of the byte-replayed
/// statement, as an EPM ChainProof carries it.
struct ModuleDeliveryKeyProof {
    uint32_t schema_version;
    std::string key_path;
    std::string account_xpub;
    std::array<uint8_t, 33> account_public;
    std::string statement;
    std::vector<uint8_t> signature_der;
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

/// One field sealed to this identity's contact-encryption key with the SDN
/// Unified ECIES field cipher (an SDS `$ENC` header's values plus the field's
/// ciphertext). The registry row names the one site whose fields it opens.
struct SealedField {
    std::array<uint8_t, 32> ephemeral_public;
    std::array<uint8_t, 8> recipient_key_id;
    std::string context;
    uint16_t field_id;
    std::vector<uint8_t> ciphertext;
};

enum class FieldOpenStatus : uint8_t {
    Opened = 0,
    NotAddressedToAccount = 1,
};

/// A field's plaintext sealed again, to the requesting page's reply key, with
/// the same cipher (reply field id = the field's index in the batch).
struct ResealedField {
    FieldOpenStatus status;
    std::vector<uint8_t> ciphertext;
};

struct FieldReply {
    std::array<uint8_t, 32> ephemeral_public;
    std::vector<ResealedField> fields;
};

/// The reply cipher's HKDF info (the reply's $ENC CONTEXT).
inline constexpr std::string_view kFieldReplyContext = "sdn-wallet-reply/v1";
inline constexpr size_t kMaximumSealedFields = 16;
inline constexpr size_t kMaximumSealedFieldBytes = 4096;
inline constexpr size_t kMaximumSealedBatchBytes = 12288;

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

IdentityOutcome<SdnPublishSignature> sign_sdn_publish_request(
    IdentityHandle handle,
    const SdnPublishRequestFields& request,
    RegistryRowId registry_row);

IdentityOutcome<ModuleDeliveryKeyProof> sign_module_delivery_key(
    IdentityHandle handle,
    const ModuleDeliveryKeyFields& request,
    RegistryRowId registry_row);

IdentityOutcome<CanonicalSignature> sign_asset_review_authority_activation(
    IdentityHandle handle,
    const AuthorityActivationFields& request,
    RegistryRowId registry_row);

IdentityOutcome<CanonicalSignature> sign_asset_review_decision(
    IdentityHandle handle,
    const AssetReviewDecisionFields& request,
    RegistryRowId registry_row);

/// Opens fields sealed to this identity's contact-encryption key and seals
/// each plaintext to `reply_public`; no key, shared secret or plaintext
/// leaves native memory. Refuses the whole batch unless every CONTEXT is
/// `<row audience>|<schema>|<field>|k<version>` (the row's audience is
/// `sdn-field-encryption/v1|<site>`). A field whose RECIPIENT_KEY_ID is not
/// sha256(contact public)[:8] comes back NotAddressedToAccount. The
/// key-unwrap row takes exactly one 32-byte $KMF KEY_BYTES (field id 4).
IdentityOutcome<FieldReply> open_sealed_fields(
    IdentityHandle handle,
    std::span<const SealedField> fields,
    std::span<const uint8_t, 32> reply_public,
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

// Identity transfer between two wallet instances (hd-wallet/sdn-identity-
// transfer-v1). A password identity moves from one instance to another
// without its seed leaving native memory, so the password KDF can run in a
// short-lived instance whose memory is then released:
//   1. the receiver calls identity_transfer_begin(): a fresh X25519 key made
//      from native randomness; only its public half is returned, and the
//      private half stays in the receiver for one open;
//   2. the sender seals the identity to that public key: an ephemeral X25519
//      agreement, HKDF-SHA256 and AES-256-GCM (as remember-wallet seals);
//   3. the receiver opens it into a new handle (no KDF runs) and forgets its
//      private key.
// Only the public keys and the sealed bytes pass between the instances.
IdentityOutcome<std::array<uint8_t, 32>> identity_transfer_begin();

IdentityOutcome<std::vector<uint8_t>> identity_transfer_seal(
    IdentityHandle handle,
    std::span<const uint8_t, 32> recipient_public);

IdentityOutcome<ImportedIdentity> identity_transfer_open(
    std::span<const uint8_t> sealed);

void destroy_identity(IdentityHandle handle) noexcept;

} // namespace hd_wallet::sdn

#endif // HD_WALLET_SDN_IDENTITY_H
